use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use rb_config::{FakeIpDnsServer, IpPrefix};

use super::Answer;

const FAKEIP_TTL: u32 = 600;

#[derive(Debug, Clone, Copy)]
struct AddressRange {
    network: IpAddr,
    last: IpAddr,
    prefix_len: u8,
}

impl AddressRange {
    fn new(prefix: IpPrefix) -> Self {
        let total_bits = if prefix.address.is_ipv4() { 32 } else { 128 };
        let mask = if prefix.prefix_len == 0 { 0 } else { u128::MAX << (total_bits - prefix.prefix_len) };
        let raw = address_bits(prefix.address) & mask;
        let network = bits_address(prefix.address.is_ipv4(), raw);
        let last = bits_address(prefix.address.is_ipv4(), raw | !mask);
        AddressRange { network, last, prefix_len: prefix.prefix_len }
    }

    fn contains(self, address: IpAddr) -> bool {
        if address.is_ipv4() != self.network.is_ipv4() {
            return false;
        }
        let total_bits = if self.network.is_ipv4() { 32 } else { 128 };
        let mask = if self.prefix_len == 0 { 0 } else { u128::MAX << (total_bits - self.prefix_len) };
        address_bits(address) & mask == address_bits(self.network)
    }

    fn initial(self) -> Option<IpAddr> {
        next_address(self.network)
    }
}

#[derive(Default)]
struct Store {
    by_address: HashMap<IpAddr, String>,
    by_domain4: HashMap<String, IpAddr>,
    by_domain6: HashMap<String, IpAddr>,
    current4: Option<IpAddr>,
    current6: Option<IpAddr>,
}

/// sing-box `dns/transport/fakeip.Transport` plus its in-memory store.
pub struct FakeIpTransport {
    inet4_range: Option<AddressRange>,
    inet6_range: Option<AddressRange>,
    store: Mutex<Store>,
}

impl std::fmt::Debug for FakeIpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeIpTransport")
            .field("inet4_range", &self.inet4_range)
            .field("inet6_range", &self.inet6_range)
            .finish_non_exhaustive()
    }
}

impl FakeIpTransport {
    pub fn new(options: &FakeIpDnsServer) -> io::Result<Self> {
        let inet4_range = options.inet4_range.map(AddressRange::new);
        let inet6_range = options.inet6_range.map(AddressRange::new);
        if inet4_range.is_none() && inet6_range.is_none() {
            return Err(invalid("at least one of inet4_range or inet6_range must be set"));
        }
        let current4 = inet4_range.and_then(AddressRange::initial);
        let current6 = inet6_range.and_then(AddressRange::initial);
        Ok(FakeIpTransport {
            inet4_range,
            inet6_range,
            store: Mutex::new(Store { current4, current6, ..Default::default() }),
        })
    }

    /// `FakeIPStore.Contains`.
    pub fn contains(&self, address: IpAddr) -> bool {
        self.inet4_range.is_some_and(|range| range.contains(address))
            || self.inet6_range.is_some_and(|range| range.contains(address))
    }

    /// `FakeIPStore.Lookup`.
    pub fn lookup(&self, address: IpAddr) -> Option<String> {
        self.store.lock().unwrap().by_address.get(&address).cloned()
    }

    /// `FakeIPStore.Create` and fakeip `DNSTransport.Query`.
    pub fn query(&self, domain: &str, query_type: u16) -> io::Result<Answer> {
        let is_ipv6 = match query_type {
            1 => false,
            28 => true,
            _ => return Err(invalid("only IP queries are supported by fakeip")),
        };
        if domain.len() > 255 {
            return Err(invalid("domain name too long for fakeip"));
        }
        let range = if is_ipv6 { self.inet6_range } else { self.inet4_range };
        let Some(range) = range else {
            return Ok(Answer { addresses: Vec::new(), ttl: 0 });
        };
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut store = self.store.lock().unwrap();
        let domain_map = if is_ipv6 { &store.by_domain6 } else { &store.by_domain4 };
        if let Some(address) = domain_map.get(&domain) {
            return Ok(Answer { addresses: vec![*address], ttl: FAKEIP_TTL });
        }

        let current = if is_ipv6 { &mut store.current6 } else { &mut store.current4 };
        let first = range.initial();
        let mut address = current.and_then(next_address);
        if address == Some(range.last) || address.is_none_or(|candidate| !range.contains(candidate)) {
            // sing-box reserves the first and broadcast addresses and wraps to
            // the first assignable address (network address + 2).
            address = first.and_then(next_address).or(first);
        }
        let Some(address) = address else {
            return Err(invalid(if is_ipv6 {
                "missing IPv6 fakeip address range"
            } else {
                "missing IPv4 fakeip address range"
            }));
        };
        *current = Some(address);

        if let Some(old_domain) = store.by_address.insert(address, domain.clone()) {
            if is_ipv6 {
                store.by_domain6.remove(&old_domain);
            } else {
                store.by_domain4.remove(&old_domain);
            }
        }
        let domain_map = if is_ipv6 { &mut store.by_domain6 } else { &mut store.by_domain4 };
        domain_map.insert(domain, address);
        Ok(Answer { addresses: vec![address], ttl: FAKEIP_TTL })
    }

    /// FakeIP does not forward non-address DNS messages.
    pub fn exchange(&self, _query: &[u8]) -> io::Result<Vec<u8>> {
        Err(invalid("only IP queries are supported by fakeip"))
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn address_bits(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u32::from(address) as u128,
        IpAddr::V6(address) => u128::from(address),
    }
}

fn bits_address(is_ipv4: bool, value: u128) -> IpAddr {
    if is_ipv4 {
        IpAddr::V4(Ipv4Addr::from(value as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(value))
    }
}

fn next_address(address: IpAddr) -> Option<IpAddr> {
    match address {
        IpAddr::V4(address) => u32::from(address).checked_add(1).map(|next| IpAddr::V4(Ipv4Addr::from(next))),
        IpAddr::V6(address) => u128::from(address).checked_add(1).map(|next| IpAddr::V6(Ipv6Addr::from(next))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn options(inet4_range: &str, inet6_range: &str) -> FakeIpDnsServer {
        FakeIpDnsServer {
            tag: "fake".into(),
            inet4_range: (!inet4_range.is_empty()).then(|| IpPrefix::from_str(inet4_range).unwrap()),
            inet6_range: (!inet6_range.is_empty()).then(|| IpPrefix::from_str(inet6_range).unwrap()),
        }
    }

    #[test]
    fn allocates_stable_addresses_per_domain_and_family() {
        let fakeip = FakeIpTransport::new(&options("198.18.0.0/29", "2001:2::/125")).unwrap();
        let first = fakeip.query("one.test.", 1).unwrap();
        assert_eq!(first.addresses, vec!["198.18.0.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(fakeip.query("ONE.TEST", 1).unwrap().addresses, first.addresses);
        let v6 = fakeip.query("one.test", 28).unwrap();
        assert_eq!(v6.addresses, vec!["2001:2::2".parse::<IpAddr>().unwrap()]);
        assert_eq!(fakeip.lookup(first.addresses[0]).as_deref(), Some("one.test"));
        assert!(fakeip.contains(first.addresses[0]));
    }

    #[test]
    fn missing_family_is_empty_and_other_types_are_rejected() {
        let fakeip = FakeIpTransport::new(&options("198.18.0.0/15", "")).unwrap();
        assert!(fakeip.query("one.test", 28).unwrap().addresses.is_empty());
        assert_eq!(fakeip.query("one.test", 16).unwrap_err().to_string(), "only IP queries are supported by fakeip");
    }
}
