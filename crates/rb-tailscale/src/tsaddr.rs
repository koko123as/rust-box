//! Tailscale-specific address classification from the fork pinned by sing-box v1.14.4.
//!
//! This module ports Tailscale address classification/translation, service IPs,
//! and via-route mapping helpers; other route helpers and endpoint behavior remain out of scope.

use std::borrow::Cow;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const CGNAT_START: u32 = u32::from_be_bytes([100, 64, 0, 0]);
const CGNAT_END: u32 = u32::from_be_bytes([100, 127, 255, 255]);
const CHROMEOS_VM_START: u32 = u32::from_be_bytes([100, 115, 92, 0]);
const CHROMEOS_VM_END: u32 = u32::from_be_bytes([100, 115, 93, 255]);
const TAILSCALE_ULA_PREFIX: [u16; 3] = [0xfd7a, 0x115c, 0xa1e0];
const TAILSCALE_4TO6_PREFIX: [u8; 13] = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0xab, 0x12, 0x48, 0x43, 0xcd, 0x96, 0x62];
const TAILSCALE_VIA_PREFIX: [u8; 8] = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0x0b, 0x1a];

/// An IP prefix preserving the supplied address and Go's invalid-prefix state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpPrefix {
    address: IpAddr,
    prefix_len: i32,
}

impl IpPrefix {
    /// Creates a prefix, storing `-1` bits when Go `netip.PrefixFrom` is invalid.
    pub fn new(address: IpAddr, prefix_len: i32) -> Self {
        let max_bits = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = if (0..=max_bits).contains(&prefix_len) { prefix_len } else { -1 };
        Self { address, prefix_len }
    }

    pub fn address(self) -> IpAddr {
        self.address
    }

    /// Returns `-1` for an invalid prefix, matching Go `netip.Prefix.Bits`.
    pub fn prefix_len(self) -> i32 {
        self.prefix_len
    }

    pub fn is_valid(self) -> bool {
        self.prefix_len >= 0
    }

    pub fn is_ipv4(self) -> bool {
        matches!(self.address, IpAddr::V4(_))
    }

    pub fn is_ipv6(self) -> bool {
        matches!(self.address, IpAddr::V6(_))
    }

    /// Tests prefix membership without normalizing the stored address.
    pub fn contains(self, address: IpAddr) -> bool {
        if !self.is_valid() {
            return false;
        }
        match (self.address, address) {
            (IpAddr::V4(prefix), IpAddr::V4(address)) => {
                let mask = if self.prefix_len == 0 { 0 } else { u32::MAX << (32 - self.prefix_len as u32) };
                u32::from(prefix) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(prefix), IpAddr::V6(address)) => {
                let mask = if self.prefix_len == 0 { 0 } else { u128::MAX << (128 - self.prefix_len as u32) };
                u128::from(prefix) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_valid() {
            write!(f, "{}/{}", self.address, self.prefix_len)
        } else {
            f.write_str("invalid Prefix")
        }
    }
}

/// Reports whether any prefix in `prefixes` contains `ip`.
pub fn prefixes_contains_ip(prefixes: &[IpPrefix], ip: IpAddr) -> bool {
    prefixes.iter().any(|prefix| prefix.contains(ip))
}

/// Reports whether the prefix retains an IPv4 address, including invalid prefixes.
pub fn prefix_is4(prefix: IpPrefix) -> bool {
    prefix.is_ipv4()
}

/// Reports whether the prefix retains an IPv6 address, including invalid prefixes.
pub fn prefix_is6(prefix: IpPrefix) -> bool {
    prefix.is_ipv6()
}

/// Returns the canonical IPv4 default route `0.0.0.0/0`.
pub fn all_ipv4() -> IpPrefix {
    IpPrefix::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
}

/// Returns the canonical IPv6 default route `::/0`.
pub fn all_ipv6() -> IpPrefix {
    IpPrefix::new(IpAddr::V6(Ipv6Addr::from(0u128)), 0)
}

/// Returns the canonical IPv4 and IPv6 default routes, in that order.
pub fn exit_routes() -> [IpPrefix; 2] {
    [all_ipv4(), all_ipv6()]
}

/// Reports whether `prefix` is exactly one of the canonical default routes.
pub fn is_exit_route(prefix: IpPrefix) -> bool {
    prefix == all_ipv4() || prefix == all_ipv6()
}

/// Reports whether both canonical IPv4 and IPv6 default routes are present.
pub fn contains_exit_routes(routes: &[IpPrefix]) -> bool {
    let mut has_ipv4 = false;
    let mut has_ipv6 = false;
    for route in routes {
        if *route == all_ipv4() {
            has_ipv4 = true;
        } else if *route == all_ipv6() {
            has_ipv6 = true;
        }
    }
    has_ipv4 && has_ipv6
}

/// Reports whether any route has a zero-length prefix, regardless of its address.
pub fn contains_exit_route(routes: &[IpPrefix]) -> bool {
    routes.iter().any(|route| route.prefix_len() == 0)
}

/// Reports whether any route has a nonzero bit length, including invalid prefixes.
pub fn contains_non_exit_subnet_routes(routes: &[IpPrefix]) -> bool {
    routes.iter().any(|route| route.prefix_len() != 0)
}

/// Removes all zero-length routes when both canonical default routes are present.
/// Otherwise, borrows and returns the original slice without copying.
pub fn without_exit_routes(routes: &[IpPrefix]) -> Cow<'_, [IpPrefix]> {
    if !contains_exit_routes(routes) {
        return Cow::Borrowed(routes);
    }
    Cow::Owned(routes.iter().copied().filter(|route| route.prefix_len() > 0).collect())
}

/// Removes all zero-length routes when at least one is present.
/// Otherwise, borrows and returns the original slice without copying.
pub fn without_exit_route(routes: &[IpPrefix]) -> Cow<'_, [IpPrefix]> {
    if !contains_exit_route(routes) {
        return Cow::Borrowed(routes);
    }
    Cow::Owned(routes.iter().copied().filter(|route| route.prefix_len() > 0).collect())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapViaError;

impl fmt::Display for MapViaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("want IPv4 CIDR with a site ID")
    }
}

impl Error for MapViaError {}

pub const TAILSCALE_SERVICE_IP_STRING: &str = "100.100.100.100";
pub const TAILSCALE_SERVICE_IPV6_STRING: &str = "fd7a:115c:a1e0::53";

/// Returns the ChromeOS host/container VM range excluded from Tailscale allocation.
pub fn chromeos_vm_range() -> IpPrefix {
    IpPrefix::new(IpAddr::V4(Ipv4Addr::new(100, 115, 92, 0)), 23)
}

/// Returns the IPv4 CGNAT range from which Tailscale allocates addresses.
pub fn cgnat_range() -> IpPrefix {
    IpPrefix::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10)
}

/// Returns the Tailscale IPv6 unique-local address supernet.
pub fn tailscale_ula_range() -> IpPrefix {
    IpPrefix::new(IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0)), 48)
}

/// Returns the IPv6 `/64` reserved for IPv4-via-IPv6 Tailscale routes.
pub fn tailscale_via_range() -> IpPrefix {
    let mut address = [0; 16];
    address[..8].copy_from_slice(&TAILSCALE_VIA_PREFIX);
    IpPrefix::new(IpAddr::V6(Ipv6Addr::from(address)), 64)
}

/// Returns the IPv6 `/104` used for automatic Tailscale IPv4-to-IPv6 mapping.
pub fn tailscale4_to6_range() -> IpPrefix {
    IpPrefix::new(IpAddr::V6(tailscale4_to6_placeholder()), 104)
}

/// Returns the IPv6 `/64` used for ephemeral IPv6-only Tailscale nodes.
pub fn tailscale_ephemeral6_range() -> IpPrefix {
    IpPrefix::new(IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0xefe3, 0, 0, 0, 0)), 64)
}

/// Returns the first address in the Tailscale IPv4-to-IPv6 mapping range.
pub fn tailscale4_to6_placeholder() -> Ipv6Addr {
    let mut address = [0; 16];
    address[..13].copy_from_slice(&TAILSCALE_4TO6_PREFIX);
    Ipv6Addr::from(address)
}

/// Returns the IPv4 Tailscale service address (`100.100.100.100`).
pub const fn tailscale_service_ip() -> Ipv4Addr {
    Ipv4Addr::new(100, 100, 100, 100)
}

/// Returns the IPv6 Tailscale service address (`fd7a:115c:a1e0::53`).
pub const fn tailscale_service_ipv6() -> Ipv6Addr {
    Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x53)
}

/// Reports whether an address belongs to a range Tailscale assigns from.
///
/// IPv4-mapped IPv6 addresses are unmapped before classification, matching the
/// pinned fork's `netip.Addr.Unmap` behavior.
pub fn is_tailscale_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => is_tailscale_ipv4(ip),
        IpAddr::V6(ipv6) => match ipv6.to_ipv4_mapped() {
            Some(ipv4) => is_tailscale_ipv4(IpAddr::V4(ipv4)),
            None => is_tailscale_ipv6_ula(ipv6),
        },
    }
}

/// Reports whether a native IPv4 address is in Tailscale's assignable CGNAT range.
///
/// The ChromeOS VM range `100.115.92.0/23` is excluded. An IPv4-mapped IPv6 input
/// returns false, matching the pinned fork's `IsTailscaleIPv4` behavior.
pub fn is_tailscale_ipv4(ip: IpAddr) -> bool {
    let IpAddr::V4(ipv4) = ip else {
        return false;
    };
    let address = u32::from(ipv4);
    (CGNAT_START..=CGNAT_END).contains(&address) && !(CHROMEOS_VM_START..=CHROMEOS_VM_END).contains(&address)
}

/// Returns the first assignable IPv4 and IPv6 addresses among the supplied prefixes.
///
/// Prefix validity is not checked before examining its address, matching the pinned
/// fork. An IPv4-mapped IPv6 address remains in the IPv6 result when selected.
pub fn first_tailscale_addrs(addresses: &[IpPrefix]) -> (Option<IpAddr>, Option<IpAddr>) {
    let (mut ipv4, mut ipv6) = (None, None);
    for prefix in addresses {
        let address = prefix.address();
        match address {
            IpAddr::V4(_) if ipv4.is_none() && is_tailscale_ip(address) => ipv4 = Some(address),
            IpAddr::V6(_) if ipv6.is_none() && is_tailscale_ip(address) => ipv6 = Some(address),
            _ => {}
        }
        if ipv4.is_some() && ipv6.is_some() {
            break;
        }
    }
    (ipv4, ipv6)
}

/// Returns the IPv6 address mapped from a native Tailscale IPv4 address.
///
/// Unlike [`is_tailscale_ip`], this follows the pinned fork's native-v4-only
/// input check: IPv4-mapped IPv6 and non-assignable IPv4 addresses return `None`.
pub fn tailscale4_to6(ip: IpAddr) -> Option<Ipv6Addr> {
    let IpAddr::V4(ipv4) = ip else {
        return None;
    };
    if !is_tailscale_ipv4(IpAddr::V4(ipv4)) {
        return None;
    }
    let octets = ipv4.octets();
    let mut mapped = [0; 16];
    mapped[..13].copy_from_slice(&TAILSCALE_4TO6_PREFIX);
    mapped[13..].copy_from_slice(&octets[1..]);
    Some(Ipv6Addr::from(mapped))
}

/// Returns the IPv4 encoding of an address in the Tailscale 4-to-6 `/104` range.
///
/// This intentionally checks only the `/104` prefix, like the pinned fork; the
/// resulting IPv4 address is not revalidated against the assignable IPv4 range.
pub fn tailscale6_to4(ip: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(ipv6) = ip else {
        return None;
    };
    let octets = ipv6.octets();
    if octets[..13] != TAILSCALE_4TO6_PREFIX {
        return None;
    }
    Some(Ipv4Addr::new(100, octets[13], octets[14], octets[15]))
}

/// Reports whether an IPv6 address is in the Tailscale IPv4-via-IPv6 `/64` range.
pub fn is_via_ip(ip: IpAddr) -> bool {
    let IpAddr::V6(ipv6) = ip else {
        return false;
    };
    ipv6.octets()[..8] == TAILSCALE_VIA_PREFIX
}

/// Reports whether a prefix's address is in the Tailscale via `/64` range.
///
/// As in the pinned fork, the prefix length is ignored; only its address is tested.
pub fn is_via_prefix(prefix: IpPrefix) -> bool {
    is_via_ip(prefix.address())
}

/// Maps an IPv4 prefix into the Tailscale via range for `site_id`.
///
/// The source address is retained as-is (including host bits), and the IPv4 prefix
/// length is extended by 96 bits. Non-IPv4 prefixes return the pinned error.
pub fn map_via(site_id: u32, ipv4_prefix: IpPrefix) -> Result<IpPrefix, MapViaError> {
    let IpAddr::V4(ipv4) = ipv4_prefix.address() else {
        return Err(MapViaError);
    };
    let mut address = [0; 16];
    address[..8].copy_from_slice(&TAILSCALE_VIA_PREFIX);
    address[8..12].copy_from_slice(&site_id.to_be_bytes());
    address[12..].copy_from_slice(&ipv4.octets());
    Ok(IpPrefix::new(IpAddr::V6(Ipv6Addr::from(address)), ipv4_prefix.prefix_len() + 96))
}

/// Unmaps an address in the Tailscale IPv4-via-IPv6 `/64` using its final 32 bits.
///
/// The pinned fork does not validate the resulting IPv4 address; addresses outside
/// the `/64` are returned unchanged.
pub fn unmap_via(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(ipv6) = ip else {
        return ip;
    };
    let octets = ipv6.octets();
    if octets[..8] != TAILSCALE_VIA_PREFIX {
        return ip;
    }
    IpAddr::V4(Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]))
}

fn is_tailscale_ipv6_ula(ipv6: Ipv6Addr) -> bool {
    ipv6.segments()[..3] == TAILSCALE_ULA_PREFIX
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::net::IpAddr;

    use super::{is_tailscale_ip, is_tailscale_ipv4, IpPrefix, MapViaError};

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("test address must be valid")
    }

    fn prefix(value: &str) -> IpPrefix {
        let (address, prefix_len) = value.split_once('/').expect("test prefix must have a length");
        IpPrefix::new(ip(address), prefix_len.parse().expect("test prefix length must be numeric"))
    }

    #[test]
    fn ipv4_cgnat_boundaries_match_pinned_go_oracle() {
        for (address, expected) in [
            ("100.63.255.255", false),
            ("100.64.0.0", true),
            ("100.64.0.1", true),
            ("100.127.255.255", true),
            ("100.128.0.0", false),
        ] {
            let address = ip(address);
            assert_eq!(is_tailscale_ipv4(address), expected, "IPv4 predicate for {address}");
            assert_eq!(is_tailscale_ip(address), expected, "general predicate for {address}");
        }
    }

    #[test]
    fn chromeos_vm_subrange_is_excluded_with_inclusive_boundaries() {
        for (address, expected) in
            [("100.115.91.255", true), ("100.115.92.0", false), ("100.115.93.255", false), ("100.115.94.0", true)]
        {
            let address = ip(address);
            assert_eq!(is_tailscale_ipv4(address), expected, "IPv4 predicate for {address}");
            assert_eq!(is_tailscale_ip(address), expected, "general predicate for {address}");
        }
    }

    #[test]
    fn ipv6_ula_prefix_boundaries_match_pinned_go_oracle() {
        for (address, expected) in [
            ("fd7a:115c:a1df:ffff::1", false),
            ("fd7a:115c:a1e0::", true),
            ("fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff", true),
            ("fd7a:115c:a1e1::", false),
            ("2001:db8::1", false),
        ] {
            let address = ip(address);
            assert_eq!(is_tailscale_ip(address), expected, "general predicate for {address}");
            assert!(!is_tailscale_ipv4(address), "IPv4 predicate for {address}");
        }
    }

    #[test]
    fn service_addresses_and_via_range_match_pinned_go_oracle() {
        assert_eq!(super::tailscale_service_ip().to_string(), "100.100.100.100");
        assert_eq!(super::tailscale_service_ipv6().to_string(), "fd7a:115c:a1e0::53");
        assert_eq!(super::TAILSCALE_SERVICE_IP_STRING, "100.100.100.100");
        assert_eq!(super::TAILSCALE_SERVICE_IPV6_STRING, "fd7a:115c:a1e0::53");
        assert_eq!(super::cgnat_range(), prefix("100.64.0.0/10"));
        assert_eq!(super::chromeos_vm_range(), prefix("100.115.92.0/23"));
        assert_eq!(super::tailscale_ula_range(), prefix("fd7a:115c:a1e0::/48"));
        assert_eq!(super::tailscale_via_range(), prefix("fd7a:115c:a1e0:b1a::/64"));
        assert_eq!(super::tailscale4_to6_range(), prefix("fd7a:115c:a1e0:ab12:4843:cd96:6200::/104"));
        assert_eq!(super::tailscale_ephemeral6_range(), prefix("fd7a:115c:a1e0:efe3::/64"));
        assert_eq!(super::tailscale4_to6_placeholder().to_string(), "fd7a:115c:a1e0:ab12:4843:cd96:6200:0");

        for (address, expected_is_via, expected_unmapped) in [
            ("fd7a:115c:a1e0:b19:ffff:ffff:ffff:ffff", false, "fd7a:115c:a1e0:b19:ffff:ffff:ffff:ffff"),
            ("fd7a:115c:a1e0:b1a::", true, "0.0.0.0"),
            ("fd7a:115c:a1e0:b1a:ffff:ffff:ffff:ffff", true, "255.255.255.255"),
            ("fd7a:115c:a1e0:b1b::", false, "fd7a:115c:a1e0:b1b::"),
            ("fd7a:115c:a1e0:b1a:ffff:ffff:c000:201", true, "192.0.2.1"),
            ("::ffff:100.64.0.1", false, "::ffff:100.64.0.1"),
            ("100.64.0.1", false, "100.64.0.1"),
        ] {
            let address = ip(address);
            assert_eq!(super::is_via_ip(address), expected_is_via, "via-range predicate for {address}");
            assert_eq!(super::unmap_via(address), ip(expected_unmapped), "UnmapVia for {address}");
        }
    }

    #[test]
    fn ip_prefix_and_via_mapping_match_pinned_go_oracle() {
        let subnet = prefix("10.0.0.1/24");
        assert!(subnet.contains(ip("10.0.0.255")));
        assert!(!subnet.contains(ip("10.0.1.0")));
        assert!(!subnet.contains(ip("fd00::1")));
        assert!(prefix("::1/0").contains(ip("2001:db8::1")));
        assert!(!prefix("::1/0").contains(ip("192.0.2.1")));
        for invalid_bits in [-1, 33] {
            let invalid_v4 = IpPrefix::new(ip("100.64.0.1"), invalid_bits);
            assert!(!invalid_v4.is_valid());
            assert!(invalid_v4.is_ipv4());
            assert_eq!(invalid_v4.prefix_len(), -1);
            assert_eq!(invalid_v4.address(), ip("100.64.0.1"));
            assert_eq!(invalid_v4.to_string(), "invalid Prefix");
            assert!(!invalid_v4.contains(ip("100.64.0.1")));
            assert_eq!(super::map_via(7, invalid_v4).unwrap().to_string(), "fd7a:115c:a1e0:b1a:0:7:6440:1/95");
        }
        let invalid_v6 = IpPrefix::new(ip("fd7a:115c:a1e0:b1a::1"), 129);
        assert!(!invalid_v6.is_valid());
        assert!(invalid_v6.is_ipv6());
        assert_eq!(invalid_v6.prefix_len(), -1);
        assert_eq!(invalid_v6.address(), ip("fd7a:115c:a1e0:b1a::1"));
        assert_eq!(super::map_via(7, invalid_v6).unwrap_err().to_string(), "want IPv4 CIDR with a site ID");
        assert!(super::is_via_prefix(invalid_v6));

        for (site_id, input, expected) in [
            (7, "100.64.0.1/32", "fd7a:115c:a1e0:b1a:0:7:6440:1/128"),
            (0x1234_5678, "192.0.2.1/24", "fd7a:115c:a1e0:b1a:1234:5678:c000:201/120"),
            (0, "0.0.0.0/0", "fd7a:115c:a1e0:b1a::/96"),
        ] {
            let mapped = super::map_via(site_id, prefix(input)).unwrap();
            assert_eq!(mapped.to_string(), expected, "MapVia for {input}");
        }
        let error = super::map_via(42, prefix("fd00::1/64")).unwrap_err();
        assert_eq!(error, MapViaError);
        assert_eq!(error.to_string(), "want IPv4 CIDR with a site ID");

        for (input, expected) in [
            ("fd7a:115c:a1e0:b1a::/64", true),
            ("fd7a:115c:a1e0:b1a::/128", true),
            ("fd7a:115c:a1e0:b1a::/0", true),
            ("fd7a:115c:a1e0:b1b::/128", false),
            ("192.0.2.1/24", false),
        ] {
            assert_eq!(super::is_via_prefix(prefix(input)), expected, "IsViaPrefix for {input}");
        }
    }

    #[test]
    fn prefix_family_and_set_queries_match_pinned_go_oracle() {
        for (address, bits, expected_v4, expected_v6) in [
            ("192.0.2.1", 24, true, false),
            ("100.64.0.1", 33, true, false),
            ("fd7a:115c:a1e0:b1a::1", 64, false, true),
            ("fd7a:115c:a1e0:b1a::1", 129, false, true),
        ] {
            let prefix = IpPrefix::new(ip(address), bits);
            assert_eq!(super::prefix_is4(prefix), expected_v4, "PrefixIs4 for {address}/{bits}");
            assert_eq!(super::prefix_is6(prefix), expected_v6, "PrefixIs6 for {address}/{bits}");
        }

        let prefixes = [prefix("10.0.0.1/24"), prefix("fd7a:115c:a1e0:b1a::1/64"), IpPrefix::new(ip("192.0.2.1"), 33)];
        for (address, expected) in [
            ("10.0.0.255", true),
            ("10.0.1.0", false),
            ("fd7a:115c:a1e0:b1a::2", true),
            ("192.0.2.1", false),
            ("fd00::1", false),
        ] {
            assert_eq!(
                super::prefixes_contains_ip(&prefixes, ip(address)),
                expected,
                "PrefixesContainsIP for {address}"
            );
        }
    }

    #[test]
    fn first_tailscale_addresses_match_pinned_go_oracle() {
        assert_eq!(super::first_tailscale_addrs(&[]), (None, None));

        let v4 = [prefix("192.0.2.1/32"), prefix("100.64.0.1/32"), prefix("100.64.0.2/32")];
        assert_eq!(super::first_tailscale_addrs(&v4), (Some(ip("100.64.0.1")), None));

        let v6 = [prefix("2001:db8::1/128"), prefix("fd7a:115c:a1e0::1/128"), prefix("fd7a:115c:a1e0::2/128")];
        assert_eq!(super::first_tailscale_addrs(&v6), (None, Some(ip("fd7a:115c:a1e0::1"))));

        let mapped = [prefix("::ffff:100.64.0.3/128"), prefix("fd7a:115c:a1e0::1/128")];
        assert_eq!(super::first_tailscale_addrs(&mapped), (None, Some(ip("::ffff:100.64.0.3"))));

        let invalid_v4 = [IpPrefix::new(ip("100.64.0.1"), 33), prefix("100.64.0.2/32")];
        assert_eq!(super::first_tailscale_addrs(&invalid_v4), (Some(ip("100.64.0.1")), None));

        let chromeos_only = [prefix("100.115.92.1/32")];
        assert_eq!(super::first_tailscale_addrs(&chromeos_only), (None, None));
    }

    #[test]
    fn exit_route_helpers_and_filters_match_pinned_go_oracle() {
        assert_eq!(super::exit_routes(), [prefix("0.0.0.0/0"), prefix("::/0")]);
        assert!(super::is_exit_route(prefix("0.0.0.0/0")));
        assert!(super::is_exit_route(prefix("::/0")));
        assert!(!super::is_exit_route(prefix("10.0.0.1/0")));

        let no_routes = [prefix("10.0.0.1/24"), prefix("fd00::1/64")];
        assert!(!super::contains_exit_routes(&no_routes));
        assert!(!super::contains_exit_route(&no_routes));
        assert!(super::contains_non_exit_subnet_routes(&no_routes));
        assert!(matches!(super::without_exit_routes(&no_routes), Cow::Borrowed(_)));
        assert!(matches!(super::without_exit_route(&no_routes), Cow::Borrowed(_)));

        let v4_only = [prefix("0.0.0.0/0"), prefix("10.0.0.1/24"), prefix("10.0.0.1/0")];
        assert!(!super::contains_exit_routes(&v4_only));
        assert!(super::contains_exit_route(&v4_only));
        assert!(super::contains_non_exit_subnet_routes(&v4_only));
        assert!(matches!(super::without_exit_routes(&v4_only), Cow::Borrowed(_)));
        assert_eq!(super::without_exit_route(&v4_only).as_ref(), [prefix("10.0.0.1/24")].as_slice());

        let both = [
            prefix("0.0.0.0/0"),
            prefix("::/0"),
            prefix("10.0.0.1/24"),
            prefix("fd00::1/64"),
            prefix("10.0.0.1/0"),
            IpPrefix::new(ip("192.0.2.1"), 33),
        ];
        assert!(super::contains_exit_routes(&both));
        assert!(super::contains_exit_route(&both));
        assert!(super::contains_non_exit_subnet_routes(&both));
        let expected_filtered = [prefix("10.0.0.1/24"), prefix("fd00::1/64")];
        assert_eq!(super::without_exit_routes(&both).as_ref(), expected_filtered.as_slice());
        assert_eq!(super::without_exit_route(&both).as_ref(), expected_filtered.as_slice());

        let noncanonical_zero = [prefix("10.0.0.1/0")];
        assert!(!super::contains_exit_routes(&noncanonical_zero));
        assert!(super::contains_exit_route(&noncanonical_zero));
        assert!(!super::contains_non_exit_subnet_routes(&noncanonical_zero));
        assert!(matches!(super::without_exit_routes(&noncanonical_zero), Cow::Borrowed(_)));
        assert!(super::without_exit_route(&noncanonical_zero).is_empty());

        let invalid_only = [IpPrefix::new(ip("192.0.2.1"), 33)];
        assert!(!super::contains_exit_routes(&invalid_only));
        assert!(!super::contains_exit_route(&invalid_only));
        assert!(super::contains_non_exit_subnet_routes(&invalid_only));
        assert!(matches!(super::without_exit_route(&invalid_only), Cow::Borrowed(_)));
        assert_eq!(super::without_exit_routes(&invalid_only).as_ref(), invalid_only.as_slice());
    }

    #[test]
    fn address_translations_match_pinned_go_oracle() {
        for (input, expected) in [
            ("100.64.0.1", Some("fd7a:115c:a1e0:ab12:4843:cd96:6240:1")),
            ("100.115.92.1", None),
            ("100.115.94.1", Some("fd7a:115c:a1e0:ab12:4843:cd96:6273:5e01")),
            ("100.127.255.255", Some("fd7a:115c:a1e0:ab12:4843:cd96:627f:ffff")),
            ("192.0.2.1", None),
            ("::ffff:100.64.0.1", None),
        ] {
            let expected = expected.map(|value| value.parse::<std::net::Ipv6Addr>().unwrap());
            assert_eq!(super::tailscale4_to6(ip(input)), expected, "4-to-6 mapping for {input}");
        }

        for (input, expected) in [
            ("fd7a:115c:a1e0:ab12:4843:cd96:6200:0", Some("100.0.0.0")),
            ("fd7a:115c:a1e0:ab12:4843:cd96:6273:5e01", Some("100.115.94.1")),
            ("fd7a:115c:a1e0:ab12:4843:cd96:62ff:ffff", Some("100.255.255.255")),
            ("fd7a:115c:a1e0:ab12:4843:cd97:0:1", None),
            ("2001:db8::1", None),
            ("100.64.0.1", None),
        ] {
            let expected = expected.map(|value| value.parse::<std::net::Ipv4Addr>().unwrap());
            assert_eq!(super::tailscale6_to4(ip(input)), expected, "6-to-4 mapping for {input}");
        }
    }

    #[test]
    fn mapped_ipv6_is_unmapped_only_by_general_predicate() {
        let mapped_tailscale = ip("::ffff:100.64.0.1");
        assert!(is_tailscale_ip(mapped_tailscale));
        assert!(!is_tailscale_ipv4(mapped_tailscale));

        let mapped_chromeos = ip("::ffff:100.115.92.0");
        assert!(!is_tailscale_ip(mapped_chromeos));
        assert!(!is_tailscale_ipv4(mapped_chromeos));

        let mapped_outside = ip("::ffff:100.128.0.1");
        assert!(!is_tailscale_ip(mapped_outside));
        assert!(!is_tailscale_ipv4(mapped_outside));
    }
}
