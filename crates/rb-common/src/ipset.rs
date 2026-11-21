//! An IP set: sorted, non-overlapping, non-adjacent address ranges, built
//! like `netipx.IPSetBuilder` (so binary rule-sets store the same ranges)
//! and turned back into prefixes like `netipx.IPSet.Prefixes`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IPv4 or IPv6 prefix (`netip.Prefix`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub addr: IpAddr,
    pub bits: u8,
}

impl Prefix {
    /// `netip.ParsePrefix`: an address, `/` and a decimal length.
    pub fn parse(text: &str) -> Result<Prefix, String> {
        let error = |reason: &str| format!("netip.ParsePrefix({text:?}): {reason}");
        let Some((address, bits)) = text.rsplit_once('/') else {
            return Err(error("no '/'"));
        };
        if address.contains('%') {
            return Err(error("IPv6 zones cannot be present in a prefix"));
        }
        let addr: IpAddr = parse_addr(address).map_err(|reason| error(&reason))?;
        if bits.is_empty() || bits.len() > 3 || !bits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(error(&format!("bad bits after slash: {bits:?}")));
        }
        if bits.len() > 1 && bits.starts_with('0') {
            return Err(error(&format!("bad bits after slash: {bits:?}")));
        }
        let bits: u16 = bits.parse().unwrap();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(error("prefix length out of range"));
        }
        Ok(Prefix { addr, bits: bits as u8 })
    }

    /// The first and last address (`netipx.RangeOfPrefix`).
    pub fn range(&self) -> Range {
        let (value, width) = to_u128(self.addr);
        let host_bits = u32::from(width - self.bits);
        let host_mask = if host_bits >= 128 { u128::MAX } else { (1u128 << host_bits) - 1 };
        let from = value & !host_mask;
        let to = from | host_mask;
        Range { from: from_u128(from, self.addr.is_ipv4()), to: from_u128(to, self.addr.is_ipv4()) }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

/// `netip.ParseAddr` (no zones, which rule items never take).
pub fn parse_addr(text: &str) -> Result<IpAddr, String> {
    if text.contains(':') {
        if text.contains('%') {
            return Err(format!("ParseAddr({text:?}): IPv6 zone not allowed"));
        }
        text.parse::<Ipv6Addr>().map(IpAddr::V6).map_err(|_| format!("ParseAddr({text:?}): unable to parse IP"))
    } else {
        text.parse::<Ipv4Addr>().map(IpAddr::V4).map_err(|_| format!("ParseAddr({text:?}): unable to parse IP"))
    }
}

/// The address as a 128-bit number and its width in bits.
fn to_u128(addr: IpAddr) -> (u128, u8) {
    match addr {
        IpAddr::V4(ip) => (u128::from(u32::from(ip)), 32),
        IpAddr::V6(ip) => (u128::from(ip), 128),
    }
}

fn from_u128(value: u128, v4: bool) -> IpAddr {
    if v4 {
        IpAddr::V4(Ipv4Addr::from(value as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(value))
    }
}

/// `netip.Addr.Next`.
fn next(addr: IpAddr) -> Option<IpAddr> {
    match addr {
        IpAddr::V4(ip) => u32::from(ip).checked_add(1).map(|value| IpAddr::V4(value.into())),
        IpAddr::V6(ip) => u128::from(ip).checked_add(1).map(|value| IpAddr::V6(value.into())),
    }
}

/// An inclusive range of addresses of one family (`netipx.IPRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Range {
    pub from: IpAddr,
    pub to: IpAddr,
}

impl Range {
    pub fn is_valid(&self) -> bool {
        self.from.is_ipv4() == self.to.is_ipv4() && self.from <= self.to
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.from <= ip && ip <= self.to
    }

    /// `IPRange.Prefixes`: the fewest prefixes that cover the range.
    pub fn prefixes(&self, output: &mut Vec<Prefix>) {
        if !self.is_valid() {
            return;
        }
        let v4 = self.from.is_ipv4();
        // netipx works on the 16-byte form, where IPv4 is mapped.
        let lift = |addr: IpAddr| match addr {
            IpAddr::V4(ip) => u128::from(ip.to_ipv6_mapped()),
            IpAddr::V6(ip) => u128::from(ip),
        };
        append_range_prefixes(output, v4, lift(self.from), lift(self.to));
    }
}

/// `mask6[n]`: the top `n` bits set.
fn mask6(bits: u32) -> u128 {
    if bits == 0 {
        0
    } else if bits >= 128 {
        u128::MAX
    } else {
        !((1u128 << (128 - bits)) - 1)
    }
}

fn compare_prefixes(a: u128, b: u128) -> (u32, bool) {
    let common = (a ^ b).leading_zeros();
    if common == 128 {
        return (common, true);
    }
    let m = mask6(common);
    (common, (a & !m) == 0 && (b | m) == u128::MAX)
}

fn append_range_prefixes(output: &mut Vec<Prefix>, v4: bool, a: u128, b: u128) {
    let (common, ok) = compare_prefixes(a, b);
    if ok {
        let addr = if v4 { IpAddr::V4(Ipv4Addr::from(a as u32)) } else { IpAddr::V6(Ipv6Addr::from(a)) };
        let bits = if v4 { common - 96 } else { common };
        output.push(Prefix { addr, bits: bits as u8 });
        return;
    }
    append_range_prefixes(output, v4, a, a | !mask6(common + 1));
    append_range_prefixes(output, v4, b & mask6(common + 1), b);
}

/// `netipx.IPSet`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpSet {
    ranges: Vec<Range>,
}

impl IpSet {
    /// A set from ranges as stored in a binary rule-set, taken as they
    /// are (sing-box casts them into an `IPSet` without normalizing).
    pub fn from_raw_ranges(ranges: Vec<Range>) -> Self {
        IpSet { ranges }
    }

    /// `IPSetBuilder.IPSet` over these ranges.
    pub fn from_ranges(ranges: impl IntoIterator<Item = Range>) -> Self {
        let mut ranges: Vec<Range> = ranges.into_iter().filter(Range::is_valid).collect();
        ranges.sort_by(|a, b| a.from.cmp(&b.from).then(a.to.cmp(&b.to)));
        let mut merged: Vec<Range> = Vec::with_capacity(ranges.len());
        for range in ranges {
            match merged.last_mut() {
                Some(previous) if next(previous.to) == Some(range.from) => previous.to = range.to,
                Some(previous) if previous.to < range.from => merged.push(range),
                Some(previous) if previous.to < range.to => previous.to = range.to,
                Some(_) => {}
                None => merged.push(range),
            }
        }
        IpSet { ranges: merged }
    }

    /// Builds a set from rule item strings: prefixes or bare addresses
    /// (sing-box `NewIPCIDRItem` / `writeRuleItemCIDR`). The error names
    /// the index of the bad item.
    pub fn parse<S: AsRef<str>>(items: &[S]) -> Result<Self, String> {
        let mut ranges = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let item = item.as_ref();
            match Prefix::parse(item) {
                Ok(prefix) => ranges.push(prefix.range()),
                Err(prefix_error) => match parse_addr(item) {
                    Ok(addr) => ranges.push(Range { from: addr, to: addr }),
                    Err(_) => return Err(format!("parse [{index}]: {prefix_error}")),
                },
            }
        }
        Ok(IpSet::from_ranges(ranges))
    }

    pub fn ranges(&self) -> &[Range] {
        &self.ranges
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// `IPSet.Contains`.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let index = self.ranges.partition_point(|range| range.from <= ip);
        index > 0 && self.ranges[index - 1].contains(ip)
    }

    /// `IPSet.Prefixes`.
    pub fn prefixes(&self) -> Vec<Prefix> {
        let mut output = Vec::with_capacity(self.ranges.len());
        for range in &self.ranges {
            range.prefixes(&mut output);
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefixes(set: &IpSet) -> Vec<String> {
        set.prefixes().iter().map(ToString::to_string).collect()
    }

    #[test]
    fn builder_merges_like_netipx() {
        let set = IpSet::parse(&["10.0.1.0/24", "10.0.0.0/24", "10.0.0.5", "192.168.0.0/16", "::1", "fe80::/10"])
            .unwrap();
        assert_eq!(set.ranges().len(), 4);
        assert_eq!(prefixes(&set), vec!["10.0.0.0/23", "192.168.0.0/16", "::1/128", "fe80::/10"]);
        assert!(set.contains("10.0.1.255".parse().unwrap()));
        assert!(!set.contains("10.0.2.0".parse().unwrap()));
        assert!(set.contains("fe80::1".parse().unwrap()));
        assert!(!set.contains("::2".parse().unwrap()));
        // A host part in a prefix is masked off.
        let set = IpSet::parse(&["1.2.3.4/8"]).unwrap();
        assert_eq!(prefixes(&set), vec!["1.0.0.0/8"]);
        // A range that is no single prefix splits.
        let set = IpSet::from_ranges([Range { from: "1.0.0.1".parse().unwrap(), to: "1.0.0.6".parse().unwrap() }]);
        assert_eq!(prefixes(&set), vec!["1.0.0.1/32", "1.0.0.2/31", "1.0.0.4/31", "1.0.0.6/32"]);
        assert_eq!(prefixes(&IpSet::parse(&["0.0.0.0/0", "::/0"]).unwrap()), vec!["0.0.0.0/0", "::/0"]);
        assert!(IpSet::parse(&["1.2.3.4/33"]).is_err());
        assert!(IpSet::parse(&["nope"]).unwrap_err().starts_with("parse [0]: "));
    }
}
