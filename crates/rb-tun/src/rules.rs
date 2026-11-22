//! What `auto_route` adds to the kernel on Linux: the routes in the TUN's
//! table and the policy rules in front of it (sing-tun `tun_linux.go`
//! `routes`/`rules`, `tun_rules.go` `BuildAutoRouteRanges` and
//! `ExcludedRanges`), as plain data, so the netlink side only sends it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rb_platform::Prefix;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const RT_TABLE_MAIN: i64 = 254;
pub const FR_ACT_UNREACHABLE: u8 = 7;
/// sing-tun `DefaultIPRoute2TableIndex`.
pub const DEFAULT_TABLE_INDEX: i64 = 2022;
/// sing-tun `DefaultIPRoute2RuleIndex`.
pub const DEFAULT_RULE_INDEX: i64 = 9000;
/// sing-tun `userEnd`.
const USER_END: u32 = 0xFFFF_FFFE;

/// An inclusive range (sing `ranges.Range[uint32]`).
pub type UidRange = (u32, u32);

/// One policy rule (`netlink.Rule`); `-1` and `None` are unset, as with
/// `netlink.NewRule()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub family: u8,
    pub priority: i64,
    pub table: i64,
    pub goto: i64,
    pub invert: bool,
    /// The rule action when set directly (`FR_ACT_UNREACHABLE`); else the
    /// action follows from `table` / `goto`.
    pub kind: u8,
    pub iif: String,
    pub oif: String,
    pub suppress_prefixlen: i64,
    pub mark: Option<u32>,
    pub mask: Option<u32>,
    pub dst: Option<Prefix>,
    pub src: Option<Prefix>,
    pub uid: Option<UidRange>,
    pub dport: Option<(u16, u16)>,
}

impl Rule {
    /// `netlink.NewRule()` with a family and priority.
    pub fn new(family: u8, priority: i64) -> Self {
        Rule {
            family,
            priority,
            table: -1,
            goto: -1,
            invert: false,
            kind: 0,
            iif: String::new(),
            oif: String::new(),
            suppress_prefixlen: -1,
            mark: None,
            mask: None,
            dst: None,
            src: None,
            uid: None,
            dport: None,
        }
    }
    fn table(mut self, table: i64) -> Self {
        self.table = table;
        self
    }
    fn goto(mut self, goto: i64) -> Self {
        self.goto = goto;
        self
    }
    fn iif(mut self, name: &str) -> Self {
        self.iif = name.to_string();
        self
    }
}

/// The options auto_route reads (a part of sing-tun `Options`).
#[derive(Debug, Clone, Default)]
pub struct RouteOptions {
    pub name: String,
    pub inet4_address: Vec<Prefix>,
    pub inet6_address: Vec<Prefix>,
    pub auto_route: bool,
    pub strict_route: bool,
    pub table_index: i64,
    pub rule_index: i64,
    pub inet4_route_address: Vec<Prefix>,
    pub inet6_route_address: Vec<Prefix>,
    pub inet4_route_exclude_address: Vec<Prefix>,
    pub inet6_route_exclude_address: Vec<Prefix>,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<UidRange>,
    pub exclude_uid: Vec<UidRange>,
    /// Android: another VPN is running (`AndroidVPNEnabled`), and whether to
    /// route through it anyway (`OverrideAndroidVPN`).
    pub android_vpn: Option<bool>,
}

/// sing `ranges.Merge`.
pub fn merge(mut ranges: Vec<UidRange>) -> Vec<UidRange> {
    ranges.sort();
    let mut merged: Vec<UidRange> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if u64::from(start) <= u64::from(last.1) + 1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// sing `ranges.Exclude`: `ranges` less `excluded`.
pub fn exclude(ranges: Vec<UidRange>, excluded: &[UidRange]) -> Vec<UidRange> {
    let mut result = merge(ranges);
    for &(cut_start, cut_end) in excluded {
        let mut next = Vec::new();
        for (start, end) in result {
            if cut_end < start || cut_start > end {
                next.push((start, end));
                continue;
            }
            if cut_start > start {
                next.push((start, cut_start - 1));
            }
            if cut_end < end {
                next.push((cut_end + 1, end));
            }
        }
        result = next;
    }
    result
}

/// sing `ranges.Revert`: what of `[start, end]` the ranges do not cover.
pub fn revert(start: u32, end: u32, ranges: &[UidRange]) -> Vec<UidRange> {
    let mut result = Vec::new();
    let mut cursor = u64::from(start);
    for &(range_start, range_end) in &merge(ranges.to_vec()) {
        if u64::from(range_start) > cursor {
            result.push((cursor as u32, range_start - 1));
        }
        cursor = cursor.max(u64::from(range_end) + 1);
    }
    if cursor <= u64::from(end) {
        result.push((cursor as u32, end));
    }
    result
}

/// sing-tun `buildExcludedRanges`: the UIDs whose traffic skips the TUN.
pub fn excluded_ranges(include: &[UidRange], exclude_uid: &[UidRange]) -> Vec<UidRange> {
    if !include.is_empty() {
        let included = exclude(include.to_vec(), exclude_uid);
        merge(revert(0, USER_END, &included))
    } else {
        merge(exclude_uid.to_vec())
    }
}

fn bits(prefix: &Prefix) -> (u128, u32) {
    match prefix.address {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    }
}

/// The interval `[first, last]` a prefix covers, in its family's width.
fn interval(prefix: &Prefix) -> (u128, u128) {
    let (value, width) = bits(prefix);
    let host = width - u32::from(prefix.len);
    let mask = if host == 128 { u128::MAX } else { (1u128 << host) - 1 };
    (value & !mask, (value & !mask) | mask)
}

/// The fewest prefixes covering `[first, last]` (go4.org/netipx `IPSet.Prefixes`).
fn to_prefixes(mut first: u128, last: u128, width: u32, v4: bool) -> Vec<Prefix> {
    let mut prefixes = Vec::new();
    loop {
        // The largest block aligned at `first` that stays within `last`.
        let mut host = if first == 0 { width } else { first.trailing_zeros().min(width) };
        while host > 0 {
            let size_minus_one = if host == 128 { u128::MAX } else { (1u128 << host) - 1 };
            if first.checked_add(size_minus_one).is_some_and(|end| end <= last) {
                break;
            }
            host -= 1;
        }
        let address = if v4 { IpAddr::V4(Ipv4Addr::from(first as u32)) } else { IpAddr::V6(Ipv6Addr::from(first)) };
        prefixes.push(Prefix::new(address, (width - host) as u8));
        let size_minus_one = if host == 128 { u128::MAX } else { (1u128 << host) - 1 };
        match first.checked_add(size_minus_one) {
            Some(end) if end < last => first = end + 1,
            _ => break,
        }
    }
    prefixes
}

/// The prefixes of `include` less `exclude` (one family).
pub fn subtract(include: &[Prefix], exclude: &[Prefix]) -> Vec<Prefix> {
    let Some(first) = include.first() else { return Vec::new() };
    let (_, width) = bits(first);
    let v4 = width == 32;
    let mut intervals: Vec<(u128, u128)> = include.iter().map(interval).collect();
    intervals.sort();
    let mut merged: Vec<(u128, u128)> = Vec::new();
    for (start, end) in intervals {
        match merged.last_mut() {
            Some(last) if last.1 == u128::MAX || start <= last.1 + 1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    for cut in exclude.iter().filter(|prefix| bits(prefix).1 == width) {
        let (cut_start, cut_end) = interval(cut);
        let mut next = Vec::new();
        for (start, end) in merged {
            if cut_end < start || cut_start > end {
                next.push((start, end));
                continue;
            }
            if cut_start > start {
                next.push((start, cut_start - 1));
            }
            if cut_end < end {
                next.push((cut_end + 1, end));
            }
        }
        merged = next;
    }
    merged.into_iter().flat_map(|(start, end)| to_prefixes(start, end, width, v4)).collect()
}

/// sing-tun `BuildAutoRouteRanges` on Linux.
pub fn route_ranges(options: &RouteOptions) -> Vec<Prefix> {
    let mut ranges = Vec::new();
    let family = |addresses: &[Prefix], route: &[Prefix], exclude: &[Prefix], all: Prefix, out: &mut Vec<Prefix>| {
        if addresses.is_empty() {
            return;
        }
        let base = if !route.is_empty() {
            route.to_vec()
        } else if options.auto_route {
            vec![all]
        } else {
            Vec::new()
        };
        if exclude.is_empty() {
            out.extend(base);
        } else {
            out.extend(subtract(&base, exclude));
        }
    };
    family(
        &options.inet4_address,
        &options.inet4_route_address,
        &options.inet4_route_exclude_address,
        Prefix::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        &mut ranges,
    );
    family(
        &options.inet6_address,
        &options.inet6_route_address,
        &options.inet6_route_exclude_address,
        Prefix::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        &mut ranges,
    );
    ranges
}

/// The address after `prefix`'s own, when it is inside the prefix (sing-tun
/// `HasNextAddress(prefix, 1)` and `Addr().Next()`).
pub fn next_address(prefix: &Prefix) -> Option<IpAddr> {
    let next = match prefix.address {
        IpAddr::V4(v4) => IpAddr::V4(u32::from(v4).checked_add(1)?.into()),
        IpAddr::V6(v6) => IpAddr::V6(u128::from(v6).checked_add(1)?.into()),
    };
    prefix.contains(next).then_some(next)
}

/// The gateway of a route to `destination` (sing-tun `Inet4GatewayAddr` /
/// `Inet6GatewayAddr`): the address after the TUN's first one on Linux,
/// none on Android.
pub fn gateway(options: &RouteOptions, destination: &Prefix) -> Option<IpAddr> {
    if cfg!(target_os = "android") {
        return None;
    }
    let addresses = if destination.address.is_ipv4() { &options.inet4_address } else { &options.inet6_address };
    addresses.first().and_then(next_address)
}

/// The routes in the TUN's table (sing-tun `routes`): without auto_route,
/// an IPv6 TUN still routes everything into its own table.
pub fn routes(options: &RouteOptions) -> Vec<Prefix> {
    let mut ranges = route_ranges(options);
    if !options.auto_route && !options.inet6_address.is_empty() && options.inet6_route_address.is_empty() {
        ranges.push(Prefix::new(Ipv6Addr::UNSPECIFIED.into(), 0));
    }
    ranges
}

/// The policy rules (sing-tun `rules`, Linux and Android, without the
/// auto_redirect mark mode). Without auto_route an IPv6 TUN gets one rule
/// sending its own traffic to its table; `next_index6` is the priority for
/// it (sing-tun `nextIndex6`, found from the kernel's rules).
pub fn rules(options: &RouteOptions, next_index6: i64) -> Vec<Rule> {
    let android = cfg!(target_os = "android");
    if !options.auto_route {
        if !options.inet6_address.is_empty() {
            let mut rule = Rule::new(AF_INET6, next_index6).table(options.table_index);
            rule.oif = options.name.clone();
            return vec![rule];
        }
        return Vec::new();
    }
    let p4 = !options.inet4_address.is_empty();
    let p6 = !options.inet6_address.is_empty();
    if !p4 && !p6 {
        return Vec::new();
    }
    let mut rules = Vec::new();
    let excluded = excluded_ranges(&options.include_uid, &options.exclude_uid);
    let start = options.rule_index;
    let mut priority = start;
    let mut priority6 = priority;
    let nop = start + 10;
    for &range in &excluded {
        if p4 {
            let mut rule = Rule::new(AF_INET, priority).goto(nop);
            rule.uid = Some(range);
            rules.push(rule);
        }
        if p6 {
            let mut rule = Rule::new(AF_INET6, priority6).goto(nop);
            rule.uid = Some(range);
            rules.push(rule);
        }
    }
    if !excluded.is_empty() {
        if p4 {
            priority += 1;
        }
        if p6 {
            priority6 += 1;
        }
    }
    if !options.include_interface.is_empty() {
        let (matched, matched6) = (priority + 2, priority6 + 2);
        for name in &options.include_interface {
            if p4 {
                rules.push(Rule::new(AF_INET, priority).iif(name).goto(matched));
            }
            if p6 {
                rules.push(Rule::new(AF_INET6, priority6).iif(name).goto(matched6));
            }
        }
        if p4 {
            priority += 1;
        }
        if p6 {
            priority6 += 1;
        }
        if p4 {
            rules.push(Rule::new(AF_INET, priority).goto(nop));
            priority += 1;
            rules.push(Rule::new(AF_INET, matched));
            priority += 1;
        }
        if p6 {
            rules.push(Rule::new(AF_INET6, priority6).goto(nop));
            priority6 += 1;
            rules.push(Rule::new(AF_INET6, matched6));
            priority6 += 1;
        }
    } else if !options.exclude_interface.is_empty() {
        for name in &options.exclude_interface {
            if p4 {
                rules.push(Rule::new(AF_INET, priority).iif(name).goto(nop));
            }
            if p6 {
                rules.push(Rule::new(AF_INET6, priority6).iif(name).goto(nop));
            }
        }
        if p4 {
            priority += 1;
        }
        if p6 {
            priority6 += 1;
        }
    }
    if let (true, Some(override_vpn)) = (android, options.android_vpn) {
        const PROTECTED_FROM_VPN: u32 = 0x20000;
        if p4 {
            let mut rule = Rule::new(AF_INET, priority).goto(nop);
            rule.mark = override_vpn.then_some(PROTECTED_FROM_VPN);
            rule.mask = Some(PROTECTED_FROM_VPN);
            rules.push(rule);
            priority += 1;
        }
        if p6 {
            let mut rule = Rule::new(AF_INET6, priority6).goto(nop);
            rule.mark = override_vpn.then_some(PROTECTED_FROM_VPN);
            rule.mask = Some(PROTECTED_FROM_VPN);
            rules.push(rule);
            priority6 += 1;
        }
    }
    if options.strict_route {
        if !p4 {
            let mut rule = Rule::new(AF_INET, priority);
            rule.kind = FR_ACT_UNREACHABLE;
            rules.push(rule);
            priority += 1;
        }
        if !p6 {
            let mut rule = Rule::new(AF_INET6, priority6);
            rule.kind = FR_ACT_UNREACHABLE;
            rules.push(rule);
            priority6 += 1;
        }
    }
    let table = options.table_index;
    if !android {
        if p4 {
            for address in &options.inet4_address {
                let mut rule = Rule::new(AF_INET, priority).table(table);
                rule.dst = Some(address.masked());
                rules.push(rule);
            }
            priority += 1;
            let mut rule = Rule::new(AF_INET, priority).table(table);
            rule.suppress_prefixlen = 0;
            rules.push(rule);
            priority += 1;
        }
        if p6 {
            let mut rule = Rule::new(AF_INET6, priority6).table(table);
            rule.suppress_prefixlen = 0;
            rules.push(rule);
            priority6 += 1;
        }
        for (enabled, family, priority) in [(p4, AF_INET, priority), (p6, AF_INET6, priority6)] {
            if enabled {
                let mut rule = Rule::new(family, priority).table(RT_TABLE_MAIN);
                rule.invert = true;
                rule.dport = Some((53, 53));
                rule.suppress_prefixlen = 0;
                rules.push(rule);
            }
        }
    }
    if p4 {
        rules.push(Rule::new(AF_INET, priority).iif(&options.name).goto(nop));
        priority += 1;
        let mut rule = Rule::new(AF_INET, priority).iif("lo").table(table);
        rule.invert = true;
        rules.push(rule);
        let mut rule = Rule::new(AF_INET, priority).iif("lo").table(table);
        rule.src = Some(Prefix::new(Ipv4Addr::UNSPECIFIED.into(), 32));
        rules.push(rule);
        for address in &options.inet4_address {
            let mut rule = Rule::new(AF_INET, priority).iif("lo").table(table);
            rule.src = Some(address.masked());
            rules.push(rule);
        }
    }
    if p6 {
        for address in &options.inet6_address {
            let mut rule = Rule::new(AF_INET6, priority6).iif("lo").table(table);
            rule.src = Some(address.masked());
            rules.push(rule);
        }
        priority6 += 1;
        rules.push(Rule::new(AF_INET6, priority6).iif(&options.name).goto(nop));
        let mut rule = Rule::new(AF_INET6, priority6).iif("lo").goto(nop);
        rule.src = Some(Prefix::new(Ipv6Addr::UNSPECIFIED.into(), 1));
        rules.push(rule);
        let mut rule = Rule::new(AF_INET6, priority6).iif("lo").goto(nop);
        rule.src = Some(Prefix::new(Ipv6Addr::from(1u128 << 127).into(), 1));
        rules.push(rule);
        priority6 += 1;
        rules.push(Rule::new(AF_INET6, priority6).table(table));
    }
    if p4 {
        rules.push(Rule::new(AF_INET, nop));
    }
    if p6 {
        rules.push(Rule::new(AF_INET6, nop));
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn prefixes(list: &[&str]) -> Vec<Prefix> {
        list.iter()
            .map(|text| {
                let (address, len) = text.split_once('/').unwrap();
                Prefix::new(address.parse().unwrap(), len.parse().unwrap())
            })
            .collect()
    }

    /// The cases of `testdata/sing_tun_rules_test.go.txt`.
    fn case(name: &str) -> RouteOptions {
        let v4 = prefixes(&["172.19.0.1/30"]);
        let v6 = prefixes(&["fdfe:dcba:9876::1/126"]);
        let base = RouteOptions {
            name: "tun0".into(),
            auto_route: true,
            table_index: DEFAULT_TABLE_INDEX,
            rule_index: DEFAULT_RULE_INDEX,
            ..Default::default()
        };
        match name {
            "v4_auto" => RouteOptions { inet4_address: v4, ..base },
            "dual_auto_strict" => RouteOptions { strict_route: true, inet4_address: v4, inet6_address: v6, ..base },
            "v4_strict" => RouteOptions { strict_route: true, inet4_address: v4, ..base },
            "uid" => RouteOptions {
                name: "tun1".into(),
                inet4_address: v4,
                inet6_address: v6,
                include_uid: vec![(1000, 1000), (2000, 3000)],
                exclude_uid: vec![(2500, 2500)],
                ..base
            },
            "exclude_uid" => RouteOptions { inet4_address: v4, exclude_uid: vec![(0, 0)], ..base },
            "include_if" => RouteOptions {
                inet4_address: v4,
                inet6_address: v6,
                include_interface: vec!["eth0".into(), "wlan0".into()],
                ..base
            },
            "exclude_if" => RouteOptions { inet4_address: v4, exclude_interface: vec!["docker0".into()], ..base },
            "route_exclude" => RouteOptions {
                inet4_address: v4,
                inet6_address: v6,
                inet4_route_exclude_address: prefixes(&["192.168.0.0/16", "10.0.0.0/8"]),
                inet6_route_exclude_address: prefixes(&["fc00::/7"]),
                ..base
            },
            "route_address" => RouteOptions {
                inet4_address: v4,
                inet4_route_address: prefixes(&["1.0.0.0/8", "8.8.0.0/16"]),
                inet4_route_exclude_address: prefixes(&["8.8.8.8/32"]),
                ..base
            },
            "route_address_no_auto" => RouteOptions {
                auto_route: false,
                inet4_address: v4,
                inet4_route_address: prefixes(&["198.18.0.0/15"]),
                ..base
            },
            "v6_only" => RouteOptions { strict_route: true, inet6_address: v6, ..base },
            _ => unreachable!("{name}"),
        }
    }

    fn to_json(rule: &Rule) -> Value {
        let mut value = serde_json::json!({
            "family": rule.family, "priority": rule.priority, "table": rule.table, "goto": rule.goto,
            "invert": rule.invert, "type": rule.kind, "iif": rule.iif, "oif": rule.oif,
            "suppress_prefixlen": rule.suppress_prefixlen, "mark": rule.mark.unwrap_or(0),
            "mark_set": rule.mark.is_some(), "mask": rule.mask.map(i64::from).unwrap_or(-1),
        });
        let object = value.as_object_mut().unwrap();
        if let Some(dst) = rule.dst {
            object.insert("dst".into(), dst.to_string().into());
        }
        if let Some(src) = rule.src {
            object.insert("src".into(), src.to_string().into());
        }
        if let Some((start, end)) = rule.uid {
            object.insert("uid".into(), format!("{start}-{end}").into());
        }
        if let Some((start, end)) = rule.dport {
            object.insert("dport".into(), format!("{start}-{end}").into());
        }
        value
    }

    /// Against what sing-tun itself builds (generated with Go from the
    /// sing-tun version sing-box v1.14.4 uses).
    #[test]
    fn same_rules_and_routes_as_sing_tun() {
        let vectors: Value = serde_json::from_str(include_str!("../testdata/sing_tun_rules.json")).unwrap();
        for (name, expected) in vectors.as_object().unwrap() {
            let options = case(name);
            let rules: Vec<Value> = rules(&options, 0).iter().map(to_json).collect();
            let expected_rules = expected["rules"].as_array().cloned().unwrap_or_default();
            assert_eq!(rules.len(), expected_rules.len(), "{name}: {rules:#?}");
            for (index, (rule, want)) in rules.iter().zip(&expected_rules).enumerate() {
                assert_eq!(rule, want, "{name} rule {index}");
            }
            let routes: Vec<String> = route_ranges(&options).iter().map(Prefix::to_string).collect();
            let expected_routes: Vec<String> = expected["routes"]
                .as_array()
                .map(|list| list.iter().map(|it| it.as_str().unwrap().to_string()).collect())
                .unwrap_or_default();
            assert_eq!(routes, expected_routes, "{name}");
        }
    }

    #[test]
    fn uid_ranges() {
        assert_eq!(
            excluded_ranges(&[(1000, 1000), (2000, 3000)], &[(2500, 2500)]),
            vec![(0, 999), (1001, 1999), (2500, 2500), (3001, USER_END)]
        );
        assert_eq!(excluded_ranges(&[], &[(5, 9), (1, 4)]), vec![(1, 9)]);
        assert_eq!(excluded_ranges(&[(0, USER_END)], &[]), Vec::<UidRange>::new());
    }
}
