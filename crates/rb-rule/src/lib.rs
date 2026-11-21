//! Rule matching, mirroring sing-box `route/rule/` (`rule_abstract.go`,
//! `rule_default.go`, `rule_dns.go` and the `rule_item_*.go` items).
//!
//! A default rule's items fall into groups, as in sing-box
//! `abstractDefaultRule`: plain items must all match; within each address or
//! port group one item matching is enough (so `domain_suffix` and `ip_cidr`
//! in one rule mean "either"), and every group present must match.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use rb_config::{DnsRuleMatch, LogicalMode, Rule, RuleMatch};
use regex::Regex;

/// What a rule looks at (the fields of sing-box `adapter.InboundContext`
/// that the implemented items read).
#[derive(Debug, Clone, Default)]
pub struct Metadata<'a> {
    pub inbound: &'a str,
    pub network: Option<&'a str>,
    pub user: Option<&'a str>,
    pub protocol: Option<&'a str>,
    /// Sniffed domain, else the destination domain.
    pub domain: Option<&'a str>,
    pub source: Option<SocketAddr>,
    /// The destination IP when the destination is an address.
    pub destination_ip: Option<IpAddr>,
    /// Resolved addresses of a domain destination.
    pub destination_addresses: &'a [IpAddr],
    pub destination_port: Option<u16>,
    /// DNS rules only.
    pub query_type: Option<u16>,
}

#[derive(Debug)]
pub struct RuleError(pub String);

impl std::error::Error for RuleError {}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// sing-box `domain.Matcher`: exact domains, and suffixes. A suffix that
/// starts with `.` matches subdomains only; otherwise it matches the domain
/// itself and its subdomains.
#[derive(Debug, Default, Clone)]
pub struct DomainMatcher {
    exact: HashSet<String>,
    suffixes: Vec<String>,
    dotted_suffixes: Vec<String>,
}

impl DomainMatcher {
    pub fn new(domains: &[String], suffixes: &[String]) -> Result<Self, RuleError> {
        if domains.iter().any(String::is_empty) {
            return Err(RuleError("domain: empty item is not allowed".into()));
        }
        if suffixes.iter().any(String::is_empty) {
            return Err(RuleError("domain_suffix: empty item is not allowed".into()));
        }
        let mut matcher = DomainMatcher::default();
        for domain in domains {
            matcher.exact.insert(domain.to_ascii_lowercase());
        }
        for suffix in suffixes {
            let suffix = suffix.to_ascii_lowercase();
            if suffix.starts_with('.') {
                matcher.dotted_suffixes.push(suffix);
            } else {
                matcher.suffixes.push(suffix);
            }
        }
        Ok(matcher)
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty() && self.dotted_suffixes.is_empty()
    }

    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        if self.exact.contains(&domain) {
            return true;
        }
        if self.dotted_suffixes.iter().any(|suffix| domain.ends_with(suffix.as_str())) {
            return true;
        }
        self.suffixes.iter().any(|suffix| {
            domain == *suffix
                || (domain.len() > suffix.len()
                    && domain.ends_with(suffix.as_str())
                    && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.')
        })
    }
}

/// sing-box `N.IsPublicAddr`, negated.
pub fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            ip.is_private() || ip.is_loopback() || ip.is_multicast() || ip.is_link_local() || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
                || (segments[0] & 0xfe00) == 0xfc00 // unique local (netip IsPrivate)
                || (segments[0] & 0xffc0) == 0xfe80 // link-local unicast
                || segments[0] == 0xff01 // interface-local multicast (also multicast)
        }
    }
}

fn parse_cidrs(items: &[String], field: &str) -> Result<Vec<IpNet>, RuleError> {
    items
        .iter()
        .map(|item| {
            if let Ok(net) = item.parse::<IpNet>() {
                return Ok(net.trunc());
            }
            match item.parse::<IpAddr>() {
                Ok(IpAddr::V4(ip)) => Ok(IpNet::from(ipnet::Ipv4Net::new(ip, 32).unwrap())),
                Ok(IpAddr::V6(ip)) => Ok(IpNet::from(ipnet::Ipv6Net::new(ip, 128).unwrap())),
                Err(_) => Err(RuleError(format!("{field}: invalid prefix {item:?}"))),
            }
        })
        .collect()
}

fn cidr_contains(nets: &[IpNet], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    nets.iter().any(|net| net.contains(&ip))
}

/// `port_range` items: `start:end`, `:end` or `start:` (sing-box `NewPortRangeItem`).
pub fn parse_port_ranges(items: &[String], field: &str) -> Result<Vec<(u16, u16)>, RuleError> {
    items
        .iter()
        .map(|item| {
            let bad = || RuleError(format!("{field}: bad port range: {item}"));
            let (start, end) = item.split_once(':').ok_or_else(bad)?;
            let start = if start.is_empty() { 0 } else { start.parse().map_err(|_| bad())? };
            let end = if end.is_empty() { u16::MAX } else { end.parse().map_err(|_| bad())? };
            Ok((start, end))
        })
        .collect()
}

#[derive(Debug, Clone)]
enum Item {
    Inbound(HashSet<String>),
    IpVersion(bool),
    Network(HashSet<String>),
    AuthUser(HashSet<String>),
    Protocol(HashSet<String>),
    QueryType(HashSet<u16>),
    Domain(DomainMatcher),
    DomainKeyword(Vec<String>),
    DomainRegex(Vec<Regex>),
    IpCidr { nets: Vec<IpNet>, source: bool },
    IpIsPrivate { source: bool },
    Port { ports: HashSet<u16>, source: bool },
    PortRange { ranges: Vec<(u16, u16)>, source: bool },
}

impl Item {
    fn matches(&self, metadata: &Metadata) -> bool {
        match self {
            Item::Inbound(set) => set.contains(metadata.inbound),
            Item::IpVersion(v6) => metadata.destination_ip.is_some_and(|ip| ip.to_canonical().is_ipv6() == *v6),
            Item::Network(set) => metadata.network.is_some_and(|network| set.contains(network)),
            Item::AuthUser(set) => metadata.user.is_some_and(|user| set.contains(user)),
            Item::Protocol(set) => metadata.protocol.is_some_and(|protocol| set.contains(protocol)),
            Item::QueryType(set) => metadata.query_type.is_some_and(|query_type| set.contains(&query_type)),
            Item::Domain(matcher) => metadata.domain.is_some_and(|domain| matcher.matches(domain)),
            Item::DomainKeyword(keywords) => metadata.domain.is_some_and(|domain| {
                let domain = domain.to_ascii_lowercase();
                keywords.iter().any(|keyword| domain.contains(keyword.as_str()))
            }),
            Item::DomainRegex(regexes) => metadata.domain.is_some_and(|domain| {
                let domain = domain.to_ascii_lowercase();
                regexes.iter().any(|regex| regex.is_match(&domain))
            }),
            Item::IpCidr { nets, source: true } => {
                metadata.source.is_some_and(|source| cidr_contains(nets, source.ip()))
            }
            Item::IpCidr { nets, source: false } => match metadata.destination_ip {
                Some(ip) => cidr_contains(nets, ip),
                None => metadata.destination_addresses.iter().any(|ip| cidr_contains(nets, *ip)),
            },
            Item::IpIsPrivate { source: true } => metadata.source.is_some_and(|source| is_private(source.ip())),
            Item::IpIsPrivate { source: false } => match metadata.destination_ip {
                Some(ip) => is_private(ip),
                None => metadata.destination_addresses.iter().any(|ip| is_private(*ip)),
            },
            Item::Port { ports, source } => port_of(metadata, *source).is_some_and(|port| ports.contains(&port)),
            Item::PortRange { ranges, source } => port_of(metadata, *source)
                .is_some_and(|port| ranges.iter().any(|(start, end)| port >= *start && port <= *end)),
        }
    }
}

fn port_of(metadata: &Metadata, source: bool) -> Option<u16> {
    if source {
        metadata.source.map(|source| source.port())
    } else {
        metadata.destination_port
    }
}

/// A compiled default rule.
#[derive(Debug, Clone, Default)]
pub struct DefaultMatcher {
    items: Vec<Item>,
    source_address: Vec<Item>,
    source_port: Vec<Item>,
    destination_address: Vec<Item>,
    destination_port: Vec<Item>,
    invert: bool,
}

impl DefaultMatcher {
    fn is_empty(&self) -> bool {
        self.items.is_empty()
            && self.source_address.is_empty()
            && self.source_port.is_empty()
            && self.destination_address.is_empty()
            && self.destination_port.is_empty()
    }

    pub fn matches(&self, metadata: &Metadata) -> bool {
        if self.is_empty() {
            return true;
        }
        let group = |items: &[Item]| items.is_empty() || items.iter().any(|item| item.matches(metadata));
        let matched = self.items.iter().all(|item| item.matches(metadata))
            && group(&self.source_address)
            && group(&self.source_port)
            && group(&self.destination_address)
            && group(&self.destination_port);
        matched != self.invert
    }
}

fn set(items: &[String]) -> HashSet<String> {
    items.iter().cloned().collect()
}

struct Builder(DefaultMatcher);

impl Builder {
    fn common(
        &mut self,
        inbound: &[String],
        ip_version: Option<u8>,
        network: &[String],
        auth_user: &[String],
        protocol: &[String],
    ) -> Result<(), RuleError> {
        if !inbound.is_empty() {
            self.0.items.push(Item::Inbound(set(inbound)));
        }
        match ip_version {
            None => {}
            Some(4) => self.0.items.push(Item::IpVersion(false)),
            Some(6) => self.0.items.push(Item::IpVersion(true)),
            Some(other) => return Err(RuleError(format!("invalid ip version: {other}"))),
        }
        if !network.is_empty() {
            for item in network {
                if item != "tcp" && item != "udp" && item != "icmp" {
                    return Err(RuleError(format!("invalid network: {item}")));
                }
            }
            self.0.items.push(Item::Network(set(network)));
        }
        if !auth_user.is_empty() {
            self.0.items.push(Item::AuthUser(set(auth_user)));
        }
        if !protocol.is_empty() {
            self.0.items.push(Item::Protocol(set(protocol)));
        }
        Ok(())
    }

    fn domains(
        &mut self,
        domain: &[String],
        suffix: &[String],
        keyword: &[String],
        regex: &[String],
    ) -> Result<(), RuleError> {
        if !domain.is_empty() || !suffix.is_empty() {
            self.0.destination_address.push(Item::Domain(DomainMatcher::new(domain, suffix)?));
        }
        if !keyword.is_empty() {
            self.0
                .destination_address
                .push(Item::DomainKeyword(keyword.iter().map(|k| k.to_ascii_lowercase()).collect()));
        }
        if !regex.is_empty() {
            let regexes = regex
                .iter()
                .map(|pattern| Regex::new(pattern).map_err(|error| RuleError(format!("domain_regex: {error}"))))
                .collect::<Result<_, _>>()?;
            self.0.destination_address.push(Item::DomainRegex(regexes));
        }
        Ok(())
    }

    fn source(&mut self, cidr: &[String], private: bool, port: &[u16], port_range: &[String]) -> Result<(), RuleError> {
        if !cidr.is_empty() {
            self.0.source_address.push(Item::IpCidr { nets: parse_cidrs(cidr, "source_ip_cidr")?, source: true });
        }
        if private {
            self.0.source_address.push(Item::IpIsPrivate { source: true });
        }
        if !port.is_empty() {
            self.0.source_port.push(Item::Port { ports: port.iter().copied().collect(), source: true });
        }
        if !port_range.is_empty() {
            self.0
                .source_port
                .push(Item::PortRange { ranges: parse_port_ranges(port_range, "source_port_range")?, source: true });
        }
        Ok(())
    }

    fn destination_port(&mut self, port: &[u16], port_range: &[String]) -> Result<(), RuleError> {
        if !port.is_empty() {
            self.0.destination_port.push(Item::Port { ports: port.iter().copied().collect(), source: false });
        }
        if !port_range.is_empty() {
            self.0
                .destination_port
                .push(Item::PortRange { ranges: parse_port_ranges(port_range, "port_range")?, source: false });
        }
        Ok(())
    }
}

/// Compiles a route rule's match fields (sing-box `NewDefaultRule`).
pub fn compile_route_match(options: &RuleMatch) -> Result<DefaultMatcher, RuleError> {
    let mut builder = Builder(DefaultMatcher { invert: options.invert, ..Default::default() });
    builder.common(
        &options.inbound.0,
        options.ip_version,
        &options.network.0,
        &options.auth_user.0,
        &options.protocol.0,
    )?;
    builder.domains(&options.domain.0, &options.domain_suffix.0, &options.domain_keyword.0, &options.domain_regex.0)?;
    if !options.ip_cidr.is_empty() {
        builder
            .0
            .destination_address
            .push(Item::IpCidr { nets: parse_cidrs(&options.ip_cidr.0, "ip_cidr")?, source: false });
    }
    if options.ip_is_private {
        builder.0.destination_address.push(Item::IpIsPrivate { source: false });
    }
    builder.source(
        &options.source_ip_cidr.0,
        options.source_ip_is_private,
        &options.source_port.0,
        &options.source_port_range.0,
    )?;
    builder.destination_port(&options.port.0, &options.port_range.0)?;
    Ok(builder.0)
}

/// Compiles a DNS rule's match fields (sing-box `NewDefaultDNSRule`).
pub fn compile_dns_match(options: &DnsRuleMatch) -> Result<DefaultMatcher, RuleError> {
    let mut builder = Builder(DefaultMatcher { invert: options.invert, ..Default::default() });
    builder.common(
        &options.inbound.0,
        options.ip_version,
        &options.network.0,
        &options.auth_user.0,
        &options.protocol.0,
    )?;
    if !options.query_type.is_empty() {
        builder.0.items.push(Item::QueryType(options.query_type.iter().map(|query_type| query_type.0).collect()));
    }
    builder.domains(&options.domain.0, &options.domain_suffix.0, &options.domain_keyword.0, &options.domain_regex.0)?;
    builder.source(
        &options.source_ip_cidr.0,
        options.source_ip_is_private,
        &options.source_port.0,
        &options.source_port_range.0,
    )?;
    builder.destination_port(&options.port.0, &options.port_range.0)?;
    Ok(builder.0)
}

/// A compiled rule tree with its action.
#[derive(Debug, Clone)]
pub enum Compiled<A> {
    Default { matcher: DefaultMatcher, action: Option<A> },
    Logical { mode: LogicalMode, rules: Vec<Compiled<A>>, invert: bool, action: Option<A> },
}

impl<A> Compiled<A> {
    pub fn matches(&self, metadata: &Metadata) -> bool {
        match self {
            Compiled::Default { matcher, .. } => matcher.matches(metadata),
            Compiled::Logical { mode, rules, invert, .. } => {
                let matched = match mode {
                    LogicalMode::And => rules.iter().all(|rule| rule.matches(metadata)),
                    LogicalMode::Or => rules.iter().any(|rule| rule.matches(metadata)),
                };
                matched != *invert
            }
        }
    }

    pub fn action(&self) -> Option<&A> {
        match self {
            Compiled::Default { action, .. } | Compiled::Logical { action, .. } => action.as_ref(),
        }
    }
}

/// Compiles a rule tree, using `compile_match` for default rules.
pub fn compile<M, A: Clone>(
    rule: &Rule<M, A>,
    compile_match: &dyn Fn(&M) -> Result<DefaultMatcher, RuleError>,
) -> Result<Compiled<A>, RuleError> {
    Ok(match rule {
        Rule::Default { matcher, action } => {
            Compiled::Default { matcher: compile_match(matcher)?, action: action.clone() }
        }
        Rule::Logical { mode, rules, invert, action } => Compiled::Logical {
            mode: *mode,
            rules: rules.iter().map(|rule| compile(rule, compile_match)).collect::<Result<_, _>>()?,
            invert: *invert,
            action: action.clone(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rb_config::RouteRule;

    fn route(json: &str) -> Compiled<rb_config::RuleAction> {
        let rule: RouteRule = serde_json_lite(json);
        compile(&rule, &compile_route_match).unwrap()
    }

    fn serde_json_lite<T: serde::de::DeserializeOwned>(json: &str) -> T {
        serde_json::from_str(json).unwrap()
    }

    fn metadata<'a>(domain: Option<&'a str>, ip: Option<IpAddr>, port: u16) -> Metadata<'a> {
        Metadata {
            inbound: "in",
            network: Some("tcp"),
            domain,
            destination_ip: ip,
            destination_port: Some(port),
            source: Some("192.168.1.2:50000".parse().unwrap()),
            ..Default::default()
        }
    }

    #[test]
    fn domain_suffix_semantics() {
        let matcher = DomainMatcher::new(&[], &["example.com".into(), ".cn".into()]).unwrap();
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("www.Example.com"));
        assert!(!matcher.matches("badexample.com"));
        assert!(matcher.matches("baidu.cn"));
        assert!(!matcher.matches("cn"));
    }

    #[test]
    fn address_group_is_or_and_groups_are_and() {
        let rule = route(r#"{"domain_suffix":"example.com","ip_cidr":"10.0.0.0/8","port":443,"outbound":"x"}"#);
        assert!(rule.matches(&metadata(Some("a.example.com"), None, 443)));
        assert!(rule.matches(&metadata(None, Some("10.1.2.3".parse().unwrap()), 443)));
        assert!(!rule.matches(&metadata(Some("a.example.com"), None, 80)));
        assert!(!rule.matches(&metadata(Some("other.org"), None, 443)));
    }

    #[test]
    fn resolved_addresses_and_private() {
        let rule = route(r#"{"ip_is_private":true,"outbound":"x"}"#);
        let addresses = ["192.168.0.1".parse().unwrap()];
        let mut meta = metadata(Some("router.lan"), None, 80);
        assert!(!rule.matches(&meta));
        meta.destination_addresses = &addresses;
        assert!(rule.matches(&meta));
        assert!(rule.matches(&metadata(None, Some("::1".parse().unwrap()), 80)));
        assert!(!rule.matches(&metadata(None, Some("8.8.8.8".parse().unwrap()), 80)));
    }

    #[test]
    fn invert_logical_and_ranges() {
        let rule = route(r#"{"port_range":["1000:2000",":10"],"invert":true,"outbound":"x"}"#);
        assert!(!rule.matches(&metadata(None, None, 1500)));
        assert!(!rule.matches(&metadata(None, None, 5)));
        assert!(rule.matches(&metadata(None, None, 3000)));
        let rule = route(
            r#"{"type":"logical","mode":"or","rules":[{"domain":"a.com"},{"source_ip_cidr":"192.168.0.0/16"}],"outbound":"x"}"#,
        );
        assert!(rule.matches(&metadata(Some("b.com"), None, 1)));
        let rule =
            route(r#"{"type":"logical","mode":"and","rules":[{"domain":"a.com"},{"network":"udp"}],"outbound":"x"}"#);
        assert!(!rule.matches(&metadata(Some("a.com"), None, 1)));
        assert!(compile(&serde_json_lite::<RouteRule>(r#"{"port_range":"80","outbound":"x"}"#), &compile_route_match)
            .is_err());
    }

    #[test]
    fn empty_rule_matches_everything() {
        let rule = route(r#"{"action":"sniff"}"#);
        assert!(rule.matches(&metadata(None, None, 1)));
    }
}
