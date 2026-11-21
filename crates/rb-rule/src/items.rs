//! Rule items (sing-box `route/rule/rule_item_*.go`).

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::rr::{Name, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use hickory_proto::serialize::txt::Parser;
use rb_common::domain::{AdGuardMatcher, Matcher as DomainMatcher};
use rb_common::ipset::IpSet;
use rb_config::DnsRecordOptions;
use regex::Regex;

use crate::{Metadata, RuleError};

#[derive(Debug, Clone)]
pub(crate) enum Item {
    Inbound(HashSet<String>),
    IpVersion(bool),
    Network(HashSet<String>),
    AuthUser(HashSet<String>),
    Protocol(HashSet<String>),
    QueryType(HashSet<u16>),
    Domain(Arc<DomainMatcher>),
    DomainKeyword(Vec<String>),
    DomainRegex(Vec<Regex>),
    AdGuard(Arc<AdGuardMatcher>),
    IpCidr {
        set: Arc<IpSet>,
        source: bool,
    },
    IpIsPrivate {
        source: bool,
    },
    IpAcceptAny,
    ResponseRcode(i32),
    ResponseRecord {
        section: ResponseSection,
        records: Vec<Record>,
    },
    Port {
        ports: HashSet<u16>,
        source: bool,
    },
    PortRange {
        ranges: Vec<(u16, u16)>,
        source: bool,
    },
    /// Items that need what rust-box does not have (a process searcher, a
    /// platform network monitor): they never match.
    Never,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ResponseSection {
    Answer,
    Ns,
    Extra,
}

/// Parses one DNS RR in sing-box's zone or standard base64 wire format.
pub(crate) fn parse_dns_record(options: &DnsRecordOptions, field: &str) -> Result<Record, RuleError> {
    if let Some(binary) = options.binary() {
        let mut decoder = BinDecoder::new(binary);
        let record = Record::read(&mut decoder).map_err(|_| RuleError(format!("{field}: parse binary DNS record")))?;
        if !decoder.is_empty() {
            return Err(RuleError(format!("{field}: parse binary DNS record")));
        }
        return Ok(record);
    }

    let input = format!("$TTL 3600\n{}\n", options.value);
    let (_, record_sets) = Parser::new(input, None, Some(Name::root()))
        .parse()
        .map_err(|_| RuleError(format!("{field}: bad DNS record: {}", options.value)))?;
    let mut records = record_sets.values().flat_map(|set| set.records_without_rrsigs());
    let record =
        records.next().cloned().ok_or_else(|| RuleError(format!("{field}: bad DNS record: {}", options.value)))?;
    if records.next().is_some() {
        return Err(RuleError(format!("{field}: bad DNS record: {}", options.value)));
    }
    Ok(record)
}

pub(crate) fn describe_dns_record(record: &Record) -> String {
    format!("{}\t{}\t{}\t{}\t{}", record.name(), record.ttl(), record.dns_class(), record.record_type(), record.data())
}

/// sing-box `N.IsPublicAddr`, negated (Go `netip.Addr` predicates, which
/// read an IPv4-mapped address as IPv4).
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
        }
    }
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

fn destination_host<'a>(metadata: &Metadata<'a>) -> Option<String> {
    metadata.domain.filter(|domain| !domain.is_empty()).map(str::to_lowercase)
}

impl Item {
    /// `NewDomainItem`.
    pub(crate) fn domain(domains: &[String], suffixes: &[String]) -> Result<Item, RuleError> {
        if domains.iter().any(String::is_empty) {
            return Err(RuleError("domain: empty item is not allowed".into()));
        }
        if suffixes.iter().any(String::is_empty) {
            return Err(RuleError("domain_suffix: empty item is not allowed".into()));
        }
        Ok(Item::Domain(Arc::new(DomainMatcher::new(domains, suffixes, false))))
    }

    /// `NewDomainRegexItem`.
    pub(crate) fn domain_regex(expressions: &[String]) -> Result<Item, RuleError> {
        let regexes = expressions
            .iter()
            .enumerate()
            .map(|(index, expression)| {
                Regex::new(expression).map_err(|error| RuleError(format!("parse expression {index}: {error}")))
            })
            .collect::<Result<_, _>>()?;
        Ok(Item::DomainRegex(regexes))
    }

    /// `NewIPCIDRItem`.
    pub(crate) fn ip_cidr(items: &[String], source: bool, field: &str) -> Result<Item, RuleError> {
        let set = IpSet::parse(items).map_err(|error| RuleError(format!("{field}: {error}")))?;
        Ok(Item::IpCidr { set: Arc::new(set), source })
    }

    pub(crate) fn port(ports: &[u16], source: bool) -> Item {
        Item::Port { ports: ports.iter().copied().collect(), source }
    }

    pub(crate) fn matches(&self, metadata: &Metadata) -> bool {
        match self {
            Item::Inbound(set) => set.contains(metadata.inbound),
            Item::IpVersion(v6) => {
                metadata.ip_version.is_some_and(|version| (version == 6) == *v6)
                    || metadata.destination_ip.is_some_and(|ip| ip.to_canonical().is_ipv6() == *v6)
            }
            Item::Network(set) => metadata.network.is_some_and(|network| set.contains(network)),
            Item::AuthUser(set) => metadata.user.is_some_and(|user| set.contains(user)),
            Item::Protocol(set) => metadata.protocol.is_some_and(|protocol| set.contains(protocol)),
            Item::QueryType(set) => {
                metadata.query_type.is_some_and(|query_type| query_type != 0 && set.contains(&query_type))
            }
            Item::Domain(matcher) => destination_host(metadata).is_some_and(|host| matcher.matches(&host)),
            Item::DomainKeyword(keywords) => destination_host(metadata)
                .is_some_and(|host| keywords.iter().any(|keyword| host.contains(keyword.as_str()))),
            Item::DomainRegex(regexes) => {
                destination_host(metadata).is_some_and(|host| regexes.iter().any(|regex| regex.is_match(&host)))
            }
            Item::AdGuard(matcher) => destination_host(metadata).is_some_and(|host| matcher.matches(&host)),
            Item::IpCidr { set, source } => {
                if *source || metadata.ip_cidr_match_source {
                    return metadata.source.is_some_and(|source| set.contains(source.ip().to_canonical()));
                }
                if metadata.destination_address_match_from_response {
                    if metadata.response_addresses.is_empty() {
                        return metadata.ip_cidr_accept_empty;
                    }
                    return metadata.response_addresses.iter().any(|ip| set.contains(ip.to_canonical()));
                }
                if let Some(ip) = metadata.destination_ip {
                    return set.contains(ip.to_canonical());
                }
                if !metadata.destination_addresses.is_empty() {
                    return metadata.destination_addresses.iter().any(|ip| set.contains(ip.to_canonical()));
                }
                metadata.ip_cidr_accept_empty
            }
            Item::IpIsPrivate { source: true } => metadata.source.is_some_and(|source| is_private(source.ip())),
            Item::IpIsPrivate { source: false } => {
                if metadata.destination_address_match_from_response {
                    return metadata.response_addresses.iter().any(|ip| is_private(*ip));
                }
                match metadata.destination_ip {
                    Some(ip) => is_private(ip),
                    None => metadata.destination_addresses.iter().any(|ip| is_private(*ip)),
                }
            }
            Item::IpAcceptAny => {
                if metadata.destination_address_match_from_response {
                    !metadata.response_addresses.is_empty()
                } else {
                    !metadata.destination_addresses.is_empty()
                }
            }
            Item::ResponseRcode(expected) => metadata.dns_response.is_some_and(|response| response.rcode == *expected),
            Item::ResponseRecord { section, records } => {
                let Some(response) = metadata.dns_response else { return false };
                let actual_records = match section {
                    ResponseSection::Answer => response.answers,
                    ResponseSection::Ns => response.ns,
                    ResponseSection::Extra => response.extra,
                };
                records.iter().any(|expected| actual_records.iter().any(|actual| expected == actual))
            }
            Item::Port { ports, source } => ports.contains(&port_of(metadata, *source)),
            Item::PortRange { ranges, source } => {
                let port = port_of(metadata, *source);
                ranges.iter().any(|(start, end)| port >= *start && port <= *end)
            }
            Item::Never => false,
        }
    }
}

/// The port an item looks at; 0 when there is none, as in Go.
fn port_of(metadata: &Metadata, source: bool) -> u16 {
    if source {
        metadata.source.map(|source| source.port()).unwrap_or(0)
    } else {
        metadata.destination_port.unwrap_or(0)
    }
}
