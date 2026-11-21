//! Rule matching, mirroring sing-box `route/rule/`: `rule_abstract.go`
//! (default and logical rules with their match groups), `match_state.go`,
//! `rule_default.go`, `rule_dns.go`, `rule_headless.go`,
//! `rule_item_rule_set.go` and the `rule_item_*.go` items.
//!
//! A default rule's items fall into groups, as in sing-box
//! `abstractDefaultRule`: plain items must all match; within each address or
//! port group one item matching is enough (so `domain_suffix` and `ip_cidr`
//! in one rule mean "either"), and every group present must match. A
//! `rule_set` item merges a rule-set's single default rule into the outer
//! rule's groups, and destination IP items can be deferred until the DNS
//! response is known (the legacy DNS address filter).

mod items;
mod rule_set;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rb_config::{DefaultHeadlessRule, DnsRuleMatch, HeadlessRule, LogicalMode, Rule, RuleMatch};

use items::Item;
pub use items::{is_private, parse_port_ranges};
pub use rule_set::{
    rule_set_metadata, RuleSet, RuleSetContent, RuleSetItem, RuleSetMetadata, RuleSets, StaticRuleSet, UpdateValidator,
};

/// What a rule looks at (the fields of sing-box `adapter.InboundContext`
/// that the implemented items read), and the match state sing-box keeps in
/// the same struct.
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
    /// `metadata.IPVersion`: from the query type in DNS rules.
    pub ip_version: Option<u8>,
    /// DNS rules only.
    pub query_type: Option<u16>,
    /// The A/AAAA answers of a successful DNS response, when
    /// `destination_address_match_from_response` is set.
    pub response_addresses: &'a [IpAddr],

    pub ip_cidr_match_source: bool,
    pub ip_cidr_accept_empty: bool,
    pub ignore_destination_ip_cidr_match: bool,
    pub destination_address_match_from_response: bool,
    pub deferred_ip_cidr_match_groups: u8,
}

impl Metadata<'_> {
    /// `ResetRuleCache`.
    pub fn reset_rule_cache(&mut self) {
        self.ip_cidr_match_source = false;
        self.ip_cidr_accept_empty = false;
        self.reset_rule_match_cache();
    }

    /// `ResetRuleMatchCache`.
    pub fn reset_rule_match_cache(&mut self) {
        self.deferred_ip_cidr_match_groups = 0;
    }

    fn snapshot(&self) -> (bool, bool, u8) {
        (self.ip_cidr_match_source, self.ip_cidr_accept_empty, self.deferred_ip_cidr_match_groups)
    }

    fn restore(&mut self, snapshot: (bool, bool, u8)) {
        (self.ip_cidr_match_source, self.ip_cidr_accept_empty, self.deferred_ip_cidr_match_groups) = snapshot;
    }
}

#[derive(Debug)]
pub struct RuleError(pub String);

impl std::error::Error for RuleError {}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn error(message: impl Into<String>) -> RuleError {
    RuleError(message.into())
}

// ruleMatchState
const SOURCE_ADDRESS: u8 = 1;
const SOURCE_PORT: u8 = 2;
const DESTINATION_ADDRESS: u8 = 4;
const DESTINATION_PORT: u8 = 8;

/// `ruleGroupMatch`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct GroupMatch {
    required: u8,
    satisfied: u8,
}

impl GroupMatch {
    fn done(self) -> bool {
        self.required & !self.satisfied == 0
    }

    fn merge(self, other: GroupMatch) -> GroupMatch {
        GroupMatch { required: self.required | other.required, satisfied: self.satisfied | other.satisfied }
    }
}

/// `abstractDefaultRule` without its action.
#[derive(Debug, Default)]
pub struct DefaultMatcher {
    items: Vec<Item>,
    source_address: Vec<Item>,
    source_port: Vec<Item>,
    destination_address: Vec<Item>,
    destination_ip_cidr: Vec<Item>,
    destination_port: Vec<Item>,
    rule_set: Option<RuleSetItem>,
    item_count: usize,
    invert: bool,
    /// The items' descriptions in the order they were added (`String()`).
    descriptions: Vec<String>,
}

fn match_any(items: &[Item], metadata: &mut Metadata) -> bool {
    items.iter().any(|item| item.matches(metadata))
}

impl DefaultMatcher {
    fn push(&mut self, group: fn(&mut DefaultMatcher) -> &mut Vec<Item>, item: Item, description: String) {
        group(self).push(item);
        self.item_count += 1;
        self.descriptions.push(description);
    }

    /// `abstractDefaultRule.Match`.
    pub fn matches(&self, metadata: &mut Metadata) -> bool {
        if self.item_count == 0 && self.rule_set.is_none() {
            return true;
        }
        let matched = self.match_inner(metadata);
        if self.invert {
            if !matched {
                metadata.deferred_ip_cidr_match_groups = 0;
                return true;
            }
            return metadata.deferred_ip_cidr_match_groups != 0;
        }
        matched
    }

    fn match_inner(&self, metadata: &mut Metadata) -> bool {
        let groups = self.evaluate_groups(metadata);
        for item in &self.items {
            if !item.matches(metadata) {
                return false;
            }
        }
        let matched = match &self.rule_set {
            Some(rule_set) => rule_set.match_with_outer_groups(metadata, groups),
            None => groups.done(),
        };
        if matched {
            metadata.deferred_ip_cidr_match_groups &= !groups.satisfied;
        }
        matched
    }

    /// `evaluateForMerge`.
    pub(crate) fn evaluate_for_merge(&self, metadata: &mut Metadata) -> Option<GroupMatch> {
        let groups = self.evaluate_groups(metadata);
        for item in &self.items {
            if !item.matches(metadata) {
                return None;
            }
        }
        Some(groups)
    }

    fn evaluate_groups(&self, metadata: &mut Metadata) -> GroupMatch {
        let mut groups = GroupMatch::default();
        if !self.source_address.is_empty() {
            groups.required |= SOURCE_ADDRESS;
            if match_any(&self.source_address, metadata) {
                groups.satisfied |= SOURCE_ADDRESS;
            }
        }
        // destinationIPCIDRMatchesSource
        if metadata.ip_cidr_match_source && !self.destination_ip_cidr.is_empty() {
            groups.required |= SOURCE_ADDRESS;
            if groups.satisfied & SOURCE_ADDRESS == 0 && match_any(&self.destination_ip_cidr, metadata) {
                groups.satisfied |= SOURCE_ADDRESS;
            }
        }
        if !self.source_port.is_empty() {
            groups.required |= SOURCE_PORT;
            if match_any(&self.source_port, metadata) {
                groups.satisfied |= SOURCE_PORT;
            }
        }
        if !self.destination_address.is_empty() {
            groups.required |= DESTINATION_ADDRESS;
            if match_any(&self.destination_address, metadata) {
                groups.satisfied |= DESTINATION_ADDRESS;
            }
        }
        // destinationIPCIDRMatchesDestination
        if !metadata.ignore_destination_ip_cidr_match
            && !metadata.ip_cidr_match_source
            && !self.destination_ip_cidr.is_empty()
        {
            groups.required |= DESTINATION_ADDRESS;
            if groups.satisfied & DESTINATION_ADDRESS == 0 && match_any(&self.destination_ip_cidr, metadata) {
                groups.satisfied |= DESTINATION_ADDRESS;
            }
        }
        if !self.destination_port.is_empty() {
            groups.required |= DESTINATION_PORT;
            if match_any(&self.destination_port, metadata) {
                groups.satisfied |= DESTINATION_PORT;
            }
        }
        if metadata.ignore_destination_ip_cidr_match
            && !metadata.ip_cidr_match_source
            && !self.destination_ip_cidr.is_empty()
            && self.destination_address.is_empty()
        {
            metadata.deferred_ip_cidr_match_groups |= DESTINATION_ADDRESS;
        }
        groups
    }

    /// Whether this default rule has destination IP items, or a rule-set
    /// with them (`DefaultDNSRule.WithAddressLimit`).
    pub fn with_address_limit(&self) -> bool {
        !self.destination_ip_cidr.is_empty()
            || self.rule_set.as_ref().is_some_and(RuleSetItem::contains_destination_ip_cidr_rule)
    }

    /// The single default rule a rule-set can merge into an outer rule
    /// (`mergeableRuleIn`).
    pub(crate) fn mergeable(&self) -> bool {
        !self.invert && self.rule_set.is_none()
    }
}

/// `abstractLogicalRule` without its action.
#[derive(Debug)]
pub struct LogicalMatcher {
    mode: LogicalMode,
    rules: Vec<Matcher>,
    invert: bool,
}

impl LogicalMatcher {
    /// `abstractLogicalRule.Match`.
    pub fn matches(&self, metadata: &mut Metadata) -> bool {
        let mut matched = false;
        let mut deferred = 0u8;
        let snapshot = metadata.snapshot();
        match self.mode {
            LogicalMode::And => {
                matched = true;
                for rule in &self.rules {
                    metadata.reset_rule_cache();
                    if !rule.matches(metadata) {
                        matched = false;
                        deferred = 0;
                        break;
                    }
                    deferred |= metadata.deferred_ip_cidr_match_groups;
                }
            }
            LogicalMode::Or => {
                for rule in &self.rules {
                    metadata.reset_rule_cache();
                    if rule.matches(metadata) {
                        matched = true;
                        if metadata.deferred_ip_cidr_match_groups == 0 {
                            deferred = 0;
                            break;
                        }
                        deferred |= metadata.deferred_ip_cidr_match_groups;
                    }
                }
            }
        }
        metadata.restore(snapshot);
        if matched {
            metadata.deferred_ip_cidr_match_groups |= deferred;
        }
        if self.invert {
            if !matched {
                return true;
            }
            return deferred != 0;
        }
        matched
    }
}

/// A rule's match part: default or logical.
#[derive(Debug)]
pub enum Matcher {
    Default(DefaultMatcher),
    Logical(LogicalMatcher),
}

impl Matcher {
    pub fn matches(&self, metadata: &mut Metadata) -> bool {
        match self {
            Matcher::Default(matcher) => matcher.matches(metadata),
            Matcher::Logical(matcher) => matcher.matches(metadata),
        }
    }

    pub fn with_address_limit(&self) -> bool {
        match self {
            Matcher::Default(matcher) => matcher.with_address_limit(),
            Matcher::Logical(matcher) => matcher.rules.iter().any(Matcher::with_address_limit),
        }
    }

    /// `LegacyPreMatch`: the rule without its destination IP items.
    pub fn legacy_pre_match(&self, metadata: &mut Metadata) -> bool {
        metadata.ignore_destination_ip_cidr_match = true;
        let matched = self.matches(metadata);
        metadata.ignore_destination_ip_cidr_match = false;
        matched
    }

    /// `MatchAddressLimit`: the rule against the addresses of a response.
    pub fn match_address_limit(&self, metadata: &Metadata, response_addresses: &[IpAddr]) -> bool {
        let mut metadata =
            Metadata { response_addresses, destination_address_match_from_response: true, ..metadata.clone() };
        metadata.reset_rule_cache();
        self.matches(&mut metadata)
    }
}

/// A compiled rule with its action.
#[derive(Debug)]
pub struct Compiled<A> {
    pub matcher: Matcher,
    pub action: Option<A>,
}

impl<A> Compiled<A> {
    pub fn matches(&self, metadata: &mut Metadata) -> bool {
        self.matcher.matches(metadata)
    }

    pub fn action(&self) -> Option<&A> {
        self.action.as_ref()
    }
}

/// What default rules are compiled with.
pub struct Context<'a> {
    pub rule_sets: &'a RuleSets,
    /// The DNS router's legacy mode (DNS rules only).
    pub legacy_dns_mode: bool,
    /// Whether a network manager exists: sing-box only adds the
    /// `network_type`, `network_is_*`, `wifi_*` and interface address
    /// items of headless rules when it does (it does in a box, not in the
    /// `rule-set match` command).
    pub network_manager: bool,
}

impl<'a> Context<'a> {
    pub fn new(rule_sets: &'a RuleSets) -> Self {
        Context { rule_sets, legacy_dns_mode: false, network_manager: true }
    }
}

/// `[a b c]` lists as sing-box items describe them.
#[derive(Clone, Copy)]
enum ListStyle {
    /// Every item.
    All,
    /// The first three and `...` (domain, ip_cidr, domain_keyword).
    Ellipsis,
    /// The first three, without `...` (the regex items).
    Truncate,
}

fn describe<S: AsRef<str>>(name: &str, items: &[S], style: ListStyle) -> String {
    let items: Vec<&str> = items.iter().map(AsRef::as_ref).collect();
    match (items.len(), style) {
        (1, _) => format!("{name}={}", items[0]),
        (count, ListStyle::Ellipsis) if count > 3 => format!("{name}=[{}...]", items[..3].join(" ")),
        (count, ListStyle::Truncate) if count > 3 => format!("{name}=[{}]", items[..3].join(" ")),
        _ => format!("{name}=[{}]", items.join(" ")),
    }
}

fn describe_domain(domains: &[String], suffixes: &[String]) -> String {
    let mut description = String::new();
    if !domains.is_empty() {
        description = describe("domain", domains, ListStyle::Ellipsis);
    }
    if !suffixes.is_empty() {
        if !description.is_empty() {
            description.push(' ');
        }
        description.push_str(&describe("domain_suffix", suffixes, ListStyle::Ellipsis));
    }
    description
}

fn query_type_name(query_type: u16) -> String {
    rb_config::query_types::name(query_type).map(str::to_string).unwrap_or_else(|| query_type.to_string())
}

fn add_domain_items(
    matcher: &mut DefaultMatcher,
    domain: &[String],
    suffix: &[String],
    keyword: &[String],
    regex: &[String],
) -> Result<(), RuleError> {
    if !domain.is_empty() || !suffix.is_empty() {
        matcher.push(|m| &mut m.destination_address, Item::domain(domain, suffix)?, describe_domain(domain, suffix));
    }
    if !keyword.is_empty() {
        matcher.push(
            |m| &mut m.destination_address,
            Item::DomainKeyword(keyword.to_vec()),
            describe("domain_keyword", keyword, ListStyle::Ellipsis),
        );
    }
    if !regex.is_empty() {
        matcher.push(
            |m| &mut m.destination_address,
            Item::domain_regex(regex)?,
            describe("domain_regex", regex, ListStyle::Truncate),
        );
    }
    Ok(())
}

fn add_ip_cidr(matcher: &mut DefaultMatcher, items: &[String], source: bool, field: &str) -> Result<(), RuleError> {
    let item = Item::ip_cidr(items, source, field)?;
    let name = if source { "source_ip_cidr" } else { "ip_cidr" };
    let description = describe(name, items, ListStyle::Ellipsis);
    if source {
        matcher.push(|m| &mut m.source_address, item, description);
    } else {
        matcher.push(|m| &mut m.destination_ip_cidr, item, description);
    }
    Ok(())
}

fn add_ports(
    matcher: &mut DefaultMatcher,
    source_port: &[u16],
    source_port_range: &[String],
    port: &[u16],
    port_range: &[String],
) -> Result<(), RuleError> {
    let numbers = |ports: &[u16]| ports.iter().map(u16::to_string).collect::<Vec<_>>();
    if !source_port.is_empty() {
        matcher.push(
            |m| &mut m.source_port,
            Item::port(source_port, true),
            describe("source_port", &numbers(source_port), ListStyle::All),
        );
    }
    if !source_port_range.is_empty() {
        matcher.push(
            |m| &mut m.source_port,
            Item::PortRange { ranges: parse_port_ranges(source_port_range, "source_port_range")?, source: true },
            describe("source_port_range", source_port_range, ListStyle::All),
        );
    }
    if !port.is_empty() {
        matcher.push(
            |m| &mut m.destination_port,
            Item::port(port, false),
            describe("port", &numbers(port), ListStyle::All),
        );
    }
    if !port_range.is_empty() {
        matcher.push(
            |m| &mut m.destination_port,
            Item::PortRange { ranges: parse_port_ranges(port_range, "port_range")?, source: false },
            describe("port_range", port_range, ListStyle::All),
        );
    }
    Ok(())
}

fn add_ip_version(matcher: &mut DefaultMatcher, ip_version: Option<u8>) -> Result<(), RuleError> {
    match ip_version {
        None | Some(0) => {}
        Some(4) => matcher.push(|m| &mut m.items, Item::IpVersion(false), "ip_version=4".into()),
        Some(6) => matcher.push(|m| &mut m.items, Item::IpVersion(true), "ip_version=6".into()),
        Some(other) => return Err(error(format!("invalid ip version: {other}"))),
    }
    Ok(())
}

fn add_sets(matcher: &mut DefaultMatcher, name: &str, values: &[String], item: fn(HashSet<String>) -> Item) {
    if !values.is_empty() {
        matcher.push(|m| &mut m.items, item(values.iter().cloned().collect()), describe(name, values, ListStyle::All));
    }
}

fn add_query_types(matcher: &mut DefaultMatcher, query_types: &[rb_config::types::QueryType]) {
    if !query_types.is_empty() {
        let names: Vec<String> = query_types.iter().map(|query_type| query_type_name(query_type.0)).collect();
        matcher.push(
            |m| &mut m.items,
            Item::QueryType(query_types.iter().map(|query_type| query_type.0).collect()),
            describe("query_type", &names, ListStyle::All),
        );
    }
}

/// Compiles a route rule's match fields (sing-box `NewDefaultRule`).
pub fn compile_route_match(options: &RuleMatch, context: &Context) -> Result<DefaultMatcher, RuleError> {
    let mut matcher = DefaultMatcher { invert: options.invert, ..Default::default() };
    add_sets(&mut matcher, "inbound", &options.inbound.0, Item::Inbound);
    add_ip_version(&mut matcher, options.ip_version)?;
    add_sets(&mut matcher, "network", &options.network.0, Item::Network);
    add_sets(&mut matcher, "auth_user", &options.auth_user.0, Item::AuthUser);
    add_sets(&mut matcher, "protocol", &options.protocol.0, Item::Protocol);
    add_domain_items(
        &mut matcher,
        &options.domain.0,
        &options.domain_suffix.0,
        &options.domain_keyword.0,
        &options.domain_regex.0,
    )?;
    if !options.source_ip_cidr.is_empty() {
        add_ip_cidr(&mut matcher, &options.source_ip_cidr.0, true, "source_ip_cidr")?;
    }
    if options.source_ip_is_private {
        matcher.push(|m| &mut m.source_address, Item::IpIsPrivate { source: true }, "source_ip_is_private=true".into());
    }
    if !options.ip_cidr.is_empty() {
        add_ip_cidr(&mut matcher, &options.ip_cidr.0, false, "ipcidr")?;
    }
    if options.ip_is_private {
        matcher.push(|m| &mut m.destination_ip_cidr, Item::IpIsPrivate { source: false }, "ip_is_private=true".into());
    }
    add_ports(
        &mut matcher,
        &options.source_port.0,
        &options.source_port_range.0,
        &options.port.0,
        &options.port_range.0,
    )?;
    if !options.rule_set.is_empty() {
        if options.rule_set_ipcidr_match_source {
            return Err(error(
                "rule_set_ipcidr_match_source is deprecated in sing-box 1.10.0 and removed in sing-box 1.11.0",
            ));
        }
        matcher.rule_set = Some(RuleSetItem::new(
            context.rule_sets,
            &options.rule_set.0,
            options.rule_set_ip_cidr_match_source,
            false,
        )?);
        matcher.descriptions.push(describe("rule_set", &options.rule_set.0, ListStyle::All));
    }
    Ok(matcher)
}

/// Compiles a DNS rule's match fields (sing-box `NewDefaultDNSRule`).
pub fn compile_dns_match(options: &DnsRuleMatch, context: &Context) -> Result<DefaultMatcher, RuleError> {
    let mut matcher = DefaultMatcher { invert: options.invert, ..Default::default() };
    add_sets(&mut matcher, "inbound", &options.inbound.0, Item::Inbound);
    add_ip_version(&mut matcher, options.ip_version)?;
    add_query_types(&mut matcher, &options.query_type.0);
    add_sets(&mut matcher, "network", &options.network.0, Item::Network);
    add_sets(&mut matcher, "auth_user", &options.auth_user.0, Item::AuthUser);
    add_sets(&mut matcher, "protocol", &options.protocol.0, Item::Protocol);
    add_domain_items(
        &mut matcher,
        &options.domain.0,
        &options.domain_suffix.0,
        &options.domain_keyword.0,
        &options.domain_regex.0,
    )?;
    if !options.source_ip_cidr.is_empty() {
        add_ip_cidr(&mut matcher, &options.source_ip_cidr.0, true, "source_ip_cidr")?;
    }
    if !options.ip_cidr.is_empty() {
        add_ip_cidr(&mut matcher, &options.ip_cidr.0, false, "ip_cidr")?;
    }
    if options.source_ip_is_private {
        matcher.push(|m| &mut m.source_address, Item::IpIsPrivate { source: true }, "source_ip_is_private=true".into());
    }
    if options.ip_is_private {
        matcher.push(|m| &mut m.destination_ip_cidr, Item::IpIsPrivate { source: false }, "ip_is_private=true".into());
    }
    if options.ip_accept_any {
        matcher.push(|m| &mut m.destination_ip_cidr, Item::IpAcceptAny, "ip_accept_any=true".into());
    }
    add_ports(
        &mut matcher,
        &options.source_port.0,
        &options.source_port_range.0,
        &options.port.0,
        &options.port_range.0,
    )?;
    if options.rule_set_ip_cidr_accept_empty && !context.legacy_dns_mode {
        return Err(error(rb_config::deprecated::RULE_SET_IP_CIDR_ACCEPT_EMPTY.message_with_link()));
    }
    if !options.rule_set.is_empty() {
        if options.rule_set_ipcidr_match_source {
            return Err(error(
                "rule_set_ipcidr_match_source is deprecated in sing-box 1.10.0 and removed in sing-box 1.11.0",
            ));
        }
        matcher.rule_set = Some(RuleSetItem::new(
            context.rule_sets,
            &options.rule_set.0,
            options.rule_set_ip_cidr_match_source,
            options.rule_set_ip_cidr_accept_empty,
        )?);
        matcher.descriptions.push(describe("rule_set", &options.rule_set.0, ListStyle::All));
    }
    Ok(matcher)
}

/// Compiles a headless rule of a rule-set (sing-box `NewHeadlessRule`).
pub fn compile_headless(rule: &HeadlessRule, context: &Context) -> Result<Matcher, RuleError> {
    match rule {
        HeadlessRule::Default(options) => {
            if !options.is_valid() {
                return Err(error("missing conditions"));
            }
            Ok(Matcher::Default(compile_default_headless(options, context)?))
        }
        HeadlessRule::Logical(options) => {
            if !options.is_valid() {
                return Err(error("missing conditions"));
            }
            let mode = match options.mode.as_str() {
                "and" => LogicalMode::And,
                "or" => LogicalMode::Or,
                other => return Err(error(format!("unknown logical mode: {other}"))),
            };
            let rules = options
                .rules
                .iter()
                .enumerate()
                .map(|(index, rule)| {
                    compile_headless(rule, context).map_err(|error| RuleError(format!("sub rule[{index}]: {error}")))
                })
                .collect::<Result<_, _>>()?;
            Ok(Matcher::Logical(LogicalMatcher { mode, rules, invert: options.invert }))
        }
    }
}

fn check_regexes(expressions: &[String]) -> Result<(), RuleError> {
    for (index, expression) in expressions.iter().enumerate() {
        regex::Regex::new(expression).map_err(|error| RuleError(format!("parse expression {index}: {error}")))?;
    }
    Ok(())
}

/// `NewDefaultHeadlessRule`.
pub fn compile_default_headless(options: &DefaultHeadlessRule, context: &Context) -> Result<DefaultMatcher, RuleError> {
    let mut matcher = DefaultMatcher { invert: options.invert, ..Default::default() };
    add_query_types(&mut matcher, &options.query_type.0);
    add_sets(&mut matcher, "network", &options.network.0, Item::Network);
    if !options.domain.is_empty() || !options.domain_suffix.is_empty() {
        matcher.push(
            |m| &mut m.destination_address,
            Item::domain(&options.domain.0, &options.domain_suffix.0)?,
            describe_domain(&options.domain.0, &options.domain_suffix.0),
        );
    } else if let Some(domain_matcher) = &options.domain_matcher {
        matcher.push(
            |m| &mut m.destination_address,
            Item::Domain(Arc::new(domain_matcher.clone())),
            "domain/domain_suffix=<binary>".into(),
        );
    }
    if !options.domain_keyword.is_empty() {
        matcher.push(
            |m| &mut m.destination_address,
            Item::DomainKeyword(options.domain_keyword.0.clone()),
            describe("domain_keyword", &options.domain_keyword.0, ListStyle::Ellipsis),
        );
    }
    if !options.domain_regex.is_empty() {
        matcher.push(
            |m| &mut m.destination_address,
            Item::domain_regex(&options.domain_regex.0).map_err(|error| RuleError(format!("domain_regex: {error}")))?,
            describe("domain_regex", &options.domain_regex.0, ListStyle::Truncate),
        );
    }
    if !options.source_ip_cidr.is_empty() {
        add_ip_cidr(&mut matcher, &options.source_ip_cidr.0, true, "source_ip_cidr")?;
    } else if let Some(set) = &options.source_ip_set {
        matcher.push(
            |m| &mut m.source_address,
            Item::IpCidr { set: Arc::new(set.clone()), source: true },
            "source_ip_cidr=<binary>".into(),
        );
    }
    if !options.ip_cidr.is_empty() {
        add_ip_cidr(&mut matcher, &options.ip_cidr.0, false, "ipcidr")?;
    } else if let Some(set) = &options.ip_set {
        matcher.push(
            |m| &mut m.destination_ip_cidr,
            Item::IpCidr { set: Arc::new(set.clone()), source: false },
            "ip_cidr=<binary>".into(),
        );
    }
    add_ports(
        &mut matcher,
        &options.source_port.0,
        &options.source_port_range.0,
        &options.port.0,
        &options.port_range.0,
    )?;
    // Process and package items: rust-box has no process searcher, so they
    // match nothing (as in sing-box when the process is not found).
    if !options.process_name.is_empty() {
        matcher.push(|m| &mut m.items, Item::Never, describe("process_name", &options.process_name.0, ListStyle::All));
    }
    if !options.process_path.is_empty() {
        matcher.push(|m| &mut m.items, Item::Never, describe("process_path", &options.process_path.0, ListStyle::All));
    }
    if !options.process_path_regex.is_empty() {
        check_regexes(&options.process_path_regex.0)
            .map_err(|error| RuleError(format!("process_path_regex: {error}")))?;
        matcher.push(
            |m| &mut m.items,
            Item::Never,
            describe("process_path_regex", &options.process_path_regex.0, ListStyle::Truncate),
        );
    }
    if !options.package_name.is_empty() {
        matcher.push(|m| &mut m.items, Item::Never, describe("package_name", &options.package_name.0, ListStyle::All));
    }
    if !options.package_name_regex.is_empty() {
        check_regexes(&options.package_name_regex.0)
            .map_err(|error| RuleError(format!("package_name_regex: {error}")))?;
        matcher.push(
            |m| &mut m.items,
            Item::Never,
            describe("package_name_regex", &options.package_name_regex.0, ListStyle::Truncate),
        );
    }
    if context.network_manager {
        // The platform network items need sing-box's network manager with a
        // platform interface; without one they match nothing.
        let names: Vec<&str> = options.network_type.iter().map(|kind| kind.name()).collect();
        let platform = [
            (!options.network_type.is_empty(), describe("network_type", &names, ListStyle::All)),
            (options.network_is_expensive, "network_is_expensive=true".to_string()),
            (options.network_is_constrained, "network_is_constrained=true".to_string()),
            (!options.wifi_ssid.is_empty(), describe("wifi_ssid", &options.wifi_ssid.0, ListStyle::All)),
            (!options.wifi_bssid.is_empty(), describe("wifi_bssid", &options.wifi_bssid.0, ListStyle::All)),
            (
                options.network_interface_address.as_ref().is_some_and(|entries| !entries.is_empty()),
                "network_interface_address=<platform>".to_string(),
            ),
            (!options.default_interface_address.is_empty(), "default_interface_address=<platform>".to_string()),
        ];
        for (present, description) in platform {
            if present {
                matcher.push(|m| &mut m.items, Item::Never, description);
            }
        }
    }
    if !options.adguard_domain.is_empty() {
        matcher.push(
            |m| &mut m.destination_address,
            Item::AdGuard(Arc::new(rb_common::domain::AdGuardMatcher::new(&options.adguard_domain))),
            "!adguard_domain_rules=<binary>".into(),
        );
    } else if let Some(adguard) = &options.adguard_domain_matcher {
        matcher.push(
            |m| &mut m.destination_address,
            Item::AdGuard(Arc::new(adguard.clone())),
            "!adguard_domain_rules=<binary>".into(),
        );
    }
    Ok(matcher)
}

impl std::fmt::Display for DefaultMatcher {
    /// `abstractDefaultRule.String`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let items = self.descriptions.join(" ");
        if self.invert {
            write!(f, "!({items})")
        } else {
            f.write_str(&items)
        }
    }
}

impl std::fmt::Display for LogicalMatcher {
    /// `abstractLogicalRule.String`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let op = match self.mode {
            LogicalMode::And => " && ",
            LogicalMode::Or => " || ",
        };
        let rules = self.rules.iter().map(ToString::to_string).collect::<Vec<_>>().join(op);
        if self.invert {
            write!(f, "!({rules})")
        } else {
            f.write_str(&rules)
        }
    }
}

impl std::fmt::Display for Matcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Matcher::Default(matcher) => matcher.fmt(f),
            Matcher::Logical(matcher) => matcher.fmt(f),
        }
    }
}

/// Compiles a route or DNS rule tree, using `compile_match` for default
/// rules (sing-box `NewRule` / `NewDNSRule`); nested rules lose their
/// action.
pub fn compile<M, A: Clone>(
    rule: &Rule<M, A>,
    compile_match: &dyn Fn(&M) -> Result<DefaultMatcher, RuleError>,
) -> Result<Compiled<A>, RuleError> {
    fn matcher_of<M, A>(
        rule: &Rule<M, A>,
        compile_match: &dyn Fn(&M) -> Result<DefaultMatcher, RuleError>,
    ) -> Result<Matcher, RuleError> {
        Ok(match rule {
            Rule::Default { matcher, .. } => Matcher::Default(compile_match(matcher)?),
            Rule::Logical { mode, rules, invert, .. } => Matcher::Logical(LogicalMatcher {
                mode: *mode,
                rules: rules
                    .iter()
                    .enumerate()
                    .map(|(index, rule)| {
                        matcher_of(rule, compile_match)
                            .map_err(|error| RuleError(format!("sub rule[{index}]: {error}")))
                    })
                    .collect::<Result<_, _>>()?,
                invert: *invert,
            }),
        })
    }
    Ok(Compiled { matcher: matcher_of(rule, compile_match)?, action: rule.action().cloned() })
}

#[cfg(test)]
mod tests;
