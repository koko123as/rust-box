//! Route and DNS rules, mirroring sing-box `option/rule.go`,
//! `option/rule_dns.go` and `option/rule_action.go`.
//!
//! A rule object carries both its match fields and its action fields
//! (sing-box composes them with `badjson.UnmarshallExcluded`). Here the keys
//! that belong to the rule's action are split off first, and the rest must
//! all be known match fields.

use serde::de::{self, DeserializeOwned, Deserializer};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::dial::NetworkStrategy;
use crate::rule_set::Prefixable;
use crate::types::{DomainStrategy, Duration, Listable, QueryType};

/// Match fields shared by route rules (sing-box `RawDefaultRule`, the subset
/// rust-box implements).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleMatch {
    #[serde(default)]
    pub inbound: Listable<String>,
    #[serde(default)]
    pub ip_version: Option<u8>,
    #[serde(default)]
    pub network: Listable<String>,
    #[serde(default)]
    pub auth_user: Listable<String>,
    #[serde(default)]
    pub protocol: Listable<String>,
    #[serde(default)]
    pub domain: Listable<String>,
    #[serde(default)]
    pub domain_suffix: Listable<String>,
    #[serde(default)]
    pub domain_keyword: Listable<String>,
    #[serde(default)]
    pub domain_regex: Listable<String>,
    #[serde(default)]
    pub source_ip_cidr: Listable<String>,
    #[serde(default)]
    pub source_ip_is_private: bool,
    #[serde(default)]
    pub ip_cidr: Listable<String>,
    #[serde(default)]
    pub ip_is_private: bool,
    #[serde(default)]
    pub source_port: Listable<u16>,
    #[serde(default)]
    pub source_port_range: Listable<String>,
    #[serde(default)]
    pub port: Listable<u16>,
    #[serde(default)]
    pub port_range: Listable<String>,
    #[serde(default)]
    pub clash_mode: String,
    #[serde(default)]
    pub rule_set: Listable<String>,
    #[serde(default)]
    pub rule_set_ip_cidr_match_source: bool,
    /// Removed in sing-box 1.11.0; rejected when the rule is built.
    #[serde(default)]
    pub rule_set_ipcidr_match_source: bool,
    #[serde(default)]
    pub invert: bool,
}

/// Match fields of DNS rules (sing-box `RawDefaultDNSRule`, the subset
/// rust-box implements).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRuleMatch {
    #[serde(default)]
    pub inbound: Listable<String>,
    #[serde(default)]
    pub ip_version: Option<u8>,
    #[serde(default)]
    pub query_type: Listable<QueryType>,
    #[serde(default)]
    pub network: Listable<String>,
    #[serde(default)]
    pub auth_user: Listable<String>,
    #[serde(default)]
    pub protocol: Listable<String>,
    #[serde(default)]
    pub domain: Listable<String>,
    #[serde(default)]
    pub domain_suffix: Listable<String>,
    #[serde(default)]
    pub domain_keyword: Listable<String>,
    #[serde(default)]
    pub domain_regex: Listable<String>,
    #[serde(default)]
    pub source_ip_cidr: Listable<String>,
    #[serde(default)]
    pub source_ip_is_private: bool,
    #[serde(default)]
    pub source_port: Listable<u16>,
    #[serde(default)]
    pub source_port_range: Listable<String>,
    #[serde(default)]
    pub port: Listable<u16>,
    #[serde(default)]
    pub port_range: Listable<String>,
    #[serde(default)]
    pub clash_mode: String,
    #[serde(default)]
    pub rule_set: Listable<String>,
    #[serde(default)]
    pub rule_set_ip_cidr_match_source: bool,
    /// Deprecated in sing-box 1.11.0: only allowed in the legacy DNS mode.
    #[serde(default)]
    pub rule_set_ip_cidr_accept_empty: bool,
    /// Removed in sing-box 1.11.0; rejected when the rule is built.
    #[serde(default)]
    pub rule_set_ipcidr_match_source: bool,
    /// Address filter items: they match the addresses of the response
    /// (sing-box's legacy DNS mode).
    #[serde(default)]
    pub ip_cidr: Listable<String>,
    #[serde(default)]
    pub ip_is_private: bool,
    #[serde(default)]
    pub ip_accept_any: bool,
    #[serde(default)]
    pub match_response: DnsMatchResponse,
    #[serde(default)]
    pub response_rcode: Option<DnsResponseCode>,
    #[serde(default)]
    pub response_answer: Listable<DnsRecordOptions>,
    #[serde(default)]
    pub response_ns: Listable<DnsRecordOptions>,
    #[serde(default)]
    pub response_extra: Listable<DnsRecordOptions>,
    #[serde(default)]
    pub invert: bool,
}

/// sing-box DNS `match_response`: false disables it, true selects the latest
/// anonymous evaluate response, and a string selects an evaluated tag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsMatchResponse {
    pub enabled: bool,
    pub tag: String,
}

impl<'de> Deserialize<'de> for DnsMatchResponse {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Bool(enabled) => Ok(Self { enabled, tag: String::new() }),
            Value::String(tag) if tag.is_empty() => Err(de::Error::custom("empty match_response tag")),
            Value::String(tag) => Ok(Self { enabled: true, tag }),
            _ => Err(de::Error::custom("invalid match_response value")),
        }
    }
}

/// A DNS response code, accepted as either an integer or the IANA mnemonic
/// used by sing-box (for example, `NOERROR` or `NXDOMAIN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsResponseCode(pub i32);

impl<'de> Deserialize<'de> for DnsResponseCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Number(number) => number
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .map(Self)
                .ok_or_else(|| de::Error::custom("invalid DNS response code")),
            Value::String(name) => {
                rcode_from_name(&name).map(Self).ok_or_else(|| de::Error::custom(format!("unknown rcode: {name}")))
            }
            _ => Err(de::Error::custom("invalid DNS response code")),
        }
    }
}

fn rcode_from_name(name: &str) -> Option<i32> {
    Some(match name {
        "NOERROR" => 0,
        "FORMERR" => 1,
        "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "NOTIMP" => 4,
        "REFUSED" => 5,
        "YXDOMAIN" => 6,
        "YXRRSET" => 7,
        "NXRRSET" => 8,
        "NOTAUTH" => 9,
        "NOTZONE" => 10,
        "DSOTYPENI" => 11,
        "BADVERS" | "BADSIG" => 16,
        "BADKEY" => 17,
        "BADTIME" => 18,
        "BADMODE" => 19,
        "BADNAME" => 20,
        "BADALG" => 21,
        "BADTRUNC" => 22,
        "BADCOOKIE" => 23,
        _ => return None,
    })
}

/// A DNS resource-record matcher. The raw zone-format or base64 form is kept
/// for the DNS rule compiler to validate and compare against response records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecordOptions {
    pub value: String,
    binary: Option<Vec<u8>>,
}

impl DnsRecordOptions {
    pub fn binary(&self) -> Option<&[u8]> {
        self.binary.as_deref()
    }

    pub fn normalize(&mut self, value: String) {
        self.value = value;
        self.binary = None;
    }
}

impl<'de> Deserialize<'de> for DnsRecordOptions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.trim().is_empty() {
            return Err(de::Error::custom("empty DNS record"));
        }
        let binary = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &value).ok();
        Ok(Self { value, binary })
    }
}

/// sing-box `LogicalRule.mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogicalMode {
    And,
    Or,
}

/// A rule: a default (field) rule or a logical rule over nested rules.
/// Nested rules never carry an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule<M, A> {
    Default { matcher: M, action: Option<A> },
    Logical { mode: LogicalMode, rules: Vec<Rule<M, A>>, invert: bool, action: Option<A> },
}

impl<M, A> Rule<M, A> {
    pub fn action(&self) -> Option<&A> {
        match self {
            Rule::Default { action, .. } | Rule::Logical { action, .. } => action.as_ref(),
        }
    }
}

pub type RouteRule = Rule<RuleMatch, RuleAction>;
pub type DnsRule = Rule<DnsRuleMatch, DnsRuleAction>;

/// `reject` action options (sing-box `RejectActionOptions`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectOptions {
    #[serde(default)]
    pub method: RejectMethod,
    #[serde(default)]
    pub no_drop: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RejectMethod {
    #[default]
    #[serde(rename = "", alias = "default")]
    Default,
    Drop,
}

/// The `route-options` fields of the `route`, `route-options` and `bypass`
/// actions (sing-box `RawRouteOptionsActionOptions`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteActionOptions {
    /// Replaces the destination host (an IP or a domain), keeping its port.
    #[serde(default)]
    pub override_address: String,
    #[serde(default)]
    pub override_port: u16,
    /// Accepted without effect, as in sing-box v1.14.4 without a platform
    /// interface: the strategy reaches the default dialer only through
    /// `direct`'s resolving dialer, which dials IP destinations directly
    /// (`resolveParallelNetworkDialer.DialParallelInterface`), and other
    /// outbounds do not read it.
    #[serde(default)]
    pub network_strategy: Option<NetworkStrategy>,
    /// A plain number, used as nanoseconds: sing-box v1.14.4 declares this
    /// field `uint32` and converts it with `time.Duration(...)`.
    #[serde(default)]
    pub fallback_delay: u32,
    #[serde(default)]
    pub udp_disable_domain_unmapping: bool,
    #[serde(default)]
    pub udp_connect: bool,
    #[serde(default)]
    pub udp_timeout: Duration,
    #[serde(default)]
    pub tls_fragment: bool,
    #[serde(default)]
    pub tls_fragment_fallback_delay: Duration,
    #[serde(default)]
    pub tls_record_fragment: bool,
    /// Rejected by [`take_route_options`]: not implemented yet.
    #[serde(default)]
    pub tls_spoof: String,
    #[serde(default)]
    pub tls_spoof_method: String,
}

const ROUTE_OPTION_FIELDS: &[&str] = &[
    "override_address",
    "override_port",
    "network_strategy",
    "fallback_delay",
    "udp_disable_domain_unmapping",
    "udp_connect",
    "udp_timeout",
    "tls_fragment",
    "tls_fragment_fallback_delay",
    "tls_record_fragment",
    "tls_spoof",
    "tls_spoof_method",
];

/// `tls_spoof_method` values (sing-box `common/tlsspoof`).
const TLS_SPOOF_METHODS: &[&str] =
    &["", "wrong-sequence", "wrong-checksum", "wrong-ack", "wrong-md5", "wrong-timestamp"];

/// Sniffer names of the `sniff` action (sing-box `route/rule/rule_action.go`).
pub const SNIFFERS: &[&str] = &["tls", "http", "quic", "dns", "stun", "bittorrent", "dtls", "ssh", "rdp", "ntp"];

/// Route rule actions (sing-box `RuleAction`, the subset rust-box implements).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Route {
        outbound: String,
        options: RouteActionOptions,
    },
    RouteOptions(RouteActionOptions),
    /// `bypass`: in connection routing it routes like `route` when it names
    /// an outbound and is skipped otherwise; the kernel-level bypass of
    /// `auto_redirect` pre-matching needs a TUN.
    Bypass {
        outbound: String,
        options: RouteActionOptions,
    },
    Reject(RejectOptions),
    HijackDns,
    Sniff {
        sniffer: Vec<String>,
        timeout: Duration,
    },
    Resolve {
        server: String,
        strategy: DomainStrategy,
        disable_cache: bool,
    },
}

/// Takes the route option fields out of a rule object. `exclusive` is set
/// for the `route-options` action, which sing-box checks for emptiness and
/// for `tls_fragment` with `tls_record_fragment`
/// (`RouteOptionsActionOptions.UnmarshalJSON`).
fn take_route_options(object: &mut Map<String, Value>, exclusive: bool) -> Result<RouteActionOptions, String> {
    let options: RouteActionOptions = take_as(object, ROUTE_OPTION_FIELDS)?;
    if exclusive {
        if options == RouteActionOptions::default() {
            return Err("empty route option action".into());
        }
        if options.tls_fragment && options.tls_record_fragment {
            return Err("`tls_fragment` and `tls_record_fragment` are mutually exclusive".into());
        }
    }
    // tlsspoof.ParseOptions
    if options.tls_spoof.is_empty() && !options.tls_spoof_method.is_empty() {
        return Err("spoof_method requires spoof".into());
    }
    if !TLS_SPOOF_METHODS.contains(&options.tls_spoof_method.as_str()) {
        return Err(format!("tls_spoof: unknown method: {}", options.tls_spoof_method));
    }
    if !options.tls_spoof.is_empty() {
        return Err("route option `tls_spoof` is not supported by rust-box yet".into());
    }
    Ok(options)
}

/// DNS route options shared by sing-box's `route` and `evaluate` actions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRouteActionOptions {
    #[serde(default)]
    pub timeout: Duration,
    #[serde(default)]
    pub strategy: DomainStrategy,
    #[serde(default)]
    pub disable_cache: bool,
    /// There is no optimistic DNS cache in rust-box, so caching is already
    /// non-optimistic regardless of this compatibility option.
    #[serde(default)]
    pub disable_optimistic_cache: bool,
    #[serde(default)]
    pub rewrite_ttl: Option<u32>,
    /// Parsed as a sing-box `Prefixable`; rejected by configuration
    /// validation until EDNS client subnet support is implemented.
    #[serde(default)]
    pub client_subnet: Option<Prefixable>,
    /// Rejected by configuration validation until EDNS client subnet support
    /// is implemented.
    #[serde(default)]
    pub remove_client_subnet: bool,
}

/// DNS rule actions (sing-box `DNSRuleAction`, the subset rust-box implements).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRuleAction {
    Route { server: String, options: DnsRouteActionOptions, speculative: bool, race: bool },
    Evaluate { server: String, tag: String, options: DnsRouteActionOptions, speculative: bool, race: bool },
    Respond { race: bool },
    Reject { options: RejectOptions, race: bool },
}

const DNS_ROUTE_OPTION_FIELDS: &[&str] = &[
    "timeout",
    "strategy",
    "disable_cache",
    "disable_optimistic_cache",
    "rewrite_ttl",
    "client_subnet",
    "remove_client_subnet",
];

fn take_dns_route_options(object: &mut Map<String, Value>) -> Result<DnsRouteActionOptions, String> {
    let options: DnsRouteActionOptions = take_as(object, DNS_ROUTE_OPTION_FIELDS)?;
    if options.client_subnet.is_some() && options.remove_client_subnet {
        return Err("`client_subnet` and `remove_client_subnet` are mutually exclusive".into());
    }
    Ok(options)
}

/// Parses rule actions out of a rule object.
pub trait ActionParser: Sized {
    /// Removes this action's keys from `object` and builds the action.
    fn take(object: &mut Map<String, Value>) -> Result<Self, String>;
}

fn take_as<T: DeserializeOwned>(object: &mut Map<String, Value>, keys: &[&str]) -> Result<T, String> {
    let mut taken = Map::new();
    for key in keys {
        if let Some(value) = object.remove(*key) {
            taken.insert((*key).to_string(), value);
        }
    }
    serde_json::from_value(Value::Object(taken)).map_err(|error| error.to_string())
}

fn action_name(object: &mut Map<String, Value>) -> Result<String, String> {
    match object.remove("action") {
        None => Ok("route".to_string()),
        Some(Value::String(name)) if name.is_empty() => Ok("route".to_string()),
        Some(Value::String(name)) => Ok(name),
        Some(other) => Err(format!("invalid rule action {other}")),
    }
}

impl ActionParser for RuleAction {
    fn take(object: &mut Map<String, Value>) -> Result<Self, String> {
        let name = action_name(object)?;
        match name.as_str() {
            "route" => {
                #[derive(Deserialize)]
                struct Route {
                    #[serde(default)]
                    outbound: String,
                }
                let route: Route = take_as(object, &["outbound"])?;
                if route.outbound.is_empty() {
                    return Err("missing outbound for route action".into());
                }
                let options = take_route_options(object, false)?;
                Ok(RuleAction::Route { outbound: route.outbound, options })
            }
            "route-options" => Ok(RuleAction::RouteOptions(take_route_options(object, true)?)),
            "bypass" => {
                #[derive(Deserialize)]
                struct Bypass {
                    #[serde(default)]
                    outbound: String,
                }
                let bypass: Bypass = take_as(object, &["outbound"])?;
                let options = take_route_options(object, false)?;
                Ok(RuleAction::Bypass { outbound: bypass.outbound, options })
            }
            "reject" => Ok(RuleAction::Reject(take_as(object, &["method", "no_drop"])?)),
            "hijack-dns" => Ok(RuleAction::HijackDns),
            "sniff" => {
                #[derive(Deserialize)]
                struct Sniff {
                    #[serde(default)]
                    sniffer: Listable<String>,
                    #[serde(default)]
                    timeout: Duration,
                }
                let sniff: Sniff = take_as(object, &["sniffer", "timeout"])?;
                if let Some(unknown) = sniff.sniffer.iter().find(|name| !SNIFFERS.contains(&name.as_str())) {
                    return Err(format!("unknown sniffer: {unknown}"));
                }
                Ok(RuleAction::Sniff { sniffer: sniff.sniffer.0, timeout: sniff.timeout })
            }
            "resolve" => {
                #[derive(Deserialize)]
                struct Resolve {
                    #[serde(default)]
                    server: String,
                    #[serde(default)]
                    strategy: DomainStrategy,
                    #[serde(default)]
                    disable_cache: bool,
                }
                let resolve: Resolve = take_as(object, &["server", "strategy", "disable_cache"])?;
                Ok(RuleAction::Resolve {
                    server: resolve.server,
                    strategy: resolve.strategy,
                    disable_cache: resolve.disable_cache,
                })
            }
            _ => Err(format!("unknown rule action: {name}")),
        }
    }
}

impl ActionParser for DnsRuleAction {
    fn take(object: &mut Map<String, Value>) -> Result<Self, String> {
        let name = action_name(object)?;
        match name.as_str() {
            "route" => {
                #[derive(Deserialize)]
                struct Route {
                    #[serde(default)]
                    server: String,
                    #[serde(default)]
                    speculative: bool,
                    #[serde(default)]
                    race: bool,
                }
                let route: Route = take_as(object, &["server", "speculative", "race"])?;
                if route.server.is_empty() {
                    return Err("missing server for DNS route action".into());
                }
                Ok(DnsRuleAction::Route {
                    server: route.server,
                    options: take_dns_route_options(object)?,
                    speculative: route.speculative,
                    race: route.race,
                })
            }
            "evaluate" => {
                #[derive(Deserialize)]
                struct Evaluate {
                    #[serde(default)]
                    server: String,
                    #[serde(default)]
                    tag: String,
                    #[serde(default)]
                    speculative: bool,
                    #[serde(default)]
                    race: bool,
                }
                let evaluate: Evaluate = take_as(object, &["server", "tag", "speculative", "race"])?;
                Ok(DnsRuleAction::Evaluate {
                    server: evaluate.server,
                    tag: evaluate.tag,
                    options: take_dns_route_options(object)?,
                    speculative: evaluate.speculative,
                    race: evaluate.race,
                })
            }
            "respond" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Respond {
                    #[serde(default)]
                    race: bool,
                }
                let respond: Respond = take_as(object, &["race"])?;
                Ok(DnsRuleAction::Respond { race: respond.race })
            }
            "reject" => {
                #[derive(Deserialize)]
                struct Reject {
                    #[serde(default)]
                    race: bool,
                }
                let reject: Reject = take_as(object, &["race"])?;
                Ok(DnsRuleAction::Reject { options: take_as(object, &["method", "no_drop"])?, race: reject.race })
            }
            "route-options" | "predefined" => Err(format!("DNS rule action {name:?} is not supported by rust-box yet")),
            _ => Err(format!("unknown DNS rule action: {name}")),
        }
    }
}

fn parse_rule<M: DeserializeOwned, A: ActionParser>(value: Value, nested: bool) -> Result<Rule<M, A>, String> {
    let Value::Object(mut object) = value else {
        return Err("a rule must be an object".into());
    };
    let kind = match object.remove("type") {
        None => String::new(),
        Some(Value::String(kind)) => kind,
        Some(other) => return Err(format!("invalid rule type {other}")),
    };
    let action = if nested {
        if object.contains_key("action") {
            return Err("DNS rule action is not supported in nested rules".into());
        }
        None
    } else {
        Some(A::take(&mut object)?)
    };
    match kind.as_str() {
        "" | "default" => {
            let matcher: M = serde_json::from_value(Value::Object(object)).map_err(|error| error.to_string())?;
            Ok(Rule::Default { matcher, action })
        }
        "logical" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Logical {
                mode: LogicalMode,
                #[serde(default)]
                rules: Vec<Value>,
                #[serde(default)]
                invert: bool,
            }
            let logical: Logical = serde_json::from_value(Value::Object(object)).map_err(|error| error.to_string())?;
            if logical.rules.is_empty() {
                return Err("logical rule without rules".into());
            }
            let rules = logical
                .rules
                .into_iter()
                .enumerate()
                .map(|(index, rule)| parse_rule(rule, true).map_err(|error| format!("rules[{index}]: {error}")))
                .collect::<Result<_, _>>()?;
            Ok(Rule::Logical { mode: logical.mode, rules, invert: logical.invert, action })
        }
        _ => Err(format!("unknown rule type: {kind}")),
    }
}

impl<'de, M: DeserializeOwned, A: ActionParser> Deserialize<'de> for Rule<M, A> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        parse_rule(value, false).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_route_rule() {
        let rule: RouteRule =
            serde_json::from_str(r#"{"domain_suffix":["example.com"],"port":443,"outbound":"proxy"}"#).unwrap();
        let Rule::Default { matcher, action } = rule else { panic!() };
        assert_eq!(matcher.domain_suffix.0, vec!["example.com"]);
        assert_eq!(matcher.port.0, vec![443]);
        assert_eq!(action, Some(RuleAction::Route { outbound: "proxy".into(), options: Default::default() }));
    }

    #[test]
    fn reject_and_unknown_fields() {
        let rule: RouteRule =
            serde_json::from_str(r#"{"ip_is_private":true,"action":"reject","method":"drop"}"#).unwrap();
        assert_eq!(
            rule.action(),
            Some(&RuleAction::Reject(RejectOptions { method: RejectMethod::Drop, no_drop: false }))
        );
        // `method` only belongs to reject; on a route rule it is an unknown field.
        assert!(serde_json::from_str::<RouteRule>(r#"{"outbound":"a","method":"drop"}"#).is_err());
        assert!(serde_json::from_str::<RouteRule>(r#"{"geoip":"cn","outbound":"a"}"#).is_err());
        assert!(matches!(
            serde_json::from_str::<RouteRule>(r#"{"action":"bypass","outbound":"a"}"#).unwrap().action(),
            Some(RuleAction::Bypass { outbound, .. }) if outbound == "a"
        ));
        assert!(serde_json::from_str::<RouteRule>(r#"{"action":"sniff","sniffer":["quic","nope"]}"#).is_err());
    }

    #[test]
    fn route_options() {
        let rule: RouteRule = serde_json::from_str(
            r#"{"network":"udp","action":"route-options","udp_disable_domain_unmapping":true,"udp_timeout":"1m"}"#,
        )
        .unwrap();
        let Some(RuleAction::RouteOptions(options)) = rule.action() else { panic!() };
        assert!(options.udp_disable_domain_unmapping);
        assert_eq!(options.udp_timeout.0, std::time::Duration::from_secs(60));
        let rule: RouteRule = serde_json::from_str(
            r#"{"outbound":"a","tls_fragment":true,"tls_record_fragment":true,"override_address":"1.2.3.4",
                "override_port":8443,"fallback_delay":300,"tls_fragment_fallback_delay":"20ms"}"#,
        )
        .unwrap();
        let Some(RuleAction::Route { options, .. }) = rule.action() else { panic!() };
        assert!(options.tls_fragment && options.tls_record_fragment);
        assert_eq!((options.override_address.as_str(), options.override_port), ("1.2.3.4", 8443));
        assert_eq!(options.fallback_delay, 300);
        assert_eq!(options.tls_fragment_fallback_delay.0, std::time::Duration::from_millis(20));
        // route-options checks what route does not.
        let error = serde_json::from_str::<RouteRule>(r#"{"action":"route-options"}"#).unwrap_err();
        assert!(error.to_string().contains("empty route option action"), "{error}");
        let error = serde_json::from_str::<RouteRule>(
            r#"{"action":"route-options","tls_fragment":true,"tls_record_fragment":true}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("mutually exclusive"), "{error}");
        // A string fallback_delay does not fit sing-box's uint32.
        assert!(serde_json::from_str::<RouteRule>(r#"{"outbound":"a","fallback_delay":"300ms"}"#).is_err());
        for (field, needle) in [
            (r#""tls_spoof":"example.com""#, "tls_spoof"),
            (r#""tls_spoof_method":"wrong-ack""#, "spoof_method requires spoof"),
            (r#""network_type":"wifi""#, "network_type"),
        ] {
            let error = serde_json::from_str::<RouteRule>(&format!(r#"{{"outbound":"a",{field}}}"#)).unwrap_err();
            assert!(error.to_string().contains(needle), "{field}: {error}");
        }
        // Accepted without effect, as sing-box without a platform interface.
        let rule: RouteRule =
            serde_json::from_str(r#"{"action":"route-options","network_strategy":"hybrid"}"#).unwrap();
        assert!(matches!(rule.action(), Some(RuleAction::RouteOptions(options))
            if options.network_strategy == Some(NetworkStrategy::Hybrid)));
        let error = serde_json::from_str::<RouteRule>(r#"{"outbound":"a","network_strategy":"fast"}"#).unwrap_err();
        assert!(error.to_string().contains("fast"), "{error}");
        assert_eq!(
            serde_json::from_str::<RouteRule>(r#"{"action":"hijack-dns"}"#).unwrap().action(),
            Some(&RuleAction::HijackDns)
        );
    }

    #[test]
    fn logical_rule() {
        let rule: RouteRule = serde_json::from_str(
            r#"{"type":"logical","mode":"and","rules":[{"network":"tcp"},{"port":80,"invert":true}],"action":"sniff"}"#,
        )
        .unwrap();
        let Rule::Logical { mode, rules, .. } = &rule else { panic!() };
        assert_eq!(*mode, LogicalMode::And);
        assert_eq!(rules.len(), 2);
        assert!(matches!(rule.action(), Some(RuleAction::Sniff { .. })));
        assert!(serde_json::from_str::<RouteRule>(
            r#"{"type":"logical","mode":"or","rules":[{"port":80,"outbound":"x"}],"outbound":"y"}"#
        )
        .is_err());
    }

    #[test]
    fn dns_rule() {
        let rule: DnsRule =
            serde_json::from_str(r#"{"query_type":["A","AAAA"],"domain":"a.com","server":"local"}"#).unwrap();
        let Rule::Default { matcher, action } = rule else { panic!() };
        assert_eq!(matcher.query_type.0.len(), 2);
        assert!(matches!(action, Some(DnsRuleAction::Route { ref server, .. }) if server == "local"));
    }

    #[test]
    fn dns_evaluate_and_respond_actions_are_strictly_parsed() {
        let rule: DnsRule = serde_json::from_str(
            r#"{"domain":"example.com","action":"evaluate","server":"remote","tag":"answer",
                "timeout":"2s","strategy":"prefer_ipv4","disable_cache":true,
                "disable_optimistic_cache":true,"rewrite_ttl":30,"speculative":true,"race":false}"#,
        )
        .unwrap();
        let Some(DnsRuleAction::Evaluate { server, tag, options, speculative, race }) = rule.action() else { panic!() };
        assert_eq!(server, "remote");
        assert_eq!(tag, "answer");
        assert_eq!(options.timeout.0, std::time::Duration::from_secs(2));
        assert_eq!(options.strategy, DomainStrategy::PreferIpv4);
        assert!(options.disable_cache && options.disable_optimistic_cache);
        assert_eq!(options.rewrite_ttl, Some(30));
        assert!(*speculative);
        assert!(!race);

        let anonymous: DnsRule = serde_json::from_str(r#"{"action":"evaluate","server":"remote"}"#).unwrap();
        assert!(matches!(anonymous.action(), Some(DnsRuleAction::Evaluate { tag, .. }) if tag.is_empty()));
        let missing_server: DnsRule = serde_json::from_str(r#"{"action":"evaluate"}"#).unwrap();
        assert!(matches!(missing_server.action(), Some(DnsRuleAction::Evaluate { server, .. }) if server.is_empty()));

        let respond: DnsRule = serde_json::from_str(r#"{"action":"respond","race":true}"#).unwrap();
        assert!(matches!(respond.action(), Some(DnsRuleAction::Respond { race: true })));
        let reject: DnsRule = serde_json::from_str(r#"{"action":"reject","method":"drop","race":true}"#).unwrap();
        assert!(matches!(reject.action(), Some(DnsRuleAction::Reject { options, race: true })
            if options.method == RejectMethod::Drop));

        for (json, expected) in [
            (r#"{"action":"evaluate","unknown":true}"#, "unknown"),
            (r#"{"action":"respond","server":"remote"}"#, "server"),
            (r#"{"action":"respond","unknown":true}"#, "unknown"),
            (r#"{"action":"route","server":"remote","unknown":true}"#, "unknown"),
            (
                r#"{"action":"evaluate","client_subnet":"192.0.2.0/24","remove_client_subnet":true}"#,
                "mutually exclusive",
            ),
        ] {
            let error = serde_json::from_str::<DnsRule>(json).unwrap_err();
            assert!(error.to_string().contains(expected), "{json}: {error}");
        }
    }

    #[test]
    fn dns_response_match_fields() {
        let rule: DnsRule = serde_json::from_str(
            r#"{"domain":"example.com","match_response":true,"response_rcode":"NXDOMAIN",
                "response_answer":["example.com. 60 IN A 192.0.2.1"],"action":"reject"}"#,
        )
        .unwrap();
        let Rule::Default { matcher, .. } = rule else { panic!() };
        assert_eq!(matcher.match_response, DnsMatchResponse { enabled: true, tag: String::new() });
        assert_eq!(matcher.response_rcode, Some(DnsResponseCode(3)));
        assert_eq!(matcher.response_answer.0[0].value, "example.com. 60 IN A 192.0.2.1");

        let tagged: DnsRule = serde_json::from_str(r#"{"match_response":"lookup","action":"reject"}"#).unwrap();
        let Rule::Default { matcher, .. } = tagged else { panic!() };
        assert_eq!(matcher.match_response, DnsMatchResponse { enabled: true, tag: "lookup".into() });

        let disabled: DnsRule = serde_json::from_str(r#"{"match_response":false,"action":"reject"}"#).unwrap();
        let Rule::Default { matcher, .. } = disabled else { panic!() };
        assert!(!matcher.match_response.enabled);

        for (json, expected) in [
            (r#"{"match_response":"","action":"reject"}"#, "empty match_response tag"),
            (r#"{"match_response":1,"action":"reject"}"#, "invalid match_response value"),
            (r#"{"response_rcode":"unknown","action":"reject"}"#, "unknown rcode"),
            (r#"{"unexpected_response":true,"action":"reject"}"#, "unexpected_response"),
        ] {
            let error = serde_json::from_str::<DnsRule>(json).unwrap_err();
            assert!(error.to_string().contains(expected), "{json}: {error}");
        }
    }
}
