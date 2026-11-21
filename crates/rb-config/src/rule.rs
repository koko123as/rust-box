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
    pub invert: bool,
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
    /// Rejected by [`take_route_options`]: graphical clients only.
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
    if options.network_strategy.is_some() {
        return Err("route option `network_strategy` is only supported in graphical clients with a platform \
                    interface (Android, Apple), which rust-box does not have yet"
            .into());
    }
    Ok(options)
}

/// DNS rule actions (sing-box `DNSRuleAction`, the subset rust-box implements).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRuleAction {
    Route { server: String, strategy: DomainStrategy, disable_cache: bool },
    Reject(RejectOptions),
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
                    strategy: DomainStrategy,
                    #[serde(default)]
                    disable_cache: bool,
                }
                let route: Route = take_as(object, &["server", "strategy", "disable_cache"])?;
                if route.server.is_empty() {
                    return Err("missing server for DNS route action".into());
                }
                Ok(DnsRuleAction::Route {
                    server: route.server,
                    strategy: route.strategy,
                    disable_cache: route.disable_cache,
                })
            }
            "reject" => Ok(DnsRuleAction::Reject(take_as(object, &["method", "no_drop"])?)),
            "evaluate" | "respond" | "route-options" | "predefined" => {
                Err(format!("DNS rule action {name:?} is not supported by rust-box yet"))
            }
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
            return Err("nested rules cannot have an action".into());
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
            (r#""network_strategy":"hybrid""#, "network_strategy"),
            (r#""network_type":"wifi""#, "network_type"),
        ] {
            let error = serde_json::from_str::<RouteRule>(&format!(r#"{{"outbound":"a",{field}}}"#)).unwrap_err();
            assert!(error.to_string().contains(needle), "{field}: {error}");
        }
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
}
