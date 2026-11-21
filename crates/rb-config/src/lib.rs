//! rust-box configuration: the JSON format of sing-box v1.14.4
//! (`docs/configuration/`), limited to what rust-box implements.
//!
//! Every object rejects unknown fields, like sing-box
//! (`json.UnmarshalDisallowUnknownFields`), so a configuration that uses a
//! feature rust-box does not have yet fails to load instead of silently
//! behaving differently.

pub mod rule;
pub mod types;

use std::net::IpAddr;

use serde::Deserialize;
use serde_json::Value;

pub use rule::{
    DnsRule, DnsRuleAction, DnsRuleMatch, LogicalMode, RejectMethod, RejectOptions, RouteActionOptions, RouteRule,
    Rule, RuleAction, RuleMatch, SNIFFERS,
};
pub use types::{DomainResolveOptions, DomainStrategy, Duration, Listable, QueryType, UdpTimeout, User};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0}")]
    Syntax(#[from] serde_json::Error),
    #[error("{path}: {message}")]
    Field { path: String, message: String },
    #[error("{0}")]
    Unsupported(String),
}

/// Top-level sections sing-box has and rust-box does not implement yet.
const UNSUPPORTED_SECTIONS: &[&str] =
    &["ntp", "certificate", "certificate_providers", "endpoints", "services", "experimental", "http_clients"];

/// sing-box `option.Options`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default, rename = "$schema")]
    pub schema: Option<String>,
    #[serde(default)]
    pub log: LogOptions,
    #[serde(default)]
    pub dns: DnsOptions,
    #[serde(default)]
    pub inbounds: Vec<Inbound>,
    #[serde(default)]
    pub outbounds: Vec<Outbound>,
    #[serde(default)]
    pub route: RouteOptions,
}

/// sing-box `LogOptions`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogOptions {
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub output: String,
    #[serde(default)]
    pub timestamp: bool,
}

/// sing-box `DNSOptions`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsOptions {
    #[serde(default)]
    pub servers: Vec<DnsServer>,
    #[serde(default)]
    pub rules: Vec<DnsRule>,
    #[serde(default)]
    pub r#final: String,
    #[serde(default)]
    pub strategy: DomainStrategy,
    #[serde(default)]
    pub timeout: Duration,
    #[serde(default)]
    pub disable_cache: bool,
    #[serde(default)]
    pub disable_expire: bool,
    #[serde(default)]
    pub cache_capacity: u32,
}

/// A DNS server (the 1.12+ typed format, sing-box `DNSServerOptions`).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum DnsServer {
    #[serde(rename = "local")]
    Local {
        #[serde(default)]
        tag: String,
    },
    #[serde(rename = "udp")]
    Udp(RemoteDnsServer),
    #[serde(rename = "tcp")]
    Tcp(RemoteDnsServer),
}

impl DnsServer {
    pub fn tag(&self) -> &str {
        match self {
            DnsServer::Local { tag } => tag,
            DnsServer::Udp(server) | DnsServer::Tcp(server) => &server.tag,
        }
    }
}

/// sing-box `RemoteDNSServerOptions` (the subset rust-box implements: the
/// server must be an IP address).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteDnsServer {
    #[serde(default)]
    pub tag: String,
    pub server: IpAddr,
    #[serde(default)]
    pub server_port: u16,
}

/// Inbounds (sing-box `option.Inbound`).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Inbound {
    #[serde(rename = "mixed")]
    Mixed(ProxyInbound),
    #[serde(rename = "socks")]
    Socks(ProxyInbound),
    #[serde(rename = "http")]
    Http(ProxyInbound),
}

impl Inbound {
    pub fn tag(&self) -> &str {
        match self {
            Inbound::Mixed(options) | Inbound::Socks(options) | Inbound::Http(options) => &options.tag,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Inbound::Mixed(_) => "mixed",
            Inbound::Socks(_) => "socks",
            Inbound::Http(_) => "http",
        }
    }
}

/// Options of the socks, http and mixed inbounds (sing-box
/// `SocksInboundOptions`, `HTTPMixedInboundOptions` with `ListenOptions`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyInbound {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub listen: Option<IpAddr>,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub users: Vec<User>,
    /// UDP NAT expiration (`ListenOptions.udp_timeout`, 5m by default). The
    /// `http` inbound accepts it like sing-box and has no UDP to apply it to.
    #[serde(default)]
    pub udp_timeout: UdpTimeout,
}

/// Outbounds (sing-box `option.Outbound`).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Outbound {
    #[serde(rename = "direct")]
    Direct(DirectOutbound),
    #[serde(rename = "block")]
    Block(BlockOutbound),
}

impl Outbound {
    pub fn tag(&self) -> &str {
        match self {
            Outbound::Direct(options) => &options.tag,
            Outbound::Block(options) => &options.tag,
        }
    }
}

/// sing-box `DirectOutboundOptions` (dial fields: the subset rust-box implements).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectOutbound {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub domain_resolver: Option<DomainResolveOptions>,
    #[serde(default)]
    pub connect_timeout: Duration,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockOutbound {
    #[serde(default)]
    pub tag: String,
}

/// sing-box `RouteOptions` (the subset rust-box implements).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOptions {
    #[serde(default)]
    pub rules: Vec<RouteRule>,
    #[serde(default)]
    pub r#final: String,
    #[serde(default)]
    pub default_domain_resolver: Option<DomainResolveOptions>,
    /// Accepted and ignored: rust-box has no TUN yet, and without a TUN
    /// nothing needs to bind to the default interface.
    #[serde(default)]
    pub auto_detect_interface: bool,
}

/// Parses a configuration, naming the path of a field that fails.
pub fn parse(content: &str) -> Result<Options, ConfigError> {
    let value: Value = serde_json::from_str(content)?;
    if let Value::Object(object) = &value {
        for section in UNSUPPORTED_SECTIONS {
            if object.contains_key(*section) {
                return Err(ConfigError::Unsupported(format!("`{section}` is not supported by rust-box yet")));
            }
        }
    }
    let options: Options = serde_path_to_error::deserialize(value)
        .map_err(|error| ConfigError::Field { path: error.path().to_string(), message: error.inner().to_string() })?;
    options.validate()?;
    Ok(options)
}

impl Options {
    /// Checks references between sections, as sing-box does when it builds
    /// the box (duplicate tags, unknown outbounds and DNS servers).
    pub fn validate(&self) -> Result<(), ConfigError> {
        let field = |path: String, message: String| ConfigError::Field { path, message };
        let mut tags = std::collections::HashSet::new();
        for (index, inbound) in self.inbounds.iter().enumerate() {
            if !inbound.tag().is_empty() && !tags.insert(("inbound", inbound.tag().to_string())) {
                return Err(field(format!("inbounds[{index}]"), format!("duplicate inbound tag: {}", inbound.tag())));
            }
        }
        let mut outbound_tags = Vec::new();
        for (index, outbound) in self.outbounds.iter().enumerate() {
            let tag = if outbound.tag().is_empty() { index.to_string() } else { outbound.tag().to_string() };
            if outbound_tags.contains(&tag) {
                return Err(field(format!("outbounds[{index}]"), format!("duplicate outbound tag: {tag}")));
            }
            outbound_tags.push(tag);
        }
        let mut server_tags = Vec::new();
        for (index, server) in self.dns.servers.iter().enumerate() {
            let tag = if server.tag().is_empty() { index.to_string() } else { server.tag().to_string() };
            if server_tags.contains(&tag) {
                return Err(field(format!("dns.servers[{index}]"), format!("duplicate DNS server tag: {tag}")));
            }
            server_tags.push(tag);
        }
        let outbound_known = |tag: &str| outbound_tags.iter().any(|known| known == tag);
        let server_known = |tag: &str| server_tags.iter().any(|known| known == tag);
        if !self.route.r#final.is_empty() && !outbound_known(&self.route.r#final) {
            return Err(field("route.final".into(), format!("outbound not found: {}", self.route.r#final)));
        }
        for (index, rule) in self.route.rules.iter().enumerate() {
            match rule.action() {
                Some(RuleAction::Route { outbound, .. }) if !outbound_known(outbound) => {
                    return Err(field(format!("route.rules[{index}]"), format!("outbound not found: {outbound}")));
                }
                Some(RuleAction::Resolve { server, .. }) if !server.is_empty() && !server_known(server) => {
                    return Err(field(format!("route.rules[{index}]"), format!("DNS server not found: {server}")));
                }
                _ => {}
            }
        }
        if let Some(resolver) = &self.route.default_domain_resolver {
            if !server_known(&resolver.server) {
                return Err(field(
                    "route.default_domain_resolver".into(),
                    format!("DNS server not found: {}", resolver.server),
                ));
            }
        }
        for (index, outbound) in self.outbounds.iter().enumerate() {
            if let Outbound::Direct(DirectOutbound { domain_resolver: Some(resolver), .. }) = outbound {
                if !server_known(&resolver.server) {
                    return Err(field(
                        format!("outbounds[{index}].domain_resolver"),
                        format!("DNS server not found: {}", resolver.server),
                    ));
                }
            }
        }
        if !self.dns.r#final.is_empty() && !server_known(&self.dns.r#final) {
            return Err(field("dns.final".into(), format!("DNS server not found: {}", self.dns.r#final)));
        }
        for (index, rule) in self.dns.rules.iter().enumerate() {
            if let Some(DnsRuleAction::Route { server, .. }) = rule.action() {
                if !server_known(server) {
                    return Err(field(format!("dns.rules[{index}]"), format!("DNS server not found: {server}")));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
      "log": {"level": "info", "timestamp": true},
      "dns": {
        "servers": [
          {"type": "local", "tag": "local"},
          {"type": "udp", "tag": "google", "server": "8.8.8.8"}
        ],
        "rules": [{"domain_suffix": "cn", "server": "local"}],
        "final": "google",
        "strategy": "prefer_ipv4"
      },
      "inbounds": [
        {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080,
         "users": [{"username": "u", "password": "p"}]}
      ],
      "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}],
      "route": {
        "rules": [
          {"action": "sniff"},
          {"protocol": "bittorrent", "action": "reject"},
          {"ip_is_private": true, "outbound": "direct"}
        ],
        "final": "direct",
        "default_domain_resolver": "local"
      }
    }"#;

    #[test]
    fn parses_example() {
        let options = parse(EXAMPLE).unwrap();
        assert_eq!(options.inbounds.len(), 1);
        assert_eq!(options.inbounds[0].kind(), "mixed");
        assert_eq!(options.dns.servers[1].tag(), "google");
        assert_eq!(options.route.rules.len(), 3);
        assert_eq!(options.dns.strategy, DomainStrategy::PreferIpv4);
    }

    #[test]
    fn rejects_what_is_not_implemented() {
        let error = parse(r#"{"experimental": {}}"#).unwrap_err().to_string();
        assert!(error.contains("experimental"), "{error}");
        let error = parse(r#"{"inbounds":[{"type":"tun"}]}"#).unwrap_err().to_string();
        assert!(error.contains("inbounds[0]"), "{error}");
        let error =
            parse(r#"{"inbounds":[{"type":"mixed","listen_port":1,"tcp_fast_open":true}]}"#).unwrap_err().to_string();
        assert!(error.contains("tcp_fast_open"), "{error}");
        let error =
            parse(r#"{"route":{"rules":[{"action":"route-options","override_port":53}]}}"#).unwrap_err().to_string();
        assert!(error.contains("route.rules[0]") && error.contains("override_port"), "{error}");
    }

    #[test]
    fn udp_fields() {
        let options = parse(
            r#"{"inbounds":[{"type":"socks","listen_port":1,"udp_timeout":60}],
                "outbounds":[{"type":"direct","tag":"d"}],
                "route":{"rules":[{"network":"udp","outbound":"d","udp_connect":true,"udp_timeout":"10s"},
                                  {"protocol":"dns","action":"hijack-dns"}]}}"#,
        )
        .unwrap();
        let Inbound::Socks(socks) = &options.inbounds[0] else { panic!() };
        assert_eq!(socks.udp_timeout.0 .0, std::time::Duration::from_secs(60));
        assert!(matches!(
            options.route.rules[0].action(),
            Some(RuleAction::Route { options, .. }) if options.udp_connect
        ));
        assert_eq!(options.route.rules[1].action(), Some(&RuleAction::HijackDns));
    }

    #[test]
    fn checks_references() {
        let error =
            parse(r#"{"outbounds":[{"type":"direct","tag":"d"}],"route":{"final":"proxy"}}"#).unwrap_err().to_string();
        assert!(error.contains("outbound not found: proxy"), "{error}");
        let error =
            parse(r#"{"outbounds":[{"type":"direct","tag":"d"},{"type":"block","tag":"d"}]}"#).unwrap_err().to_string();
        assert!(error.contains("duplicate outbound tag"), "{error}");
        let error = parse(r#"{"route":{"default_domain_resolver":"nope"}}"#).unwrap_err().to_string();
        assert!(error.contains("DNS server not found"), "{error}");
    }
}
