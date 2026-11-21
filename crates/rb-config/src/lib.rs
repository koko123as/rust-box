//! rust-box configuration: the JSON format of sing-box v1.14.4
//! (`docs/configuration/`), limited to what rust-box implements.
//!
//! Every object rejects unknown fields, like sing-box
//! (`json.UnmarshalDisallowUnknownFields`), so a configuration that uses a
//! feature rust-box does not have yet fails to load instead of silently
//! behaving differently.

#[macro_use]
pub mod dial;
pub mod adguard;
pub mod deprecated;
pub mod query_types;
pub mod rule;
pub mod rule_set;
pub mod srs;
pub mod types;

use std::net::IpAddr;

use serde::Deserialize;
use serde_json::Value;

pub use dial::{DialerOptions, FwMark, InterfaceType, ListenOptions, NetworkStrategy};
pub use rule::{
    DnsRule, DnsRuleAction, DnsRuleMatch, LogicalMode, RejectMethod, RejectOptions, RouteActionOptions, RouteRule,
    Rule, RuleAction, RuleMatch, SNIFFERS,
};
pub use rule_set::{
    DefaultHeadlessRule, HeadlessRule, LogicalHeadlessRule, PlainRuleSet, PlainRuleSetCompat, RemoteRuleSet,
    RuleSetKind, RuleSetOptions,
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
const UNSUPPORTED_SECTIONS: &[&str] = &[
    "ntp",
    "certificate_providers",
    "endpoints",
    "services",
    "experimental",
    "http_clients",
    "network_namespaces",
];

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
    #[serde(default)]
    pub certificate: Option<CertificateOptions>,
}

/// The top-level `certificate` section (sing-box `option.CertificateOptions`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateOptions {
    /// `system` (the default), `mozilla`, `chrome` or `none`.
    #[serde(default)]
    pub store: String,
    #[serde(default)]
    pub certificate: Listable<String>,
    #[serde(default)]
    pub certificate_path: Listable<String>,
    #[serde(default)]
    pub certificate_directory_path: Listable<String>,
}

/// Strips `//`, `/* */` and `#` comments outside strings, keeping line
/// breaks (sing-box `contextjson.stripJSONComments`).
pub fn strip_json_comments(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut clean = data.to_vec();
    let blank = |clean: &mut Vec<u8>, start: usize, end: usize| {
        for byte in &mut clean[start..end] {
            if *byte != b'\n' && *byte != b'\r' {
                *byte = b' ';
            }
        }
    };
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'"' => {
                i += 1;
                while i < data.len() {
                    match data[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                i = i.min(data.len());
            }
            b'#' => {
                let start = i;
                while i < data.len() && data[i] != b'\n' && data[i] != b'\r' {
                    i += 1;
                }
                blank(&mut clean, start, i);
            }
            b'/' if i + 1 < data.len() && data[i + 1] == b'/' => {
                let start = i;
                while i < data.len() && data[i] != b'\n' && data[i] != b'\r' {
                    i += 1;
                }
                blank(&mut clean, start, i);
            }
            b'/' if i + 1 < data.len() && data[i + 1] == b'*' => {
                let start = i;
                i += 2;
                while i + 1 < data.len() && (data[i] != b'*' || data[i + 1] != b'/') {
                    i += 1;
                }
                if i + 1 >= data.len() {
                    return Err(format!("unexpected end of JSON comment (offset {start})"));
                }
                i += 2;
                blank(&mut clean, start, i);
            }
            _ => i += 1,
        }
    }
    Ok(clean)
}

/// sing-box `json.UnmarshalExtended` into a JSON value: comments allowed,
/// syntax errors located by row and column.
pub fn parse_json_extended(content: &[u8]) -> Result<Value, String> {
    let clean = strip_json_comments(content)?;
    serde_json::from_slice(&clean).map_err(|error| error.to_string())
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

with_dial_fields! {
    /// sing-box `RemoteDNSServerOptions` with its dial fields (the server
    /// must be an IP address in rust-box).
    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RemoteDnsServer {
        #[serde(default)]
        pub tag: String,
        pub server: IpAddr,
        #[serde(default)]
        pub server_port: u16,
    }
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

with_listen_fields! {
    /// Options of the socks, http and mixed inbounds (sing-box
    /// `SocksInboundOptions`, `HTTPMixedInboundOptions` with `ListenOptions`).
    /// The `http` inbound accepts `udp_timeout` and `udp_fragment` like
    /// sing-box and has no UDP to apply them to.
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ProxyInbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub users: Vec<User>,
    }
}

/// Outbounds (sing-box `option.Outbound`).
#[allow(clippy::large_enum_variant)]
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

with_dial_fields! {
    /// sing-box `DirectOutboundOptions`: the dial fields and the removed
    /// destination override fields (rejected when set).
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DirectOutbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub override_address: String,
        #[serde(default)]
        pub override_port: u16,
        #[serde(default)]
        pub proxy_protocol: u8,
    }
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
    pub rule_set: Vec<RuleSetOptions>,
    #[serde(default)]
    pub r#final: String,
    #[serde(default)]
    pub default_domain_resolver: Option<DomainResolveOptions>,
    /// Accepted and ignored: rust-box has no TUN yet, and without a TUN
    /// nothing needs to bind to the default interface.
    #[serde(default)]
    pub auto_detect_interface: bool,
    /// Interface outbound connections bind to by default (Linux).
    #[serde(default)]
    pub default_interface: String,
    /// Routing mark outbound connections get by default (Linux).
    #[serde(default)]
    pub default_mark: FwMark,
    /// `default_network_strategy`, `default_network_type`,
    /// `default_fallback_network_type` and `default_fallback_delay` are the
    /// defaults of the dial fields of the same names. sing-box only reads
    /// them with a platform interface (its graphical clients); its command
    /// line checks `default_network_strategy` against `default_interface`
    /// and `auto_detect_interface` and otherwise leaves them without effect,
    /// and so does rust-box.
    #[serde(default)]
    pub default_network_strategy: Option<NetworkStrategy>,
    #[serde(default)]
    pub default_network_type: Listable<InterfaceType>,
    #[serde(default)]
    pub default_fallback_network_type: Listable<InterfaceType>,
    #[serde(default)]
    pub default_fallback_delay: Duration,
}

/// Parses a configuration, naming the path of a field that fails.
pub fn parse(content: &str) -> Result<Options, ConfigError> {
    let clean = strip_json_comments(content.as_bytes()).map_err(ConfigError::Unsupported)?;
    let value: Value = serde_json::from_slice(&clean)?;
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
        // sing-box `route.NewNetworkManager`.
        if self.route.default_network_strategy.is_some() {
            if !self.route.default_interface.is_empty() {
                return Err(field(
                    "route.default_network_strategy".into(),
                    "`default_network_strategy` is conflict with `default_interface`".into(),
                ));
            }
            if !self.route.auto_detect_interface {
                return Err(field(
                    "route.default_network_strategy".into(),
                    "`auto_detect_interface` is required by `default_network_strategy`".into(),
                ));
            }
        }
        let mut tags = std::collections::HashSet::new();
        let inbound_tags: Vec<String> = self
            .inbounds
            .iter()
            .enumerate()
            .map(
                |(index, inbound)| if inbound.tag().is_empty() { index.to_string() } else { inbound.tag().to_string() },
            )
            .collect();
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
        let check_resolver = |path: &str, resolver: &DomainResolveOptions| -> Result<(), ConfigError> {
            if !server_known(&resolver.server) {
                return Err(field(path.into(), format!("DNS server not found: {}", resolver.server)));
            }
            if resolver.client_subnet.is_some() {
                return Err(field(
                    format!("{path}.client_subnet"),
                    "`client_subnet` is not supported by rust-box yet".into(),
                ));
            }
            Ok(())
        };
        if let Some(resolver) = &self.route.default_domain_resolver {
            check_resolver("route.default_domain_resolver", resolver)?;
        }
        for (index, inbound) in self.inbounds.iter().enumerate() {
            let options = inbound.options();
            if let Some(message) = options.removed_field_error() {
                return Err(field(format!("inbounds[{index}]"), message.to_string()));
            }
            let detour = &options.detour;
            if !detour.is_empty() && !inbound_tags.contains(detour) {
                return Err(field(format!("inbounds[{index}].detour"), format!("inbound detour not found: {detour}")));
            }
        }
        for (index, outbound) in self.outbounds.iter().enumerate() {
            let Outbound::Direct(direct) = outbound else { continue };
            let path = format!("outbounds[{index}]");
            if !direct.override_address.is_empty() || direct.override_port != 0 {
                return Err(field(
                    path,
                    "destination override fields in direct outbound are deprecated in sing-box 1.11.0 and removed \
                     in sing-box 1.13.0, use route options instead"
                        .into(),
                ));
            }
            if direct.proxy_protocol != 0 {
                return Err(field(path, dial::PROXY_PROTOCOL_ERROR.into()));
            }
            if !direct.detour.is_empty() {
                return Err(field(format!("{path}.detour"), "`detour` is not supported in direct context".into()));
            }
            self.check_dialer(&path, &direct.dialer_options(), &server_known)?;
        }
        for (index, server) in self.dns.servers.iter().enumerate() {
            if let DnsServer::Udp(remote) | DnsServer::Tcp(remote) = server {
                self.check_dialer(&format!("dns.servers[{index}]"), &remote.dialer_options(), &server_known)?;
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

    /// Checks one object's dial fields: references, and the fields rust-box
    /// cannot honor.
    fn check_dialer(
        &self,
        path: &str,
        options: &DialerOptions,
        server_known: &dyn Fn(&str) -> bool,
    ) -> Result<(), ConfigError> {
        let field = |path: String, message: String| ConfigError::Field { path, message };
        // sing-box checks this in `dialer.NewDefault`, which only runs for a
        // dialer without `detour`.
        if options.detour.is_empty() {
            if let Some(message) = options.network_strategy_conflict() {
                return Err(field(format!("{path}.network_strategy"), message.into()));
            }
        }
        if let Some(resolver) = &options.domain_resolver {
            if !server_known(&resolver.server) {
                return Err(field(
                    format!("{path}.domain_resolver"),
                    format!("DNS server not found: {}", resolver.server),
                ));
            }
            if resolver.client_subnet.is_some() {
                return Err(field(
                    format!("{path}.domain_resolver.client_subnet"),
                    "`client_subnet` is not supported by rust-box yet".into(),
                ));
            }
        }
        for (name, address, ipv4) in [
            ("inet4_bind_address", options.inet4_bind_address, true),
            ("inet6_bind_address", options.inet6_bind_address, false),
        ] {
            if let Some(address) = address {
                if address.is_ipv4() != ipv4 {
                    return Err(field(
                        format!("{path}.{name}"),
                        format!("not an IPv{} address: {address}", if ipv4 { 4 } else { 6 }),
                    ));
                }
            }
        }
        if !options.detour.is_empty() {
            let target = self.outbounds.iter().enumerate().find(|(index, outbound)| {
                let tag = if outbound.tag().is_empty() { index.to_string() } else { outbound.tag().to_string() };
                tag == options.detour
            });
            match target {
                None => {
                    return Err(field(
                        format!("{path}.detour"),
                        format!("outbound detour not found: {}", options.detour),
                    ))
                }
                Some((_, Outbound::Direct(direct))) if direct.dialer_options().is_empty() => {
                    return Err(field(
                        format!("{path}.detour"),
                        "detour to an empty direct outbound makes no sense".into(),
                    ))
                }
                Some(_) => {}
            }
        }
        Ok(())
    }
}

impl Inbound {
    /// The listen fields of any inbound.
    pub fn options(&self) -> &ProxyInbound {
        match self {
            Inbound::Mixed(options) | Inbound::Socks(options) | Inbound::Http(options) => options,
        }
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
        let error = parse(r#"{"network_namespaces": []}"#).unwrap_err().to_string();
        assert!(error.contains("network_namespaces"), "{error}");
        let error = parse(r#"{"inbounds":[{"type":"tun"}]}"#).unwrap_err().to_string();
        assert!(error.contains("inbounds[0]"), "{error}");
        let error =
            parse(r#"{"inbounds":[{"type":"mixed","listen_port":1,"tcp_brutal":true}]}"#).unwrap_err().to_string();
        assert!(error.contains("inbounds[0]") && error.contains("tcp_brutal"), "{error}");
        let error =
            parse(r#"{"route":{"rules":[{"action":"route-options","tls_spoof":"a.com"}]}}"#).unwrap_err().to_string();
        assert!(error.contains("route.rules[0]") && error.contains("tls_spoof"), "{error}");
        let error = parse(
            r#"{"dns":{"servers":[{"type":"local","tag":"l"}]},
                "outbounds":[{"type":"direct","domain_resolver":{"server":"l","client_subnet":"1.2.3.0/24"}}]}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("outbounds[0].domain_resolver.client_subnet"), "{error}");
    }

    /// sing-box v1.14.4 without a platform interface: the platform network
    /// fields are accepted without effect, and only its own checks fail.
    #[test]
    fn platform_network_fields() {
        let options = parse(
            r#"{"outbounds":[{"type":"direct","network_strategy":"hybrid","network_type":["wifi","cellular"],
                "fallback_network_type":"ethernet","fallback_delay":"100ms"}],
                "route":{"rules":[{"action":"route-options","network_strategy":"fallback"}],
                "default_network_type":"wifi","default_fallback_network_type":["cellular"],
                "default_fallback_delay":"1s"}}"#,
        )
        .unwrap();
        let Outbound::Direct(direct) = &options.outbounds[0] else { panic!() };
        let dialer = direct.dialer_options();
        assert_eq!(dialer.network_strategy, Some(NetworkStrategy::Hybrid));
        assert_eq!(dialer.fallback_network_type.unwrap().0, vec![InterfaceType::Ethernet]);
        assert_eq!(options.route.default_network_type.0, vec![InterfaceType::Wifi]);
        // `null` is a nil list in Go, `[]` an empty one.
        let options = parse(r#"{"outbounds":[{"type":"direct","fallback_network_type":null}]}"#).unwrap();
        let Outbound::Direct(direct) = &options.outbounds[0] else { panic!() };
        assert!(direct.fallback_network_type.is_none());

        // dialer.NewDefault: conflict with the fields that bind the socket.
        let conflict =
            "is conflict with `bind_interface`, `inet4_bind_address`, `inet6_bind_address` and `tcp_fast_open`";
        for dial in [
            r#""network_strategy":"default","tcp_fast_open":true"#,
            r#""network_strategy":"hybrid","bind_interface":"eth0""#,
            r#""network_strategy":"hybrid","inet4_bind_address":"127.0.0.1""#,
            r#""network_type":"wifi","inet6_bind_address":"::1""#,
        ] {
            let error = parse(&format!(r#"{{"outbounds":[{{"type":"direct",{dial}}}]}}"#)).unwrap_err().to_string();
            assert!(error.contains("outbounds[0].network_strategy") && error.contains(conflict), "{dial}: {error}");
        }
        // Go's precedence: `network_type` alone only conflicts without
        // `fallback_network_type` (even an empty list) and `fallback_delay`.
        for dial in [
            r#""network_type":"wifi","fallback_network_type":[],"tcp_fast_open":true"#,
            r#""network_type":"wifi","fallback_delay":"1ms","tcp_fast_open":true"#,
            r#""fallback_network_type":"wifi","tcp_fast_open":true"#,
            r#""network_type":"wifi""#,
        ] {
            parse(&format!(r#"{{"outbounds":[{{"type":"direct",{dial}}}]}}"#)).unwrap();
        }
        // A DNS server's dialer is checked the same way, but not one with a
        // `detour` (sing-box builds no default dialer for it).
        let error = parse(
            r#"{"dns":{"servers":[{"type":"udp","server":"1.1.1.1","network_strategy":"hybrid","tcp_fast_open":true}]}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("dns.servers[0].network_strategy") && error.contains(conflict), "{error}");
        parse(
            r#"{"dns":{"servers":[{"type":"udp","server":"1.1.1.1","detour":"d","network_strategy":"hybrid",
                "tcp_fast_open":true}]},"outbounds":[{"type":"direct","tag":"d","routing_mark":1}]}"#,
        )
        .unwrap();

        // route.NewNetworkManager.
        let error = parse(r#"{"route":{"default_network_strategy":"hybrid"}}"#).unwrap_err().to_string();
        assert!(
            error.contains("route.default_network_strategy")
                && error.contains("`auto_detect_interface` is required by `default_network_strategy`"),
            "{error}"
        );
        let error = parse(
            r#"{"route":{"default_network_strategy":"hybrid","auto_detect_interface":true,"default_interface":"eth0"}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("`default_network_strategy` is conflict with `default_interface`"), "{error}");
        parse(r#"{"route":{"default_network_strategy":"hybrid","auto_detect_interface":true}}"#).unwrap();
        let error = parse(r#"{"route":{"default_network_strategy":"fast","auto_detect_interface":true}}"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("route.default_network_strategy"), "{error}");
    }

    #[test]
    fn dial_fields() {
        let options = parse(
            r#"{"dns":{"servers":[{"type":"local","tag":"local"},
                                  {"type":"udp","tag":"remote","server":"1.1.1.1","detour":"d2","connect_timeout":"3s"}]},
                "outbounds":[
                  {"type":"direct","tag":"d1","bind_interface":"eth0","inet4_bind_address":"192.0.2.1",
                   "inet6_bind_address":"2001:db8::1","bind_address_no_port":true,"protect_path":"/tmp/p",
                   "routing_mark":"0x20","reuse_addr":true,"netns":"ns1","connect_timeout":"2s",
                   "tcp_fast_open":true,"tcp_multi_path":true,"disable_tcp_keep_alive":true,
                   "tcp_keep_alive":"1m","tcp_keep_alive_interval":"10s","udp_fragment":false,
                   "domain_resolver":{"server":"local","strategy":"ipv4_only","rewrite_ttl":60,
                                      "disable_optimistic_cache":true},
                   "fallback_delay":"100ms","domain_strategy":"prefer_ipv6"},
                  {"type":"direct","tag":"d2","inet4_bind_address":"127.0.0.1"}],
                "route":{"default_interface":"eth1","default_mark":7}}"#,
        )
        .unwrap();
        let Outbound::Direct(direct) = &options.outbounds[0] else { panic!() };
        let dial = direct.dialer_options();
        assert_eq!(dial.bind_interface, "eth0");
        assert_eq!(dial.routing_mark, FwMark(0x20));
        assert_eq!(dial.udp_fragment, Some(false));
        assert!(dial.tcp_fast_open && dial.tcp_multi_path && dial.disable_tcp_keep_alive && dial.reuse_addr);
        assert_eq!(dial.fallback_delay.0, std::time::Duration::from_millis(100));
        assert_eq!(dial.domain_strategy, DomainStrategy::PreferIpv6);
        let resolver = dial.domain_resolver.clone().unwrap();
        assert_eq!((resolver.strategy, resolver.rewrite_ttl), (DomainStrategy::Ipv4Only, Some(60)));
        assert!(!dial.is_empty());
        assert_eq!(options.route.default_mark, FwMark(7));
        let DnsServer::Udp(remote) = &options.dns.servers[1] else { panic!() };
        assert_eq!(remote.dialer_options().detour, "d2");
    }

    #[test]
    fn dial_references_and_removed_fields() {
        for (config, needle) in [
            (
                r#"{"outbounds":[{"type":"direct","detour":"x"}]}"#,
                "outbounds[0].detour: `detour` is not supported in direct context",
            ),
            (r#"{"outbounds":[{"type":"direct","override_port":53}]}"#, "destination override fields"),
            (r#"{"outbounds":[{"type":"direct","proxy_protocol":1}]}"#, "Proxy Protocol"),
            (r#"{"outbounds":[{"type":"direct","inet4_bind_address":"::1"}]}"#, "not an IPv4 address"),
            (
                r#"{"dns":{"servers":[{"type":"udp","server":"1.1.1.1","detour":"nope"}]}}"#,
                "dns.servers[0].detour: outbound detour not found: nope",
            ),
            (
                r#"{"dns":{"servers":[{"type":"udp","server":"1.1.1.1","detour":"d"}]},"outbounds":[{"type":"direct","tag":"d"}]}"#,
                "detour to an empty direct outbound makes no sense",
            ),
            (r#"{"inbounds":[{"type":"socks","sniff":true}]}"#, "legacy inbound fields"),
            (r#"{"inbounds":[{"type":"socks","domain_strategy":"ipv4_only"}]}"#, "legacy inbound fields"),
            (r#"{"inbounds":[{"type":"http","proxy_protocol":true}]}"#, "Proxy Protocol"),
            (r#"{"inbounds":[{"type":"http","detour":"nope"}]}"#, "inbounds[0].detour: inbound detour not found: nope"),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(needle), "{config}: {error}");
        }
        // Legacy fields at their zero values are accepted, as sing-box does.
        parse(r#"{"inbounds":[{"type":"socks","sniff":false,"sniff_timeout":"0s","proxy_protocol":false}]}"#).unwrap();
    }

    #[test]
    fn listen_fields() {
        let options = parse(
            r#"{"inbounds":[
                  {"type":"mixed","tag":"a","listen":"::","listen_port":1080,"bind_interface":"eth0",
                   "routing_mark":16,"reuse_addr":true,"netns":"/run/netns/x","disable_tcp_keep_alive":false,
                   "tcp_keep_alive":"30s","tcp_keep_alive_interval":"5s","tcp_fast_open":true,
                   "tcp_multi_path":true,"udp_fragment":true,"udp_timeout":"1m","detour":"b"},
                  {"type":"socks","tag":"b"}]}"#,
        )
        .unwrap();
        let listen = options.inbounds[0].options().listen_options();
        assert_eq!(listen.listen, Some("::".parse().unwrap()));
        assert_eq!(listen.routing_mark, FwMark(16));
        assert_eq!(listen.detour, "b");
        assert_eq!(listen.udp_fragment, Some(true));
        assert_eq!(listen.udp_timeout.0 .0, std::time::Duration::from_secs(60));
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
