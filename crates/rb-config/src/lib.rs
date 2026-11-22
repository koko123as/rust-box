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
pub mod experimental;
pub mod query_types;
pub mod quic;
pub mod rule;
pub mod rule_set;
pub mod srs;
pub mod tls;
pub mod tun;
pub mod types;

use std::net::IpAddr;

use serde::Deserialize;
use serde_json::Value;

pub use dial::{DialerOptions, FwMark, InterfaceType, ListenOptions, NetworkStrategy};
pub use experimental::{
    CacheFileOptions, ClashApiOptions, DebugOptions, ExperimentalOptions, SelectorOutbound, UrlTestOutbound,
    V2RayApiOptions,
};
pub use quic::{
    Hysteria2Inbound, Hysteria2Obfs, Hysteria2Outbound, Hysteria2User, MemoryBytes, QuicOptions, TuicInbound,
    TuicOutbound, TuicUser,
};
pub use rule::{
    DnsMatchResponse, DnsRecordOptions, DnsResponseCode, DnsRouteActionOptions, DnsRule, DnsRuleAction, DnsRuleMatch,
    LogicalMode, RejectMethod, RejectOptions, RouteActionOptions, RouteRule, Rule, RuleAction, RuleMatch, SNIFFERS,
};
pub use rule_set::{
    DefaultHeadlessRule, HeadlessRule, LogicalHeadlessRule, PlainRuleSet, PlainRuleSetCompat, RemoteRuleSet,
    RuleSetKind, RuleSetOptions,
};
pub use tls::{Base64Bytes, ClientAuthType, CurvePreference, InboundTlsOptions, OutboundTlsOptions};
pub use types::{DomainResolveOptions, DomainStrategy, Duration, IpPrefix, Listable, QueryType, UdpTimeout, User};

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
    &["ntp", "certificate_providers", "endpoints", "services", "http_clients", "network_namespaces"];

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
    #[serde(default)]
    pub experimental: Option<ExperimentalOptions>,
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
    #[serde(rename = "tls")]
    Tls(Box<RemoteTlsDnsServer>),
    #[serde(rename = "quic")]
    Quic(Box<RemoteTlsDnsServer>),
    #[serde(rename = "https")]
    Https(Box<RemoteHttpsDnsServer>),
    #[serde(rename = "h3")]
    Http3(Box<RemoteHttpsDnsServer>),
    #[serde(rename = "hosts")]
    Hosts(HostsDnsServer),
    #[serde(rename = "fakeip")]
    FakeIp(FakeIpDnsServer),
}

impl DnsServer {
    pub fn tag(&self) -> &str {
        match self {
            DnsServer::Local { tag } => tag,
            DnsServer::Udp(server) | DnsServer::Tcp(server) => &server.tag,
            DnsServer::Tls(server) | DnsServer::Quic(server) => &server.tag,
            DnsServer::Https(server) | DnsServer::Http3(server) => &server.tag,
            DnsServer::Hosts(server) => &server.tag,
            DnsServer::FakeIp(server) => &server.tag,
        }
    }
}

with_dial_fields! {
    /// sing-box `RemoteDNSServerOptions` with its dial fields (the server
    /// for `udp` and `tcp` must be an IP address in rust-box).
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

with_dial_fields! {
    /// sing-box `RemoteTLSDNSServerOptions` (DNS over TLS).
    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RemoteTlsDnsServer {
        #[serde(default)]
        pub tag: String,
        pub server: String,
        #[serde(default)]
        pub server_port: u16,
        #[serde(default)]
        pub tls: Option<OutboundTlsOptions>,
    }
}

with_dial_fields! {
    /// sing-box `RemoteHTTPSDNSServerOptions` (DNS over HTTPS).
    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RemoteHttpsDnsServer {
        #[serde(default)]
        pub tag: String,
        pub server: String,
        #[serde(default)]
        pub server_port: u16,
        #[serde(default)]
        pub path: String,
        #[serde(default)]
        pub method: String,
        #[serde(default)]
        pub headers: std::collections::BTreeMap<String, Listable<String>>,
        #[serde(default)]
        pub tls: Option<OutboundTlsOptions>,
    }
}

/// sing-box `HostsDNSServerOptions`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostsDnsServer {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub path: Listable<String>,
    #[serde(default)]
    pub predefined: Option<std::collections::BTreeMap<String, Listable<IpAddr>>>,
}

/// sing-box `FakeIPDNSServerOptions`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeIpDnsServer {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub inet4_range: Option<IpPrefix>,
    #[serde(default)]
    pub inet6_range: Option<IpPrefix>,
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
    #[serde(rename = "shadowsocks")]
    Shadowsocks(ShadowsocksInbound),
    #[serde(rename = "trojan")]
    Trojan(TrojanInbound),
    #[serde(rename = "vless")]
    Vless(VlessInbound),
    #[serde(rename = "vmess")]
    Vmess(VmessInbound),
    #[serde(rename = "tun")]
    Tun(tun::TunInbound),
    #[serde(rename = "tuic")]
    Tuic(TuicInbound),
    #[serde(rename = "hysteria2")]
    Hysteria2(Hysteria2Inbound),
}

impl Inbound {
    pub fn tag(&self) -> &str {
        match self {
            Inbound::Mixed(options) | Inbound::Socks(options) | Inbound::Http(options) => &options.tag,
            Inbound::Shadowsocks(options) => &options.tag,
            Inbound::Trojan(options) => &options.tag,
            Inbound::Vless(options) => &options.tag,
            Inbound::Vmess(options) => &options.tag,
            Inbound::Tun(options) => &options.tag,
            Inbound::Tuic(options) => &options.tag,
            Inbound::Hysteria2(options) => &options.tag,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Inbound::Mixed(_) => "mixed",
            Inbound::Socks(_) => "socks",
            Inbound::Http(_) => "http",
            Inbound::Shadowsocks(_) => "shadowsocks",
            Inbound::Trojan(_) => "trojan",
            Inbound::Vless(_) => "vless",
            Inbound::Vmess(_) => "vmess",
            Inbound::Tun(_) => "tun",
            Inbound::Tuic(_) => "tuic",
            Inbound::Hysteria2(_) => "hysteria2",
        }
    }

    /// The listen fields of any inbound.
    pub fn listen_options(&self) -> ListenOptions {
        match self {
            Inbound::Mixed(options) | Inbound::Socks(options) | Inbound::Http(options) => options.listen_options(),
            Inbound::Shadowsocks(options) => options.listen_options(),
            Inbound::Trojan(options) => options.listen_options(),
            Inbound::Vless(options) => options.listen_options(),
            Inbound::Vmess(options) => options.listen_options(),
            Inbound::Tun(_) => ListenOptions::default(),
            Inbound::Tuic(options) => options.listen_options(),
            Inbound::Hysteria2(options) => options.listen_options(),
        }
    }

    /// The error sing-box reports for a removed listen field that is set.
    pub fn removed_field_error(&self) -> Option<&'static str> {
        match self {
            Inbound::Mixed(options) | Inbound::Socks(options) | Inbound::Http(options) => options.removed_field_error(),
            Inbound::Shadowsocks(options) => options.removed_field_error(),
            Inbound::Trojan(options) => options.removed_field_error(),
            Inbound::Vless(options) => options.removed_field_error(),
            Inbound::Vmess(options) => options.removed_field_error(),
            Inbound::Tun(options) => options.removed_field_error(),
            Inbound::Tuic(options) => options.removed_field_error(),
            Inbound::Hysteria2(options) => options.removed_field_error(),
        }
    }
}

with_listen_fields! {
    /// sing-box `ShadowsocksInboundOptions`.
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ShadowsocksInbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub network: NetworkList,
        #[serde(default)]
        pub method: String,
        #[serde(default)]
        pub password: String,
        #[serde(default)]
        pub users: Vec<ShadowsocksUser>,
        #[serde(default)]
        pub destinations: Vec<ShadowsocksDestination>,
        /// Not supported yet: rejected when enabled.
        #[serde(default)]
        pub multiplex: Option<InboundMultiplexOptions>,
        /// Accepted: without the SSM API service (which rust-box does not
        /// have) a managed inbound simply has no users, as in sing-box.
        #[serde(default)]
        pub managed: bool,
    }
}

/// sing-box `ShadowsocksUser`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksUser {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub password: String,
}

/// sing-box `ShadowsocksDestination` (a relay destination).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksDestination {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub server_port: u16,
}

/// sing-box `BrutalOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrutalOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub up_mbps: i64,
    #[serde(default)]
    pub down_mbps: i64,
}

/// sing-box `InboundMultiplexOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundMultiplexOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub padding: bool,
    #[serde(default)]
    pub brutal: Option<BrutalOptions>,
}

/// sing-box `OutboundMultiplexOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundMultiplexOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub max_connections: i64,
    #[serde(default)]
    pub min_streams: i64,
    #[serde(default)]
    pub max_streams: i64,
    #[serde(default)]
    pub padding: bool,
    #[serde(default)]
    pub brutal: Option<BrutalOptions>,
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
        /// `http` and `mixed` only (sing-box `InboundTLSOptionsContainer`
        /// in `HTTPMixedInboundOptions`); rejected on `socks`.
        #[serde(default)]
        pub tls: Option<InboundTlsOptions>,
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
    #[serde(rename = "socks")]
    Socks(SocksOutbound),
    #[serde(rename = "http")]
    Http(HttpOutbound),
    #[serde(rename = "shadowsocks")]
    Shadowsocks(ShadowsocksOutbound),
    #[serde(rename = "trojan")]
    Trojan(TrojanOutbound),
    #[serde(rename = "vless")]
    Vless(VlessOutbound),
    #[serde(rename = "vmess")]
    Vmess(VmessOutbound),
    #[serde(rename = "selector")]
    Selector(SelectorOutbound),
    #[serde(rename = "urltest")]
    UrlTest(UrlTestOutbound),
    #[serde(rename = "tuic")]
    Tuic(TuicOutbound),
    #[serde(rename = "hysteria2")]
    Hysteria2(Hysteria2Outbound),
}

impl Outbound {
    pub fn tag(&self) -> &str {
        match self {
            Outbound::Direct(options) => &options.tag,
            Outbound::Block(options) => &options.tag,
            Outbound::Socks(options) => &options.tag,
            Outbound::Http(options) => &options.tag,
            Outbound::Shadowsocks(options) => &options.tag,
            Outbound::Trojan(options) => &options.tag,
            Outbound::Vless(options) => &options.tag,
            Outbound::Vmess(options) => &options.tag,
            Outbound::Selector(options) => &options.tag,
            Outbound::UrlTest(options) => &options.tag,
            Outbound::Tuic(options) => &options.tag,
            Outbound::Hysteria2(options) => &options.tag,
        }
    }

    /// The dial fields of an outbound that dials (sing-box outbounds
    /// embedding `DialerOptions`).
    pub fn dialer_options(&self) -> Option<DialerOptions> {
        match self {
            Outbound::Direct(options) => Some(options.dialer_options()),
            Outbound::Block(_) => None,
            Outbound::Socks(options) => Some(options.dialer_options()),
            Outbound::Http(options) => Some(options.dialer_options()),
            Outbound::Shadowsocks(options) => Some(options.dialer_options()),
            Outbound::Trojan(options) => Some(options.dialer_options()),
            Outbound::Vless(options) => Some(options.dialer_options()),
            Outbound::Vmess(options) => Some(options.dialer_options()),
            Outbound::Selector(_) | Outbound::UrlTest(_) => None,
            Outbound::Tuic(options) => Some(options.dialer_options()),
            Outbound::Hysteria2(options) => Some(options.dialer_options()),
        }
    }
}

/// sing-box `option.NetworkList`: `tcp`, `udp` or both, as one string or a
/// list. Empty means both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkList(pub Vec<String>);

impl NetworkList {
    /// sing-box `NetworkList.Build`.
    pub fn build(&self) -> Vec<String> {
        if self.0.is_empty() {
            vec!["tcp".into(), "udp".into()]
        } else {
            self.0.clone()
        }
    }
}

impl<'de> Deserialize<'de> for NetworkList {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let list = Listable::<String>::deserialize(deserializer)?;
        for network in list.iter() {
            if network != "tcp" && network != "udp" {
                return Err(serde::de::Error::custom(format!("unknown network: {network}")));
            }
        }
        Ok(NetworkList(list.0))
    }
}

/// sing-box `option.UDPOverTCPOptions`: a bool, or `{"enabled", "version"}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UdpOverTcpOptions {
    pub enabled: bool,
    pub version: u8,
}

impl<'de> Deserialize<'de> for UdpOverTcpOptions {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Object {
            #[serde(default)]
            enabled: bool,
            #[serde(default)]
            version: u8,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Form {
            Bool(bool),
            Object(Object),
        }
        Ok(match Form::deserialize(deserializer)? {
            Form::Bool(enabled) => UdpOverTcpOptions { enabled, version: 0 },
            Form::Object(object) => UdpOverTcpOptions { enabled: object.enabled, version: object.version },
        })
    }
}

with_dial_fields! {
    /// sing-box `SOCKSOutboundOptions` (`DialerOptions` + `ServerOptions`).
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SocksOutbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub server: String,
        #[serde(default)]
        pub server_port: u16,
        /// `4`, `4a` or `5` (the default).
        #[serde(default)]
        pub version: String,
        #[serde(default)]
        pub username: String,
        #[serde(default)]
        pub password: String,
        #[serde(default)]
        pub network: NetworkList,
        /// Not supported yet: rejected when enabled.
        #[serde(default)]
        pub udp_over_tcp: Option<UdpOverTcpOptions>,
    }
}

with_dial_fields! {
    /// sing-box `ShadowsocksOutboundOptions` (`DialerOptions` + `ServerOptions`).
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ShadowsocksOutbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub server: String,
        #[serde(default)]
        pub server_port: u16,
        #[serde(default)]
        pub method: String,
        #[serde(default)]
        pub password: String,
        /// SIP003 plugin: not supported yet, rejected when set.
        #[serde(default)]
        pub plugin: String,
        #[serde(default)]
        pub plugin_opts: String,
        #[serde(default)]
        pub network: NetworkList,
        #[serde(default)]
        pub udp_over_tcp: Option<UdpOverTcpOptions>,
        /// Not supported yet: rejected when enabled (and `udp_over_tcp` is
        /// not, which makes sing-box ignore it).
        #[serde(default)]
        pub multiplex: Option<OutboundMultiplexOptions>,
    }
}

/// The `tls`, `multiplex` and `transport` checks of the trojan, vless and
/// vmess outbounds.
fn check_proxy_outbound(
    path: &str,
    tls: Option<&OutboundTlsOptions>,
    multiplex: Option<&OutboundMultiplexOptions>,
    transport: &Option<V2RayTransportOptions>,
) -> Result<(), ConfigError> {
    let field = |path: String, message: String| ConfigError::Field { path, message };
    if let Some(tls) = tls {
        tls.validate(&format!("{path}.tls"))?;
    }
    if multiplex
        .is_some_and(|multiplex| multiplex.enabled && multiplex.brutal.as_ref().is_some_and(|brutal| brutal.enabled))
    {
        return Err(field(format!("{path}.multiplex.brutal"), "`brutal` is not supported by rust-box yet".into()));
    }
    check_v2ray_transport(&format!("{path}.transport"), transport.as_ref(), true)?;
    Ok(())
}

fn check_tuic_outbound(path: &str, options: &TuicOutbound) -> Result<(), ConfigError> {
    let field = |name: &str, message: String| ConfigError::Field { path: format!("{path}.{name}"), message };
    let Some(tls) = options.tls.as_ref() else {
        return Err(field("tls", "TLS is required".into()));
    };
    if !tls.enabled {
        return Err(field("tls.enabled", "TLS is required".into()));
    }
    tls.validate(&format!("{path}.tls"))?;

    match options.congestion_control.as_str() {
        "" | "cubic" => {}
        "new_reno" | "bbr" => {
            return Err(field("congestion_control", "`congestion_control` is not supported by rust-box yet".into()));
        }
        other => {
            return Err(field("congestion_control", format!("unknown congestion control algorithm: {other}")));
        }
    }
    if options.udp_over_stream && !options.udp_relay_mode.is_empty() {
        return Err(field("udp_over_stream", "udp_over_stream is conflict with udp_relay_mode".into()));
    }
    match options.udp_relay_mode.as_str() {
        "" | "native" => {}
        "quic" => {
            return Err(field("udp_relay_mode", "`udp_relay_mode` is not supported by rust-box yet".into()));
        }
        other => return Err(field("udp_relay_mode", format!("unknown UDP relay mode: {other}"))),
    }
    if options.zero_rtt_handshake {
        return Err(field("zero_rtt_handshake", "`zero_rtt_handshake` is not supported by rust-box yet".into()));
    }
    if options.udp_over_stream {
        return Err(field("udp_over_stream", "`udp_over_stream` is not supported by rust-box yet".into()));
    }
    Ok(())
}

fn check_v2ray_transport(
    path: &str,
    transport: Option<&V2RayTransportOptions>,
    allow_grpc: bool,
) -> Result<(), ConfigError> {
    let field = |path: String, message: String| ConfigError::Field { path, message };
    let Some(transport) = transport else { return Ok(()) };
    match &transport.config {
        V2RayTransportConfig::WebSocket(options)
            if options.max_early_data == 0 && options.early_data_header_name.is_empty() =>
        {
            Ok(())
        }
        V2RayTransportConfig::WebSocket(options) if options.max_early_data > 0 => {
            Err(field(format!("{path}.max_early_data"), "`max_early_data` is not supported by rust-box yet".into()))
        }
        V2RayTransportConfig::WebSocket(_) => Err(field(
            format!("{path}.early_data_header_name"),
            "`early_data_header_name` is not supported by rust-box yet".into(),
        )),
        V2RayTransportConfig::HttpUpgrade(_) => Ok(()),
        V2RayTransportConfig::Http(options) => {
            for (name, duration) in [("idle_timeout", options.idle_timeout.0), ("ping_timeout", options.ping_timeout.0)]
            {
                if !duration.is_zero() {
                    return Err(field(format!("{path}.{name}"), format!("`{name}` is not supported by rust-box yet")));
                }
            }
            Ok(())
        }
        V2RayTransportConfig::Grpc(options) if allow_grpc => {
            for (name, duration) in [("idle_timeout", options.idle_timeout.0), ("ping_timeout", options.ping_timeout.0)]
            {
                if !duration.is_zero() {
                    return Err(field(format!("{path}.{name}"), format!("`{name}` is not supported by rust-box yet")));
                }
            }
            if options.permit_without_stream {
                return Err(field(
                    format!("{path}.permit_without_stream"),
                    "`permit_without_stream` is not supported by rust-box yet".into(),
                ));
            }
            Ok(())
        }
        _ => Err(field(path.to_string(), "`transport` is not supported by rust-box yet".into())),
    }
}

fn check_hysteria2_obfs(path: &str, obfs: Option<&Hysteria2Obfs>) -> Result<(), ConfigError> {
    let Some(obfs) = obfs else { return Ok(()) };
    let field_path = format!("{path}.type");
    let message = match obfs.r#type.as_str() {
        "salamander" | "gecko" => "`obfs.type` is not supported by rust-box yet".to_string(),
        other => format!("unknown Hysteria2 obfs type: {other}"),
    };
    Err(ConfigError::Field { path: field_path, message })
}

fn check_hysteria2_inbound(path: &str, options: &Hysteria2Inbound) -> Result<(), ConfigError> {
    let field = |name: &str| ConfigError::Field {
        path: format!("{path}.{name}"),
        message: format!("`{name}` is not supported by rust-box yet"),
    };
    if options.masquerade.is_some() {
        return Err(field("masquerade"));
    }
    if options.realm.is_some() {
        return Err(field("realm"));
    }
    if !options.detour.is_empty() {
        return Err(field("detour"));
    }
    check_hysteria2_obfs(&format!("{path}.obfs"), options.obfs.as_ref())?;
    for (name, enabled) in [("bbr_profile", !options.bbr_profile.is_empty()), ("brutal_debug", options.brutal_debug)] {
        if enabled {
            return Err(field(name));
        }
    }
    Ok(())
}

fn check_hysteria2_outbound(path: &str, options: &Hysteria2Outbound) -> Result<(), ConfigError> {
    let field = |name: &str| ConfigError::Field {
        path: format!("{path}.{name}"),
        message: format!("`{name}` is not supported by rust-box yet"),
    };
    if options.realm.is_some() {
        return Err(field("realm"));
    }
    check_hysteria2_obfs(&format!("{path}.obfs"), options.obfs.as_ref())?;
    if !options.disable_chrome_parrot {
        return Err(field("disable_chrome_parrot"));
    }
    for (name, enabled) in [
        ("server_ports", !options.server_ports.is_empty()),
        ("hop_interval", !options.hop_interval.0.is_zero()),
        ("hop_interval_max", !options.hop_interval_max.0.is_zero()),
        ("bbr_profile", !options.bbr_profile.is_empty()),
        ("brutal_debug", options.brutal_debug),
    ] {
        if enabled {
            return Err(field(name));
        }
    }
    Ok(())
}

/// A V2Ray transport configuration. Unsupported transport features are
/// rejected with their configuration path.
#[derive(Debug, Clone, PartialEq)]
pub struct V2RayTransportOptions {
    pub r#type: String,
    pub config: V2RayTransportConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub enum V2RayTransportConfig {
    Http(V2RayHttpOptions),
    WebSocket(V2RayWebSocketOptions),
    Grpc(V2RayGrpcOptions),
    HttpUpgrade(V2RayHttpUpgradeOptions),
    /// The upstream `quic` transport is recognized but is outside this
    /// milestone's supported transport set.
    Quic(serde_json::Value),
}

pub type V2RayHeaders = std::collections::HashMap<String, Listable<String>>;

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2RayWebSocketOptions {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub headers: V2RayHeaders,
    #[serde(default)]
    pub max_early_data: u32,
    #[serde(default)]
    pub early_data_header_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2RayHttpOptions {
    #[serde(default)]
    pub host: Listable<String>,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub headers: V2RayHeaders,
    #[serde(default)]
    pub idle_timeout: Duration,
    #[serde(default)]
    pub ping_timeout: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2RayGrpcOptions {
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub idle_timeout: Duration,
    #[serde(default)]
    pub ping_timeout: Duration,
    #[serde(default)]
    pub permit_without_stream: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2RayHttpUpgradeOptions {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub headers: V2RayHeaders,
}

impl<'de> Deserialize<'de> for V2RayTransportOptions {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let options = serde_json::Value::deserialize(deserializer)?;
        let serde_json::Value::Object(mut object) = options else {
            return Err(serde::de::Error::custom("invalid type: expected an object"));
        };
        let r#type = match object.remove("type") {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::String(value)) => value,
            Some(_) => return Err(serde::de::Error::custom("invalid type: expected a string for `type`")),
        };
        let fields = serde_json::Value::Object(object);
        let config = match r#type.as_str() {
            "http" => V2RayTransportConfig::Http(serde_json::from_value(fields).map_err(serde::de::Error::custom)?),
            "ws" => V2RayTransportConfig::WebSocket(serde_json::from_value(fields).map_err(serde::de::Error::custom)?),
            "grpc" => V2RayTransportConfig::Grpc(serde_json::from_value(fields).map_err(serde::de::Error::custom)?),
            "httpupgrade" => {
                V2RayTransportConfig::HttpUpgrade(serde_json::from_value(fields).map_err(serde::de::Error::custom)?)
            }
            "quic" => V2RayTransportConfig::Quic(fields),
            other => return Err(serde::de::Error::custom(format!("unknown transport type: {other}"))),
        };
        Ok(V2RayTransportOptions { r#type, config })
    }
}

/// sing-box `ServerOptions` (`server`, `server_port`) as an object, as the
/// trojan inbound's `fallback` uses it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerOptions {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub server_port: u16,
}

with_listen_fields! {
    /// sing-box `TrojanInboundOptions`.
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TrojanInbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub users: Vec<TrojanUser>,
        #[serde(default)]
        pub tls: Option<InboundTlsOptions>,
        #[serde(default)]
        pub fallback: Option<ServerOptions>,
        /// ALPN protocol to fallback server (`null` values count as an
        /// empty server, as sing-box's nil pointer would not build).
        #[serde(default)]
        pub fallback_for_alpn: std::collections::BTreeMap<String, Option<ServerOptions>>,
        /// Not supported yet: rejected when enabled.
        #[serde(default)]
        pub multiplex: Option<InboundMultiplexOptions>,
        /// WebSocket and HTTPUpgrade are supported; other V2Ray transport types are rejected.
        #[serde(default)]
        pub transport: Option<V2RayTransportOptions>,
    }
}

impl TrojanInbound {
    /// sing-box `trojan.NewInbound`'s fallback checks.
    pub fn validate_fallback(&self, path: &str) -> Result<(), ConfigError> {
        let field = |message: String| ConfigError::Field { path: path.to_string(), message };
        let tls = self.tls.as_ref().is_some_and(|tls| tls.enabled);
        if !self.fallback_for_alpn.is_empty() {
            if !tls {
                return Err(field("fallback for ALPN is not supported without TLS".into()));
            }
            for (protocol, destination) in &self.fallback_for_alpn {
                let server = destination.as_ref().map_or("", |destination| destination.server.as_str());
                if server.is_empty() {
                    let port = destination.as_ref().map_or(0, |destination| destination.server_port);
                    return Err(field(format!("invalid fallback address for ALPN {protocol}: :{port}")));
                }
            }
        }
        Ok(())
    }
}

/// sing-box `TrojanUser`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanUser {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub password: String,
}

with_listen_fields! {
    /// sing-box `VLESSInboundOptions`.
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct VlessInbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub users: Vec<VlessUser>,
        #[serde(default)]
        pub tls: Option<InboundTlsOptions>,
        /// Not supported yet: rejected when enabled.
        #[serde(default)]
        pub multiplex: Option<InboundMultiplexOptions>,
        /// WebSocket and HTTPUpgrade are supported; other V2Ray transport types are rejected.
        #[serde(default)]
        pub transport: Option<V2RayTransportOptions>,
    }
}

/// sing-box `VLESSUser`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessUser {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub flow: String,
}

with_dial_fields! {
    /// sing-box `TrojanOutboundOptions` (`DialerOptions` + `ServerOptions`).
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TrojanOutbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub server: String,
        #[serde(default)]
        pub server_port: u16,
        #[serde(default)]
        pub password: String,
        #[serde(default)]
        pub network: NetworkList,
        #[serde(default)]
        pub tls: Option<OutboundTlsOptions>,
        /// Not supported yet: rejected when enabled.
        #[serde(default)]
        pub multiplex: Option<OutboundMultiplexOptions>,
        /// WebSocket and HTTPUpgrade are supported; other V2Ray transport types are rejected.
        #[serde(default)]
        pub transport: Option<V2RayTransportOptions>,
    }
}

with_dial_fields! {
    /// sing-box `VLESSOutboundOptions` (`DialerOptions` + `ServerOptions`).
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct VlessOutbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub server: String,
        #[serde(default)]
        pub server_port: u16,
        #[serde(default)]
        pub uuid: String,
        #[serde(default)]
        pub flow: String,
        #[serde(default)]
        pub network: NetworkList,
        #[serde(default)]
        pub tls: Option<OutboundTlsOptions>,
        /// Not supported yet: rejected when enabled.
        #[serde(default)]
        pub multiplex: Option<OutboundMultiplexOptions>,
        /// WebSocket and HTTPUpgrade are supported; other V2Ray transport types are rejected.
        #[serde(default)]
        pub transport: Option<V2RayTransportOptions>,
        /// `xudp` (the default when absent), `packetaddr`, or empty for
        /// none; anything else fails when the outbound is built, as in
        /// sing-box.
        #[serde(default)]
        pub packet_encoding: Option<String>,
    }
}

with_listen_fields! {
    /// sing-box `VMessInboundOptions`.
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct VmessInbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub users: Vec<VmessUser>,
        #[serde(default)]
        pub tls: Option<InboundTlsOptions>,
        /// Not supported yet: rejected when enabled.
        #[serde(default)]
        pub multiplex: Option<InboundMultiplexOptions>,
        /// WebSocket and HTTPUpgrade are supported; other V2Ray transport types are rejected.
        #[serde(default)]
        pub transport: Option<V2RayTransportOptions>,
    }
}

/// sing-box `VMessUser` (`alterId` is camel case, as in sing-box; Go's
/// `int`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmessUser {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub uuid: String,
    #[serde(default, rename = "alterId")]
    pub alter_id: i64,
}

with_dial_fields! {
    /// sing-box `VMessOutboundOptions` (`DialerOptions` + `ServerOptions`).
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct VmessOutbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub server: String,
        #[serde(default)]
        pub server_port: u16,
        #[serde(default)]
        pub uuid: String,
        /// `auto` (also when empty), `none`, `zero`, `aes-128-cfb`,
        /// `aes-128-gcm`, `chacha20-poly1305`; anything else fails when the
        /// outbound is built ("vmess: unsupported security type: X").
        #[serde(default)]
        pub security: String,
        #[serde(default)]
        pub alter_id: i64,
        #[serde(default)]
        pub global_padding: bool,
        #[serde(default)]
        pub authenticated_length: bool,
        #[serde(default)]
        pub network: NetworkList,
        #[serde(default)]
        pub tls: Option<OutboundTlsOptions>,
        /// Empty (none, the default), `packetaddr` or `xudp`; anything else
        /// fails when the outbound is built.
        #[serde(default)]
        pub packet_encoding: String,
        /// Not supported yet: rejected when enabled.
        #[serde(default)]
        pub multiplex: Option<OutboundMultiplexOptions>,
        /// WebSocket and HTTPUpgrade are supported; other V2Ray transport types are rejected.
        #[serde(default)]
        pub transport: Option<V2RayTransportOptions>,
    }
}

with_dial_fields! {
    /// sing-box `HTTPOutboundOptions` (`DialerOptions` + `ServerOptions`).
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HttpOutbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub server: String,
        #[serde(default)]
        pub server_port: u16,
        #[serde(default)]
        pub username: String,
        #[serde(default)]
        pub password: String,
        #[serde(default)]
        pub tls: Option<OutboundTlsOptions>,
        #[serde(default)]
        pub path: String,
        /// sing-box `badoption.HTTPHeader`: a name to one value or a list.
        #[serde(default)]
        pub headers: std::collections::BTreeMap<String, Listable<String>>,
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
    /// Outbound sockets are protected by the platform interface, or bound
    /// to the default interface (Linux), so they do not loop into a TUN.
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

fn validate_hosts_predefined(value: &Value) -> Result<(), ConfigError> {
    let Some(servers) = value.get("dns").and_then(|dns| dns.get("servers")).and_then(Value::as_array) else {
        return Ok(());
    };
    for (index, server) in servers.iter().enumerate() {
        if server.get("type").and_then(Value::as_str) != Some("hosts") {
            continue;
        }
        let Some(predefined) = server.get("predefined").and_then(Value::as_object) else { continue };
        for (domain, addresses) in predefined {
            let invalid = match addresses {
                Value::String(address) => address.parse::<IpAddr>().is_err(),
                Value::Array(values) => {
                    values.iter().filter_map(Value::as_str).any(|address| address.parse::<IpAddr>().is_err())
                }
                _ => false,
            };
            if invalid {
                return Err(ConfigError::Field {
                    path: format!("dns.servers[{index}].predefined.{domain}"),
                    message: "invalid IP address syntax".into(),
                });
            }
        }
    }
    Ok(())
}

fn validate_fakeip_ranges(value: &Value) -> Result<(), ConfigError> {
    let Some(servers) = value.get("dns").and_then(|dns| dns.get("servers")).and_then(Value::as_array) else {
        return Ok(());
    };
    for (index, server) in servers.iter().enumerate() {
        if server.get("type").and_then(Value::as_str) != Some("fakeip") {
            continue;
        }
        for field in ["inet4_range", "inet6_range"] {
            let Some(range) = server.get(field) else { continue };
            let result = match range {
                Value::Null => continue,
                Value::String(prefix) => prefix.parse::<IpPrefix>().map(|_| ()).map_err(|error| error.to_string()),
                other => serde_json::from_value::<String>(other.clone()).map(|_| ()).map_err(|error| error.to_string()),
            };
            if let Err(message) = result {
                return Err(ConfigError::Field { path: format!("dns.servers[{index}].{field}"), message });
            }
        }
    }
    Ok(())
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
    validate_hosts_predefined(&value)?;
    validate_fakeip_ranges(&value)?;
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
        if let Some(experimental) = &self.experimental {
            experimental.validate_debug()?;
        }
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
            if let Some(message) = inbound.removed_field_error() {
                return Err(field(format!("inbounds[{index}]"), message.to_string()));
            }
            let detour = &inbound.listen_options().detour;
            if !detour.is_empty() && !inbound_tags.contains(detour) {
                return Err(field(format!("inbounds[{index}].detour"), format!("inbound detour not found: {detour}")));
            }
            let multiplex = match inbound {
                Inbound::Shadowsocks(options) => options.multiplex.as_ref(),
                Inbound::Trojan(options) => options.multiplex.as_ref(),
                Inbound::Vless(options) => options.multiplex.as_ref(),
                Inbound::Vmess(options) => options.multiplex.as_ref(),
                _ => None,
            };
            if multiplex.is_some_and(|multiplex| {
                multiplex.enabled && multiplex.brutal.as_ref().is_some_and(|brutal| brutal.enabled)
            }) {
                return Err(field(
                    format!("inbounds[{index}].multiplex.brutal"),
                    "`brutal` is not supported by rust-box yet".into(),
                ));
            }
            let transport = match inbound {
                Inbound::Trojan(options) => options.transport.as_ref(),
                Inbound::Vless(options) => options.transport.as_ref(),
                Inbound::Vmess(options) => options.transport.as_ref(),
                _ => None,
            };
            check_v2ray_transport(&format!("inbounds[{index}].transport"), transport, true)?;
            if let Inbound::Hysteria2(options) = inbound {
                check_hysteria2_inbound(&format!("inbounds[{index}]"), options)?;
            }
            if let Inbound::Trojan(trojan) = inbound {
                trojan.validate_fallback(&format!("inbounds[{index}]"))?;
            }
            if let Inbound::Tun(tun) = inbound {
                let rule_set_known =
                    |tag: &str| self.route.rule_set.iter().any(|set| set.tags.iter().any(|t| t == tag));
                tun.validate(&format!("inbounds[{index}]"), &rule_set_known)?;
            }
            let tls = match inbound {
                Inbound::Mixed(options) | Inbound::Socks(options) | Inbound::Http(options) => options.tls.as_ref(),
                Inbound::Shadowsocks(_) | Inbound::Tun(_) => None,
                Inbound::Trojan(options) => options.tls.as_ref(),
                Inbound::Vless(options) => options.tls.as_ref(),
                Inbound::Vmess(options) => options.tls.as_ref(),
                Inbound::Tuic(options) => options.tls.as_ref(),
                Inbound::Hysteria2(options) => options.tls.as_ref(),
            };
            if let Some(tls) = tls {
                // sing-box's socks inbound has no `tls` field.
                if matches!(inbound, Inbound::Socks(_)) {
                    return Err(field(format!("inbounds[{index}]"), "unknown field `tls`".into()));
                }
                tls.validate(&format!("inbounds[{index}].tls"))?;
            }
        }
        for (index, outbound) in self.outbounds.iter().enumerate() {
            let path = format!("outbounds[{index}]");
            match outbound {
                Outbound::Socks(socks) => {
                    if !matches!(socks.version.as_str(), "" | "4" | "4a" | "5") {
                        return Err(field(
                            format!("{path}.version"),
                            format!("unknown socks version: {}", socks.version),
                        ));
                    }
                    if socks.udp_over_tcp.as_ref().is_some_and(|uot| uot.enabled) {
                        return Err(field(
                            format!("{path}.udp_over_tcp"),
                            "`udp_over_tcp` is not supported by rust-box yet".into(),
                        ));
                    }
                    self.check_dialer(&path, &socks.dialer_options(), &server_known)?;
                }
                Outbound::Http(http) => {
                    if let Some(tls) = &http.tls {
                        tls.validate(&format!("{path}.tls"))?;
                    }
                    self.check_dialer(&path, &http.dialer_options(), &server_known)?;
                }
                Outbound::Shadowsocks(shadowsocks) => {
                    if !shadowsocks.plugin.is_empty() {
                        return Err(field(
                            format!("{path}.plugin"),
                            "`plugin` is not supported by rust-box yet".into(),
                        ));
                    }
                    let uot = shadowsocks.udp_over_tcp.as_ref().is_some_and(|uot| uot.enabled);
                    if !uot
                        && shadowsocks.multiplex.as_ref().is_some_and(|multiplex| {
                            multiplex.enabled && multiplex.brutal.as_ref().is_some_and(|brutal| brutal.enabled)
                        })
                    {
                        return Err(field(
                            format!("{path}.multiplex.brutal"),
                            "`brutal` is not supported by rust-box yet".into(),
                        ));
                    }
                    self.check_dialer(&path, &shadowsocks.dialer_options(), &server_known)?;
                }
                Outbound::Trojan(trojan) => {
                    check_proxy_outbound(&path, trojan.tls.as_ref(), trojan.multiplex.as_ref(), &trojan.transport)?;
                    self.check_dialer(&path, &trojan.dialer_options(), &server_known)?;
                }
                Outbound::Vless(vless) => {
                    check_proxy_outbound(&path, vless.tls.as_ref(), vless.multiplex.as_ref(), &vless.transport)?;
                    self.check_dialer(&path, &vless.dialer_options(), &server_known)?;
                }
                Outbound::Vmess(vmess) => {
                    check_proxy_outbound(&path, vmess.tls.as_ref(), vmess.multiplex.as_ref(), &vmess.transport)?;
                    self.check_dialer(&path, &vmess.dialer_options(), &server_known)?;
                }
                Outbound::Selector(selector) => experimental::check_group_tags(&path, &selector.outbounds)?,
                Outbound::UrlTest(urltest) => experimental::check_group_tags(&path, &urltest.outbounds)?,
                Outbound::Tuic(tuic) => {
                    check_tuic_outbound(&path, tuic)?;
                    self.check_dialer(&path, &tuic.dialer_options(), &server_known)?;
                }
                Outbound::Hysteria2(hysteria2) => check_hysteria2_outbound(&path, hysteria2)?,
                _ => {}
            }
            let Outbound::Direct(direct) = outbound else { continue };
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
            match server {
                DnsServer::Udp(remote) | DnsServer::Tcp(remote) => {
                    self.check_dialer(&format!("dns.servers[{index}]"), &remote.dialer_options(), &server_known)?;
                }
                DnsServer::Tls(remote) | DnsServer::Quic(remote) => {
                    self.check_dialer(&format!("dns.servers[{index}]"), &remote.dialer_options(), &server_known)?;
                    if let Some(tls) = &remote.tls {
                        // sing-box forces TLS on for `type: tls` and `type: quic`,
                        // even when `enabled` is absent or false.
                        let mut tls = tls.clone();
                        tls.enabled = true;
                        tls.validate(&format!("dns.servers[{index}].tls"))?;
                    }
                }
                DnsServer::Https(remote) | DnsServer::Http3(remote) => {
                    self.check_dialer(&format!("dns.servers[{index}]"), &remote.dialer_options(), &server_known)?;
                    if let Some(tls) = &remote.tls {
                        // sing-box forces TLS on for `type: https` and `type: h3` DNS servers.
                        let mut tls = tls.clone();
                        tls.enabled = true;
                        tls.validate(&format!("dns.servers[{index}].tls"))?;
                    }
                }
                _ => {}
            }
        }
        if !self.dns.r#final.is_empty() && !server_known(&self.dns.r#final) {
            return Err(field("dns.final".into(), format!("DNS server not found: {}", self.dns.r#final)));
        }
        let check_dns_route_options = |path: &str, options: &rule::DnsRouteActionOptions| {
            if options.client_subnet.is_some() {
                return Err(field(
                    format!("{path}.client_subnet"),
                    "`client_subnet` is not supported by rust-box yet".into(),
                ));
            }
            if options.remove_client_subnet {
                return Err(field(
                    format!("{path}.remove_client_subnet"),
                    "`remove_client_subnet` is not supported by rust-box yet".into(),
                ));
            }
            Ok(())
        };
        for (index, rule) in self.dns.rules.iter().enumerate() {
            let path = format!("dns.rules[{index}]");
            match rule.action() {
                Some(DnsRuleAction::Route { server, options, .. }) => {
                    if !server_known(server) {
                        return Err(field(path, format!("DNS server not found: {server}")));
                    }
                    check_dns_route_options(&path, options)?;
                }
                Some(DnsRuleAction::Evaluate { server, options, .. }) => {
                    if server.is_empty() {
                        return Err(field(path, "missing server field".into()));
                    }
                    if !server_known(server) {
                        return Err(field(path, format!("DNS server not found: {server}")));
                    }
                    let fakeip = self.dns.servers.iter().enumerate().any(|(server_index, candidate)| {
                        let tag = if candidate.tag().is_empty() {
                            server_index.to_string()
                        } else {
                            candidate.tag().to_string()
                        };
                        tag == *server && matches!(candidate, DnsServer::FakeIp(_))
                    });
                    if fakeip {
                        return Err(field(path, format!("evaluate action cannot use fakeip server: {server}")));
                    }
                    check_dns_route_options(&path, options)?;
                }
                _ => {}
            }
        }
        if let Some(experimental) = &self.experimental {
            experimental.validate_services()?;
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
    fn hosts_server_options() {
        let options = parse(
            r#"{"dns":{"servers":[{"type":"hosts","tag":"hosts","path":["/etc/hosts","$HOME/.hosts"],
                "predefined":{"localhost":"127.0.0.1","dual":["127.0.0.1","::1"]}}]}}"#,
        )
        .unwrap();
        assert_eq!(options.dns.servers[0].tag(), "hosts");
        let DnsServer::Hosts(hosts) = &options.dns.servers[0] else { panic!() };
        assert_eq!(hosts.path.0, vec!["/etc/hosts", "$HOME/.hosts"]);
        let predefined = hosts.predefined.as_ref().unwrap();
        assert_eq!(predefined["localhost"].0, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(predefined["dual"].0, vec!["127.0.0.1".parse::<IpAddr>().unwrap(), "::1".parse().unwrap()]);

        let error = parse(r#"{"dns":{"servers":[{"type":"hosts","unknown":true}]}}"#).unwrap_err().to_string();
        assert!(error.contains("dns.servers[0]") && error.contains("unknown field"), "{error}");
        let error = parse(r#"{"dns":{"servers":[{"type":"hosts","predefined":{"bad":"not-an-ip"}}]}}"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("dns.servers[0].predefined.bad"), "{error}");
    }

    #[test]
    fn fakeip_server_options() {
        let options = parse(
            r#"{"dns":{"servers":[{"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15",
                "inet6_range":"2001:2::/48"}]}}"#,
        )
        .unwrap();
        assert_eq!(options.dns.servers[0].tag(), "fake");
        let DnsServer::FakeIp(fakeip) = &options.dns.servers[0] else { panic!() };
        assert_eq!(fakeip.inet4_range.unwrap().prefix_len, 15);
        assert_eq!(fakeip.inet6_range.unwrap().prefix_len, 48);

        for (config, field) in [
            (r#"{"dns":{"servers":[{"type":"fakeip","inet4_range":"not-a-cidr"}]}}"#, "inet4_range"),
            (r#"{"dns":{"servers":[{"type":"fakeip","inet4_range":"198.18.0.0/33"}]}}"#, "inet4_range"),
            (r#"{"dns":{"servers":[{"type":"fakeip","unknown":true}]}}"#, "unknown"),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains("dns.servers[0]") && error.contains(field), "{error}");
        }
    }

    #[test]
    fn dns_evaluate_validates_server_and_unsupported_route_options() {
        parse(
            r#"{"dns":{"servers":[{"type":"local","tag":"local"}],
                "rules":[{"domain":"example.com","action":"evaluate","server":"local"} ]}}"#,
        )
        .unwrap();

        for (config, expected) in [
            (r#"{"dns":{"rules":[{"action":"evaluate"}]}}"#, "dns.rules[0]: missing server field"),
            (
                r#"{"dns":{"rules":[{"action":"evaluate","server":"missing"}]}}"#,
                "dns.rules[0]: DNS server not found: missing",
            ),
            (
                r#"{"dns":{"servers":[{"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"}],
                    "rules":[{"action":"evaluate","server":"fake"}]}}"#,
                "evaluate action cannot use fakeip server: fake",
            ),
            (
                r#"{"dns":{"servers":[{"type":"local","tag":"local"}],
                    "rules":[{"action":"evaluate","server":"local","client_subnet":"192.0.2.0/24"}]}}"#,
                "dns.rules[0].client_subnet: `client_subnet` is not supported by rust-box yet",
            ),
            (
                r#"{"dns":{"servers":[{"type":"local","tag":"local"}],
                    "rules":[{"action":"route","server":"local","remove_client_subnet":true}]}}"#,
                "dns.rules[0].remove_client_subnet: `remove_client_subnet` is not supported by rust-box yet",
            ),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(expected), "expected {expected:?}, got {error}");
        }
    }

    #[test]
    fn rejects_what_is_not_implemented() {
        let error = parse(r#"{"ntp": {}}"#).unwrap_err().to_string();
        assert!(error.contains("ntp"), "{error}");
        let error = parse(r#"{"network_namespaces": []}"#).unwrap_err().to_string();
        assert!(error.contains("network_namespaces"), "{error}");
        let error = parse(r#"{"inbounds":[{"type":"tproxy"}]}"#).unwrap_err().to_string();
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

    #[test]
    fn tuic_outbound_native_network_and_unsupported_options() {
        let base = r#"{"outbounds":[{"type":"tuic","server":"example.org","server_port":443,
            "uuid":"550e8400-e29b-41d4-a716-446655440000","tls":{"enabled":true},"network":"tcp"}]}"#;
        let options = parse(base).unwrap();
        assert!(matches!(options.outbounds[0], Outbound::Tuic(_)));
        let options =
            parse(r#"{"outbounds":[{"type":"tuic","server":"example.org","server_port":443,"tls":{"enabled":true}}]}"#)
                .unwrap();
        let Outbound::Tuic(tuic) = &options.outbounds[0] else { panic!() };
        assert_eq!(tuic.network.build(), vec!["tcp", "udp"]);
        let options = parse(
            r#"{"outbounds":[{"type":"tuic","server":"example.org","server_port":443,"tls":{"enabled":true},"network":"udp"}]}"#,
        )
        .unwrap();
        let Outbound::Tuic(tuic) = &options.outbounds[0] else { panic!() };
        assert_eq!(tuic.network.build(), vec!["udp"]);

        for (config, expected) in [
            (
                r#"{"outbounds":[{"type":"tuic","server":"example.org","server_port":443,"network":"tcp"}]}"#,
                "outbounds[0].tls: TLS is required",
            ),
            (
                r#"{"outbounds":[{"type":"tuic","server":"example.org","server_port":443,"tls":{"enabled":true},"network":"tcp","zero_rtt_handshake":true}]}"#,
                "outbounds[0].zero_rtt_handshake: `zero_rtt_handshake` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"tuic","server":"example.org","server_port":443,"tls":{"enabled":true},"network":"tcp","congestion_control":"bbr"}]}"#,
                "outbounds[0].congestion_control: `congestion_control` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"tuic","server":"example.org","server_port":443,"tls":{"enabled":true},"udp_relay_mode":"quic"}]}"#,
                "outbounds[0].udp_relay_mode: `udp_relay_mode` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"tuic","server":"example.org","server_port":443,"tls":{"enabled":true},"udp_over_stream":true}]}"#,
                "outbounds[0].udp_over_stream: `udp_over_stream` is not supported by rust-box yet",
            ),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(expected), "expected {expected:?}, got {error}");
        }
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
    fn tls_dns_server_options() {
        let options = parse(
            r#"{"dns":{"servers":[{"type":"local","tag":"local"},
                {"type":"tls","tag":"dot","server":"dns.example","domain_resolver":"local",
                 "tls":{"server_name":"dns.example","alpn":[]}}]}}"#,
        )
        .unwrap();
        let DnsServer::Tls(server) = &options.dns.servers[1] else { panic!() };
        assert_eq!(server.server, "dns.example");
        assert_eq!(server.server_port, 0);
        assert_eq!(server.dialer_options().domain_resolver.unwrap().server, "local");
        assert_eq!(server.tls.as_ref().unwrap().server_name, "dns.example");
        assert!(server.tls.as_ref().unwrap().alpn.is_empty());

        let error = parse(
            r#"{"dns":{"servers":[{"type":"local","tag":"local"},
                {"type":"tls","server":"dns.example","domain_resolver":"local",
                 "tls":{"utls":{"enabled":true}}}]}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("dns.servers[1].tls.utls: `utls` is not supported by rust-box yet"), "{error}");

        let error =
            parse(r#"{"dns":{"servers":[{"type":"tls","server":"1.1.1.1","unknown":true}]}}"#).unwrap_err().to_string();
        assert!(error.contains("unknown field `unknown`"), "{error}");
    }

    #[test]
    fn quic_dns_server_options() {
        let options = parse(
            r#"{"dns":{"servers":[{"type":"local","tag":"local"},
                {"type":"quic","tag":"doq","server":"dns.example","domain_resolver":"local",
                 "tls":{"server_name":"dns.example","alpn":[]}}]}}"#,
        )
        .unwrap();
        assert_eq!(options.dns.servers[1].tag(), "doq");
        let DnsServer::Quic(server) = &options.dns.servers[1] else { panic!() };
        assert_eq!(server.server, "dns.example");
        assert_eq!(server.server_port, 0);
        assert_eq!(server.dialer_options().domain_resolver.unwrap().server, "local");
        assert!(server.tls.as_ref().unwrap().alpn.is_empty());

        for (config, needle) in [
            (
                r#"{"dns":{"servers":[{"type":"local","tag":"local"},
                    {"type":"quic","server":"dns.example","domain_resolver":"local",
                     "tls":{"utls":{"enabled":true}}}]}}"#,
                "dns.servers[1].tls.utls: `utls` is not supported by rust-box yet",
            ),
            (r#"{"dns":{"servers":[{"type":"quic","server":"1.1.1.1","unknown":true}]}}"#, "unknown field `unknown`"),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(needle), "{config}: {error}");
        }
    }

    #[test]
    fn https_dns_server_options() {
        let options = parse(
            r#"{"dns":{"servers":[{"type":"local","tag":"local"},
                {"type":"https","tag":"doh","server":"dns.example","domain_resolver":"local",
                 "server_port":8443,"path":"/custom-query","method":"GET",
                 "headers":{"Host":"resolver.example","X-Mode":["one","two"]},
                 "tls":{"server_name":"tls.example","alpn":[]}}]}}"#,
        )
        .unwrap();
        assert_eq!(options.dns.servers[1].tag(), "doh");
        let DnsServer::Https(server) = &options.dns.servers[1] else { panic!() };
        assert_eq!((server.server.as_str(), server.server_port), ("dns.example", 8443));
        assert_eq!(server.path, "/custom-query");
        assert_eq!(server.method, "GET");
        assert_eq!(server.headers["Host"].0, vec!["resolver.example"]);
        assert_eq!(server.headers["X-Mode"].0, vec!["one", "two"]);
        assert_eq!(server.dialer_options().domain_resolver.unwrap().server, "local");
        assert_eq!(server.tls.as_ref().unwrap().server_name, "tls.example");
        assert!(server.tls.as_ref().unwrap().alpn.is_empty());

        for (config, needle) in [
            (
                r#"{"dns":{"servers":[{"type":"local","tag":"local"},
                    {"type":"https","server":"dns.example","domain_resolver":"local",
                     "tls":{"utls":{"enabled":true}}}]}}"#,
                "dns.servers[1].tls.utls: `utls` is not supported by rust-box yet",
            ),
            (
                r#"{"dns":{"servers":[{"type":"https","server":"dns.example","unknown":true}]}}"#,
                "unknown field `unknown`",
            ),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(needle), "{config}: {error}");
        }
    }

    #[test]
    fn http3_dns_server_options() {
        let options = parse(
            r#"{"dns":{"servers":[{"type":"local","tag":"local"},
                {"type":"h3","tag":"h3","server":"dns.example","domain_resolver":"local",
                 "path":"/custom","method":"GET","headers":{"Host":"resolver.example"},
                 "tls":{"server_name":"tls.example","alpn":["h2"]}}]}}"#,
        )
        .unwrap();
        assert_eq!(options.dns.servers[1].tag(), "h3");
        let DnsServer::Http3(server) = &options.dns.servers[1] else { panic!() };
        assert_eq!(
            (server.server.as_str(), server.path.as_str(), server.method.as_str()),
            ("dns.example", "/custom", "GET")
        );
        assert_eq!(server.headers["Host"].0, vec!["resolver.example"]);
        assert_eq!(server.dialer_options().domain_resolver.unwrap().server, "local");
        assert_eq!(server.tls.as_ref().unwrap().server_name, "tls.example");
        assert_eq!(server.tls.as_ref().unwrap().alpn.0, vec!["h2"]);

        for (config, needle) in [
            (
                r#"{"dns":{"servers":[{"type":"local","tag":"local"},
                    {"type":"h3","server":"dns.example","domain_resolver":"local",
                     "tls":{"utls":{"enabled":true}}}]}}"#,
                "dns.servers[1].tls.utls: `utls` is not supported by rust-box yet",
            ),
            (r#"{"dns":{"servers":[{"type":"h3","server":"1.1.1.1","unknown":true}]}}"#, "unknown field `unknown`"),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(needle), "{config}: {error}");
        }
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
        let listen = options.inbounds[0].listen_options();
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
    fn proxy_outbounds_and_tls() {
        let options = parse(
            r#"{"dns":{"servers":[{"type":"local","tag":"l"}]},
                "inbounds":[{"type":"http","tls":{"enabled":true,"certificate_path":"c","key_path":"k"}}],
                "outbounds":[
                  {"type":"socks","tag":"s","server":"proxy.test","server_port":1080,"version":"4a",
                   "username":"u","network":"tcp","udp_over_tcp":false,"domain_resolver":"l"},
                  {"type":"http","tag":"h","server":"1.2.3.4","server_port":8080,"path":"/p",
                   "headers":{"X-A":["1","2"],"host":"h.test"},"detour":"s",
                   "tls":{"enabled":true,"server_name":"h.test","alpn":"http/1.1","fragment":true}}]}"#,
        )
        .unwrap();
        let Outbound::Socks(socks) = &options.outbounds[0] else { panic!() };
        assert_eq!((socks.server.as_str(), socks.server_port, socks.version.as_str()), ("proxy.test", 1080, "4a"));
        assert_eq!(socks.network.build(), vec!["tcp"]);
        let Outbound::Http(http) = &options.outbounds[1] else { panic!() };
        assert_eq!(http.headers["X-A"].0, vec!["1", "2"]);
        assert_eq!(http.tls.as_ref().unwrap().server_name, "h.test");
        assert_eq!(http.dialer_options().detour, "s");
        let Inbound::Http(http) = &options.inbounds[0] else { panic!() };
        assert!(http.tls.is_some());

        for (config, needle) in [
            (r#"{"outbounds":[{"type":"socks","version":"6"}]}"#, "outbounds[0].version: unknown socks version: 6"),
            (
                r#"{"outbounds":[{"type":"socks","udp_over_tcp":true}]}"#,
                "outbounds[0].udp_over_tcp: `udp_over_tcp` is not supported by rust-box yet",
            ),
            (r#"{"outbounds":[{"type":"socks","network":"icmp"}]}"#, "unknown network: icmp"),
            (r#"{"outbounds":[{"type":"http","detour":"x"}]}"#, "outbounds[0].detour: outbound detour not found: x"),
            (
                r#"{"outbounds":[{"type":"http","tls":{"enabled":true,"utls":{"enabled":true}}}]}"#,
                "outbounds[0].tls.utls: `utls` is not supported by rust-box yet",
            ),
            (r#"{"inbounds":[{"type":"socks","tls":{"enabled":true}}]}"#, "inbounds[0]: unknown field `tls`"),
            (
                r#"{"inbounds":[{"type":"mixed","tls":{"enabled":true,"reality":{"enabled":true}}}]}"#,
                "inbounds[0].tls.reality",
            ),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(needle), "{config}: {error}");
        }
    }

    #[test]
    fn shadowsocks_options() {
        let options = parse(
            r#"{"inbounds":[
                  {"type":"shadowsocks","tag":"ss","listen_port":8388,"network":"tcp",
                   "method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA==",
                   "users":[{"name":"u","password":"AQEBAQEBAQEBAQEBAQEBAQ=="}],"multiplex":{"enabled":false}},
                  {"type":"shadowsocks","method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA==",
                   "destinations":[{"name":"d","server":"example.com","server_port":8388,
                                    "password":"AQEBAQEBAQEBAQEBAQEBAQ=="}],"managed":false}],
                "outbounds":[
                  {"type":"shadowsocks","tag":"o","server":"127.0.0.1","server_port":8388,
                   "method":"aes-128-gcm","password":"p","network":["tcp","udp"],
                   "udp_over_tcp":{"enabled":true,"version":2},"multiplex":{"enabled":true,"protocol":"smux"}},
                  {"type":"shadowsocks","method":"none","plugin":"","udp_over_tcp":false}]}"#,
        )
        .unwrap();
        let Inbound::Shadowsocks(inbound) = &options.inbounds[0] else { panic!() };
        assert_eq!(inbound.network.build(), vec!["tcp"]);
        assert_eq!(inbound.users[0], ShadowsocksUser { name: "u".into(), password: "AQEBAQEBAQEBAQEBAQEBAQ==".into() });
        assert_eq!(options.inbounds[0].listen_options().listen_port, 8388);
        let Inbound::Shadowsocks(relay) = &options.inbounds[1] else { panic!() };
        assert_eq!((relay.destinations[0].server.as_str(), relay.destinations[0].server_port), ("example.com", 8388));
        let Outbound::Shadowsocks(outbound) = &options.outbounds[0] else { panic!() };
        assert_eq!(outbound.udp_over_tcp, Some(UdpOverTcpOptions { enabled: true, version: 2 }));
        assert!(outbound.multiplex.as_ref().unwrap().enabled);

        for (config, needle) in [
            (
                r#"{"outbounds":[{"type":"shadowsocks","method":"none","plugin":"obfs-local"}]}"#,
                "outbounds[0].plugin: `plugin` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"shadowsocks","method":"none","multiplex":{"enabled":true,"brutal":{"enabled":true,"up_mbps":10,"down_mbps":10}}}]}"#,
                "outbounds[0].multiplex.brutal: `brutal` is not supported by rust-box yet",
            ),
            (
                r#"{"inbounds":[{"type":"shadowsocks","method":"none","multiplex":{"enabled":true,"brutal":{"enabled":true,"up_mbps":10,"down_mbps":10}}}]}"#,
                "inbounds[0].multiplex.brutal: `brutal` is not supported by rust-box yet",
            ),
            (r#"{"inbounds":[{"type":"shadowsocks","method":"none","tls":{}}]}"#, "unknown field `tls`"),
            (r#"{"inbounds":[{"type":"shadowsocks","users":[{"name":"a","uuid":"x"}]}]}"#, "unknown field `uuid`"),
            (r#"{"inbounds":[{"type":"shadowsocks","network":"icmp"}]}"#, "unknown network: icmp"),
            (r#"{"inbounds":[{"type":"shadowsocks","sniff":true}]}"#, "legacy inbound fields"),
            (
                r#"{"outbounds":[{"type":"shadowsocks","multiplex":{"protocol":"smux","foo":1}}]}"#,
                "unknown field `foo`",
            ),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(needle), "{config}: {error}");
        }
    }

    #[test]
    fn vmess_options() {
        let options = parse(
            r#"{"inbounds":[
                  {"type":"vmess","tag":"m","listen_port":10086,
                   "users":[{"name":"a","uuid":"bf000d23-0752-40b4-affe-68f7707a9661","alterId":4},{"uuid":"x"}],
                   "tls":{"enabled":false},"multiplex":{"enabled":false},
                   "transport":{"type":"ws","path":"/proxy"}}],
                "outbounds":[
                  {"type":"vmess","tag":"mo","server":"127.0.0.1","server_port":10086,
                   "uuid":"bf000d23-0752-40b4-affe-68f7707a9661","security":"chacha20-poly1305","alter_id":1,
                   "global_padding":true,"authenticated_length":true,"network":"udp","packet_encoding":"xudp",
                   "tls":{"enabled":true,"server_name":"example.com"},
                   "transport":{"type":"ws","path":"/proxy"}},
                  {"type":"vmess","tag":"mn"}]}"#,
        )
        .unwrap();
        let Inbound::Vmess(vmess) = &options.inbounds[0] else { panic!() };
        assert!(vmess.transport.is_some());
        assert_eq!(
            vmess.users[0],
            VmessUser { name: "a".into(), uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(), alter_id: 4 }
        );
        assert_eq!(vmess.users[1].alter_id, 0);
        let Outbound::Vmess(outbound) = &options.outbounds[0] else { panic!() };
        assert!(outbound.transport.is_some());
        assert_eq!(outbound.security, "chacha20-poly1305");
        assert_eq!(outbound.alter_id, 1);
        assert!(outbound.global_padding && outbound.authenticated_length);
        assert_eq!(outbound.packet_encoding, "xudp");
        assert_eq!(outbound.network.build(), vec!["udp"]);
        let Outbound::Vmess(outbound) = &options.outbounds[1] else { panic!() };
        assert_eq!((outbound.security.as_str(), outbound.packet_encoding.as_str()), ("", ""));

        for (config, needle) in [
            (
                r#"{"inbounds":[{"type":"vmess","multiplex":{"enabled":true,"brutal":{"enabled":true,"up_mbps":10,"down_mbps":10}}}]}"#,
                "inbounds[0].multiplex.brutal: `brutal` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"vmess","multiplex":{"enabled":true,"protocol":"smux","brutal":{"enabled":true,"up_mbps":10,"down_mbps":10}}}]}"#,
                "outbounds[0].multiplex.brutal: `brutal` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"vmess","transport":{"type":"ws","max_early_data":1}}]}"#,
                "outbounds[0].transport.max_early_data: `max_early_data` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"vmess","transport":{"type":"ws","early_data_header_name":"Sec-WebSocket-Protocol"}}]}"#,
                "outbounds[0].transport.early_data_header_name: `early_data_header_name` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"vmess","transport":{"type":"grpc","idle_timeout":"1s"}}]}"#,
                "outbounds[0].transport.idle_timeout: `idle_timeout` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"vmess","transport":{"type":"grpc","ping_timeout":"1s"}}]}"#,
                "outbounds[0].transport.ping_timeout: `ping_timeout` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"vmess","transport":{"type":"grpc","permit_without_stream":true}}]}"#,
                "outbounds[0].transport.permit_without_stream: `permit_without_stream` is not supported by rust-box yet",
            ),
            (
                r#"{"inbounds":[{"type":"vmess","transport":{"type":"grpc","idle_timeout":"1s"}}]}"#,
                "inbounds[0].transport.idle_timeout: `idle_timeout` is not supported by rust-box yet",
            ),
            (r#"{"outbounds":[{"type":"vmess","transport":{"type":"kcp"}}]}"#, "unknown transport type: kcp"),
            (r#"{"inbounds":[{"type":"vmess","users":[{"alter_id":1}]}]}"#, "unknown field `alter_id`"),
            (r#"{"inbounds":[{"type":"vmess","users":[{"flow":"x"}]}]}"#, "unknown field `flow`"),
            (r#"{"outbounds":[{"type":"vmess","alterId":1}]}"#, "unknown field `alterId`"),
            (r#"{"outbounds":[{"type":"vmess","flow":"x"}]}"#, "unknown field `flow`"),
            (r#"{"outbounds":[{"type":"vmess","alter_id":"1"}]}"#, "invalid type"),
            (
                r#"{"outbounds":[{"type":"vmess","tls":{"enabled":true,"reality":{"enabled":true}}}]}"#,
                "outbounds[0].tls.reality",
            ),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(needle), "{config}: {error}");
        }
    }

    #[test]
    fn tuic_and_hysteria2_options_are_typed_and_strict() {
        let options = parse(
            r#"{"inbounds":[
                  {"type":"tuic","tag":"tuic-in","listen":"127.0.0.1","listen_port":443,
                   "users":[{"name":"alice","uuid":"bf000d23-0752-40b4-affe-68f7707a9661","password":"p"}],
                   "congestion_control":"new_reno","tls":{"enabled":true}},
                  {"type":"hysteria2","tag":"hy2-in","listen_port":8443,
                   "users":[{"name":"bob","password":"q"}],"tls":{"enabled":true}}],
                "outbounds":[
                  {"type":"tuic","tag":"tuic-out","server":"example.com","server_port":443,
                   "uuid":"bf000d23-0752-40b4-affe-68f7707a9661","password":"p",
                   "udp_relay_mode":"native","tls":{"enabled":true}},
                  {"type":"hysteria2","tag":"hy2-out","server":"example.com","server_port":8443,
                   "password":"q","network":"tcp","disable_chrome_parrot":true,"tls":{"enabled":true}}]}"#,
        )
        .unwrap();
        assert_eq!(options.inbounds[0].kind(), "tuic");
        assert_eq!(options.inbounds[0].listen_options().listen_port, 443);
        let Inbound::Tuic(tuic) = &options.inbounds[0] else { panic!() };
        assert_eq!(tuic.users[0].name, "alice");
        assert_eq!(tuic.congestion_control, "new_reno");
        let Inbound::Hysteria2(hysteria2) = &options.inbounds[1] else { panic!() };
        assert_eq!(hysteria2.users[0].password, "q");
        let Outbound::Tuic(tuic) = &options.outbounds[0] else { panic!() };
        assert_eq!(tuic.udp_relay_mode, "native");
        assert_eq!(tuic.dialer_options().detour, "");
        let Outbound::Hysteria2(hysteria2) = &options.outbounds[1] else { panic!() };
        assert_eq!(hysteria2.up_mbps, 0);

        let unknown_top_level = parse(r#"{"inbounds":[{"type":"tuic","unknown":true}]}"#).unwrap_err().to_string();
        assert!(
            unknown_top_level.contains("inbounds[0]") && unknown_top_level.contains("unknown field"),
            "{unknown_top_level}"
        );
        let unknown_nested =
            parse(r#"{"outbounds":[{"type":"hysteria2","obfs":{"type":"salamander","unknown":true}}]}"#)
                .unwrap_err()
                .to_string();
        assert!(unknown_nested.contains("unknown field `unknown`"), "{unknown_nested}");
    }

    #[test]
    fn tuic_unimplemented_outbound_options_fail_with_config_paths() {
        for (options, expected) in [
            (
                r#""congestion_control":"new_reno""#,
                "outbounds[0].congestion_control: `congestion_control` is not supported by rust-box yet",
            ),
            (
                r#""udp_relay_mode":"quic""#,
                "outbounds[0].udp_relay_mode: `udp_relay_mode` is not supported by rust-box yet",
            ),
            (
                r#""zero_rtt_handshake":true"#,
                "outbounds[0].zero_rtt_handshake: `zero_rtt_handshake` is not supported by rust-box yet",
            ),
            (
                r#""udp_over_stream":true"#,
                "outbounds[0].udp_over_stream: `udp_over_stream` is not supported by rust-box yet",
            ),
            (r#""udp_relay_mode":"invalid""#, "outbounds[0].udp_relay_mode: unknown UDP relay mode: invalid"),
            (
                r#""udp_over_stream":true,"udp_relay_mode":"native""#,
                "outbounds[0].udp_over_stream: udp_over_stream is conflict with udp_relay_mode",
            ),
        ] {
            let config =
                format!(r#"{{"outbounds":[{{"type":"tuic","tls":{{"enabled":true,"insecure":true}},{options}}}]}}"#);
            let error = parse(&config).unwrap_err().to_string();
            assert!(error.contains(expected), "{config}: {error}");
        }
    }

    #[test]
    fn hysteria2_unimplemented_options_fail_with_their_config_paths() {
        for (config, expected) in [
            (
                r#"{"inbounds":[{"type":"hysteria2","masquerade":{"type":"string","content":"hello"}}]}"#,
                "inbounds[0].masquerade: `masquerade` is not supported by rust-box yet",
            ),
            (
                r#"{"inbounds":[{"type":"hysteria2","realm":{"server_url":"https://realm.test","realm_id":"x"}}]}"#,
                "inbounds[0].realm: `realm` is not supported by rust-box yet",
            ),
            (
                r#"{"inbounds":[{"type":"hysteria2","detour":"next"},{"type":"socks","tag":"next"}]}"#,
                "inbounds[0].detour: `detour` is not supported by rust-box yet",
            ),
            (
                r#"{"inbounds":[{"type":"hysteria2","obfs":{"type":"salamander","password":"secret"}}]}"#,
                "inbounds[0].obfs.type: `obfs.type` is not supported by rust-box yet",
            ),
            (
                r#"{"inbounds":[{"type":"hysteria2","obfs":{"type":"gecko","password":"secret"}}]}"#,
                "inbounds[0].obfs.type: `obfs.type` is not supported by rust-box yet",
            ),
            (
                r#"{"inbounds":[{"type":"hysteria2","bbr_profile":"aggressive"}]}"#,
                "inbounds[0].bbr_profile: `bbr_profile` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"hysteria2","network":"tcp","disable_chrome_parrot":true,"server_ports":["443-444"]}]}"#,
                "outbounds[0].server_ports: `server_ports` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"hysteria2","network":"tcp","disable_chrome_parrot":false}]}"#,
                "outbounds[0].disable_chrome_parrot: `disable_chrome_parrot` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"hysteria2","network":"tcp","disable_chrome_parrot":true,"hop_interval":"30s"}]}"#,
                "outbounds[0].hop_interval: `hop_interval` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"hysteria2","realm":{"server_url":"https://realm.test","realm_id":"x"}}]}"#,
                "outbounds[0].realm: `realm` is not supported by rust-box yet",
            ),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(expected), "{config}: {error}");
        }
    }

    #[test]
    fn hysteria2_inbound_accepts_bandwidth_options_for_negotiation() {
        let options =
            parse(r#"{"inbounds":[{"type":"hysteria2","up_mbps":10,"down_mbps":20,"ignore_client_bandwidth":true}]}"#)
                .unwrap();
        let Inbound::Hysteria2(hysteria2) = &options.inbounds[0] else { panic!() };
        assert_eq!(hysteria2.up_mbps, 10);
        assert_eq!(hysteria2.down_mbps, 20);
        assert!(hysteria2.ignore_client_bandwidth);
    }

    #[test]
    fn hysteria2_outbound_accepts_bandwidth_options_for_negotiation() {
        let options = parse(
            r#"{"outbounds":[{"type":"hysteria2","network":"tcp","disable_chrome_parrot":true,"up_mbps":10,"down_mbps":20}]}"#,
        )
        .unwrap();
        let Outbound::Hysteria2(hysteria2) = &options.outbounds[0] else { panic!() };
        assert_eq!(hysteria2.up_mbps, 10);
        assert_eq!(hysteria2.down_mbps, 20);
    }

    #[test]
    fn hysteria2_outbound_accepts_udp_network() {
        let options =
            parse(r#"{"outbounds":[{"type":"hysteria2","network":"udp","disable_chrome_parrot":true}]}"#).unwrap();
        let Outbound::Hysteria2(hysteria2) = &options.outbounds[0] else { panic!() };
        assert_eq!(hysteria2.network.build(), vec!["udp".to_string()]);
    }

    #[test]
    fn trojan_and_vless_options() {
        let options = parse(
            r#"{"inbounds":[
                  {"type":"trojan","tag":"t","listen_port":443,"users":[{"name":"a","password":"p"}],
                   "tls":{"enabled":true,"insecure":true},"fallback":{"server":"127.0.0.1","server_port":8080},
                   "fallback_for_alpn":{"h2":{"server":"127.0.0.1","server_port":8081}},
                   "multiplex":{"enabled":false}},
                  {"type":"vless","tag":"v","users":[{"name":"b","uuid":"bf000d23-0752-40b4-affe-68f7707a9661",
                   "flow":"xtls-rprx-vision"}],"tls":{"enabled":false}}],
                "outbounds":[
                  {"type":"trojan","tag":"to","server":"example.com","server_port":443,"password":"p",
                   "network":"tcp","tls":{"enabled":true,"server_name":"example.com"},"multiplex":{"enabled":false}},
                  {"type":"vless","tag":"vo","server":"127.0.0.1","server_port":443,
                   "uuid":"bf000d23-0752-40b4-affe-68f7707a9661","flow":"xtls-rprx-vision",
                   "packet_encoding":"packetaddr"},
                  {"type":"vless","tag":"vn","packet_encoding":""}]}"#,
        )
        .unwrap();
        let Inbound::Trojan(trojan) = &options.inbounds[0] else { panic!() };
        assert_eq!(trojan.users[0], TrojanUser { name: "a".into(), password: "p".into() });
        assert_eq!(trojan.fallback, Some(ServerOptions { server: "127.0.0.1".into(), server_port: 8080 }));
        assert_eq!(trojan.fallback_for_alpn["h2"].as_ref().unwrap().server_port, 8081);
        let Inbound::Vless(vless) = &options.inbounds[1] else { panic!() };
        assert_eq!(vless.users[0].flow, "xtls-rprx-vision");
        let Outbound::Trojan(outbound) = &options.outbounds[0] else { panic!() };
        assert_eq!(outbound.network.build(), vec!["tcp"]);
        let Outbound::Vless(outbound) = &options.outbounds[1] else { panic!() };
        assert_eq!(outbound.packet_encoding.as_deref(), Some("packetaddr"));
        let Outbound::Vless(outbound) = &options.outbounds[2] else { panic!() };
        assert_eq!(outbound.packet_encoding.as_deref(), Some(""));

        for (config, needle) in [
            (r#"{"inbounds":[{"type":"trojan","transport":{}}]}"#, "unknown transport type: "),
            (r#"{"outbounds":[{"type":"vless","transport":{"type":"kcp"}}]}"#, "unknown transport type: kcp"),
            (
                r#"{"inbounds":[{"type":"vless","multiplex":{"enabled":true,"brutal":{"enabled":true,"up_mbps":10,"down_mbps":10}}}]}"#,
                "inbounds[0].multiplex.brutal: `brutal` is not supported by rust-box yet",
            ),
            (
                r#"{"outbounds":[{"type":"trojan","multiplex":{"enabled":true,"protocol":"h2mux","brutal":{"enabled":true,"up_mbps":10,"down_mbps":10}}}]}"#,
                "outbounds[0].multiplex.brutal: `brutal` is not supported by rust-box yet",
            ),
            (
                r#"{"inbounds":[{"type":"trojan","fallback_for_alpn":{"h2":{"server":"a","server_port":1}}}]}"#,
                "inbounds[0]: fallback for ALPN is not supported without TLS",
            ),
            (
                r#"{"inbounds":[{"type":"trojan","tls":{"enabled":true},"fallback_for_alpn":{"h2":{"server_port":1}}}]}"#,
                "invalid fallback address for ALPN h2: :1",
            ),
            (r#"{"inbounds":[{"type":"trojan","users":[{"uuid":"x"}]}]}"#, "unknown field `uuid`"),
            (r#"{"inbounds":[{"type":"vless","users":[{"password":"x"}]}]}"#, "unknown field `password`"),
            (r#"{"inbounds":[{"type":"vless","network":"tcp"}]}"#, "unknown field `network`"),
            (r#"{"outbounds":[{"type":"vless","method":"x"}]}"#, "unknown field `method`"),
            (
                r#"{"outbounds":[{"type":"trojan","tls":{"enabled":true,"utls":{"enabled":true}}}]}"#,
                "outbounds[0].tls.utls",
            ),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(needle), "{config}: {error}");
        }
    }

    #[test]
    fn httpupgrade_transport_is_accepted_for_proxy_protocols() {
        let options = parse(
            r#"{"inbounds":[
                  {"type":"trojan","transport":{"type":"httpupgrade","host":"t.test"}},
                  {"type":"vless","transport":{"type":"httpupgrade","path":"/v"}},
                  {"type":"vmess","transport":{"type":"httpupgrade"}}],
                "outbounds":[
                  {"type":"trojan","transport":{"type":"httpupgrade"}},
                  {"type":"vless","transport":{"type":"httpupgrade"}},
                  {"type":"vmess","transport":{"type":"httpupgrade"}}]}"#,
        )
        .unwrap();
        assert_eq!(options.inbounds.len(), 3);
        assert_eq!(options.outbounds.len(), 3);
    }

    #[test]
    fn http_transport_is_accepted_and_rejects_unimplemented_timeouts() {
        let options = parse(
            r#"{"inbounds":[
                  {"type":"trojan","transport":{"type":"http","host":["a.test","b.test"],"path":"/edge","method":"POST","headers":{"X-Test":"inbound"}}},
                  {"type":"vless","transport":{"type":"http"}},
                  {"type":"vmess","transport":{"type":"http"}}],
                "outbounds":[
                  {"type":"trojan","transport":{"type":"http"}},
                  {"type":"vless","transport":{"type":"http"}},
                  {"type":"vmess","transport":{"type":"http"}}]}"#,
        )
        .unwrap();
        assert_eq!(options.inbounds.len(), 3);
        assert_eq!(options.outbounds.len(), 3);

        for (config, expected) in [
            (
                r#"{"outbounds":[{"type":"vless","transport":{"type":"http","idle_timeout":"1s"}}]}"#,
                "outbounds[0].transport.idle_timeout: `idle_timeout` is not supported by rust-box yet",
            ),
            (
                r#"{"inbounds":[{"type":"trojan","transport":{"type":"http","ping_timeout":"1s"}}]}"#,
                "inbounds[0].transport.ping_timeout: `ping_timeout` is not supported by rust-box yet",
            ),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(expected), "{config}: {error}");
        }
    }

    #[test]
    fn grpc_transport_is_supported_and_rejects_unsupported_keepalive() {
        assert!(parse(r#"{"outbounds":[{"type":"trojan","transport":{"type":"grpc","service_name":"edge"}}]}"#).is_ok());
        assert!(parse(r#"{"outbounds":[{"type":"vless","transport":{"type":"grpc"}}]}"#).is_ok());
        assert!(parse(r#"{"inbounds":[{"type":"vless","transport":{"type":"grpc"}}]}"#).is_ok());
        let error = parse(r#"{"outbounds":[{"type":"vless","transport":{"type":"grpc","idle_timeout":"1s"}}]}"#)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("outbounds[0].transport.idle_timeout: `idle_timeout` is not supported by rust-box yet"),
            "{error}"
        );
        let error = parse(r#"{"outbounds":[{"type":"vmess","transport":{"type":"grpc","ping_timeout":"1s"}}]}"#)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("outbounds[0].transport.ping_timeout: `ping_timeout` is not supported by rust-box yet"),
            "{error}"
        );
        let error = parse(r#"{"inbounds":[{"type":"trojan","transport":{"type":"grpc","idle_timeout":"1s"}}]}"#)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("inbounds[0].transport.idle_timeout: `idle_timeout` is not supported by rust-box yet"),
            "{error}"
        );
        let error = parse(r#"{"inbounds":[{"type":"vmess","transport":{"type":"grpc","ping_timeout":"1s"}}]}"#)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("inbounds[0].transport.ping_timeout: `ping_timeout` is not supported by rust-box yet"),
            "{error}"
        );
        assert!(parse(
            r#"{"inbounds":[{"type":"vless","users":[{"uuid":"bf000d23-0752-40b4-affe-68f7707a9661","flow":"xtls-rprx-vision"}],"transport":{"type":"grpc"}}]}"#
        )
        .is_ok());
        assert!(
            parse(r#"{"outbounds":[{"type":"vless","flow":"xtls-rprx-vision","transport":{"type":"grpc"}}]}"#).is_ok()
        );
    }
    #[test]
    fn v2ray_transport_options_are_typed_and_strict() {
        let websocket: V2RayTransportOptions = serde_json::from_str(
            r#"{"type":"ws","path":"/socket","headers":{"X-Test":["one","two"]},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}"#,
        )
        .unwrap();
        assert_eq!(websocket.r#type, "ws");
        let V2RayTransportConfig::WebSocket(websocket) = websocket.config else { panic!() };
        assert_eq!(websocket.path, "/socket");
        assert_eq!(websocket.headers["X-Test"].0, ["one", "two"]);
        assert_eq!(websocket.max_early_data, 2048);
        assert_eq!(websocket.early_data_header_name, "Sec-WebSocket-Protocol");

        let http: V2RayTransportOptions =
            serde_json::from_str(r#"{"type":"http","host":"one.test","path":"/proxy","idle_timeout":"15s"}"#).unwrap();
        let V2RayTransportConfig::Http(http) = http.config else { panic!() };
        assert_eq!(http.host.0, ["one.test"]);
        assert_eq!(http.path, "/proxy");
        assert_eq!(http.idle_timeout.0, std::time::Duration::from_secs(15));
        assert!(http.ping_timeout.0.is_zero());

        let grpc: V2RayTransportOptions = serde_json::from_str(
            r#"{"type":"grpc","service_name":"edge","idle_timeout":"5s","ping_timeout":"2s","permit_without_stream":true}"#,
        )
        .unwrap();
        let V2RayTransportConfig::Grpc(grpc) = grpc.config else { panic!() };
        assert_eq!(grpc.service_name, "edge");
        assert_eq!(grpc.idle_timeout.0, std::time::Duration::from_secs(5));
        assert_eq!(grpc.ping_timeout.0, std::time::Duration::from_secs(2));
        assert!(grpc.permit_without_stream);

        let httpupgrade: V2RayTransportOptions =
            serde_json::from_str(r#"{"type":"httpupgrade","host":"edge.test","path":"/upgrade"}"#).unwrap();
        let V2RayTransportConfig::HttpUpgrade(httpupgrade) = httpupgrade.config else { panic!() };
        assert_eq!((httpupgrade.host.as_str(), httpupgrade.path.as_str()), ("edge.test", "/upgrade"));
        assert!(httpupgrade.headers.is_empty());

        parse(r#"{"inbounds":[{"type":"vmess","transport":{"type":"grpc"}}]}"#).unwrap();

        let quic: V2RayTransportOptions = serde_json::from_str(r#"{"type":"quic","key":"legacy"}"#).unwrap();
        assert!(matches!(quic.config, V2RayTransportConfig::Quic(_)));

        for transport in ["ws", "http", "grpc", "httpupgrade"] {
            let config = format!(r#"{{"type":"{transport}","unknown_option":true}}"#);
            let error = serde_json::from_str::<V2RayTransportOptions>(&config).unwrap_err().to_string();
            assert!(error.contains("unknown field `unknown_option`"), "{config}: {error}");
        }
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
