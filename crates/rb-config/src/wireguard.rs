//! WireGuard endpoint options from sing-box v1.14.4 (`option/wireguard.go`).
//!
//! Keep this separate from ordinary outbounds: sing-box exposes WireGuard in
//! the top-level `endpoints` section while its runtime endpoint also implements
//! the outbound interface.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::de::{self, Deserializer};
use serde::Deserialize;

use crate::tun::UdpNatBehavior;
use crate::types::{IpPrefix, Listable, UdpTimeout};
use crate::ConfigError;

with_dial_fields! {
    /// sing-box `option.WireGuardEndpointOptions` (v1.14.4).
    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct WireGuardEndpointOptions {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub system: bool,
        #[serde(default)]
        pub name: String,
        #[serde(default)]
        pub mtu: u32,
        #[serde(default)]
        pub address: Listable<IpPrefix>,
        #[serde(default)]
        pub private_key: String,
        #[serde(default)]
        pub listen_port: u16,
        #[serde(default)]
        pub peers: Vec<WireGuardPeer>,
        #[serde(default)]
        pub udp_timeout: UdpTimeout,
        #[serde(default)]
        pub udp_mapping: UdpNatBehavior,
        #[serde(default)]
        pub udp_filtering: UdpNatBehavior,
        #[serde(default)]
        pub udp_nat_max: u32,
        #[serde(default)]
        pub workers: i32,
    }
}

impl WireGuardEndpointOptions {
    /// Checks fields whose behavior is intentionally unsupported in the
    /// user-space endpoint implementation, with the exact config path.
    pub fn validate(&self, path: &str) -> Result<(), ConfigError> {
        let field = |name: &str, message: &str| ConfigError::Field {
            path: format!("{path}.{name}"),
            message: message.to_string(),
        };
        if self.system {
            return Err(field("system", "system WireGuard mode is not supported by rust-box yet"));
        }
        if !self.name.is_empty() {
            return Err(field("name", "a named system interface is not supported by rust-box yet"));
        }
        if self.workers != 0 {
            return Err(field("workers", "explicit WireGuard workers are not supported by rust-box yet"));
        }
        if self.listen_port != 0 && !self.detour.is_empty() {
            return Err(ConfigError::Field {
                path: path.to_string(),
                message: "`listen_port` is conflict with `detour`".into(),
            });
        }
        for (index, peer) in self.peers.iter().enumerate() {
            let peer_path = format!("{path}.peers[{index}]");
            if peer.public_key.is_empty() {
                return Err(ConfigError::Field {
                    path: format!("{peer_path}.public_key"),
                    message: "missing peer public key".into(),
                });
            }
            if peer.allowed_ips.0.is_empty() {
                return Err(ConfigError::Field {
                    path: format!("{peer_path}.allowed_ips"),
                    message: "missing peer AllowedIPs".into(),
                });
            }
            if !peer.reserved.is_empty() && peer.reserved.len() != 3 {
                return Err(ConfigError::Field {
                    path: format!("{peer_path}.reserved"),
                    message: "reserved must contain exactly 3 bytes".into(),
                });
            }
        }
        Ok(())
    }
}

/// sing-box `option.WireGuardPeer` (v1.14.4).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardPeer {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub pre_shared_key: String,
    #[serde(default)]
    pub allowed_ips: Listable<IpPrefix>,
    #[serde(default)]
    pub persistent_keepalive_interval: u16,
    #[serde(default, deserialize_with = "deserialize_reserved")]
    pub reserved: Vec<u8>,
}

fn deserialize_reserved<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(Vec::new()),
        serde_json::Value::String(encoded) => STANDARD.decode(encoded).map_err(de::Error::custom),
        serde_json::Value::Array(values) => values
            .into_iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|number| u8::try_from(number).ok())
                    .ok_or_else(|| de::Error::custom("reserved byte must be an integer from 0 to 255"))
            })
            .collect(),
        _ => Err(de::Error::custom("reserved must be a base64 string or byte array")),
    }
}

/// WireGuard endpoint entries are separate config values, but are exposed as
/// route outbounds by sing-box v1.14.4.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Endpoint {
    #[serde(rename = "wireguard")]
    WireGuard(WireGuardEndpointOptions),
}

impl Endpoint {
    pub fn tag(&self) -> &str {
        match self {
            Endpoint::WireGuard(options) => &options.tag,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Endpoint::WireGuard(_) => "wireguard",
        }
    }

    pub fn dialer_options(&self) -> crate::DialerOptions {
        match self {
            Endpoint::WireGuard(options) => options.dialer_options(),
        }
    }

    pub fn validate(&self, path: &str) -> Result<(), ConfigError> {
        match self {
            Endpoint::WireGuard(options) => options.validate(path),
        }
    }
}
