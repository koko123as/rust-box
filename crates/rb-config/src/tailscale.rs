//! Tailscale endpoint options from sing-box v1.14.4 (`option/tailscale.go`).
//!
//! The endpoint is parsed strictly even while its runtime is being ported, so
//! unsupported configuration never disappears silently.

use std::fmt;
use std::net::SocketAddr;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::types::{IpPrefix, Listable, UdpTimeout};
use crate::ConfigError;

with_dial_fields! {
    /// sing-box `option.TailscaleEndpointOptions` (v1.14.4).
    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TailscaleEndpointOptions {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub state_directory: String,
        #[serde(default)]
        pub auth_key: String,
        #[serde(default)]
        pub control_url: String,
        #[serde(default)]
        pub ephemeral: bool,
        #[serde(default)]
        pub hostname: String,
        #[serde(default)]
        pub accept_routes: bool,
        #[serde(default)]
        pub exit_node: String,
        #[serde(default)]
        pub exit_node_allow_lan_access: bool,
        #[serde(default)]
        pub advertise_routes: Vec<IpPrefix>,
        #[serde(default)]
        pub advertise_exit_node: bool,
        #[serde(default)]
        pub advertise_tags: Listable<String>,
        #[serde(default)]
        pub listen_port: u16,
        #[serde(default)]
        pub relay_server_port: Option<u16>,
        #[serde(default)]
        pub relay_server_static_endpoints: Vec<SocketAddr>,
        #[serde(default)]
        pub system_interface: bool,
        #[serde(default)]
        pub system_interface_name: String,
        #[serde(default)]
        pub system_interface_mtu: u32,
        #[serde(default)]
        pub udp_timeout: UdpTimeout,
        #[serde(default)]
        pub ssh_server: Option<TailscaleSshServerOptions>,
        #[serde(default)]
        pub taildrop_directory: String,
    }
}

impl TailscaleEndpointOptions {
    /// Reproduces the configuration-level incompatibilities checked by
    /// sing-box v1.14.4 before creating its Tailscale endpoint.
    pub fn validate(&self, path: &str) -> Result<(), ConfigError> {
        if self.advertise_routes.iter().any(|route| route.address.is_unspecified() && route.prefix_len == 0) {
            return Err(ConfigError::Field {
                path: format!("{path}.advertise_routes"),
                message: "`advertise_routes` cannot be default, use `advertise_exit_node` instead.".into(),
            });
        }
        if self.advertise_exit_node && !self.exit_node.is_empty() {
            return Err(ConfigError::Field {
                path: path.to_string(),
                message: "cannot advertise an exit node and use an exit node at the same time.".into(),
            });
        }
        Ok(())
    }
}

/// sing-box accepts `ssh_server` as either a boolean or a strict object.
#[derive(Debug, Clone)]
pub enum TailscaleSshServerOptions {
    Enabled(bool),
    Settings(TailscaleSshServerSettings),
}

impl<'de> Deserialize<'de> for TailscaleSshServerOptions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SshServerOptionsVisitor;

        impl<'de> Visitor<'de> for SshServerOptionsVisitor {
            type Value = TailscaleSshServerOptions;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a boolean or Tailscale SSH server options object")
            }

            fn visit_bool<E>(self, enabled: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TailscaleSshServerOptions::Enabled(enabled))
            }

            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let settings = TailscaleSshServerSettings::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(TailscaleSshServerOptions::Settings(settings))
            }
        }

        deserializer.deserialize_any(SshServerOptionsVisitor)
    }
}

/// Object form of sing-box `option.TailscaleSSHServerOptions`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailscaleSshServerSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub disable_pty: bool,
    #[serde(default)]
    pub disable_sftp: bool,
    #[serde(default)]
    pub disable_forwarding: bool,
}
