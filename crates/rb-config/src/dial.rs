//! Dial and listen fields shared by many objects: sing-box
//! `option.DialerOptions` (`docs/configuration/shared/dial.md`) and
//! `option.ListenOptions` (`docs/configuration/shared/listen.md`).
//!
//! sing-box embeds these structs in every outbound, DNS server and inbound
//! that dials or listens. serde cannot flatten a struct into one that
//! rejects unknown fields, so the fields are spliced into each object by
//! the macros below; the object then hands them out as one
//! [`DialerOptions`] / [`ListenOptions`] value.

use std::fmt;
use std::net::IpAddr;

use serde::de::{self, Deserializer};
use serde::Deserialize;

use crate::types::{DomainResolveOptions, DomainStrategy, Duration, Listable, UdpTimeout};

/// A netfilter mark: an integer or a string such as `"0x1234"` (sing-box
/// `option.FwMark`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FwMark(pub u32);

impl<'de> Deserialize<'de> for FwMark {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = FwMark;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a number or a string mark such as \"0x1234\"")
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<FwMark, E> {
                u32::try_from(value).map(FwMark).map_err(|_| E::custom("invalid number or string mark"))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<FwMark, E> {
                u32::try_from(value).map(FwMark).map_err(|_| E::custom("invalid number or string mark"))
            }
            // strconv.ParseUint(value, 0, 32): decimal, 0x hex, 0o / leading 0 octal, 0b binary.
            fn visit_str<E: de::Error>(self, value: &str) -> Result<FwMark, E> {
                parse_uint_base0(value).map(FwMark).ok_or_else(|| E::custom(format!("invalid mark {value:?}")))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// Go `strconv.ParseUint(text, 0, 32)`.
pub(crate) fn parse_uint_base0(text: &str) -> Option<u32> {
    let text = text.replace('_', "");
    let lower = text.to_ascii_lowercase();
    let (digits, radix) = if let Some(rest) = lower.strip_prefix("0x") {
        (rest.to_string(), 16)
    } else if let Some(rest) = lower.strip_prefix("0b") {
        (rest.to_string(), 2)
    } else if let Some(rest) = lower.strip_prefix("0o") {
        (rest.to_string(), 8)
    } else if lower.len() > 1 && lower.starts_with('0') {
        (lower[1..].to_string(), 8)
    } else {
        (lower, 10)
    };
    if digits.is_empty() {
        return None;
    }
    u32::from_str_radix(&digits, radix).ok()
}

/// sing-box `C.NetworkStrategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkStrategy {
    Default,
    Hybrid,
    Fallback,
}

/// sing-box `C.InterfaceType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceType {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

/// sing-box `option.DialerOptions` (with `AbstractDialerOptions`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DialerOptions {
    pub detour: String,
    pub bind_interface: String,
    pub inet4_bind_address: Option<IpAddr>,
    pub inet6_bind_address: Option<IpAddr>,
    pub bind_address_no_port: bool,
    pub protect_path: String,
    pub routing_mark: FwMark,
    pub reuse_addr: bool,
    pub netns: String,
    pub connect_timeout: Duration,
    pub tcp_fast_open: bool,
    pub tcp_multi_path: bool,
    pub disable_tcp_keep_alive: bool,
    pub tcp_keep_alive: Duration,
    pub tcp_keep_alive_interval: Duration,
    pub udp_fragment: Option<bool>,
    pub domain_resolver: Option<DomainResolveOptions>,
    pub network_strategy: Option<NetworkStrategy>,
    pub network_type: Listable<InterfaceType>,
    /// `None` when absent or `null`; `Some` (possibly empty) when given, as
    /// sing-box tells a nil `Listable` from an empty one.
    pub fallback_network_type: Option<Listable<InterfaceType>>,
    pub fallback_delay: Duration,
    /// Deprecated in sing-box 1.12.0 (migrated to `domain_resolver`), still
    /// honored by v1.14.4.
    pub domain_strategy: DomainStrategy,
}

impl DialerOptions {
    /// Whether nothing is set (sing-box compares a direct outbound's dialer
    /// options against the empty value for `DirectDialer.IsEmpty`).
    pub fn is_empty(&self) -> bool {
        *self == DialerOptions::default()
    }

    /// sing-box `dialer.NewDefault`'s check of the platform network fields
    /// against the fields that bind the socket themselves. `network_strategy`,
    /// `network_type` and `fallback_network_type` are otherwise accepted and
    /// only take effect with a platform interface and
    /// `auto_detect_interface` (sing-box's graphical clients); rust-box has
    /// no platform interface, so, like sing-box's command line, it leaves
    /// them without effect.
    pub fn network_strategy_conflict(&self) -> Option<&'static str> {
        let disable_default_bind =
            !self.bind_interface.is_empty() || self.inet4_bind_address.is_some() || self.inet6_bind_address.is_some();
        // Go: `NetworkStrategy != nil || len(NetworkType) > 0 &&
        // FallbackNetworkType == nil && FallbackDelay == 0`.
        if (disable_default_bind || self.tcp_fast_open)
            && (self.network_strategy.is_some()
                || !self.network_type.is_empty()
                    && self.fallback_network_type.is_none()
                    && self.fallback_delay.0.is_zero())
        {
            Some(
                "`network_strategy` is conflict with `bind_interface`, `inet4_bind_address`, \
                 `inet6_bind_address` and `tcp_fast_open`",
            )
        } else {
            None
        }
    }
}

/// sing-box `option.ListenOptions`, with the legacy inbound fields it still
/// parses (and rejects when set).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenOptions {
    pub listen: Option<IpAddr>,
    pub listen_port: u16,
    pub bind_interface: String,
    pub routing_mark: FwMark,
    pub reuse_addr: bool,
    pub netns: String,
    pub disable_tcp_keep_alive: bool,
    pub tcp_keep_alive: Duration,
    pub tcp_keep_alive_interval: Duration,
    pub tcp_fast_open: bool,
    pub tcp_multi_path: bool,
    pub udp_fragment: Option<bool>,
    pub udp_timeout: UdpTimeout,
    pub detour: String,
}

/// Generates a struct with the dial fields spliced in, and its
/// `dialer_options()`.
macro_rules! with_dial_fields {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            $( $(#[$field_meta:meta])* pub $field:ident : $ty:ty, )*
        }
    ) => {
        $(#[$meta])*
        pub struct $name {
            $( $(#[$field_meta])* pub $field: $ty, )*
            #[serde(default)]
            pub detour: String,
            #[serde(default)]
            pub bind_interface: String,
            #[serde(default)]
            pub inet4_bind_address: Option<std::net::IpAddr>,
            #[serde(default)]
            pub inet6_bind_address: Option<std::net::IpAddr>,
            #[serde(default)]
            pub bind_address_no_port: bool,
            #[serde(default)]
            pub protect_path: String,
            #[serde(default)]
            pub routing_mark: $crate::dial::FwMark,
            #[serde(default)]
            pub reuse_addr: bool,
            #[serde(default)]
            pub netns: String,
            #[serde(default)]
            pub connect_timeout: $crate::types::Duration,
            #[serde(default)]
            pub tcp_fast_open: bool,
            #[serde(default)]
            pub tcp_multi_path: bool,
            #[serde(default)]
            pub disable_tcp_keep_alive: bool,
            #[serde(default)]
            pub tcp_keep_alive: $crate::types::Duration,
            #[serde(default)]
            pub tcp_keep_alive_interval: $crate::types::Duration,
            #[serde(default)]
            pub udp_fragment: Option<bool>,
            #[serde(default)]
            pub domain_resolver: Option<$crate::types::DomainResolveOptions>,
            #[serde(default)]
            pub network_strategy: Option<$crate::dial::NetworkStrategy>,
            #[serde(default)]
            pub network_type: $crate::types::Listable<$crate::dial::InterfaceType>,
            #[serde(default)]
            pub fallback_network_type: Option<$crate::types::Listable<$crate::dial::InterfaceType>>,
            #[serde(default)]
            pub fallback_delay: $crate::types::Duration,
            #[serde(default)]
            pub domain_strategy: $crate::types::DomainStrategy,
        }

        impl $name {
            pub fn dialer_options(&self) -> $crate::dial::DialerOptions {
                $crate::dial::DialerOptions {
                    detour: self.detour.clone(),
                    bind_interface: self.bind_interface.clone(),
                    inet4_bind_address: self.inet4_bind_address,
                    inet6_bind_address: self.inet6_bind_address,
                    bind_address_no_port: self.bind_address_no_port,
                    protect_path: self.protect_path.clone(),
                    routing_mark: self.routing_mark,
                    reuse_addr: self.reuse_addr,
                    netns: self.netns.clone(),
                    connect_timeout: self.connect_timeout,
                    tcp_fast_open: self.tcp_fast_open,
                    tcp_multi_path: self.tcp_multi_path,
                    disable_tcp_keep_alive: self.disable_tcp_keep_alive,
                    tcp_keep_alive: self.tcp_keep_alive,
                    tcp_keep_alive_interval: self.tcp_keep_alive_interval,
                    udp_fragment: self.udp_fragment,
                    domain_resolver: self.domain_resolver.clone(),
                    network_strategy: self.network_strategy,
                    network_type: self.network_type.clone(),
                    fallback_network_type: self.fallback_network_type.clone(),
                    fallback_delay: self.fallback_delay,
                    domain_strategy: self.domain_strategy,
                }
            }
        }
    };
}

/// Generates a struct with the listen fields (and the legacy inbound fields
/// sing-box still parses) spliced in, and its `listen_options()` and
/// `legacy_field()`.
macro_rules! with_listen_fields {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            $( $(#[$field_meta:meta])* pub $field:ident : $ty:ty, )*
        }
    ) => {
        $(#[$meta])*
        pub struct $name {
            $( $(#[$field_meta])* pub $field: $ty, )*
            #[serde(default)]
            pub listen: Option<std::net::IpAddr>,
            #[serde(default)]
            pub listen_port: u16,
            #[serde(default)]
            pub bind_interface: String,
            #[serde(default)]
            pub routing_mark: $crate::dial::FwMark,
            #[serde(default)]
            pub reuse_addr: bool,
            #[serde(default)]
            pub netns: String,
            #[serde(default)]
            pub disable_tcp_keep_alive: bool,
            #[serde(default)]
            pub tcp_keep_alive: $crate::types::Duration,
            #[serde(default)]
            pub tcp_keep_alive_interval: $crate::types::Duration,
            #[serde(default)]
            pub tcp_fast_open: bool,
            #[serde(default)]
            pub tcp_multi_path: bool,
            #[serde(default)]
            pub udp_fragment: Option<bool>,
            /// UDP NAT expiration (5m by default).
            #[serde(default)]
            pub udp_timeout: $crate::types::UdpTimeout,
            #[serde(default)]
            pub detour: String,
            /// Removed in sing-box 1.6.0: rejected when set.
            #[serde(default)]
            pub proxy_protocol: bool,
            #[serde(default)]
            pub proxy_protocol_accept_no_header: bool,
            /// Legacy inbound fields, removed in sing-box 1.13.0: rejected when set.
            #[serde(default)]
            pub sniff: bool,
            #[serde(default)]
            pub sniff_override_destination: bool,
            #[serde(default)]
            pub sniff_timeout: $crate::types::Duration,
            #[serde(default)]
            pub domain_strategy: $crate::types::DomainStrategy,
            #[serde(default)]
            pub udp_disable_domain_unmapping: bool,
        }

        impl $name {
            pub fn listen_options(&self) -> $crate::dial::ListenOptions {
                $crate::dial::ListenOptions {
                    listen: self.listen,
                    listen_port: self.listen_port,
                    bind_interface: self.bind_interface.clone(),
                    routing_mark: self.routing_mark,
                    reuse_addr: self.reuse_addr,
                    netns: self.netns.clone(),
                    disable_tcp_keep_alive: self.disable_tcp_keep_alive,
                    tcp_keep_alive: self.tcp_keep_alive,
                    tcp_keep_alive_interval: self.tcp_keep_alive_interval,
                    tcp_fast_open: self.tcp_fast_open,
                    tcp_multi_path: self.tcp_multi_path,
                    udp_fragment: self.udp_fragment,
                    udp_timeout: self.udp_timeout,
                    detour: self.detour.clone(),
                }
            }

            /// The error sing-box v1.14.4 reports for a removed listen
            /// field that is set.
            pub fn removed_field_error(&self) -> Option<&'static str> {
                if self.sniff
                    || self.sniff_override_destination
                    || !self.sniff_timeout.0.is_zero()
                    || self.domain_strategy != $crate::types::DomainStrategy::AsIs
                    || self.udp_disable_domain_unmapping
                {
                    Some($crate::dial::LEGACY_INBOUND_FIELDS_ERROR)
                } else if self.proxy_protocol || self.proxy_protocol_accept_no_header {
                    Some($crate::dial::PROXY_PROTOCOL_ERROR)
                } else {
                    None
                }
            }
        }
    };
}

/// sing-box `option/inbound.go`.
pub const LEGACY_INBOUND_FIELDS_ERROR: &str = "legacy inbound fields are deprecated in sing-box 1.11.0 and removed \
     in sing-box 1.13.0, checkout migration: https://sing-box.sagernet.org/migration/#migrate-legacy-inbound-fields-to-rule-actions";
/// sing-box `common/listener/listener_tcp.go`.
pub const PROXY_PROTOCOL_ERROR: &str = "Proxy Protocol is deprecated and removed in sing-box 1.6.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks() {
        assert_eq!(serde_json::from_str::<FwMark>("1234").unwrap(), FwMark(1234));
        assert_eq!(serde_json::from_str::<FwMark>("\"0x1234\"").unwrap(), FwMark(0x1234));
        assert_eq!(serde_json::from_str::<FwMark>("\"0b101\"").unwrap(), FwMark(5));
        assert_eq!(serde_json::from_str::<FwMark>("\"017\"").unwrap(), FwMark(15));
        assert_eq!(serde_json::from_str::<FwMark>("\"99\"").unwrap(), FwMark(99));
        assert!(serde_json::from_str::<FwMark>("\"0x1ffffffff\"").is_err());
        assert!(serde_json::from_str::<FwMark>("-1").is_err());
        assert!(serde_json::from_str::<FwMark>("\"mark\"").is_err());
    }

    #[test]
    fn strategies_and_types() {
        assert_eq!(serde_json::from_str::<NetworkStrategy>("\"hybrid\"").unwrap(), NetworkStrategy::Hybrid);
        assert!(serde_json::from_str::<NetworkStrategy>("\"fast\"").is_err());
        let types: Listable<InterfaceType> = serde_json::from_str("[\"wifi\",\"cellular\"]").unwrap();
        assert_eq!(types.0, vec![InterfaceType::Wifi, InterfaceType::Cellular]);
        let one: Listable<InterfaceType> = serde_json::from_str("\"ethernet\"").unwrap();
        assert_eq!(one.0, vec![InterfaceType::Ethernet]);
    }
}
