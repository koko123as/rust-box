//! QUIC protocol options shared by sing-box v1.14.4 TUIC and Hysteria2.
use std::fmt;

use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::{Duration, InboundTlsOptions, Listable, NetworkList, OutboundTlsOptions};

/// A `byteformats.MemoryBytes` value (decimal JSON integer or a binary memory unit string).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryBytes(pub u64);

impl MemoryBytes {
    pub fn value(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for MemoryBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Form {
            Signed(i64),
            Unsigned(u64),
            Text(String),
        }
        let value = match Form::deserialize(deserializer)? {
            Form::Signed(value) => value as u64,
            Form::Unsigned(value) => value,
            Form::Text(value) => {
                let unit_index = value.find(|character: char| !character.is_ascii_digit()).unwrap_or(0);
                if unit_index == 0 {
                    return Err(serde::de::Error::custom(format!("invalid format: {value}")));
                }
                let number = value[..unit_index]
                    .parse::<u64>()
                    .map_err(|error| serde::de::Error::custom(format!("parse {}: {error}", &value[..unit_index])))?;
                let unit = value[unit_index..].trim().to_ascii_lowercase();
                let multiplier = match unit.as_str() {
                    "b" => 1,
                    "k" | "kb" => 1 << 10,
                    "m" | "mb" => 1 << 20,
                    "g" | "gb" => 1 << 30,
                    "t" | "tb" => 1 << 40,
                    "p" | "pb" => 1 << 50,
                    "e" | "eb" => 1 << 60,
                    _ => return Err(serde::de::Error::custom(format!("unsupported unit: {}", &value[unit_index..]))),
                };
                number.checked_mul(multiplier).ok_or_else(|| serde::de::Error::custom("memory size overflow"))?
            }
        };
        Ok(Self(value))
    }
}

/// sing-box `HTTP2Options` embedded in QUIC options.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuicOptions {
    #[serde(default)]
    pub idle_timeout: Duration,
    #[serde(default)]
    pub keep_alive_period: Duration,
    #[serde(default)]
    pub stream_receive_window: Option<MemoryBytes>,
    #[serde(default)]
    pub connection_receive_window: Option<MemoryBytes>,
    #[serde(default)]
    pub max_concurrent_streams: i64,
    #[serde(default)]
    pub initial_packet_size: i64,
    #[serde(default)]
    pub disable_path_mtu_discovery: bool,
}

/// sing-box `TUICUser`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TuicUser {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub password: String,
}

with_listen_fields! {
    /// sing-box `TUICInboundOptions`.
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TuicInbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub users: Vec<TuicUser>,
        #[serde(default)]
        pub congestion_control: String,
        #[serde(default)]
        pub auth_timeout: Duration,
        #[serde(default)]
        pub zero_rtt_handshake: bool,
        #[serde(default)]
        pub heartbeat: Duration,
        #[serde(default)]
        pub tls: Option<InboundTlsOptions>,
        #[serde(default)]
        pub idle_timeout: Duration,
        #[serde(default)]
        pub keep_alive_period: Duration,
        #[serde(default)]
        pub stream_receive_window: Option<MemoryBytes>,
        #[serde(default)]
        pub connection_receive_window: Option<MemoryBytes>,
        #[serde(default)]
        pub max_concurrent_streams: i64,
        #[serde(default)]
        pub initial_packet_size: i64,
        #[serde(default)]
        pub disable_path_mtu_discovery: bool,
    }
}

with_dial_fields! {
    /// sing-box `TUICOutboundOptions`.
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TuicOutbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub server: String,
        #[serde(default)]
        pub server_port: u16,
        #[serde(default)]
        pub uuid: String,
        #[serde(default)]
        pub password: String,
        #[serde(default)]
        pub congestion_control: String,
        #[serde(default)]
        pub udp_relay_mode: String,
        #[serde(default)]
        pub udp_over_stream: bool,
        #[serde(default)]
        pub zero_rtt_handshake: bool,
        #[serde(default)]
        pub heartbeat: Duration,
        #[serde(default)]
        pub network: NetworkList,
        #[serde(default)]
        pub tls: Option<OutboundTlsOptions>,
        #[serde(default)]
        pub idle_timeout: Duration,
        #[serde(default)]
        pub keep_alive_period: Duration,
        #[serde(default)]
        pub stream_receive_window: Option<MemoryBytes>,
        #[serde(default)]
        pub connection_receive_window: Option<MemoryBytes>,
        #[serde(default)]
        pub max_concurrent_streams: i64,
        #[serde(default)]
        pub initial_packet_size: i64,
        #[serde(default)]
        pub disable_path_mtu_discovery: bool,
    }
}

/// sing-box Hysteria2 user entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2User {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub password: String,
}

/// Hysteria2 obfs; Gecko's size fields are only meaningful for `type=gecko`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Obfs {
    #[serde(default, rename = "type")]
    pub r#type: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub min_packet_size: i64,
    #[serde(default)]
    pub max_packet_size: i64,
}

with_listen_fields! {
    /// sing-box `Hysteria2InboundOptions`.
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Hysteria2Inbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub up_mbps: i64,
        #[serde(default)]
        pub down_mbps: i64,
        #[serde(default)]
        pub obfs: Option<Hysteria2Obfs>,
        #[serde(default)]
        pub users: Vec<Hysteria2User>,
        #[serde(default)]
        pub ignore_client_bandwidth: bool,
        #[serde(default)]
        pub tls: Option<InboundTlsOptions>,
        #[serde(default)]
        pub idle_timeout: Duration,
        #[serde(default)]
        pub keep_alive_period: Duration,
        #[serde(default)]
        pub stream_receive_window: Option<MemoryBytes>,
        #[serde(default)]
        pub connection_receive_window: Option<MemoryBytes>,
        #[serde(default)]
        pub max_concurrent_streams: i64,
        #[serde(default)]
        pub initial_packet_size: i64,
        #[serde(default)]
        pub disable_path_mtu_discovery: bool,
        #[serde(default)]
        pub masquerade: Option<Value>,
        #[serde(default)]
        pub bbr_profile: String,
        #[serde(default)]
        pub brutal_debug: bool,
        #[serde(default)]
        pub realm: Option<Value>,
    }
}

with_dial_fields! {
    /// sing-box `Hysteria2OutboundOptions`.
    #[derive(Debug, Clone, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Hysteria2Outbound {
        #[serde(default)]
        pub tag: String,
        #[serde(default)]
        pub server: String,
        #[serde(default)]
        pub server_port: u16,
        #[serde(default)]
        pub server_ports: Listable<String>,
        #[serde(default)]
        pub hop_interval: Duration,
        #[serde(default)]
        pub hop_interval_max: Duration,
        #[serde(default)]
        pub up_mbps: i64,
        #[serde(default)]
        pub down_mbps: i64,
        #[serde(default)]
        pub obfs: Option<Hysteria2Obfs>,
        #[serde(default)]
        pub password: String,
        #[serde(default)]
        pub network: NetworkList,
        #[serde(default)]
        pub tls: Option<OutboundTlsOptions>,
        #[serde(default)]
        pub idle_timeout: Duration,
        #[serde(default)]
        pub keep_alive_period: Duration,
        #[serde(default)]
        pub stream_receive_window: Option<MemoryBytes>,
        #[serde(default)]
        pub connection_receive_window: Option<MemoryBytes>,
        #[serde(default)]
        pub max_concurrent_streams: i64,
        #[serde(default)]
        pub initial_packet_size: i64,
        #[serde(default)]
        pub disable_path_mtu_discovery: bool,
        #[serde(default)]
        pub bbr_profile: String,
        #[serde(default)]
        pub brutal_debug: bool,
        #[serde(default)]
        pub disable_chrome_parrot: bool,
        #[serde(default)]
        pub realm: Option<Value>,
    }
}

impl fmt::Display for MemoryBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Hysteria2Inbound, Hysteria2Outbound, MemoryBytes, QuicOptions, TuicInbound, TuicOutbound};

    #[test]
    fn memory_bytes_accepts_v1_14_4_numeric_and_binary_unit_forms() {
        for (source, expected) in [("65536", 65536), ("\"4 MB\"", 4 * 1024 * 1024), ("\"2 GB\"", 2 << 30)] {
            assert_eq!(serde_json::from_str::<MemoryBytes>(source).unwrap().value(), expected);
        }
        assert!(serde_json::from_str::<MemoryBytes>("\"1.5GB\"").is_err());
        assert!(serde_json::from_str::<MemoryBytes>("\"2 GiB\"").is_err());
        assert!(serde_json::from_str::<MemoryBytes>("\"8MBps\"").is_err());
    }

    #[test]
    fn quic_and_protocol_configs_reject_unknown_fields() {
        assert!(serde_json::from_str::<QuicOptions>(r#"{"stream_receive_window":"4 MB","unknown":true}"#).is_err());
        assert!(serde_json::from_str::<TuicInbound>(r#"{"users":[],"unknown":true}"#).is_err());
        assert!(serde_json::from_str::<TuicOutbound>(r#"{"udp_relay_mode":"native","unknown":true}"#).is_err());
        assert!(serde_json::from_str::<Hysteria2Inbound>(r#"{"bbr_profile":"standard","unknown":true}"#).is_err());
        assert!(serde_json::from_str::<Hysteria2Outbound>(r#"{"disable_chrome_parrot":true,"unknown":true}"#).is_err());
    }
}
