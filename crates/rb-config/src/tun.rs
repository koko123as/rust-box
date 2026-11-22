//! The `tun` inbound (sing-box `option/tun.go`, `option/tun_platform.go`)
//! and the checks sing-box v1.14.4 makes when it builds one
//! (`protocol/tun/inbound.go` `NewInbound`).
//!
//! Fields rust-box does not implement yet are parsed (so an unknown field
//! still fails as in sing-box) and rejected by [`TunInbound::validate`] with
//! "`...` is not supported by rust-box yet" and the field path.

use std::net::IpAddr;

use serde::de::{self, Deserializer};
use serde::Deserialize;

use crate::dial::FwMark;
use crate::types::{DomainStrategy, Duration, IpPrefix, Listable, UdpTimeout};
use crate::ConfigError;

/// sing-box `option.UDPNATBehavior`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UdpNatBehavior {
    #[default]
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

impl<'de> Deserialize<'de> for UdpNatBehavior {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "" | "endpoint_independent" => Ok(UdpNatBehavior::EndpointIndependent),
            "address_dependent" => Ok(UdpNatBehavior::AddressDependent),
            "address_and_port_dependent" => Ok(UdpNatBehavior::AddressAndPortDependent),
            _ => Err(de::Error::custom(format!("unknown UDP NAT behavior: {value}"))),
        }
    }
}

/// sing-box `option.HTTPProxyOptions` (`platform.http_proxy`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunHttpProxyOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub server_port: u16,
    #[serde(default)]
    pub bypass_domain: Listable<String>,
    #[serde(default)]
    pub match_domain: Listable<String>,
}

/// sing-box `option.TunPlatformOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunPlatformOptions {
    #[serde(default)]
    pub http_proxy: Option<TunHttpProxyOptions>,
}

/// sing-box `option.TunInboundOptions`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunInbound {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub interface_name: String,
    #[serde(default)]
    pub netns: String,
    #[serde(default)]
    pub mtu: u32,
    #[serde(default)]
    pub address: Listable<IpPrefix>,
    /// `disabled`, `native` or `hijack` (the default with `auto_route`).
    #[serde(default)]
    pub dns_mode: String,
    #[serde(default)]
    pub dns_address: Listable<IpAddr>,
    #[serde(default)]
    pub auto_route: bool,
    #[serde(default)]
    pub iproute2_table_index: i64,
    #[serde(default)]
    pub iproute2_rule_index: i64,
    #[serde(default)]
    pub auto_redirect: bool,
    #[serde(default)]
    pub auto_redirect_input_mark: FwMark,
    #[serde(default)]
    pub auto_redirect_output_mark: FwMark,
    #[serde(default)]
    pub auto_redirect_reset_mark: FwMark,
    #[serde(default)]
    pub auto_redirect_nfqueue: u16,
    #[serde(default)]
    pub auto_redirect_iproute2_fallback_rule_index: i64,
    #[serde(default)]
    pub exclude_mptcp: bool,
    #[serde(default)]
    pub loopback_address: Listable<IpAddr>,
    #[serde(default)]
    pub strict_route: bool,
    #[serde(default)]
    pub route_address: Listable<IpPrefix>,
    #[serde(default)]
    pub route_address_set: Listable<String>,
    #[serde(default)]
    pub route_exclude_address: Listable<IpPrefix>,
    #[serde(default)]
    pub route_exclude_address_set: Listable<String>,
    #[serde(default)]
    pub include_interface: Listable<String>,
    #[serde(default)]
    pub exclude_interface: Listable<String>,
    #[serde(default)]
    pub include_uid: Listable<u32>,
    #[serde(default)]
    pub include_uid_range: Listable<String>,
    #[serde(default)]
    pub exclude_uid: Listable<u32>,
    #[serde(default)]
    pub exclude_uid_range: Listable<String>,
    #[serde(default)]
    pub include_android_user: Listable<i64>,
    #[serde(default)]
    pub include_package: Listable<String>,
    #[serde(default)]
    pub exclude_package: Listable<String>,
    #[serde(default)]
    pub include_mac_address: Listable<String>,
    #[serde(default)]
    pub exclude_mac_address: Listable<String>,
    #[serde(default)]
    pub udp_timeout: UdpTimeout,
    #[serde(default)]
    pub udp_mapping: UdpNatBehavior,
    #[serde(default)]
    pub udp_filtering: UdpNatBehavior,
    #[serde(default)]
    pub udp_nat_max: u32,
    /// `system`, `gvisor` or `mixed`; all run rust-box's own stack.
    #[serde(default)]
    pub stack: String,
    #[serde(default)]
    pub platform: Option<TunPlatformOptions>,

    // Legacy inbound fields (`option.InboundOptions`), removed in 1.13.0.
    #[serde(default)]
    pub sniff: bool,
    #[serde(default)]
    pub sniff_override_destination: bool,
    #[serde(default)]
    pub sniff_timeout: Duration,
    #[serde(default)]
    pub domain_strategy: DomainStrategy,
    #[serde(default)]
    pub udp_disable_domain_unmapping: bool,

    // Removed fields.
    #[serde(default)]
    pub gso: bool,
    #[serde(default)]
    pub inet4_address: Listable<IpPrefix>,
    #[serde(default)]
    pub inet6_address: Listable<IpPrefix>,
    #[serde(default)]
    pub inet4_route_address: Listable<IpPrefix>,
    #[serde(default)]
    pub inet6_route_address: Listable<IpPrefix>,
    #[serde(default)]
    pub inet4_route_exclude_address: Listable<IpPrefix>,
    #[serde(default)]
    pub inet6_route_exclude_address: Listable<IpPrefix>,
    /// Removed without a check in sing-box: accepted and ignored.
    #[serde(default)]
    pub endpoint_independent_nat: bool,
}

/// An inclusive range of user IDs (sing-box `ranges.Range[uint32]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UidRange {
    pub start: u32,
    pub end: u32,
}

/// sing-box `parseRange`: `start:end`, each parsed like Go
/// `strconv.ParseUint(text, 0, 32)`.
pub fn parse_uid_ranges(list: &[String]) -> Result<Vec<UidRange>, String> {
    let mut ranges = Vec::new();
    for range in list {
        let Some(index) = range.find(':') else {
            return Err(format!("missing ':' in range: {range}"));
        };
        if index == 0 {
            return Err(format!("missing range start: {range}"));
        } else if index == range.len() - 1 {
            return Err(format!("missing range end: {range}"));
        }
        let start = crate::dial::parse_uint_base0(&range[..index]).ok_or_else(|| {
            format!("parse range start: strconv.ParseUint: parsing {:?}: invalid syntax", &range[..index])
        })?;
        let end = crate::dial::parse_uint_base0(&range[index + 1..]).ok_or_else(|| {
            format!("parse range end: strconv.ParseUint: parsing {:?}: invalid syntax", &range[index + 1..])
        })?;
        ranges.push(UidRange { start, end });
    }
    Ok(ranges)
}

/// Go `net.ParseMAC` for the 6-byte forms (`aa:bb:..`, `aa-bb-..`,
/// `aabb.ccdd.eeff`); also accepts the 8 and 20 byte lengths Go does.
pub fn parse_mac(text: &str) -> Option<Vec<u8>> {
    let hex = |s: &str| -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
    };
    let valid_len = |n: usize| matches!(n, 6 | 8 | 20);
    let bytes = if text.len() >= 14 && text.as_bytes().get(4) == Some(&b'.') {
        let groups: Vec<&str> = text.split('.').collect();
        if groups.iter().any(|g| g.len() != 4) {
            return None;
        }
        hex(&groups.concat())?
    } else {
        let separator = if text.contains(':') { ':' } else { '-' };
        let groups: Vec<&str> = text.split(separator).collect();
        if groups.len() < 2 || groups.iter().any(|g| g.len() != 2) {
            return None;
        }
        hex(&groups.concat())?
    };
    valid_len(bytes.len()).then_some(bytes)
}

fn unsupported(path: &str, name: &str) -> ConfigError {
    ConfigError::Field { path: format!("{path}.{name}"), message: format!("`{name}` is not supported by rust-box yet") }
}

impl TunInbound {
    /// The error sing-box v1.14.4 reports for a removed field that is set
    /// (checked first in `NewInbound`).
    pub fn removed_field_error(&self) -> Option<&'static str> {
        if !self.inet4_address.is_empty()
            || !self.inet6_address.is_empty()
            || !self.inet4_route_address.is_empty()
            || !self.inet6_route_address.is_empty()
            || !self.inet4_route_exclude_address.is_empty()
            || !self.inet6_route_exclude_address.is_empty()
        {
            Some("legacy tun address fields are deprecated in sing-box 1.10.0 and removed in sing-box 1.12.0")
        } else if self.gso {
            Some("GSO option in tun is deprecated in sing-box 1.11.0 and removed in sing-box 1.12.0")
        } else if self.sniff
            || self.sniff_override_destination
            || !self.sniff_timeout.0.is_zero()
            || self.domain_strategy != DomainStrategy::AsIs
            || self.udp_disable_domain_unmapping
        {
            Some(crate::dial::LEGACY_INBOUND_FIELDS_ERROR)
        } else {
            None
        }
    }

    /// The include and exclude UID ranges (`include_uid` + `include_uid_range`).
    pub fn uid_ranges(&self) -> Result<(Vec<UidRange>, Vec<UidRange>), String> {
        let mut include: Vec<UidRange> =
            self.include_uid.iter().map(|&uid| UidRange { start: uid, end: uid }).collect();
        include
            .extend(parse_uid_ranges(&self.include_uid_range.0).map_err(|e| format!("parse include_uid_range: {e}"))?);
        let mut exclude: Vec<UidRange> =
            self.exclude_uid.iter().map(|&uid| UidRange { start: uid, end: uid }).collect();
        exclude
            .extend(parse_uid_ranges(&self.exclude_uid_range.0).map_err(|e| format!("parse exclude_uid_range: {e}"))?);
        Ok((include, exclude))
    }

    /// The checks of sing-box `NewInbound`, in its order, then the fields
    /// rust-box does not implement. `path` is `inbounds[N]`; `rule_set_known`
    /// tells whether a route rule-set tag exists.
    pub fn validate(&self, path: &str, rule_set_known: &dyn Fn(&str) -> bool) -> Result<(), ConfigError> {
        let field = |message: String| ConfigError::Field { path: path.to_string(), message };
        if let Some(message) = self.removed_field_error() {
            return Err(field(message.into()));
        }
        if !self.netns.is_empty() && !cfg!(target_os = "linux") && !cfg!(target_os = "android") {
            return Err(field("`netns` is only supported on Linux".into()));
        }
        self.uid_ranges().map_err(field)?;
        for (name, list) in
            [("include_mac_address", &self.include_mac_address), ("exclude_mac_address", &self.exclude_mac_address)]
        {
            for (index, mac) in list.iter().enumerate() {
                if parse_mac(mac).is_none() {
                    return Err(field(format!("parse {name}[{index}]: address {mac}: invalid MAC address")));
                }
            }
        }
        for (name, list) in [
            ("route_address_set", &self.route_address_set),
            ("route_exclude_address_set", &self.route_exclude_address_set),
        ] {
            for tag in list.iter() {
                if !rule_set_known(tag) {
                    return Err(field(format!("parse {name}: rule-set not found: {tag}")));
                }
            }
        }
        if self.auto_redirect && !self.auto_route {
            return Err(field("`auto_route` is required by `auto_redirect`".into()));
        }
        if !matches!(self.dns_mode.as_str(), "" | "disabled" | "native" | "hijack") {
            // sing-box accepts any string here and treats an unknown mode
            // like `native`; rust-box keeps the value but refuses to guess.
            return Err(unsupported(path, "dns_mode"));
        }
        // Not implemented yet.
        if !self.netns.is_empty() {
            return Err(unsupported(path, "netns"));
        }
        if self.auto_redirect {
            return Err(unsupported(path, "auto_redirect"));
        }
        let marks = [
            ("auto_redirect_input_mark", self.auto_redirect_input_mark.0 != 0),
            ("auto_redirect_output_mark", self.auto_redirect_output_mark.0 != 0),
            ("auto_redirect_reset_mark", self.auto_redirect_reset_mark.0 != 0),
            ("auto_redirect_nfqueue", self.auto_redirect_nfqueue != 0),
            ("auto_redirect_iproute2_fallback_rule_index", self.auto_redirect_iproute2_fallback_rule_index != 0),
            ("exclude_mptcp", self.exclude_mptcp),
            ("loopback_address", !self.loopback_address.is_empty()),
            ("include_mac_address", !self.include_mac_address.is_empty()),
            ("exclude_mac_address", !self.exclude_mac_address.is_empty()),
            ("route_address_set", !self.route_address_set.is_empty()),
            ("route_exclude_address_set", !self.route_exclude_address_set.is_empty()),
        ];
        for (name, set) in marks {
            if set {
                return Err(unsupported(path, name));
            }
        }
        // `platform.http_proxy` only takes effect through a platform
        // interface (the Android app); without one sing-box ignores it.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tun(json: &str) -> TunInbound {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn parses_fields() {
        let options = tun(r#"{"tag":"tun-in","interface_name":"tun0","mtu":9000,
            "address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":true,"strict_route":true,
            "route_address":"0.0.0.0/1","route_exclude_address":["192.168.0.0/16"],
            "include_uid":1000,"exclude_uid_range":["2000:3000"],"include_package":["a.b"],
            "udp_timeout":300,"udp_mapping":"address_dependent","stack":"gvisor",
            "platform":{"http_proxy":{"enabled":true,"server":"127.0.0.1","server_port":8080}}}"#);
        assert_eq!(options.address.0.len(), 2);
        assert_eq!(options.address.0[0].prefix_len, 30);
        assert_eq!(options.udp_mapping, UdpNatBehavior::AddressDependent);
        assert_eq!(options.udp_timeout.0 .0, std::time::Duration::from_secs(300));
        let (include, exclude) = options.uid_ranges().unwrap();
        assert_eq!(include, vec![UidRange { start: 1000, end: 1000 }]);
        assert_eq!(exclude, vec![UidRange { start: 2000, end: 3000 }]);
        options.validate("inbounds[0]", &|_| false).unwrap();
        assert!(serde_json::from_str::<TunInbound>(r#"{"listen_port":1}"#).is_err());
        let error = serde_json::from_str::<TunInbound>(r#"{"udp_mapping":"x"}"#).unwrap_err().to_string();
        assert!(error.contains("unknown UDP NAT behavior: x"), "{error}");
    }

    #[test]
    fn uid_ranges_like_go() {
        let range = |s: &str| parse_uid_ranges(&[s.to_string()]);
        assert_eq!(range("1").unwrap_err(), "missing ':' in range: 1");
        assert_eq!(range(":1").unwrap_err(), "missing range start: :1");
        assert_eq!(range("1:").unwrap_err(), "missing range end: 1:");
        assert_eq!(range("0x10:0o20").unwrap(), vec![UidRange { start: 16, end: 16 }]);
        assert!(range("a:1").unwrap_err().starts_with("parse range start"));
    }

    #[test]
    fn mac_addresses_like_go() {
        assert_eq!(parse_mac("00:11:22:aa:BB:cc"), Some(vec![0, 0x11, 0x22, 0xaa, 0xbb, 0xcc]));
        assert!(parse_mac("00-11-22-aa-bb-cc").is_some());
        assert!(parse_mac("0011.22aa.bbcc").is_some());
        assert!(parse_mac("zz").is_none());
        assert!(parse_mac("00:11:22").is_none());
    }

    #[test]
    fn errors_in_sing_box_order() {
        let cases = [
            (r#"{"inet4_address":"1.1.1.1/30","gso":true}"#, "inbounds[0]: legacy tun address fields"),
            (r#"{"gso":true}"#, "inbounds[0]: GSO option in tun is deprecated"),
            (r#"{"sniff":true}"#, "inbounds[0]: legacy inbound fields are deprecated"),
            (r#"{"include_uid_range":["1"]}"#, "inbounds[0]: parse include_uid_range: missing ':' in range: 1"),
            (
                r#"{"include_mac_address":["zz"]}"#,
                "inbounds[0]: parse include_mac_address[0]: address zz: invalid MAC address",
            ),
            (r#"{"route_address_set":["x"]}"#, "inbounds[0]: parse route_address_set: rule-set not found: x"),
            (r#"{"auto_redirect":true}"#, "inbounds[0]: `auto_route` is required by `auto_redirect`"),
            (
                r#"{"auto_redirect":true,"auto_route":true}"#,
                "inbounds[0].auto_redirect: `auto_redirect` is not supported by rust-box yet",
            ),
            (r#"{"netns":"x"}"#, "inbounds[0].netns: `netns` is not supported by rust-box yet"),
            (
                r#"{"exclude_mptcp":true}"#,
                "inbounds[0].exclude_mptcp: `exclude_mptcp` is not supported by rust-box yet",
            ),
            (
                r#"{"auto_redirect_output_mark":"0x2024"}"#,
                "inbounds[0].auto_redirect_output_mark: `auto_redirect_output_mark` is not supported by rust-box yet",
            ),
            (
                r#"{"include_mac_address":["00:11:22:33:44:55"]}"#,
                "inbounds[0].include_mac_address: `include_mac_address` is not supported by rust-box yet",
            ),
            (
                r#"{"route_address_set":["geoip"]}"#,
                "inbounds[0].route_address_set: `route_address_set` is not supported by rust-box yet",
            ),
            (
                r#"{"loopback_address":"10.7.0.1"}"#,
                "inbounds[0].loopback_address: `loopback_address` is not supported by rust-box yet",
            ),
            (r#"{"dns_mode":"foo"}"#, "inbounds[0].dns_mode: `dns_mode` is not supported by rust-box yet"),
        ];
        for (json, expected) in cases {
            let error = tun(json).validate("inbounds[0]", &|tag| tag == "geoip").unwrap_err().to_string();
            assert!(error.starts_with(expected), "{json}: expected {expected:?}, got {error}");
        }
        tun(r#"{"endpoint_independent_nat":true,"dns_mode":"hijack","stack":"system"}"#)
            .validate("inbounds[0]", &|_| false)
            .unwrap();
    }
}
