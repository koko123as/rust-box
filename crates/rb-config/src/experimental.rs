//! The `experimental` section and the group outbounds, mirroring sing-box
//! `option/experimental.go`, `option/debug.go` and `option/group.go`, and
//! the Clash mode list (`experimental/clashmode.CalculateModeList`).

use serde::Deserialize;
use serde_json::Value;

use crate::rule::{DnsRule, RouteRule, Rule};
use crate::types::{Duration, Listable};
use crate::ConfigError;

/// sing-box `ExperimentalOptions`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentalOptions {
    #[serde(default)]
    pub cache_file: Option<CacheFileOptions>,
    #[serde(default)]
    pub clash_api: Option<ClashApiOptions>,
    #[serde(default)]
    pub v2ray_api: Option<V2RayApiOptions>,
    #[serde(default)]
    pub debug: Option<DebugOptions>,
}

/// sing-box `CacheFileOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheFileOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub cache_id: String,
    #[serde(default)]
    pub store_fakeip: bool,
    /// Deprecated in sing-box 1.14.0 (reported, still effective).
    #[serde(default)]
    pub store_rdrc: bool,
    #[serde(default)]
    pub rdrc_timeout: Duration,
    #[serde(default)]
    pub store_dns: bool,
}

/// sing-box `ClashAPIOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClashApiOptions {
    #[serde(default)]
    pub external_controller: String,
    #[serde(default)]
    pub external_ui: String,
    #[serde(default)]
    pub external_ui_download_url: String,
    #[serde(default)]
    pub external_ui_download_detour: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub default_mode: String,
    #[serde(default)]
    pub access_control_allow_origin: Listable<String>,
    #[serde(default)]
    pub access_control_allow_private_network: bool,
    /// Removed (migrated to `experimental.cache_file`): rejected when set.
    #[serde(default)]
    pub cache_file: String,
    #[serde(default)]
    pub cache_id: String,
    #[serde(default)]
    pub store_mode: bool,
    #[serde(default)]
    pub store_selected: bool,
    #[serde(default)]
    pub store_fakeip: bool,
}

/// sing-box `V2RayAPIOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2RayApiOptions {
    #[serde(default)]
    pub listen: String,
    #[serde(default)]
    pub stats: Option<V2RayStatsServiceOptions>,
}

/// sing-box `V2RayStatsServiceOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2RayStatsServiceOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub inbounds: Vec<String>,
    #[serde(default)]
    pub outbounds: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
}

/// sing-box `DebugOptions`. The Go runtime settings have nothing to set in
/// rust-box and are accepted without effect.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugOptions {
    #[serde(default)]
    pub listen: String,
    #[serde(default)]
    pub gc_percent: Option<i64>,
    #[serde(default)]
    pub max_stack: Option<i64>,
    #[serde(default)]
    pub max_threads: Option<i64>,
    #[serde(default)]
    pub panic_on_fault: Option<bool>,
    #[serde(default)]
    pub trace_back: String,
    /// A byte size, as a number or a string such as `"100MB"`.
    #[serde(default)]
    pub memory_limit: Option<Value>,
    #[serde(default)]
    pub oom_killer: Option<bool>,
}

/// sing-box `SelectorOutboundOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorOutbound {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub outbounds: Vec<String>,
    #[serde(default)]
    pub default: String,
    #[serde(default)]
    pub interrupt_exist_connections: bool,
}

/// sing-box `URLTestOutboundOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlTestOutbound {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub outbounds: Vec<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub interval: Duration,
    #[serde(default)]
    pub tolerance: u16,
    #[serde(default)]
    pub idle_timeout: Duration,
    #[serde(default)]
    pub interrupt_exist_connections: bool,
}

/// The member check both groups make when they are created (`NewSelector`,
/// `NewURLTest`).
pub(crate) fn check_group_tags(path: &str, tags: &[String]) -> Result<(), ConfigError> {
    let field = |message: String| ConfigError::Field { path: path.into(), message };
    if tags.is_empty() {
        return Err(field("missing tags".into()));
    }
    for (index, tag) in tags.iter().enumerate() {
        if tags[..index].contains(tag) {
            return Err(field(format!("duplicate tag: {tag}")));
        }
    }
    Ok(())
}

impl ExperimentalOptions {
    /// The debug options, which `box.New` checks first.
    pub(crate) fn validate_debug(&self) -> Result<(), ConfigError> {
        let field = |path: &str, message: &str| ConfigError::Field { path: path.into(), message: message.into() };
        if let Some(debug) = &self.debug {
            if debug.oom_killer.is_some() {
                return Err(field(
                    "experimental.debug",
                    "legacy oom_killer in debug options is removed, use oom-killer service instead",
                ));
            }
            if !debug.listen.is_empty() {
                return Err(field("experimental.debug.listen", "`listen` is not supported by rust-box yet"));
            }
        }
        Ok(())
    }

    /// The Clash and V2Ray API checks, which `box.New` makes once the
    /// router is built.
    pub(crate) fn validate_services(&self) -> Result<(), ConfigError> {
        let field = |path: &str, message: &str| ConfigError::Field { path: path.into(), message: message.into() };
        if let Some(clash_api) = &self.clash_api {
            if clash_api.store_mode
                || clash_api.store_selected
                || clash_api.store_fakeip
                || !clash_api.cache_file.is_empty()
                || !clash_api.cache_id.is_empty()
            {
                return Err(field(
                    "experimental.clash_api",
                    "create clash-server: cache_file and related fields in Clash API is deprecated in sing-box \
                     1.8.0, use experimental.cache_file instead.",
                ));
            }
        }
        if let Some(v2ray_api) = &self.v2ray_api {
            // Release builds of sing-box are built without `with_v2ray_api`,
            // so a V2Ray API with a listen address fails the same way.
            if !v2ray_api.listen.is_empty() {
                return Err(field("experimental.v2ray_api", "create v2ray-server: invalid argument"));
            }
        }
        Ok(())
    }
}

fn route_rule_modes(rules: &[RouteRule], modes: &mut Vec<String>) {
    for rule in rules {
        match rule {
            Rule::Default { matcher, .. } => {
                if !matcher.clash_mode.is_empty() {
                    modes.push(matcher.clash_mode.clone());
                }
            }
            Rule::Logical { rules, .. } => route_rule_modes(rules, modes),
        }
    }
}

fn dns_rule_modes(rules: &[DnsRule], modes: &mut Vec<String>) {
    for rule in rules {
        match rule {
            Rule::Default { matcher, .. } => {
                if !matcher.clash_mode.is_empty() {
                    modes.push(matcher.clash_mode.clone());
                }
            }
            Rule::Logical { rules, .. } => dns_rule_modes(rules, modes),
        }
    }
}

/// `clashmode.CalculateModeList`: the modes the route and DNS rules name,
/// the unknown ones sorted, then `Rule`, `Global` and `Direct` in that
/// order when named.
pub fn clash_mode_list(route: &[RouteRule], dns: &[DnsRule]) -> Vec<String> {
    let mut named = Vec::new();
    route_rule_modes(route, &mut named);
    dns_rule_modes(dns, &mut named);
    let mut unique: Vec<String> = Vec::new();
    for mode in named {
        if !mode.is_empty() && !unique.contains(&mode) {
            unique.push(mode);
        }
    }
    const PREDEFINED: [&str; 3] = ["Rule", "Global", "Direct"];
    let mut modes: Vec<String> = unique.iter().filter(|mode| !PREDEFINED.contains(&mode.as_str())).cloned().collect();
    modes.sort();
    for mode in PREDEFINED {
        if unique.iter().any(|named| named == mode) {
            modes.push(mode.to_string());
        }
    }
    modes
}

#[cfg(test)]
mod tests {
    use crate::parse;

    #[test]
    fn parses_experimental() {
        let options = parse(
            r#"{"experimental": {
                "cache_file": {"enabled": true, "path": "a.db", "cache_id": "x", "store_fakeip": true,
                               "store_rdrc": true, "rdrc_timeout": "1h", "store_dns": true},
                "clash_api": {"external_controller": "127.0.0.1:9090", "secret": "s", "default_mode": "Global",
                              "access_control_allow_origin": "*", "access_control_allow_private_network": true},
                "v2ray_api": {"stats": {"enabled": true}},
                "debug": {"gc_percent": 50, "memory_limit": "100MB"}
            }}"#,
        )
        .unwrap();
        let experimental = options.experimental.unwrap();
        let cache_file = experimental.cache_file.unwrap();
        assert!(cache_file.enabled && cache_file.store_dns);
        assert_eq!(cache_file.rdrc_timeout.0.as_secs(), 3600);
        assert_eq!(experimental.clash_api.unwrap().default_mode, "Global");
    }

    #[test]
    fn rejects_what_sing_box_rejects() {
        for (config, expected) in [
            (r#"{"experimental":{"clash_api":{"store_selected":true}}}"#, "deprecated in sing-box 1.8.0"),
            (r#"{"experimental":{"clash_api":{"cache_file":"a.db"}}}"#, "use experimental.cache_file instead"),
            (r#"{"experimental":{"v2ray_api":{"listen":"127.0.0.1:1"}}}"#, "create v2ray-server: invalid argument"),
            (r#"{"experimental":{"debug":{"oom_killer":true}}}"#, "legacy oom_killer in debug options is removed"),
            (r#"{"experimental":{"debug":{"listen":":1"}}}"#, "`listen` is not supported by rust-box yet"),
            (r#"{"experimental":{"cache_file":{"unknown":1}}}"#, "unknown field"),
            (r#"{"outbounds":[{"type":"selector","tag":"s"}]}"#, "outbounds[0]: missing tags"),
            (r#"{"outbounds":[{"type":"urltest","tag":"u","outbounds":["a","a"]}]}"#, "outbounds[0]: duplicate tag: a"),
        ] {
            let error = parse(config).unwrap_err().to_string();
            assert!(error.contains(expected), "expected {expected:?}, got {error}");
        }
    }

    #[test]
    fn mode_list() {
        let options = parse(
            r#"{"route":{"rules":[{"clash_mode":"Direct","action":"route","outbound":"d"},
                {"type":"logical","mode":"or","rules":[{"clash_mode":"zeta"},{"clash_mode":"Global"}],
                 "action":"route","outbound":"d"}]},
                "dns":{"servers":[{"type":"local","tag":"l"}],
                       "rules":[{"clash_mode":"alpha","server":"l"},{"clash_mode":"Direct","server":"l"}]},
                "outbounds":[{"type":"direct","tag":"d"}]}"#,
        )
        .unwrap();
        assert_eq!(
            super::clash_mode_list(&options.route.rules, &options.dns.rules),
            ["alpha", "zeta", "Global", "Direct"]
        );
    }
}
