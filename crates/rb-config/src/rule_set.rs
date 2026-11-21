//! Rule-sets, mirroring sing-box `option/rule_set.go`: the `route.rule_set`
//! entries (inline, local and remote), the source format
//! (`PlainRuleSetCompat`, versions 1 to 5) and its headless rules, with
//! output formatted as sing-box's JSON encoder writes it.

use serde::Deserialize;
use serde_json::{Map, Value};

use rb_common::domain::{AdGuardMatcher, Matcher};
use rb_common::gojson::Value as Json;
use rb_common::ipset::{IpSet, Prefix};

use crate::dial::InterfaceType;
use crate::types::{Duration, Listable, QueryType};

/// `C.RuleSetVersion1` ... `C.RuleSetVersionCurrent`.
pub const RULE_SET_VERSION_1: u8 = 1;
pub const RULE_SET_VERSION_2: u8 = 2;
pub const RULE_SET_VERSION_3: u8 = 3;
pub const RULE_SET_VERSION_4: u8 = 4;
pub const RULE_SET_VERSION_5: u8 = 5;
pub const RULE_SET_VERSION_CURRENT: u8 = RULE_SET_VERSION_5;
/// `C.RuleSetTagPlaceholder`.
pub const TAG_PLACEHOLDER: &str = "{tag}";

pub const FORMAT_SOURCE: &str = "source";
pub const FORMAT_BINARY: &str = "binary";

impl InterfaceType {
    /// `C.InterfaceType` values.
    pub fn code(self) -> u8 {
        match self {
            InterfaceType::Wifi => 0,
            InterfaceType::Cellular => 1,
            InterfaceType::Ethernet => 2,
            InterfaceType::Other => 3,
        }
    }

    pub fn from_code(code: u8) -> Result<Self, u8> {
        Ok(match code {
            0 => InterfaceType::Wifi,
            1 => InterfaceType::Cellular,
            2 => InterfaceType::Ethernet,
            3 => InterfaceType::Other,
            other => return Err(other),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            InterfaceType::Wifi => "wifi",
            InterfaceType::Cellular => "cellular",
            InterfaceType::Ethernet => "ethernet",
            InterfaceType::Other => "other",
        }
    }
}

/// A `badoption.Prefixable`: a prefix, or an address meaning its host
/// prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefixable(pub Prefix);

impl<'de> Deserialize<'de> for Prefixable {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        match Prefix::parse(&text) {
            Ok(prefix) => Ok(Prefixable(prefix)),
            Err(prefix_error) => match rb_common::ipset::parse_addr(&text) {
                Ok(addr) => Ok(Prefixable(Prefix { addr, bits: if addr.is_ipv4() { 32 } else { 128 } })),
                Err(_) => Err(serde::de::Error::custom(prefix_error)),
            },
        }
    }
}

impl Prefixable {
    fn to_json(self) -> Json {
        let full = if self.0.addr.is_ipv4() { 32 } else { 128 };
        if self.0.bits == full {
            Json::string(self.0.addr.to_string())
        } else {
            Json::string(self.0.to_string())
        }
    }
}

/// `option.DefaultHeadlessRule`. The last fields are the binary forms a
/// rule read from an SRS file carries (`json:"-"` in sing-box).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultHeadlessRule {
    #[serde(default)]
    pub query_type: Listable<QueryType>,
    #[serde(default)]
    pub network: Listable<String>,
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
    pub ip_cidr: Listable<String>,
    #[serde(default)]
    pub source_port: Listable<u16>,
    #[serde(default)]
    pub source_port_range: Listable<String>,
    #[serde(default)]
    pub port: Listable<u16>,
    #[serde(default)]
    pub port_range: Listable<String>,
    #[serde(default)]
    pub process_name: Listable<String>,
    #[serde(default)]
    pub process_path: Listable<String>,
    #[serde(default)]
    pub process_path_regex: Listable<String>,
    #[serde(default)]
    pub package_name: Listable<String>,
    #[serde(default)]
    pub package_name_regex: Listable<String>,
    #[serde(default)]
    pub network_type: Listable<InterfaceType>,
    #[serde(default, deserialize_with = "null_false")]
    pub network_is_expensive: bool,
    #[serde(default, deserialize_with = "null_false")]
    pub network_is_constrained: bool,
    #[serde(default)]
    pub wifi_ssid: Listable<String>,
    #[serde(default)]
    pub wifi_bssid: Listable<String>,
    #[serde(default, deserialize_with = "interface_address_map")]
    pub network_interface_address: Option<Vec<(InterfaceType, Vec<Prefixable>)>>,
    #[serde(default)]
    pub default_interface_address: Listable<Prefixable>,
    #[serde(default, deserialize_with = "null_false")]
    pub invert: bool,

    #[serde(skip)]
    pub domain_matcher: Option<Matcher>,
    #[serde(skip)]
    pub source_ip_set: Option<IpSet>,
    #[serde(skip)]
    pub ip_set: Option<IpSet>,
    #[serde(skip)]
    pub adguard_domain: Vec<String>,
    #[serde(skip)]
    pub adguard_domain_matcher: Option<AdGuardMatcher>,
}

fn null_false<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    Ok(Option::<bool>::deserialize(deserializer)?.unwrap_or(false))
}

/// `*badjson.TypedMap[InterfaceType, badoption.Listable[*badoption.Prefixable]]`,
/// keeping the key order.
#[allow(clippy::type_complexity)]
fn interface_address_map<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<(InterfaceType, Vec<Prefixable>)>>, D::Error> {
    use serde::de::Error;
    let Some(value) = Option::<Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    let Value::Object(object) = value else {
        return Err(D::Error::custom("expected json object start"));
    };
    let mut entries = Vec::with_capacity(object.len());
    for (key, value) in object {
        let key: InterfaceType =
            serde_json::from_value(Value::String(key.clone())).map_err(|_| D::Error::custom(format!("unknown interface type: {key}")))?;
        let value: Listable<Prefixable> = serde_json::from_value(value).map_err(D::Error::custom)?;
        entries.push((key, value.0));
    }
    Ok(Some(entries))
}

impl DefaultHeadlessRule {
    /// `DefaultHeadlessRule.IsValid`: anything set besides `invert`.
    pub fn is_valid(&self) -> bool {
        *self != DefaultHeadlessRule { invert: self.invert, ..Default::default() }
    }

    fn to_json(&self) -> Json {
        let mut fields: Vec<(String, Json)> = Vec::new();
        let strings = |fields: &mut Vec<(String, Json)>, name: &str, items: &[String]| {
            if !items.is_empty() {
                fields.push((name.into(), Json::string_listable(items)));
            }
        };
        if !self.query_type.is_empty() {
            fields.push((
                "query_type".into(),
                Json::listable(self.query_type.iter().map(|query_type| query_type.to_json()).collect()),
            ));
        }
        strings(&mut fields, "network", &self.network.0);
        strings(&mut fields, "domain", &self.domain.0);
        strings(&mut fields, "domain_suffix", &self.domain_suffix.0);
        strings(&mut fields, "domain_keyword", &self.domain_keyword.0);
        strings(&mut fields, "domain_regex", &self.domain_regex.0);
        strings(&mut fields, "source_ip_cidr", &self.source_ip_cidr.0);
        strings(&mut fields, "ip_cidr", &self.ip_cidr.0);
        let ports = |items: &[u16]| Json::listable(items.iter().map(|port| Json::uint(u64::from(*port))).collect());
        if !self.source_port.is_empty() {
            fields.push(("source_port".into(), ports(&self.source_port.0)));
        }
        strings(&mut fields, "source_port_range", &self.source_port_range.0);
        if !self.port.is_empty() {
            fields.push(("port".into(), ports(&self.port.0)));
        }
        strings(&mut fields, "port_range", &self.port_range.0);
        strings(&mut fields, "process_name", &self.process_name.0);
        strings(&mut fields, "process_path", &self.process_path.0);
        strings(&mut fields, "process_path_regex", &self.process_path_regex.0);
        strings(&mut fields, "package_name", &self.package_name.0);
        strings(&mut fields, "package_name_regex", &self.package_name_regex.0);
        if !self.network_type.is_empty() {
            fields.push((
                "network_type".into(),
                Json::listable(self.network_type.iter().map(|kind| Json::string(kind.name())).collect()),
            ));
        }
        if self.network_is_expensive {
            fields.push(("network_is_expensive".into(), Json::Bool(true)));
        }
        if self.network_is_constrained {
            fields.push(("network_is_constrained".into(), Json::Bool(true)));
        }
        strings(&mut fields, "wifi_ssid", &self.wifi_ssid.0);
        strings(&mut fields, "wifi_bssid", &self.wifi_bssid.0);
        if let Some(entries) = &self.network_interface_address {
            fields.push((
                "network_interface_address".into(),
                Json::Object(
                    entries
                        .iter()
                        .map(|(kind, prefixes)| {
                            (
                                kind.name().to_string(),
                                Json::listable(prefixes.iter().map(|prefix| prefix.to_json()).collect()),
                            )
                        })
                        .collect(),
                ),
            ));
        }
        if !self.default_interface_address.is_empty() {
            fields.push((
                "default_interface_address".into(),
                Json::listable(self.default_interface_address.iter().map(|prefix| prefix.to_json()).collect()),
            ));
        }
        if self.invert {
            fields.push(("invert".into(), Json::Bool(true)));
        }
        Json::Object(fields)
    }
}

impl QueryType {
    /// `DNSQueryType.MarshalJSON`: the name when miekg/dns knows it.
    pub fn to_json(self) -> Json {
        match crate::query_types::name(self.0) {
            Some(name) => Json::string(name),
            None => Json::uint(u64::from(self.0)),
        }
    }
}

/// `option.LogicalHeadlessRule`; `mode` is kept as written and checked
/// when the rule is built.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LogicalHeadlessRule {
    pub mode: String,
    pub rules: Vec<HeadlessRule>,
    pub invert: bool,
}

impl LogicalHeadlessRule {
    pub fn is_valid(&self) -> bool {
        !self.rules.is_empty() && self.rules.iter().all(HeadlessRule::is_valid)
    }
}

/// `option.HeadlessRule`.
#[derive(Debug, Clone, PartialEq)]
pub enum HeadlessRule {
    Default(DefaultHeadlessRule),
    Logical(LogicalHeadlessRule),
}

impl HeadlessRule {
    pub fn is_valid(&self) -> bool {
        match self {
            HeadlessRule::Default(rule) => rule.is_valid(),
            HeadlessRule::Logical(rule) => rule.is_valid(),
        }
    }

    /// Parses a rule (`HeadlessRule.UnmarshalJSON`).
    pub fn from_value(value: Value) -> Result<Self, String> {
        let Value::Object(mut object) = value else {
            return Err(format!("json: cannot unmarshal {} into Go value of type option._HeadlessRule", kind_of(&value)));
        };
        let kind = take_string(&mut object, "type", "option._HeadlessRule.type")?;
        match kind.as_str() {
            "" | "default" => serde_json::from_value(Value::Object(object))
                .map(HeadlessRule::Default)
                .map_err(|error| error.to_string()),
            "logical" => {
                let mode = take_string(&mut object, "mode", "option.LogicalHeadlessRule.mode")?;
                let rules = match object.remove("rules") {
                    None | Some(Value::Null) => Vec::new(),
                    Some(Value::Array(items)) => parse_rules(items)?,
                    Some(other) => {
                        return Err(format!(
                            "json: cannot unmarshal {} into Go struct field LogicalHeadlessRule.rules of type []option.HeadlessRule",
                            kind_of(&other)
                        ))
                    }
                };
                let invert = match object.remove("invert") {
                    None | Some(Value::Null) => false,
                    Some(Value::Bool(value)) => value,
                    Some(other) => {
                        return Err(format!(
                            "json: cannot unmarshal {} into Go struct field LogicalHeadlessRule.invert of type bool",
                            kind_of(&other)
                        ))
                    }
                };
                if let Some(key) = object.keys().next() {
                    return Err(format!("json: unknown field {key:?}"));
                }
                Ok(HeadlessRule::Logical(LogicalHeadlessRule { mode, rules, invert }))
            }
            other => Err(format!("unknown rule type: {other}")),
        }
    }

    pub fn to_json(&self) -> Json {
        match self {
            HeadlessRule::Default(rule) => rule.to_json(),
            HeadlessRule::Logical(rule) => {
                let mut fields = vec![("type".to_string(), Json::string("logical")), ("mode".into(), Json::string(&rule.mode))];
                if !rule.rules.is_empty() {
                    fields.push(("rules".into(), Json::Array(rule.rules.iter().map(HeadlessRule::to_json).collect())));
                }
                if rule.invert {
                    fields.push(("invert".into(), Json::Bool(true)));
                }
                Json::Object(fields)
            }
        }
    }

    /// `rule.HasHeadlessRule`: whether a default rule in the tree satisfies
    /// `condition`.
    pub fn any_default(rules: &[HeadlessRule], condition: &dyn Fn(&DefaultHeadlessRule) -> bool) -> bool {
        rules.iter().any(|rule| match rule {
            HeadlessRule::Default(rule) => condition(rule),
            HeadlessRule::Logical(rule) => HeadlessRule::any_default(&rule.rules, condition),
        })
    }
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn take_string(object: &mut Map<String, Value>, key: &str, field: &str) -> Result<String, String> {
    match object.remove(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(text),
        Some(other) => {
            Err(format!("json: cannot unmarshal {} into Go struct field {field} of type string", kind_of(&other)))
        }
    }
}

/// A `[]option.HeadlessRule` list. sing-box's decoder leaves the list
/// empty when every item decodes to an empty default rule (`[{}]`,
/// `[{"domain":[]}]`, `[{"type":"default"}]`), while one real rule keeps
/// the empty ones beside it (which then fail with "missing conditions").
fn parse_rules(items: Vec<Value>) -> Result<Vec<HeadlessRule>, String> {
    let rules: Vec<HeadlessRule> = items.into_iter().map(HeadlessRule::from_value).collect::<Result<_, _>>()?;
    let empty = HeadlessRule::Default(DefaultHeadlessRule::default());
    if rules.iter().all(|rule| *rule == empty) {
        return Ok(Vec::new());
    }
    Ok(rules)
}

/// `option.PlainRuleSet`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PlainRuleSet {
    pub rules: Vec<HeadlessRule>,
}

impl PlainRuleSet {
    fn from_object(mut object: Map<String, Value>) -> Result<Self, String> {
        let rules = match object.remove("rules") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => parse_rules(items)?,
            Some(other) => {
                return Err(format!(
                    "json: cannot unmarshal {} into Go struct field PlainRuleSet.rules of type []option.HeadlessRule",
                    kind_of(&other)
                ))
            }
        };
        if let Some(key) = object.keys().next() {
            return Err(format!("json: unknown field {key:?}"));
        }
        Ok(PlainRuleSet { rules })
    }
}

/// `option.PlainRuleSetCompat`: a source rule-set file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PlainRuleSetCompat {
    pub version: u8,
    pub options: PlainRuleSet,
}

impl PlainRuleSetCompat {
    /// `json.UnmarshalExtended[option.PlainRuleSetCompat]`.
    pub fn parse(content: &[u8]) -> Result<Self, String> {
        let value: Value = crate::parse_json_extended(content)?;
        Self::from_value(value)
    }

    pub fn from_value(value: Value) -> Result<Self, String> {
        let Value::Object(mut object) = value else {
            return Err(format!(
                "json: cannot unmarshal {} into Go value of type option._PlainRuleSetCompat",
                kind_of(&value)
            ));
        };
        let version = match object.remove("version") {
            None | Some(Value::Null) => 0,
            Some(Value::Number(number)) => match number.as_u64() {
                Some(version) if version <= 255 => version as u8,
                _ => {
                    return Err(format!(
                        "json: cannot unmarshal number {number} into Go struct field _PlainRuleSetCompat.version of type uint8"
                    ))
                }
            },
            Some(other) => {
                return Err(format!(
                    "json: cannot unmarshal {} into Go struct field _PlainRuleSetCompat.version of type uint8",
                    kind_of(&other)
                ))
            }
        };
        match version {
            RULE_SET_VERSION_1..=RULE_SET_VERSION_5 => {}
            0 => return Err("missing rule-set version".into()),
            other => return Err(format!("unknown rule-set version: {other}")),
        }
        Ok(PlainRuleSetCompat { version, options: PlainRuleSet::from_object(object)? })
    }

    /// `PlainRuleSetCompat.Upgrade`.
    pub fn upgrade(&self) -> Result<PlainRuleSet, String> {
        match self.version {
            RULE_SET_VERSION_1..=RULE_SET_VERSION_5 => Ok(self.options.clone()),
            other => Err(format!("unknown rule-set version: {other}")),
        }
    }

    pub fn to_json(&self) -> Json {
        let mut fields = vec![("version".to_string(), Json::uint(u64::from(self.version)))];
        if !self.options.rules.is_empty() {
            fields.push(("rules".into(), Json::Array(self.options.rules.iter().map(HeadlessRule::to_json).collect())));
        }
        Json::Object(fields)
    }
}

/// `route.rule_set[]` (sing-box `option.RuleSet`).
#[derive(Debug, Clone, PartialEq)]
pub struct RuleSetOptions {
    pub tags: Vec<String>,
    /// `source` or `binary`; empty for inline rule-sets.
    pub format: String,
    pub kind: RuleSetKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleSetKind {
    Inline { rules: Vec<HeadlessRule> },
    Local { path: String },
    Remote(RemoteRuleSet),
}

/// `option.RemoteRuleSet`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteRuleSet {
    pub url: String,
    pub initial_path: String,
    pub update_interval: Duration,
    /// Deprecated in sing-box (use `http_client`), still honored.
    pub download_detour: String,
}

impl RuleSetOptions {
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            RuleSetKind::Inline { .. } => "inline",
            RuleSetKind::Local { .. } => "local",
            RuleSetKind::Remote(_) => "remote",
        }
    }
}

/// `ruleSetDefaultFormat`: from the extension of a path or URL path.
pub fn default_format(path: &str) -> &'static str {
    // url.Parse succeeds for nearly every path; use its path part.
    let path = url_path(path);
    let file = path.rsplit('/').next().unwrap_or("");
    match file.rfind('.') {
        Some(index) if &file[index..] == ".json" => FORMAT_SOURCE,
        Some(index) if &file[index..] == ".srs" => FORMAT_BINARY,
        _ => "",
    }
}

/// The path part of a URL as Go's `url.Parse` gives it: without the scheme
/// and authority, the query and the fragment.
fn url_path(text: &str) -> &str {
    let mut rest = text;
    if let Some(index) = rest.find('#') {
        rest = &rest[..index];
    }
    if let Some(index) = rest.find('?') {
        rest = &rest[..index];
    }
    // scheme: a letter followed by letters, digits, + - . up to ':'
    if let Some(colon) = rest.find(':') {
        let scheme = &rest[..colon];
        if !scheme.is_empty()
            && scheme.as_bytes()[0].is_ascii_alphabetic()
            && scheme.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        {
            rest = &rest[colon + 1..];
            if let Some(authority) = rest.strip_prefix("//") {
                rest = match authority.find('/') {
                    Some(index) => &authority[index..],
                    None => "",
                };
            }
        }
    }
    rest
}

impl<'de> Deserialize<'de> for RuleSetOptions {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        RuleSetOptions::from_value(value).map_err(serde::de::Error::custom)
    }
}

impl RuleSetOptions {
    /// `RuleSet.UnmarshalJSON`.
    pub fn from_value(value: Value) -> Result<Self, String> {
        let Value::Object(mut object) = value else {
            return Err(format!("json: cannot unmarshal {} into Go value of type option._RuleSet", kind_of(&value)));
        };
        let kind = take_string(&mut object, "type", "_RuleSet.type")?;
        let tags: Listable<String> = match object.remove("tag") {
            None | Some(Value::Null) => Listable::default(),
            Some(value) => serde_json::from_value(value).map_err(|error| error.to_string())?,
        };
        let mut format = take_string(&mut object, "format", "_RuleSet.format")?;
        if tags.is_empty() || tags.iter().any(String::is_empty) {
            return Err("missing tag".into());
        }
        let kind = match kind.as_str() {
            "" | "inline" => RuleSetKind::Inline { rules: PlainRuleSet::from_object(object)?.rules },
            "local" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Local {
                    #[serde(default)]
                    path: Option<String>,
                }
                let local: Local = serde_json::from_value(Value::Object(object)).map_err(|error| error.to_string())?;
                RuleSetKind::Local { path: local.path.unwrap_or_default() }
            }
            "remote" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Remote {
                    #[serde(default)]
                    url: Option<String>,
                    #[serde(default)]
                    initial_path: Option<String>,
                    #[serde(default)]
                    http_client: Option<Value>,
                    #[serde(default)]
                    update_interval: Option<Duration>,
                    #[serde(default)]
                    download_detour: Option<String>,
                }
                let remote: Remote = serde_json::from_value(Value::Object(object)).map_err(|error| error.to_string())?;
                match &remote.http_client {
                    None | Some(Value::Null) => {}
                    Some(Value::Object(object)) if object.is_empty() => {}
                    Some(Value::String(tag)) if tag.is_empty() => {}
                    Some(_) => return Err("`http_client` is not supported by rust-box yet".into()),
                }
                RuleSetKind::Remote(RemoteRuleSet {
                    url: remote.url.unwrap_or_default(),
                    initial_path: remote.initial_path.unwrap_or_default(),
                    update_interval: remote.update_interval.unwrap_or_default(),
                    download_detour: remote.download_detour.unwrap_or_default(),
                })
            }
            other => return Err(format!("unknown rule-set type: {other}")),
        };
        match &kind {
            RuleSetKind::Inline { .. } => format.clear(),
            RuleSetKind::Local { path } | RuleSetKind::Remote(RemoteRuleSet { url: path, .. }) => {
                if format.is_empty() {
                    format = default_format(path).to_string();
                }
                match format.as_str() {
                    "" => return Err("missing format".into()),
                    FORMAT_SOURCE | FORMAT_BINARY => {}
                    other => return Err(format!("unknown rule-set format: {other}")),
                }
            }
        }
        if tags.0.len() > 1 {
            match &kind {
                RuleSetKind::Inline { .. } => return Err("inline rule-set does not support multiple tags".into()),
                RuleSetKind::Local { path } => {
                    if !path.contains(TAG_PLACEHOLDER) {
                        return Err(format!("missing {TAG_PLACEHOLDER} placeholder in path"));
                    }
                }
                RuleSetKind::Remote(remote) => {
                    if !remote.url.contains(TAG_PLACEHOLDER) {
                        return Err(format!("missing {TAG_PLACEHOLDER} placeholder in url"));
                    }
                    if !remote.initial_path.is_empty() && !remote.initial_path.contains(TAG_PLACEHOLDER) {
                        return Err(format!("missing {TAG_PLACEHOLDER} placeholder in initial_path"));
                    }
                }
            }
        }
        Ok(RuleSetOptions { tags: tags.0, format, kind })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_set(json: &str) -> Result<RuleSetOptions, String> {
        RuleSetOptions::from_value(serde_json::from_str(json).unwrap())
    }

    #[test]
    fn rule_set_entries() {
        let inline = rule_set(r#"{"tag":"a","rules":[{"domain":"a.com"}]}"#).unwrap();
        assert_eq!(inline.kind_name(), "inline");
        assert_eq!(inline.format, "");
        let local = rule_set(r#"{"type":"local","tag":"b","path":"rules/b.srs"}"#).unwrap();
        assert_eq!(local.format, "binary");
        let remote =
            rule_set(r#"{"type":"remote","tag":"c","url":"https://x.test/c.json?x=1","update_interval":"1h"}"#).unwrap();
        assert_eq!(remote.format, "source");
        let RuleSetKind::Remote(remote) = remote.kind else { panic!() };
        assert_eq!(remote.update_interval.0, std::time::Duration::from_secs(3600));
        assert_eq!(rule_set(r#"{"type":"local","path":"a.srs"}"#).unwrap_err(), "missing tag");
        assert_eq!(rule_set(r#"{"type":"local","tag":"a","path":"a.txt"}"#).unwrap_err(), "missing format");
        assert_eq!(
            rule_set(r#"{"type":"local","tag":"a","path":"a.txt","format":"yaml"}"#).unwrap_err(),
            "unknown rule-set format: yaml"
        );
        assert_eq!(
            rule_set(r#"{"type":"local","tag":["a","b"],"path":"a.srs"}"#).unwrap_err(),
            "missing {tag} placeholder in path"
        );
        assert!(rule_set(r#"{"type":"local","tag":["a","b"],"path":"{tag}.srs"}"#).is_ok());
        assert_eq!(rule_set(r#"{"tag":["a","b"],"rules":[]}"#).unwrap_err(), "inline rule-set does not support multiple tags");
        assert!(rule_set(r#"{"type":"local","tag":"a","path":"a.srs","url":"x"}"#).is_err());
        assert_eq!(rule_set(r#"{"type":"web","tag":"a"}"#).unwrap_err(), "unknown rule-set type: web");
        assert_eq!(default_format("https://h/x.srs#frag"), "binary");
        assert_eq!(default_format("https://h/"), "");
    }

    #[test]
    fn source_format_round_trip() {
        let content = br#"{"version":3,"rules":[{"domain":["a.com"],"port":[80,443],"query_type":["A",64,4242],
            "network_type":"wifi"},{"type":"logical","mode":"or","rules":[{"ip_cidr":"10.0.0.0/8"}],"invert":true}]}"#;
        let rule_set = PlainRuleSetCompat::parse(content).unwrap();
        assert_eq!(
            rb_common::gojson::to_string(&rule_set.to_json()),
            r#"{"version":3,"rules":[{"query_type":["A","SVCB",4242],"domain":"a.com","port":[80,443],"network_type":"wifi"},{"type":"logical","mode":"or","rules":[{"ip_cidr":"10.0.0.0/8"}],"invert":true}]}"#
        );
        assert_eq!(PlainRuleSetCompat::parse(br#"{"rules":[]}"#).unwrap_err(), "missing rule-set version");
        assert_eq!(PlainRuleSetCompat::parse(br#"{"version":9}"#).unwrap_err(), "unknown rule-set version: 9");
        assert!(PlainRuleSetCompat::parse(br#"{"version":1,"rules":[{"outbound":"x"}]}"#).is_err());
        assert!(PlainRuleSetCompat::parse(br#"{"version":1,"extra":1}"#).is_err());
        let rule = HeadlessRule::from_value(serde_json::json!({"invert": true})).unwrap();
        // All-empty rule lists decode as no rules, as in sing-box.
        for source in [r#"{"version":3,"rules":[{}]}"#, r#"{"version":3,"rules":[{"domain":[]},{"type":"default"}]}"#] {
            assert!(PlainRuleSetCompat::parse(source.as_bytes()).unwrap().options.rules.is_empty(), "{source}");
        }
        let kept = PlainRuleSetCompat::parse(br#"{"version":3,"rules":[{},{"domain":"a"}]}"#).unwrap();
        assert_eq!(kept.options.rules.len(), 2);
        let logical = PlainRuleSetCompat::parse(br#"{"version":3,"rules":[{"type":"logical","mode":"and","rules":[{}]}]}"#).unwrap();
        assert!(matches!(&logical.options.rules[0], HeadlessRule::Logical(rule) if rule.rules.is_empty()));
        assert!(!rule.is_valid());
    }
}
