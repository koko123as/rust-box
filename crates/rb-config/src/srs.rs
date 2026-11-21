//! The binary rule-set format (SRS), mirroring sing-box `common/srs`:
//! the magic `SRS`, a version byte, then a zlib stream with the rules.

use std::io::{Read, Write};
use std::net::IpAddr;

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use rb_common::domain::{AdGuardMatcher, Matcher};
use rb_common::ipset::{IpSet, Prefix, Range};
use rb_common::varbin::{write_uvarint, ReadError, Reader};

use crate::dial::InterfaceType;
use crate::rule_set::{
    DefaultHeadlessRule, HeadlessRule, LogicalHeadlessRule, PlainRuleSet, PlainRuleSetCompat, Prefixable,
    RULE_SET_VERSION_1, RULE_SET_VERSION_2, RULE_SET_VERSION_3, RULE_SET_VERSION_4, RULE_SET_VERSION_5,
    RULE_SET_VERSION_CURRENT,
};
use crate::types::{Listable, QueryType};

pub const MAGIC: [u8; 3] = *b"SRS";

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD_DOMAIN: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;
const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
const ITEM_FINAL: u8 = 0xff;

const MAX_LOGICAL_RULE_DEPTH: usize = 100;

#[derive(Debug)]
pub struct SrsError(pub String);

impl std::fmt::Display for SrsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SrsError {}

impl From<ReadError> for SrsError {
    fn from(error: ReadError) -> Self {
        SrsError(error.to_string())
    }
}

/// The rules of an SRS file, uncompressed: everything after the version
/// byte, as the zlib stream holds it.
pub fn decompress(content: &[u8]) -> Result<(u8, Vec<u8>), SrsError> {
    if content.len() < 3 {
        return Err(SrsError("unexpected EOF".into()));
    }
    if content[..3] != MAGIC {
        return Err(SrsError("invalid sing-box rule-set file".into()));
    }
    let version = *content.get(3).ok_or_else(|| SrsError("unexpected EOF".into()))?;
    if version > RULE_SET_VERSION_CURRENT {
        return Err(SrsError(format!("unsupported version: {version}")));
    }
    let mut data = Vec::new();
    ZlibDecoder::new(&content[4..]).read_to_end(&mut data).map_err(|error| SrsError(format!("zlib: {error}")))?;
    Ok((version, data))
}

/// `srs.Read`. With `recover`, the binary items are also turned back into
/// their source fields (for `rule-set decompile`).
pub fn read(content: &[u8], recover: bool) -> Result<PlainRuleSetCompat, SrsError> {
    let (version, data) = decompress(content)?;
    let mut reader = Reader::new(&data);
    let length = reader.read_uvarint()?;
    let mut rules = Vec::new();
    let mut index = 0u64;
    while index < length {
        let rule =
            read_rule(&mut reader, recover, 0).map_err(|error| SrsError(format!("read rule[{index}]: {error}")))?;
        rules.push(rule);
        index += 1;
    }
    Ok(PlainRuleSetCompat { version, options: PlainRuleSet { rules } })
}

fn read_rule(reader: &mut Reader, recover: bool, depth: usize) -> Result<HeadlessRule, SrsError> {
    if depth > MAX_LOGICAL_RULE_DEPTH {
        return Err(SrsError("logical rule nested too deep".into()));
    }
    match reader.read_u8()? {
        0 => Ok(HeadlessRule::Default(read_default_rule(reader, recover)?)),
        1 => Ok(HeadlessRule::Logical(read_logical_rule(reader, recover, depth)?)),
        other => Err(SrsError(format!("unknown rule type: {other}"))),
    }
}

fn read_strings(reader: &mut Reader) -> Result<Listable<String>, SrsError> {
    let length = reader.read_uvarint()?;
    let mut result = Vec::new();
    let mut index = 0u64;
    while index < length {
        let value = reader.read_byte_slice()?;
        result.push(String::from_utf8_lossy(&value).into_owned());
        index += 1;
    }
    Ok(Listable(result))
}

fn read_address(reader: &mut Reader) -> Result<IpAddr, SrsError> {
    let length = reader.read_uvarint()?;
    if length != 4 && length != 16 {
        return Err(SrsError("invalid argument".into()));
    }
    let bytes = reader.read_bytes(length as usize)?;
    Ok(if length == 4 {
        IpAddr::from(<[u8; 4]>::try_from(bytes).unwrap())
    } else {
        IpAddr::from(<[u8; 16]>::try_from(bytes).unwrap())
    })
}

fn read_prefix(reader: &mut Reader) -> Result<Prefix, SrsError> {
    let addr = read_address(reader)?;
    let bits = reader.read_u8()?;
    Ok(Prefix { addr, bits })
}

fn read_prefixes(reader: &mut Reader) -> Result<Vec<Prefixable>, SrsError> {
    let count = reader.read_uvarint()?;
    let mut value = Vec::new();
    let mut index = 0u64;
    while index < count {
        value.push(Prefixable(read_prefix(reader)?));
        index += 1;
    }
    Ok(value)
}

/// `readIPSet`.
fn read_ip_set(reader: &mut Reader) -> Result<IpSet, SrsError> {
    if reader.read_u8()? != 1 {
        return Err(SrsError("invalid argument".into()));
    }
    let length = reader.read_u64()?;
    let mut ranges = Vec::new();
    let mut index = 0u64;
    while index < length {
        let from = read_address(reader)?;
        let to = read_address(reader)?;
        ranges.push(Range { from, to });
        index += 1;
    }
    Ok(IpSet::from_raw_ranges(ranges))
}

fn read_default_rule(reader: &mut Reader, recover: bool) -> Result<DefaultHeadlessRule, SrsError> {
    let mut rule = DefaultHeadlessRule::default();
    let mut last_item_type = 0u8;
    loop {
        let item_type = reader.read_u8()?;
        match item_type {
            ITEM_QUERY_TYPE => {
                rule.query_type = Listable(reader.read_u16_slice()?.into_iter().map(QueryType).collect());
            }
            ITEM_NETWORK => rule.network = read_strings(reader)?,
            ITEM_DOMAIN => {
                let matcher = Matcher::read(reader)?;
                if recover {
                    let (domains, suffixes) = matcher.dump();
                    rule.domain = Listable(domains);
                    rule.domain_suffix = Listable(suffixes);
                }
                rule.domain_matcher = Some(matcher);
            }
            ITEM_DOMAIN_KEYWORD => rule.domain_keyword = read_strings(reader)?,
            ITEM_DOMAIN_REGEX => rule.domain_regex = read_strings(reader)?,
            ITEM_SOURCE_IP_CIDR => {
                let set = read_ip_set(reader)?;
                if recover {
                    rule.source_ip_cidr = Listable(set.prefixes().iter().map(ToString::to_string).collect());
                }
                rule.source_ip_set = Some(set);
            }
            ITEM_IP_CIDR => {
                let set = read_ip_set(reader)?;
                if recover {
                    rule.ip_cidr = Listable(set.prefixes().iter().map(ToString::to_string).collect());
                }
                rule.ip_set = Some(set);
            }
            ITEM_SOURCE_PORT => rule.source_port = Listable(reader.read_u16_slice()?),
            ITEM_SOURCE_PORT_RANGE => rule.source_port_range = read_strings(reader)?,
            ITEM_PORT => rule.port = Listable(reader.read_u16_slice()?),
            ITEM_PORT_RANGE => rule.port_range = read_strings(reader)?,
            ITEM_PROCESS_NAME => rule.process_name = read_strings(reader)?,
            ITEM_PROCESS_PATH => rule.process_path = read_strings(reader)?,
            ITEM_PROCESS_PATH_REGEX => rule.process_path_regex = read_strings(reader)?,
            ITEM_PACKAGE_NAME => rule.package_name = read_strings(reader)?,
            ITEM_PACKAGE_NAME_REGEX => rule.package_name_regex = read_strings(reader)?,
            ITEM_WIFI_SSID => rule.wifi_ssid = read_strings(reader)?,
            ITEM_WIFI_BSSID => rule.wifi_bssid = read_strings(reader)?,
            ITEM_ADGUARD_DOMAIN => {
                let matcher = AdGuardMatcher::read(reader)?;
                if recover {
                    rule.adguard_domain = matcher.dump();
                }
                rule.adguard_domain_matcher = Some(matcher);
            }
            ITEM_NETWORK_TYPE => {
                let values = reader.read_byte_slice()?;
                let mut types = Vec::with_capacity(values.len());
                for value in values {
                    types.push(
                        InterfaceType::from_code(value)
                            .map_err(|code| SrsError(format!("unknown interface type: {code}")))?,
                    );
                }
                rule.network_type = Listable(types);
            }
            ITEM_NETWORK_IS_EXPENSIVE => rule.network_is_expensive = true,
            ITEM_NETWORK_IS_CONSTRAINED => rule.network_is_constrained = true,
            ITEM_NETWORK_INTERFACE_ADDRESS => {
                let size = reader.read_uvarint()?;
                let mut entries = Vec::new();
                let mut index = 0u64;
                while index < size {
                    let key = reader.read_u8()?;
                    let key = InterfaceType::from_code(key)
                        .map_err(|code| SrsError(format!("unknown interface type: {code}")))?;
                    let value = read_prefixes(reader)?;
                    // TypedMap.Put replaces an existing key in place.
                    match entries
                        .iter_mut()
                        .find(|(existing, _): &&mut (InterfaceType, Vec<Prefixable>)| *existing == key)
                    {
                        Some(entry) => entry.1 = value,
                        None => entries.push((key, value)),
                    }
                    index += 1;
                }
                rule.network_interface_address = Some(entries);
            }
            ITEM_DEFAULT_INTERFACE_ADDRESS => rule.default_interface_address = Listable(read_prefixes(reader)?),
            ITEM_FINAL => {
                rule.invert = reader.read_bool()?;
                return Ok(rule);
            }
            _ => {
                return Err(SrsError(format!("unknown rule item type: {item_type}, last type: {last_item_type}")));
            }
        }
        last_item_type = item_type;
    }
}

fn read_logical_rule(reader: &mut Reader, recover: bool, depth: usize) -> Result<LogicalHeadlessRule, SrsError> {
    let mode = match reader.read_u8()? {
        0 => "and",
        1 => "or",
        other => return Err(SrsError(format!("unknown logical mode: {other}"))),
    };
    let length = reader.read_uvarint()?;
    let mut rules = Vec::new();
    let mut index = 0u64;
    while index < length {
        let rule = read_rule(reader, recover, depth + 1)
            .map_err(|error| SrsError(format!("read logical rule [{index}]: {error}")))?;
        rules.push(rule);
        index += 1;
    }
    let invert = reader.read_bool()?;
    Ok(LogicalHeadlessRule { mode: mode.into(), rules, invert })
}

/// `srs.Write`: the rules, uncompressed (for comparing with other
/// writers), and [`write`] for the whole file.
pub fn encode_rules(rule_set: &PlainRuleSet, version: u8) -> Result<Vec<u8>, SrsError> {
    let mut buffer = Vec::new();
    write_uvarint(&mut buffer, rule_set.rules.len() as u64);
    for rule in &rule_set.rules {
        write_rule(&mut buffer, rule, version)?;
    }
    Ok(buffer)
}

/// `srs.Write`. The zlib stream uses the best compression like sing-box;
/// the compressed bytes can differ from Go's, the content does not.
pub fn write(rule_set: &PlainRuleSet, version: u8) -> Result<Vec<u8>, SrsError> {
    let rules = encode_rules(rule_set, version)?;
    let mut output = Vec::with_capacity(rules.len() / 2 + 16);
    output.extend_from_slice(&MAGIC);
    output.push(version);
    let mut encoder = ZlibEncoder::new(output, Compression::best());
    encoder.write_all(&rules).map_err(|error| SrsError(error.to_string()))?;
    encoder.finish().map_err(|error| SrsError(error.to_string()))
}

fn write_rule(buffer: &mut Vec<u8>, rule: &HeadlessRule, version: u8) -> Result<(), SrsError> {
    match rule {
        HeadlessRule::Default(rule) => write_default_rule(buffer, rule, version),
        HeadlessRule::Logical(rule) => write_logical_rule(buffer, rule, version),
    }
}

fn write_strings(buffer: &mut Vec<u8>, item_type: u8, values: &[String]) {
    buffer.push(item_type);
    write_uvarint(buffer, values.len() as u64);
    for value in values {
        write_uvarint(buffer, value.len() as u64);
        buffer.extend_from_slice(value.as_bytes());
    }
}

fn write_u16s(buffer: &mut Vec<u8>, item_type: u8, values: &[u16]) {
    buffer.push(item_type);
    write_uvarint(buffer, values.len() as u64);
    for value in values {
        buffer.extend_from_slice(&value.to_be_bytes());
    }
}

fn address_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn write_prefix(buffer: &mut Vec<u8>, prefix: &Prefix) {
    let bytes = address_bytes(prefix.addr);
    write_uvarint(buffer, bytes.len() as u64);
    buffer.extend_from_slice(&bytes);
    buffer.push(prefix.bits);
}

/// `writeIPSet`.
pub fn write_ip_set(buffer: &mut Vec<u8>, set: &IpSet) {
    buffer.push(1);
    buffer.extend_from_slice(&(set.ranges().len() as u64).to_be_bytes());
    for range in set.ranges() {
        for addr in [range.from, range.to] {
            let bytes = address_bytes(addr);
            write_uvarint(buffer, bytes.len() as u64);
            buffer.extend_from_slice(&bytes);
        }
    }
}

fn write_cidr(buffer: &mut Vec<u8>, item_type: u8, values: &[String], name: &str) -> Result<(), SrsError> {
    let set = IpSet::parse(values).map_err(|error| SrsError(format!("{name}: {error}")))?;
    buffer.push(item_type);
    write_ip_set(buffer, &set);
    Ok(())
}

fn write_default_rule(buffer: &mut Vec<u8>, rule: &DefaultHeadlessRule, version: u8) -> Result<(), SrsError> {
    buffer.push(0);
    if !rule.query_type.is_empty() {
        write_u16s(buffer, ITEM_QUERY_TYPE, &rule.query_type.iter().map(|query_type| query_type.0).collect::<Vec<_>>());
    }
    if !rule.network.is_empty() {
        write_strings(buffer, ITEM_NETWORK, &rule.network.0);
    }
    if !rule.domain.is_empty() || !rule.domain_suffix.is_empty() {
        buffer.push(ITEM_DOMAIN);
        Matcher::new(&rule.domain.0, &rule.domain_suffix.0, version == RULE_SET_VERSION_1).write(buffer);
    }
    if !rule.domain_keyword.is_empty() {
        write_strings(buffer, ITEM_DOMAIN_KEYWORD, &rule.domain_keyword.0);
    }
    if !rule.domain_regex.is_empty() {
        write_strings(buffer, ITEM_DOMAIN_REGEX, &rule.domain_regex.0);
    }
    if !rule.source_ip_cidr.is_empty() {
        write_cidr(buffer, ITEM_SOURCE_IP_CIDR, &rule.source_ip_cidr.0, "source_ip_cidr")?;
    }
    if !rule.ip_cidr.is_empty() {
        write_cidr(buffer, ITEM_IP_CIDR, &rule.ip_cidr.0, "ipcidr")?;
    }
    if !rule.source_port.is_empty() {
        write_u16s(buffer, ITEM_SOURCE_PORT, &rule.source_port.0);
    }
    if !rule.source_port_range.is_empty() {
        write_strings(buffer, ITEM_SOURCE_PORT_RANGE, &rule.source_port_range.0);
    }
    if !rule.port.is_empty() {
        write_u16s(buffer, ITEM_PORT, &rule.port.0);
    }
    if !rule.port_range.is_empty() {
        write_strings(buffer, ITEM_PORT_RANGE, &rule.port_range.0);
    }
    if !rule.process_name.is_empty() {
        write_strings(buffer, ITEM_PROCESS_NAME, &rule.process_name.0);
    }
    if !rule.process_path.is_empty() {
        write_strings(buffer, ITEM_PROCESS_PATH, &rule.process_path.0);
    }
    if !rule.process_path_regex.is_empty() {
        write_strings(buffer, ITEM_PROCESS_PATH_REGEX, &rule.process_path_regex.0);
    }
    if !rule.package_name.is_empty() {
        write_strings(buffer, ITEM_PACKAGE_NAME, &rule.package_name.0);
    }
    if !rule.package_name_regex.is_empty() {
        if version < RULE_SET_VERSION_5 {
            return Err(SrsError("`package_name_regex` rule item is only supported in version 5 or later".into()));
        }
        write_strings(buffer, ITEM_PACKAGE_NAME_REGEX, &rule.package_name_regex.0);
    }
    if !rule.network_type.is_empty() {
        if version < RULE_SET_VERSION_3 {
            return Err(SrsError("`network_type` rule item is only supported in version 3 or later".into()));
        }
        buffer.push(ITEM_NETWORK_TYPE);
        write_uvarint(buffer, rule.network_type.0.len() as u64);
        buffer.extend(rule.network_type.iter().map(|kind| kind.code()));
    }
    if rule.network_is_expensive {
        if version < RULE_SET_VERSION_3 {
            return Err(SrsError("`network_is_expensive` rule item is only supported in version 3 or later".into()));
        }
        buffer.push(ITEM_NETWORK_IS_EXPENSIVE);
    }
    if rule.network_is_constrained {
        if version < RULE_SET_VERSION_3 {
            return Err(SrsError("`network_is_constrained` rule item is only supported in version 3 or later".into()));
        }
        buffer.push(ITEM_NETWORK_IS_CONSTRAINED);
    }
    if let Some(entries) = rule.network_interface_address.as_ref().filter(|entries| !entries.is_empty()) {
        if version < RULE_SET_VERSION_4 {
            return Err(SrsError(
                "`network_interface_address` rule item is only supported in version 4 or later".into(),
            ));
        }
        buffer.push(ITEM_NETWORK_INTERFACE_ADDRESS);
        write_uvarint(buffer, entries.len() as u64);
        for (kind, prefixes) in entries {
            buffer.push(kind.code());
            write_uvarint(buffer, prefixes.len() as u64);
            for prefix in prefixes {
                write_prefix(buffer, &prefix.0);
            }
        }
    }
    if !rule.default_interface_address.is_empty() {
        if version < RULE_SET_VERSION_4 {
            return Err(SrsError(
                "`default_interface_address` rule item is only supported in version 4 or later".into(),
            ));
        }
        buffer.push(ITEM_DEFAULT_INTERFACE_ADDRESS);
        write_uvarint(buffer, rule.default_interface_address.0.len() as u64);
        for prefix in rule.default_interface_address.iter() {
            write_prefix(buffer, &prefix.0);
        }
    }
    if !rule.wifi_ssid.is_empty() {
        write_strings(buffer, ITEM_WIFI_SSID, &rule.wifi_ssid.0);
    }
    if !rule.wifi_bssid.is_empty() {
        write_strings(buffer, ITEM_WIFI_BSSID, &rule.wifi_bssid.0);
    }
    if !rule.adguard_domain.is_empty() {
        if version < RULE_SET_VERSION_2 {
            return Err(SrsError("AdGuard rule items is only supported in version 2 or later".into()));
        }
        buffer.push(ITEM_ADGUARD_DOMAIN);
        AdGuardMatcher::new(&rule.adguard_domain).write(buffer);
    }
    buffer.push(ITEM_FINAL);
    buffer.push(u8::from(rule.invert));
    Ok(())
}

fn write_logical_rule(buffer: &mut Vec<u8>, rule: &LogicalHeadlessRule, version: u8) -> Result<(), SrsError> {
    buffer.push(1);
    match rule.mode.as_str() {
        "and" => buffer.push(0),
        "or" => buffer.push(1),
        // sing-box panics here
        other => return Err(SrsError(format!("unknown logical mode: {other}"))),
    }
    write_uvarint(buffer, rule.rules.len() as u64);
    for rule in &rule.rules {
        write_rule(buffer, rule, version)?;
    }
    buffer.push(u8::from(rule.invert));
    Ok(())
}

/// The version `rule-set compile` writes: the source version, lowered
/// while the rules use nothing of the newer versions
/// (`downgradeRuleSetVersion`).
pub fn downgrade_version(version: u8, rule_set: &PlainRuleSet) -> u8 {
    let mut version = version;
    let rules = &rule_set.rules;
    if version == RULE_SET_VERSION_5 && !HeadlessRule::any_default(rules, &|rule| !rule.package_name_regex.is_empty()) {
        version = RULE_SET_VERSION_4;
    }
    if version == RULE_SET_VERSION_4
        && !HeadlessRule::any_default(rules, &|rule| {
            rule.network_interface_address.as_ref().is_some_and(|entries| !entries.is_empty())
                || !rule.default_interface_address.is_empty()
        })
    {
        version = RULE_SET_VERSION_3;
    }
    if version == RULE_SET_VERSION_3
        && !HeadlessRule::any_default(rules, &|rule| {
            !rule.network_type.is_empty() || rule.network_is_expensive || rule.network_is_constrained
        })
    {
        version = RULE_SET_VERSION_2;
    }
    version
}

#[cfg(test)]
mod tests {
    use super::*;

    fn craft(body: &[u8]) -> Vec<u8> {
        let mut output = MAGIC.to_vec();
        output.push(RULE_SET_VERSION_CURRENT);
        let mut encoder = ZlibEncoder::new(output, Compression::default());
        encoder.write_all(body).unwrap();
        encoder.finish().unwrap()
    }

    fn uvarint(value: u64) -> Vec<u8> {
        let mut buffer = Vec::new();
        write_uvarint(&mut buffer, value);
        buffer
    }

    #[test]
    fn read_malformed() {
        let default_rule = [0u8];
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("huge_rule_count", uvarint(1 << 40)),
            (
                "huge_string_count",
                [uvarint(1), default_rule.to_vec(), vec![ITEM_DOMAIN_KEYWORD], uvarint(1 << 40)].concat(),
            ),
            (
                "huge_string_length",
                [uvarint(1), default_rule.to_vec(), vec![ITEM_DOMAIN_KEYWORD], uvarint(1), uvarint(1 << 40)].concat(),
            ),
            (
                "huge_uint16_count",
                [uvarint(1), default_rule.to_vec(), vec![ITEM_QUERY_TYPE], uvarint(1 << 40)].concat(),
            ),
            (
                "huge_ip_range_count",
                [uvarint(1), default_rule.to_vec(), vec![ITEM_IP_CIDR, 1], (1u64 << 40).to_be_bytes().to_vec()]
                    .concat(),
            ),
            (
                "bad_ip_range_address_length",
                [uvarint(1), default_rule.to_vec(), vec![ITEM_IP_CIDR, 1], 1u64.to_be_bytes().to_vec(), uvarint(99)]
                    .concat(),
            ),
            (
                "huge_prefix_address_length",
                [uvarint(1), default_rule.to_vec(), vec![ITEM_DEFAULT_INTERFACE_ADDRESS], uvarint(1), uvarint(1 << 40)]
                    .concat(),
            ),
            (
                "empty_domain_matcher",
                [uvarint(1), default_rule.to_vec(), vec![ITEM_DOMAIN, 0], uvarint(0), uvarint(0), uvarint(0)].concat(),
            ),
            (
                "huge_domain_matcher_bitmap",
                [uvarint(1), default_rule.to_vec(), vec![ITEM_DOMAIN, 0], uvarint(1 << 40)].concat(),
            ),
            ("deep_logical_nesting", [uvarint(1), [1u8, 0, 1].repeat(10000)].concat()),
        ];
        for (name, body) in cases {
            assert!(read(&craft(&body), false).is_err(), "{name}");
        }
        assert!(read(b"SRX\x01", false).is_err());
        assert!(read(b"SRS\x09", false).is_err());
    }

    #[test]
    fn round_trip() {
        let source = PlainRuleSetCompat::parse(
            br#"{"version":2,"rules":[
              {"domain":["a.com","b.org"],"domain_suffix":[".cn","example.net"],"domain_keyword":"kw",
               "ip_cidr":["10.0.0.0/8","10.1.0.0/16","::1"],"port":[443],"port_range":"1000:2000","invert":true},
              {"type":"logical","mode":"and","rules":[{"network":"udp"},{"source_ip_cidr":"192.168.0.0/24"}]}
            ]}"#,
        )
        .unwrap();
        let binary = write(&source.options, source.version).unwrap();
        let decoded = read(&binary, true).unwrap();
        assert_eq!(decoded.version, 2);
        let HeadlessRule::Default(rule) = &decoded.options.rules[0] else { panic!() };
        assert_eq!(rule.domain.0, vec!["a.com", "b.org"]);
        assert_eq!(rule.domain_suffix.0, vec![".cn", "example.net"]);
        assert_eq!(rule.ip_cidr.0, vec!["10.0.0.0/8", "::1/128"]);
        assert!(rule.invert && rule.domain_matcher.is_some());
        // Rewriting what was read gives the same content.
        let mut plain = decoded.options.clone();
        for rule in &mut plain.rules {
            if let HeadlessRule::Default(rule) = rule {
                rule.domain_matcher = None;
                rule.ip_set = None;
            }
        }
        assert_eq!(encode_rules(&plain, 2).unwrap(), encode_rules(&source.options, 2).unwrap());
        assert!(write(&source.options, 1).is_ok());
        let network = PlainRuleSetCompat::parse(br#"{"version":2,"rules":[{"network_type":"wifi"}]}"#).unwrap();
        assert!(write(&network.options, 2).unwrap_err().0.contains("version 3"));
        assert_eq!(downgrade_version(5, &network.options), 3);
        assert_eq!(downgrade_version(5, &source.options), 2);
    }
}
