//! AdGuard DNS filters to headless rules, mirroring sing-box
//! `common/convertor/adguard` (`ToOptions`).

use crate::rule_set::{DefaultHeadlessRule, HeadlessRule, LogicalHeadlessRule};
use crate::types::Listable;

#[derive(Debug, Clone, Default)]
struct RuleLine {
    rule_line: String,
    is_raw_domain: bool,
    is_exclude: bool,
    is_suffix: bool,
    has_start: bool,
    has_end: bool,
    is_regexp: bool,
    is_important: bool,
}

/// Go `net.isDomainName` (what sing's `M.IsDomainName` links to).
pub fn is_domain_name(s: &str) -> bool {
    if s == "." {
        return true;
    }
    let bytes = s.as_bytes();
    let length = bytes.len();
    if length == 0 || length > 254 || (length == 254 && bytes[length - 1] != b'.') {
        return false;
    }
    let mut last = b'.';
    let mut non_numeric = false;
    let mut part_length = 0;
    for &c in bytes {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                part_length += 1;
            }
            b'0'..=b'9' => part_length += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                part_length += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' {
                    return false;
                }
                if part_length > 63 || part_length == 0 {
                    return false;
                }
                part_length = 0;
            }
            _ => return false,
        }
        last = c;
    }
    if last == b'-' || part_length > 63 {
        return false;
    }
    non_numeric
}

fn substring_after<'a>(s: &'a str, separator: &str) -> &'a str {
    s.split_once(separator).map(|(_, after)| after).unwrap_or(s)
}

fn substring_before<'a>(s: &'a str, separator: &str) -> &'a str {
    s.split_once(separator).map(|(before, _)| before).unwrap_or(s)
}

fn parse_u8(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) && text.parse::<u8>().is_ok()
}

fn ignore_ip_cidr_regexp(rule_line: &str) -> bool {
    let rule_line = if let Some(rest) = rule_line.strip_prefix("(http?:\\/\\/)") {
        rest
    } else if let Some(rest) = rule_line.strip_prefix("(https?:\\/\\/)") {
        rest
    } else if let Some(rest) = rule_line.strip_prefix('^') {
        rest
    } else {
        rule_line
    };
    parse_u8(substring_before(rule_line, "\\.")) || parse_u8(substring_before(rule_line, "."))
}

/// `parseAdGuardHostLine`: `Ok(Some(domain))` for `0.0.0.0 domain`,
/// `Ok(None)` for a host line with another address.
fn parse_host_line(rule_line: &str) -> Result<Option<String>, ()> {
    let (before, after) = rule_line.split_once(' ').ok_or(())?;
    let address = rb_common::ipset::parse_addr(before).map_err(|_| ())?;
    if !address.is_unspecified() {
        return Ok(None);
    }
    if !is_domain_name(after) {
        return Err(());
    }
    Ok(Some(after.to_string()))
}

fn parse_ip_cidr_line(rule_line: &str) -> bool {
    let (rule_line, is_prefix) = match rule_line.strip_suffix('.') {
        Some(rest) => (rest, true),
        None => (rule_line, false),
    };
    let parts: Vec<&str> = rule_line.split('.').collect();
    if parts.len() > 4 || (parts.len() < 4 && !is_prefix) {
        return false;
    }
    parts.iter().all(|part| parse_u8(part))
}

/// `adguard.ToOptions`. Unsupported lines are skipped (logged at debug).
pub fn to_options(content: &str) -> Result<Vec<HeadlessRule>, String> {
    let mut rule_lines: Vec<RuleLine> = Vec::new();
    let mut ignored = 0usize;
    'lines: for line in content.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            continue;
        }
        let origin = line;
        if is_domain_name(line) {
            rule_lines.push(RuleLine { rule_line: line.to_string(), is_raw_domain: true, ..Default::default() });
            continue;
        }
        match parse_host_line(line) {
            Ok(Some(host)) => {
                rule_lines.push(RuleLine {
                    rule_line: host,
                    is_raw_domain: true,
                    has_start: true,
                    has_end: true,
                    ..Default::default()
                });
                continue;
            }
            Ok(None) => continue,
            Err(()) => {}
        }
        let mut rule_line = line.strip_suffix('|').unwrap_or(line).to_string();
        let mut entry = RuleLine::default();
        if !rule_line.starts_with('/') && rule_line.contains('$') {
            let params = substring_after(&rule_line, "$").to_string();
            for param in params.split(',') {
                let parts: Vec<&str> = param.split('=').collect();
                let mut ignore = false;
                if !parts.is_empty() && parts.len() <= 2 {
                    match parts[0] {
                        "important" => {
                            ignore = true;
                            entry.is_important = true;
                        }
                        "dnsrewrite" => {
                            if parts.len() == 2
                                && rb_common::ipset::parse_addr(parts[1]).ok().is_some_and(|addr| addr.is_unspecified())
                            {
                                ignore = true;
                            }
                        }
                        _ => {}
                    }
                }
                if !ignore {
                    ignored += 1;
                    tracing::debug!("ignored unsupported rule with modifier: {}: {origin}", parts[0]);
                    continue 'lines;
                }
            }
            rule_line = substring_before(&rule_line, "$").to_string();
        }
        if let Some(rest) = rule_line.strip_prefix("@@") {
            rule_line = rest.to_string();
            entry.is_exclude = true;
        }
        if let Some(rest) = rule_line.strip_suffix('|') {
            rule_line = rest.to_string();
        }
        if let Some(rest) = rule_line.strip_prefix("||") {
            rule_line = rest.to_string();
            entry.is_suffix = true;
        } else if let Some(rest) = rule_line.strip_prefix('|') {
            rule_line = rest.to_string();
            entry.has_start = true;
        }
        if let Some(rest) = rule_line.strip_suffix('^') {
            rule_line = rest.to_string();
            entry.has_end = true;
        }
        if rule_line.len() >= 2 && rule_line.starts_with('/') && rule_line.ends_with('/') {
            rule_line = rule_line[1..rule_line.len() - 1].to_string();
            if ignore_ip_cidr_regexp(&rule_line) {
                ignored += 1;
                tracing::debug!("ignored unsupported rule with IPCIDR regexp: {origin}");
                continue;
            }
            entry.is_regexp = true;
        } else {
            if rule_line.contains("://") {
                rule_line = substring_after(&rule_line, "://").to_string();
                entry.is_suffix = true;
            }
            if rule_line.contains('/') {
                ignored += 1;
                tracing::debug!("ignored unsupported rule with path: {origin}");
                continue;
            }
            if rule_line.contains('?') || rule_line.contains('&') {
                ignored += 1;
                tracing::debug!("ignored unsupported rule with query: {origin}");
                continue;
            }
            if rule_line.contains(['[', ']', '(', ')', '!', '#']) {
                ignored += 1;
                tracing::debug!("ignored unsupported cosmetic filter: {origin}");
                continue;
            }
            if rule_line.contains('~') {
                ignored += 1;
                tracing::debug!("ignored unsupported rule modifier: {origin}");
                continue;
            }
            if rule_line.is_empty() {
                ignored += 1;
                tracing::debug!("ignored unsupported rule with empty domain{origin}");
                continue;
            }
            let domain_check = if rule_line.starts_with('.') || rule_line.starts_with('-') {
                format!("r{rule_line}")
            } else {
                rule_line.clone()
            };
            let domain_check = domain_check.replace('*', "x");
            if !is_domain_name(&domain_check) {
                ignored += 1;
                if parse_ip_cidr_line(&rule_line) {
                    tracing::debug!("ignored unsupported rule with IPCIDR: {origin}");
                } else {
                    tracing::debug!("ignored unsupported rule with invalid domain: {origin}");
                }
                continue;
            }
        }
        entry.rule_line = rule_line;
        rule_lines.push(entry);
    }
    if rule_lines.is_empty() {
        return Err("AdGuard rule-set is empty or all rules are unsupported".into());
    }
    if rule_lines.iter().all(|line| line.is_raw_domain) {
        return Ok(vec![HeadlessRule::Default(DefaultHeadlessRule {
            domain: Listable(rule_lines.into_iter().map(|line| line.rule_line).collect()),
            ..Default::default()
        })]);
    }
    let map_domain = |line: &RuleLine| {
        let mut text = line.rule_line.clone();
        if line.is_suffix {
            text = format!("||{text}");
        } else if line.has_start {
            text = format!("|{text}");
        }
        if line.has_end {
            text.push('^');
        }
        text
    };
    let select = |important: bool, regexp: bool, exclude: bool| -> Vec<String> {
        rule_lines
            .iter()
            .filter(|line| line.is_important == important && line.is_regexp == regexp && line.is_exclude == exclude)
            .map(map_domain)
            .collect()
    };
    let leaf = |adguard: Vec<String>, regex: Vec<String>, invert: bool| {
        HeadlessRule::Default(DefaultHeadlessRule {
            adguard_domain: adguard,
            domain_regex: Listable(regex),
            invert,
            ..Default::default()
        })
    };
    let wrap = |mode: &str, first: HeadlessRule, current: HeadlessRule| {
        HeadlessRule::Logical(LogicalHeadlessRule { mode: mode.into(), rules: vec![first, current], invert: false })
    };
    let mut current = leaf(select(false, false, false), select(false, true, false), false);
    let (exclude, exclude_regex) = (select(false, false, true), select(false, true, true));
    if !exclude.is_empty() || !exclude_regex.is_empty() {
        current = wrap("and", leaf(exclude, exclude_regex, true), current);
    }
    let (important, important_regex) = (select(true, false, false), select(true, true, false));
    if !important.is_empty() || !important_regex.is_empty() {
        current = wrap("or", leaf(important, important_regex, false), current);
    }
    let (important_exclude, important_exclude_regex) = (select(true, false, true), select(true, true, true));
    if !important_exclude.is_empty() || !important_exclude_regex.is_empty() {
        current = wrap("and", leaf(important_exclude, important_exclude_regex, true), current);
    }
    if ignored > 0 {
        tracing::info!("parsed rules: {}/{}", rule_lines.len(), rule_lines.len() + ignored);
    }
    Ok(vec![current])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_names() {
        assert!(is_domain_name("example.com") && is_domain_name("a_b.c") && is_domain_name("x."));
        assert!(
            !is_domain_name("1.2.3.4") && !is_domain_name("a..b") && !is_domain_name("-a.b") && !is_domain_name("")
        );
    }

    #[test]
    fn converts_filters() {
        let rules = to_options("example.com\n0.0.0.0 ads.test\n").unwrap();
        let HeadlessRule::Default(rule) = &rules[0] else { panic!() };
        assert_eq!(rule.domain.0, vec!["example.com", "ads.test"]);
        let content =
            "! comment\n||ads.example.org^\n@@||good.example.org^\n||vip.test^$important\n/ad[0-9]+\\.test/\n\
                       ||x.test/path\nexample.net$third-party\n";
        let rules = to_options(content).unwrap();
        let json = rb_common::gojson::to_string(
            &crate::rule_set::PlainRuleSetCompat { version: 2, options: crate::rule_set::PlainRuleSet { rules } }
                .to_json(),
        );
        assert_eq!(
            json,
            r#"{"version":2,"rules":[{"type":"logical","mode":"or","rules":[{},{"type":"logical","mode":"and","rules":[{"invert":true},{"domain_regex":"ad[0-9]+\\.test"}]}]}]}"#
        );
        let HeadlessRule::Logical(top) = &to_options(content).unwrap()[0] else { panic!() };
        let HeadlessRule::Default(important) = &top.rules[0] else { panic!() };
        assert_eq!(important.adguard_domain, vec!["||vip.test^"]);
        assert!(to_options("! only comments\n").is_err());
    }
}
