use std::net::IpAddr;
use std::sync::Arc;

use rb_config::{DnsRule, DnsRuleAction, HeadlessRule, RouteRule, RuleAction};

use super::*;
use crate::rule_set::{RuleSetContent, StaticRuleSet};

fn json<T: serde::de::DeserializeOwned>(text: &str) -> T {
    serde_json::from_str(text).unwrap()
}

/// Rule-sets from `(tag, [headless rule JSON])`.
fn rule_sets(sets: &[(&str, &[&str])]) -> RuleSets {
    let mut registry = RuleSets::new();
    for (tag, rules) in sets {
        let rules: Vec<HeadlessRule> =
            rules.iter().map(|rule| HeadlessRule::from_value(serde_json::from_str(rule).unwrap()).unwrap()).collect();
        let content = RuleSetContent::compile(&rules, &Context::new(&RuleSets::new())).unwrap();
        registry.insert(Arc::new(StaticRuleSet { tag: tag.to_string(), content: Arc::new(content) })).unwrap();
    }
    registry
}

fn route_with(sets: &RuleSets, text: &str) -> Compiled<RuleAction> {
    let rule: RouteRule = json(text);
    let context = Context::new(sets);
    compile(&rule, &|options| compile_route_match(options, &context)).unwrap()
}

fn route(text: &str) -> Compiled<RuleAction> {
    route_with(&RuleSets::new(), text)
}

fn dns_with(sets: &RuleSets, text: &str, legacy: bool) -> Compiled<DnsRuleAction> {
    let rule: DnsRule = json(text);
    let context = Context { rule_sets: sets, legacy_dns_mode: legacy, network_manager: true };
    compile(&rule, &|options| compile_dns_match(options, &context)).unwrap()
}

fn metadata<'a>(domain: Option<&'a str>, ip: Option<IpAddr>, port: u16) -> Metadata<'a> {
    Metadata {
        inbound: "in",
        network: Some("tcp"),
        domain,
        destination_ip: ip,
        destination_port: Some(port),
        source: Some("192.168.1.2:50000".parse().unwrap()),
        ..Default::default()
    }
}

/// sing-box `testMetadata`.
fn test_metadata(domain: &str) -> Metadata<'_> {
    Metadata {
        network: Some("tcp"),
        source: Some("10.0.0.1:1000".parse().unwrap()),
        domain: Some(domain),
        destination_port: Some(443),
        ..Default::default()
    }
}

#[test]
fn address_group_is_or_and_groups_are_and() {
    let rule = route(r#"{"domain_suffix":"example.com","ip_cidr":"10.0.0.0/8","port":443,"outbound":"x"}"#);
    assert!(rule.matches(&mut metadata(Some("a.example.com"), None, 443)));
    assert!(rule.matches(&mut metadata(None, Some("10.1.2.3".parse().unwrap()), 443)));
    assert!(!rule.matches(&mut metadata(Some("a.example.com"), None, 80)));
    assert!(!rule.matches(&mut metadata(Some("other.org"), None, 443)));
}

#[test]
fn resolved_addresses_and_private() {
    let rule = route(r#"{"ip_is_private":true,"outbound":"x"}"#);
    let addresses = ["192.168.0.1".parse().unwrap()];
    let mut meta = metadata(Some("router.lan"), None, 80);
    assert!(!rule.matches(&mut meta.clone()));
    meta.destination_addresses = &addresses;
    assert!(rule.matches(&mut meta));
    assert!(rule.matches(&mut metadata(None, Some("::1".parse().unwrap()), 80)));
    assert!(!rule.matches(&mut metadata(None, Some("8.8.8.8".parse().unwrap()), 80)));
}

#[test]
fn invert_logical_and_ranges() {
    let rule = route(r#"{"port_range":["1000:2000",":10"],"invert":true,"outbound":"x"}"#);
    assert!(!rule.matches(&mut metadata(None, None, 1500)));
    assert!(!rule.matches(&mut metadata(None, None, 5)));
    assert!(rule.matches(&mut metadata(None, None, 3000)));
    let rule = route(
        r#"{"type":"logical","mode":"or","rules":[{"domain":"a.com"},{"source_ip_cidr":"192.168.0.0/16"}],"outbound":"x"}"#,
    );
    assert!(rule.matches(&mut metadata(Some("b.com"), None, 1)));
    let rule =
        route(r#"{"type":"logical","mode":"and","rules":[{"domain":"a.com"},{"network":"udp"}],"outbound":"x"}"#);
    assert!(!rule.matches(&mut metadata(Some("a.com"), None, 1)));
    let rule: RouteRule = json(r#"{"port_range":"80","outbound":"x"}"#);
    let sets = RuleSets::new();
    let context = Context::new(&sets);
    assert!(compile(&rule, &|options| compile_route_match(options, &context)).is_err());
}

#[test]
fn empty_rule_matches_everything() {
    let rule = route(r#"{"action":"sniff"}"#);
    assert!(rule.matches(&mut metadata(None, None, 1)));
}

#[test]
fn domain_items_follow_sing_box() {
    // Keywords are not lowercased, the domain is.
    let rule = route(r#"{"domain_keyword":"Example","outbound":"x"}"#);
    assert!(!rule.matches(&mut metadata(Some("www.example.com"), None, 1)));
    let rule = route(r#"{"domain_keyword":"example","outbound":"x"}"#);
    assert!(rule.matches(&mut metadata(Some("WWW.EXAMPLE.COM"), None, 1)));
    let rule = route(r#"{"domain_suffix":[".cn"],"domain":"a.org","outbound":"x"}"#);
    assert!(rule.matches(&mut metadata(Some("a.b.cn"), None, 1)));
    assert!(!rule.matches(&mut metadata(Some("cn"), None, 1)));
    assert!(rule.matches(&mut metadata(Some("A.org"), None, 1)));
}

#[test]
fn rule_set_merges_into_outer_groups() {
    // TestRouteRuleSetMergeDestinationAddressGroup / MergeSourceAndPortGroups
    for (inner, name) in [
        (r#"{"domain":"www.example.com"}"#, "domain"),
        (r#"{"domain_suffix":"example.com"}"#, "domain_suffix"),
        (r#"{"domain_keyword":"example"}"#, "domain_keyword"),
        (r#"{"domain_regex":"^www\\.example\\.com$"}"#, "domain_regex"),
    ] {
        let sets = rule_sets(&[("s", &[inner])]);
        let rule = route_with(&sets, r#"{"rule_set":"s","ip_cidr":"203.0.113.0/24","outbound":"x"}"#);
        assert!(rule.matches(&mut test_metadata("www.example.com")), "{name}");
    }
    let sets = rule_sets(&[("s", &[r#"{"ip_cidr":"8.8.8.0/24"}"#])]);
    let rule = route_with(&sets, r#"{"rule_set":"s","ip_cidr":"203.0.113.0/24","outbound":"x"}"#);
    let addresses = ["8.8.8.8".parse().unwrap()];
    let mut meta = test_metadata("lookup.example");
    meta.destination_addresses = &addresses;
    assert!(rule.matches(&mut meta));
    for (inner, outer) in [
        (r#"{"source_ip_cidr":"10.0.0.0/8"}"#, r#"{"rule_set":"s","source_ip_cidr":"198.51.100.0/24","outbound":"x"}"#),
        (
            r#"{"ip_cidr":"10.0.0.0/8"}"#,
            r#"{"rule_set":"s","rule_set_ip_cidr_match_source":true,"source_ip_cidr":"198.51.100.0/24","outbound":"x"}"#,
        ),
        (r#"{"port":443}"#, r#"{"rule_set":"s","port":8443,"outbound":"x"}"#),
        (r#"{"port_range":"400:500"}"#, r#"{"rule_set":"s","port":8443,"outbound":"x"}"#),
        (r#"{"source_port":1000}"#, r#"{"rule_set":"s","source_port":2000,"outbound":"x"}"#),
        (r#"{"source_port_range":"900:1100"}"#, r#"{"rule_set":"s","source_port":2000,"outbound":"x"}"#),
    ] {
        let sets = rule_sets(&[("s", &[inner])]);
        assert!(route_with(&sets, outer).matches(&mut test_metadata("www.example.com")), "{inner}");
    }
}

#[test]
fn rule_set_or_and_logical_semantics() {
    // later ruleset can satisfy outer group
    let sets = rule_sets(&[("a", &[r#"{"network":"tcp"}"#]), ("b", &[r#"{"domain_suffix":"example.com"}"#])]);
    let rule = route_with(&sets, r#"{"rule_set":["a","b"],"ip_cidr":"203.0.113.0/24","outbound":"x"}"#);
    assert!(rule.matches(&mut test_metadata("www.example.com")));
    // multi rule set does not satisfy outer group
    let sets = rule_sets(&[("a", &[r#"{"network":"tcp"}"#, r#"{"domain_suffix":"example.com"}"#])]);
    let rule = route_with(&sets, r#"{"rule_set":"a","ip_cidr":"203.0.113.0/24","outbound":"x"}"#);
    assert!(!rule.matches(&mut test_metadata("www.example.com")));
    // cross ruleset union is not allowed
    let sets = rule_sets(&[("a", &[r#"{"source_port":1000}"#]), ("b", &[r#"{"domain_suffix":"example.com"}"#])]);
    let rule =
        route_with(&sets, r#"{"rule_set":["a","b"],"source_port":2000,"ip_cidr":"203.0.113.0/24","outbound":"x"}"#);
    assert!(!rule.matches(&mut test_metadata("www.example.com")));
    // logical set does not satisfy outer group
    let sets = rule_sets(&[(
        "a",
        &[r#"{"type":"logical","mode":"or","rules":[{"network":"tcp"},{"domain_suffix":"example.com"}]}"#],
    )]);
    let rule = route_with(&sets, r#"{"rule_set":"a","ip_cidr":"203.0.113.0/24","outbound":"x"}"#);
    assert!(!rule.matches(&mut test_metadata("www.example.com")));
    // logical branch matches on its own conditions
    let sets = rule_sets(&[(
        "a",
        &[r#"{"type":"logical","mode":"and","rules":[{"domain_suffix":"example.com"},{"source_port":1000}]}"#],
    )]);
    assert!(route_with(&sets, r#"{"rule_set":"a","source_port":1000,"outbound":"x"}"#)
        .matches(&mut test_metadata("www.example.com")));
    assert!(!route_with(&sets, r#"{"rule_set":"a","ip_cidr":"203.0.113.0/24","source_port":2000,"outbound":"x"}"#)
        .matches(&mut test_metadata("www.example.com")));
    // inverted set does not satisfy outer group
    let sets = rule_sets(&[("a", &[r#"{"domain_suffix":"cn","invert":true}"#])]);
    assert!(!route_with(&sets, r#"{"rule_set":"a","ip_cidr":"203.0.113.0/24","outbound":"x"}"#)
        .matches(&mut test_metadata("www.example.com")));
    // standalone reference
    assert!(route_with(&sets, r#"{"rule_set":"a","outbound":"x"}"#).matches(&mut test_metadata("www.example.com")));
    let missing: RouteRule = json(r#"{"rule_set":"nope","outbound":"x"}"#);
    let context = Context::new(&sets);
    let error = compile(&missing, &|options| compile_route_match(options, &context)).unwrap_err();
    assert_eq!(error.0, "rule-set not found: nope");
}

#[test]
fn dns_legacy_address_limit() {
    // TestDNSLegacyAddressLimitPreLookupDefersDirectRules
    let sets = RuleSets::new();
    for (rule, matched, unmatched) in [
        (r#"{"ip_cidr":"203.0.113.0/24","server":"s"}"#, vec!["203.0.113.1"], vec!["8.8.8.8"]),
        (r#"{"ip_is_private":true,"server":"s"}"#, vec!["10.0.0.1"], vec!["8.8.8.8"]),
        (r#"{"ip_accept_any":true,"server":"s"}"#, vec!["203.0.113.1"], vec![]),
    ] {
        let rule = dns_with(&sets, rule, true);
        assert!(rule.matcher.with_address_limit());
        assert!(rule.matcher.legacy_pre_match(&mut test_metadata("lookup.example")), "{rule:?}");
        let matched: Vec<IpAddr> = matched.iter().map(|ip| ip.parse().unwrap()).collect();
        let unmatched: Vec<IpAddr> = unmatched.iter().map(|ip| ip.parse().unwrap()).collect();
        assert!(rule.matcher.match_address_limit(&test_metadata("lookup.example"), &matched));
        assert!(!rule.matcher.match_address_limit(&test_metadata("lookup.example"), &unmatched));
    }
    // A rule-set's destination CIDR is deferred the same way.
    let sets = rule_sets(&[("ip", &[r#"{"ip_cidr":"203.0.113.0/24"}"#])]);
    let rule = dns_with(&sets, r#"{"rule_set":"ip","server":"s"}"#, true);
    assert!(rule.matcher.with_address_limit());
    assert!(rule.matcher.legacy_pre_match(&mut test_metadata("lookup.example")));
    assert!(rule.matcher.match_address_limit(&test_metadata("lookup.example"), &["203.0.113.1".parse().unwrap()]));
    assert!(!rule.matcher.match_address_limit(&test_metadata("lookup.example"), &["8.8.8.8".parse().unwrap()]));
    // With rule_set_ip_cidr_match_source the set matches the source instead.
    let rule = dns_with(&sets, r#"{"rule_set":"ip","rule_set_ip_cidr_match_source":true,"server":"s"}"#, true);
    assert!(!rule.matcher.with_address_limit());
    // Inverted: the pre-match passes, the response decides.
    let rule = dns_with(&RuleSets::new(), r#"{"ip_cidr":"203.0.113.0/24","invert":true,"server":"s"}"#, true);
    assert!(rule.matcher.legacy_pre_match(&mut test_metadata("lookup.example")));
    assert!(!rule.matcher.match_address_limit(&test_metadata("lookup.example"), &["203.0.113.1".parse().unwrap()]));
    assert!(rule.matcher.match_address_limit(&test_metadata("lookup.example"), &["8.8.8.8".parse().unwrap()]));
    // Logical rules defer their nested rules.
    let rule = dns_with(
        &RuleSets::new(),
        r#"{"type":"logical","mode":"and","rules":[{"ip_is_private":true}],"server":"s"}"#,
        true,
    );
    assert!(rule.matcher.legacy_pre_match(&mut test_metadata("lookup.example")));
    assert!(rule.matcher.match_address_limit(&test_metadata("lookup.example"), &["10.0.0.1".parse().unwrap()]));
    assert!(!rule.matcher.match_address_limit(&test_metadata("lookup.example"), &["8.8.8.8".parse().unwrap()]));
}

#[test]
fn dns_query_type_and_ip_version() {
    let sets = RuleSets::new();
    let rule = dns_with(&sets, r#"{"ip_version":6,"query_type":"AAAA","server":"s"}"#, false);
    let mut meta = test_metadata("a.example");
    meta.query_type = Some(28);
    meta.ip_version = Some(6);
    assert!(rule.matches(&mut meta));
    meta.query_type = Some(1);
    meta.ip_version = Some(4);
    assert!(!rule.matches(&mut meta));
    let rule: DnsRule = json(r#"{"rule_set_ip_cidr_accept_empty":true,"server":"s"}"#);
    let context = Context::new(&sets);
    let error = compile(&rule, &|options| compile_dns_match(options, &context)).unwrap_err();
    assert!(error.0.contains("rule_set_ip_cidr_accept_empty"), "{error}");
}

#[test]
fn headless_platform_items() {
    // Process and platform items never match in a box; without a network
    // manager (`rule-set match`) the platform items are left out.
    let rule = HeadlessRule::from_value(serde_json::json!({"network_type": "wifi"})).unwrap();
    let sets = RuleSets::new();
    let in_box = compile_headless(&rule, &Context::new(&sets)).unwrap();
    assert!(!in_box.matches(&mut test_metadata("a")));
    let standalone =
        compile_headless(&rule, &Context { rule_sets: &sets, legacy_dns_mode: false, network_manager: false }).unwrap();
    assert!(standalone.matches(&mut test_metadata("a")));
    let rule = HeadlessRule::from_value(serde_json::json!({"process_name": "curl"})).unwrap();
    assert!(!compile_headless(&rule, &Context::new(&sets)).unwrap().matches(&mut test_metadata("a")));
    let rule = HeadlessRule::from_value(serde_json::json!({"invert": true})).unwrap();
    assert_eq!(compile_headless(&rule, &Context::new(&sets)).unwrap_err().0, "missing conditions");
}

#[test]
fn rule_set_metadata_flags() {
    let rules: Vec<HeadlessRule> = [r#"{"ip_cidr":"1.0.0.0/8"}"#, r#"{"query_type":"A"}"#]
        .iter()
        .map(|rule| HeadlessRule::from_value(serde_json::from_str(rule).unwrap()).unwrap())
        .collect();
    let metadata = rule_set_metadata(&rules);
    assert!(
        metadata.contains_ip_cidr_rule && metadata.contains_dns_query_type_rule && metadata.contains_non_ip_cidr_rule
    );
    let pure = rule_set_metadata(&rules[..1]);
    assert!(pure.contains_ip_cidr_rule && !pure.contains_non_ip_cidr_rule);
}
