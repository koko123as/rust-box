//! The DNS rule mode, mirroring sing-box `dns/router.go`
//! (`resolveLegacyDNSMode`, `validateLegacyDNSModeDisabledRules`,
//! `ValidateRuleSetMetadataUpdate`): rules with address filter fields
//! (`ip_cidr`, `ip_is_private`, `ip_accept_any`, a rule-set with IP rules)
//! or a route `strategy` need the legacy mode; `ip_version`, `query_type` or
//! a rule-set with `query_type` rules rule it out.

use std::collections::HashMap;

use rb_config::deprecated::{LEGACY_DNS_ADDRESS_FILTER, LEGACY_DNS_RULE_STRATEGY, RULE_SET_IP_CIDR_ACCEPT_EMPTY};
use rb_config::{DnsRule, DnsRuleAction, DnsRuleMatch, DomainStrategy, Rule};
use rb_rule::{RuleSetMetadata, RuleSets};

/// `dnsRuleModeFlags`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ModeFlags {
    pub disabled: bool,
    pub needed: bool,
    pub needed_from_strategy: bool,
}

impl ModeFlags {
    fn merge(&mut self, other: ModeFlags) {
        self.disabled |= other.disabled;
        self.needed |= other.needed;
        self.needed_from_strategy |= other.needed_from_strategy;
    }
}

/// Rule-set metadata, with the metadata of an update taking the place of
/// the current one.
pub(crate) struct MetadataLookup<'a> {
    pub rule_sets: &'a RuleSets,
    pub overrides: HashMap<String, RuleSetMetadata>,
}

impl MetadataLookup<'_> {
    fn get(&self, tag: &str) -> Result<RuleSetMetadata, String> {
        if let Some(metadata) = self.overrides.get(tag) {
            return Ok(*metadata);
        }
        self.rule_sets.get(tag).map(|set| set.metadata()).ok_or_else(|| format!("rule-set not found: {tag}"))
    }
}

/// `dnsRuleActionHasStrategy`.
fn action_has_strategy(action: Option<&DnsRuleAction>) -> bool {
    matches!(action, Some(DnsRuleAction::Route { strategy, .. }) if *strategy != DomainStrategy::AsIs)
}

/// `defaultRuleNeedsLegacyDNSModeFromAddressFilter`.
fn needs_legacy_from_address_filter(rule: &DnsRuleMatch) -> bool {
    rule.rule_set_ip_cidr_accept_empty || rule.ip_accept_any || !rule.ip_cidr.is_empty() || rule.ip_is_private
}

/// `defaultRuleDisablesLegacyDNSMode` (rust-box has no `match_response`,
/// response fields, `evaluate` or `respond` yet).
fn disables_legacy(rule: &DnsRuleMatch) -> bool {
    rule.ip_version.is_some_and(|version| version > 0) || !rule.query_type.is_empty()
}

fn rule_flags(rule: &DnsRule, lookup: &MetadataLookup) -> Result<ModeFlags, String> {
    match rule {
        Rule::Default { matcher, action } => {
            let mut flags = ModeFlags {
                disabled: disables_legacy(matcher),
                needed_from_strategy: action_has_strategy(action.as_ref()),
                ..Default::default()
            };
            flags.needed = needs_legacy_from_address_filter(matcher) || flags.needed_from_strategy;
            for tag in matcher.rule_set.iter() {
                let metadata = lookup.get(tag)?;
                flags.disabled |= metadata.contains_dns_query_type_rule;
                if !matcher.rule_set_ip_cidr_match_source && metadata.contains_ip_cidr_rule {
                    flags.needed = true;
                }
            }
            Ok(flags)
        }
        Rule::Logical { rules, action, .. } => {
            let mut flags =
                ModeFlags { needed_from_strategy: action_has_strategy(action.as_ref()), ..Default::default() };
            flags.needed = flags.needed_from_strategy;
            for (index, rule) in rules.iter().enumerate() {
                flags.merge(rule_flags(rule, lookup).map_err(|error| format!("sub rule[{index}]: {error}"))?);
            }
            Ok(flags)
        }
    }
}

/// `resolveLegacyDNSMode`: whether the rules run in the legacy mode.
pub(crate) fn resolve_legacy_mode(rules: &[DnsRule], lookup: &MetadataLookup) -> Result<(bool, ModeFlags), String> {
    let mut flags = ModeFlags::default();
    for (index, rule) in rules.iter().enumerate() {
        flags.merge(rule_flags(rule, lookup).map_err(|error| format!("dns rule[{index}]: {error}"))?);
    }
    if flags.disabled && flags.needed_from_strategy {
        return Err(LEGACY_DNS_RULE_STRATEGY.message_with_link());
    }
    if flags.disabled {
        return Ok((false, flags));
    }
    Ok((flags.needed, flags))
}

const RESPONSE_FIELDS_ERROR: &str = "Response Match Fields (ip_cidr, ip_is_private, ip_accept_any, response_rcode, \
                                     response_answer, response_ns, response_extra) require match_response to be enabled";

fn validate_disabled_tree(rule: &DnsRule, lookup: &MetadataLookup) -> Result<(), String> {
    match rule {
        Rule::Default { matcher, .. } => {
            if !matcher.ip_cidr.is_empty() || matcher.ip_is_private || matcher.ip_accept_any {
                return Err(RESPONSE_FIELDS_ERROR.into());
            }
            for tag in matcher.rule_set.iter() {
                let metadata = lookup.get(tag)?;
                if metadata.contains_ip_cidr_rule && !metadata.contains_non_ip_cidr_rule {
                    return Err(LEGACY_DNS_ADDRESS_FILTER.message_with_link());
                }
            }
            if matcher.rule_set_ip_cidr_accept_empty {
                return Err(RULE_SET_IP_CIDR_ACCEPT_EMPTY.message_with_link());
            }
            Ok(())
        }
        Rule::Logical { rules, .. } => {
            for (index, rule) in rules.iter().enumerate() {
                validate_disabled_tree(rule, lookup).map_err(|error| format!("sub rule[{index}]: {error}"))?;
            }
            Ok(())
        }
    }
}

/// `validateLegacyDNSModeDisabledRules`: what the default mode refuses.
pub(crate) fn validate_disabled_rules(rules: &[DnsRule], lookup: &MetadataLookup) -> Result<(), String> {
    for (index, rule) in rules.iter().enumerate() {
        validate_disabled_tree(rule, lookup).map_err(|error| format!("validate dns rule[{index}]: {error}"))?;
    }
    Ok(())
}

/// The router's side of `ValidateRuleSetMetadataUpdate`.
pub(crate) fn validate_update(
    rules: &[DnsRule],
    lookup: &MetadataLookup,
    started: bool,
    legacy: bool,
) -> Result<(), String> {
    if rules.is_empty() {
        return Ok(());
    }
    if !started {
        let (candidate, _) = resolve_legacy_mode(rules, lookup)?;
        if !candidate {
            return validate_disabled_rules(rules, lookup);
        }
        return Ok(());
    }
    let (candidate, flags) = resolve_legacy_mode(rules, lookup)?;
    if legacy {
        if !candidate && flags.disabled {
            validate_disabled_rules(rules, lookup)?;
            return Err(LEGACY_DNS_ADDRESS_FILTER.message_with_link());
        }
        return Ok(());
    }
    if candidate {
        return Err(LEGACY_DNS_ADDRESS_FILTER.message_with_link());
    }
    validate_disabled_rules(rules, lookup)
}
