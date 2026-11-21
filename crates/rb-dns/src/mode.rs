//! The DNS rule mode, mirroring sing-box `dns/router.go`
//! (`resolveLegacyDNSMode`, `validateLegacyDNSModeDisabledRules`,
//! `ValidateRuleSetMetadataUpdate`): rules with address filter fields
//! (`ip_cidr`, `ip_is_private`, `ip_accept_any`, a rule-set with IP rules)
//! or a route `strategy` need the legacy mode; `ip_version`, `query_type` or
//! a rule-set with `query_type` rules rule it out.

use std::collections::{HashMap, HashSet};

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
    matches!(
        action,
        Some(DnsRuleAction::Route { options, .. } | DnsRuleAction::Evaluate { options, .. })
            if options.strategy != DomainStrategy::AsIs
    )
}

fn action_disables_legacy_mode(action: Option<&DnsRuleAction>) -> bool {
    match action {
        Some(DnsRuleAction::Route { options, speculative, race, .. })
        | Some(DnsRuleAction::Evaluate { options, speculative, race, .. }) => {
            *race || *speculative || options.disable_optimistic_cache
        }
        Some(DnsRuleAction::Respond { race }) | Some(DnsRuleAction::Reject { race, .. }) => *race,
        None => false,
    }
}

/// `defaultRuleNeedsLegacyDNSModeFromAddressFilter`.
fn needs_legacy_from_address_filter(rule: &DnsRuleMatch) -> bool {
    rule.rule_set_ip_cidr_accept_empty
        || (!rule.match_response.enabled && (rule.ip_accept_any || !rule.ip_cidr.is_empty() || rule.ip_is_private))
}

fn has_response_fields(rule: &DnsRuleMatch) -> bool {
    rule.response_rcode.is_some()
        || !rule.response_answer.is_empty()
        || !rule.response_ns.is_empty()
        || !rule.response_extra.is_empty()
}

/// `defaultRuleDisablesLegacyDNSMode`.
fn disables_legacy(rule: &DnsRuleMatch) -> bool {
    rule.match_response.enabled
        || has_response_fields(rule)
        || rule.ip_version.is_some_and(|version| version > 0)
        || !rule.query_type.is_empty()
}

fn rule_flags(rule: &DnsRule, lookup: &MetadataLookup) -> Result<ModeFlags, String> {
    match rule {
        Rule::Default { matcher, action } => {
            let mut flags = ModeFlags {
                disabled: disables_legacy(matcher) || action_disables_legacy_mode(action.as_ref()),
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
            let mut flags = ModeFlags {
                disabled: action_disables_legacy_mode(action.as_ref()),
                needed_from_strategy: action_has_strategy(action.as_ref()),
                ..Default::default()
            };
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
            if (has_response_fields(matcher)
                || !matcher.ip_cidr.is_empty()
                || matcher.ip_is_private
                || matcher.ip_accept_any)
                && !matcher.match_response.enabled
            {
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
    validate_evaluate_rules(rules)
}

fn collect_matchers<'a>(rule: &'a DnsRule, matchers: &mut Vec<&'a DnsRuleMatch>) {
    match rule {
        Rule::Default { matcher, .. } => matchers.push(matcher),
        Rule::Logical { rules, .. } => {
            for rule in rules {
                collect_matchers(rule, matchers);
            }
        }
    }
}

fn validate_nested_action_tree(rule: &DnsRule) -> Result<(), String> {
    if let Rule::Logical { rules, .. } = rule {
        for (index, rule) in rules.iter().enumerate() {
            if rule.action().is_some() {
                return Err(format!("sub rule[{index}]: DNS rule action is not supported in nested rules"));
            }
            validate_nested_action_tree(rule).map_err(|error| format!("sub rule[{index}]: {error}"))?;
        }
    }
    Ok(())
}

/// Nested DNS rule actions are rejected by sing-box in either DNS rule mode.
pub(crate) fn validate_nested_actions(rules: &[DnsRule]) -> Result<(), String> {
    for (index, rule) in rules.iter().enumerate() {
        validate_nested_action_tree(rule).map_err(|error| format!("dns rule[{index}]: {error}"))?;
    }
    Ok(())
}

/// Checks evaluate references and action-only constraints. sing-box runs
/// these checks only when legacy DNS mode is disabled.
pub(crate) fn validate_evaluate_rules(rules: &[DnsRule]) -> Result<(), String> {
    let mut named_tags = HashMap::<String, usize>::new();
    let mut referenced_tags = HashSet::<String>::new();
    let mut anonymous_evaluate: Option<(usize, bool)> = None;

    for (index, rule) in rules.iter().enumerate() {
        let rule_error = |message: String| format!("dns rule[{index}]: {message}");

        let is_logical = matches!(rule, Rule::Logical { .. });
        let mut matchers = Vec::new();
        collect_matchers(rule, &mut matchers);
        for matcher in &matchers {
            if !matcher.match_response.enabled {
                continue;
            }
            if matcher.match_response.tag.is_empty() {
                if anonymous_evaluate.is_none() {
                    let message = if named_tags.is_empty() {
                        "response-based matching requires a preceding evaluate action"
                    } else {
                        "response-based matching requires a preceding evaluate action without `tag`; use `match_response` with an evaluate tag to reference a tagged result"
                    };
                    return Err(rule_error(message.into()));
                }
                if let Some((_, used)) = anonymous_evaluate.as_mut() {
                    *used = true;
                }
            } else {
                let tag = matcher.match_response.tag.as_str();
                if !named_tags.contains_key(tag) {
                    return Err(rule_error(format!("undefined evaluate tag: {tag}")));
                }
                referenced_tags.insert(tag.to_string());
            }
        }

        if let Some(DnsRuleAction::Respond { .. }) = rule.action() {
            if is_logical
                && matchers
                    .iter()
                    .any(|matcher| matcher.match_response.enabled && !matcher.match_response.tag.is_empty())
            {
                return Err(rule_error(
                    "respond on a logical rule cannot bind a `match_response` tag from its sub rules; use a non-logical rule"
                        .into(),
                ));
            }
        }

        let (race, speculative, final_action) = match rule.action() {
            Some(DnsRuleAction::Route { race, speculative, .. }) => (*race, *speculative, true),
            Some(DnsRuleAction::Evaluate { race, speculative, .. }) => (*race, *speculative, false),
            Some(DnsRuleAction::Respond { race }) | Some(DnsRuleAction::Reject { race, .. }) => (*race, false, true),
            None => (false, false, false),
        };
        if race {
            if !final_action {
                return Err(rule_error("`race` requires a final action".into()));
            }
            if speculative {
                return Err(rule_error("`race` and `speculative` cannot be combined on the same rule".into()));
            }
            if !matchers.iter().any(|matcher| matcher.match_response.enabled) {
                let requirement = if is_logical {
                    "`race` requires `match_response` in sub-rules"
                } else {
                    "`race` requires `match_response`"
                };
                return Err(rule_error(requirement.into()));
            }
        }

        if let Some(DnsRuleAction::Evaluate { tag, .. }) = rule.action() {
            if tag.is_empty() {
                if let Some((previous_index, used)) = anonymous_evaluate {
                    if !used {
                        tracing::warn!(
                            rule = previous_index,
                            replaced_by = index,
                            "evaluated response is overwritten before any use"
                        );
                    }
                }
                anonymous_evaluate = Some((index, false));
            } else if named_tags.insert(tag.clone(), index).is_some() {
                return Err(rule_error(format!("duplicate evaluate tag: {tag}")));
            }
        }
    }

    for tag in named_tags.keys() {
        if !referenced_tags.contains(tag) {
            tracing::warn!(tag, "evaluate tag is never referenced");
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(json: &str) -> Vec<DnsRule> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn evaluate_tags_must_be_defined_before_their_references() {
        let valid = rules(
            r#"[{"action":"evaluate","server":"local","tag":"answer"},
                {"match_response":"answer","action":"respond"}]"#,
        );
        assert!(validate_evaluate_rules(&valid).is_ok());

        for (json, expected) in [
            (
                r#"[{"match_response":"later","action":"respond"},
                    {"action":"evaluate","server":"local","tag":"later"}]"#,
                "undefined evaluate tag: later",
            ),
            (
                r#"[{"action":"evaluate","server":"local","tag":"same"},
                    {"action":"evaluate","server":"local","tag":"same"}]"#,
                "duplicate evaluate tag: same",
            ),
            (
                r#"[{"match_response":true,"action":"respond"}]"#,
                "response-based matching requires a preceding evaluate action",
            ),
            (
                r#"[{"action":"evaluate","server":"local","tag":"named"},
                    {"match_response":true,"action":"respond"}]"#,
                "preceding evaluate action without `tag`",
            ),
        ] {
            let error = validate_evaluate_rules(&rules(json)).unwrap_err();
            assert!(error.contains(expected), "expected {expected:?}, got {error}");
        }
    }

    #[test]
    fn race_and_logical_respond_constraints_match_sing_box() {
        for (json, expected) in [
            (r#"[{"action":"evaluate","server":"local","race":true}]"#, "`race` requires a final action"),
            (
                r#"[{"action":"evaluate","server":"local","tag":"answer"},
                    {"action":"route","server":"local","race":true,"speculative":true,
                     "match_response":"answer"}]"#,
                "`race` and `speculative` cannot be combined",
            ),
            (r#"[{"action":"route","server":"local","race":true}]"#, "`race` requires `match_response`"),
            (
                r#"[{"type":"logical","mode":"and","rules":[{"domain":"example.com"}],
                     "action":"route","server":"local","race":true}]"#,
                "`race` requires `match_response` in sub-rules",
            ),
        ] {
            let error = validate_evaluate_rules(&rules(json)).unwrap_err();
            assert!(error.contains(expected), "expected {expected:?}, got {error}");
        }
        let logical_race = rules(
            r#"[{"action":"evaluate","server":"local","tag":"answer"},
                {"type":"logical","mode":"and","rules":[{"match_response":"answer"}],
                 "action":"route","server":"local","race":true}]"#,
        );
        assert!(validate_evaluate_rules(&logical_race).is_ok());
    }
}
