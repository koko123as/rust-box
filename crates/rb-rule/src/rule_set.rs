//! Rule-sets as rules see them: the `RuleSet` interface (sing-box
//! `adapter.RuleSet`), its metadata (`buildRuleSetMetadata`), the
//! compiled content a rule-set swaps on reload, and the `rule_set` rule
//! item (`rule_item_rule_set.go`).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, OnceLock};

use rb_config::{DefaultHeadlessRule, HeadlessRule};

use crate::{compile_headless, Context, DefaultMatcher, GroupMatch, Matcher, Metadata, RuleError};

/// `adapter.RuleSetMetadata`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuleSetMetadata {
    pub contains_process_rule: bool,
    pub contains_wifi_rule: bool,
    pub contains_ip_cidr_rule: bool,
    pub contains_dns_query_type_rule: bool,
    /// At least one rule has a predicate other than destination
    /// `ip_cidr`; a set without one but with IP rules is "pure-IP".
    pub contains_non_ip_cidr_rule: bool,
}

fn is_process_rule(rule: &DefaultHeadlessRule) -> bool {
    !rule.process_name.is_empty()
        || !rule.process_path.is_empty()
        || !rule.process_path_regex.is_empty()
        || !rule.package_name.is_empty()
        || !rule.package_name_regex.is_empty()
}

fn is_ip_cidr_rule(rule: &DefaultHeadlessRule) -> bool {
    !rule.ip_cidr.is_empty() || rule.ip_set.is_some()
}

fn is_non_ip_cidr_rule(rule: &DefaultHeadlessRule) -> bool {
    let ip_only = DefaultHeadlessRule {
        ip_cidr: rule.ip_cidr.clone(),
        ip_set: rule.ip_set.clone(),
        invert: rule.invert,
        ..Default::default()
    };
    *rule != ip_only
}

/// `buildRuleSetMetadata`.
pub fn rule_set_metadata(rules: &[HeadlessRule]) -> RuleSetMetadata {
    RuleSetMetadata {
        contains_process_rule: HeadlessRule::any_default(rules, &is_process_rule),
        contains_wifi_rule: HeadlessRule::any_default(rules, &|rule| {
            !rule.wifi_ssid.is_empty() || !rule.wifi_bssid.is_empty()
        }),
        contains_ip_cidr_rule: HeadlessRule::any_default(rules, &is_ip_cidr_rule),
        contains_dns_query_type_rule: HeadlessRule::any_default(rules, &|rule| !rule.query_type.is_empty()),
        contains_non_ip_cidr_rule: HeadlessRule::any_default(rules, &is_non_ip_cidr_rule),
    }
}

/// The compiled rules of a rule-set at one moment.
#[derive(Debug, Default)]
pub struct RuleSetContent {
    rules: Vec<Matcher>,
    metadata: RuleSetMetadata,
}

impl RuleSetContent {
    /// Compiles headless rules (sing-box `reloadRules` / `loadBytes`).
    pub fn compile(rules: &[HeadlessRule], context: &Context) -> Result<Self, RuleError> {
        let compiled = rules
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                compile_headless(rule, context)
                    .map_err(|error| RuleError(format!("parse rule_set.rules.[{index}]: {error}")))
            })
            .collect::<Result<_, _>>()?;
        Ok(RuleSetContent { rules: compiled, metadata: rule_set_metadata(rules) })
    }

    pub fn metadata(&self) -> RuleSetMetadata {
        self.metadata
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// `matchAnyHeadlessRule`.
    pub fn matches(&self, metadata: &mut Metadata) -> bool {
        let mut matched = false;
        let mut deferred = 0u8;
        let snapshot = metadata.snapshot();
        for rule in &self.rules {
            metadata.reset_rule_match_cache();
            if rule.matches(metadata) {
                if metadata.deferred_ip_cidr_match_groups == 0 {
                    metadata.restore(snapshot);
                    return true;
                }
                matched = true;
                deferred |= metadata.deferred_ip_cidr_match_groups;
            }
        }
        metadata.restore(snapshot);
        if matched {
            metadata.deferred_ip_cidr_match_groups |= deferred;
        }
        matched
    }

    /// `mergeableRuleIn`: the one default rule, when that is all there is.
    fn mergeable(&self) -> Option<&DefaultMatcher> {
        match self.rules.as_slice() {
            [Matcher::Default(rule)] if rule.mergeable() => Some(rule),
            _ => None,
        }
    }
}

/// A rule-set (sing-box `adapter.RuleSet`): its rules can change while it
/// runs (file reload, remote update), so matching takes the current
/// content.
pub trait RuleSet: Send + Sync {
    fn name(&self) -> &str;
    fn content(&self) -> Arc<RuleSetContent>;
    fn metadata(&self) -> RuleSetMetadata {
        self.content().metadata()
    }
    fn matches(&self, metadata: &mut Metadata) -> bool {
        self.content().matches(metadata)
    }
}

impl fmt::Debug for dyn RuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rule-set {}", self.name())
    }
}

/// Checks the metadata of a rule-set's new content before it replaces the
/// old (sing-box `adapter.DNSRuleSetUpdateValidator`, implemented by the
/// DNS router).
pub type UpdateValidator = dyn Fn(&str, &RuleSetMetadata) -> Result<(), String> + Send + Sync;

/// The rule-sets by tag (sing-box `Router.RuleSet`), and the validator
/// rule-set updates go through.
#[derive(Default)]
pub struct RuleSets {
    sets: HashMap<String, Arc<dyn RuleSet>>,
    order: Vec<String>,
    validator: OnceLock<Box<UpdateValidator>>,
}

impl fmt::Debug for RuleSets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(&self.order).finish()
    }
}

impl RuleSets {
    pub fn new() -> Self {
        RuleSets::default()
    }

    /// Adds a rule-set; a tag can only be used once ("duplicate rule-set tag").
    pub fn insert(&mut self, rule_set: Arc<dyn RuleSet>) -> Result<(), RuleError> {
        let tag = rule_set.name().to_string();
        if self.sets.contains_key(&tag) {
            return Err(RuleError(format!("duplicate rule-set tag: {tag}")));
        }
        self.order.push(tag.clone());
        self.sets.insert(tag, rule_set);
        Ok(())
    }

    pub fn get(&self, tag: &str) -> Option<&Arc<dyn RuleSet>> {
        self.sets.get(tag)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn RuleSet>> {
        self.order.iter().map(|tag| &self.sets[tag])
    }

    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// Installs the update validator (once).
    pub fn set_validator(&self, validator: Box<UpdateValidator>) {
        let _ = self.validator.set(validator);
    }

    /// `validateRuleSetMetadataUpdate`.
    pub fn validate_update(&self, tag: &str, metadata: &RuleSetMetadata) -> Result<(), String> {
        match self.validator.get() {
            Some(validator) => validator(tag, metadata),
            None => Ok(()),
        }
    }
}

/// The `rule_set` item of route and DNS rules (sing-box `RuleSetItem`).
#[derive(Debug)]
pub struct RuleSetItem {
    tags: Vec<String>,
    sets: Vec<Arc<dyn RuleSet>>,
    ip_cidr_match_source: bool,
    ip_cidr_accept_empty: bool,
}

impl RuleSetItem {
    /// `NewRuleSetItem` and `Start`: the rule-sets are looked up now.
    pub fn new(
        rule_sets: &RuleSets,
        tags: &[String],
        ip_cidr_match_source: bool,
        ip_cidr_accept_empty: bool,
    ) -> Result<Self, RuleError> {
        let sets = tags
            .iter()
            .map(|tag| rule_sets.get(tag).cloned().ok_or_else(|| RuleError(format!("rule-set not found: {tag}"))))
            .collect::<Result<_, _>>()?;
        Ok(RuleSetItem { tags: tags.to_vec(), sets, ip_cidr_match_source, ip_cidr_accept_empty })
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    fn prepare_nested_match(&self, metadata: &mut Metadata) {
        metadata.reset_rule_match_cache();
        metadata.ip_cidr_match_source = self.ip_cidr_match_source;
        metadata.ip_cidr_accept_empty = self.ip_cidr_accept_empty;
    }

    /// `RuleSetItem.Match`.
    pub fn matches(&self, metadata: &mut Metadata) -> bool {
        let snapshot = metadata.snapshot();
        for set in &self.sets {
            self.prepare_nested_match(metadata);
            if set.matches(metadata) {
                metadata.restore(snapshot);
                return true;
            }
        }
        metadata.restore(snapshot);
        false
    }

    /// `matchWithOuterGroups`.
    pub(crate) fn match_with_outer_groups(&self, metadata: &mut Metadata, outer: GroupMatch) -> bool {
        let outer_done = outer.done();
        let mut matched = false;
        let mut deferred = 0u8;
        let snapshot = metadata.snapshot();
        for set in &self.sets {
            self.prepare_nested_match(metadata);
            let content = set.content();
            if let Some(branch) = content.mergeable() {
                if let Some(branch_groups) = branch.evaluate_for_merge(metadata) {
                    let merged = outer.merge(branch_groups);
                    if merged.done() {
                        let branch_deferred = metadata.deferred_ip_cidr_match_groups & !merged.satisfied;
                        if branch_deferred == 0 {
                            metadata.restore(snapshot);
                            metadata.deferred_ip_cidr_match_groups &= !merged.satisfied;
                            return true;
                        }
                        matched = true;
                        deferred |= branch_deferred;
                    }
                }
                continue;
            }
            if outer_done && content.matches(metadata) {
                if metadata.deferred_ip_cidr_match_groups == 0 {
                    metadata.restore(snapshot);
                    return true;
                }
                matched = true;
                deferred |= metadata.deferred_ip_cidr_match_groups;
            }
        }
        metadata.restore(snapshot);
        if matched {
            metadata.deferred_ip_cidr_match_groups |= deferred;
        }
        matched
    }

    /// `ContainsDestinationIPCIDRRule`.
    pub fn contains_destination_ip_cidr_rule(&self) -> bool {
        !self.ip_cidr_match_source && self.sets.iter().any(|set| set.metadata().contains_ip_cidr_rule)
    }
}

/// A rule-set whose rules never change (used by tests and the
/// `rule-set match` command).
pub struct StaticRuleSet {
    pub tag: String,
    pub content: Arc<RuleSetContent>,
}

impl RuleSet for StaticRuleSet {
    fn name(&self) -> &str {
        &self.tag
    }

    fn content(&self) -> Arc<RuleSetContent> {
        self.content.clone()
    }
}
