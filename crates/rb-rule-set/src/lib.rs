//! Rule-sets, mirroring sing-box `route/rule/rule_set_local.go`,
//! `rule_set_remote.go` and `rule_set_updater.go`: inline rule-sets, local
//! files (reloaded when they change) and remote ones (downloaded at start,
//! then every `update_interval` with `If-None-Match`).

pub mod http;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime};

use rb_adapter::OutboundRegistry;
use rb_config::rule_set::{FORMAT_BINARY, FORMAT_SOURCE, TAG_PLACEHOLDER};
use rb_config::{HeadlessRule, PlainRuleSetCompat, RuleSetKind, RuleSetOptions};
use rb_dialer::DetourDialer;
use rb_rule::{Context, RuleSet, RuleSetContent, RuleSetMetadata, RuleSets, UpdateValidator};

/// Remote rule-sets update once a day by default.
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long one download may take (sing-box `C.StartTimeout` bounds the
/// start; the Go client itself has no timeout).
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub struct RuleSetError(pub String);

impl std::fmt::Display for RuleSetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RuleSetError {}

fn error(message: impl Into<String>) -> RuleSetError {
    RuleSetError(message.into())
}

/// The check a rule-set's new content goes through before it is used
/// (sing-box `validateRuleSetMetadataUpdate`); installed once the DNS
/// router exists.
pub type ValidatorSlot = Arc<OnceLock<Box<UpdateValidator>>>;

/// What rule-sets need from the box.
#[derive(Clone)]
pub struct Env {
    pub certificates: Arc<rb_certificate::Store>,
    pub outbounds: Arc<OutboundRegistry>,
    /// The outbound remote rule-sets download through when they name no
    /// `download_detour` (sing-box's implicit default HTTP client).
    pub default_outbound: String,
    pub validator: ValidatorSlot,
}

/// Parses rule-set content in `format` (`loadBytes` / `reloadFile`).
pub fn parse_content(format: &str, content: &[u8]) -> Result<Vec<HeadlessRule>, RuleSetError> {
    let compat = match format {
        FORMAT_SOURCE | "" => PlainRuleSetCompat::parse(content).map_err(error)?,
        FORMAT_BINARY => rb_config::srs::read(content, false).map_err(|e| error(e.0))?,
        other => return Err(error(format!("unknown rule-set format: {other}"))),
    };
    Ok(compat.upgrade().map_err(error)?.rules)
}

enum Source {
    Inline,
    Local { path: PathBuf, format: String, watcher: Mutex<Option<rb_fswatch::Watcher>> },
    Remote(Remote),
}

struct Remote {
    url: String,
    initial_path: Option<PathBuf>,
    format: String,
    update_interval: Duration,
    download_detour: String,
    state: Mutex<RemoteState>,
}

#[derive(Default)]
struct RemoteState {
    last_updated: Option<SystemTime>,
    last_etag: Option<String>,
    client: Option<http::Client>,
}

/// A rule-set of any type.
pub struct ManagedRuleSet {
    tag: String,
    content: RwLock<Arc<RuleSetContent>>,
    source: Source,
    validator: ValidatorSlot,
}

impl RuleSet for ManagedRuleSet {
    fn name(&self) -> &str {
        &self.tag
    }

    fn content(&self) -> Arc<RuleSetContent> {
        self.content.read().unwrap().clone()
    }
}

fn compile(rules: &[HeadlessRule]) -> Result<RuleSetContent, RuleSetError> {
    // Headless rules hold no rule-set items, so no rule-sets are needed.
    let rule_sets = RuleSets::new();
    RuleSetContent::compile(rules, &Context::new(&rule_sets)).map_err(|e| error(e.0))
}

impl ManagedRuleSet {
    /// `NewRuleSet`: inline rule-sets are compiled and local files loaded
    /// now; remote ones start empty.
    pub fn new(options: &RuleSetOptions, tag: &str, env: &Env) -> Result<Arc<Self>, RuleSetError> {
        let (source, content) = match &options.kind {
            RuleSetKind::Inline { rules } => {
                if rules.is_empty() {
                    return Err(error("empty inline rule-set"));
                }
                (Source::Inline, compile(rules)?)
            }
            RuleSetKind::Local { path } => {
                let path = std::path::absolute(path.replace(TAG_PLACEHOLDER, tag)).map_err(|e| error(e.to_string()))?;
                let content = load_file(&path, &options.format)?;
                (Source::Local { path, format: options.format.clone(), watcher: Mutex::new(None) }, content)
            }
            RuleSetKind::Remote(remote) => {
                let initial_path = (!remote.initial_path.is_empty())
                    .then(|| std::path::absolute(remote.initial_path.replace(TAG_PLACEHOLDER, tag)).ok())
                    .flatten();
                let update_interval =
                    if remote.update_interval.0.is_zero() { DEFAULT_UPDATE_INTERVAL } else { remote.update_interval.0 };
                (
                    Source::Remote(Remote {
                        url: remote.url.replace(TAG_PLACEHOLDER, tag),
                        initial_path,
                        format: options.format.clone(),
                        update_interval,
                        download_detour: remote.download_detour.clone(),
                        state: Mutex::new(RemoteState::default()),
                    }),
                    RuleSetContent::default(),
                )
            }
        };
        let rule_set = Arc::new(ManagedRuleSet {
            tag: tag.to_string(),
            content: RwLock::new(Arc::new(content)),
            source,
            validator: env.validator.clone(),
        });
        if let Source::Local { path, format, watcher } = &rule_set.source {
            let weak = Arc::downgrade(&rule_set);
            let format = format.clone();
            let created = rb_fswatch::Watcher::new(rb_fswatch::Options {
                paths: vec![path.clone()],
                direct: false,
                callback: Arc::new(move |path| {
                    let Some(rule_set) = weak.upgrade() else { return };
                    match load_file(path, &format).and_then(|content| rule_set.replace(content)) {
                        Ok(()) => tracing::info!("rule-set {}: reloaded", rule_set.tag),
                        Err(e) => tracing::error!("reload rule-set {}: {e}", rule_set.tag),
                    }
                }),
                wait_timeout: None,
            })
            .map_err(|e| error(e.to_string()))?;
            *watcher.lock().unwrap() = Some(created);
        }
        Ok(rule_set)
    }

    pub fn is_remote(&self) -> bool {
        matches!(self.source, Source::Remote(_))
    }

    /// Swaps in new content once the update validator accepts it.
    fn replace(&self, content: RuleSetContent) -> Result<(), RuleSetError> {
        if let Some(validator) = self.validator.get() {
            validator(&self.tag, &content.metadata()).map_err(error)?;
        }
        *self.content.write().unwrap() = Arc::new(content);
        Ok(())
    }

    /// `StartContext`: local files start being watched; a remote rule-set
    /// loads its initial file or downloads, which must succeed.
    pub async fn start(&self, env: &Env) -> Result<(), RuleSetError> {
        match &self.source {
            Source::Inline => Ok(()),
            Source::Local { watcher, .. } => {
                if let Some(watcher) = watcher.lock().unwrap().as_ref() {
                    if let Err(e) = watcher.start() {
                        tracing::error!("rule-set {}: watch rule-set file: {e}", self.tag);
                    }
                }
                Ok(())
            }
            Source::Remote(remote) => {
                let client =
                    self.client(remote, env).map_err(|e| error(format!("create rule-set http client: {e}")))?;
                remote.state.lock().unwrap().client = Some(client);
                if let Some(path) = &remote.initial_path {
                    let loaded = std::fs::read(path)
                        .map_err(|e| error(e.to_string()))
                        .and_then(|content| parse_content(&remote.format, &content))
                        .and_then(|rules| compile(&rules))
                        .and_then(|content| self.replace(content));
                    match loaded {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            tracing::warn!("rule-set {}: load initial rule-set from {}: {e}", self.tag, path.display())
                        }
                    }
                }
                self.fetch(remote).await.map_err(|e| error(format!("initial rule-set: {}: {e}", self.tag)))
            }
        }
    }

    fn client(&self, remote: &Remote, env: &Env) -> Result<http::Client, String> {
        let detour = if !remote.download_detour.is_empty() {
            rb_config::deprecated::report(rb_config::deprecated::LEGACY_RULE_SET_DOWNLOAD_DETOUR);
            remote.download_detour.clone()
        } else {
            rb_config::deprecated::report(rb_config::deprecated::IMPLICIT_DEFAULT_HTTP_CLIENT);
            env.default_outbound.clone()
        };
        if detour.is_empty() {
            return Err("default http client transport is not initialized".into());
        }
        Ok(http::Client {
            dialer: Arc::new(DetourDialer::new(env.outbounds.clone(), detour)),
            roots: Arc::new(env.certificates.pool().roots().clone()),
            timeout: DOWNLOAD_TIMEOUT,
        })
    }

    /// `fetch`: one download; 304 keeps the content.
    async fn fetch(&self, remote: &Remote) -> Result<(), RuleSetError> {
        tracing::debug!("updating rule-set {} from URL: {}", self.tag, remote.url);
        let (client, etag) = {
            let state = remote.state.lock().unwrap();
            (state.client.clone().ok_or_else(|| error("rule-set not started"))?, state.last_etag.clone())
        };
        let response = client.get(&remote.url, etag.as_deref()).await.map_err(|e| error(e.to_string()))?;
        match response.status {
            200 => {}
            304 => {
                remote.state.lock().unwrap().last_updated = Some(SystemTime::now());
                tracing::info!("update rule-set {}: not modified", self.tag);
                return Ok(());
            }
            _ => return Err(error(format!("unexpected status: {}", response.status_text()))),
        }
        let rules = parse_content(&remote.format, &response.body)?;
        self.replace(compile(&rules)?)?;
        let mut state = remote.state.lock().unwrap();
        if let Some(etag) = response.etag.filter(|etag| !etag.is_empty()) {
            state.last_etag = Some(etag);
        }
        state.last_updated = Some(SystemTime::now());
        tracing::info!("updated rule-set {}", self.tag);
        Ok(())
    }

    /// `updateOnce`.
    pub async fn update_once(&self) {
        if let Source::Remote(remote) = &self.source {
            if let Err(e) = self.fetch(remote).await {
                tracing::error!("fetch rule-set {}: {e}", self.tag);
            }
        }
    }

    /// When the next update is due (`lastUpdated + updateInterval`).
    fn next_update(&self) -> Option<SystemTime> {
        let Source::Remote(remote) = &self.source else { return None };
        let last = remote.state.lock().unwrap().last_updated.unwrap_or(SystemTime::UNIX_EPOCH);
        Some(last + remote.update_interval)
    }

    fn update_interval(&self) -> Duration {
        match &self.source {
            Source::Remote(remote) => remote.update_interval,
            _ => DEFAULT_UPDATE_INTERVAL,
        }
    }

    pub fn close(&self) {
        if let Source::Local { watcher, .. } = &self.source {
            if let Some(watcher) = watcher.lock().unwrap().take() {
                watcher.close();
            }
        }
    }

    pub fn metadata(&self) -> RuleSetMetadata {
        self.content().metadata()
    }
}

fn load_file(path: &std::path::Path, format: &str) -> Result<RuleSetContent, RuleSetError> {
    let content = std::fs::read(path).map_err(|e| error(format!("open {}: {e}", path.display())))?;
    compile(&parse_content(format, &content)?)
}

/// `RuleSetUpdater`: updates every remote rule-set when it is due.
pub struct Updater {
    task: tokio::task::JoinHandle<()>,
}

impl Updater {
    /// `NewRuleSetUpdater` + `Start`; `None` without remote rule-sets.
    pub fn start(rule_sets: Vec<Arc<ManagedRuleSet>>) -> Option<Updater> {
        let remote: Vec<_> = rule_sets.into_iter().filter(|rule_set| rule_set.is_remote()).collect();
        if remote.is_empty() {
            return None;
        }
        let task = tokio::spawn(async move {
            let mut next: Vec<SystemTime> = remote.iter().map(|rule_set| rule_set.next_update().unwrap()).collect();
            loop {
                let now = SystemTime::now();
                for (index, rule_set) in remote.iter().enumerate() {
                    if now < next[index] {
                        continue;
                    }
                    rule_set.update_once().await;
                    next[index] = now + rule_set.update_interval();
                }
                let soonest = next.iter().min().copied().unwrap();
                let wait = soonest.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO);
                tokio::time::sleep(wait).await;
            }
        });
        Some(Updater { task })
    }

    pub fn close(&self) {
        self.task.abort();
    }
}

impl Drop for Updater {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests;
