//! The box: builds every part from the options and runs them, mirroring
//! sing-box `box.go` (`New`, `Start`, `Close`).
//!
//! Build order follows the dependencies: the certificate store, the
//! rule-sets (inline and local ones load now), DNS, then outbounds (which
//! resolve through DNS), then the router (which holds the outbounds and
//! rules referring to rule-sets), then inbounds (which hand connections to
//! the router). Start runs like sing-box's start stages: the certificate
//! store, the rule-sets (remote ones download), the DNS rules (built with
//! the loaded rule-sets), the inbounds, then the rule-set updater; close
//! runs in reverse.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use rb_adapter::{
    ConnectionRouter, ConnectionTracker, DnsResolver, HistoryStorage, Inbound, InboundRegistry, Outbound,
    OutboundRegistry,
};
use rb_cachefile::CacheFile;
use rb_clashapi::{ApiParts, ClashApi, ModeManager, TrafficManager};
use rb_config::{Endpoint as EndpointOptions, Inbound as InboundOptions, Options, Outbound as OutboundOptions};
use rb_dialer::{DialerEnv, NetworkDefaults};
use rb_dns::DnsRouter;
use rb_group::{GroupContext, Selector, UrlTest};
use rb_protocol::{
    Block, Direct, HttpOutbound, Hysteria2Inbound, Hysteria2Outbound, NaiveOutbound, ProxyInbound, ProxyKind,
    ShadowsocksInbound, ShadowsocksOutbound, SocksOutbound, TrojanInbound, TrojanOutbound, TuicInbound, TuicOutbound,
    VlessInbound, VlessOutbound, VmessInbound, VmessOutbound, WireGuardOutbound,
};
use rb_route::{Management, Router};
use rb_rule::{RuleSet, RuleSets};
use rb_rule_set::{Env as RuleSetEnv, ManagedRuleSet, RuleSetCache, SavedRuleSet, Updater};
use tracing::info;

/// How many rule-sets start at once (sing-box runs them in a task group
/// with concurrency 5).
const RULE_SET_START_CONCURRENCY: usize = 5;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The sing-box version whose behaviour rust-box follows (what the Clash
/// API reports with its own).
pub const SING_BOX_VERSION: &str = "1.14.4";

/// The cache file's `rule_set` bucket as remote rule-sets use it.
struct RuleSetStore(Arc<CacheFile>);

impl RuleSetCache for RuleSetStore {
    fn load_rule_set(&self, tag: &str) -> Option<SavedRuleSet> {
        self.0.load_rule_set(tag).map(|saved| SavedRuleSet {
            content: saved.content,
            last_updated: saved.last_updated,
            last_etag: saved.last_etag,
            url_hash: saved.url_hash,
        })
    }

    fn save_rule_set(&self, tag: &str, saved: &SavedRuleSet) -> Result<(), String> {
        let saved = rb_cachefile::SavedBinary {
            content: saved.content.clone(),
            last_updated: saved.last_updated,
            last_etag: saved.last_etag.clone(),
            url_hash: saved.url_hash.clone(),
        };
        self.0.save_rule_set(tag, &saved).map_err(|error| error.to_string())
    }
}

/// A group outbound, started with the others.
enum Group {
    Selector(Arc<Selector>),
    UrlTest(Arc<UrlTest>),
}

pub struct RustBox {
    inbounds: Vec<Arc<dyn Inbound>>,
    endpoints: Vec<Arc<WireGuardOutbound>>,
    pub router: Arc<Router>,
    pub dns: Arc<DnsRouter>,
    certificates: Arc<rb_certificate::Store>,
    rule_sets: Arc<RuleSets>,
    managed_rule_sets: Vec<Arc<ManagedRuleSet>>,
    rule_set_env: RuleSetEnv,
    updater: Mutex<Option<Updater>>,
    outbound_registry: Arc<OutboundRegistry>,
    groups: Vec<Group>,
    cache_file: Option<Arc<CacheFile>>,
    dns_disable_expire: bool,
    mode: Option<Arc<ModeManager>>,
    clash_api: Option<ClashApi>,
}

impl RustBox {
    pub fn new(options: &Options) -> Result<Self> {
        // Dial defaults from the route section (sing-box's network manager).
        let defaults = NetworkDefaults {
            default_interface: options.route.default_interface.clone(),
            default_mark: options.route.default_mark.0,
            auto_detect_interface: options.route.auto_detect_interface,
        };
        defaults.check().map_err(|error| anyhow!("route: {error}"))?;
        // Parts built before the outbounds and inbounds get handles that
        // are filled once those exist (DNS server detours, inbound detours).
        let outbound_registry = OutboundRegistry::new();
        let inbound_registry = InboundRegistry::new();
        let certificates = rb_certificate::Store::new(options.certificate.as_ref())
            .map_err(|error| anyhow!("initialize certificate store: {error}"))?;
        // Remote rule-sets download through `download_detour`, else the
        // default outbound (route.final, else the first outbound).
        let default_outbound = if !options.route.r#final.is_empty() {
            options.route.r#final.clone()
        } else {
            match options.outbounds.first() {
                Some(outbound) if !outbound.tag().is_empty() => outbound.tag().to_string(),
                Some(_) => "0".into(),
                None => "direct".into(),
            }
        };
        let experimental = options.experimental.clone().unwrap_or_default();
        let cache_file = experimental
            .cache_file
            .as_ref()
            .filter(|cache_file| cache_file.enabled)
            .map(|cache_file| Arc::new(CacheFile::new(cache_file)));
        let rule_set_env = RuleSetEnv {
            certificates: certificates.clone(),
            outbounds: outbound_registry.clone(),
            default_outbound,
            validator: Arc::default(),
            cache: Arc::default(),
        };
        if let Some(cache_file) = &cache_file {
            let _ = rule_set_env.cache.set(Arc::new(RuleSetStore(cache_file.clone())));
        }
        let mut rule_sets = RuleSets::new();
        let mut managed_rule_sets = Vec::new();
        for (index, rule_set) in options.route.rule_set.iter().enumerate() {
            for tag in &rule_set.tags {
                if rule_sets.get(tag).is_some() {
                    return Err(anyhow!("initialize router: duplicate rule-set tag: {tag}"));
                }
                let managed = ManagedRuleSet::new(rule_set, tag, &rule_set_env)
                    .map_err(|error| anyhow!("initialize router: parse rule-set[{index}]: {error}"))?;
                rule_sets
                    .insert(managed.clone() as Arc<dyn RuleSet>)
                    .map_err(|error| anyhow!("initialize router: {error}"))?;
                managed_rule_sets.push(managed);
            }
        }
        let rule_sets = Arc::new(rule_sets);
        let dns_router = DnsRouter::new(&options.dns, &defaults, &outbound_registry, &rule_sets, &certificates)
            .context("initialize DNS")?;
        {
            // Rule-set updates go through the DNS router's check.
            let dns = Arc::downgrade(&dns_router);
            let sets = Arc::downgrade(&rule_sets);
            let _ =
                rule_set_env.validator.set(Box::new(move |tag: &str, metadata: &rb_rule::RuleSetMetadata| {
                    match (dns.upgrade(), sets.upgrade()) {
                        (Some(dns), Some(sets)) => dns.validate_rule_set_update(&sets, tag, metadata),
                        _ => Ok(()),
                    }
                }));
        }
        // The Clash mode exists with the Clash API (sing-box creates it with
        // the traffic manager).
        let mode = experimental.clash_api.as_ref().map(|clash_api| {
            let list = rb_config::experimental::clash_mode_list(&options.route.rules, &options.dns.rules);
            Arc::new(ModeManager::new(&clash_api.default_mode, list, Some(dns_router.clone()), cache_file.clone()))
        });
        if let Some(mode) = &mode {
            dns_router.set_clash_mode(mode.clash_mode());
        }
        let history = HistoryStorage::new();
        let group_context =
            GroupContext { cache_file: cache_file.clone(), history: history.clone(), store: certificates.clone() };
        let mut groups = Vec::new();
        let dns: Arc<dyn DnsResolver> = dns_router.clone();
        let default_resolver = options.route.default_domain_resolver.as_ref();
        // What remote proxy outbounds dial their server with.
        let dialer_env = DialerEnv {
            defaults: defaults.clone(),
            outbounds: outbound_registry.clone(),
            dns: dns.clone(),
            default_resolver: default_resolver.cloned(),
        };
        let mut outbounds: Vec<Arc<dyn Outbound>> = Vec::new();
        for (index, outbound) in options.outbounds.iter().enumerate() {
            let tag = if outbound.tag().is_empty() { index.to_string() } else { outbound.tag().to_string() };
            let built: Arc<dyn Outbound> = match outbound {
                OutboundOptions::Direct(direct) => Arc::new(
                    Direct::new(direct, tag, dns.clone(), default_resolver, &defaults)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?,
                ),
                OutboundOptions::Block(_) => Arc::new(Block::new(tag)),
                OutboundOptions::Socks(socks) => Arc::new(
                    SocksOutbound::new(socks, tag, &dialer_env)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?,
                ),
                OutboundOptions::Http(http) => Arc::new(
                    HttpOutbound::new(http, tag, &dialer_env, &certificates)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?,
                ),
                OutboundOptions::Naive(naive) => Arc::new(
                    NaiveOutbound::new(naive, tag, &dialer_env, &certificates)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?,
                ),
                OutboundOptions::Shadowsocks(shadowsocks) => {
                    let built: Arc<dyn Outbound> = ShadowsocksOutbound::new(shadowsocks, tag, &dialer_env)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?;
                    built
                }
                OutboundOptions::Trojan(trojan) => {
                    let built: Arc<dyn Outbound> = TrojanOutbound::new(trojan, tag, &dialer_env, &certificates)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?;
                    built
                }
                OutboundOptions::Vless(vless) => {
                    let built: Arc<dyn Outbound> = VlessOutbound::new(vless, tag, &dialer_env, &certificates)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?;
                    built
                }
                OutboundOptions::Vmess(vmess) => {
                    let built: Arc<dyn Outbound> = VmessOutbound::new(vmess, tag, &dialer_env, &certificates)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?;
                    built
                }
                OutboundOptions::Selector(selector) => {
                    let selector = rb_config::SelectorOutbound { tag: tag.clone(), ..selector.clone() };
                    let built = Arc::new(Selector::new(&selector, group_context.clone()));
                    groups.push(Group::Selector(built.clone()));
                    built
                }
                OutboundOptions::UrlTest(urltest) => {
                    let urltest = rb_config::UrlTestOutbound { tag: tag.clone(), ..urltest.clone() };
                    let built = Arc::new(UrlTest::new(&urltest, group_context.clone()));
                    groups.push(Group::UrlTest(built.clone()));
                    built
                }
                OutboundOptions::Tuic(tuic) => {
                    let built: Arc<dyn Outbound> = TuicOutbound::new(tuic, tag, &dialer_env, &certificates)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?;
                    built
                }
                OutboundOptions::Hysteria2(hysteria2) => {
                    Hysteria2Outbound::new(hysteria2, tag, &dialer_env, &certificates, &format!("outbounds[{index}]"))
                        .map_err(anyhow::Error::msg)?
                }
            };
            outbounds.push(built);
        }
        let mut endpoints: Vec<Arc<WireGuardOutbound>> = Vec::new();
        for (index, endpoint) in options.endpoints.iter().enumerate() {
            let tag = if endpoint.tag().is_empty() { index.to_string() } else { endpoint.tag().to_string() };
            match endpoint {
                EndpointOptions::WireGuard(wireguard) => {
                    let built = Arc::new(
                        WireGuardOutbound::new(wireguard, tag, &dialer_env, &format!("endpoints[{index}]"))
                            .map_err(anyhow::Error::msg)?,
                    );
                    outbounds.push(built.clone() as Arc<dyn Outbound>);
                    endpoints.push(built);
                }
            }
        }
        if outbounds.is_empty() {
            // sing-box adds a default direct outbound when none is configured.
            outbounds.push(Arc::new(
                Direct::new(&Default::default(), "direct".into(), dns.clone(), default_resolver, &defaults)
                    .map_err(|error| anyhow!("default outbound: {error}"))?,
            ));
        }
        outbound_registry.set(&outbounds);
        let all_outbounds = outbounds.clone();
        let router = Arc::new(
            Router::with_clash_mode(
                &options.route,
                outbounds,
                dns,
                inbound_registry.clone(),
                &rule_sets,
                mode.as_ref().map(|mode| mode.clash_mode()),
            )
            .context("initialize router")?,
        );
        for endpoint in &endpoints {
            endpoint.set_router(router.clone());
        }
        let traffic = experimental.clash_api.as_ref().map(|_| TrafficManager::new());
        let trackers: Vec<Arc<dyn ConnectionTracker>> =
            traffic.iter().map(|traffic| Arc::new(traffic.clone()) as Arc<dyn ConnectionTracker>).collect();
        router.set_management(Management { trackers, history: history.clone() });
        let clash_api = match (&experimental.clash_api, traffic, &mode) {
            (Some(clash_api), Some(traffic), Some(mode)) => {
                let log_level = if options.log.level.is_empty() {
                    rb_clashapi::log::LEVEL_INFO
                } else {
                    rb_clashapi::log::parse_level(&options.log.level).unwrap_or(rb_clashapi::log::LEVEL_INFO)
                };
                let parts = ApiParts {
                    options: clash_api.clone(),
                    router: router.clone(),
                    dns: dns_router.clone(),
                    outbounds: all_outbounds,
                    registry: outbound_registry.clone(),
                    traffic,
                    history,
                    mode: mode.clone(),
                    cache_file: cache_file.clone(),
                    store: certificates.clone(),
                    log_level,
                    version: format!("sing-box {SING_BOX_VERSION} (rust-box {VERSION})"),
                };
                Some(ClashApi::new(parts).map_err(|error| anyhow!("create clash-server: {error}"))?)
            }
            _ => None,
        };
        let connection_router: Arc<dyn ConnectionRouter> = router.clone();
        let mut inbounds: Vec<Arc<dyn Inbound>> = Vec::new();
        for (index, inbound) in options.inbounds.iter().enumerate() {
            let tag = if inbound.tag().is_empty() { index.to_string() } else { inbound.tag().to_string() };
            let built: Arc<dyn Inbound> = match inbound {
                InboundOptions::Mixed(proxy) => Arc::new(
                    ProxyInbound::new(ProxyKind::Mixed, proxy, tag, connection_router.clone())
                        .map_err(|error| anyhow!("inbounds[{index}]: {error}"))?,
                ),
                InboundOptions::Socks(proxy) => Arc::new(
                    ProxyInbound::new(ProxyKind::Socks, proxy, tag, connection_router.clone())
                        .map_err(|error| anyhow!("inbounds[{index}]: {error}"))?,
                ),
                InboundOptions::Http(proxy) => Arc::new(
                    ProxyInbound::new(ProxyKind::Http, proxy, tag, connection_router.clone())
                        .map_err(|error| anyhow!("inbounds[{index}]: {error}"))?,
                ),
                InboundOptions::Shadowsocks(shadowsocks) => Arc::new(
                    ShadowsocksInbound::new(shadowsocks, tag, connection_router.clone())
                        .map_err(|error| anyhow!("inbounds[{index}]: {error}"))?,
                ),
                InboundOptions::Trojan(trojan) => Arc::new(
                    TrojanInbound::new(trojan, tag, connection_router.clone())
                        .map_err(|error| anyhow!("inbounds[{index}]: {error}"))?,
                ),
                InboundOptions::Vless(vless) => Arc::new(
                    VlessInbound::new(vless, tag, connection_router.clone())
                        .map_err(|error| anyhow!("inbounds[{index}]: {error}"))?,
                ),
                InboundOptions::Vmess(vmess) => Arc::new(
                    VmessInbound::new(vmess, tag, connection_router.clone())
                        .map_err(|error| anyhow!("inbounds[{index}]: {error}"))?,
                ),
                InboundOptions::Tun(tun) => Arc::new(
                    rb_tun::TunInbound::new(tun, tag, router.clone(), dns_router.clone())
                        .map_err(|error| anyhow!("inbounds[{index}]: {error}"))?,
                ),
                InboundOptions::Tuic(tuic) => Arc::new(
                    TuicInbound::new(tuic, tag, connection_router.clone())
                        .map_err(|error| anyhow!("inbounds[{index}]: {error}"))?,
                ),
                InboundOptions::Hysteria2(hysteria2) => Arc::new(
                    Hysteria2Inbound::new(hysteria2, tag, connection_router.clone())
                        .map_err(|error| anyhow!("inbounds[{index}]: {error}"))?,
                ),
            };
            inbounds.push(built);
        }
        inbound_registry.set(&inbounds);
        Ok(RustBox {
            inbounds,
            endpoints,
            router,
            dns: dns_router,
            certificates,
            rule_sets,
            managed_rule_sets,
            rule_set_env,
            updater: Mutex::new(None),
            outbound_registry,
            groups,
            cache_file,
            dns_disable_expire: options.dns.disable_expire,
            mode,
            clash_api,
        })
    }

    /// Starts the rule-sets: local files start being watched, remote ones
    /// download (at most five at once; the first failure stops the start).
    async fn start_rule_sets(&self) -> Result<()> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(RULE_SET_START_CONCURRENCY));
        let mut tasks = tokio::task::JoinSet::new();
        for (index, rule_set) in self.managed_rule_sets.iter().enumerate() {
            let (rule_set, env, semaphore) = (rule_set.clone(), self.rule_set_env.clone(), semaphore.clone());
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await;
                rule_set.start(&env).await.map_err(|error| anyhow!("initialize rule-set[{index}]: {error}"))
            });
        }
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result.map_err(|error| anyhow!("{error}"))? {
                tasks.abort_all();
                return Err(error);
            }
        }
        Ok(())
    }

    pub async fn start(&self) -> Result<()> {
        if let Some(cache_file) = &self.cache_file {
            cache_file.open().map_err(|error| anyhow!("start cache-file: {error}"))?;
            cache_file.set_disable_expire(self.dns_disable_expire);
            cache_file.start();
            let storage = rb_dns::DnsStorage {
                fakeip: cache_file.store_fakeip().then(|| cache_file.clone() as Arc<dyn rb_dns::FakeIpStorage>),
                rdrc: cache_file.store_rdrc().then(|| cache_file.clone() as Arc<dyn rb_dns::RdrcStore>),
                dns_cache: cache_file.store_dns().then(|| cache_file.clone() as Arc<dyn rb_dns::DnsCacheStore>),
            };
            self.dns.set_storage(storage);
        }
        self.certificates.start().map_err(|error| anyhow!("start certificate store: {error}"))?;
        let lookup = |tag: &str| self.outbound_registry.get(tag).ok();
        for group in &self.groups {
            match group {
                Group::Selector(selector) => selector.start(&lookup),
                Group::UrlTest(urltest) => urltest.start(&lookup),
            }
            .map_err(|error| anyhow!("start outbound: {error}"))?;
        }
        if let Some(mode) = &self.mode {
            mode.start();
        }
        self.start_rule_sets().await.context("start router")?;
        self.dns.start(&self.rule_sets).context("start dns-router")?;
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            if let Err(error) = endpoint.start_stack().await {
                for started in self.endpoints[..index].iter().rev() {
                    started.close();
                }
                return Err(anyhow!("start endpoint/wireguard[{}]: {error}", endpoint.tag()));
            }
        }
        for endpoint in &self.endpoints {
            if let Err(error) = endpoint.start_transports().await {
                for started in self.endpoints.iter().rev() {
                    started.close();
                }
                return Err(anyhow!("start endpoint/wireguard[{}]: {error}", endpoint.tag()));
            }
        }
        for inbound in &self.inbounds {
            inbound
                .clone()
                .start()
                .await
                .with_context(|| format!("start inbound/{}[{}]", inbound.kind(), inbound.tag()))?;
        }
        *self.updater.lock().unwrap() = Updater::start(self.managed_rule_sets.clone());
        for group in &self.groups {
            if let Group::UrlTest(urltest) = group {
                urltest.post_start();
            }
        }
        if let Some(clash_api) = &self.clash_api {
            clash_api.start().await.map_err(|error| anyhow!("start clash-server: {error}"))?;
        }
        info!("rust-box started");
        Ok(())
    }

    pub async fn close(&self) {
        if let Some(clash_api) = &self.clash_api {
            clash_api.close();
        }
        for group in &self.groups {
            if let Group::UrlTest(urltest) = group {
                urltest.close();
            }
        }
        if let Some(updater) = self.updater.lock().unwrap().take() {
            updater.close();
        }
        self.dns.close();
        for inbound in self.inbounds.iter().rev() {
            inbound.close().await;
        }
        for endpoint in self.endpoints.iter().rev() {
            endpoint.close();
        }
        for rule_set in &self.managed_rule_sets {
            rule_set.close();
        }
        self.certificates.close();
        if let Some(cache_file) = &self.cache_file {
            cache_file.close();
        }
    }

    pub fn rule_sets(&self) -> &RuleSets {
        &self.rule_sets
    }

    pub fn inbounds(&self) -> &[Arc<dyn Inbound>] {
        &self.inbounds
    }
}
