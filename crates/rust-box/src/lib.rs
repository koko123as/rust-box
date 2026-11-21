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
use rb_adapter::{ConnectionRouter, DnsResolver, Inbound, InboundRegistry, Outbound, OutboundRegistry};
use rb_config::{Inbound as InboundOptions, Options, Outbound as OutboundOptions};
use rb_dialer::{DialerEnv, NetworkDefaults};
use rb_dns::DnsRouter;
use rb_protocol::{
    Block, Direct, HttpOutbound, ProxyInbound, ProxyKind, ShadowsocksInbound, ShadowsocksOutbound, SocksOutbound,
    TrojanInbound, TrojanOutbound,
};
use rb_route::Router;
use rb_rule::{RuleSet, RuleSets};
use rb_rule_set::{Env as RuleSetEnv, ManagedRuleSet, Updater};
use tracing::info;

/// How many rule-sets start at once (sing-box runs them in a task group
/// with concurrency 5).
const RULE_SET_START_CONCURRENCY: usize = 5;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct RustBox {
    inbounds: Vec<Arc<dyn Inbound>>,
    pub router: Arc<Router>,
    pub dns: Arc<DnsRouter>,
    certificates: Arc<rb_certificate::Store>,
    rule_sets: Arc<RuleSets>,
    managed_rule_sets: Vec<Arc<ManagedRuleSet>>,
    rule_set_env: RuleSetEnv,
    updater: Mutex<Option<Updater>>,
}

impl RustBox {
    pub fn new(options: &Options) -> Result<Self> {
        // Dial defaults from the route section (sing-box's network manager).
        let defaults = NetworkDefaults {
            default_interface: options.route.default_interface.clone(),
            default_mark: options.route.default_mark.0,
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
        let rule_set_env = RuleSetEnv {
            certificates: certificates.clone(),
            outbounds: outbound_registry.clone(),
            default_outbound,
            validator: Arc::default(),
        };
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
        let dns_router = Arc::new(
            DnsRouter::new(&options.dns, &defaults, &outbound_registry, &rule_sets).context("initialize DNS")?,
        );
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
            outbounds.push(match outbound {
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
                OutboundOptions::Shadowsocks(shadowsocks) => Arc::new(
                    ShadowsocksOutbound::new(shadowsocks, tag, &dialer_env)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?,
                ),
                OutboundOptions::Trojan(trojan) => Arc::new(
                    TrojanOutbound::new(trojan, tag, &dialer_env, &certificates)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?,
                ),
                OutboundOptions::Vless(_) => {
                    return Err(anyhow!("outbounds[{index}]: not supported by rust-box yet"));
                }
            });
        }
        if outbounds.is_empty() {
            // sing-box adds a default direct outbound when none is configured.
            outbounds.push(Arc::new(
                Direct::new(&Default::default(), "direct".into(), dns.clone(), default_resolver, &defaults)
                    .map_err(|error| anyhow!("default outbound: {error}"))?,
            ));
        }
        outbound_registry.set(&outbounds);
        let router = Arc::new(
            Router::new(&options.route, outbounds, dns, inbound_registry.clone(), &rule_sets)
                .context("initialize router")?,
        );
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
                InboundOptions::Vless(_) => {
                    return Err(anyhow!("inbounds[{index}]: not supported by rust-box yet"));
                }
            };
            inbounds.push(built);
        }
        inbound_registry.set(&inbounds);
        Ok(RustBox {
            inbounds,
            router,
            dns: dns_router,
            certificates,
            rule_sets,
            managed_rule_sets,
            rule_set_env,
            updater: Mutex::new(None),
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
        self.certificates.start().map_err(|error| anyhow!("start certificate store: {error}"))?;
        self.start_rule_sets().await.context("start router")?;
        self.dns.start(&self.rule_sets).context("start dns-router")?;
        for inbound in &self.inbounds {
            inbound
                .clone()
                .start()
                .await
                .with_context(|| format!("start inbound/{}[{}]", inbound.kind(), inbound.tag()))?;
        }
        *self.updater.lock().unwrap() = Updater::start(self.managed_rule_sets.clone());
        info!("rust-box started");
        Ok(())
    }

    pub async fn close(&self) {
        if let Some(updater) = self.updater.lock().unwrap().take() {
            updater.close();
        }
        self.dns.close();
        for inbound in self.inbounds.iter().rev() {
            inbound.close().await;
        }
        for rule_set in &self.managed_rule_sets {
            rule_set.close();
        }
        self.certificates.close();
    }

    pub fn rule_sets(&self) -> &RuleSets {
        &self.rule_sets
    }

    pub fn inbounds(&self) -> &[Arc<dyn Inbound>] {
        &self.inbounds
    }
}
