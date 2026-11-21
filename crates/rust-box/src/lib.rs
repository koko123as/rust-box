//! The box: builds every part from the options and runs them, mirroring
//! sing-box `box.go` (`New`, `Start`, `Close`).
//!
//! Build order follows the dependencies: DNS first, then outbounds (which
//! resolve through DNS), then the router (which holds the outbounds), then
//! inbounds (which hand connections to the router). Start runs in the same
//! order and close in reverse, like sing-box's start stages.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rb_adapter::{ConnectionRouter, DnsResolver, Inbound, InboundRegistry, Outbound, OutboundRegistry};
use rb_config::{Inbound as InboundOptions, Options, Outbound as OutboundOptions};
use rb_dialer::NetworkDefaults;
use rb_dns::DnsRouter;
use rb_protocol::{Block, Direct, ProxyInbound, ProxyKind};
use rb_route::Router;
use tracing::info;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct RustBox {
    inbounds: Vec<Arc<dyn Inbound>>,
    pub router: Arc<Router>,
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
        let dns: Arc<dyn DnsResolver> =
            Arc::new(DnsRouter::new(&options.dns, &defaults, &outbound_registry).context("initialize DNS")?);
        let default_resolver = options.route.default_domain_resolver.as_ref();
        let mut outbounds: Vec<Arc<dyn Outbound>> = Vec::new();
        for (index, outbound) in options.outbounds.iter().enumerate() {
            let tag = if outbound.tag().is_empty() { index.to_string() } else { outbound.tag().to_string() };
            outbounds.push(match outbound {
                OutboundOptions::Direct(direct) => Arc::new(
                    Direct::new(direct, tag, dns.clone(), default_resolver, &defaults)
                        .map_err(|error| anyhow!("outbounds[{index}]: {error}"))?,
                ),
                OutboundOptions::Block(_) => Arc::new(Block::new(tag)),
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
            Router::new(&options.route, outbounds, dns, inbound_registry.clone()).context("initialize router")?,
        );
        let connection_router: Arc<dyn ConnectionRouter> = router.clone();
        let mut inbounds: Vec<Arc<dyn Inbound>> = Vec::new();
        for (index, inbound) in options.inbounds.iter().enumerate() {
            let tag = if inbound.tag().is_empty() { index.to_string() } else { inbound.tag().to_string() };
            let (kind, proxy) = match inbound {
                InboundOptions::Mixed(proxy) => (ProxyKind::Mixed, proxy),
                InboundOptions::Socks(proxy) => (ProxyKind::Socks, proxy),
                InboundOptions::Http(proxy) => (ProxyKind::Http, proxy),
            };
            let inbound = ProxyInbound::new(kind, proxy, tag, connection_router.clone())
                .map_err(|error| anyhow!("inbounds[{index}]: {error}"))?;
            inbounds.push(Arc::new(inbound));
        }
        inbound_registry.set(&inbounds);
        Ok(RustBox { inbounds, router })
    }

    pub async fn start(&self) -> Result<()> {
        for inbound in &self.inbounds {
            inbound
                .clone()
                .start()
                .await
                .with_context(|| format!("start inbound/{}[{}]", inbound.kind(), inbound.tag()))?;
        }
        info!("rust-box started");
        Ok(())
    }

    pub async fn close(&self) {
        for inbound in self.inbounds.iter().rev() {
            inbound.close().await;
        }
    }

    pub fn inbounds(&self) -> &[Arc<dyn Inbound>] {
        &self.inbounds
    }
}
