//! The box: builds every part from the options and runs them, mirroring
//! sing-box `box.go` (`New`, `Start`, `Close`).
//!
//! Build order follows the dependencies: DNS first, then outbounds (which
//! resolve through DNS), then the router (which holds the outbounds), then
//! inbounds (which hand connections to the router). Start runs in the same
//! order and close in reverse, like sing-box's start stages.

use std::sync::Arc;

use anyhow::{Context, Result};
use rb_adapter::{ConnectionRouter, DnsResolver, Inbound, Outbound};
use rb_config::{Inbound as InboundOptions, Options, Outbound as OutboundOptions};
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
        let dns: Arc<dyn DnsResolver> = Arc::new(DnsRouter::new(&options.dns).context("initialize DNS")?);
        let default_resolver = options.route.default_domain_resolver.as_ref();
        let mut outbounds: Vec<Arc<dyn Outbound>> = Vec::new();
        for (index, outbound) in options.outbounds.iter().enumerate() {
            let tag = if outbound.tag().is_empty() { index.to_string() } else { outbound.tag().to_string() };
            outbounds.push(match outbound {
                OutboundOptions::Direct(direct) => Arc::new(Direct::new(direct, tag, dns.clone(), default_resolver)),
                OutboundOptions::Block(_) => Arc::new(Block::new(tag)),
            });
        }
        if outbounds.is_empty() {
            // sing-box adds a default direct outbound when none is configured.
            outbounds.push(Arc::new(Direct::new(&Default::default(), "direct".into(), dns.clone(), default_resolver)));
        }
        let router = Arc::new(Router::new(&options.route, outbounds, dns).context("initialize router")?);
        let connection_router: Arc<dyn ConnectionRouter> = router.clone();
        let inbounds = options
            .inbounds
            .iter()
            .enumerate()
            .map(|(index, inbound)| {
                let tag = if inbound.tag().is_empty() { index.to_string() } else { inbound.tag().to_string() };
                let (kind, proxy) = match inbound {
                    InboundOptions::Mixed(proxy) => (ProxyKind::Mixed, proxy),
                    InboundOptions::Socks(proxy) => (ProxyKind::Socks, proxy),
                    InboundOptions::Http(proxy) => (ProxyKind::Http, proxy),
                };
                Arc::new(ProxyInbound::new(kind, proxy, tag, connection_router.clone())) as Arc<dyn Inbound>
            })
            .collect();
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
