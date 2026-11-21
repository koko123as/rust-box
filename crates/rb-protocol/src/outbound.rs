//! The `direct` outbound (sing-box `protocol/direct/outbound.go`) and the
//! legacy `block` outbound (`protocol/block`).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{BoxStream, DnsResolver, Host, InboundContext, LookupOptions, Outbound};
use rb_config::{DirectOutbound, DomainResolveOptions};
use tokio::net::TcpStream;
use tracing::debug;

/// sing-box `C.TCPConnectTimeout`.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Direct {
    tag: String,
    dns: Arc<dyn DnsResolver>,
    resolve: LookupOptions,
    connect_timeout: Duration,
}

impl Direct {
    /// `default_resolver` is `route.default_domain_resolver`, used when the
    /// outbound has no `domain_resolver` of its own.
    pub fn new(
        options: &DirectOutbound,
        tag: String,
        dns: Arc<dyn DnsResolver>,
        default_resolver: Option<&DomainResolveOptions>,
    ) -> Self {
        let resolver = options.domain_resolver.as_ref().or(default_resolver);
        let resolve = match resolver {
            Some(resolver) => LookupOptions {
                server: Some(resolver.server.clone()),
                strategy: resolver.strategy,
                disable_cache: resolver.disable_cache,
                timeout: (!resolver.timeout.0.is_zero()).then_some(resolver.timeout.0),
                inbound: None,
            },
            None => LookupOptions::default(),
        };
        let connect_timeout =
            if options.connect_timeout.0.is_zero() { DEFAULT_CONNECT_TIMEOUT } else { options.connect_timeout.0 };
        Direct { tag, dns, resolve, connect_timeout }
    }
}

#[async_trait]
impl Outbound for Direct {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "direct"
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        let destination = &context.destination;
        let addresses: Vec<IpAddr> = match &destination.host {
            Host::Ip(ip) => vec![*ip],
            Host::Domain(_) if !context.destination_addresses.is_empty() => context.destination_addresses.clone(),
            Host::Domain(domain) => {
                let options = LookupOptions { inbound: Some(context.inbound.clone()), ..self.resolve.clone() };
                self.dns.lookup(domain, &options).await?
            }
        };
        // Addresses in the order the strategy left them, one after another
        // (sing-box dials them with a fallback delay; parallel dialing is a
        // later step).
        let mut last_error = io::Error::new(io::ErrorKind::NotFound, format!("{destination}: no addresses"));
        for address in addresses {
            let target = SocketAddr::new(address, destination.port);
            match tokio::time::timeout(self.connect_timeout, TcpStream::connect(target)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    debug!(%target, "direct: connected");
                    return Ok(Box::new(stream));
                }
                Ok(Err(error)) => last_error = io::Error::new(error.kind(), format!("{target}: {error}")),
                Err(_) => last_error = io::Error::new(io::ErrorKind::TimedOut, format!("{target}: connect timed out")),
            }
        }
        Err(last_error)
    }
}

/// Refuses every connection.
pub struct Block {
    tag: String,
}

impl Block {
    pub fn new(tag: String) -> Self {
        Block { tag }
    }
}

#[async_trait]
impl Outbound for Block {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "block"
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{}: blocked", context.destination)))
    }
}
