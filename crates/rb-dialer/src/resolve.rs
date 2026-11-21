//! The dialer of a remote proxy outbound (sing-box `dialer.New` with
//! `RemoteIsDomain`): the detour or default dialer from the dial fields,
//! behind a resolving layer when the server is a domain (sing-box
//! `resolveDialer`).
//!
//! As in sing-box, the resolving layer is left out when the dial fields
//! name a `detour` and no `domain_resolver`: the detour outbound gets the
//! domain itself. Lookups go through `domain_resolver`, else
//! `route.default_domain_resolver`, else the DNS rules (sing-box: the
//! default transport when there is at most one DNS server, else the rules
//! with a deprecation warning). Resolved addresses are dialed in parallel
//! (happy eyeballs, `fallback_delay`) unless there is a `detour` or
//! `tcp_fast_open`, then one after another.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{
    BoxStream, DnsResolver, Host, LookupOptions, OutboundRegistry, PacketConn, SharedPacketConn, Socksaddr,
};
use rb_config::{DialerOptions, DomainResolveOptions, DomainStrategy};
use tracing::warn;

use crate::{dial_parallel, dial_serial, new_dialer, Dialer, NetworkDefaults};

/// Lookup options from a `domain_resolver` object.
pub fn resolve_options(resolver: &DomainResolveOptions) -> LookupOptions {
    LookupOptions {
        server: Some(resolver.server.clone()),
        strategy: resolver.strategy,
        disable_cache: resolver.disable_cache,
        timeout: (!resolver.timeout.0.is_zero()).then_some(resolver.timeout.0),
        rewrite_ttl: resolver.rewrite_ttl,
        ..Default::default()
    }
}

/// The lookup options of an object's dial fields (sing-box
/// `NewDNSQueryOptions` plus the deprecated `domain_strategy`): its own
/// `domain_resolver`, else `default_resolver`, else the DNS rules.
/// `owner` names the object in the deprecation warning.
pub fn lookup_options(
    options: &DialerOptions,
    default_resolver: Option<&DomainResolveOptions>,
    owner: &str,
) -> LookupOptions {
    let own = options.domain_resolver.as_ref().filter(|resolver| !resolver.server.is_empty());
    let mut lookup = match own.or(default_resolver) {
        Some(resolver) => resolve_options(resolver),
        None => LookupOptions::default(),
    };
    // The deprecated `domain_strategy` still sets the strategy when the
    // resolver has none (sing-box `dialer.NewWithOptions`).
    if options.domain_strategy != DomainStrategy::AsIs
        && own.is_none_or(|resolver| resolver.strategy == DomainStrategy::AsIs)
    {
        warn!("{owner}: `domain_strategy` is deprecated in sing-box 1.12.0, use `domain_resolver` instead");
        lookup.strategy = options.domain_strategy;
    }
    lookup
}

/// What an outbound's dialer is built with (the parts sing-box finds in
/// its context).
#[derive(Clone)]
pub struct DialerEnv {
    pub defaults: NetworkDefaults,
    pub outbounds: Arc<OutboundRegistry>,
    pub dns: Arc<dyn DnsResolver>,
    /// `route.default_domain_resolver`.
    pub default_resolver: Option<DomainResolveOptions>,
}

/// sing-box `dialer.New(ctx, options, remoteIsDomain)` for a remote proxy
/// outbound. `owner` (such as `outbound/socks[proxy]`) names it in
/// warnings.
pub fn new_outbound_dialer(
    options: &DialerOptions,
    remote_is_domain: bool,
    env: &DialerEnv,
    owner: &str,
) -> Result<Arc<dyn Dialer>, String> {
    // sing-box's UDPFragmentDefault is only set for direct.
    let dialer = new_dialer(options, &env.defaults, &env.outbounds, false)?;
    let has_resolver = options.domain_resolver.as_ref().is_some_and(|resolver| !resolver.server.is_empty());
    if !remote_is_domain || (!options.detour.is_empty() && !has_resolver) {
        return Ok(dialer);
    }
    Ok(Arc::new(ResolveDialer {
        dialer,
        dns: env.dns.clone(),
        lookup: lookup_options(options, env.default_resolver.as_ref(), owner),
        parallel: options.detour.is_empty() && !options.tcp_fast_open,
        fallback_delay: options.fallback_delay.0,
    }))
}

/// Resolves domain destinations, then dials their addresses through the
/// inner dialer (sing-box `resolveDialer`).
pub struct ResolveDialer {
    dialer: Arc<dyn Dialer>,
    dns: Arc<dyn DnsResolver>,
    lookup: LookupOptions,
    parallel: bool,
    fallback_delay: Duration,
}

impl ResolveDialer {
    pub fn new(
        dialer: Arc<dyn Dialer>,
        dns: Arc<dyn DnsResolver>,
        lookup: LookupOptions,
        parallel: bool,
        fallback_delay: Duration,
    ) -> Self {
        ResolveDialer { dialer, dns, lookup, parallel, fallback_delay }
    }

    async fn resolve(&self, domain: &str, destination: &Socksaddr) -> io::Result<Vec<IpAddr>> {
        let addresses = self.dns.lookup(domain, &self.lookup).await?;
        if addresses.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("{destination}: no addresses")));
        }
        Ok(addresses)
    }
}

#[async_trait]
impl Dialer for ResolveDialer {
    async fn dial_tcp(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let Host::Domain(domain) = &destination.host else { return self.dialer.dial_tcp(destination).await };
        let addresses = self.resolve(domain, destination).await?;
        let port = destination.port;
        let connect = |address: IpAddr| {
            let target = Socksaddr::new(Host::Ip(address), port);
            async move { self.dialer.dial_tcp(&target).await }
        };
        if self.parallel {
            dial_parallel(&addresses, addresses[0].is_ipv6(), self.fallback_delay, &connect).await
        } else {
            dial_serial(&addresses, &connect).await
        }
    }

    async fn dial_udp(&self, destination: &Socksaddr) -> io::Result<SharedPacketConn> {
        let Host::Domain(domain) = &destination.host else { return self.dialer.dial_udp(destination).await };
        let addresses = self.resolve(domain, destination).await?;
        let port = destination.port;
        let connect = |address: IpAddr| {
            let target = Socksaddr::new(Host::Ip(address), port);
            async move { self.dialer.dial_udp(&target).await }
        };
        dial_serial(&addresses, &connect).await
    }

    /// sing `N.ListenSerial` and `bufio.NewNATPacketConn`: packets to the
    /// domain go to the resolved address, replies from it come back as
    /// the domain.
    async fn listen_packet(&self, destination: &Socksaddr) -> io::Result<SharedPacketConn> {
        let Host::Domain(domain) = &destination.host else { return self.dialer.listen_packet(destination).await };
        let addresses = self.resolve(domain, destination).await?;
        let port = destination.port;
        let found: Mutex<Option<IpAddr>> = Mutex::new(None);
        let connect = |address: IpAddr| {
            let target = Socksaddr::new(Host::Ip(address), port);
            let found = &found;
            async move {
                let conn = self.dialer.listen_packet(&target).await?;
                *found.lock().unwrap() = Some(address);
                Ok(conn)
            }
        };
        let conn = dial_serial(&addresses, &connect).await?;
        let address = found.lock().unwrap().expect("connected address");
        let resolved = Socksaddr::new(Host::Ip(address), port);
        Ok(Arc::new(NatPacketConn {
            inner: conn,
            to_resolved: HashMap::from([(destination.clone(), resolved.clone())]),
            to_domain: HashMap::from([(resolved, destination.clone())]),
        }))
    }
}

/// Maps one destination to another and replies back (sing
/// `bufio.NATPacketConn`).
pub struct NatPacketConn {
    inner: SharedPacketConn,
    to_resolved: HashMap<Socksaddr, Socksaddr>,
    to_domain: HashMap<Socksaddr, Socksaddr>,
}

#[async_trait]
impl PacketConn for NatPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (length, source) = self.inner.read_packet(buffer).await?;
        Ok((length, self.to_domain.get(&source).cloned().unwrap_or(source)))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        self.inner.write_packet(data, self.to_resolved.get(address).unwrap_or(address)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolves every domain to 127.0.0.1 and ::1, recording the options.
    struct Dns(Mutex<Vec<LookupOptions>>);

    #[async_trait]
    impl DnsResolver for Dns {
        async fn lookup(&self, _domain: &str, options: &LookupOptions) -> io::Result<Vec<IpAddr>> {
            self.0.lock().unwrap().push(options.clone());
            Ok(vec!["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()])
        }
    }

    /// Fails IPv6 and records what it was asked to dial.
    struct Recorder(Mutex<Vec<Socksaddr>>);

    #[async_trait]
    impl Dialer for Recorder {
        async fn dial_tcp(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
            self.0.lock().unwrap().push(destination.clone());
            if destination.ip().is_some_and(|ip| ip.is_ipv6()) {
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            }
            Ok(Box::new(tokio::io::empty()))
        }
        async fn dial_udp(&self, _destination: &Socksaddr) -> io::Result<SharedPacketConn> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
        async fn listen_packet(&self, _destination: &Socksaddr) -> io::Result<SharedPacketConn> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    #[tokio::test]
    async fn resolves_domains_only() {
        let recorder = Arc::new(Recorder(Mutex::new(Vec::new())));
        let dns = Arc::new(Dns(Mutex::new(Vec::new())));
        let resolver = DomainResolveOptions { server: "local".into(), ..Default::default() };
        let options = DialerOptions { domain_resolver: Some(resolver), ..Default::default() };
        let lookup = lookup_options(&options, None, "test");
        assert_eq!(lookup.server.as_deref(), Some("local"));
        let dialer = ResolveDialer::new(recorder.clone(), dns.clone(), lookup, true, Duration::from_millis(10));
        dialer.dial_tcp(&Socksaddr::from_host_port("proxy.test", 1080)).await.unwrap();
        let dialed = recorder.0.lock().unwrap().clone();
        assert!(dialed.contains(&Socksaddr::from_host_port("127.0.0.1", 1080)), "{dialed:?}");
        assert_eq!(dns.0.lock().unwrap().len(), 1);
        dialer.dial_tcp(&Socksaddr::from_host_port("10.0.0.1", 1080)).await.unwrap();
        assert_eq!(dns.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn lookup_defaults() {
        let default = DomainResolveOptions { server: "remote".into(), ..Default::default() };
        let lookup = lookup_options(&DialerOptions::default(), Some(&default), "test");
        assert_eq!(lookup.server.as_deref(), Some("remote"));
        let options = DialerOptions { domain_strategy: DomainStrategy::Ipv4Only, ..Default::default() };
        let lookup = lookup_options(&options, None, "test");
        assert_eq!((lookup.server, lookup.strategy), (None, DomainStrategy::Ipv4Only));
    }
}
