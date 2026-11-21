//! Core abstractions, mirroring sing-box `adapter/`.
//!
//! sing-box connects its parts through interfaces in `adapter/` and finds
//! them at run time through a service registry in the context
//! (`sing/service`). rust-box passes the same parts explicitly: an inbound
//! holds the [`ConnectionRouter`], the router holds the outbounds and the
//! [`DnsResolver`], so every dependency shows in a constructor.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use rb_config::DomainStrategy;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A host: a domain name or an IP address (sing-box `M.Socksaddr`'s `Fqdn`/`Addr`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

/// An address with a port, the destination of a connection (sing-box `M.Socksaddr`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Socksaddr {
    pub host: Host,
    pub port: u16,
}

impl Socksaddr {
    pub fn new(host: Host, port: u16) -> Self {
        Socksaddr { host, port }
    }

    /// Parses `host:port`, `[v6]:port` or a bare IP literal host, as
    /// sing-box `M.ParseSocksaddrHostPort` does. Domains are lowercased.
    pub fn from_host_port(host: &str, port: u16) -> Self {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        match host.parse::<IpAddr>() {
            Ok(ip) => Socksaddr::new(Host::Ip(ip.to_canonical()), port),
            Err(_) => Socksaddr::new(Host::Domain(host.trim_end_matches('.').to_ascii_lowercase()), port),
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match &self.host {
            Host::Domain(domain) => Some(domain),
            Host::Ip(_) => None,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self.host {
            Host::Ip(ip) => Some(ip),
            Host::Domain(_) => None,
        }
    }
}

impl From<SocketAddr> for Socksaddr {
    fn from(address: SocketAddr) -> Self {
        Socksaddr::new(Host::Ip(address.ip().to_canonical()), address.port())
    }
}

impl fmt::Display for Socksaddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]:{}", self.port),
            Host::Ip(ip) => write!(f, "{ip}:{}", self.port),
            Host::Domain(domain) => write!(f, "{domain}:{}", self.port),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        }
    }
}

/// What is known about a connection while it is routed (sing-box
/// `adapter.InboundContext`, the fields rust-box uses).
#[derive(Debug, Clone)]
pub struct InboundContext {
    /// Tag of the inbound that accepted it.
    pub inbound: String,
    /// Type of that inbound (`mixed`, `socks`, `http`).
    pub inbound_type: &'static str,
    pub network: Network,
    pub source: SocketAddr,
    pub destination: Socksaddr,
    /// Addresses the destination domain resolved to (`resolve` action), which
    /// IP rules and the direct outbound use.
    pub destination_addresses: Vec<IpAddr>,
    /// The authenticated user, when the inbound has users.
    pub user: Option<String>,
    /// Protocol found by sniffing (`tls`, `http`, ...).
    pub protocol: Option<String>,
    /// Domain found by sniffing (TLS server name, HTTP host).
    pub sniff_host: Option<String>,
}

impl InboundContext {
    pub fn new(
        inbound: &str,
        inbound_type: &'static str,
        network: Network,
        source: SocketAddr,
        destination: Socksaddr,
    ) -> Self {
        InboundContext {
            inbound: inbound.to_string(),
            inbound_type,
            network,
            source,
            destination,
            destination_addresses: Vec::new(),
            user: None,
            protocol: None,
            sniff_host: None,
        }
    }

    /// The domain rules match: the sniffed one, or else the destination's
    /// (sing-box `DomainItem.Match`: `metadata.Domain`, then `Destination.Fqdn`).
    pub fn domain(&self) -> Option<&str> {
        self.sniff_host.as_deref().or(self.destination.domain())
    }
}

/// A bidirectional byte stream (sing-box `net.Conn` for TCP).
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

pub type BoxStream = Box<dyn Stream>;

/// A stream with bytes already read from it put back in front (what sing-box
/// `bufio.NewCachedConn` does after sniffing or protocol detection).
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        PrefixedStream { prefix, offset: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let count = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..count]);
            self.offset += count;
            if self.offset == self.prefix.len() {
                self.prefix = Vec::new();
                self.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// An outbound (sing-box `adapter.Outbound`, TCP part).
#[async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    fn kind(&self) -> &'static str;
    /// Opens a TCP connection to the context's destination.
    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream>;
}

/// Why a routed connection ended without being relayed.
#[derive(Debug)]
pub enum RouteError {
    /// A rule rejected the connection.
    Rejected,
    /// Resolving the destination failed.
    Resolve(io::Error),
    /// The outbound could not connect.
    Dial(io::Error),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteError::Rejected => f.write_str("rejected by rule"),
            RouteError::Resolve(error) => write!(f, "resolve: {error}"),
            RouteError::Dial(error) => write!(f, "dial: {error}"),
        }
    }
}

impl std::error::Error for RouteError {}

/// The router as the inbounds see it (sing-box `adapter.ConnectionRouterEx`).
///
/// As in sing-box, an inbound finishes its own handshake first (a SOCKS5
/// success reply, `200 Connection established`) and then hands the
/// connection over: the router matches rules (sniffing reads the client's
/// first bytes), opens the outbound connection and copies both directions
/// until both are done (sing-box `bufio.CopyConn`).
#[async_trait]
pub trait ConnectionRouter: Send + Sync {
    async fn route_connection(&self, context: InboundContext, client: BoxStream) -> Result<(), RouteError>;
}

/// Domain resolution as outbounds and the router use it (sing-box
/// `adapter.DNSRouter.Lookup`).
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Resolves through the DNS server `server`, or through the DNS rules
    /// and `dns.final` when `server` is `None`.
    async fn lookup(&self, domain: &str, options: &LookupOptions) -> io::Result<Vec<IpAddr>>;
}

#[derive(Debug, Clone, Default)]
pub struct LookupOptions {
    pub server: Option<String>,
    pub strategy: DomainStrategy,
    pub disable_cache: bool,
    pub timeout: Option<Duration>,
    /// The inbound the query is for, for DNS rules.
    pub inbound: Option<String>,
}

/// A running inbound (sing-box `adapter.Inbound`).
#[async_trait]
pub trait Inbound: Send + Sync {
    fn tag(&self) -> &str;
    fn kind(&self) -> &'static str;
    /// The address it listens on, once started.
    fn local_addr(&self) -> Option<SocketAddr>;
    async fn start(self: Arc<Self>) -> io::Result<()>;
    async fn close(&self);
}

/// Sorts or filters addresses by a domain strategy (sing-box
/// `dns.SortAddresses` / strategy filtering).
pub fn apply_strategy(mut addresses: Vec<IpAddr>, strategy: DomainStrategy) -> Vec<IpAddr> {
    match strategy {
        DomainStrategy::AsIs => addresses,
        DomainStrategy::Ipv4Only => {
            addresses.retain(IpAddr::is_ipv4);
            addresses
        }
        DomainStrategy::Ipv6Only => {
            addresses.retain(IpAddr::is_ipv6);
            addresses
        }
        DomainStrategy::PreferIpv4 => {
            addresses.sort_by_key(|address| !address.is_ipv4());
            addresses
        }
        DomainStrategy::PreferIpv6 => {
            addresses.sort_by_key(|address| !address.is_ipv6());
            addresses
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn socksaddr() {
        let address = Socksaddr::from_host_port("Example.COM.", 443);
        assert_eq!(address.domain(), Some("example.com"));
        assert_eq!(address.to_string(), "example.com:443");
        let address = Socksaddr::from_host_port("[::1]", 80);
        assert_eq!(address.to_string(), "[::1]:80");
        let address = Socksaddr::from_host_port("::ffff:1.2.3.4", 80);
        assert_eq!(address.to_string(), "1.2.3.4:80");
    }

    #[test]
    fn strategies() {
        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        assert_eq!(apply_strategy(vec![v6, v4], DomainStrategy::PreferIpv4), vec![v4, v6]);
        assert_eq!(apply_strategy(vec![v4, v6], DomainStrategy::PreferIpv6), vec![v6, v4]);
        assert_eq!(apply_strategy(vec![v4, v6], DomainStrategy::Ipv6Only), vec![v6]);
    }

    #[tokio::test]
    async fn prefixed_stream() {
        let mut stream = PrefixedStream::new(b"ab".to_vec(), &b"cd"[..]);
        let mut all = Vec::new();
        stream.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"abcd");
    }
}
