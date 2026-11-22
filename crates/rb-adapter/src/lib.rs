//! Core abstractions, mirroring sing-box `adapter/`.
//!
//! sing-box connects its parts through interfaces in `adapter/` and finds
//! them at run time through a service registry in the context
//! (`sing/service`). rust-box passes the same parts explicitly: an inbound
//! holds the [`ConnectionRouter`], the router holds the outbounds and the
//! [`DnsResolver`], so every dependency shows in a constructor.

use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use rb_config::DomainStrategy;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod track;
pub use track::{
    real_tag, Attachment, ConnectionTracker, HistoryStorage, Interrupt, InterruptPacketConn, InterruptStream,
    OutboundGroup, RoutedConnection, UrlTestHistory,
};

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
    /// Domain found by sniffing (TLS server name, HTTP host, QUIC server name).
    pub sniff_host: Option<String>,
    /// The inbound's UDP NAT expiration (`udp_timeout` listen field); the
    /// router never keeps a packet connection idle longer than this.
    pub inbound_udp_timeout: Option<Duration>,
    /// `udp_timeout` from a matched route action (sing-box `metadata.UDPTimeout`).
    pub udp_timeout: Option<Duration>,
    /// `udp_connect` from a matched route action.
    pub udp_connect: bool,
    /// `udp_disable_domain_unmapping` from a matched route action.
    pub udp_disable_domain_unmapping: bool,
    /// The local address the client connected to (sing-box
    /// `metadata.OriginDestination`).
    pub origin_destination: Option<SocketAddr>,
    /// The inbound this connection is handed to after the first inbound's
    /// handshake (listen field `detour`, sing-box `metadata.InboundDetour`).
    pub inbound_detour: Option<String>,
    /// The inbound that handed this connection over (sing-box `metadata.LastInbound`).
    pub last_inbound: Option<String>,
    /// The destination before `override_address`/`override_port` (sing-box
    /// `metadata.RouteOriginalDestination`).
    pub route_original_destination: Option<Socksaddr>,
    /// The synthetic FakeIP endpoint before it is restored to a domain.
    pub fake_ip_original_destination: Option<Socksaddr>,
    /// `fallback_delay` from a matched route action.
    pub fallback_delay: Option<Duration>,
    /// `tls_fragment` from a matched route action.
    pub tls_fragment: bool,
    /// `tls_fragment_fallback_delay` from the route action that set `tls_fragment`.
    pub tls_fragment_fallback_delay: Option<Duration>,
    /// `tls_record_fragment` from a matched route action.
    pub tls_record_fragment: bool,
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
            inbound_udp_timeout: None,
            udp_timeout: None,
            udp_connect: false,
            udp_disable_domain_unmapping: false,
            origin_destination: None,
            inbound_detour: None,
            last_inbound: None,
            route_original_destination: None,
            fake_ip_original_destination: None,
            fallback_delay: None,
            tls_fragment: false,
            tls_fragment_fallback_delay: None,
            tls_record_fragment: false,
        }
    }

    /// A context for a connection rust-box opens itself (a DNS query through
    /// a `detour` outbound), with no inbound behind it.
    pub fn internal(network: Network, destination: Socksaddr) -> Self {
        let unspecified = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        InboundContext::new("", "", network, unspecified, destination)
    }

    /// The domain rules match: the sniffed one, or else the destination's
    /// (sing-box `DomainItem.Match`: `metadata.Domain`, then `Destination.Fqdn`).
    pub fn domain(&self) -> Option<&str> {
        self.sniff_host.as_deref().or(self.destination.domain())
    }
}

/// A bidirectional byte stream (sing-box `net.Conn` for TCP).
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {
    /// The concrete stream, so a layer can reach the socket under a boxed
    /// stream (what sing-box does with `N.UnwrapReader`), as the TLS
    /// fragmenter does to read `TCP_INFO`.
    fn as_any(&self) -> &dyn Any;
}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Stream for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

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

/// Largest UDP payload a packet connection carries.
pub const MAX_PACKET_SIZE: usize = 65535;

/// A connection that carries datagrams, each with an address (sing-box
/// `N.PacketConn`).
///
/// On the client side of a route (what an inbound hands the router) the
/// address of a read packet is where the client sent it, and the address of
/// a written packet is the source the client should see. On the remote side
/// (what an outbound returns) it is the other way around: packets are
/// written to their destination and read with their source.
///
/// Both methods take `&self` so the two directions run at once, and
/// `read_packet` must be cancel safe: the router races it against timeouts.
#[async_trait]
pub trait PacketConn: Send + Sync {
    /// Reads one packet into `buffer` (truncated to its length) and returns
    /// the packet's length and address.
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)>;
    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()>;

    /// The local UDP socket address, when the underlying packet connection
    /// exposes one.
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// The connected UDP peer, when the packet connection has one.
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
}

pub type SharedPacketConn = Arc<dyn PacketConn>;

/// A packet connection with packets already read from it put back in front
/// (sing-box `bufio.NewCachedPacketConn`).
pub struct CachedPacketConn {
    cached: Mutex<VecDeque<(Vec<u8>, Socksaddr)>>,
    inner: SharedPacketConn,
}

impl CachedPacketConn {
    pub fn new(packets: Vec<(Vec<u8>, Socksaddr)>, inner: SharedPacketConn) -> Self {
        CachedPacketConn { cached: Mutex::new(packets.into()), inner }
    }
}

#[async_trait]
impl PacketConn for CachedPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let cached = self.cached.lock().unwrap().pop_front();
        if let Some((data, address)) = cached {
            let length = data.len().min(buffer.len());
            buffer[..length].copy_from_slice(&data[..length]);
            return Ok((length, address));
        }
        self.inner.read_packet(buffer).await
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        self.inner.write_packet(data, address).await
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr()
    }
}

/// An outbound (sing-box `adapter.Outbound`).
#[async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    fn kind(&self) -> &'static str;
    /// The networks it carries (sing-box `Outbound.Network`); the router
    /// refuses the others.
    fn networks(&self) -> &[Network] {
        &[Network::Tcp, Network::Udp]
    }
    /// Opens a TCP connection to the context's destination.
    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream>;
    /// Opens a packet connection for UDP whose first destination is the
    /// context's (sing-box `ListenPacket`; `DialContext("udp")` when the
    /// context asks for `udp_connect`).
    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        let _ = context;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("outbound/{}[{}]: UDP is not supported", self.kind(), self.tag()),
        ))
    }
    /// The group behind this outbound, when it is one (sing-box
    /// `adapter.OutboundGroup`).
    fn group(&self) -> Option<&dyn OutboundGroup> {
        None
    }
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
    /// Reading from the client failed while routing (packet sniffing).
    Io(io::Error),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteError::Rejected => f.write_str("rejected by rule"),
            RouteError::Resolve(error) => write!(f, "resolve: {error}"),
            RouteError::Dial(error) => write!(f, "dial: {error}"),
            RouteError::Io(error) => write!(f, "{error}"),
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

    /// Routes a UDP session (sing-box `RoutePacketConnectionEx`): the rules
    /// are matched once, with the destination of the first packet, and the
    /// session relays packets until it is idle for its UDP timeout or the
    /// returned future is dropped. As in sing-box, an inbound that knows the
    /// first packet already hands it in front of `client`
    /// ([`CachedPacketConn`]).
    async fn route_packet_connection(
        &self,
        context: InboundContext,
        client: SharedPacketConn,
    ) -> Result<(), RouteError>;
}

/// Domain resolution as outbounds and the router use it (sing-box
/// `adapter.DNSRouter.Lookup`).
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// Resolves through the DNS server `server`, or through the DNS rules
    /// and `dns.final` when `server` is `None`.
    async fn lookup(&self, domain: &str, options: &LookupOptions) -> io::Result<Vec<IpAddr>>;

    /// Answers a whole DNS query message through the DNS rules (what
    /// `hijack-dns` uses, sing-box `DNSRouter.Exchange`). `Ok(None)` means the
    /// query is dropped without an answer.
    async fn exchange(&self, query: &[u8], options: &LookupOptions) -> io::Result<Option<Vec<u8>>> {
        let _ = (query, options);
        Err(io::Error::new(io::ErrorKind::Unsupported, "DNS exchange is not supported"))
    }

    /// Resolves an address previously allocated by a synthetic DNS server.
    /// Implementations without reverse mappings return `Ok(None)`.
    fn reverse_lookup(&self, address: IpAddr) -> io::Result<Option<String>> {
        let _ = address;
        Ok(None)
    }
}

#[derive(Debug, Clone, Default)]
pub struct LookupOptions {
    pub server: Option<String>,
    pub strategy: DomainStrategy,
    pub disable_cache: bool,
    pub timeout: Option<Duration>,
    /// The inbound the query is for, for DNS rules.
    pub inbound: Option<String>,
    /// The connection the query is for, for DNS rules (`source_ip_cidr`,
    /// `source_port`, `auth_user`, `network`).
    pub source: Option<SocketAddr>,
    pub user: Option<String>,
    pub network: Option<Network>,
    /// Replaces the TTL of the answers (`rewrite_ttl`).
    pub rewrite_ttl: Option<u32>,
}

impl LookupOptions {
    /// Options for a query made on behalf of a connection.
    pub fn for_context(context: &InboundContext) -> Self {
        LookupOptions {
            inbound: Some(context.inbound.clone()),
            source: Some(context.source),
            user: context.user.clone(),
            network: Some(context.network),
            ..Default::default()
        }
    }
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

    /// Takes a connection another inbound accepted, as if this inbound had
    /// accepted it (sing-box `adapter.TCPInjectableInbound`, used by the
    /// listen field `detour`). `context` carries the source and the
    /// first inbound's addresses.
    async fn new_connection(&self, context: InboundContext, stream: BoxStream) -> io::Result<()> {
        let _ = (context, stream);
        Err(io::Error::new(io::ErrorKind::Unsupported, format!("inbound detour is not TCP injectable: {}", self.tag())))
    }

    /// The same for packet connections (sing-box `adapter.UDPInjectableInbound`).
    async fn new_packet_connection(&self, context: InboundContext, conn: SharedPacketConn) -> io::Result<()> {
        let _ = (context, conn);
        Err(io::Error::new(io::ErrorKind::Unsupported, format!("inbound detour is not UDP injectable: {}", self.tag())))
    }
}

/// The outbounds by tag, filled once they are all built (sing-box
/// `adapter.OutboundManager`). Parts built before the outbounds (DNS
/// servers with a `detour`) take this handle in their constructor and look
/// the outbound up when they first dial, as sing-box's `DetourDialer` does.
#[derive(Default)]
pub struct OutboundRegistry {
    outbounds: OnceLock<HashMap<String, Arc<dyn Outbound>>>,
}

impl OutboundRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(OutboundRegistry::default())
    }

    /// Publishes the outbounds; later calls are ignored.
    pub fn set(&self, outbounds: &[Arc<dyn Outbound>]) {
        let map = outbounds.iter().map(|outbound| (outbound.tag().to_string(), outbound.clone())).collect();
        let _ = self.outbounds.set(map);
    }

    pub fn get(&self, tag: &str) -> io::Result<Arc<dyn Outbound>> {
        let outbounds = self
            .outbounds
            .get()
            .ok_or_else(|| io::Error::other(format!("outbound {tag} used before the outbounds were built")))?;
        outbounds
            .get(tag)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("outbound detour not found: {tag}")))
    }
}

/// The inbounds by tag, filled once they are all built (sing-box
/// `adapter.InboundManager`), for the router's inbound `detour`.
#[derive(Default)]
pub struct InboundRegistry {
    inbounds: OnceLock<HashMap<String, Arc<dyn Inbound>>>,
}

impl InboundRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(InboundRegistry::default())
    }

    /// Publishes the inbounds; later calls are ignored.
    pub fn set(&self, inbounds: &[Arc<dyn Inbound>]) {
        let map = inbounds.iter().map(|inbound| (inbound.tag().to_string(), inbound.clone())).collect();
        let _ = self.inbounds.set(map);
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn Inbound>> {
        self.inbounds.get()?.get(tag).cloned()
    }
}

/// Ports of server-first protocols (SMTP, IMAP, POP3), where the client
/// waits for the server to speak (sing-box `sniff.Skip`).
pub fn server_first_port(port: u16) -> bool {
    matches!(port, 25 | 465 | 587 | 143 | 993 | 110 | 995)
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

    struct Silent;

    #[async_trait]
    impl PacketConn for Silent {
        async fn read_packet(&self, _buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        async fn write_packet(&self, _data: &[u8], _address: &Socksaddr) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn cached_packet_conn() {
        let address = Socksaddr::from_host_port("1.2.3.4", 53);
        let conn = CachedPacketConn::new(vec![(b"abc".to_vec(), address.clone())], Arc::new(Silent));
        let mut buffer = [0u8; 2];
        assert_eq!(conn.read_packet(&mut buffer).await.unwrap(), (2, address));
        assert_eq!(&buffer, b"ab");
        assert!(conn.read_packet(&mut buffer).await.is_err());
    }

    #[tokio::test]
    async fn prefixed_stream() {
        let mut stream = PrefixedStream::new(b"ab".to_vec(), &b"cd"[..]);
        let mut all = Vec::new();
        stream.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"abcd");
    }
}
