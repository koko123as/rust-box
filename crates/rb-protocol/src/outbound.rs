//! The `direct` outbound (sing-box `protocol/direct/outbound.go`) and the
//! legacy `block` outbound (`protocol/block`).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{
    BoxStream, DnsResolver, Host, InboundContext, LookupOptions, Outbound, PacketConn, SharedPacketConn, Socksaddr,
};
use rb_config::{DirectOutbound, DomainResolveOptions};
use tokio::net::{TcpStream, UdpSocket};
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
                ..Default::default()
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
        let addresses = self.addresses(context).await?;
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

    /// A UDP socket for the session (sing-box `ListenPacket`, or
    /// `DialContext("udp")` with `udp_connect`). A domain destination is
    /// resolved first, and replies from its address are reported as coming
    /// from the domain unless `udp_disable_domain_unmapping` is set (sing
    /// `bufio.NATPacketConn` / `UnidirectionalNATPacketConn`).
    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        let destination = &context.destination;
        let address = *self
            .addresses(context)
            .await?
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{destination}: no addresses")))?;
        let target = SocketAddr::new(address, destination.port);
        let (socket, dual_stack) = bind_udp(address.is_ipv6()).await?;
        let connected = if context.udp_connect {
            socket.connect(socket_address(target, dual_stack)).await?;
            Some(target)
        } else {
            None
        };
        debug!(%target, connected = connected.is_some(), "direct: packet connection");
        let mut unmap = HashMap::new();
        let mut resolved = HashMap::new();
        if let Host::Domain(domain) = &destination.host {
            resolved.insert(domain.clone(), address);
            if !context.udp_disable_domain_unmapping {
                unmap.insert(target, destination.clone());
            }
        }
        Ok(Arc::new(DirectPacketConn {
            socket,
            dual_stack,
            connected,
            dns: self.dns.clone(),
            resolve: self.lookup_options(context),
            disable_unmapping: context.udp_disable_domain_unmapping,
            resolved: Mutex::new(resolved),
            unmap: Mutex::new(unmap),
        }))
    }
}

impl Direct {
    /// The resolver options, with the connection for DNS rules.
    fn lookup_options(&self, context: &InboundContext) -> LookupOptions {
        let from = LookupOptions::for_context(context);
        LookupOptions {
            inbound: from.inbound,
            source: from.source,
            user: from.user,
            network: from.network,
            ..self.resolve.clone()
        }
    }

    /// The addresses to try for the context's destination: the IP itself,
    /// the addresses a `resolve` action found, or a lookup.
    async fn addresses(&self, context: &InboundContext) -> io::Result<Vec<IpAddr>> {
        Ok(match &context.destination.host {
            Host::Ip(ip) => vec![*ip],
            Host::Domain(_) if !context.destination_addresses.is_empty() => context.destination_addresses.clone(),
            Host::Domain(domain) => {
                let options = self.lookup_options(context);
                self.dns.lookup(domain, &options).await?
            }
        })
    }
}

/// Binds an unconnected UDP socket on all addresses: dual stack where the
/// system has IPv6 (as Go's `ListenPacket("udp", "")`), else IPv4 only.
async fn bind_udp(need_ipv6: bool) -> io::Result<(UdpSocket, bool)> {
    match UdpSocket::bind("[::]:0").await {
        Ok(socket) => Ok((socket, true)),
        Err(error) if need_ipv6 => Err(error),
        Err(_) => Ok((UdpSocket::bind("0.0.0.0:0").await?, false)),
    }
}

/// An IPv4 address as a dual-stack socket takes it (`::ffff:a.b.c.d`).
fn socket_address(address: SocketAddr, dual_stack: bool) -> SocketAddr {
    match address {
        SocketAddr::V4(v4) if dual_stack => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        address => address,
    }
}

struct DirectPacketConn {
    socket: UdpSocket,
    dual_stack: bool,
    /// With `udp_connect`: the one peer; every packet goes there.
    connected: Option<SocketAddr>,
    dns: Arc<dyn DnsResolver>,
    resolve: LookupOptions,
    disable_unmapping: bool,
    /// Domains resolved in this session.
    resolved: Mutex<HashMap<String, IpAddr>>,
    /// Resolved address -> the domain address replies are reported from.
    unmap: Mutex<HashMap<SocketAddr, Socksaddr>>,
}

impl DirectPacketConn {
    async fn target(&self, destination: &Socksaddr) -> io::Result<SocketAddr> {
        let domain = match &destination.host {
            Host::Ip(ip) => return Ok(SocketAddr::new(*ip, destination.port)),
            Host::Domain(domain) => domain,
        };
        let known = self.resolved.lock().unwrap().get(domain).copied();
        let address = match known {
            Some(address) => address,
            None => {
                let addresses = self.dns.lookup(domain, &self.resolve).await?;
                let address =
                    addresses.iter().copied().find(|address| self.dual_stack || address.is_ipv4()).ok_or_else(
                        || io::Error::new(io::ErrorKind::NotFound, format!("{destination}: no addresses")),
                    )?;
                self.resolved.lock().unwrap().insert(domain.clone(), address);
                address
            }
        };
        let target = SocketAddr::new(address, destination.port);
        if !self.disable_unmapping {
            self.unmap.lock().unwrap().entry(target).or_insert_with(|| destination.clone());
        }
        Ok(target)
    }
}

#[async_trait]
impl PacketConn for DirectPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let (length, source) = match self.connected {
            Some(peer) => (self.socket.recv(buffer).await?, peer),
            None => {
                let (length, source) = self.socket.recv_from(buffer).await?;
                (length, SocketAddr::new(source.ip().to_canonical(), source.port()))
            }
        };
        let source = match self.unmap.lock().unwrap().get(&source) {
            Some(domain) => domain.clone(),
            None => Socksaddr::from(source),
        };
        Ok((length, source))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        if self.connected.is_some() {
            // A connected socket sends everything to its peer (sing
            // `bufio.NewUnbindPacketConn`).
            return self.socket.send(data).await.map(|_| ());
        }
        let target = self.target(address).await?;
        if target.is_ipv6() && !self.dual_stack {
            return Err(io::Error::new(io::ErrorKind::Unsupported, format!("{target}: no IPv6 socket")));
        }
        self.socket.send_to(data, socket_address(target, self.dual_stack)).await.map(|_| ())
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

    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{}: blocked", context.destination)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rb_adapter::Network;

    /// Resolves every domain to 127.0.0.1.
    struct Loopback;

    #[async_trait]
    impl DnsResolver for Loopback {
        async fn lookup(&self, _domain: &str, _options: &LookupOptions) -> io::Result<Vec<IpAddr>> {
            Ok(vec!["127.0.0.1".parse().unwrap()])
        }
    }

    async fn echo_server() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
                let _ = socket.send_to(&buffer[..length], peer).await;
            }
        });
        address
    }

    fn context(destination: Socksaddr) -> InboundContext {
        InboundContext::new("in", "socks", Network::Udp, "127.0.0.1:1".parse().unwrap(), destination)
    }

    async fn roundtrip(conn: &SharedPacketConn, destination: &Socksaddr) -> Socksaddr {
        conn.write_packet(b"hello", destination).await.unwrap();
        let mut buffer = [0u8; 64];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(5), conn.read_packet(&mut buffer)).await.unwrap().unwrap();
        assert_eq!(&buffer[..length], b"hello");
        source
    }

    #[tokio::test]
    async fn direct_udp_domain_mapping() {
        let echo = echo_server().await;
        let direct = Direct::new(&Default::default(), "direct".into(), Arc::new(Loopback), None);
        let domain = Socksaddr::from_host_port("echo.test", echo.port());
        let ip = Socksaddr::from(echo);

        // Replies from the resolved address come back as the domain.
        let conn = direct.listen_packet(&context(domain.clone())).await.unwrap();
        assert_eq!(roundtrip(&conn, &domain).await, domain);
        // One session reaches other destinations too.
        let other = echo_server().await;
        assert_eq!(roundtrip(&conn, &Socksaddr::from(other)).await, Socksaddr::from(other));

        // udp_disable_domain_unmapping: replies keep the address.
        let mut unmapped = context(domain.clone());
        unmapped.udp_disable_domain_unmapping = true;
        let conn = direct.listen_packet(&unmapped).await.unwrap();
        assert_eq!(roundtrip(&conn, &domain).await, ip);

        // udp_connect: a connected socket, still mapped back to the domain.
        let mut connected = context(domain.clone());
        connected.udp_connect = true;
        let conn = direct.listen_packet(&connected).await.unwrap();
        assert_eq!(roundtrip(&conn, &domain).await, domain);
    }

    #[tokio::test]
    async fn block_refuses_udp() {
        let block = Block::new("block".into());
        let error = block.listen_packet(&context(Socksaddr::from_host_port("1.1.1.1", 53))).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
