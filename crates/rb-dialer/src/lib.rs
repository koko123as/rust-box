//! Dialing and listening, mirroring sing-box `common/dialer` (the default
//! dialer with the shared dial fields, the detour dialer, happy-eyeballs),
//! `common/listener` (the listen fields) and `common/tlsfragment`.
//!
//! Dependencies come in through constructors: the default dialer takes its
//! options and the route-level defaults ([`NetworkDefaults`]), the detour
//! dialer takes the [`OutboundRegistry`] handle.
//!
//! Platform support of the dial and listen fields (see also
//! `docs/roadmap.md`):
//!
//! | Field | Linux | Android | other |
//! |---|---|---|---|
//! | `bind_interface` | yes | yes | refused |
//! | `routing_mark`, `default_mark` | yes | yes | refused (sing-box: Linux only) |
//! | `bind_address_no_port` | yes | yes | refused (sing-box: Linux only) |
//! | `netns` | yes (needs `CAP_SYS_ADMIN`) | yes | refused (sing-box: Linux only) |
//! | `tcp_fast_open` | yes | yes | refused |
//! | `tcp_multi_path` | yes, falls back to TCP | same | plain TCP (as Go) |
//! | `udp_fragment` | `IP_MTU_DISCOVER` | same | system default |
//! | `protect_path` | yes | yes | refused (sing-box: Unix only) |

pub mod listener;
pub mod parallel;
pub mod quic;
pub mod resolve;
pub mod sys;
pub mod tfo;
pub mod tls_fragment;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{BoxStream, Host, InboundContext, Network, OutboundRegistry, PacketConn, SharedPacketConn, Socksaddr};
use rb_config::DialerOptions;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpStream, UdpSocket};

pub use parallel::{dial_parallel, dial_serial, DEFAULT_FALLBACK_DELAY};
pub use resolve::{lookup_options, new_outbound_dialer, resolve_options, DialerEnv, NatPacketConn, ResolveDialer};

/// sing-box `C.TCPConnectTimeout`.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// sing-box `C.TCPKeepAliveInitial`.
pub const DEFAULT_KEEP_ALIVE_IDLE: Duration = Duration::from_secs(300);
/// sing-box `C.TCPKeepAliveInterval`.
pub const DEFAULT_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(75);

/// Dial defaults from the route section (sing-box
/// `adapter.NetworkOptions`): `route.default_interface` and
/// `route.default_mark`.
#[derive(Debug, Clone, Default)]
pub struct NetworkDefaults {
    pub default_interface: String,
    pub default_mark: u32,
    /// `route.auto_detect_interface`: sockets without an interface of their
    /// own are protected by the platform, or bound to the default
    /// interface ([`rb_platform::auto_detect_interface_control`]).
    pub auto_detect_interface: bool,
}

impl NetworkDefaults {
    /// Checks the defaults the way sing-box's network manager does.
    pub fn check(&self) -> Result<(), String> {
        if !self.default_interface.is_empty() && !sys::IS_LINUX {
            return Err("`default_interface` is not supported by rust-box on this platform".into());
        }
        if self.default_mark != 0 && !sys::IS_LINUX {
            return Err("`default_mark` is only supported on linux".into());
        }
        Ok(())
    }
}

/// Something that opens connections to IP destinations (sing `N.Dialer`).
#[async_trait]
pub trait Dialer: Send + Sync {
    /// A TCP connection.
    async fn dial_tcp(&self, destination: &Socksaddr) -> io::Result<BoxStream>;
    /// A UDP socket connected to `destination` (sing `DialContext("udp")`).
    async fn dial_udp(&self, destination: &Socksaddr) -> io::Result<SharedPacketConn>;
    /// An unconnected UDP socket for packets to `destination` and others
    /// (sing `ListenPacket`).
    async fn listen_packet(&self, destination: &Socksaddr) -> io::Result<SharedPacketConn>;
}

fn not_resolved(destination: &Socksaddr) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("{destination}: domain not resolved"))
}

fn ip_destination(destination: &Socksaddr) -> io::Result<SocketAddr> {
    match destination.host {
        Host::Ip(ip) => Ok(SocketAddr::new(ip, destination.port)),
        Host::Domain(_) => Err(not_resolved(destination)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketKind {
    TcpConnect,
    UdpConnect,
    UdpListen,
}

/// The system dialer with the dial fields applied (sing-box
/// `dialer.DefaultDialer`).
#[derive(Debug, Clone)]
pub struct DefaultDialer {
    connect_timeout: Duration,
    bind_interface: Option<String>,
    routing_mark: Option<u32>,
    inet4_bind_address: Option<Ipv4Addr>,
    inet6_bind_address: Option<Ipv6Addr>,
    bind_address_no_port: bool,
    protect_path: Option<PathBuf>,
    /// `route.auto_detect_interface` applies (no interface or address bound).
    auto_detect_interface: bool,
    reuse_addr: bool,
    netns: Option<PathBuf>,
    tcp_fast_open: bool,
    tcp_multi_path: bool,
    keep_alive: Option<(Duration, Duration)>,
    udp_fragment: bool,
}

impl DefaultDialer {
    /// Builds the dialer (sing-box `dialer.NewDefault`). `udp_fragment_default`
    /// is what `udp_fragment` means when unset: on for `direct`, off for DNS
    /// servers. `detour`, `domain_resolver`, `domain_strategy` and
    /// `fallback_delay` belong to the layers above and are not read here.
    pub fn new(
        options: &DialerOptions,
        defaults: &NetworkDefaults,
        udp_fragment_default: bool,
    ) -> Result<Self, String> {
        let linux_only = |set: bool, name: &str| -> Result<(), String> {
            if set && !sys::IS_LINUX {
                Err(format!("`{name}` is only supported on Linux"))
            } else {
                Ok(())
            }
        };
        if !options.bind_interface.is_empty() && !sys::IS_LINUX {
            return Err("`bind_interface` is not supported by rust-box on this platform".into());
        }
        linux_only(options.routing_mark.0 > 0, "routing_mark")?;
        linux_only(options.bind_address_no_port, "bind_address_no_port")?;
        linux_only(!options.netns.is_empty(), "netns")?;
        if options.tcp_fast_open && !sys::IS_LINUX {
            return Err("`tcp_fast_open` is not supported by rust-box on this platform".into());
        }
        if !options.protect_path.is_empty() && !cfg!(unix) {
            return Err("`protect_path` is only supported on Unix".into());
        }
        if let Some(message) = options.network_strategy_conflict() {
            return Err(message.into());
        }
        defaults.check()?;
        let inet4_bind_address = match options.inet4_bind_address {
            None => None,
            Some(IpAddr::V4(v4)) => Some(v4),
            Some(other) => return Err(format!("`inet4_bind_address`: not an IPv4 address: {other}")),
        };
        let inet6_bind_address = match options.inet6_bind_address {
            None => None,
            Some(IpAddr::V6(v6)) => Some(v6),
            Some(other) => return Err(format!("`inet6_bind_address`: not an IPv6 address: {other}")),
        };
        let disable_default_bind =
            !options.bind_interface.is_empty() || inet4_bind_address.is_some() || inet6_bind_address.is_some();
        let bind_interface = if !options.bind_interface.is_empty() {
            Some(options.bind_interface.clone())
        } else if !defaults.default_interface.is_empty() && !disable_default_bind {
            Some(defaults.default_interface.clone())
        } else {
            None
        };
        let routing_mark = if options.routing_mark.0 > 0 {
            Some(options.routing_mark.0)
        } else if defaults.default_mark != 0 {
            Some(defaults.default_mark)
        } else {
            None
        };
        let keep_alive = (!options.disable_tcp_keep_alive).then(|| {
            let idle =
                if options.tcp_keep_alive.0.is_zero() { DEFAULT_KEEP_ALIVE_IDLE } else { options.tcp_keep_alive.0 };
            let interval = if options.tcp_keep_alive_interval.0.is_zero() {
                DEFAULT_KEEP_ALIVE_INTERVAL
            } else {
                options.tcp_keep_alive_interval.0
            };
            (idle, interval)
        });
        Ok(DefaultDialer {
            connect_timeout: if options.connect_timeout.0.is_zero() {
                DEFAULT_CONNECT_TIMEOUT
            } else {
                options.connect_timeout.0
            },
            bind_interface,
            routing_mark,
            inet4_bind_address,
            inet6_bind_address,
            bind_address_no_port: options.bind_address_no_port,
            protect_path: (!options.protect_path.is_empty()).then(|| PathBuf::from(&options.protect_path)),
            auto_detect_interface: defaults.auto_detect_interface
                && !disable_default_bind
                && defaults.default_interface.is_empty(),
            reuse_addr: options.reuse_addr,
            netns: (!options.netns.is_empty()).then(|| sys::netns_path(&options.netns)),
            tcp_fast_open: options.tcp_fast_open,
            tcp_multi_path: options.tcp_multi_path,
            keep_alive,
            udp_fragment: options.udp_fragment.unwrap_or(udp_fragment_default),
        })
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub fn tcp_fast_open(&self) -> bool {
        self.tcp_fast_open
    }

    /// Creates and configures one socket, in the network namespace when
    /// one is set. `bind` is the local address, if any.
    fn socket(
        &self,
        domain: Domain,
        kind: SocketKind,
        bind: Option<SocketAddr>,
        dual_stack: bool,
    ) -> io::Result<Socket> {
        sys::maybe_in_netns(self.netns.as_deref(), || {
            let socket = match kind {
                SocketKind::TcpConnect => {
                    // Go's SetMultipathTCP falls back to TCP when the kernel
                    // has no MPTCP. sing-box enables it on its IPv4 dialer only.
                    let mptcp = self.tcp_multi_path && domain == Domain::IPV4 && sys::IS_LINUX;
                    let multipath = if mptcp {
                        Socket::new(domain, Type::STREAM, Some(Protocol::from(mptcp_protocol()))).ok()
                    } else {
                        None
                    };
                    match multipath {
                        Some(socket) => socket,
                        None => Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?,
                    }
                }
                SocketKind::UdpConnect | SocketKind::UdpListen => {
                    Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?
                }
            };
            socket.set_nonblocking(true)?;
            if domain == Domain::IPV6 && kind == SocketKind::UdpListen {
                socket.set_only_v6(!dual_stack)?;
            }
            let fd = socket.as_raw_fd();
            if let Some(name) = &self.bind_interface {
                sys::bind_to_interface(fd, name)
                    .map_err(|error| io::Error::new(error.kind(), format!("bind to interface {name}: {error}")))?;
            }
            if let Some(mark) = self.routing_mark {
                sys::set_mark(fd, mark)
                    .map_err(|error| io::Error::new(error.kind(), format!("set mark {mark}: {error}")))?;
            }
            if self.reuse_addr && kind == SocketKind::UdpListen {
                sys::set_reuse_addr(fd)?;
            }
            if let Some(path) = &self.protect_path {
                sys::protect(fd, path)?;
            }
            if self.auto_detect_interface {
                rb_platform::auto_detect_interface_control(fd, domain == Domain::IPV6)?;
            }
            match kind {
                SocketKind::TcpConnect => {
                    if self.bind_address_no_port {
                        sys::set_bind_address_no_port(fd)?;
                    }
                    if let Some((idle, interval)) = self.keep_alive {
                        sys::set_keep_alive(fd, idle, interval)?;
                    }
                }
                SocketKind::UdpConnect | SocketKind::UdpListen => {
                    sys::set_udp_fragment(fd, domain == Domain::IPV6, self.udp_fragment)?;
                }
            }
            if let Some(bind) = bind {
                socket
                    .bind(&bind.into())
                    .map_err(|error| io::Error::new(error.kind(), format!("bind {bind}: {error}")))?;
            }
            Ok(socket)
        })
    }

    /// The local address for a connection to `destination`
    /// (`inet4_bind_address` / `inet6_bind_address`).
    fn local_address(&self, destination: IpAddr) -> Option<SocketAddr> {
        match destination {
            IpAddr::V4(_) => self.inet4_bind_address.map(|ip| SocketAddr::new(IpAddr::V4(ip), 0)),
            IpAddr::V6(_) => self.inet6_bind_address.map(|ip| SocketAddr::new(IpAddr::V6(ip), 0)),
        }
    }

    /// A TCP connection to `address`, without Fast Open.
    pub async fn connect_tcp(&self, address: SocketAddr) -> io::Result<TcpStream> {
        let domain = Domain::for_address(address);
        let socket = self.socket(domain, SocketKind::TcpConnect, self.local_address(address.ip()), false)?;
        let socket = tokio::net::TcpSocket::from_std_stream(std::net::TcpStream::from(socket));
        let stream = tokio::time::timeout(self.connect_timeout, socket.connect(address))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{address}: connect timed out")))?
            .map_err(|error| io::Error::new(error.kind(), format!("{address}: {error}")))?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    /// A TCP connection to `address`: with `tcp_fast_open` a lazy one that
    /// connects on the first write (unless `server_first`, where nothing
    /// would ever be written first), else [`DefaultDialer::connect_tcp`].
    pub async fn dial_tcp_stream(&self, address: SocketAddr, server_first: bool) -> io::Result<BoxStream> {
        if self.tcp_fast_open && !server_first {
            let domain = Domain::for_address(address);
            let socket = self.socket(domain, SocketKind::TcpConnect, self.local_address(address.ip()), false)?;
            return Ok(Box::new(tfo::TfoStream::new(socket, address, self.connect_timeout)));
        }
        Ok(Box::new(self.connect_tcp(address).await?))
    }

    /// A UDP socket connected to `address`.
    pub async fn connect_udp(&self, address: SocketAddr) -> io::Result<UdpSocket> {
        let domain = Domain::for_address(address);
        let socket = self.socket(domain, SocketKind::UdpConnect, self.local_address(address.ip()), false)?;
        let socket = UdpSocket::from_std(std::net::UdpSocket::from(socket))?;
        socket.connect(address).await?;
        Ok(socket)
    }

    /// An unconnected UDP socket for packets to `destination` (sing-box
    /// `DefaultDialer.ListenPacket`): an IPv4-only socket for an IPv4
    /// destination, else dual stack unless a bind address decides the
    /// family. Returns the socket and whether it is a dual-stack IPv6 one.
    pub async fn listen_udp(&self, destination: Option<IpAddr>) -> io::Result<(UdpSocket, bool)> {
        let any4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let any6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let bind4 = self.inet4_bind_address.map(|ip| SocketAddr::new(IpAddr::V4(ip), 0));
        let bind6 = self.inet6_bind_address.map(|ip| SocketAddr::new(IpAddr::V6(ip), 0));
        let (socket, dual_stack) = match destination {
            Some(IpAddr::V6(_)) => match bind6 {
                Some(bind) => (self.socket(Domain::IPV6, SocketKind::UdpListen, Some(bind), false)?, false),
                None => (self.socket(Domain::IPV6, SocketKind::UdpListen, Some(any6), true)?, true),
            },
            Some(IpAddr::V4(v4)) if !v4.is_unspecified() => {
                (self.socket(Domain::IPV4, SocketKind::UdpListen, Some(bind4.unwrap_or(any4)), false)?, false)
            }
            _ => match bind4 {
                Some(bind) => (self.socket(Domain::IPV4, SocketKind::UdpListen, Some(bind), false)?, false),
                // Go's "udp" on "": dual stack where the system has IPv6.
                None => match self.socket(Domain::IPV6, SocketKind::UdpListen, Some(any6), true) {
                    Ok(socket) => (socket, true),
                    Err(_) => (self.socket(Domain::IPV4, SocketKind::UdpListen, Some(any4), false)?, false),
                },
            },
        };
        Ok((UdpSocket::from_std(std::net::UdpSocket::from(socket))?, dual_stack))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn mptcp_protocol() -> i32 {
    sys::IPPROTO_MPTCP
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn mptcp_protocol() -> i32 {
    libc::IPPROTO_TCP
}

#[async_trait]
impl Dialer for DefaultDialer {
    async fn dial_tcp(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        self.dial_tcp_stream(ip_destination(destination)?, rb_adapter::server_first_port(destination.port)).await
    }

    async fn dial_udp(&self, destination: &Socksaddr) -> io::Result<SharedPacketConn> {
        let address = ip_destination(destination)?;
        let socket = self.connect_udp(address).await?;
        Ok(Arc::new(UdpPacketConn::connected(socket, address)))
    }

    async fn listen_packet(&self, destination: &Socksaddr) -> io::Result<SharedPacketConn> {
        let (socket, dual_stack) = self.listen_udp(destination.ip()).await?;
        Ok(Arc::new(UdpPacketConn::new(socket, dual_stack)))
    }
}

/// An IPv4 address as a dual-stack socket takes it (`::ffff:a.b.c.d`).
pub fn socket_address(address: SocketAddr, dual_stack: bool) -> SocketAddr {
    match address {
        SocketAddr::V4(v4) if dual_stack => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        address => address,
    }
}

/// A UDP socket as a packet connection, to IP addresses only.
pub struct UdpPacketConn {
    socket: UdpSocket,
    dual_stack: bool,
    /// For a connected socket: its one peer, which every packet goes to and
    /// comes from (sing `bufio.NewUnbindPacketConn`).
    connected: Option<SocketAddr>,
}

impl UdpPacketConn {
    pub fn new(socket: UdpSocket, dual_stack: bool) -> Self {
        UdpPacketConn { socket, dual_stack, connected: None }
    }

    pub fn connected(socket: UdpSocket, peer: SocketAddr) -> Self {
        UdpPacketConn { socket, dual_stack: false, connected: Some(peer) }
    }

    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }
}

#[async_trait]
impl PacketConn for UdpPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        match self.connected {
            Some(peer) => Ok((self.socket.recv(buffer).await?, Socksaddr::from(peer))),
            None => {
                let (length, source) = self.socket.recv_from(buffer).await?;
                Ok((length, Socksaddr::from(source)))
            }
        }
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        if self.connected.is_some() {
            return self.socket.send(data).await.map(|_| ());
        }
        let target = ip_destination(address)?;
        if target.is_ipv6() && !self.dual_stack && self.socket.local_addr()?.is_ipv4() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, format!("{target}: no IPv6 socket")));
        }
        self.socket.send_to(data, socket_address(target, self.dual_stack)).await.map(|_| ())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.local_addr().ok()
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        self.connected
    }
}

/// Dials through another outbound (sing-box `dialer.DetourDialer`). The
/// outbound is looked up when first used, since the parts that dial
/// through one can be built before the outbounds.
pub struct DetourDialer {
    outbounds: Arc<OutboundRegistry>,
    detour: String,
}

impl DetourDialer {
    pub fn new(outbounds: Arc<OutboundRegistry>, detour: String) -> Self {
        DetourDialer { outbounds, detour }
    }
}

#[async_trait]
impl Dialer for DetourDialer {
    async fn dial_tcp(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let outbound = self.outbounds.get(&self.detour)?;
        outbound.dial_tcp(&InboundContext::internal(Network::Tcp, destination.clone())).await
    }

    async fn dial_udp(&self, destination: &Socksaddr) -> io::Result<SharedPacketConn> {
        let outbound = self.outbounds.get(&self.detour)?;
        let mut context = InboundContext::internal(Network::Udp, destination.clone());
        context.udp_connect = true;
        outbound.listen_packet(&context).await
    }

    async fn listen_packet(&self, destination: &Socksaddr) -> io::Result<SharedPacketConn> {
        let outbound = self.outbounds.get(&self.detour)?;
        outbound.listen_packet(&InboundContext::internal(Network::Udp, destination.clone())).await
    }
}

/// The dialer an object's dial fields describe (sing-box
/// `dialer.NewWithOptions` without the resolving layer): a detour when
/// `detour` is set (all other fields are then ignored, as documented), else
/// the default dialer.
pub fn new_dialer(
    options: &DialerOptions,
    defaults: &NetworkDefaults,
    outbounds: &Arc<OutboundRegistry>,
    udp_fragment_default: bool,
) -> Result<Arc<dyn Dialer>, String> {
    if !options.detour.is_empty() {
        return Ok(Arc::new(DetourDialer::new(outbounds.clone(), options.detour.clone())));
    }
    Ok(Arc::new(DefaultDialer::new(options, defaults, udp_fragment_default)?))
}

#[cfg(test)]
mod tests;
