//! The `shadowsocks` outbound and inbound (sing-box `protocol/shadowsocks`)
//! over the wire format of `rb-shadowsocks`.
//!
//! The outbound dials its server through [`rb_dialer::new_outbound_dialer`]
//! (dial fields, `detour`, `domain_resolver`); UDP goes in its own UDP
//! packets, or with `udp_over_tcp` in a TCP connection to the UoT magic
//! destination. [`ShadowsocksOutbound::connect`] is the plain shadowsocks
//! TCP dialer (sing-box `shadowsocksDialer`) that UoT, and later a
//! multiplex client, run over.
//!
//! The inbound listens on TCP and UDP (`network`). TCP requests go through
//! the service's handshake to the router; a request to a UoT magic
//! destination carries UDP (sing-box `common/uot.Router`). UDP packets of
//! all clients share one socket: each client (a source address, or a 2022
//! session id) becomes a session of the NAT table, routed once.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{
    BoxStream, ConnectionRouter, Inbound, InboundContext, Network, Outbound, PacketConn, PrefixedStream, RouteError,
    SharedPacketConn, Socksaddr, MAX_PACKET_SIZE,
};
use rb_config::{ShadowsocksInbound as InboundOptions, ShadowsocksOutbound as OutboundOptions};
use rb_dialer::listener::Listener;
use rb_dialer::{new_outbound_dialer, socket_address, Dialer, DialerEnv};
use rb_route::nat::{KeyedNat, SessionWriter};
use rb_shadowsocks::server::{Accepted, ReplyEncoder, Service};
use rb_shadowsocks::tcp::ShadowStream;
use rb_shadowsocks::udp::ClientPacketCodec;
use rb_shadowsocks::ClientMethod;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::inbound::DEFAULT_UDP_TIMEOUT;
use crate::uot::{self, Request as UotRequest, UotPacketConn};

/// The `shadowsocks` outbound.
pub struct ShadowsocksOutbound {
    tag: String,
    dialer: Arc<dyn Dialer>,
    method: ClientMethod,
    server: Socksaddr,
    networks: Vec<Network>,
    /// The UoT version when `udp_over_tcp` is enabled.
    uot: Option<u8>,
    /// The sing-mux client when `multiplex` is enabled (and UoT is not).
    mux: Option<rb_mux::Client>,
}

impl ShadowsocksOutbound {
    /// sing-box `shadowsocks.NewOutbound`.
    pub fn new(options: &OutboundOptions, tag: String, env: &DialerEnv) -> Result<Arc<Self>, String> {
        let method = ClientMethod::new(&options.method, &options.password)?;
        let server = Socksaddr::from_host_port(&options.server, options.server_port);
        let dialer = new_outbound_dialer(
            &options.dialer_options(),
            server.domain().is_some(),
            env,
            &format!("outbound/shadowsocks[{tag}]"),
        )?;
        if !options.plugin.is_empty() {
            return Err("`plugin` is not supported by rust-box yet".into());
        }
        let uot = options.udp_over_tcp.as_ref().filter(|uot| uot.enabled).map(|uot| uot.version);
        // sing-box ignores `multiplex` with UoT.
        let multiplex =
            if uot.is_none() { crate::multiplex::client_options(options.multiplex.as_ref())? } else { None };
        let networks = options
            .network
            .build()
            .iter()
            .map(|network| if network == "udp" { Network::Udp } else { Network::Tcp })
            .collect();
        Ok(Arc::new_cyclic(|this| ShadowsocksOutbound {
            tag,
            dialer,
            method,
            server,
            networks,
            uot,
            mux: crate::multiplex::new_client(this, multiplex),
        }))
    }

    /// A shadowsocks TCP connection to `destination` through the server,
    /// its request header sent (sing-box `shadowsocksDialer.DialContext`
    /// for TCP with the header written at once, as sing-box's
    /// `kickWriteHandshake` does). A multiplex client dials its sessions
    /// with this.
    pub async fn connect(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let stream = self.dialer.dial_tcp(&self.server).await?;
        let mut stream = ShadowStream::client(&self.method, stream, destination)?;
        stream.flush().await?;
        Ok(Box::new(stream))
    }

    fn log_prefix(&self) -> String {
        format!("outbound/shadowsocks[{}]", self.tag)
    }
}

#[async_trait]
impl Outbound for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "shadowsocks"
    }

    fn networks(&self) -> &[Network] {
        &self.networks
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        match &self.mux {
            Some(mux) => mux.dial_tcp(&context.destination).await,
            None => self.connect(&context.destination).await,
        }
    }

    async fn listen_packet(&self, context: &InboundContext) -> io::Result<SharedPacketConn> {
        if let Some(mux) = &self.mux {
            return mux.listen_packet(&context.destination).await;
        }
        if let Some(version) = self.uot {
            let request = UotRequest { is_connect: context.udp_connect, destination: context.destination.clone() };
            if request.is_connect {
                info!("{}: outbound UoT connect packet connection to {}", self.log_prefix(), context.destination);
            } else {
                info!("{}: outbound UoT packet connection to {}", self.log_prefix(), context.destination);
            }
            if !matches!(version, 0 | uot::VERSION | uot::LEGACY_VERSION) {
                return Err(io::Error::other(format!("unknown protocol version: {version}")));
            }
            let stream = self.connect(&uot::request_destination(version)).await?;
            return Ok(Arc::new(UotPacketConn::client(stream, version, request).await?));
        }
        let conn = self.dialer.dial_udp(&self.server).await?;
        Ok(Arc::new(ShadowsocksPacketConn {
            conn,
            codec: ClientPacketCodec::new(&self.method),
            server: self.server.clone(),
        }))
    }
}

/// The outbound's UDP: one shadowsocks packet per datagram to the server
/// (sing-shadowsocks2 `clientPacketConn`).
pub struct ShadowsocksPacketConn {
    conn: SharedPacketConn,
    codec: ClientPacketCodec,
    server: Socksaddr,
}

#[async_trait]
impl PacketConn for ShadowsocksPacketConn {
    async fn read_packet(&self, buffer: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut packet = vec![0u8; MAX_PACKET_SIZE];
        let (length, _) = self.conn.read_packet(&mut packet).await?;
        packet.truncate(length);
        // A packet that does not decode ends the connection, as in sing.
        let (source, start) = self.codec.decode(&mut packet)?;
        let payload = &packet[start..];
        let length = payload.len().min(buffer.len());
        buffer[..length].copy_from_slice(&payload[..length]);
        Ok((length, source))
    }

    async fn write_packet(&self, data: &[u8], address: &Socksaddr) -> io::Result<()> {
        let packet = self.codec.encode(data, address)?;
        self.conn.write_packet(&packet, &self.server).await
    }
}

/// Which service an inbound runs (sing-box `NewInbound`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Single,
    Multi,
    Relay,
}

/// A NAT session: per client address, or per 2022 client session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum NatKey {
    Source(SocketAddr),
    Session(u64),
}

#[async_trait]
impl crate::multiplex::MuxConnect for ShadowsocksOutbound {
    async fn connect_mux(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        self.connect(destination).await
    }
}

/// The `shadowsocks` inbound.
pub struct ShadowsocksInbound {
    tag: String,
    kind: Kind,
    listener: Listener,
    tcp: bool,
    udp: bool,
    service: Arc<Service>,
    /// User (or relay destination) names by index.
    names: Vec<String>,
    /// Relay destinations by index.
    destinations: Vec<Socksaddr>,
    detour: Option<String>,
    udp_timeout: Duration,
    router: Arc<dyn ConnectionRouter>,
    nat: KeyedNat<NatKey>,
    /// The sing-mux server when `multiplex` is enabled.
    multiplex: Option<rb_mux::ServerOptions>,
    /// The inbound itself, for the streams of multiplexed connections.
    this: OnceLock<Weak<Self>>,
    local_addr: OnceLock<SocketAddr>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl ShadowsocksInbound {
    /// sing-box `shadowsocks.NewInbound`.
    pub fn new(options: &InboundOptions, tag: String, router: Arc<dyn ConnectionRouter>) -> Result<Self, String> {
        if !options.users.is_empty() && !options.destinations.is_empty() {
            return Err("users and destinations options must not be combined".into());
        }
        if options.managed && (!options.users.is_empty() || !options.destinations.is_empty()) {
            return Err("users and destinations options are not supported in managed servers".into());
        }
        let multiplex = crate::multiplex::server_options(options.multiplex.as_ref())?;
        let listen = options.listen_options();
        let udp_timeout = if listen.udp_timeout.0 .0.is_zero() { DEFAULT_UDP_TIMEOUT } else { listen.udp_timeout.0 .0 };
        let (kind, service, names, destinations) = if !options.users.is_empty() || options.managed {
            let passwords: Vec<String> = options.users.iter().map(|user| user.password.clone()).collect();
            let service = Service::multi(&options.method, &options.password, &passwords, udp_timeout)?;
            (Kind::Multi, service, options.users.iter().map(|user| user.name.clone()).collect(), Vec::new())
        } else if !options.destinations.is_empty() {
            let passwords: Vec<String> =
                options.destinations.iter().map(|destination| destination.password.clone()).collect();
            let service = Service::relay(&options.method, &options.password, &passwords, udp_timeout)?;
            let names = options.destinations.iter().map(|destination| destination.name.clone()).collect();
            let destinations = options
                .destinations
                .iter()
                .map(|destination| Socksaddr::from_host_port(&destination.server, destination.server_port))
                .collect();
            (Kind::Relay, service, names, destinations)
        } else {
            (Kind::Single, Service::single(&options.method, &options.password, udp_timeout)?, Vec::new(), Vec::new())
        };
        let networks = options.network.build();
        Ok(ShadowsocksInbound {
            tag,
            kind,
            listener: Listener::new(&listen)?,
            tcp: networks.iter().any(|network| network == "tcp"),
            udp: networks.iter().any(|network| network == "udp"),
            service: Arc::new(service),
            names,
            destinations,
            detour: (!listen.detour.is_empty()).then(|| listen.detour.clone()),
            udp_timeout,
            nat: KeyedNat::new(router.clone()),
            router,
            multiplex,
            this: OnceLock::new(),
            local_addr: OnceLock::new(),
            tasks: Mutex::new(Vec::new()),
        })
    }

    fn log_prefix(&self) -> String {
        format!("inbound/shadowsocks[{}]", self.tag)
    }

    /// The name a user is logged with, and the one routing sees (only a
    /// configured name: sing-box leaves `metadata.User` empty otherwise).
    fn user(&self, index: Option<usize>) -> (Option<String>, Option<String>) {
        let Some(index) = index else { return (None, None) };
        match self.names.get(index).filter(|name| !name.is_empty()) {
            Some(name) => (Some(name.clone()), Some(name.clone())),
            None => (Some(index.to_string()), None),
        }
    }

    fn log_target(&self, logged: &Option<String>, what: &str, target: &impl std::fmt::Display) {
        match logged {
            Some(user) => info!("{}: [{user}] {what} {target}", self.log_prefix()),
            None => info!("{}: {what} {target}", self.log_prefix()),
        }
    }

    /// Serves one TCP connection (sing-box `Inbound.NewConnection`).
    async fn handle(&self, stream: BoxStream, context: InboundContext) {
        let source = context.source;
        let accepted = match self.service.accept(stream).await {
            Ok(accepted) => accepted,
            Err(error) => {
                if is_closed(&error) {
                    debug!("{}: connection closed: {error}", self.log_prefix());
                } else {
                    error!(
                        "{}: process connection from {source}: shadowsocks: serve TCP from {source}: {error}",
                        self.log_prefix()
                    );
                }
                return;
            }
        };
        let (client, destination, user): (BoxStream, Socksaddr, Option<usize>) = match accepted {
            Accepted::Stream { stream, destination, user } => (Box::new(stream), destination, user),
            Accepted::Relay { io, prefix, user } => {
                (Box::new(PrefixedStream::new(prefix, io)), self.destinations[user].clone(), Some(user))
            }
        };
        let (logged, routed) = self.user(user);
        let mut context = context;
        context.inbound = self.tag.clone();
        context.inbound_type = "shadowsocks";
        context.network = Network::Tcp;
        context.user = routed;
        // sing-box sets the inbound detour of multi-user and relay
        // connections again here (the listener already did for TCP).
        if let Some(options) = self.multiplex.as_ref().filter(|_| rb_mux::is_destination(&destination)) {
            self.log_target(&logged, "inbound connection to", &destination);
            if let Some(this) = self.this.get().and_then(Weak::upgrade) {
                crate::multiplex::serve(this, options, context, client, self.log_prefix()).await;
            }
            return;
        }
        if let Err(error) = self.route(context, destination, client, &logged, true).await {
            error!("{}: process connection from {source}: {error}", self.log_prefix());
        }
    }

    /// Routes a request, or the UDP of a UoT request (sing-box `uot.Router`).
    async fn route(
        &self,
        mut context: InboundContext,
        destination: Socksaddr,
        mut client: BoxStream,
        logged: &Option<String>,
        log_destination: bool,
    ) -> io::Result<()> {
        let source = context.source;
        let request = match destination.domain() {
            Some(uot::MAGIC_ADDRESS) => {
                if log_destination {
                    self.log_target(logged, "inbound connection to", &destination);
                }
                let request = UotRequest::read(&mut client)
                    .await
                    .map_err(|error| io::Error::other(format!("read UoT request: {error}")))?;
                if request.is_connect {
                    info!("{}: inbound UoT connect connection to {}", self.log_prefix(), request.destination);
                } else {
                    info!("{}: inbound UoT connection to {}", self.log_prefix(), request.destination);
                }
                Some(request)
            }
            Some(uot::LEGACY_MAGIC_ADDRESS) => {
                if log_destination {
                    self.log_target(logged, "inbound connection to", &destination);
                }
                info!("{}: inbound legacy UoT connection", self.log_prefix());
                Some(UotRequest { is_connect: false, destination: Socksaddr::from_host_port("0.0.0.0", 0) })
            }
            _ => None,
        };
        let result = match request {
            Some(request) => {
                context.sniff_host = destination.domain().map(str::to_string);
                context.network = Network::Udp;
                context.destination = request.destination.clone();
                context.inbound_udp_timeout = Some(self.udp_timeout);
                let conn: SharedPacketConn = Arc::new(UotPacketConn::new(client, request));
                self.router.route_packet_connection(context, conn).await
            }
            None => {
                if log_destination {
                    self.log_target(logged, "inbound connection to", &destination);
                }
                context.destination = destination;
                self.router.route_connection(context, client).await
            }
        };
        match result {
            Ok(()) | Err(RouteError::Rejected) => {}
            Err(error) => warn!("{}: {source}: {error}", self.log_prefix()),
        }
        Ok(())
    }

    /// Takes one UDP packet (sing-box `Inbound.NewPacket`).
    fn new_packet(&self, socket: &Arc<UdpSocket>, dual_stack: bool, peer: SocketAddr, mut data: Vec<u8>) {
        let source = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        let packet = match self.service.decode_packet(&mut data) {
            Ok(packet) => packet,
            Err(error) => {
                error!(
                    "{}: process packet from {source}: shadowsocks: serve UDP from {source}: {error}",
                    self.log_prefix()
                );
                return;
            }
        };
        let destination = match self.kind {
            Kind::Relay => self.destinations[packet.user.expect("relay user")].clone(),
            _ => packet.destination.clone(),
        };
        let (logged, routed) = self.user(packet.user);
        let mut context = InboundContext::new(&self.tag, "shadowsocks", Network::Udp, source, destination.clone());
        context.user = routed;
        context.inbound_udp_timeout = Some(self.udp_timeout);
        // sing-box: only the multi-user and relay inbounds carry the detour
        // for packets.
        if self.kind != Kind::Single {
            context.inbound_detour = self.detour.clone();
        }
        let key = match packet.session {
            Some(session) => NatKey::Session(session),
            None => NatKey::Source(source),
        };
        let payload = data.split_off(packet.payload_start);
        let reply = packet.reply;
        let socket = socket.clone();
        let created = self.nat.new_packet(key, context, payload, move || {
            Arc::new(ReplyWriter { socket, reply, peer: socket_address(peer, dual_stack) })
        });
        if created {
            self.log_target(&logged, "inbound packet connection from", &source);
            self.log_target(&logged, "inbound packet connection to", &destination);
        }
    }
}

#[async_trait]
impl crate::multiplex::MuxRouteTarget for ShadowsocksInbound {
    async fn route_mux_stream(&self, context: InboundContext, destination: Socksaddr, stream: BoxStream) {
        let source = context.source;
        if let Err(error) = self.route(context, destination, stream, &None, false).await {
            error!("{}: process connection from {source}: {error}", self.log_prefix());
        }
    }

    async fn route_mux_packets(&self, mut context: InboundContext, destination: Socksaddr, conn: SharedPacketConn) {
        let source = context.source;
        context.network = Network::Udp;
        context.destination = destination;
        context.inbound_udp_timeout = Some(self.udp_timeout);
        match self.router.route_packet_connection(context, conn).await {
            Ok(()) | Err(RouteError::Rejected) => {}
            Err(error) => warn!("{}: {source}: {error}", self.log_prefix()),
        }
    }
}

/// Replies of one UDP session, encoded for its client.
struct ReplyWriter {
    socket: Arc<UdpSocket>,
    reply: ReplyEncoder,
    peer: SocketAddr,
}

#[async_trait]
impl SessionWriter for ReplyWriter {
    async fn write_packet(&self, data: &[u8], from: &Socksaddr) -> io::Result<()> {
        let packet = self.reply.encode(data, from)?;
        self.socket.send_to(&packet, self.peer).await.map(|_| ())
    }
}

/// sing `E.IsClosedOrCanceled` for a handshake: the client went away.
fn is_closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    )
}

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

#[async_trait]
impl Inbound for ShadowsocksInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "shadowsocks"
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr.get().copied()
    }

    async fn start(self: Arc<Self>) -> io::Result<()> {
        let _ = self.this.set(Arc::downgrade(&self));
        let mut tasks = Vec::new();
        if self.tcp {
            let listener = self.listener.listen_tcp()?;
            let local = listener.local_addr()?;
            let _ = self.local_addr.set(local);
            info!("{}: tcp server started at {}", self.log_prefix(), local);
            let inbound = self.clone();
            tasks.push(tokio::spawn(async move {
                let mut accept_delay = Duration::ZERO;
                loop {
                    match listener.accept().await {
                        Ok((stream, source)) => {
                            accept_delay = Duration::ZERO;
                            if let Err(error) = inbound.listener.accepted(&stream) {
                                debug!("{}: {source}: set socket options: {error}", inbound.log_prefix());
                            }
                            let origin = stream.local_addr().ok();
                            let inbound = inbound.clone();
                            tokio::spawn(async move {
                                info!("{}: inbound connection from {}", inbound.log_prefix(), source);
                                let mut context = InboundContext::new(
                                    &inbound.tag,
                                    "shadowsocks",
                                    Network::Tcp,
                                    canonical(source),
                                    Socksaddr::from(source),
                                );
                                context.origin_destination = origin;
                                context.inbound_detour = inbound.detour.clone();
                                inbound.handle(Box::new(stream), context).await
                            });
                        }
                        Err(error) => {
                            accept_delay = if accept_delay.is_zero() {
                                Duration::from_millis(5)
                            } else {
                                (accept_delay * 2).min(Duration::from_secs(1))
                            };
                            error!("{}: {error}, retrying in {accept_delay:?}", inbound.log_prefix());
                            tokio::time::sleep(accept_delay).await;
                        }
                    }
                }
            }));
        }
        if self.udp {
            let socket = Arc::new(self.listener.listen_udp()?);
            let local = socket.local_addr()?;
            let _ = self.local_addr.set(local);
            info!("{}: udp server started at {}", self.log_prefix(), local);
            let dual_stack = local.is_ipv6() && local.ip().is_unspecified();
            let inbound = self.clone();
            tasks.push(tokio::spawn(async move {
                let mut buffer = vec![0u8; MAX_PACKET_SIZE];
                loop {
                    match socket.recv_from(&mut buffer).await {
                        Ok((length, peer)) => {
                            inbound.new_packet(&socket, dual_stack, peer, buffer[..length].to_vec());
                        }
                        Err(error) => {
                            // A refused reply (ICMP) shows up as a receive
                            // error on Linux; the socket stays usable.
                            if error.kind() == io::ErrorKind::ConnectionRefused {
                                continue;
                            }
                            error!("{}: udp listener closed: {error}", inbound.log_prefix());
                            return;
                        }
                    }
                }
            }));
        }
        *self.tasks.lock().unwrap() = tasks;
        Ok(())
    }

    async fn close(&self) {
        for task in self.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
        self.nat.close();
    }

    /// A connection handed over by another inbound's `detour`.
    async fn new_connection(&self, context: InboundContext, stream: BoxStream) -> io::Result<()> {
        let mut context = context;
        context.inbound = self.tag.clone();
        context.inbound_type = "shadowsocks";
        self.handle(stream, context).await;
        Ok(())
    }
}
