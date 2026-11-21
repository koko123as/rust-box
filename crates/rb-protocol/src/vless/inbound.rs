//! The `vless` inbound (sing-box `protocol/vless/inbound.go` with
//! sing-vmess `vless.Service`): TCP, UDP, mux (XUDP) requests, Vision, and
//! UDP over TCP requests (sing-box wraps its router in `uot.NewRouter`).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{
    BoxStream, CachedPacketConn, ConnectionRouter, Inbound, InboundContext, Network, RouteError, SharedPacketConn,
    Socksaddr, MAX_PACKET_SIZE,
};
use rb_config::VlessInbound as InboundOptions;
use rb_dialer::listener::Listener;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use super::mux::{self, MuxHandler};
use super::outbound::VISION_WITHOUT_TLS;
use super::packet::{PacketAddrConn, ServerPacketConn, PACKET_ADDR_MAGIC};
use super::protocol::{self, VlessStream, COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, FLOW_VISION};
use super::vision::{RecordGate, RecordStream, VisionStream};
use crate::uot::{self, Request as UotRequest, UotPacketConn};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// sing-vmess `flowName`.
fn flow_name(flow: &str) -> &str {
    if flow.is_empty() {
        "none"
    } else {
        flow
    }
}

/// What routing a request needs, shared with the sessions of a mux
/// connection (also the vmess inbound's).
pub(crate) struct Routing {
    pub(crate) kind: &'static str,
    pub(crate) tag: String,
    pub(crate) names: Vec<String>,
    pub(crate) router: Arc<dyn ConnectionRouter>,
    /// The sing-mux server when `multiplex` is enabled.
    pub(crate) multiplex: Option<rb_mux::ServerOptions>,
}

impl Routing {
    fn log_prefix(&self) -> String {
        format!("inbound/{}[{}]", self.kind, self.tag)
    }

    /// The logged name of a user and the one routing sees (only a
    /// configured name: sing-box leaves `metadata.User` empty otherwise).
    fn user(&self, index: usize) -> (String, Option<String>) {
        match self.names.get(index).filter(|name| !name.is_empty()) {
            Some(name) => (name.clone(), Some(name.clone())),
            None => (index.to_string(), None),
        }
    }

    pub(crate) fn finish(&self, source: SocketAddr, result: Result<(), RouteError>) {
        match result {
            Ok(()) | Err(RouteError::Rejected) => {}
            Err(error) => warn!("{}: {source}: {error}", self.log_prefix()),
        }
    }

    /// sing-box `Inbound.newConnectionEx`, then the multiplex router and
    /// `uot.Router`.
    pub(crate) async fn route_connection(
        self: &Arc<Self>,
        mut context: InboundContext,
        user: usize,
        destination: Socksaddr,
        stream: BoxStream,
    ) {
        let (logged, routed) = self.user(user);
        info!("{}: [{logged}] inbound connection to {destination}", self.log_prefix());
        context.inbound = self.tag.clone();
        context.inbound_type = self.kind;
        context.user = routed;
        if let Some(options) = self.multiplex.as_ref().filter(|_| rb_mux::is_destination(&destination)) {
            crate::multiplex::serve(self.clone(), options, context, stream, self.log_prefix()).await;
            return;
        }
        self.route_stream(context, destination, stream).await;
    }

    /// `uot.Router` and the router, for a context with the user set.
    async fn route_stream(&self, mut context: InboundContext, destination: Socksaddr, mut stream: BoxStream) {
        let source = context.source;
        let request = match destination.domain() {
            Some(uot::MAGIC_ADDRESS) => match UotRequest::read(&mut stream).await {
                Ok(request) => {
                    if request.is_connect {
                        info!("{}: inbound UoT connect connection to {}", self.log_prefix(), request.destination);
                    } else {
                        info!("{}: inbound UoT connection to {}", self.log_prefix(), request.destination);
                    }
                    Some(request)
                }
                Err(error) => {
                    error!("{}: process connection from {source}: UoT read request: {error}", self.log_prefix());
                    return;
                }
            },
            Some(uot::LEGACY_MAGIC_ADDRESS) => {
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
                let conn: SharedPacketConn = Arc::new(UotPacketConn::new(stream, request));
                self.router.route_packet_connection(context, conn).await
            }
            None => {
                context.network = Network::Tcp;
                context.destination = destination;
                self.router.route_connection(context, stream).await
            }
        };
        self.finish(source, result);
    }

    /// sing-box `Inbound.newPacketConnectionEx`.
    pub(crate) async fn route_packet_connection(
        &self,
        mut context: InboundContext,
        user: usize,
        destination: Socksaddr,
        conn: SharedPacketConn,
    ) {
        let (logged, routed) = self.user(user);
        context.inbound = self.tag.clone();
        context.inbound_type = self.kind;
        context.user = routed;
        if destination.domain() == Some(PACKET_ADDR_MAGIC) {
            info!("{}: [{logged}] inbound packet addr connection", self.log_prefix());
        } else {
            info!("{}: [{logged}] inbound packet connection to {destination}", self.log_prefix());
        }
        self.route_packets(context, destination, conn).await;
    }

    /// Routes a packet connection of a context with the user set.
    async fn route_packets(&self, mut context: InboundContext, destination: Socksaddr, mut conn: SharedPacketConn) {
        context.network = Network::Udp;
        let source = context.source;
        if destination.domain() == Some(PACKET_ADDR_MAGIC) {
            // sing-box routes with no destination; rust-box needs one and
            // takes the first packet's.
            let addressed: SharedPacketConn =
                Arc::new(PacketAddrConn::new(conn, Socksaddr::from_host_port("0.0.0.0", 0)));
            let mut buffer = vec![0u8; MAX_PACKET_SIZE];
            let (length, first) = match addressed.read_packet(&mut buffer).await {
                Ok(read) => read,
                Err(error) => {
                    debug!("{}: {source}: packet addr: {error}", self.log_prefix());
                    return;
                }
            };
            buffer.truncate(length);
            context.destination = first.clone();
            conn = Arc::new(CachedPacketConn::new(vec![(buffer, first)], addressed));
        } else {
            context.destination = destination;
        }
        self.finish(source, self.router.route_packet_connection(context, conn).await);
    }
}

#[async_trait]
impl crate::multiplex::MuxRouteTarget for Routing {
    async fn route_mux_stream(&self, context: InboundContext, destination: Socksaddr, stream: BoxStream) {
        self.route_stream(context, destination, stream).await;
    }

    async fn route_mux_packets(&self, context: InboundContext, destination: Socksaddr, conn: SharedPacketConn) {
        self.route_packets(context, destination, conn).await;
    }
}

/// The sessions of one mux connection.
pub(crate) struct MuxSessions {
    pub(crate) routing: Arc<Routing>,
    pub(crate) context: InboundContext,
    pub(crate) user: usize,
}

#[async_trait]
impl MuxHandler for MuxSessions {
    async fn new_connection(self: Arc<Self>, destination: Socksaddr, stream: BoxStream) {
        self.routing.route_connection(self.context.clone(), self.user, destination, stream).await;
    }

    async fn new_packet_connection(self: Arc<Self>, destination: Socksaddr, conn: SharedPacketConn) {
        self.routing.route_packet_connection(self.context.clone(), self.user, destination, conn).await;
    }
}

/// A client connection after the inbound TLS: typed for Vision.
enum ClientConn {
    /// With the gate of its record stream (Vision).
    Tls(Box<rb_tls::TlsServerStream>, RecordGate),
    Plain(BoxStream),
}

impl ClientConn {
    fn boxed(self) -> BoxStream {
        match self {
            ClientConn::Tls(stream, _) => stream,
            ClientConn::Plain(stream) => stream,
        }
    }
}

/// The `vless` inbound.
pub struct VlessInbound {
    tag: String,
    listener: Listener,
    routing: Arc<Routing>,
    users: HashMap<[u8; 16], usize>,
    flows: Vec<String>,
    tls: Option<rb_tls::TlsServer>,
    /// Whether TLS runs over a [`RecordStream`] (some user has Vision).
    record_stream: bool,
    detour: Option<String>,
    local_addr: OnceLock<SocketAddr>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl VlessInbound {
    /// sing-box `vless.NewInbound`.
    pub fn new(options: &InboundOptions, tag: String, router: Arc<dyn ConnectionRouter>) -> Result<Self, String> {
        let multiplex = crate::multiplex::server_options(options.multiplex.as_ref())?;
        // sing-vmess `UpdateUsers`: a later user with the same id wins.
        let mut users = HashMap::new();
        for (index, user) in options.users.iter().enumerate() {
            users.insert(protocol::parse_uuid(&user.uuid), index);
        }
        let tls = match options.tls.as_ref().filter(|tls| tls.enabled) {
            Some(tls) => Some(rb_tls::TlsServer::new(tls)?),
            None => None,
        };
        if options.transport.is_some() {
            return Err("`transport` is not supported by rust-box yet".into());
        }
        let listen = options.listen_options();
        let record_stream = tls.is_some() && options.users.iter().any(|user| user.flow == FLOW_VISION);
        Ok(VlessInbound {
            routing: Arc::new(Routing {
                kind: "vless",
                tag: tag.clone(),
                names: options.users.iter().map(|user| user.name.clone()).collect(),
                router,
                multiplex,
            }),
            tag,
            listener: Listener::new(&listen)?,
            users,
            flows: options.users.iter().map(|user| user.flow.clone()).collect(),
            tls,
            record_stream,
            detour: (!listen.detour.is_empty()).then(|| listen.detour.clone()),
            local_addr: OnceLock::new(),
            task: Mutex::new(None),
        })
    }

    fn log_prefix(&self) -> String {
        format!("inbound/vless[{}]", self.tag)
    }

    /// Serves one connection (sing-box `Inbound.NewConnection`).
    async fn handle(&self, stream: BoxStream, context: InboundContext) {
        let source = context.source;
        let conn = match &self.tls {
            Some(tls) => {
                let (stream, gate): (BoxStream, RecordGate) = if self.record_stream {
                    let stream = RecordStream::new(stream);
                    let gate = stream.gate();
                    (Box::new(stream), gate)
                } else {
                    (stream, RecordGate::default())
                };
                match tls.handshake(stream).await {
                    Ok(stream) => ClientConn::Tls(Box::new(stream), gate),
                    Err(error) => {
                        error!("{}: process connection from {source}: TLS handshake: {error}", self.log_prefix());
                        return;
                    }
                }
            }
            None => ClientConn::Plain(stream),
        };
        if let Err(error) = self.serve(conn, context).await {
            error!("{}: process connection from {source}: {error}", self.log_prefix());
        }
    }

    /// sing-vmess `Service.NewConnection`.
    async fn serve(&self, mut conn: ClientConn, context: InboundContext) -> io::Result<()> {
        let request = match &mut conn {
            ClientConn::Tls(stream, _) => protocol::read_request(stream.as_mut()).await?,
            ClientConn::Plain(stream) => protocol::read_request(stream).await?,
        };
        let Some(&user) = self.users.get(&request.uuid) else {
            return Err(invalid(format!("unknown UUID: {}", protocol::uuid_string(&request.uuid))));
        };
        let user_flow = self.flows[user].as_str();
        if request.flow == FLOW_VISION && request.command == COMMAND_UDP {
            return Err(invalid(format!("{FLOW_VISION} flow does not support UDP")));
        } else if request.flow != user_flow {
            return Err(invalid(format!(
                "flow mismatch: expected {}, but got {}",
                flow_name(user_flow),
                flow_name(&request.flow)
            )));
        }
        let destination = request.destination.clone();
        if request.command == COMMAND_UDP {
            let destination = destination.expect("UDP request destination");
            let conn: SharedPacketConn = Arc::new(ServerPacketConn::new(conn.boxed(), destination.clone()));
            self.routing.route_packet_connection(context, user, destination, conn).await;
            return Ok(());
        }
        let stream: BoxStream = match user_flow {
            FLOW_VISION => match conn {
                ClientConn::Tls(stream, gate) => {
                    Box::new(VisionStream::new(VlessStream::server(*stream), request.uuid, gate))
                }
                ClientConn::Plain(_) => return Err(io::Error::other(VISION_WITHOUT_TLS)),
            },
            "" => Box::new(VlessStream::server(conn.boxed())),
            flow => return Err(invalid(format!("unknown flow: {flow}"))),
        };
        match request.command {
            COMMAND_TCP => {
                let destination = destination.expect("TCP request destination");
                self.routing.route_connection(context, user, destination, stream).await;
                Ok(())
            }
            COMMAND_MUX => {
                let sessions = Arc::new(MuxSessions { routing: self.routing.clone(), context, user });
                Err(mux::serve(stream, sessions).await)
            }
            command => Err(invalid(format!("unknown command: {command}"))),
        }
    }
}

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

#[async_trait]
impl Inbound for VlessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "vless"
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr.get().copied()
    }

    async fn start(self: Arc<Self>) -> io::Result<()> {
        if let Some(tls) = &self.tls {
            tls.start().map_err(io::Error::other)?;
        }
        let listener = self.listener.listen_tcp()?;
        let local = listener.local_addr()?;
        let _ = self.local_addr.set(local);
        info!("{}: tcp server started at {}", self.log_prefix(), local);
        let inbound = self.clone();
        let task = tokio::spawn(async move {
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
                                "vless",
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
        });
        *self.task.lock().unwrap() = Some(task);
        Ok(())
    }

    async fn close(&self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
        if let Some(tls) = &self.tls {
            tls.close();
        }
    }

    /// A connection handed over by another inbound's `detour`.
    async fn new_connection(&self, context: InboundContext, stream: BoxStream) -> io::Result<()> {
        let mut context = context;
        context.inbound = self.tag.clone();
        context.inbound_type = "vless";
        self.handle(stream, context).await;
        Ok(())
    }
}
