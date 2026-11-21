//! The `socks`, `http` and `mixed` inbounds: a TCP listener with the listen
//! fields applied, the protocol handshake, then the connection handed to
//! the router (sing-box `protocol/{socks,http,mixed}/inbound.go` with
//! `common/listener`).
//!
//! A SOCKS5 UDP ASSOCIATE (in `socks` and `mixed`) opens a UDP socket on the
//! address the client reached, reads the first packet and hands the whole
//! association to the router as one packet connection, which lives until it
//! is idle for `udp_timeout` or the control connection closes (sing
//! `socks.HandleConnectionEx`).
//!
//! With the listen field `detour`, connections accepted here carry the
//! detour inbound in their context and the router hands them to it after
//! this inbound's handshake (sing-box `metadata.InboundDetour`). These
//! inbounds also take connections handed over that way
//! ([`Inbound::new_connection`]).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{
    BoxStream, CachedPacketConn, ConnectionRouter, Inbound, InboundContext, Network, PrefixedStream, RouteError,
    SharedPacketConn, Socksaddr, MAX_PACKET_SIZE,
};
use rb_config::ProxyInbound as ProxyInboundOptions;
use rb_dialer::listener::Listener;
use tokio::io::AsyncReadExt;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::{http, socks};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Socks,
    Http,
    /// Detects SOCKS or HTTP by the first byte (sing-box `protocol/mixed`).
    Mixed,
}

impl ProxyKind {
    fn name(self) -> &'static str {
        match self {
            ProxyKind::Socks => "socks",
            ProxyKind::Http => "http",
            ProxyKind::Mixed => "mixed",
        }
    }
}

/// sing-box `C.UDPTimeout`.
pub const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(300);

pub struct ProxyInbound {
    tag: String,
    kind: ProxyKind,
    listener: Listener,
    detour: Option<String>,
    users: Arc<HashMap<String, String>>,
    udp_timeout: Duration,
    router: Arc<dyn ConnectionRouter>,
    local_addr: OnceLock<SocketAddr>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl ProxyInbound {
    pub fn new(
        kind: ProxyKind,
        options: &ProxyInboundOptions,
        tag: String,
        router: Arc<dyn ConnectionRouter>,
    ) -> Result<Self, String> {
        let listen = options.listen_options();
        let listener = Listener::new(&listen)?;
        let users = options.users.iter().map(|user| (user.username.clone(), user.password.clone())).collect();
        Ok(ProxyInbound {
            tag,
            kind,
            listener,
            detour: (!listen.detour.is_empty()).then(|| listen.detour.clone()),
            users: Arc::new(users),
            udp_timeout: if listen.udp_timeout.0 .0.is_zero() { DEFAULT_UDP_TIMEOUT } else { listen.udp_timeout.0 .0 },
            router,
            local_addr: OnceLock::new(),
            task: Mutex::new(None),
        })
    }

    fn log_prefix(&self) -> String {
        format!("inbound/{}[{}]", self.kind.name(), self.tag)
    }
}

#[async_trait]
impl Inbound for ProxyInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        self.kind.name()
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr.get().copied()
    }

    async fn start(self: Arc<Self>) -> io::Result<()> {
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
                                inbound.kind.name(),
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
                        // sing-box's backoff for temporary accept errors.
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
    }

    /// A connection handed over by another inbound's `detour`: served as if
    /// accepted here, keeping the source and the first inbound's addresses.
    async fn new_connection(&self, context: InboundContext, stream: BoxStream) -> io::Result<()> {
        let mut context = context;
        context.inbound = self.tag.clone();
        context.inbound_type = self.kind.name();
        self.handle(stream, context).await;
        Ok(())
    }
}

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// The HTTP server's connections, routed with the inbound's context.
struct HttpHandler<'a> {
    inbound: &'a ProxyInbound,
    base: &'a InboundContext,
}

#[async_trait]
impl http::ConnectionHandler for HttpHandler<'_> {
    async fn new_connection(
        &self,
        source: SocketAddr,
        destination: Socksaddr,
        user: Option<String>,
        stream: BoxStream,
    ) {
        let mut context = self.base.clone();
        context.source = source;
        let _ = self.inbound.route(context, destination, user, stream).await;
    }
}

impl ProxyInbound {
    /// Serves one client connection; `context` carries the source, the
    /// local address and any inbound detour.
    async fn handle(&self, mut stream: BoxStream, context: InboundContext) {
        let source = context.source;
        let kind = match self.kind {
            ProxyKind::Mixed => {
                let mut first = [0u8; 1];
                match stream.read(&mut first).await {
                    Ok(1) => {
                        stream = Box::new(PrefixedStream::new(first.to_vec(), stream));
                        if first[0] == socks::VERSION4 || first[0] == socks::VERSION5 {
                            ProxyKind::Socks
                        } else {
                            ProxyKind::Http
                        }
                    }
                    _ => return,
                }
            }
            kind => kind,
        };
        let result = match kind {
            ProxyKind::Socks => match socks::handshake(&mut stream, &self.users).await {
                Ok(request) if request.command == socks::Command::UdpAssociate => {
                    self.associate(stream, context, request.user).await
                }
                Ok(request) => self.route(context, request.destination, request.user, stream).await,
                Err(error) => Err(error),
            },
            _ => {
                let handler = HttpHandler { inbound: self, base: &context };
                http::serve(stream, &self.users, &handler, source).await
            }
        };
        if let Err(error) = result {
            debug!("{}: {source}: {error}", self.log_prefix());
        }
    }

    /// Serves a UDP ASSOCIATE until the session ends or the control
    /// connection closes; then the socket and the connection close together.
    async fn associate(&self, mut control: BoxStream, context: InboundContext, user: Option<String>) -> io::Result<()> {
        let source = context.source;
        let local_ip = context.origin_destination.map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |local| local.ip());
        let socket = self
            .listener
            .listen_packet(SocketAddr::new(local_ip, 0))
            .map_err(|error| io::Error::new(error.kind(), format!("socks5: listen udp: {error}")))?;
        let bind = socket.local_addr()?;
        socks::write_bind_reply(&mut control, &Socksaddr::from(bind)).await?;
        let conn: SharedPacketConn = Arc::new(socks::AssociatePacketConn::new(socket, source.ip()));
        let mut buffer = vec![0u8; MAX_PACKET_SIZE];
        let mut closed = [0u8; 1];
        let (length, destination) = tokio::select! {
            read = tokio::time::timeout(self.udp_timeout, conn.read_packet(&mut buffer)) => match read {
                Ok(read) => read?,
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "socks5: read first packet: timed out")),
            },
            _ = control.read(&mut closed) => return Ok(()),
        };
        buffer.truncate(length);
        let conn: SharedPacketConn = Arc::new(CachedPacketConn::new(vec![(buffer, destination.clone())], conn));
        match &user {
            Some(user) => info!("{}: [{user}] inbound packet connection to {destination}", self.log_prefix()),
            None => info!("{}: inbound packet connection to {destination}", self.log_prefix()),
        }
        let mut context = context;
        context.inbound = self.tag.clone();
        context.inbound_type = self.kind.name();
        context.network = Network::Udp;
        context.destination = destination;
        context.user = user;
        context.inbound_udp_timeout = Some(self.udp_timeout);
        tokio::select! {
            result = self.router.route_packet_connection(context, conn) => match result {
                Ok(()) | Err(RouteError::Rejected) => {}
                Err(error) => warn!("{}: {source}: {error}", self.log_prefix()),
            },
            // Anything on the control connection, or its end, ends the association.
            _ = control.read(&mut closed) => debug!("{}: {source}: UDP association closed", self.log_prefix()),
        }
        Ok(())
    }

    async fn route(
        &self,
        context: InboundContext,
        destination: Socksaddr,
        user: Option<String>,
        client: BoxStream,
    ) -> io::Result<()> {
        let source = context.source;
        match &user {
            Some(user) => info!("{}: [{user}] inbound connection to {destination}", self.log_prefix()),
            None => info!("{}: inbound connection to {destination}", self.log_prefix()),
        }
        let mut context = context;
        context.inbound = self.tag.clone();
        context.inbound_type = self.kind.name();
        context.network = Network::Tcp;
        context.destination = destination;
        context.user = user;
        match self.router.route_connection(context, client).await {
            Ok(()) | Err(RouteError::Rejected) => {}
            Err(error) => warn!("{}: {source}: {error}", self.log_prefix()),
        }
        Ok(())
    }
}
