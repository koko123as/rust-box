//! The `vmess` inbound (sing-box `protocol/vmess/inbound.go` with
//! sing-vmess `Service`): TCP, UDP and mux (XUDP) requests, the AEAD and
//! the legacy (alterId) headers, UDP over TCP requests and TLS.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{BoxStream, ConnectionRouter, Inbound, InboundContext, Network, SharedPacketConn, Socksaddr};
use rb_config::VmessInbound as InboundOptions;
use rb_dialer::listener::Listener;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use super::protocol::{COMMAND_MUX, COMMAND_TCP, COMMAND_UDP};
use super::session::{ServerUsers, LEGACY_UPDATE_INTERVAL};
use super::stream::{VmessPacketConn, VmessStream};
use crate::vless::inbound::{MuxSessions, Routing};
use crate::vless::{mux, protocol::parse_uuid};

/// The `vmess` inbound.
pub struct VmessInbound {
    tag: String,
    listener: Listener,
    routing: Arc<Routing>,
    users: Arc<ServerUsers>,
    tls: Option<rb_tls::TlsServer>,
    transport: Option<crate::v2ray::StreamTransport>,
    this: OnceLock<Weak<Self>>,
    detour: Option<String>,
    local_addr: OnceLock<SocketAddr>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl VmessInbound {
    /// sing-box `vmess.NewInbound`.
    pub fn new(options: &InboundOptions, tag: String, router: Arc<dyn ConnectionRouter>) -> Result<Self, String> {
        let transport = crate::v2ray::transport_options(options.transport.as_ref())?;
        let multiplex = crate::multiplex::server_options(options.multiplex.as_ref())?;
        let users: Vec<([u8; 16], i64)> =
            options.users.iter().map(|user| (parse_uuid(&user.uuid), user.alter_id)).collect();
        let tls = match options.tls.as_ref().filter(|tls| tls.enabled) {
            Some(tls) => Some(crate::v2ray::transport_tls_server(tls, transport.as_ref())?),
            None => None,
        };
        let listen = options.listen_options();
        Ok(VmessInbound {
            routing: Arc::new(Routing {
                kind: "vmess",
                tag: tag.clone(),
                names: options.users.iter().map(|user| user.name.clone()).collect(),
                router,
                multiplex,
            }),
            tag,
            listener: Listener::new(&listen)?,
            users: Arc::new(ServerUsers::new(&users)),
            tls,
            transport,
            this: OnceLock::new(),
            detour: (!listen.detour.is_empty()).then(|| listen.detour.clone()),
            local_addr: OnceLock::new(),
            tasks: Mutex::new(Vec::new()),
        })
    }

    fn log_prefix(&self) -> String {
        format!("inbound/vmess[{}]", self.tag)
    }

    /// Serves one connection (sing-box `Inbound.NewConnection`).
    async fn handle(&self, stream: BoxStream, context: InboundContext) {
        let source = context.source;
        let (mut stream, alpn) = match &self.tls {
            Some(tls) => match tls.handshake(stream).await {
                Ok(stream) => {
                    let alpn =
                        stream.get_ref().1.alpn_protocol().map(|alpn| String::from_utf8_lossy(alpn).into_owned());
                    (Box::new(stream) as BoxStream, alpn)
                }
                Err(error) => {
                    error!("{}: process connection from {source}: TLS handshake: {error}", self.log_prefix());
                    return;
                }
            },
            None => (stream, None),
        };
        if let Some(crate::v2ray::StreamTransport::Http(options)) = &self.transport {
            let session =
                match crate::v2ray::http::server_session(stream, options, self.tls.is_some(), alpn.as_deref()).await {
                    Ok(session) => session,
                    Err(error) => {
                        error!("{}: process HTTP connection from {source}: {error}", self.log_prefix());
                        return;
                    }
                };
            match session {
                crate::v2ray::http::ServerSession::Http1(stream) => {
                    if let Err(error) = self.serve(stream, context).await {
                        error!("{}: process HTTP/1.1 stream from {source}: {error}", self.log_prefix());
                    }
                }
                crate::v2ray::http::ServerSession::Http2(server) => {
                    let Some(inbound) = self.this.get().and_then(Weak::upgrade) else {
                        error!("{}: HTTP handler is not initialized", self.log_prefix());
                        return;
                    };
                    loop {
                        let stream = match server.accept().await {
                            Ok(Some(stream)) => stream,
                            Ok(None) => return,
                            Err(error) => {
                                error!("{}: process HTTP/2 connection from {source}: {error}", self.log_prefix());
                                return;
                            }
                        };
                        let inbound = inbound.clone();
                        let context = context.clone();
                        tokio::spawn(async move {
                            if let Err(error) = inbound.serve(stream, context).await {
                                error!("{}: process HTTP/2 stream from {source}: {error}", inbound.log_prefix());
                            }
                        });
                    }
                }
            }
            return;
        }
        if let Some(crate::v2ray::StreamTransport::Grpc(options)) = &self.transport {
            let server = crate::v2ray::grpc_lite::GrpcLiteServer::new(stream, options);
            let Some(inbound) = self.this.get().and_then(Weak::upgrade) else {
                error!("{}: gRPC handler is not initialized", self.log_prefix());
                return;
            };
            loop {
                let stream = match server.accept().await {
                    Ok(Some(stream)) => stream,
                    Ok(None) => return,
                    Err(error) => {
                        error!("{}: process gRPC connection from {source}: {error}", self.log_prefix());
                        return;
                    }
                };
                let inbound = inbound.clone();
                let context = context.clone();
                tokio::spawn(async move {
                    let log_prefix = inbound.log_prefix();
                    if let Err(error) = inbound.serve(stream, context).await {
                        error!("{log_prefix}: process gRPC stream from {source}: {error}");
                    }
                });
            }
        }
        if let Some(transport) = &self.transport {
            stream = match crate::v2ray::transport_server(stream, transport).await {
                Ok(stream) => stream,
                Err(error) => {
                    error!(
                        "{}: process connection from {source}: {} handshake: {error}",
                        self.log_prefix(),
                        transport.log_name()
                    );
                    return;
                }
            };
        }
        if let Err(error) = self.serve(stream, context).await {
            error!("{}: process connection from {source}: {error}", self.log_prefix());
        }
    }

    /// sing-vmess `Service.NewConnection`.
    async fn serve(&self, mut stream: BoxStream, context: InboundContext) -> io::Result<()> {
        let request = self.users.read_request(&mut stream).await?;
        let user = request.user;
        match request.command {
            COMMAND_TCP => {
                let destination = request.destination.expect("TCP request destination");
                let stream: BoxStream = Box::new(VmessStream::new(stream, request.writer, request.reader));
                self.routing.route_connection(context, user, destination, stream).await;
                Ok(())
            }
            COMMAND_UDP => {
                let destination = request.destination.expect("UDP request destination");
                let conn: SharedPacketConn =
                    Arc::new(VmessPacketConn::new(stream, request.writer, request.reader, destination.clone()));
                self.routing.route_packet_connection(context, user, destination, conn).await;
                Ok(())
            }
            COMMAND_MUX => {
                let stream: BoxStream = Box::new(VmessStream::new(stream, request.writer, request.reader));
                let sessions = Arc::new(MuxSessions { routing: self.routing.clone(), context, user });
                Err(mux::serve(stream, sessions).await)
            }
            command => Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown command: {command}"))),
        }
    }
}

fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

#[async_trait]
impl Inbound for VmessInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "vmess"
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr.get().copied()
    }

    async fn start(self: Arc<Self>) -> io::Result<()> {
        let _ = self.this.set(Arc::downgrade(&self));
        if self.users.has_legacy() {
            // sing-vmess `Service.Start`: the legacy keys move every ten
            // seconds.
            let users = self.users.clone();
            self.tasks.lock().unwrap().push(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(LEGACY_UPDATE_INTERVAL);
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    users.generate_legacy_keys();
                }
            }));
        }
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
                                "vmess",
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
        self.tasks.lock().unwrap().push(task);
        Ok(())
    }

    async fn close(&self) {
        for task in self.tasks.lock().unwrap().drain(..) {
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
        context.inbound_type = "vmess";
        self.handle(stream, context).await;
        Ok(())
    }
}
