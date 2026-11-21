//! The `socks`, `http` and `mixed` inbounds: a TCP listener, the protocol
//! handshake, then the connection handed to the router (sing-box
//! `protocol/{socks,http,mixed}/inbound.go` with `common/listener`).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};

use async_trait::async_trait;
use rb_adapter::{BoxStream, ConnectionRouter, Inbound, InboundContext, Network, PrefixedStream, RouteError};
use rb_config::ProxyInbound as ProxyInboundOptions;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

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

pub struct ProxyInbound {
    tag: String,
    kind: ProxyKind,
    listen: SocketAddr,
    users: Arc<HashMap<String, String>>,
    router: Arc<dyn ConnectionRouter>,
    local_addr: OnceLock<SocketAddr>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl ProxyInbound {
    pub fn new(kind: ProxyKind, options: &ProxyInboundOptions, tag: String, router: Arc<dyn ConnectionRouter>) -> Self {
        let ip = options.listen.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let users = options.users.iter().map(|user| (user.username.clone(), user.password.clone())).collect();
        ProxyInbound {
            tag,
            kind,
            listen: SocketAddr::new(ip, options.listen_port),
            users: Arc::new(users),
            router,
            local_addr: OnceLock::new(),
            task: Mutex::new(None),
        }
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
        let listener = TcpListener::bind(self.listen)
            .await
            .map_err(|error| io::Error::new(error.kind(), format!("listen {}: {error}", self.listen)))?;
        let local = listener.local_addr()?;
        let _ = self.local_addr.set(local);
        info!("inbound/{}[{}]: tcp server started at {}", self.kind.name(), self.tag, local);
        let inbound = self.clone();
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, source)) => {
                        let inbound = inbound.clone();
                        tokio::spawn(async move { inbound.handle(stream, source).await });
                    }
                    Err(error) => {
                        warn!("inbound/{}[{}]: accept: {error}", inbound.kind.name(), inbound.tag);
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
}

impl ProxyInbound {
    async fn handle(&self, mut stream: TcpStream, source: SocketAddr) {
        let _ = stream.set_nodelay(true);
        info!("inbound/{}[{}]: inbound connection from {}", self.kind.name(), self.tag, source);
        let kind = match self.kind {
            ProxyKind::Mixed => {
                let mut first = [0u8; 1];
                match stream.peek(&mut first).await {
                    Ok(1) if first[0] == socks::VERSION4 || first[0] == socks::VERSION5 => ProxyKind::Socks,
                    Ok(1) => ProxyKind::Http,
                    _ => return,
                }
            }
            kind => kind,
        };
        let result = match kind {
            ProxyKind::Socks => match socks::handshake(&mut stream, &self.users).await {
                Ok(request) => self.route(source, request.destination, request.user, Box::new(stream)).await,
                Err(error) => Err(error),
            },
            _ => match http::handshake(&mut stream, &self.users).await {
                Ok(request) => {
                    let client: BoxStream = if request.initial.is_empty() {
                        Box::new(stream)
                    } else {
                        // For a plain request the rewritten head goes to the
                        // destination first; it travels as if the client
                        // had sent it.
                        Box::new(PrefixedStream::new(request.initial, stream))
                    };
                    self.route(source, request.destination, request.user, client).await
                }
                Err(error) => Err(error),
            },
        };
        if let Err(error) = result {
            debug!("inbound/{}[{}]: {source}: {error}", self.kind.name(), self.tag);
        }
    }

    async fn route(
        &self,
        source: SocketAddr,
        destination: rb_adapter::Socksaddr,
        user: Option<String>,
        client: BoxStream,
    ) -> io::Result<()> {
        info!("inbound/{}[{}]: inbound connection to {}", self.kind.name(), self.tag, destination);
        let mut context = InboundContext::new(&self.tag, self.kind.name(), Network::Tcp, source, destination);
        context.user = user;
        match self.router.route_connection(context, client).await {
            Ok(()) => Ok(()),
            Err(RouteError::Rejected) => Ok(()),
            Err(error) => {
                warn!("inbound/{}[{}]: {source}: {error}", self.kind.name(), self.tag);
                Ok(())
            }
        }
    }
}
