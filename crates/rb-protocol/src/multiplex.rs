//! The `multiplex` field of the shadowsocks, trojan, vless and vmess
//! inbounds and outbounds (sing-box `common/mux`): the outbound's sing-mux
//! client dials its sessions with the outbound's own connection, the
//! inbound hands connections to `sp.mux.sing-box.arpa:444` to the sing-mux
//! server and routes its streams with the connection's metadata.

use std::io;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use rb_adapter::{BoxStream, InboundContext, SharedPacketConn, Socksaddr};
use rb_config::{InboundMultiplexOptions, OutboundMultiplexOptions};

/// sing-box `NewClientWithOptions`: `None` when not enabled.
pub(crate) fn client_options(
    options: Option<&OutboundMultiplexOptions>,
) -> Result<Option<rb_mux::ClientOptions>, String> {
    let Some(options) = options.filter(|options| options.enabled) else { return Ok(None) };
    if options.brutal.as_ref().is_some_and(|brutal| brutal.enabled) {
        return Err("`brutal` is not supported by rust-box yet".into());
    }
    let count = |value: i64| value.max(0) as usize;
    rb_mux::ClientOptions::new(
        &options.protocol,
        count(options.max_connections),
        count(options.min_streams),
        count(options.max_streams),
        options.padding,
    )
    .map(Some)
}

/// sing-box `NewRouterWithOptions`: `None` when not enabled.
pub(crate) fn server_options(
    options: Option<&InboundMultiplexOptions>,
) -> Result<Option<rb_mux::ServerOptions>, String> {
    let Some(options) = options.filter(|options| options.enabled) else { return Ok(None) };
    if options.brutal.as_ref().is_some_and(|brutal| brutal.enabled) {
        return Err("`brutal` is not supported by rust-box yet".into());
    }
    Ok(Some(rb_mux::ServerOptions { padding: options.padding }))
}

/// An outbound's own connection to a destination, which its multiplex
/// client opens sessions with.
#[async_trait]
pub(crate) trait MuxConnect: Send + Sync + 'static {
    async fn connect_mux(&self, destination: &Socksaddr) -> io::Result<BoxStream>;
}

/// The outbound seen by its own multiplex client (weak, as the client
/// lives in the outbound).
struct WeakDialer<T>(Weak<T>);

#[async_trait]
impl<T: MuxConnect> rb_mux::MuxDialer for WeakDialer<T> {
    async fn dial(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let outbound = self.0.upgrade().ok_or_else(|| io::Error::other("outbound closed"))?;
        outbound.connect_mux(destination).await
    }
}

/// The multiplex client of an outbound being built with
/// `Arc::new_cyclic`.
pub(crate) fn new_client<T: MuxConnect>(
    outbound: &Weak<T>,
    options: Option<rb_mux::ClientOptions>,
) -> Option<rb_mux::Client> {
    options.map(|options| rb_mux::Client::new(Arc::new(WeakDialer(outbound.clone())), options))
}

/// Where an inbound routes the streams of a multiplexed connection.
#[async_trait]
pub(crate) trait MuxRouteTarget: Send + Sync + 'static {
    async fn route_mux_stream(&self, context: InboundContext, destination: Socksaddr, stream: BoxStream);
    async fn route_mux_packets(&self, context: InboundContext, destination: Socksaddr, conn: SharedPacketConn);
}

struct MuxRoute<T> {
    target: Arc<T>,
    context: InboundContext,
}

#[async_trait]
impl<T: MuxRouteTarget> rb_mux::ServerHandler for MuxRoute<T> {
    async fn new_connection(self: Arc<Self>, destination: Socksaddr, stream: BoxStream) {
        self.target.route_mux_stream(self.context.clone(), destination, stream).await;
    }

    async fn new_packet_connection(self: Arc<Self>, destination: Socksaddr, conn: SharedPacketConn) {
        self.target.route_mux_packets(self.context.clone(), destination, conn).await;
    }
}

/// Serves a connection to the multiplex destination: its streams go to
/// `target` with `context` (the connection's metadata).
pub(crate) async fn serve<T: MuxRouteTarget>(
    target: Arc<T>,
    options: &rb_mux::ServerOptions,
    context: InboundContext,
    stream: BoxStream,
    log_prefix: String,
) {
    let source = context.source;
    rb_mux::serve(stream, source, options, Arc::new(MuxRoute { target, context }), log_prefix).await;
}
