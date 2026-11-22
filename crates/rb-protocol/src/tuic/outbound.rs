//! TUIC v5 TCP client runtime, following sing-quic `tuic.Client`.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use super::wire;
use async_trait::async_trait;
use rb_adapter::{BoxStream, InboundContext, Network, Outbound, Socksaddr};
use rb_config::{QuicOptions, TuicOutbound as OutboundOptions};
use rb_dialer::{new_outbound_dialer, Dialer, DialerEnv};

/// A TUIC v5 outbound. This substep implements TCP streams; UDP network
/// requests are rejected during configuration validation until its packet
/// sessions and fragmentation lifetime are wired end-to-end.
pub struct TuicOutbound {
    tag: String,
    dialer: Arc<dyn Dialer>,
    server: Socksaddr,
    server_name: String,
    tls: Arc<rustls::ClientConfig>,
    uuid: [u8; 16],
    password: String,
    heartbeat: Duration,
    quic: QuicOptions,
    networks: Vec<Network>,
}

impl TuicOutbound {
    /// Builds a TUIC outbound with the same required TLS and UUID semantics as
    /// sing-box `protocol/tuic.NewOutbound`.
    pub fn new(
        options: &OutboundOptions,
        tag: String,
        env: &DialerEnv,
        certificates: &Arc<rb_certificate::Store>,
    ) -> Result<Arc<Self>, String> {
        let tls_options = options.tls.as_ref().filter(|tls| tls.enabled).ok_or("TLS is required")?;
        let tls = rb_tls::TlsClient::new(tls_options, &options.server, certificates)?.with_alpn(&["h3"]);
        let uuid = crate::vless::protocol::parse_uuid_strict(&options.uuid).ok_or("invalid uuid")?;
        if !matches!(options.congestion_control.as_str(), "" | "cubic") {
            return Err(format!("congestion control is not supported by rust-box yet: {}", options.congestion_control));
        }
        let server = Socksaddr::from_host_port(&options.server, options.server_port);
        let dialer = new_outbound_dialer(
            &options.dialer_options(),
            server.domain().is_some(),
            env,
            &format!("outbound/tuic[{tag}]"),
        )?;
        let heartbeat = if options.heartbeat.0.is_zero() { Duration::from_secs(10) } else { options.heartbeat.0 };
        let quic = QuicOptions {
            idle_timeout: options.idle_timeout,
            keep_alive_period: options.keep_alive_period,
            stream_receive_window: options.stream_receive_window,
            connection_receive_window: options.connection_receive_window,
            max_concurrent_streams: options.max_concurrent_streams,
            initial_packet_size: options.initial_packet_size,
            disable_path_mtu_discovery: options.disable_path_mtu_discovery,
        };
        let networks = options
            .network
            .build()
            .iter()
            .map(|network| if network == "udp" { Network::Udp } else { Network::Tcp })
            .collect();
        Ok(Arc::new(Self {
            tag,
            dialer,
            server,
            server_name: tls.server_name().to_string(),
            tls: tls.rustls_config(),
            uuid,
            password: options.password.clone(),
            heartbeat,
            quic,
            networks,
        }))
    }

    async fn connect(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let packet_conn = self.dialer.dial_udp(&self.server).await?;
        let (endpoint, connection) = rb_dialer::quic::connect_with_datagrams(
            packet_conn,
            self.server.clone(),
            self.tls.clone(),
            &self.server_name,
            &self.quic,
        )
        .await?;

        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, &self.uuid, self.password.as_bytes())
            .map_err(|error| io::Error::other(format!("TUIC export keying material: {error:?}")))?;
        let mut auth_stream = connection
            .open_uni()
            .await
            .map_err(|error| io::Error::other(format!("TUIC open authentication stream: {error}")))?;
        auth_stream.write_all(&wire::encode_auth(&self.uuid, &token)).await?;
        auth_stream
            .finish()
            .map_err(|error| io::Error::other(format!("TUIC finish authentication stream: {error}")))?;

        spawn_heartbeat(connection.clone(), self.heartbeat);
        let (mut send, recv) =
            connection.open_bi().await.map_err(|error| io::Error::other(format!("TUIC open TCP stream: {error}")))?;
        send.write_all(&wire::encode_connect(destination)?).await?;
        Ok(rb_dialer::quic::bidi_stream_with_close(endpoint, connection, send, recv))
    }
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "tuic"
    }

    fn networks(&self) -> &[Network] {
        &self.networks
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        self.connect(&context.destination).await
    }
}

fn spawn_heartbeat(connection: quinn::Connection, interval: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = connection.closed() => break,
                _ = tokio::time::sleep(interval) => {
                    if connection.send_datagram(wire::encode_heartbeat().to_vec().into()).is_err() {
                        break;
                    }
                }
            }
        }
    });
}
