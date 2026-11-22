//! Hysteria2 outbound TCP runtime: HTTP/3 authentication followed by raw QUIC
//! bidirectional streams, matching sing-box's outbound connection sequence.
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use http::{Method, Request, Uri};
use quinn::{Connection, RecvStream, VarInt};
use rand::Rng;
use rb_adapter::{BoxStream, InboundContext, Network, Outbound};
use rb_config::{Duration as ConfigDuration, Hysteria2Outbound as OutboundOptions, MemoryBytes, QuicOptions};
use rb_dialer::{new_outbound_dialer, Dialer, DialerEnv};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

use super::auth::{AuthRequest, AUTH_HOST, AUTH_OK_STATUS, AUTH_PATH};
use super::tcp;

const TCP_REQUEST_PADDING_MIN: usize = 64;
const TCP_REQUEST_PADDING_MAX: usize = 512;
const TCP_RESPONSE_MESSAGE_LIMIT: usize = 2048;
const TCP_RESPONSE_PADDING_LIMIT: usize = 4096;
const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// A Hysteria2 outbound with TCP support. UDP, obfuscation and bandwidth
/// controls remain rejected by the config validator until their runtime paths
/// are implemented.
pub struct Hysteria2Outbound {
    tag: String,
    dialer: Arc<dyn Dialer>,
    server: rb_adapter::Socksaddr,
    server_name: String,
    tls: Arc<rustls::ClientConfig>,
    auth_timeout: std::time::Duration,
    password: String,
    quic: QuicOptions,
}

impl Hysteria2Outbound {
    pub fn new(
        options: &OutboundOptions,
        tag: String,
        env: &DialerEnv,
        certificates: &Arc<rb_certificate::Store>,
        config_path: &str,
    ) -> Result<Arc<Self>, String> {
        if options.realm.is_some() {
            return Err(unsupported_config_field(config_path, "realm", "realm"));
        }
        if let Some(obfs) = &options.obfs {
            return match obfs.r#type.as_str() {
                "salamander" | "gecko" => Err(unsupported_config_field(config_path, "obfs.type", "obfs.type")),
                other => Err(format!("{config_path}.obfs.type: unknown Hysteria2 obfs type: {other}")),
            };
        }
        if options.network.build().iter().any(|network| network == "udp") {
            return Err(unsupported_config_field(config_path, "network", "network"));
        }
        if !options.disable_chrome_parrot {
            return Err(unsupported_config_field(config_path, "disable_chrome_parrot", "disable_chrome_parrot"));
        }
        for (path, name, is_set) in [
            ("server_ports", "server_ports", !options.server_ports.is_empty()),
            ("hop_interval", "hop_interval", !options.hop_interval.0.is_zero()),
            ("hop_interval_max", "hop_interval_max", !options.hop_interval_max.0.is_zero()),
            ("up_mbps", "up_mbps", options.up_mbps != 0),
            ("down_mbps", "down_mbps", options.down_mbps != 0),
            ("bbr_profile", "bbr_profile", !options.bbr_profile.is_empty()),
            ("brutal_debug", "brutal_debug", options.brutal_debug),
        ] {
            if is_set {
                return Err(unsupported_config_field(config_path, path, name));
            }
        }

        let tls_options = options
            .tls
            .as_ref()
            .filter(|tls| tls.enabled)
            .ok_or_else(|| format!("{config_path}.tls: TLS is required"))?;
        let tls_client = rb_tls::TlsClient::new(tls_options, &options.server, certificates)
            .map_err(|error| format!("{config_path}.tls: {error}"))?
            .with_alpn(&["h3"]);
        let auth_timeout = tls_client.handshake_timeout();
        let server_name = tls_client.server_name().to_string();
        let tls = tls_client.rustls_config();
        let server = rb_adapter::Socksaddr::from_host_port(&options.server, options.server_port);
        let dialer = new_outbound_dialer(
            &options.dialer_options(),
            server.domain().is_some(),
            env,
            &format!("outbound/hysteria2[{tag}]"),
        )
        .map_err(|error| format!("{config_path}: {error}"))?;
        let quic = hysteria2_quic_options(options);
        Ok(Arc::new(Self {
            tag,
            dialer,
            server,
            server_name,
            tls,
            auth_timeout,
            password: options.password.clone(),
            quic,
        }))
    }

    async fn connect_tcp(&self, destination: &rb_adapter::Socksaddr) -> io::Result<BoxStream> {
        let packet_conn = self.dialer.dial_udp(&self.server).await?;
        // Hysteria2 with zero configured send bandwidth uses BBR. Quinn's BBR
        // controller is used here; upstream's BBR-meta2 profile is tracked as
        // a compatibility difference and must be replaced before M7 acceptance.
        let controller = Arc::new(quinn::congestion::BbrConfig::default());
        let (endpoint, connection) = rb_dialer::quic::connect_with_congestion_controller(
            packet_conn,
            self.server.clone(),
            self.tls.clone(),
            &self.server_name,
            &self.quic,
            controller,
        )
        .await?;
        let driver = match tokio::time::timeout(self.auth_timeout, authenticate(&connection, &self.password)).await {
            Ok(Ok(driver)) => driver,
            Ok(Err(error)) => {
                connection.close(VarInt::from_u32(0), b"Hysteria2 authentication failed");
                endpoint.wait_idle().await;
                return Err(error);
            }
            Err(_) => {
                connection.close(VarInt::from_u32(0), b"Hysteria2 authentication timed out");
                endpoint.wait_idle().await;
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Hysteria2 authentication timed out"));
            }
        };

        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(error) => {
                driver.abort();
                return Err(io::Error::other(format!("Hysteria2 open TCP stream: {error}")));
            }
        };
        let request = tcp::encode_tcp_request(&destination.to_string(), &random_padding())?;
        if let Err(error) = send.write_all(&request).await {
            driver.abort();
            return Err(io::Error::other(format!("Hysteria2 write TCP request: {error}")));
        }
        let (status, message) = match read_tcp_response(&mut recv).await {
            Ok(response) => response,
            Err(error) => {
                driver.abort();
                return Err(error);
            }
        };
        if status != 0 {
            driver.abort();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Hysteria2 TCP request rejected: {}", String::from_utf8_lossy(&message)),
            ));
        }
        let inner = rb_dialer::quic::bidi_stream_with_close(endpoint, connection, send, recv);
        Ok(Box::new(Hysteria2TcpStream { inner, h3_driver: driver }))
    }
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "hysteria2"
    }

    fn networks(&self) -> &[Network] {
        &[Network::Tcp]
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        self.connect_tcp(&context.destination).await
    }
}

fn unsupported_config_field(config_path: &str, path: &str, name: &str) -> String {
    format!("{config_path}.{path}: `{name}` is not supported by rust-box yet")
}

async fn authenticate(connection: &Connection, password: &str) -> io::Result<JoinHandle<()>> {
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let (mut driver, mut sender) = h3::client::new(h3_connection)
        .await
        .map_err(|error| io::Error::other(format!("Hysteria2 establish HTTP/3: {error}")))?;
    let driver = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let uri = Uri::builder()
        .scheme("https")
        .authority(AUTH_HOST)
        .path_and_query(AUTH_PATH)
        .build()
        .map_err(|error| io::Error::other(format!("Hysteria2 auth URI: {error}")))?;
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .body(())
        .map_err(|error| io::Error::other(format!("Hysteria2 auth request: {error}")))?;
    *request.headers_mut() = AuthRequest { password: password.to_string(), receive_bps: 0 }.headers()?;

    let mut stream = match sender.send_request(request).await {
        Ok(stream) => stream,
        Err(error) => {
            driver.abort();
            return Err(io::Error::other(format!("Hysteria2 send auth request: {error}")));
        }
    };
    if let Err(error) = stream.finish().await {
        driver.abort();
        return Err(io::Error::other(format!("Hysteria2 finish auth request: {error}")));
    }
    let response = match stream.recv_response().await {
        Ok(response) => response,
        Err(error) => {
            driver.abort();
            return Err(io::Error::other(format!("Hysteria2 read auth response: {error}")));
        }
    };
    let status = response.status().as_u16();
    if status != AUTH_OK_STATUS {
        driver.abort();
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("Hysteria2 authentication failed: HTTP {status}"),
        ));
    }
    stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
    Ok(driver)
}

fn hysteria2_quic_options(options: &OutboundOptions) -> QuicOptions {
    let duration_or_default = |duration: ConfigDuration, seconds| {
        if duration.0.is_zero() {
            ConfigDuration(std::time::Duration::from_secs(seconds))
        } else {
            duration
        }
    };
    let window_or_default = |window: Option<MemoryBytes>, default| {
        window.filter(|window| window.value() != 0).unwrap_or(MemoryBytes(default))
    };
    QuicOptions {
        idle_timeout: duration_or_default(options.idle_timeout, 30),
        keep_alive_period: duration_or_default(options.keep_alive_period, 10),
        stream_receive_window: Some(window_or_default(options.stream_receive_window, 8 << 20)),
        connection_receive_window: Some(window_or_default(options.connection_receive_window, 20 << 20)),
        max_concurrent_streams: options.max_concurrent_streams,
        initial_packet_size: options.initial_packet_size,
        disable_path_mtu_discovery: options.disable_path_mtu_discovery,
    }
}

async fn read_tcp_response(stream: &mut RecvStream) -> io::Result<(u8, Vec<u8>)> {
    let mut status = [0u8; 1];
    read_quic_exact(stream, &mut status).await?;
    let message_length = usize::try_from(read_varint(stream).await?)
        .map_err(|_| invalid_data("Hysteria2 TCP response message length overflow"))?;
    if message_length > TCP_RESPONSE_MESSAGE_LIMIT {
        return Err(invalid_data("Hysteria2 TCP response message exceeds the limit"));
    }
    let mut message = vec![0; message_length];
    read_quic_exact(stream, &mut message).await?;
    let padding_length = usize::try_from(read_varint(stream).await?)
        .map_err(|_| invalid_data("Hysteria2 TCP response padding length overflow"))?;
    if padding_length > TCP_RESPONSE_PADDING_LIMIT {
        return Err(invalid_data("Hysteria2 TCP response padding exceeds the limit"));
    }
    let mut padding = vec![0; padding_length];
    read_quic_exact(stream, &mut padding).await?;
    Ok((status[0], message))
}

async fn read_quic_exact(stream: &mut RecvStream, buffer: &mut [u8]) -> io::Result<()> {
    stream
        .read_exact(buffer)
        .await
        .map(|_| ())
        .map_err(|error| io::Error::new(io::ErrorKind::UnexpectedEof, error.to_string()))
}

async fn read_varint(stream: &mut RecvStream) -> io::Result<u64> {
    let mut encoded = [0u8; 8];
    read_quic_exact(stream, &mut encoded[..1]).await?;
    let length = 1usize << (encoded[0] >> 6);
    if length > 1 {
        read_quic_exact(stream, &mut encoded[1..length]).await?;
    }
    let mut value = u64::from(encoded[0] & 0x3f);
    for byte in &encoded[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(value)
}

fn random_padding() -> Vec<u8> {
    let mut rng = rand::rng();
    let length = rng.random_range(TCP_REQUEST_PADDING_MIN..TCP_REQUEST_PADDING_MAX);
    (0..length).map(|_| PADDING_CHARS[rng.random_range(0..PADDING_CHARS.len())]).collect()
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct Hysteria2TcpStream {
    inner: BoxStream,
    h3_driver: JoinHandle<()>,
}

impl Drop for Hysteria2TcpStream {
    fn drop(&mut self) {
        self.h3_driver.abort();
    }
}

impl AsyncRead for Hysteria2TcpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for Hysteria2TcpStream {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_request_padding_matches_upstream_range() {
        let padding = random_padding();
        assert!((TCP_REQUEST_PADDING_MIN..TCP_REQUEST_PADDING_MAX).contains(&padding.len()));
        assert!(padding.iter().all(|byte| PADDING_CHARS.contains(byte)));
    }

    #[test]
    fn quic_defaults_match_sing_quic_hysteria2_defaults() {
        let options = hysteria2_quic_options(&OutboundOptions::default());
        assert_eq!(options.idle_timeout.0, std::time::Duration::from_secs(30));
        assert_eq!(options.keep_alive_period.0, std::time::Duration::from_secs(10));
        assert_eq!(options.stream_receive_window, Some(MemoryBytes(8 << 20)));
        assert_eq!(options.connection_receive_window, Some(MemoryBytes(20 << 20)));
    }

    #[test]
    fn quic_explicit_options_override_hysteria2_defaults() {
        let input = OutboundOptions {
            idle_timeout: ConfigDuration(std::time::Duration::from_secs(45)),
            stream_receive_window: Some(MemoryBytes(4 << 20)),
            ..Default::default()
        };
        let options = hysteria2_quic_options(&input);
        assert_eq!(options.idle_timeout.0, std::time::Duration::from_secs(45));
        assert_eq!(options.stream_receive_window, Some(MemoryBytes(4 << 20)));
        assert_eq!(options.connection_receive_window, Some(MemoryBytes(20 << 20)));
    }
}
