//! The TLS client (sing-box `common/tls/std_client.go`, `client.go`).

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rb_adapter::{BoxStream, SharedPacketConn, Socksaddr};
use rb_certificate::{Pool, Store};
use rb_config::OutboundTlsOptions;
use rb_dialer::tls_fragment::TlsFragmentStream;
use rb_dialer::Dialer;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;

use crate::verify::{Roots, ServerVerifier};
use crate::{crypto, join_lines, key_pair, read_file, timeout_error, DEFAULT_HANDSHAKE_TIMEOUT, MISSING_SERVER_NAME};

/// A client TLS stream over a boxed stream.
pub type TlsClientStream = tokio_rustls::client::TlsStream<BoxStream>;

/// A TLS client configuration (sing-box `STDClientConfig`).
#[derive(Clone)]
pub struct TlsClient {
    config: Arc<ClientConfig>,
    server_name: String,
    disable_sni: bool,
    insecure: bool,
    handshake_timeout: Duration,
    fragment: bool,
    record_fragment: bool,
    fragment_fallback_delay: Duration,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient").field("server_name", &self.server_name).finish()
    }
}

impl TlsClient {
    /// sing-box `tls.NewClient`: `server_address` (the outbound's `server`)
    /// is the server name when `server_name` is empty. The options must be
    /// `enabled`; `store` supplies the roots unless `certificate` or
    /// `certificate_path` is set.
    pub fn new(options: &OutboundTlsOptions, server_address: &str, store: &Arc<Store>) -> Result<Self, String> {
        Self::new_with(options, server_address, store, false)
    }

    /// [`TlsClient::new`] with sing-box's `AllowEmptyServerName` (for
    /// protocols that set the server name per connection).
    pub fn new_with(
        options: &OutboundTlsOptions,
        server_address: &str,
        store: &Arc<Store>,
        allow_empty_server_name: bool,
    ) -> Result<Self, String> {
        let server_name =
            if !options.server_name.is_empty() { options.server_name.clone() } else { server_address.to_string() };
        if server_name.is_empty() && !options.insecure && !allow_empty_server_name {
            return Err(MISSING_SERVER_NAME.into());
        }
        // Callers can use this public constructor without parsing a root config;
        // keep unsupported TLS options fail-closed in that path as well.
        options.validate("tls").map_err(|error| error.to_string())?;
        let crypto =
            crypto(&options.min_version, &options.max_version, &options.cipher_suites, &options.curve_preferences)?;
        let mut certificate = Vec::new();
        if !options.certificate.is_empty() {
            certificate = join_lines(&options.certificate);
        } else if !options.certificate_path.is_empty() {
            certificate = read_file(&options.certificate_path).map_err(|error| format!("read certificate: {error}"))?;
        }
        let verifier = if !options.certificate_public_key_sha256.is_empty() {
            if !options.certificate.is_empty() || !options.certificate_path.is_empty() {
                return Err("certificate_public_key_sha256 is conflict with certificate or certificate_path".into());
            }
            let keys = options.certificate_public_key_sha256.iter().map(|key| key.0.clone()).collect();
            ServerVerifier::public_keys(keys, crypto.provider.clone())
        } else if options.insecure {
            ServerVerifier::insecure(crypto.provider.clone())
        } else if !certificate.is_empty() {
            let mut pool = Pool::default();
            if !pool.append_pem(&certificate) {
                return Err(format!("failed to parse certificate:\n\n{}", String::from_utf8_lossy(&certificate)));
            }
            ServerVerifier::roots(Roots::Fixed(Arc::new(pool)), crypto.provider.clone())
        } else {
            ServerVerifier::roots(Roots::Store(store.clone()), crypto.provider.clone())
        };
        let builder = ClientConfig::builder_with_provider(crypto.provider.clone())
            .with_protocol_versions(&crypto.versions)
            .map_err(|error| error.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));

        let mut client_certificate = Vec::new();
        if !options.client_certificate.is_empty() {
            client_certificate = join_lines(&options.client_certificate);
        } else if !options.client_certificate_path.is_empty() {
            client_certificate = read_file(&options.client_certificate_path)
                .map_err(|error| format!("read client certificate: {error}"))?;
        }
        let mut client_key = Vec::new();
        if !options.client_key.is_empty() {
            client_key = join_lines(&options.client_key);
        } else if !options.client_key_path.is_empty() {
            client_key = read_file(&options.client_key_path).map_err(|error| format!("read client key: {error}"))?;
        }
        let mut config = if !client_certificate.is_empty() && !client_key.is_empty() {
            let certified = key_pair(&client_certificate, &client_key, &crypto.provider)
                .map_err(|error| format!("parse client x509 key pair: {error}"))?;
            builder
                .with_client_auth_cert(certified.cert.clone(), certified_key_pem(&client_key)?)
                .map_err(|error| format!("parse client x509 key pair: {error}"))?
        } else if !client_certificate.is_empty() || !client_key.is_empty() {
            return Err("client certificate and client key must be provided together".into());
        } else {
            builder.with_no_client_auth()
        };
        config.alpn_protocols = options.alpn.iter().map(|protocol| protocol.as_bytes().to_vec()).collect();
        config.enable_sni = !options.disable_sni;
        // Go's client keeps no session cache unless one is configured.
        config.resumption = rustls::client::Resumption::disabled();
        Ok(TlsClient {
            config: Arc::new(config),
            server_name,
            disable_sni: options.disable_sni,
            insecure: options.insecure || !options.certificate_public_key_sha256.is_empty(),
            handshake_timeout: if options.handshake_timeout.0.is_zero() {
                DEFAULT_HANDSHAKE_TIMEOUT
            } else {
                options.handshake_timeout.0
            },
            fragment: options.fragment,
            record_fragment: options.record_fragment,
            fragment_fallback_delay: options.fragment_fallback_delay.0,
        })
    }

    /// sing-box `Config.ServerName`.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The ALPN protocols offered (sing-box `Config.NextProtos`).
    pub fn alpn(&self) -> Vec<String> {
        self.config.alpn_protocols.iter().map(|protocol| String::from_utf8_lossy(protocol).into_owned()).collect()
    }

    /// Shares the exact rustls configuration with transports such as QUIC,
    /// preserving the configured verifier, roots, and client certificate.
    pub fn rustls_config(&self) -> Arc<ClientConfig> {
        self.config.clone()
    }

    /// A copy offering other ALPN protocols (sing-box `SetNextProtos`).
    pub fn with_alpn(&self, alpn: &[&str]) -> Self {
        let mut config = (*self.config).clone();
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.as_bytes().to_vec()).collect();
        TlsClient { config: Arc::new(config), ..self.clone() }
    }

    /// A copy for another server name (sing-box `SetServerName`).
    pub fn with_server_name(&self, server_name: &str) -> Self {
        TlsClient { server_name: server_name.to_string(), ..self.clone() }
    }

    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// The name rustls verifies against (and sends as SNI unless it is an
    /// IP or `disable_sni` is set).
    fn rustls_server_name(&self) -> io::Result<ServerName<'static>> {
        if self.server_name.is_empty() {
            if !self.insecure {
                // sing-box `verifyConnection` with an empty name.
                return Err(io::Error::new(io::ErrorKind::InvalidInput, MISSING_SERVER_NAME));
            }
            // No name to send or verify: an IP sends no SNI.
            return Ok(ServerName::IpAddress(IpAddr::V4(Ipv4Addr::UNSPECIFIED).into()));
        }
        let name = self.server_name.trim_start_matches('[').trim_end_matches(']');
        ServerName::try_from(name.to_string())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("server_name {name}: {error}")))
    }

    /// Runs the client handshake (sing-box `tls.ClientHandshake`) within
    /// the handshake timeout, with the TLS fragmenter in front when
    /// `fragment` / `record_fragment` is set.
    pub async fn handshake(&self, stream: BoxStream) -> io::Result<TlsClientStream> {
        let stream: BoxStream = if self.fragment || self.record_fragment {
            Box::new(TlsFragmentStream::new(
                stream,
                self.fragment,
                self.record_fragment,
                Some(self.fragment_fallback_delay),
            ))
        } else {
            stream
        };
        let name = self.rustls_server_name()?;
        let _ = self.disable_sni;
        let connector = tokio_rustls::TlsConnector::from(self.config.clone());
        tokio::time::timeout(self.handshake_timeout, connector.connect(name, stream))
            .await
            .map_err(|_| timeout_error())?
    }

    /// [`TlsClient::handshake`], boxed.
    pub async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        Ok(Box::new(self.handshake(stream).await?))
    }
}

/// The signing key of a PEM private key.
fn certified_key_pem(key: &[u8]) -> Result<rustls_pki_types::PrivateKeyDer<'static>, String> {
    use rustls_pki_types::pem::PemObject;
    rustls_pki_types::PrivateKeyDer::from_pem_slice(key).map_err(|error| error.to_string())
}

/// A dialer whose TCP connections are TLS client connections (sing-box
/// `tls.NewDialer`); it has no UDP.
pub struct TlsDialer {
    dialer: Arc<dyn Dialer>,
    client: TlsClient,
}

impl TlsDialer {
    pub fn new(dialer: Arc<dyn Dialer>, client: TlsClient) -> Self {
        TlsDialer { dialer, client }
    }

    pub fn client(&self) -> &TlsClient {
        &self.client
    }
}

#[async_trait]
impl Dialer for TlsDialer {
    async fn dial_tcp(&self, destination: &Socksaddr) -> io::Result<BoxStream> {
        let stream = self.dialer.dial_tcp(destination).await?;
        self.client.connect(stream).await
    }

    async fn dial_udp(&self, _destination: &Socksaddr) -> io::Result<SharedPacketConn> {
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    }

    async fn listen_packet(&self, _destination: &Socksaddr) -> io::Result<SharedPacketConn> {
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    }
}
