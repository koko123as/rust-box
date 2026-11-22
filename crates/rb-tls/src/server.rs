//! The TLS server (sing-box `common/tls/std_server.go`, `server.go`).

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use rb_adapter::BoxStream;
use rb_certificate::Pool;
use rb_config::{ClientAuthType, InboundTlsOptions};
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use tracing::{error, info};

use crate::verify::{root_store, AnyClientCert};
use crate::{crypto, join_lines, key_pair, read_file, timeout_error, Crypto, DEFAULT_HANDSHAKE_TIMEOUT};

/// A server TLS stream over a boxed stream.
pub type TlsServerStream = tokio_rustls::server::TlsStream<BoxStream>;

/// A TLS server configuration (sing-box `STDServerConfig`); clones share
/// one configuration, which reloads when its files change.
#[derive(Clone)]
pub struct TlsServer {
    inner: Arc<Inner>,
}

struct Inner {
    options: InboundTlsOptions,
    crypto: Crypto,
    handshake_timeout: Duration,
    material: Mutex<Material>,
    config: RwLock<Arc<ServerConfig>>,
    watcher: Mutex<Option<rb_fswatch::Watcher>>,
}

/// What the configuration is built from, kept for reloads.
#[derive(Clone)]
struct Material {
    certificate: Vec<u8>,
    key: Vec<u8>,
    /// `None`: `insecure` without a certificate, self-signed per name.
    certified: Option<Arc<CertifiedKey>>,
    client_auth: ClientAuth,
}

#[derive(Clone)]
enum ClientAuth {
    None,
    /// Request (or require) any certificate, optionally pinned.
    Any {
        mandatory: bool,
        public_keys: Option<Vec<Vec<u8>>>,
    },
    /// Verify against these roots; optional unless `mandatory`.
    Verify {
        mandatory: bool,
        roots: Arc<Pool>,
    },
}

impl std::fmt::Debug for TlsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsServer").finish()
    }
}

fn client_pool_from_paths(paths: &[String]) -> Result<Pool, String> {
    let mut pool = Pool::default();
    for path in paths {
        let content = read_file(path).map_err(|error| format!("read client certificate from {path}: {error}"))?;
        if !pool.append_pem(&content) {
            return Err(format!("invalid client certificate file: {path}"));
        }
    }
    Ok(pool)
}

impl TlsServer {
    /// sing-box `tls.NewServer` for enabled options.
    pub fn new(options: &InboundTlsOptions) -> Result<Self, String> {
        let crypto =
            crypto(&options.min_version, &options.max_version, &options.cipher_suites, &options.curve_preferences)?;
        let mut certificate = Vec::new();
        if !options.certificate.is_empty() {
            certificate = join_lines(&options.certificate);
        } else if !options.certificate_path.is_empty() {
            certificate = read_file(&options.certificate_path).map_err(|error| format!("read certificate: {error}"))?;
        }
        let mut key = Vec::new();
        if !options.key.is_empty() {
            key = join_lines(&options.key);
        } else if !options.key_path.is_empty() {
            key = read_file(&options.key_path).map_err(|error| format!("read key: {error}"))?;
        }
        let certified = if certificate.is_empty() && key.is_empty() && options.insecure {
            None
        } else {
            if certificate.is_empty() {
                return Err("missing certificate".into());
            } else if key.is_empty() {
                return Err("missing key".into());
            }
            Some(
                key_pair(&certificate, &key, &crypto.provider)
                    .map_err(|error| format!("parse x509 key pair: {error}"))?,
            )
        };
        let mut mode = options.client_authentication;
        if (!options.client_certificate.is_empty() || !options.client_certificate_path.is_empty())
            && mode == ClientAuthType::No
        {
            mode = ClientAuthType::RequireAndVerify;
        }
        let client_auth = match mode {
            ClientAuthType::No => ClientAuth::None,
            ClientAuthType::Request => ClientAuth::Any { mandatory: false, public_keys: None },
            ClientAuthType::RequireAny => ClientAuth::Any { mandatory: true, public_keys: None },
            ClientAuthType::VerifyIfGiven | ClientAuthType::RequireAndVerify => {
                let mandatory = mode == ClientAuthType::RequireAndVerify;
                if !options.client_certificate.is_empty() {
                    let mut pool = Pool::default();
                    if !pool.append_pem(&join_lines(&options.client_certificate)) {
                        return Err("invalid client certificate strings".into());
                    }
                    ClientAuth::Verify { mandatory, roots: Arc::new(pool) }
                } else if !options.client_certificate_path.is_empty() {
                    ClientAuth::Verify {
                        mandatory,
                        roots: Arc::new(client_pool_from_paths(&options.client_certificate_path.0)?),
                    }
                } else if !options.client_certificate_public_key_sha256.is_empty() {
                    // Go downgrades to RequireAnyClientCert / RequestClientCert
                    // and checks the pinned keys itself.
                    let keys = options.client_certificate_public_key_sha256.iter().map(|key| key.0.clone()).collect();
                    ClientAuth::Any { mandatory, public_keys: Some(keys) }
                } else {
                    return Err("missing client_certificate, client_certificate_path or \
                                client_certificate_public_key_sha256 for client authentication"
                        .into());
                }
            }
        };
        let material = Material { certificate, key, certified, client_auth };
        let config = build_config(options, &crypto, &material)?;
        Ok(TlsServer {
            inner: Arc::new(Inner {
                options: options.clone(),
                handshake_timeout: if options.handshake_timeout.0.is_zero() {
                    DEFAULT_HANDSHAKE_TIMEOUT
                } else {
                    options.handshake_timeout.0
                },
                crypto,
                material: Mutex::new(material),
                config: RwLock::new(Arc::new(config)),
                watcher: Mutex::new(None),
            }),
        })
    }

    /// The ALPN protocols offered (sing-box `NextProtos`).
    pub fn alpn(&self) -> Vec<String> {
        self.inner.options.alpn.0.clone()
    }

    pub fn handshake_timeout(&self) -> Duration {
        self.inner.handshake_timeout
    }

    /// sing-box `STDServerConfig.Start`: watches `certificate_path`,
    /// `key_path` and `client_certificate_path`. A watcher that cannot be
    /// created is logged, as sing-box does.
    pub fn start(&self) -> Result<(), String> {
        let options = &self.inner.options;
        let mut paths: Vec<String> = Vec::new();
        if !options.certificate_path.is_empty() {
            paths.push(options.certificate_path.clone());
        }
        if !options.key_path.is_empty() {
            paths.push(options.key_path.clone());
        }
        paths.extend(options.client_certificate_path.iter().cloned());
        if paths.is_empty() {
            return Ok(());
        }
        let weak = Arc::downgrade(&self.inner);
        let watcher = rb_fswatch::Watcher::new(rb_fswatch::Options {
            paths: paths.iter().map(|path| absolute(path)).collect(),
            direct: false,
            callback: Arc::new(move |path: &Path| {
                if let Some(inner) = weak.upgrade() {
                    if let Err(error) = inner.certificate_updated(path) {
                        error!("reload certificate: {error}");
                    }
                }
            }),
            wait_timeout: None,
        });
        match watcher.and_then(|watcher| watcher.start().map(|_| watcher)) {
            Ok(watcher) => *self.inner.watcher.lock().unwrap() = Some(watcher),
            Err(error) => tracing::warn!("create fsnotify watcher: {error}"),
        }
        Ok(())
    }

    pub fn close(&self) {
        if let Some(watcher) = self.inner.watcher.lock().unwrap().take() {
            watcher.close();
        }
    }

    /// Runs the server handshake (sing-box `tls.ServerHandshake`) within
    /// the handshake timeout (15s by default), with the configuration
    /// current at the time.
    pub async fn handshake(&self, stream: BoxStream) -> io::Result<TlsServerStream> {
        let config = self.inner.config.read().unwrap().clone();
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        tokio::time::timeout(self.inner.handshake_timeout, acceptor.accept(stream))
            .await
            .map_err(|_| timeout_error())?
    }

    /// [`TlsServer::handshake`], boxed.
    pub async fn accept(&self, stream: BoxStream) -> io::Result<BoxStream> {
        Ok(Box::new(self.handshake(stream).await?))
    }
}

fn absolute(path: &str) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path))
}

impl Inner {
    /// sing-box `certificateUpdated`.
    fn certificate_updated(&self, path: &Path) -> Result<(), String> {
        // The certificate's and the key's callbacks fire on threads of their
        // own; one at a time, or the second would put back the file the
        // first just read.
        static RELOAD: Mutex<()> = Mutex::new(());
        let _reload = RELOAD.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let options = &self.options;
        let is = |configured: &str| !configured.is_empty() && absolute(configured) == path;
        let mut material = self.material.lock().unwrap().clone();
        if is(&options.certificate_path) || is(&options.key_path) {
            if is(&options.certificate_path) {
                material.certificate = read_file(&options.certificate_path)
                    .map_err(|error| format!("reload certificate from {}: {error}", options.certificate_path))?;
            }
            if is(&options.key_path) {
                material.key = read_file(&options.key_path)
                    .map_err(|error| format!("reload key from {}: {error}", options.key_path))?;
            }
            // The file read is kept even when the pair does not match yet
            // (the other file may be about to change), as sing-box does.
            {
                let mut current = self.material.lock().unwrap();
                current.certificate = material.certificate.clone();
                current.key = material.key.clone();
            }
            material.certified = Some(
                key_pair(&material.certificate, &material.key, &self.crypto.provider)
                    .map_err(|error| format!("reload key pair: {error}"))?,
            );
            self.publish(material)?;
            info!("reloaded TLS certificate");
        } else if options.client_certificate_path.iter().any(|configured| is(configured)) {
            let mut pool = Pool::default();
            let mut reloaded = false;
            for configured in options.client_certificate_path.iter() {
                match read_file(configured) {
                    Err(error) => error!("reload certificate from {configured}: {error}"),
                    Ok(content) if !pool.append_pem(&content) => {
                        error!("invalid client certificate file: {configured}")
                    }
                    Ok(_) => reloaded = true,
                }
            }
            if !reloaded {
                return Err("client certificates is empty".into());
            }
            if let ClientAuth::Verify { roots, .. } = &mut material.client_auth {
                *roots = Arc::new(pool);
            }
            self.publish(material)?;
            info!("reloaded client certificates");
        }
        Ok(())
    }

    fn publish(&self, material: Material) -> Result<(), String> {
        let config = build_config(&self.options, &self.crypto, &material)?;
        *self.material.lock().unwrap() = material;
        *self.config.write().unwrap() = Arc::new(config);
        Ok(())
    }
}

fn build_config(options: &InboundTlsOptions, crypto: &Crypto, material: &Material) -> Result<ServerConfig, String> {
    let builder = ServerConfig::builder_with_provider(crypto.provider.clone())
        .with_protocol_versions(&crypto.versions)
        .map_err(|error| error.to_string())?;
    let builder = match &material.client_auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::Any { mandatory, public_keys } => builder.with_client_cert_verifier(Arc::new(AnyClientCert {
            mandatory: *mandatory,
            public_keys: public_keys.clone(),
            provider: crypto.provider.clone(),
        })),
        ClientAuth::Verify { mandatory, roots } => {
            let mut verifier = WebPkiClientVerifier::builder_with_provider(root_store(roots), crypto.provider.clone());
            if !mandatory {
                verifier = verifier.allow_unauthenticated();
            }
            builder.with_client_cert_verifier(verifier.build().map_err(|error| error.to_string())?)
        }
    };
    let resolver: Arc<dyn ResolvesServerCert> = match &material.certified {
        Some(certified) => Arc::new(SingleCert(certified.clone())),
        None => Arc::new(SelfSigned { provider: crypto.provider.clone(), cache: Mutex::new(HashMap::new()) }),
    };
    let mut config = builder.with_cert_resolver(resolver);
    config.alpn_protocols = options.alpn.iter().map(|protocol| protocol.as_bytes().to_vec()).collect();
    Ok(config)
}

#[derive(Debug)]
struct SingleCert(Arc<CertifiedKey>);

impl ResolvesServerCert for SingleCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// `insecure` without a certificate: a self-signed certificate for the
/// name the client asked for (sing-box `GenerateKeyPair`).
#[derive(Debug)]
struct SelfSigned {
    provider: Arc<CryptoProvider>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for SelfSigned {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name().unwrap_or_default().to_string();
        if let Some(certified) = self.cache.lock().unwrap().get(&name) {
            return Some(certified.clone());
        }
        match generate_key_pair(&name, &self.provider) {
            Ok(certified) => {
                self.cache.lock().unwrap().insert(name, certified.clone());
                Some(certified)
            }
            Err(error) => {
                error!("generate self-signed certificate for {name:?}: {error}");
                None
            }
        }
    }
}

/// A self-signed server certificate for `server_name`.
pub(crate) fn generate_key_pair(server_name: &str, provider: &CryptoProvider) -> Result<Arc<CertifiedKey>, String> {
    let names = if server_name.is_empty() { Vec::new() } else { vec![server_name.to_string()] };
    let mut params = rcgen::CertificateParams::new(names).map_err(|error| error.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, server_name);
    params.key_usages = vec![rcgen::KeyUsagePurpose::KeyEncipherment, rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    let key = rcgen::KeyPair::generate().map_err(|error| error.to_string())?;
    let certificate = params.self_signed(&key).map_err(|error| error.to_string())?;
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
    CertifiedKey::from_der(vec![certificate.der().clone()], key_der, provider)
        .map(Arc::new)
        .map_err(|error| error.to_string())
}
