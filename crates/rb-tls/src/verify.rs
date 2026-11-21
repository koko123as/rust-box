//! Certificate verifiers: the certificate store's roots (re-read when the
//! store reloads), `insecure`, `certificate_public_key_sha256`, and the
//! client certificate modes of `client_authentication`.

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use rb_certificate::{Pool, Store};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

use crate::der;

/// SHA-256 of a certificate's public key (SubjectPublicKeyInfo), as
/// `certificate_public_key_sha256` lists them.
pub fn public_key_sha256(certificate: &[u8]) -> Option<[u8; 32]> {
    der::subject_public_key_info(certificate).map(|spki| Sha256::digest(spki).into())
}

/// sing-box `VerifyPublicKeySHA256`.
pub(crate) fn verify_public_key_sha256(known: &[Vec<u8>], leaf: &CertificateDer<'_>) -> Result<(), Error> {
    let hash = public_key_sha256(leaf).ok_or_else(|| Error::General("failed to parse leaf certificate".into()))?;
    if known.iter().any(|value| value.as_slice() == hash) {
        return Ok(());
    }
    Err(Error::General(format!(
        "unrecognized remote public key: {}",
        base64::engine::general_purpose::STANDARD.encode(hash)
    )))
}

/// Where the server verifier takes its roots from.
pub(crate) enum Roots {
    /// The top-level certificate store, read at every handshake so a
    /// reloaded store applies to new connections.
    Store(Arc<Store>),
    /// `certificate` / `certificate_path` of the TLS options.
    Fixed(Arc<Pool>),
}

/// Verifies a server certificate the way the options ask.
#[derive(Debug)]
pub(crate) struct ServerVerifier {
    mode: ServerMode,
    provider: Arc<CryptoProvider>,
}

enum ServerMode {
    /// Chain verification against roots.
    Roots { roots: Roots, cache: Mutex<Option<(Arc<Pool>, Arc<WebPkiServerVerifier>)>> },
    /// `insecure`: anything goes.
    Insecure,
    /// `certificate_public_key_sha256`: only the leaf's key counts.
    PublicKeys(Vec<Vec<u8>>),
}

impl std::fmt::Debug for ServerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ServerMode::Roots { .. } => "Roots",
            ServerMode::Insecure => "Insecure",
            ServerMode::PublicKeys(_) => "PublicKeys",
        })
    }
}

impl ServerVerifier {
    pub(crate) fn roots(roots: Roots, provider: Arc<CryptoProvider>) -> Self {
        ServerVerifier { mode: ServerMode::Roots { roots, cache: Mutex::new(None) }, provider }
    }

    pub(crate) fn insecure(provider: Arc<CryptoProvider>) -> Self {
        ServerVerifier { mode: ServerMode::Insecure, provider }
    }

    pub(crate) fn public_keys(keys: Vec<Vec<u8>>, provider: Arc<CryptoProvider>) -> Self {
        ServerVerifier { mode: ServerMode::PublicKeys(keys), provider }
    }

    fn webpki(&self) -> Result<Option<Arc<WebPkiServerVerifier>>, Error> {
        let ServerMode::Roots { roots, cache } = &self.mode else { return Ok(None) };
        let pool = match roots {
            Roots::Store(store) => store.pool(),
            Roots::Fixed(pool) => pool.clone(),
        };
        let mut cache = cache.lock().unwrap();
        if let Some((cached, verifier)) = cache.as_ref() {
            if Arc::ptr_eq(cached, &pool) {
                return Ok(Some(verifier.clone()));
            }
        }
        if pool.is_empty() {
            // Go: "x509: certificate signed by unknown authority".
            return Err(Error::InvalidCertificate(CertificateError::UnknownIssuer));
        }
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(pool.roots().clone()), self.provider.clone())
                .build()
                .map_err(|error| Error::General(error.to_string()))?;
        *cache = Some((pool, verifier.clone()));
        Ok(Some(verifier))
    }
}

impl ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match &self.mode {
            ServerMode::Insecure => Ok(ServerCertVerified::assertion()),
            ServerMode::PublicKeys(keys) => {
                verify_public_key_sha256(keys, end_entity).map(|_| ServerCertVerified::assertion())
            }
            ServerMode::Roots { .. } => self.webpki()?.expect("roots mode").verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Client certificates without chain verification: Go's
/// `RequestClientCert` (optional) and `RequireAnyClientCert` (mandatory),
/// optionally pinned by `client_certificate_public_key_sha256`.
#[derive(Debug)]
pub(crate) struct AnyClientCert {
    pub(crate) mandatory: bool,
    pub(crate) public_keys: Option<Vec<Vec<u8>>>,
    pub(crate) provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if let Some(keys) = &self.public_keys {
            verify_public_key_sha256(keys, end_entity)?;
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A root store from a pool.
pub(crate) fn root_store(pool: &Pool) -> Arc<RootCertStore> {
    Arc::new(pool.roots().clone())
}
