//! TLS, mirroring sing-box `common/tls` (the `go` engine: `std_client.go`,
//! `std_server.go`, `client.go`, `server.go`, `config.go`) on rustls with
//! the ring provider.
//!
//! # API
//!
//! Protocols wrap any [`BoxStream`] with TLS:
//!
//! ```ignore
//! // Client (sing-box `tls.NewClient` + `tls.ClientHandshake`): the server
//! // name defaults to `server_address` (the outbound's `server`).
//! let client = TlsClient::new(&tls_options, &server_address, &certificate_store)?;
//! let stream: BoxStream = client.connect(stream).await?;
//! // or, to read the negotiated ALPN: client.handshake(stream).await? -> TlsClientStream
//!
//! // Server (sing-box `tls.NewServer` + `Start` + `tls.ServerHandshake`):
//! let server = TlsServer::new(&inbound_tls_options)?;
//! server.start()?;                      // watches certificate_path / key_path / client_certificate_path
//! let stream: BoxStream = server.accept(stream).await?;
//! server.close();
//! ```
//!
//! Both are cheap to clone and share (`Arc` inside). [`TlsClient::with_alpn`]
//! and [`TlsClient::with_server_name`] return modified copies, as sing-box's
//! `SetNextProtos` / `SetServerName` do on a cloned config. [`TlsDialer`]
//! wraps an [`rb_dialer::Dialer`] so every TCP connection it opens is a TLS
//! client connection (sing-box `tls.NewDialer`).
//!
//! # Differences from sing-box
//!
//! rustls has no TLS 1.0/1.1, no CBC cipher suites, and (with ring) no P-521
//! or X25519MLKEM768 key exchange: `min_version` `1.0`/`1.1` acts as `1.2`,
//! a `max_version` below 1.2 and those cipher suites and curves are refused.
//! A server with `insecure` and no certificate makes an ECDSA P-256
//! self-signed certificate per server name (sing-box: RSA 2048 per
//! handshake).

mod client;
mod der;
mod server;
mod verify;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use rb_config::{CurvePreference, Listable};
use rustls::crypto::ring as provider;
use rustls::crypto::CryptoProvider;
use rustls::SupportedProtocolVersion;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

pub use client::{TlsClient, TlsClientStream, TlsDialer};
pub use server::{TlsServer, TlsServerStream};
pub use verify::public_key_sha256;

pub use rb_adapter::BoxStream;

/// sing-box `C.TCPTimeout`, the default handshake timeout.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// sing-box `errMissingServerName`.
pub const MISSING_SERVER_NAME: &str = "missing server_name or insecure=true";

/// A TLS version as sing-box writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Version {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

/// sing-box `ParseTLSVersion`.
fn parse_version(version: &str) -> Result<Version, String> {
    match version {
        "1.0" => Ok(Version::Tls10),
        "1.1" => Ok(Version::Tls11),
        "1.2" => Ok(Version::Tls12),
        "1.3" => Ok(Version::Tls13),
        // Go's E.New("unknown tls version:", version) has no space.
        _ => Err(format!("unknown tls version:{version}")),
    }
}

/// The TLS versions `min_version`..`max_version` allow (TLS 1.2 to 1.3 by
/// default, like Go). rustls has neither TLS 1.0 nor 1.1.
fn versions(min_version: &str, max_version: &str) -> Result<(Version, Version), String> {
    let min = if min_version.is_empty() {
        Version::Tls12
    } else {
        parse_version(min_version).map_err(|error| format!("parse min_version: {error}"))?
    };
    let max = if max_version.is_empty() {
        Version::Tls13
    } else {
        parse_version(max_version).map_err(|error| format!("parse max_version: {error}"))?
    };
    if max < Version::Tls12 {
        return Err(format!("max_version {max_version}: TLS 1.0 and 1.1 are not supported by rust-box yet"));
    }
    Ok((min.max(Version::Tls12), max))
}

/// Go `tls.CipherSuites()` names of TLS 1.3 suites, which Go accepts and
/// does not apply (TLS 1.3 suites are not configurable).
const TLS13_SUITE_NAMES: &[&str] =
    &["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"];

/// Go `tls.CipherSuites()` names rustls lacks.
const UNSUPPORTED_SUITE_NAMES: &[&str] = &[
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
];

fn tls12_suite(name: &str) -> Option<rustls::SupportedCipherSuite> {
    use provider::cipher_suite as suite;
    Some(match name {
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        _ => return None,
    })
}

/// The crypto provider and protocol versions the options describe.
struct Crypto {
    provider: Arc<CryptoProvider>,
    versions: Vec<&'static SupportedProtocolVersion>,
}

fn crypto(
    min_version: &str,
    max_version: &str,
    cipher_suites: &Listable<String>,
    curves: &Listable<CurvePreference>,
) -> Result<Crypto, String> {
    let (min, max) = versions(min_version, max_version)?;
    let mut provider = provider::default_provider();
    if !cipher_suites.is_empty() {
        let mut tls12 = Vec::new();
        for name in cipher_suites.iter() {
            if TLS13_SUITE_NAMES.contains(&name.as_str()) {
                continue;
            }
            if UNSUPPORTED_SUITE_NAMES.contains(&name.as_str()) {
                return Err(format!("cipher_suite {name} is not supported by rust-box yet"));
            }
            match tls12_suite(name) {
                Some(suite) => tls12.push(suite),
                None => return Err(format!("unknown cipher_suite: {name}")),
            }
        }
        provider.cipher_suites.retain(|suite| suite.version() == &rustls::version::TLS13);
        provider.cipher_suites.extend(tls12);
    }
    if !curves.is_empty() {
        // Go picks from the set in its own preference order.
        let mut groups = Vec::new();
        for (curve, group) in [
            (CurvePreference::X25519, provider::kx_group::X25519),
            (CurvePreference::P256, provider::kx_group::SECP256R1),
            (CurvePreference::P384, provider::kx_group::SECP384R1),
        ] {
            if curves.iter().any(|wanted| *wanted == curve) {
                groups.push(group);
            }
        }
        if let Some(curve) = curves
            .iter()
            .find(|curve| !matches!(curve, CurvePreference::X25519 | CurvePreference::P256 | CurvePreference::P384))
        {
            return Err(format!("curve {} is not supported by rust-box yet", curve.name()));
        }
        provider.kx_groups = groups;
    }
    let has_tls12 = provider.cipher_suites.iter().any(|suite| suite.version() == &rustls::version::TLS12);
    let mut versions = Vec::new();
    if min <= Version::Tls12 && max >= Version::Tls12 && has_tls12 {
        versions.push(&rustls::version::TLS12);
    }
    if max >= Version::Tls13 {
        versions.push(&rustls::version::TLS13);
    }
    if versions.is_empty() {
        return Err("no usable TLS version and cipher suite".into());
    }
    Ok(Crypto { provider: Arc::new(provider), versions })
}

/// Joins inline PEM lines (sing-box `strings.Join(lines, "\n")`).
fn join_lines(lines: &Listable<String>) -> Vec<u8> {
    lines.0.join("\n").into_bytes()
}

fn read_file(path: &str) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

/// Go `tls.X509KeyPair`: a certificate chain and its private key, checked to
/// belong together.
fn key_pair(
    certificate: &[u8],
    key: &[u8],
    provider: &CryptoProvider,
) -> Result<Arc<rustls::sign::CertifiedKey>, String> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(certificate).collect::<Result<_, _>>().map_err(|error| error.to_string())?;
    if chain.is_empty() {
        return Err("tls: failed to find any PEM data in certificate input".into());
    }
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|error| match error {
        rustls_pki_types::pem::Error::NoItemsFound => "tls: failed to find any PEM data in key input".to_string(),
        error => error.to_string(),
    })?;
    let certified = rustls::sign::CertifiedKey::from_der(chain, key, provider).map_err(|error| match error {
        rustls::Error::InconsistentKeys(_) => "tls: private key does not match public key".to_string(),
        error => error.to_string(),
    })?;
    Ok(Arc::new(certified))
}

fn timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "TLS handshake: context deadline exceeded")
}

#[cfg(test)]
mod tests;
