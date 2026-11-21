use std::sync::Arc;
use std::time::Duration;

use rb_certificate::Store;
use rb_config::{CertificateOptions, InboundTlsOptions, Listable, OutboundTlsOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

/// A CA and a server certificate for `names` signed by it, as PEM.
pub(crate) struct TestPki {
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub key_spki_sha256: [u8; 32],
}

pub(crate) fn pki(names: &[&str]) -> TestPki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "rust-box test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(names.iter().map(|name| name.to_string()).collect::<Vec<_>>()).unwrap();
    let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
    let key_spki_sha256 = Sha256::digest(key.public_key_der()).into();
    TestPki { ca: ca.pem(), cert: cert.pem(), key: key.serialize_pem(), key_spki_sha256 }
}

use sha2::{Digest, Sha256};

fn lines(pem: &str) -> Listable<String> {
    Listable(pem.lines().map(str::to_string).collect())
}

fn empty_store() -> Arc<Store> {
    Store::new(Some(&CertificateOptions { store: "none".into(), ..Default::default() })).unwrap()
}

fn server_options(pki: &TestPki) -> InboundTlsOptions {
    InboundTlsOptions { enabled: true, certificate: lines(&pki.cert), key: lines(&pki.key), ..Default::default() }
}

fn client_options(pki: &TestPki) -> OutboundTlsOptions {
    OutboundTlsOptions { enabled: true, certificate: lines(&pki.ca), ..Default::default() }
}

/// Runs one handshake over an in-memory pipe and echoes a line through it.
async fn exchange(client: &TlsClient, server: &TlsServer) -> Result<Option<Vec<u8>>, String> {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let server = server.clone();
    let accept = tokio::spawn(async move {
        let mut stream = server.handshake(Box::new(b)).await.map_err(|error| error.to_string())?;
        let mut buffer = [0u8; 5];
        stream.read_exact(&mut buffer).await.map_err(|error| error.to_string())?;
        stream.write_all(&buffer).await.map_err(|error| error.to_string())?;
        stream.flush().await.map_err(|error| error.to_string())?;
        Ok::<_, String>(())
    });
    let result = async {
        let mut stream = client.handshake(Box::new(a)).await.map_err(|error| error.to_string())?;
        let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        stream.write_all(b"hello").await.map_err(|error| error.to_string())?;
        stream.flush().await.map_err(|error| error.to_string())?;
        let mut buffer = [0u8; 5];
        stream.read_exact(&mut buffer).await.map_err(|error| error.to_string())?;
        assert_eq!(&buffer, b"hello");
        Ok(alpn)
    }
    .await;
    let server_result = tokio::time::timeout(Duration::from_secs(5), accept).await;
    match (result, server_result) {
        (Ok(alpn), Ok(Ok(Ok(())))) => Ok(alpn),
        (Err(error), _) => Err(error),
        (Ok(_), Ok(Ok(Err(error)))) => Err(format!("server: {error}")),
        (Ok(_), other) => Err(format!("server: {other:?}")),
    }
}

#[tokio::test]
async fn verifies_and_negotiates_alpn() {
    let pki = pki(&["example.test"]);
    let mut server = server_options(&pki);
    server.alpn = Listable(vec!["h2".into(), "http/1.1".into()]);
    let server = TlsServer::new(&server).unwrap();
    let mut client = client_options(&pki);
    client.alpn = Listable(vec!["http/1.1".into()]);
    // The server address is the default server name.
    let tls = TlsClient::new(&client, "example.test", &empty_store()).unwrap();
    assert_eq!(tls.server_name(), "example.test");
    assert_eq!(exchange(&tls, &server).await.unwrap(), Some(b"http/1.1".to_vec()));

    // Another name fails verification.
    let wrong = TlsClient::new(&client, "other.test", &empty_store()).unwrap();
    let error = exchange(&wrong, &server).await.unwrap_err();
    assert!(error.contains("NotValidForName") || error.contains("not valid"), "{error}");

    // The store's roots: none here, so the server is unknown.
    let store_client =
        TlsClient::new(&OutboundTlsOptions { enabled: true, ..Default::default() }, "example.test", &empty_store())
            .unwrap();
    let error = exchange(&store_client, &server).await.unwrap_err();
    assert!(error.contains("UnknownIssuer"), "{error}");

    // disable_sni still verifies the name.
    let mut no_sni = client_options(&pki);
    no_sni.disable_sni = true;
    let tls = TlsClient::new(&no_sni, "example.test", &empty_store()).unwrap();
    exchange(&tls, &server).await.unwrap();
}

#[tokio::test]
async fn insecure_and_pinned_keys() {
    let pki = pki(&["example.test"]);
    let server = TlsServer::new(&server_options(&pki)).unwrap();
    let insecure = OutboundTlsOptions { enabled: true, insecure: true, ..Default::default() };
    let tls = TlsClient::new(&insecure, "", &empty_store()).unwrap();
    exchange(&tls, &server).await.unwrap();

    let pinned = OutboundTlsOptions {
        enabled: true,
        certificate_public_key_sha256: Listable(vec![rb_config::Base64Bytes(pki.key_spki_sha256.to_vec())]),
        ..Default::default()
    };
    let tls = TlsClient::new(&pinned, "anything.test", &empty_store()).unwrap();
    exchange(&tls, &server).await.unwrap();
    let wrong = OutboundTlsOptions {
        enabled: true,
        certificate_public_key_sha256: Listable(vec![rb_config::Base64Bytes(vec![0; 32])]),
        ..Default::default()
    };
    let tls = TlsClient::new(&wrong, "anything.test", &empty_store()).unwrap();
    let error = exchange(&tls, &server).await.unwrap_err();
    assert!(error.contains("unrecognized remote public key"), "{error}");

    // A self-signed server: `insecure` without certificate.
    let self_signed =
        TlsServer::new(&InboundTlsOptions { enabled: true, insecure: true, ..Default::default() }).unwrap();
    let tls = TlsClient::new(&insecure, "made.up", &empty_store()).unwrap();
    exchange(&tls, &self_signed).await.unwrap();
}

#[test]
fn spki_hash_matches() {
    let pki = pki(&["a.test"]);
    let der = rustls_pki_types::CertificateDer::from_pem_slice(pki.cert.as_bytes()).unwrap();
    assert_eq!(public_key_sha256(&der).unwrap(), pki.key_spki_sha256);
}

#[tokio::test]
async fn client_authentication() {
    let pki = pki(&["example.test"]);
    let client_pki = self::pki(&["client.test"]);
    let mut server = server_options(&pki);
    server.client_certificate = lines(&client_pki.ca);
    let server = TlsServer::new(&server).unwrap();

    let without = TlsClient::new(&client_options(&pki), "example.test", &empty_store()).unwrap();
    assert!(exchange(&without, &server).await.is_err());

    let mut with = client_options(&pki);
    with.client_certificate = lines(&client_pki.cert);
    with.client_key = lines(&client_pki.key);
    let with = TlsClient::new(&with, "example.test", &empty_store()).unwrap();
    exchange(&with, &server).await.unwrap();

    // request: a certificate is asked for, none needed, none verified.
    let mut request = server_options(&pki);
    request.client_authentication = rb_config::ClientAuthType::Request;
    let request = TlsServer::new(&request).unwrap();
    exchange(&without, &request).await.unwrap();

    // Pinned client keys.
    let mut pinned = server_options(&pki);
    pinned.client_authentication = rb_config::ClientAuthType::RequireAndVerify;
    pinned.client_certificate_public_key_sha256 =
        Listable(vec![rb_config::Base64Bytes(client_pki.key_spki_sha256.to_vec())]);
    let pinned = TlsServer::new(&pinned).unwrap();
    exchange(&with, &pinned).await.unwrap();
    assert!(exchange(&without, &pinned).await.is_err());

    let mut missing = server_options(&pki);
    missing.client_authentication = rb_config::ClientAuthType::VerifyIfGiven;
    assert!(TlsServer::new(&missing).unwrap_err().starts_with("missing client_certificate"));
}

#[tokio::test]
async fn versions_and_suites() {
    let pki = pki(&["example.test"]);
    let mut server = server_options(&pki);
    server.min_version = "1.3".into();
    let server = TlsServer::new(&server).unwrap();
    let mut client = client_options(&pki);
    client.max_version = "1.2".into();
    let tls = TlsClient::new(&client, "example.test", &empty_store()).unwrap();
    assert!(exchange(&tls, &server).await.is_err());

    // TLS 1.2 with a chosen suite.
    let mut server = server_options(&pki);
    server.max_version = "1.2".into();
    server.cipher_suites = Listable(vec!["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into()]);
    let server = TlsServer::new(&server).unwrap();
    let mut client = client_options(&pki);
    client.min_version = "1.0".into();
    client.curve_preferences = Listable(vec![rb_config::CurvePreference::P256]);
    let tls = TlsClient::new(&client, "example.test", &empty_store()).unwrap();
    exchange(&tls, &server).await.unwrap();

    let error = |options: OutboundTlsOptions| TlsClient::new(&options, "a.test", &empty_store()).unwrap_err();
    let base = OutboundTlsOptions { enabled: true, ..Default::default() };
    assert_eq!(
        error(OutboundTlsOptions { min_version: "1.4".into(), ..base.clone() }),
        "parse min_version: unknown tls version:1.4"
    );
    assert!(error(OutboundTlsOptions { max_version: "1.1".into(), ..base.clone() }).contains("not supported"));
    assert_eq!(
        error(OutboundTlsOptions { cipher_suites: Listable(vec!["TLS_RSA_WITH_RC4_128_SHA".into()]), ..base.clone() }),
        "unknown cipher_suite: TLS_RSA_WITH_RC4_128_SHA"
    );
    assert!(error(OutboundTlsOptions {
        cipher_suites: Listable(vec!["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".into()]),
        ..base.clone()
    })
    .contains("not supported by rust-box yet"));
    assert_eq!(TlsClient::new(&base, "", &empty_store()).unwrap_err(), "missing server_name or insecure=true");
    assert_eq!(
        error(OutboundTlsOptions { client_key: Listable(vec!["x".into()]), ..base.clone() }),
        "client certificate and client key must be provided together"
    );
    assert!(error(OutboundTlsOptions {
        certificate: Listable(vec!["x".into()]),
        certificate_public_key_sha256: Listable(vec![rb_config::Base64Bytes(vec![1])]),
        ..base.clone()
    })
    .contains("conflict"));
    assert_eq!(
        TlsServer::new(&InboundTlsOptions { enabled: true, ..Default::default() }).unwrap_err(),
        "missing certificate"
    );
    let other = self::pki(&["b.test"]);
    let mismatched = InboundTlsOptions {
        enabled: true,
        certificate: lines(&pki.cert),
        key: lines(&other.key),
        ..Default::default()
    };
    assert!(TlsServer::new(&mismatched).unwrap_err().starts_with("parse x509 key pair"));
}

#[tokio::test]
async fn reloads_certificate_files() {
    let first = pki(&["example.test"]);
    let directory = tempfile::tempdir().unwrap();
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&cert_path, &first.cert).unwrap();
    std::fs::write(&key_path, &first.key).unwrap();
    let server = TlsServer::new(&InboundTlsOptions {
        enabled: true,
        certificate_path: cert_path.to_string_lossy().into(),
        key_path: key_path.to_string_lossy().into(),
        ..Default::default()
    })
    .unwrap();
    server.start().unwrap();
    exchange(&TlsClient::new(&client_options(&first), "example.test", &empty_store()).unwrap(), &server).await.unwrap();

    let second = pki(&["example.test"]);
    // Key first, then certificate: the pair only matches after both.
    std::fs::write(&key_path, &second.key).unwrap();
    std::fs::write(&cert_path, &second.cert).unwrap();
    let client = TlsClient::new(&client_options(&second), "example.test", &empty_store()).unwrap();
    let mut ok = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if exchange(&client, &server).await.is_ok() {
            ok = true;
            break;
        }
    }
    server.close();
    assert!(ok, "the new certificate was not loaded");
}
