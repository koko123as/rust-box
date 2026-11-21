//! XTLS Vision over rustls, both sides in process: a TLS 1.3 connection
//! carried through VLESS + Vision must go direct (raw on TCP) in both
//! directions and still carry its bytes intact; a TLS 1.2 or plain inner
//! connection stays padded inside the outer TLS.

use std::sync::Arc;

use rb_adapter::{BoxStream, Socksaddr};
use rb_protocol::vless::protocol::{self, Request, VlessStream, COMMAND_TCP, FLOW_VISION};
use rb_protocol::vless::vision::{RecordStream, VisionStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";

/// A leaf certificate for `name` signed by its own test CA.
struct Certificate {
    /// The CA, which clients trust.
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    pem: String,
    key_pem: String,
    der: CertificateDer<'static>,
    key_der: Vec<u8>,
}

fn certificate(name: &str) -> Certificate {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "rust-box vision test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap().signed_by(&key, &ca, &ca_key).unwrap();
    Certificate {
        ca_pem: ca.pem(),
        ca_der: ca.der().clone(),
        pem: cert.pem(),
        key_pem: key.serialize_pem(),
        der: cert.der().clone(),
        key_der: key.serialize_der(),
    }
}

fn lines(pem: &str) -> Vec<String> {
    pem.lines().map(str::to_string).collect()
}

/// The proxied ("inner") TLS, plain rustls with TLS 1.3 or 1.2 only.
fn inner_configs(tls13: bool) -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let certificate = certificate("inner.test");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] =
        if tls13 { &[&rustls::version::TLS13] } else { &[&rustls::version::TLS12] };
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.key_der.clone())),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.ca_der).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

/// Runs one Vision connection: the server side echoes the inner TLS's
/// bytes. Returns the direct states (client write, client read, server
/// write, server read) and whether the echo was intact.
async fn run(inner: Option<bool>) -> (bool, bool, bool, bool) {
    let outer = certificate("outer.test");
    let server_tls: rb_config::InboundTlsOptions = serde_json::from_value(
        json!({"enabled": true, "certificate": lines(&outer.pem), "key": lines(&outer.key_pem)}),
    )
    .unwrap();
    let server_tls = rb_tls::TlsServer::new(&server_tls).unwrap();
    server_tls.start().unwrap();
    let client_tls: rb_config::OutboundTlsOptions = serde_json::from_value(
        json!({"enabled": true, "server_name": "outer.test", "certificate": lines(&outer.ca_pem)}),
    )
    .unwrap();
    let store = rb_certificate::Store::new(None).unwrap();
    let client_tls = rb_tls::TlsClient::new(&client_tls, "127.0.0.1", &store).unwrap();
    let (inner_server, inner_client) = inner_configs(inner.unwrap_or(true));
    let uuid = protocol::parse_uuid(UUID);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let payload: Vec<u8> = (0..300_000u32).map(|index| (index % 251) as u8).collect();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let stream = RecordStream::new(Box::new(stream));
        let gate = stream.gate();
        let stream: BoxStream = Box::new(stream);
        let mut tls = server_tls.handshake(stream).await.unwrap();
        let request = protocol::read_request(&mut tls).await.unwrap();
        assert_eq!((request.command, request.flow.as_str()), (COMMAND_TCP, FLOW_VISION));
        let mut vision = VisionStream::new(VlessStream::server(tls), request.uuid, gate);
        match inner {
            Some(_) => {
                let acceptor = tokio_rustls::TlsAcceptor::from(inner_server);
                let mut inner = acceptor.accept(&mut vision).await.unwrap();
                let mut buffer = vec![0u8; 16 * 1024];
                loop {
                    let read = inner.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    inner.write_all(&buffer[..read]).await.unwrap();
                }
                inner.shutdown().await.unwrap();
            }
            None => {
                let mut buffer = vec![0u8; 16 * 1024];
                loop {
                    let read = vision.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    vision.write_all(&buffer[..read]).await.unwrap();
                }
                vision.shutdown().await.unwrap();
            }
        }
        (vision.is_direct_write(), vision.is_direct_read())
    });

    let stream = RecordStream::new(Box::new(TcpStream::connect(address).await.unwrap()));
    let gate = stream.gate();
    let stream: BoxStream = Box::new(stream);
    let tls = client_tls.handshake(stream).await.unwrap();
    let request = protocol::encode_request(&Request {
        uuid,
        command: COMMAND_TCP,
        destination: Some(Socksaddr::from_host_port("inner.test", 443)),
        flow: FLOW_VISION.into(),
    })
    .unwrap();
    let mut vision = VisionStream::new(VlessStream::client(tls, request), uuid, gate);
    vision.kick().await.unwrap();
    let echoed = match inner {
        Some(_) => {
            let connector = tokio_rustls::TlsConnector::from(inner_client);
            let name = ServerName::try_from("inner.test").unwrap();
            let inner = connector.connect(name, &mut vision).await.unwrap();
            let (mut reader, mut writer) = tokio::io::split(inner);
            let data = payload.clone();
            let writing = async move {
                writer.write_all(&data).await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let reading = async move {
                let mut echoed = Vec::new();
                reader.read_to_end(&mut echoed).await.unwrap();
                echoed
            };
            tokio::join!(writing, reading).1
        }
        None => {
            let (mut reader, mut writer) = tokio::io::split(&mut vision);
            let data = payload.clone();
            let writing = async move {
                writer.write_all(&data).await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let reading = async move {
                let mut echoed = Vec::new();
                reader.read_to_end(&mut echoed).await.unwrap();
                echoed
            };
            tokio::join!(writing, reading).1
        }
    };
    assert_eq!(echoed.len(), payload.len());
    assert!(echoed == payload, "echo intact");
    let (server_write, server_read) = server.await.unwrap();
    (vision.is_direct_write(), vision.is_direct_read(), server_write, server_read)
}

#[tokio::test]
async fn tls13_goes_direct_both_ways() {
    assert_eq!(run(Some(true)).await, (true, true, true, true));
}

#[tokio::test]
async fn tls12_stays_inside() {
    assert_eq!(run(Some(false)).await, (false, false, false, false));
}

#[tokio::test]
async fn plain_stays_inside() {
    assert_eq!(run(None).await, (false, false, false, false));
}
