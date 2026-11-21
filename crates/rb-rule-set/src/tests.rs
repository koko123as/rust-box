use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use rb_adapter::{BoxStream, InboundContext, Outbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

/// An outbound that connects straight to the destination IP.
struct Plain;

#[async_trait]
impl Outbound for Plain {
    fn tag(&self) -> &str {
        "direct"
    }

    fn kind(&self) -> &'static str {
        "direct"
    }

    async fn dial_tcp(&self, context: &InboundContext) -> io::Result<BoxStream> {
        let destination = &context.destination;
        let host = match destination.domain() {
            Some("localhost") => "127.0.0.1".parse().unwrap(),
            Some(other) => return Err(io::Error::other(format!("no DNS in tests: {other}"))),
            None => destination.ip().unwrap(),
        };
        Ok(Box::new(TcpStream::connect((host, destination.port)).await?))
    }
}

fn env(store: &str, certificates: &[&str]) -> Env {
    let options = rb_config::CertificateOptions {
        store: store.into(),
        certificate: rb_config::types::Listable(certificates.iter().map(|text| text.to_string()).collect()),
        ..Default::default()
    };
    let outbounds = OutboundRegistry::new();
    outbounds.set(&[Arc::new(Plain) as Arc<dyn Outbound>]);
    Env {
        certificates: rb_certificate::Store::new(Some(&options)).unwrap(),
        outbounds,
        default_outbound: "direct".into(),
        validator: Arc::default(),
    }
}

fn options(json: &str) -> RuleSetOptions {
    serde_json::from_str(json).unwrap()
}

fn matches(rule_set: &ManagedRuleSet, domain: &str) -> bool {
    let mut metadata = rb_rule::Metadata { domain: Some(domain), ..Default::default() };
    rule_set.matches(&mut metadata)
}

const SOURCE_V1: &str = r#"{"version":3,"rules":[{"domain_suffix":"one.test"}]}"#;
const SOURCE_V2: &str = r#"{"version":3,"rules":[{"domain_suffix":"two.test"}]}"#;

#[test]
fn inline_and_errors() {
    let env = env("none", &[]);
    let rule_set = ManagedRuleSet::new(&options(r#"{"tag":"i","rules":[{"domain":"a.test"}]}"#), "i", &env).unwrap();
    assert!(matches(&rule_set, "a.test") && !matches(&rule_set, "b.test"));
    let error = ManagedRuleSet::new(&options(r#"{"tag":"i","rules":[]}"#), "i", &env).err().unwrap();
    assert_eq!(error.0, "empty inline rule-set");
    let error =
        ManagedRuleSet::new(&options(r#"{"tag":"i","rules":[{"domain_regex":"("}]}"#), "i", &env).err().unwrap();
    assert!(error.0.starts_with("parse rule_set.rules.[0]: domain_regex: parse expression 0"), "{error}");
    let error = ManagedRuleSet::new(&options(r#"{"type":"local","tag":"l","path":"/nonexistent/x.json"}"#), "l", &env)
        .err()
        .unwrap();
    assert!(error.0.contains("/nonexistent/x.json"), "{error}");
}

#[tokio::test]
async fn local_file_reload() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rules.json");
    std::fs::write(&path, SOURCE_V1).unwrap();
    let env = env("none", &[]);
    let json = format!(r#"{{"type":"local","tag":"l","path":{:?}}}"#, path.to_string_lossy());
    let rule_set = ManagedRuleSet::new(&options(&json), "l", &env).unwrap();
    rule_set.start(&env).await.unwrap();
    assert!(matches(&rule_set, "a.one.test"));
    std::fs::write(&path, SOURCE_V2).unwrap();
    let mut reloaded = false;
    for _ in 0..100 {
        if matches(&rule_set, "a.two.test") {
            reloaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(reloaded);
    assert!(!matches(&rule_set, "a.one.test"));
    // A broken file keeps the rules that work.
    std::fs::write(&path, "{").unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(matches(&rule_set, "a.two.test"));
    // An update the validator refuses is not used either.
    let refused = env.clone();
    refused.validator.set(Box::new(|tag: &str, _: &RuleSetMetadata| Err(format!("refused {tag}")))).ok().unwrap();
    let rule_set = ManagedRuleSet::new(&options(&json), "l", &refused).unwrap();
    rule_set.start(&refused).await.unwrap();
    std::fs::write(&path, SOURCE_V1).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(matches(&rule_set, "a.two.test"));
    rule_set.close();
}

struct Server {
    port: u16,
    requests: Arc<AtomicUsize>,
    not_modified: Arc<AtomicUsize>,
    body: Arc<Mutex<(Vec<u8>, &'static str)>>,
}

/// An HTTP(S) server answering every GET with the current body and its
/// ETag, 304 when `If-None-Match` names it; the body is gzip-encoded when
/// the client accepts it.
async fn serve(tls: Option<tokio_rustls::TlsAcceptor>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(AtomicUsize::new(0));
    let not_modified = Arc::new(AtomicUsize::new(0));
    let body = Arc::new(Mutex::new((SOURCE_V1.as_bytes().to_vec(), "\"v1\"")));
    let (counter, unchanged, current) = (requests.clone(), not_modified.clone(), body.clone());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (counter, unchanged, current, tls) = (counter.clone(), unchanged.clone(), current.clone(), tls.clone());
            tokio::spawn(async move {
                let mut stream: Box<dyn rb_adapter::Stream> = match tls {
                    Some(acceptor) => match acceptor.accept(stream).await {
                        Ok(stream) => Box::new(stream),
                        Err(_) => return,
                    },
                    None => Box::new(stream),
                };
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let Ok(read) = stream.read(&mut buffer).await else { return };
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let request = String::from_utf8_lossy(&request).to_lowercase();
                let (content, etag) = current.lock().unwrap().clone();
                let response = if request.contains(&format!("if-none-match: {}", etag.to_lowercase())) {
                    unchanged.fetch_add(1, Ordering::SeqCst);
                    format!("HTTP/1.1 304 Not Modified\r\nETag: {etag}\r\n\r\n").into_bytes()
                } else if request.starts_with("get /missing") {
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
                } else {
                    assert!(request.contains("accept-encoding: gzip"));
                    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                    std::io::Write::write_all(&mut encoder, &content).unwrap();
                    let encoded = encoder.finish().unwrap();
                    let mut response = format!(
                        "HTTP/1.1 200 OK\r\nETag: {etag}\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                        encoded.len()
                    )
                    .into_bytes();
                    response.extend_from_slice(&encoded);
                    response
                };
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Server { port, requests, not_modified, body }
}

#[tokio::test]
async fn remote_etag_and_not_modified() {
    let server = serve(None).await;
    let env = env("none", &[]);
    let json = format!(
        r#"{{"type":"remote","tag":"r","url":"http://127.0.0.1:{}/r.json","update_interval":"1h"}}"#,
        server.port
    );
    let rule_set = ManagedRuleSet::new(&options(&json), "r", &env).unwrap();
    assert!(!matches(&rule_set, "a.one.test"));
    rule_set.start(&env).await.unwrap();
    assert!(matches(&rule_set, "a.one.test"));
    // Unchanged: 304, the rules stay.
    rule_set.update_once().await;
    assert_eq!(server.not_modified.load(Ordering::SeqCst), 1);
    assert!(matches(&rule_set, "a.one.test"));
    // Changed: the new rules and ETag are taken.
    *server.body.lock().unwrap() = (SOURCE_V2.as_bytes().to_vec(), "\"v2\"");
    rule_set.update_once().await;
    assert!(matches(&rule_set, "a.two.test") && !matches(&rule_set, "a.one.test"));
    rule_set.update_once().await;
    assert_eq!(server.not_modified.load(Ordering::SeqCst), 2);
    assert_eq!(server.requests.load(Ordering::SeqCst), 4);
    // A failed initial download fails the start.
    let json = format!(r#"{{"type":"remote","tag":"m","url":"http://127.0.0.1:{}/missing.json"}}"#, server.port);
    let missing = ManagedRuleSet::new(&options(&json), "m", &env).unwrap();
    let error = missing.start(&env).await.unwrap_err();
    assert_eq!(error.0, "initial rule-set: m: unexpected status: 404 Not Found");
    // The initial path is used instead of a download.
    let directory = tempfile::tempdir().unwrap();
    let initial = directory.path().join("m.json");
    std::fs::write(&initial, SOURCE_V2).unwrap();
    let json = format!(
        r#"{{"type":"remote","tag":"m","url":"http://127.0.0.1:{}/missing.json","initial_path":{:?}}}"#,
        server.port,
        initial.to_string_lossy()
    );
    let from_file = ManagedRuleSet::new(&options(&json), "m", &env).unwrap();
    from_file.start(&env).await.unwrap();
    assert!(matches(&from_file, "x.two.test"));
}

#[tokio::test]
async fn remote_https_with_custom_ca() {
    let certificate = include_str!("../tests/data/server.pem");
    let key = include_str!("../tests/data/server.key");
    let ca = include_str!("../tests/data/ca.pem");
    use rustls_pki_types::pem::PemObject;
    let chain = vec![rustls_pki_types::CertificateDer::from_pem_slice(certificate.as_bytes()).unwrap()];
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let server = serve(Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))).await;
    let json = format!(r#"{{"type":"remote","tag":"s","url":"https://localhost:{}/s.json"}}"#, server.port);
    // Trusted through the `certificate` section.
    let trusted = env("none", &[ca]);
    let rule_set = ManagedRuleSet::new(&options(&json), "s", &trusted).unwrap();
    rule_set.start(&trusted).await.unwrap();
    assert!(matches(&rule_set, "a.one.test"));
    // Not trusted by the embedded Mozilla roots.
    let untrusted = env("mozilla", &[]);
    let rule_set = ManagedRuleSet::new(&options(&json), "s", &untrusted).unwrap();
    let error = rule_set.start(&untrusted).await.unwrap_err();
    assert!(error.0.contains("certificate"), "{error}");
}

#[tokio::test]
async fn binary_rule_sets_download() {
    let server = serve(None).await;
    let compat = PlainRuleSetCompat::parse(SOURCE_V2.as_bytes()).unwrap();
    let binary = rb_config::srs::write(&compat.options, 2).unwrap();
    *server.body.lock().unwrap() = (binary, "\"b\"");
    let env = env("none", &[]);
    let json = format!(r#"{{"type":"remote","tag":"b","url":"http://127.0.0.1:{}/b.srs"}}"#, server.port);
    let rule_set = ManagedRuleSet::new(&options(&json), "b", &env).unwrap();
    rule_set.start(&env).await.unwrap();
    assert!(matches(&rule_set, "a.two.test"));
}
