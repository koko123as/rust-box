//! End to end: route rules with `rule_set` items over inline, local
//! (source and binary) and remote rule-sets, including a local file that
//! changes while the box runs.

use std::net::SocketAddr;
use std::time::Duration;

use rust_box::RustBox;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

/// Serves `body` to every HTTP GET.
async fn http_server(body: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let body = body.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => request.extend_from_slice(&buffer[..read]),
                    }
                }
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });
    address
}

/// A SOCKS5 CONNECT; the reply code (0 when connected).
async fn socks5(proxy: SocketAddr, host: &str, port: u16) -> (u8, TcpStream) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    match stream.read_exact(&mut reply).await {
        Ok(_) => (reply[1], stream),
        Err(_) => (255, stream),
    }
}

async fn reaches(proxy: SocketAddr, host: &str, port: u16) -> bool {
    let (code, mut stream) = socks5(proxy, host, port).await;
    if code != 0 {
        return false;
    }
    if stream.write_all(b"ping").await.is_err() {
        return false;
    }
    let mut buffer = [0u8; 4];
    matches!(tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buffer)).await, Ok(Ok(_)))
        && &buffer == b"ping"
}

#[tokio::test]
async fn route_rules_use_rule_sets() {
    let echo = echo_server().await;
    let directory = tempfile::tempdir().unwrap();
    let local = directory.path().join("local.json");
    std::fs::write(&local, r#"{"version":3,"rules":[{"domain":"localhost"}]}"#).unwrap();
    // A binary rule-set written by `rule-set compile` and served over HTTP;
    // downloaded through `direct`, since the default outbound (`final`)
    // blocks, as in sing-box.
    let compiled = rb_config::srs::write(
        &rb_config::PlainRuleSetCompat::parse(br#"{"version":2,"rules":[{"domain_suffix":"remote.test"}]}"#)
            .unwrap()
            .options,
        2,
    )
    .unwrap();
    let server = http_server(compiled).await;
    let config = format!(
        r#"{{
  "inbounds": [{{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}}],
  "outbounds": [{{"type": "direct", "tag": "direct"}}, {{"type": "block", "tag": "block"}}],
  "route": {{
    "rule_set": [
      {{"tag": "blocked", "rules": [{{"domain_suffix": "blocked.test"}}]}},
      {{"type": "local", "tag": "local", "path": {local:?}}},
      {{"type": "remote", "tag": "remote", "format": "binary", "url": "http://{server}/remote.srs", "download_detour": "direct"}}
    ],
    "rules": [
      {{"rule_set": "blocked", "action": "reject"}},
      {{"rule_set": "remote", "action": "reject"}},
      {{"rule_set": ["local"], "outbound": "direct"}}
    ],
    "final": "block"
  }}
}}"#
    );
    let options = rb_config::parse(&config).unwrap();
    let instance = RustBox::new(&options).unwrap();
    instance.start().await.unwrap();
    let proxy = instance.inbounds()[0].local_addr().unwrap();

    assert!(reaches(proxy, "localhost", echo.port()).await);
    assert!(!reaches(proxy, "a.blocked.test", echo.port()).await);
    assert!(!reaches(proxy, "x.remote.test", echo.port()).await);

    // The local file changes: localhost now falls through to `final`.
    std::fs::write(&local, r#"{"version":3,"rules":[{"domain":"other.test"}]}"#).unwrap();
    let mut blocked = false;
    for _ in 0..50 {
        if !reaches(proxy, "localhost", echo.port()).await {
            blocked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(blocked, "the reloaded rule-set was not used");
    instance.close().await;
}
