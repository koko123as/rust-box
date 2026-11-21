//! End to end: a box with a mixed inbound, direct and block outbounds,
//! driven over SOCKS5 and HTTP against a local echo server.

use std::net::SocketAddr;

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
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&buffer[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    address
}

async fn start(config: &str) -> (RustBox, SocketAddr) {
    let options = rb_config::parse(config).unwrap();
    let instance = RustBox::new(&options).unwrap();
    instance.start().await.unwrap();
    let address = instance.inbounds()[0].local_addr().unwrap();
    (instance, address)
}

const CONFIG: &str = r#"{
  "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}],
  "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}],
  "route": {
    "rules": [
      {"action": "sniff"},
      {"domain_suffix": "blocked.test", "action": "reject"},
      {"protocol": "ssh", "outbound": "block"},
      {"domain": "localhost", "outbound": "direct"}
    ],
    "final": "direct"
  }
}"#;

async fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    assert_eq!(reply[1], 0, "socks5 reply");
    Ok(stream)
}

#[tokio::test]
async fn socks5_through_direct() {
    let echo = echo_server().await;
    let (_instance, proxy) = start(CONFIG).await;
    let mut stream = socks5_connect(proxy, "localhost", echo.port()).await.unwrap();
    stream.write_all(b"hello over socks").await.unwrap();
    let mut buffer = [0u8; 16];
    stream.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"hello over socks");
}

#[tokio::test]
async fn http_connect_and_plain() {
    let echo = echo_server().await;
    let (_instance, proxy) = start(CONFIG).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", echo.port()).as_bytes()).await.unwrap();
    let mut reply = vec![0u8; 39];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, b"HTTP/1.1 200 Connection established\r\n\r\n");
    stream.write_all(b"ping").await.unwrap();
    let mut buffer = [0u8; 4];
    stream.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"ping");

    // A plain request is rewritten to origin form; the HTTP server sends
    // the request head back as its body.
    let http = http_server().await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let request = format!("GET http://127.0.0.1:{}/x HTTP/1.1\r\nProxy-Connection: keep-alive\r\n\r\n", http.port());
    stream.write_all(request.as_bytes()).await.unwrap();
    let (head, body) = read_response(&mut stream).await;
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert!(body.starts_with("GET /x HTTP/1.1\r\n"), "{body}");
    assert!(!body.contains("Proxy-Connection"));
}

/// An HTTP/1.1 server that answers every request with its own head as the
/// body, keeping connections open.
async fn http_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut data = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    while let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = data.drain(..end + 4).collect();
                        let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", head.len());
                        if stream.write_all(response.as_bytes()).await.is_err()
                            || stream.write_all(&head).await.is_err()
                        {
                            return;
                        }
                    }
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => data.extend_from_slice(&chunk[..read]),
                    }
                }
            });
        }
    });
    address
}

/// Reads one response with a Content-Length body.
async fn read_response(stream: &mut TcpStream) -> (String, String) {
    let mut data = Vec::new();
    let mut byte = [0u8; 1];
    while !data.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).await.unwrap(), 1, "connection closed in head: {data:?}");
        data.push(byte[0]);
    }
    let head = String::from_utf8(data).unwrap();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .map(|value| value.trim().parse().unwrap())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.unwrap();
    (head, String::from_utf8(body).unwrap())
}

#[tokio::test]
async fn http_keep_alive_reuses_the_client_connection() {
    let http = http_server().await;
    let (_instance, proxy) = start(CONFIG).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    // Two requests, to different paths, then a third without keep-alive.
    for (index, path) in ["/first", "/second"].iter().enumerate() {
        let request = format!(
            "GET http://localhost:{}{path} HTTP/1.1\r\nHost: localhost\r\nProxy-Connection: keep-alive\r\n\r\n",
            http.port()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let (head, body) = read_response(&mut stream).await;
        assert!(head.contains("Proxy-Connection: keep-alive"), "request {index}: {head}");
        assert!(body.starts_with(&format!("GET {path} HTTP/1.1\r\nHost: localhost:{}\r\n", http.port())), "{body}");
    }
    let request = format!("POST http://localhost:{}/last HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody", http.port());
    stream.write_all(request.as_bytes()).await.unwrap();
    let (head, body) = read_response(&mut stream).await;
    assert!(head.contains("Connection: close"), "{head}");
    assert!(body.starts_with("POST /last HTTP/1.1\r\n"), "{body}");
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "the proxy closes after a request without keep-alive");
}

#[tokio::test]
async fn reject_and_block() {
    let echo = echo_server().await;
    let (_instance, proxy) = start(CONFIG).await;
    // Rejected by domain: the connection is closed after the SOCKS reply.
    let mut stream = socks5_connect(proxy, "a.blocked.test", 80).await.unwrap();
    let mut buffer = [0u8; 1];
    assert_eq!(stream.read(&mut buffer).await.unwrap_or(0), 0);
    // Sniffed as SSH and sent to the block outbound.
    let mut stream = socks5_connect(proxy, "127.0.0.1", echo.port()).await.unwrap();
    stream.write_all(b"SSH-2.0-test\r\n").await.unwrap();
    assert_eq!(stream.read(&mut buffer).await.unwrap_or(0), 0);
}

#[tokio::test]
async fn socks_authentication() {
    let echo = echo_server().await;
    let config = r#"{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":0,"users":[{"username":"u","password":"p"}]}],
                     "outbounds":[{"type":"direct","tag":"direct"}],
                     "route":{"rules":[{"auth_user":"u","outbound":"direct"},{"action":"reject"}]}}"#;
    let (_instance, proxy) = start(config).await;
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 2, 1, 1, b'u', 1, b'p']).await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 2, 1, 0]);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    stream.write_all(b"ok").await.unwrap();
    let mut buffer = [0u8; 2];
    stream.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"ok");
}
