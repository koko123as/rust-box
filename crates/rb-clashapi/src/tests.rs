use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

use crate::http::{self, Request};

#[tokio::test]
async fn reads_requests_and_bodies() {
    let (mut client, server) = tokio::io::duplex(4096);
    client
        .write_all(
            b"\r\nPATCH /configs?a=1&level=debug HTTP/1.1\r\nHost: x\r\nContent-Length: 15\r\n\r\n{\"mode\":\"rule\"}GET / HTTP/1.0\r\n\r\n",
        )
        .await
        .unwrap();
    let mut reader = BufReader::new(server);
    let Ok(first) = http::read_request(&mut reader).await else { panic!("first request") };
    assert_eq!(first.method, "PATCH");
    assert_eq!(first.path, "/configs");
    assert_eq!(first.query_get("level"), "debug");
    assert_eq!(first.query_get("missing"), "");
    assert_eq!(first.body, b"{\"mode\":\"rule\"}");
    assert!(first.keep_alive);
    let Ok(second) = http::read_request(&mut reader).await else { panic!("second request") };
    assert!(!second.keep_alive);
}

#[test]
fn websocket_handshake_and_frames() {
    let request = Request {
        method: "GET".into(),
        path: "/traffic".into(),
        headers: vec![
            ("Upgrade".into(), "websocket".into()),
            ("Connection".into(), "keep-alive, Upgrade".into()),
            ("Sec-WebSocket-Version".into(), "13".into()),
            ("Sec-WebSocket-Key".into(), "dGhlIHNhbXBsZSBub25jZQ==".into()),
        ],
        ..Default::default()
    };
    let head = String::from_utf8(http::websocket_accept(&request, Vec::new()).unwrap()).unwrap();
    // RFC 6455's example.
    assert!(head.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "{head}");
    assert!(head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
    assert_eq!(http::websocket_frame(1, b"hi"), vec![0x81, 2, b'h', b'i']);
    assert_eq!(&http::websocket_frame(1, &[0; 300])[..4], &[0x81, 126, 1, 44]);
    let mut bad = request.clone();
    bad.headers[2].1 = "8".into();
    assert_eq!(http::websocket_accept(&bad, Vec::new()).unwrap_err().status, 426);
}

#[tokio::test]
async fn websocket_drain_answers_ping_and_close() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
    // A masked ping "ab", then a masked close with code 1000.
    let mask = [1u8, 2, 3, 4];
    let mut frames = vec![0x89, 0x82];
    frames.extend_from_slice(&mask);
    frames.extend(b"ab".iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    frames.extend_from_slice(&[0x88, 0x82]);
    frames.extend_from_slice(&mask);
    frames.extend([0x03u8, 0xe8].iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    client.write_all(&frames).await.unwrap();
    http::websocket_drain(&mut server, sender).await.unwrap();
    assert_eq!(receiver.recv().await.unwrap(), vec![0x8A, 2, b'a', b'b']);
    assert_eq!(receiver.recv().await.unwrap(), vec![0x88, 2, 0x03, 0xe8]);
    drop(client);
    let mut rest = Vec::new();
    let _ = server.read_to_end(&mut rest).await;
}

#[test]
fn expand_env_like_go() {
    std::env::set_var("RB_CLASHAPI_TEST", "ui");
    assert_eq!(crate::expand_env("$RB_CLASHAPI_TEST/x"), "ui/x");
    assert_eq!(crate::expand_env("${RB_CLASHAPI_TEST}-y"), "ui-y");
    assert_eq!(crate::expand_env("a$"), "a$");
    assert_eq!(crate::expand_env("${RB_CLASHAPI_UNSET_VAR}z"), "z");
}

#[test]
fn zip_extraction_trims_single_directory() {
    // A stored entry and a deflated entry under "dist/".
    fn entry(name: &str, data: &[u8], method: u16, local: &mut Vec<u8>, central: &mut Vec<u8>) {
        let compressed = if method == 8 {
            use std::io::Write;
            let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(data).unwrap();
            encoder.finish().unwrap()
        } else {
            data.to_vec()
        };
        let offset = local.len() as u32;
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&[20, 0, 0, 0]);
        local.extend_from_slice(&method.to_le_bytes());
        local.extend_from_slice(&[0; 8]);
        local.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&[0, 0]);
        local.extend_from_slice(name.as_bytes());
        local.extend_from_slice(&compressed);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&[0; 8]);
        central.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let (mut local, mut central) = (Vec::new(), Vec::new());
    entry("dist/index.html", b"<html></html>", 0, &mut local, &mut central);
    entry("dist/assets/app.js", b"console.log(1)", 8, &mut local, &mut central);
    let mut archive = local.clone();
    let central_offset = archive.len() as u32;
    archive.extend_from_slice(&central);
    archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    archive.extend_from_slice(&[0, 0, 0, 0, 2, 0, 2, 0]);
    archive.extend_from_slice(&(central.len() as u32).to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&[0, 0]);
    let directory = tempfile::tempdir().unwrap();
    crate::ui::extract_zip(&archive, directory.path()).unwrap();
    assert_eq!(std::fs::read(directory.path().join("index.html")).unwrap(), b"<html></html>");
    assert_eq!(std::fs::read(directory.path().join("assets/app.js")).unwrap(), b"console.log(1)");
    let response = crate::ui::serve(directory.path(), "");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"<html></html>");
    assert_eq!(crate::ui::serve(directory.path(), "assets").status, 301);
    assert_eq!(crate::ui::serve(directory.path(), "index.html").status, 301);
    assert_eq!(crate::ui::serve(directory.path(), "../etc/passwd").status, 404);
    assert_eq!(
        crate::ui::serve(directory.path(), "assets/app.js").get("Content-Type"),
        Some("text/javascript; charset=utf-8")
    );
}
