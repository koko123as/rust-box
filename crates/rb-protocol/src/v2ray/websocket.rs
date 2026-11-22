//! V2Ray WebSocket transport (sing-box `transport/v2raywebsocket`).
//!
//! A WebSocket connection is exposed to the proxy protocol as a byte stream:
//! binary and text messages contribute payload bytes, while writes become
//! binary messages. Early data is validated by the configuration layer and is
//! not silently discarded.

use std::io;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use http::header::{HOST, USER_AGENT};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use rb_adapter::{BoxStream, Socksaddr};
use rb_config::{V2RayHeaders, V2RayWebSocketOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request as ServerRequest, Response};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_hdr_async, client_async, WebSocketStream};

const HANDSHAKE_TIMEOUT: Duration = rb_tls::DEFAULT_HANDSHAKE_TIMEOUT;
const DUPLEX_CAPACITY: usize = 64 * 1024;
const FRAME_CHUNK_SIZE: usize = 16 * 1024;

/// Establishes the V2Ray WebSocket client handshake over an already dialed
/// (and, when configured, TLS-wrapped) stream.
pub async fn client(stream: BoxStream, server: &Socksaddr, options: &V2RayWebSocketOptions) -> io::Result<BoxStream> {
    reject_early_data(options)?;
    let mut headers = build_headers(&options.headers)?;
    // sing-box moves a configured Host header to the request URL authority.
    let authority = match headers.remove(HOST) {
        Some(value) if !value.as_bytes().is_empty() => value
            .to_str()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid WebSocket Host: {error}")))?
            .to_owned(),
        _ => server.to_string(),
    };
    if headers.get(USER_AGENT).is_none_or(|value| value.as_bytes().is_empty()) {
        headers.insert(USER_AGENT, HeaderValue::from_static("Go-http-client/1.1"));
    }
    let path = normalized_path(&options.path);
    let uri = format!("ws://{authority}{path}");
    let mut request = uri
        .as_str()
        .into_client_request()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("websocket request: {error}")))?;
    for name in headers.keys() {
        let values = headers.get_all(name);
        if name.as_str() == "sec-websocket-protocol" {
            if let Some(first) = values.iter().next() {
                if first.as_bytes().is_empty() {
                    for value in values.iter() {
                        request.headers_mut().append(name.clone(), value.clone());
                    }
                } else {
                    request.headers_mut().append(name.clone(), first.clone());
                }
            }
        } else {
            for value in values.iter() {
                request.headers_mut().append(name.clone(), value.clone());
            }
        }
    }

    let websocket = tokio::time::timeout(HANDSHAKE_TIMEOUT, client_async(request, stream))
        .await
        .map_err(|_| handshake_timeout())?
        .map_err(|error| handshake_error(error.to_string()))?
        .0;
    Ok(byte_stream(websocket))
}

/// Accepts a V2Ray WebSocket server handshake over an already TLS-terminated
/// (when configured) inbound stream.
#[allow(clippy::result_large_err)]
pub async fn server(stream: BoxStream, options: &V2RayWebSocketOptions) -> io::Result<BoxStream> {
    reject_early_data(options)?;
    let path = normalized_path(&options.path);
    let response_headers = build_headers(&options.headers)?;
    let callback = move |request: &ServerRequest, mut response: Response| {
        if request.uri().path() != path {
            let mut error = ErrorResponse::new(Some("bad path".to_owned()));
            *error.status_mut() = StatusCode::NOT_FOUND;
            return Err(error);
        }
        for (name, value) in response_headers.iter() {
            response.headers_mut().append(name.clone(), value.clone());
        }
        Ok(response)
    };

    let websocket = tokio::time::timeout(HANDSHAKE_TIMEOUT, accept_hdr_async(stream, callback))
        .await
        .map_err(|_| handshake_timeout())?
        .map_err(|error| handshake_error(error.to_string()))?;
    Ok(byte_stream(websocket))
}

fn reject_early_data(options: &V2RayWebSocketOptions) -> io::Result<()> {
    if options.max_early_data > 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transport.max_early_data is not supported by rust-box yet",
        ));
    }
    if !options.early_data_header_name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "transport.early_data_header_name is not supported by rust-box yet",
        ));
    }
    Ok(())
}

fn normalized_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

fn build_headers(headers: &V2RayHeaders) -> io::Result<HeaderMap> {
    let mut result = HeaderMap::new();
    for (name, values) in headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid WebSocket header name: {error}"))
        })?;
        for value in values.iter() {
            let value = HeaderValue::from_bytes(value.as_bytes()).map_err(|error| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("invalid WebSocket header value: {error}"))
            })?;
            result.append(name.clone(), value);
        }
    }
    Ok(result)
}

fn byte_stream<S>(websocket: WebSocketStream<S>) -> BoxStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (application, bridge) = tokio::io::duplex(DUPLEX_CAPACITY);
    tokio::spawn(async move {
        let (mut application_read, mut application_write) = tokio::io::split(bridge);
        let (mut websocket_sink, mut websocket_source) = websocket.split();
        let mut buffer = vec![0u8; FRAME_CHUNK_SIZE];
        loop {
            tokio::select! {
                message = websocket_source.next() => {
                    match message {
                        Some(Ok(Message::Binary(payload))) => {
                            if application_write.write_all(payload.as_ref()).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Text(payload))) => {
                            if application_write.write_all(payload.as_bytes()).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Ping(payload))) => {
                            if websocket_sink.send(Message::Pong(payload)).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Pong(_))) => {}
                        Some(Ok(Message::Close(frame))) => {
                            let _ = websocket_sink.send(Message::Close(frame)).await;
                            break;
                        }
                        Some(Ok(_)) => {}
                        Some(Err(_)) | None => break,
                    }
                }
                read = application_read.read(&mut buffer) => {
                    match read {
                        Ok(0) => {
                            let _ = websocket_sink.send(Message::Close(None)).await;
                            break;
                        }
                        Ok(length) => {
                            let payload = buffer[..length].to_vec().into();
                            if websocket_sink.send(Message::Binary(payload)).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let _ = application_write.shutdown().await;
    });
    Box::new(application)
}

fn handshake_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "websocket handshake: context deadline exceeded")
}

fn handshake_error(error: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("websocket handshake: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn client_and_server_bridge_bidirectional_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_options = V2RayWebSocketOptions { path: "/proxy".into(), ..Default::default() };
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server(Box::new(stream), &server_options).await.unwrap()
        });

        let client_options = V2RayWebSocketOptions { path: "/proxy".into(), ..Default::default() };
        let client_stream = TcpStream::connect(address).await.unwrap();
        let mut client_stream =
            client(Box::new(client_stream), &Socksaddr::from(address), &client_options).await.unwrap();
        let mut server_stream = server_task.await.unwrap();

        client_stream.write_all(b"from client").await.unwrap();
        let mut received = [0u8; 11];
        server_stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"from client");

        server_stream.write_all(b"from server").await.unwrap();
        let mut received = [0u8; 11];
        client_stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"from server");
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)]
    async fn client_moves_configured_host_to_request_authority() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (host_sender, host_receiver) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept_hdr_async(stream, move |request: &ServerRequest, response: Response| {
                let _ = host_sender.send(request.headers().get(HOST).unwrap().to_str().unwrap().to_owned());
                Ok(response)
            })
            .await
            .unwrap()
        });

        let options = V2RayWebSocketOptions {
            path: "/proxy".into(),
            headers: std::collections::HashMap::from([(
                "Host".into(),
                rb_config::Listable(vec!["cdn.example".into()]),
            )]),
            ..Default::default()
        };
        let stream = TcpStream::connect(address).await.unwrap();
        let _client = client(Box::new(stream), &Socksaddr::from(address), &options).await.unwrap();
        assert_eq!(host_receiver.await.unwrap(), "cdn.example");
        server_task.abort();
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)]
    async fn client_uses_first_configured_subprotocol_and_validates_server_selection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (protocol_sender, protocol_receiver) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept_hdr_async(stream, move |request: &ServerRequest, mut response: Response| {
                let _ = protocol_sender
                    .send(request.headers().get("sec-websocket-protocol").unwrap().to_str().unwrap().to_owned());
                response.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static("alpha"));
                Ok(response)
            })
            .await
            .unwrap()
        });

        let options = V2RayWebSocketOptions {
            path: "/proxy".into(),
            headers: std::collections::HashMap::from([(
                "Sec-WebSocket-Protocol".into(),
                rb_config::Listable(vec!["alpha".into(), "beta".into()]),
            )]),
            ..Default::default()
        };
        let stream = TcpStream::connect(address).await.unwrap();
        let _client = client(Box::new(stream), &Socksaddr::from(address), &options).await.unwrap();
        assert_eq!(protocol_receiver.await.unwrap(), "alpha");
        server_task.abort();
    }
}
