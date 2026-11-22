//! gRPC-lite message framing over an asynchronous byte stream.
use super::h2::{H2Client, H2Server};
use http::{header, Request, Response, StatusCode};
use rb_adapter::Host;
use rb_adapter::{BoxStream, Socksaddr};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::h2::H2Stream;

/// A byte stream carrying one gRPC-lite envelope per successful non-empty write.
pub struct GrpcLiteStream<S = H2Stream> {
    inner: S,
    input: BytesMut,
    payload: Bytes,
    header: [u8; 5],
    header_len: usize,
    outer_remaining: Option<usize>,
    tag_seen: bool,
    varint_value: u64,
    varint_len: usize,
    payload_remaining: usize,
    output: Option<(Bytes, usize)>,
    pending_write_len: Option<usize>,
    eof: bool,
    write_closed: bool,
}

impl<S> GrpcLiteStream<S> {
    /// Wrap an H2 byte stream (or another async byte stream) with gRPC-lite framing.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            input: BytesMut::new(),
            payload: Bytes::new(),
            header: [0; 5],
            header_len: 0,
            outer_remaining: None,
            tag_seen: false,
            varint_value: 0,
            varint_len: 0,
            payload_remaining: 0,
            output: None,
            pending_write_len: None,
            eof: false,
            write_closed: false,
        }
    }
}

impl<S: AsyncRead + Unpin> GrpcLiteStream<S> {
    fn take_payload_chunk(&mut self) -> io::Result<bool> {
        if self.input.is_empty() || self.payload_remaining == 0 {
            return Ok(false);
        }
        let n = self.input.len().min(self.payload_remaining);
        self.payload = self.input.split_to(n).freeze();
        self.payload_remaining -= n;
        let outer_remaining = self.outer_remaining.as_mut().expect("payload has an outer frame");
        *outer_remaining = outer_remaining
            .checked_sub(n)
            .ok_or_else(|| invalid_data("gRPC-lite envelope and protobuf lengths differ"))?;
        if self.payload_remaining == 0 {
            if *outer_remaining != 0 {
                return Err(invalid_data("gRPC-lite envelope and protobuf lengths differ"));
            }
            self.outer_remaining = None;
            self.tag_seen = false;
            self.varint_value = 0;
            self.varint_len = 0;
        }
        Ok(true)
    }

    fn parse_available(&mut self) -> io::Result<bool> {
        if self.payload.has_remaining() {
            return Ok(true);
        }
        self.payload = Bytes::new();
        if self.payload_remaining > 0 {
            return self.take_payload_chunk();
        }
        loop {
            if self.outer_remaining.is_none() {
                while self.header_len < self.header.len() && !self.input.is_empty() {
                    self.header[self.header_len] = self.input[0];
                    self.input.advance(1);
                    self.header_len += 1;
                }
                if self.header_len < self.header.len() {
                    return Ok(false);
                }
                if self.header[0] != 0 {
                    return Err(invalid_data("compressed gRPC-lite messages are unsupported"));
                }
                self.outer_remaining = Some(u32::from_be_bytes(self.header[1..5].try_into().unwrap()) as usize);
                self.header_len = 0;
                self.tag_seen = false;
                self.varint_value = 0;
                self.varint_len = 0;
            }

            if !self.tag_seen {
                if self.outer_remaining == Some(0) {
                    return Err(invalid_data("invalid gRPC-lite protobuf message"));
                }
                if self.input.is_empty() {
                    return Ok(false);
                }
                if self.input[0] != 0x0a {
                    return Err(invalid_data("invalid gRPC-lite protobuf message"));
                }
                self.input.advance(1);
                *self.outer_remaining.as_mut().unwrap() -= 1;
                self.tag_seen = true;
            }

            loop {
                if self.outer_remaining == Some(0) {
                    return Err(invalid_data("truncated gRPC-lite protobuf length"));
                }
                if self.input.is_empty() {
                    return Ok(false);
                }
                let byte = self.input[0];
                self.input.advance(1);
                let index = self.varint_len;
                if index >= 10 || (index == 9 && byte > 1) {
                    return Err(invalid_data("gRPC-lite varint overflow"));
                }
                self.varint_value |= u64::from(byte & 0x7f) << (index * 7);
                *self.outer_remaining.as_mut().unwrap() -= 1;
                self.varint_len += 1;
                if byte & 0x80 == 0 {
                    break;
                }
                if self.varint_len == 10 {
                    return Err(invalid_data("gRPC-lite varint overflow"));
                }
            }

            let payload_len =
                usize::try_from(self.varint_value).map_err(|_| invalid_data("gRPC-lite payload length overflow"))?;
            if self.outer_remaining != Some(payload_len) {
                return Err(invalid_data("gRPC-lite envelope and protobuf lengths differ"));
            }
            self.payload_remaining = payload_len;
            if payload_len == 0 {
                self.outer_remaining = None;
                self.tag_seen = false;
                self.varint_value = 0;
                self.varint_len = 0;
                continue;
            }
            return self.take_payload_chunk();
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for GrpcLiteStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.payload.has_remaining() {
                let n = this.payload.len().min(buf.remaining());
                buf.put_slice(&this.payload.split_to(n));
                return Poll::Ready(Ok(()));
            }
            match this.parse_available() {
                Ok(true) => continue,
                Err(error) => return Poll::Ready(Err(error)),
                Ok(false) if this.eof => {
                    if this.header_len != 0 || this.outer_remaining.is_some() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated gRPC-lite frame",
                        )));
                    }
                    return Poll::Ready(Ok(()));
                }
                Ok(false) => {}
            }
            // Retain at most the current read chunk and consume its framing as soon as possible.
            if this.input.is_empty() {
                let mut chunk = [0u8; 8192];
                let mut read_buf = ReadBuf::new(&mut chunk);
                match ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read_buf)) {
                    Ok(()) if read_buf.filled().is_empty() => this.eof = true,
                    Ok(()) => this.input.extend_from_slice(read_buf.filled()),
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> GrpcLiteStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some((frame, offset)) = self.output.as_mut() {
            if *offset == frame.len() {
                self.output = None;
                break;
            }
            match ready!(Pin::new(&mut self.inner).poll_write(cx, &frame[*offset..])) {
                Ok(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write gRPC-lite frame",
                    )))
                }
                Ok(n) => *offset += n,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GrpcLiteStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "gRPC-lite stream is closed")));
        }
        if let Some(payload_len) = self.pending_write_len {
            ready!(self.poll_drain(cx))?;
            self.pending_write_len = None;
            return Poll::Ready(Ok(payload_len));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.poll_drain(cx))?;
        let payload_len = u32::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "gRPC-lite payload exceeds u32 length"))?;
        let mut varint = [0u8; 10];
        let varint_len = encode_varint(payload_len as u64, &mut varint);
        let protobuf_len = 1usize + varint_len + data.len();
        let protobuf_len = u32::try_from(protobuf_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "gRPC-lite message exceeds u32 length"))?;
        let mut frame = BytesMut::with_capacity(5 + protobuf_len as usize);
        frame.extend_from_slice(&[0]);
        frame.extend_from_slice(&protobuf_len.to_be_bytes());
        frame.extend_from_slice(&[0x0a]);
        frame.extend_from_slice(&varint[..varint_len]);
        frame.extend_from_slice(data);
        self.output = Some((frame.freeze(), 0));
        self.pending_write_len = Some(data.len());
        ready!(self.poll_drain(cx))?;
        self.pending_write_len = None;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        self.write_closed = true;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn encode_varint(mut value: u64, output: &mut [u8; 10]) -> usize {
    let mut len = 0;
    while value >= 0x80 {
        output[len] = (value as u8) | 0x80;
        value >>= 7;
        len += 1;
    }
    output[len] = value as u8;
    len + 1
}

/// Establish the sing-box-compatible gRPC-lite HTTP/2 client stream.
pub(crate) async fn client(
    stream: BoxStream,
    server: &Socksaddr,
    tls_server_name: Option<&str>,
    options: &rb_config::V2RayGrpcOptions,
) -> io::Result<BoxStream> {
    let host =
        tls_server_name.filter(|name| !name.is_empty()).map(str::to_owned).unwrap_or_else(|| match &server.host {
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(domain) => domain.clone(),
        });
    let authority =
        if host.contains(':') { format!("[{host}]:{}", server.port) } else { format!("{host}:{}", server.port) };
    let uri = format!("https://{authority}/{}/Tun", escape_service_name(&options.service_name));
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header(header::USER_AGENT, "grpc-go/1.48.0")
        .header("te", "trailers")
        .body(())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let client = H2Client::new(stream).await?;
    let body = client.open_stream(request).await?;
    Ok(Box::new(GrpcLiteStream::new(body)))
}

fn escape_service_name(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'$' | b'&' | b'+' | b'=' | b':' | b'@')
        {
            result.push(byte as char);
        } else {
            use std::fmt::Write;
            write!(&mut result, "%{byte:02X}").expect("write to String");
        }
    }
    result
}

/// Server-side gRPC-lite HTTP/2 session for one configured service path.
pub(crate) struct GrpcLiteServer {
    h2: H2Server,
    path: String,
}

impl GrpcLiteServer {
    pub(crate) fn new(stream: BoxStream, options: &rb_config::V2RayGrpcOptions) -> Self {
        Self { h2: H2Server::new(stream), path: format!("/{}/Tun", options.service_name) }
    }

    /// Accept the next valid gRPC-lite stream, rejecting unrelated HTTP/2 requests.
    pub(crate) async fn accept(&self) -> io::Result<Option<BoxStream>> {
        loop {
            let Some(incoming) = self.h2.accept().await? else { return Ok(None) };
            let request = &incoming.request;
            let valid = request.method() == http::Method::POST
                && decoded_path_matches(request.uri().path(), &self.path)
                && request
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .is_some_and(|value| value.as_bytes().starts_with(b"application/grpc"));
            let status = if valid { StatusCode::OK } else { StatusCode::NOT_FOUND };
            let mut builder = Response::builder().status(status);
            if valid {
                builder = builder.header(header::CONTENT_TYPE, "application/grpc").header("te", "trailers");
            }
            let response = builder.body(()).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            let mut stream = incoming.respond(response)?;
            if valid {
                return Ok(Some(Box::new(GrpcLiteStream::new(stream))));
            }
            tokio::io::AsyncWriteExt::shutdown(&mut stream).await?;
        }
    }
}

fn decoded_path_matches(path: &str, expected: &str) -> bool {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return false;
            }
            let Some(high) = hex_value(bytes[index + 1]) else { return false };
            let Some(low) = hex_value(bytes[index + 2]) else { return false };
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    decoded == expected.as_bytes()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2ray::h2::H2Client;
    use std::io::Cursor;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[test]
    fn service_name_escaping_matches_go_path_escape() {
        assert_eq!(escape_service_name("a/b;c,d?e:f@g+h$i&j=k% l"), "a%2Fb%3Bc%2Cd%3Fe:f@g+h$i&j=k%25%20l");
    }

    #[test]
    fn server_path_decodes_percent_escapes_before_comparing() {
        assert!(decoded_path_matches("/svc%2fname/Tun", "/svc/name/Tun"));
        assert!(decoded_path_matches("/svc%2Fname/Tun", "/svc/name/Tun"));
        assert!(!decoded_path_matches("/svc%2Gname/Tun", "/svc/name/Tun"));
        assert!(!decoded_path_matches("/svc%2", "/svc/Tun"));
        assert!(!decoded_path_matches("/svc%2Fname/Tun?x=1", "/svc/name/Tun"));
    }

    #[tokio::test]
    async fn server_rejects_bad_request_then_accepts_grpc_lite_on_same_connection() {
        let (client_io, server_io) = duplex(1 << 20);
        let options = rb_config::V2RayGrpcOptions { service_name: "svc/name".into(), ..Default::default() };
        let server = GrpcLiteServer::new(Box::new(server_io), &options);
        let client = H2Client::new(Box::new(client_io)).await.unwrap();
        let server_task = tokio::spawn(async move {
            let mut stream = server.accept().await.unwrap().unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            payload
        });

        let bad = Request::builder().method("GET").uri("https://example.com/wrong/Tun").body(()).unwrap();
        let (response, _body) = client.open(bad).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let good = Request::builder()
            .method("POST")
            .uri("https://example.com/svc%2fname/Tun?ignored=yes")
            .header(header::CONTENT_TYPE, "application/grpc+proto")
            .body(())
            .unwrap();
        let (response, body) = client.open(good).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get(header::CONTENT_TYPE).unwrap(), "application/grpc");
        assert_eq!(response.headers().get("te").unwrap(), "trailers");
        let mut framed = GrpcLiteStream::new(body);
        framed.write_all(b"payload").await.unwrap();
        framed.shutdown().await.unwrap();
        assert_eq!(server_task.await.unwrap(), b"payload");
    }

    #[tokio::test]
    async fn reads_header_split_across_chunks() {
        let wire = [0, 0, 0, 0, 4, 0x0a, 2, b'o', b'k'];
        let mut stream = GrpcLiteStream::new(OneByteReader(Cursor::new(wire)));
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"ok");
    }

    #[tokio::test]
    async fn streams_payload_one_byte_at_a_time() {
        let mut wire = vec![0];
        wire.extend_from_slice(&1003u32.to_be_bytes());
        wire.extend_from_slice(&[0x0a, 0xe8, 0x07]);
        wire.extend(std::iter::repeat_n(b'x', 1000));
        let mut stream = GrpcLiteStream::new(OneByteReader(Cursor::new(wire)));
        let mut output = vec![0; 1000];
        stream.read_exact(&mut output).await.unwrap();
        assert!(output.iter().all(|byte| *byte == b'x'));
        assert_eq!(stream.input.len(), 0);
    }

    #[tokio::test]
    async fn reads_concatenated_frames() {
        let wire = [0, 0, 0, 0, 3, 0x0a, 1, b'a', 0, 0, 0, 0, 3, 0x0a, 1, b'b'];
        let mut stream = GrpcLiteStream::new(OneByteReader(Cursor::new(wire)));
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"ab");
    }

    #[tokio::test]
    async fn truncated_frame_returns_unexpected_eof() {
        for wire in [&[0, 0][..], &[0, 0, 0, 0, 3, 0x0a][..], &[0, 0, 0, 0, 4, 0x0a, 2, b'a'][..]] {
            let mut stream = GrpcLiteStream::new(OneByteReader(Cursor::new(wire)));
            let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[tokio::test]
    async fn writes_exact_envelope_and_drains_partial_writes() {
        let mut stream = GrpcLiteStream::new(PartialWriter { bytes: Vec::new() });
        stream.write_all(b"Hunk").await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(stream.inner.bytes, [0, 0, 0, 0, 6, 0x0a, 4, b'H', b'u', b'n', b'k']);
    }

    #[tokio::test]
    async fn write_sends_grpc_lite_frame_without_waiting_for_flush() {
        let (client, mut peer) = duplex(1 << 16);
        let mut stream = GrpcLiteStream::new(client);
        stream.write_all(b"payload").await.unwrap();
        let mut frame = [0; 14];
        tokio::time::timeout(std::time::Duration::from_secs(1), peer.read_exact(&mut frame)).await.unwrap().unwrap();
        assert_eq!(frame, [0, 0, 0, 0, 9, 0x0a, 7, b'p', b'a', b'y', b'l', b'o', b'a', b'd']);
    }

    struct OneByteReader<T>(Cursor<T>);
    impl<T: AsRef<[u8]> + Unpin> AsyncRead for OneByteReader<T> {
        fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let mut byte = [0; 1];
            let n = std::io::Read::read(&mut self.0, &mut byte)?;
            if n != 0 {
                buf.put_slice(&byte[..n]);
            }
            Poll::Ready(Ok(()))
        }
    }

    struct PartialWriter {
        bytes: Vec<u8>,
    }
    impl AsyncWrite for PartialWriter {
        fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let count = buf.len().min(2);
            self.bytes.extend_from_slice(&buf[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
