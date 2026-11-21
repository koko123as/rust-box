//! TLS ClientHello fragmentation, the `tls_fragment` and
//! `tls_record_fragment` route options (sing-box `common/tlsfragment`).
//!
//! The first write on a connection is checked for a ClientHello with a
//! server name. If there is one, it is cut inside the server name:
//! `tls_fragment` sends the pieces as separate TCP segments, waiting for
//! each to be acknowledged (`TCP_INFO`) or `tls_fragment_fallback_delay`;
//! `tls_record_fragment` wraps each piece in its own TLS record; both
//! together send one record per segment.
//!
//! Where the cuts go follows v1.14.4: the server name's labels are first
//! reduced by the number of dots in the name (`splits[:len(splits) -
//! strings.Count(serverName, ".")]`), which leaves its first label, and
//! one cut is made at a random offset inside it.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use rand::Rng;
use rb_adapter::{BoxStream, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::tfo::TfoStream;

/// sing-box `C.TLSFragmentFallbackDelay`.
pub const DEFAULT_FALLBACK_DELAY: Duration = Duration::from_millis(500);

const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 6;
const RANDOM_LEN: usize = 32;
const SESSION_ID_HEADER_LEN: usize = 1;

/// Where the server name sits in a ClientHello (sing-box `MyServerName`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerName {
    pub index: usize,
    pub length: usize,
    pub name: String,
}

/// sing-box `IndexTLSServerName`.
pub fn index_server_name(payload: &[u8]) -> Option<ServerName> {
    if payload.len() < RECORD_HEADER_LEN || payload[0] != 22 {
        return None;
    }
    let segment_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < RECORD_HEADER_LEN + segment_len {
        return None;
    }
    let mut name = index_in_handshake(&payload[RECORD_HEADER_LEN..])?;
    name.index += RECORD_HEADER_LEN;
    Some(name)
}

fn index_in_handshake(handshake: &[u8]) -> Option<ServerName> {
    if handshake.len() < HANDSHAKE_HEADER_LEN + RANDOM_LEN + SESSION_ID_HEADER_LEN || handshake[0] != 1 {
        return None;
    }
    let handshake_len = (handshake[1] as usize) << 16 | (handshake[2] as usize) << 8 | handshake[3] as usize;
    if handshake.len() - 4 != handshake_len {
        return None;
    }
    let version = u16::from_be_bytes([handshake[4], handshake[5]]);
    if version & 0xFFFC != 0x0300 && version != 0x0304 {
        return None;
    }
    let session_id_len = handshake[38] as usize;
    let mut index = HANDSHAKE_HEADER_LEN + RANDOM_LEN + SESSION_ID_HEADER_LEN + session_id_len;
    if handshake.len() < index {
        return None;
    }
    let cipher_suites = &handshake[index..];
    if cipher_suites.len() < 2 {
        return None;
    }
    let suites_len = u16::from_be_bytes([cipher_suites[0], cipher_suites[1]]) as usize;
    if cipher_suites.len() < 2 + suites_len + 1 {
        return None;
    }
    let compression_len = cipher_suites[2 + suites_len] as usize;
    index += 2 + suites_len + 1 + compression_len;
    if handshake.len() < index {
        return None;
    }
    let mut name = index_in_extensions(&handshake[index..])?;
    name.index += index;
    Some(name)
}

fn index_in_extensions(extensions: &[u8]) -> Option<ServerName> {
    if extensions.len() < 2 {
        return None;
    }
    let total = u16::from_be_bytes([extensions[0], extensions[1]]) as usize;
    let mut rest = &extensions[2..];
    if rest.len() < total {
        return None;
    }
    let mut index = 2;
    while !rest.is_empty() {
        if rest.len() < 4 {
            return None;
        }
        let kind = u16::from_be_bytes([rest[0], rest[1]]);
        let length = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if rest.len() < 4 + length {
            return None;
        }
        let body = &rest[4..4 + length];
        if kind == 0 {
            if body.len() < 5 || body[2] != 0 {
                return None;
            }
            let name_len = u16::from_be_bytes([body[3], body[4]]) as usize;
            return Some(ServerName {
                index: index + 4 + 5,
                length: name_len,
                name: String::from_utf8_lossy(&body[5..]).into_owned(),
            });
        }
        rest = &rest[4 + length..];
        index += 4 + length;
    }
    None
}

/// The cut points in `payload` for `name` (one, inside the first label),
/// with `pick(n)` choosing an offset below `n`.
pub fn split_indexes(name: &ServerName, pick: &mut dyn FnMut(usize) -> usize) -> Vec<usize> {
    let labels: Vec<&str> = name.name.split('.').collect();
    let dots = name.name.matches('.').count();
    let labels = &labels[..labels.len() - dots];
    let mut current = name.index;
    let mut indexes = Vec::new();
    for (position, label) in labels.iter().enumerate() {
        if label.is_empty() {
            // sing-box would panic in rand.Intn(0); leave such a name alone.
            return Vec::new();
        }
        indexes.push(current + pick(label.len()));
        current += label.len();
        if position != labels.len() - 1 {
            current += 1;
        }
    }
    indexes
}

/// The writes for a fragmented ClientHello: with `split_packet` each piece
/// is one write (and with `split_record` each piece is its own record);
/// with `split_record` alone all records go in one write.
pub fn fragment(payload: &[u8], indexes: &[usize], split_packet: bool, split_record: bool) -> Vec<Vec<u8>> {
    let mut writes = Vec::new();
    let mut records = Vec::new();
    for i in 0..=indexes.len() {
        let mut piece = if i == 0 {
            &payload[..indexes[0]]
        } else if i == indexes.len() {
            &payload[indexes[i - 1]..]
        } else {
            &payload[indexes[i - 1]..indexes[i]]
        };
        if i == 0 && split_record {
            piece = &piece[RECORD_HEADER_LEN..];
        }
        if split_record {
            let mut record = Vec::with_capacity(piece.len() + RECORD_HEADER_LEN);
            record.extend_from_slice(&payload[..3]);
            record.extend_from_slice(&(piece.len() as u16).to_be_bytes());
            record.extend_from_slice(piece);
            if split_packet {
                writes.push(record);
            } else {
                records.extend_from_slice(&record);
            }
        } else if split_packet {
            writes.push(piece.to_vec());
        }
    }
    if split_record && !split_packet {
        writes.push(records);
    }
    writes
}

type Wait = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

enum State {
    /// Nothing written yet.
    First,
    /// Writing the pieces of a ClientHello of `original` bytes.
    Fragmenting {
        writes: Vec<Vec<u8>>,
        index: usize,
        offset: usize,
        wait: Option<Wait>,
        original: usize,
    },
    Done,
}

/// A stream whose first write is fragmented (sing-box `tf.Conn`).
pub struct TlsFragmentStream {
    inner: BoxStream,
    split_packet: bool,
    split_record: bool,
    fallback_delay: Duration,
    state: State,
}

impl TlsFragmentStream {
    pub fn new(inner: BoxStream, split_packet: bool, split_record: bool, fallback_delay: Option<Duration>) -> Self {
        TlsFragmentStream {
            inner,
            split_packet,
            split_record,
            fallback_delay: fallback_delay.filter(|delay| !delay.is_zero()).unwrap_or(DEFAULT_FALLBACK_DELAY),
            state: State::First,
        }
    }

    /// The TCP socket under the stream, when there is one (sing-box
    /// `N.UnwrapReader(conn).(*net.TCPConn)`).
    fn tcp(&self) -> Option<&TcpStream> {
        let stream: &dyn Stream = &*self.inner;
        let any = stream.as_any();
        any.downcast_ref::<TcpStream>().or_else(|| any.downcast_ref::<TfoStream>().and_then(TfoStream::stream))
    }
}

/// sing-box `writeAndWaitAck` after the write: polls `TCP_INFO` until the
/// segment is acknowledged; an acknowledgement within 20ms means a
/// transparent proxy answered, so the fallback delay is waited too.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn wait_ack(fd: i32, fallback_delay: Duration) -> Wait {
    Box::pin(async move {
        let start = Instant::now();
        loop {
            if crate::sys::tcp_unacked(fd)? == 0 {
                if start.elapsed() <= Duration::from_millis(20) {
                    tokio::time::sleep(fallback_delay).await;
                }
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn wait_ack(_fd: i32, fallback_delay: Duration) -> Wait {
    let _ = Instant::now();
    Box::pin(async move {
        tokio::time::sleep(fallback_delay).await;
        Ok(())
    })
}

impl AsyncWrite for TlsFragmentStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        loop {
            match &mut this.state {
                State::Done => return Pin::new(&mut this.inner).poll_write(cx, data),
                State::First => {
                    if data.is_empty() {
                        return Pin::new(&mut this.inner).poll_write(cx, data);
                    }
                    let indexes = index_server_name(data)
                        .map(|name| split_indexes(&name, &mut |n| rand::rng().random_range(0..n)))
                        .unwrap_or_default();
                    if indexes.is_empty() {
                        this.state = State::Done;
                        continue;
                    }
                    if this.split_packet {
                        if let Some(tcp) = this.tcp() {
                            tcp.set_nodelay(true)?;
                        }
                    }
                    let writes = fragment(data, &indexes, this.split_packet, this.split_record);
                    this.state = State::Fragmenting { writes, index: 0, offset: 0, wait: None, original: data.len() };
                }
                State::Fragmenting { writes, index, offset, wait, original } => {
                    if let Some(future) = wait {
                        match future.as_mut().poll(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(result) => {
                                *wait = None;
                                result?;
                            }
                        }
                    }
                    if *index == writes.len() {
                        let original = *original;
                        this.state = State::Done;
                        if let Some(tcp) = this.tcp() {
                            // As sing-box does after fragmenting.
                            tcp.set_nodelay(false)?;
                        }
                        return Poll::Ready(Ok(original));
                    }
                    let piece = &writes[*index][*offset..];
                    let written = match Pin::new(&mut this.inner).poll_write(cx, piece) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result?,
                    };
                    if written == 0 {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                    }
                    *offset += written;
                    if *offset < writes[*index].len() {
                        continue;
                    }
                    *index += 1;
                    *offset = 0;
                    if this.split_packet && *index < writes.len() {
                        let delay = this.fallback_delay;
                        let fd = {
                            let stream: &dyn Stream = &*this.inner;
                            let any = stream.as_any();
                            any.downcast_ref::<TcpStream>()
                                .or_else(|| any.downcast_ref::<TfoStream>().and_then(TfoStream::stream))
                                .map(std::os::fd::AsRawFd::as_raw_fd)
                        };
                        let future: Wait = match fd {
                            Some(fd) => wait_ack(fd, delay),
                            None => Box::pin(async move {
                                tokio::time::sleep(delay).await;
                                Ok(())
                            }),
                        };
                        if let State::Fragmenting { wait, .. } = &mut this.state {
                            *wait = Some(future);
                        }
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for TlsFragmentStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello for `name` with a few extensions before the SNI.
    pub fn client_hello(name: &str) -> Vec<u8> {
        let mut extensions = Vec::new();
        // supported_groups first, so the SNI is not the first extension.
        extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name.as_bytes());
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn finds_the_server_name() {
        let hello = client_hello("www.example.com");
        let name = index_server_name(&hello).unwrap();
        assert_eq!(name.name, "www.example.com");
        assert_eq!(&hello[name.index..name.index + name.length], b"www.example.com");
        assert!(index_server_name(&hello[..hello.len() - 1]).is_none());
        assert!(index_server_name(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn cuts_inside_the_first_label() {
        let hello = client_hello("www.example.com");
        let name = index_server_name(&hello).unwrap();
        let indexes = split_indexes(&name, &mut |n| n - 1);
        assert_eq!(indexes, vec![name.index + 2]);
        let indexes = split_indexes(&name, &mut |_| 0);
        assert_eq!(indexes, vec![name.index]);
        let single = ServerName { index: 10, length: 9, name: "localhost".into() };
        assert_eq!(split_indexes(&single, &mut |_| 4), vec![14]);
        let odd = ServerName { index: 10, length: 4, name: ".com".into() };
        assert!(split_indexes(&odd, &mut |_| 0).is_empty());
    }

    #[test]
    fn packet_and_record_fragments() {
        let hello = client_hello("www.example.com");
        let name = index_server_name(&hello).unwrap();
        let cut = name.index + 1;
        // Segments: the bytes are unchanged, in two writes.
        let writes = fragment(&hello, &[cut], true, false);
        assert_eq!(writes.len(), 2);
        assert_eq!(writes.concat(), hello);
        // Records: one write of two records carrying the handshake.
        let writes = fragment(&hello, &[cut], false, true);
        assert_eq!(writes.len(), 1);
        let records = &writes[0];
        let first_len = u16::from_be_bytes([records[3], records[4]]) as usize;
        assert_eq!(first_len, cut - 5);
        let second = &records[5 + first_len..];
        assert_eq!(&second[..3], &hello[..3]);
        let mut handshake = records[5..5 + first_len].to_vec();
        handshake.extend_from_slice(&second[5..]);
        assert_eq!(handshake, hello[5..]);
        // Both: two writes, one record each.
        let writes = fragment(&hello, &[cut], true, true);
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0][..5], [0x16, 0x03, 0x01, 0x00, (cut - 5) as u8]);
    }

    #[tokio::test]
    async fn stream_writes_fragments() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let hello = client_hello("www.example.com");
        let (client, mut server) = tokio::io::duplex(65536);
        let mut stream = TlsFragmentStream::new(Box::new(client), false, true, None);
        stream.write_all(&hello).await.unwrap();
        stream.write_all(b"after").await.unwrap();
        drop(stream);
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        // Two records (5 more header bytes), then the next write untouched.
        assert_eq!(received.len(), hello.len() + 5 + 5);
        assert!(received.ends_with(b"after"));
        assert_eq!(received[0], 0x16);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_waits_between_segments_without_tcp() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let hello = client_hello("www.example.com");
        let (client, mut server) = tokio::io::duplex(65536);
        let mut stream = TlsFragmentStream::new(Box::new(client), true, false, Some(Duration::from_millis(40)));
        let start = tokio::time::Instant::now();
        stream.write_all(&hello).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(40));
        drop(stream);
        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, hello);
    }
}
