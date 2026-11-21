//! XTLS Vision (`flow: xtls-rprx-vision`, sing-vmess `vless/vision.go`).
//!
//! Vision pads the first packets of the proxied connection inside the
//! outer TLS (blocks of `command content-length padding-length content
//! padding`, the first one led by the user id) and watches them for the
//! proxied TLS handshake. When the proxied connection is TLS 1.3 with a
//! cipher Vision accepts, the side that sees its first application data
//! record sends the "direct" command and from then on writes that
//! direction raw on the TCP connection, past the outer TLS; the reading
//! side, on the direct command, takes what the outer TLS still holds and
//! reads raw from then on.
//!
//! sing-vmess reaches into Go's `tls.Conn` for the bytes it holds (the
//! decrypted rest of the current record, and raw bytes read past it).
//! With rustls the decrypted rest is taken from the connection's plaintext
//! buffer, and raw bytes past the current record never get into rustls:
//! the outer TLS runs over a [`RecordStream`], which gives rustls at most
//! one TLS record per read, and rustls asks for more only once its
//! plaintext is consumed. So at the direct command the raw bytes that
//! follow are still in the record stream, read next by the raw reads.

use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, Read as _};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use rand::Rng;
use rb_adapter::BoxStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::protocol::VlessStream;

const CHUNK_SIZE: usize = 8192;
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

const COMMAND_PADDING_CONTINUE: u8 = 0;
const COMMAND_PADDING_END: u8 = 1;
const COMMAND_PADDING_DIRECT: u8 = 2;

/// The TLS 1.3 cipher suites Vision goes direct for (sing-vmess
/// `tls13CipherSuiteDic` without `TLS_AES_128_CCM_8_SHA256`).
fn direct_cipher(cipher: u16) -> bool {
    matches!(cipher, 0x1301..=0x1304)
}

/// The outer TLS connection under Vision.
pub trait TlsConn: AsyncRead + AsyncWrite + Unpin + Send {
    /// The stream under the TLS (a [`RecordStream`] over TCP).
    fn raw(&mut self) -> &mut BoxStream;
    /// The decrypted bytes the TLS connection holds and has not returned.
    fn take_plaintext(&mut self) -> io::Result<Vec<u8>>;
}

fn drain_reader(mut reader: rustls::Reader<'_>) -> io::Result<Vec<u8>> {
    let mut plaintext = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(plaintext),
            Ok(count) => plaintext.extend_from_slice(&chunk[..count]),
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::UnexpectedEof) => {
                return Ok(plaintext)
            }
            Err(error) => return Err(error),
        }
    }
}

impl TlsConn for rb_tls::TlsClientStream {
    fn raw(&mut self) -> &mut BoxStream {
        self.get_mut().0
    }

    fn take_plaintext(&mut self) -> io::Result<Vec<u8>> {
        drain_reader(self.get_mut().1.reader())
    }
}

impl TlsConn for rb_tls::TlsServerStream {
    fn raw(&mut self) -> &mut BoxStream {
        self.get_mut().0
    }

    fn take_plaintext(&mut self) -> io::Result<Vec<u8>> {
        drain_reader(self.get_mut().1.reader())
    }
}

/// Where the reader is in the TLS record framing.
#[derive(Debug, Clone, Copy)]
enum Record {
    /// `filled` bytes of the 5-byte header handed out so far.
    Header { header: [u8; 5], filled: usize },
    /// Body bytes of the current record still to hand out.
    Body(usize),
}

/// A stream that returns at most the rest of the current TLS record per
/// read (writes pass through), so a TLS implementation over it never holds
/// raw bytes of a later record. Bytes read from the socket past the
/// current record stay here and come out on later reads, whoever reads.
pub struct RecordStream {
    inner: BoxStream,
    buffer: Vec<u8>,
    offset: usize,
    record: Record,
}

impl RecordStream {
    pub fn new(inner: BoxStream) -> Self {
        RecordStream { inner, buffer: Vec::new(), offset: 0, record: Record::Header { header: [0; 5], filled: 0 } }
    }

    /// How many buffered bytes the next read may return, advancing the
    /// record state over them.
    fn take(&mut self, wanted: usize) -> usize {
        let mut available = (self.buffer.len() - self.offset).min(wanted);
        let mut taken = 0;
        while available > 0 {
            match self.record {
                Record::Header { mut header, filled } => {
                    let count = (5 - filled).min(available);
                    header[filled..filled + count]
                        .copy_from_slice(&self.buffer[self.offset + taken..self.offset + taken + count]);
                    taken += count;
                    available -= count;
                    let filled = filled + count;
                    self.record = if filled == 5 {
                        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
                        if length == 0 {
                            Record::Header { header: [0; 5], filled: 0 }
                        } else {
                            Record::Body(length)
                        }
                    } else {
                        Record::Header { header, filled }
                    };
                    if filled == 5 && matches!(self.record, Record::Header { .. }) {
                        // An empty record: stop at its end.
                        break;
                    }
                }
                Record::Body(left) => {
                    let count = left.min(available);
                    taken += count;
                    self.record = if count == left {
                        Record::Header { header: [0; 5], filled: 0 }
                    } else {
                        Record::Body(left - count)
                    };
                    // Never past the end of this record.
                    break;
                }
            }
        }
        taken
    }
}

impl AsyncRead for RecordStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.offset >= this.buffer.len() {
            this.buffer.resize(16 * 1024 + 5, 0);
            this.offset = 0;
            let mut read = ReadBuf::new(&mut this.buffer);
            let result = Pin::new(&mut this.inner).poll_read(cx, &mut read);
            let filled = read.filled().len();
            this.buffer.truncate(filled);
            ready!(result)?;
            if filled == 0 {
                return Poll::Ready(Ok(()));
            }
        }
        let count = this.take(buf.remaining());
        let start = this.offset;
        buf.put_slice(&this.buffer[start..start + count]);
        this.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RecordStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Queued output.
enum Out {
    /// Through the VLESS stream (inside TLS).
    Tls(Vec<u8>, usize),
    /// Flush the TLS before writing raw.
    SwitchDirect,
    /// sing-vmess sleeps 5ms before the raw rest of a split write.
    Sleep(Option<Pin<Box<tokio::time::Sleep>>>),
    /// Raw on the TCP connection.
    Direct(Vec<u8>, usize),
}

/// sing-vmess `reshapeBuffer`: splits a write too big for one padded
/// block, preferably at a TLS application data record.
fn reshape(data: &[u8]) -> Vec<Vec<u8>> {
    const LIMIT: usize = 8192 - 21;
    if data.len() < LIMIT {
        return vec![data.to_vec()];
    }
    let mut buffers = Vec::new();
    let mut rest = data;
    while rest.len() >= LIMIT {
        let found = rest.windows(3).rposition(|window| window == TLS_APPLICATION_DATA_START);
        let index = match found {
            Some(index) if (32..=LIMIT).contains(&index) => index,
            _ => 8192 / 2,
        };
        buffers.push(rest[..index].to_vec());
        rest = &rest[index..];
    }
    buffers.push(rest.to_vec());
    buffers
}

/// A Vision connection over a VLESS stream over TLS (sing-vmess
/// `VisionConn`), for either side.
pub struct VisionStream<T> {
    inner: VlessStream<T>,
    uuid: [u8; 16],
    is_tls: bool,
    packets_to_filter: i32,
    is_tls12_or_above: bool,
    remaining_server_hello: i32,
    cipher: u16,
    enable_xtls: bool,
    is_padding: bool,
    direct_write: bool,
    write_uuid: bool,
    within_padding_buffers: bool,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
    padding_header: [u8; 5],
    padding_header_len: usize,
    direct_read: bool,
    remaining: VecDeque<Vec<u8>>,
    out: VecDeque<Out>,
    /// The data of a pass-through write that returned pending was already
    /// filtered.
    filtered: bool,
    /// Room for one chunk read through the TLS.
    chunk: Vec<u8>,
}

impl<T: TlsConn> VisionStream<T> {
    pub fn new(inner: VlessStream<T>, uuid: [u8; 16]) -> Self {
        VisionStream {
            inner,
            uuid,
            is_tls: false,
            packets_to_filter: 8,
            is_tls12_or_above: false,
            remaining_server_hello: -1,
            cipher: 0,
            enable_xtls: false,
            is_padding: true,
            direct_write: false,
            write_uuid: true,
            within_padding_buffers: true,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            padding_header: [0; 5],
            padding_header_len: 0,
            direct_read: false,
            remaining: VecDeque::new(),
            out: VecDeque::new(),
            filtered: false,
            chunk: Vec::new(),
        }
    }

    /// Writes an empty padded block (and so the VLESS request with it), as
    /// sing-box's `kickWriteHandshake` does with `Write(nil)`.
    pub async fn kick(&mut self) -> io::Result<()> {
        self.filter_and_encode(&[]);
        std::future::poll_fn(|cx| {
            ready!(self.poll_drain(cx))?;
            Pin::new(&mut self.inner).poll_flush(cx)
        })
        .await
    }

    /// Whether this side writes raw on the TCP connection now.
    pub fn is_direct_write(&self) -> bool {
        self.direct_write
    }

    /// Whether this side reads raw from the TCP connection now.
    pub fn is_direct_read(&self) -> bool {
        self.direct_read
    }

    fn raw(&mut self) -> &mut BoxStream {
        self.inner.get_mut().raw()
    }

    /// sing-vmess `filterTLS`.
    fn filter_tls(&mut self, buffers: &[&[u8]]) {
        for buffer in buffers {
            self.packets_to_filter -= 1;
            if buffer.len() > 6 {
                if buffer[0] == 22 && buffer[1] == 3 && buffer[2] == 3 {
                    self.is_tls = true;
                    if buffer[5] == 2 {
                        self.is_tls12_or_above = true;
                        self.remaining_server_hello = ((buffer[3] as i32) << 8 | buffer[4] as i32) + 5;
                        if buffer.len() >= 79 && self.remaining_server_hello >= 79 {
                            let session_id_len = buffer[43] as usize;
                            if buffer.len() >= 43 + session_id_len + 3 {
                                let cipher = &buffer[43 + session_id_len + 1..43 + session_id_len + 3];
                                self.cipher = (cipher[0] as u16) << 8 | cipher[1] as u16;
                            }
                        }
                    }
                } else if buffer[..2] == TLS_CLIENT_HANDSHAKE_START && buffer[5] == 1 {
                    self.is_tls = true;
                }
            }
            if self.remaining_server_hello > 0 {
                let end = (self.remaining_server_hello as usize).min(buffer.len());
                self.remaining_server_hello -= end as i32;
                if buffer[..end]
                    .windows(TLS13_SUPPORTED_VERSIONS.len())
                    .any(|window| window == TLS13_SUPPORTED_VERSIONS)
                {
                    if direct_cipher(self.cipher) {
                        self.enable_xtls = true;
                    }
                    self.packets_to_filter = 0;
                    return;
                } else if self.remaining_server_hello == 0 {
                    self.packets_to_filter = 0;
                    return;
                }
            }
        }
    }

    /// sing-vmess `padding`.
    fn padding(&mut self, content: &[u8], command: u8) -> Vec<u8> {
        let mut rng = rand::rng();
        let padding_len = if content.len() < 900 && self.is_tls {
            rng.random_range(0..500) + 900 - content.len()
        } else {
            rng.random_range(0..256)
        };
        let mut block = Vec::with_capacity(16 + 5 + content.len() + padding_len);
        if self.write_uuid {
            block.extend_from_slice(&self.uuid);
            self.write_uuid = false;
        }
        block.extend_from_slice(&[
            command,
            (content.len() >> 8) as u8,
            content.len() as u8,
            (padding_len >> 8) as u8,
            padding_len as u8,
        ]);
        block.extend_from_slice(content);
        block.resize(block.len() + padding_len, 0);
        block
    }

    /// The padding branch of sing-vmess `Write`, queued.
    fn encode_padded(&mut self, data: &[u8]) {
        let mut buffers = reshape(data);
        let mut special = 0;
        #[allow(clippy::needless_range_loop)]
        for index in 0..buffers.len() {
            let buffer = std::mem::take(&mut buffers[index]);
            if self.is_tls && buffer.len() > 6 && buffer[..3] == TLS_APPLICATION_DATA_START {
                let mut command = COMMAND_PADDING_END;
                if self.enable_xtls {
                    self.direct_write = true;
                    special = index;
                    command = COMMAND_PADDING_DIRECT;
                }
                self.is_padding = false;
                buffers[index] = self.padding(&buffer, command);
                break;
            } else if !self.is_tls12_or_above && self.packets_to_filter <= 1 {
                self.is_padding = false;
                buffers[index] = self.padding(&buffer, COMMAND_PADDING_END);
                break;
            }
            buffers[index] = self.padding(&buffer, COMMAND_PADDING_CONTINUE);
        }
        if self.direct_write {
            let rest = buffers.split_off(special + 1);
            self.out.push_back(Out::Tls(buffers.concat(), 0));
            self.out.push_back(Out::SwitchDirect);
            if !rest.is_empty() {
                self.out.push_back(Out::Sleep(None));
                self.out.push_back(Out::Direct(rest.concat(), 0));
            }
        } else {
            self.out.push_back(Out::Tls(buffers.concat(), 0));
        }
    }

    /// sing-vmess `Write` while padding: filter, then pad.
    fn filter_and_encode(&mut self, data: &[u8]) {
        if self.packets_to_filter > 0 {
            self.filter_tls(&[data]);
        }
        self.encode_padded(data);
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(front) = self.out.front_mut() {
            match front {
                Out::Tls(data, offset) => {
                    while *offset < data.len() {
                        let written = ready!(Pin::new(&mut self.inner).poll_write(cx, &data[*offset..]))?;
                        if written == 0 {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        *offset += written;
                    }
                }
                Out::SwitchDirect => ready!(Pin::new(&mut self.inner).poll_flush(cx))?,
                Out::Sleep(sleep) => {
                    let sleep = sleep.get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_millis(5))));
                    ready!(sleep.as_mut().poll(cx));
                }
                Out::Direct(data, offset) => {
                    while *offset < data.len() {
                        let written = ready!(Pin::new(self.inner.get_mut().raw()).poll_write(cx, &data[*offset..]))?;
                        if written == 0 {
                            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                        }
                        *offset += written;
                    }
                }
            }
            self.out.pop_front();
        }
        Poll::Ready(Ok(()))
    }

    /// sing-vmess `unPadding`.
    fn unpadding(&mut self, buffer: &[u8]) -> Vec<Vec<u8>> {
        let mut index = 0;
        if self.remaining_content == -1
            && self.remaining_padding == -1
            && buffer.len() >= 21
            && buffer[..16] == self.uuid
        {
            index = 16;
            self.remaining_content = 0;
            self.remaining_padding = 0;
            self.current_command = 0;
        }
        if self.remaining_content == -1 && self.remaining_padding == -1 {
            return vec![buffer.to_vec()];
        }
        let mut buffers = Vec::new();
        while index < buffer.len() {
            if self.remaining_content <= 0 && self.remaining_padding <= 0 {
                if self.current_command == 1 {
                    buffers.push(buffer[index..].to_vec());
                    break;
                }
                let count = (5 - self.padding_header_len).min(buffer.len() - index);
                self.padding_header[self.padding_header_len..self.padding_header_len + count]
                    .copy_from_slice(&buffer[index..index + count]);
                self.padding_header_len += count;
                index += count;
                if self.padding_header_len < 5 {
                    break;
                }
                self.padding_header_len = 0;
                self.current_command = self.padding_header[0];
                self.remaining_content = (self.padding_header[1] as i32) << 8 | self.padding_header[2] as i32;
                self.remaining_padding = (self.padding_header[3] as i32) << 8 | self.padding_header[4] as i32;
            } else if self.remaining_content > 0 {
                let end = (self.remaining_content as usize).min(buffer.len() - index);
                buffers.push(buffer[index..index + end].to_vec());
                self.remaining_content -= end as i32;
                index += end;
            } else {
                let end = (self.remaining_padding as usize).min(buffer.len() - index);
                self.remaining_padding -= end as i32;
                index += end;
            }
            if index == buffer.len() {
                break;
            }
        }
        buffers
    }

    /// The rest of sing-vmess `Read` for one chunk read through the TLS.
    fn process_chunk(&mut self, chunk: Vec<u8>) -> io::Result<()> {
        if self.within_padding_buffers || self.packets_to_filter > 0 {
            let mut buffers = self.unpadding(&chunk);
            if self.remaining_content == 0 && self.remaining_padding == 0 {
                match self.current_command {
                    COMMAND_PADDING_END => {
                        self.within_padding_buffers = false;
                        self.remaining_content = -1;
                        self.remaining_padding = -1;
                    }
                    COMMAND_PADDING_DIRECT => {
                        self.within_padding_buffers = false;
                        self.direct_read = true;
                        // What the TLS decrypted and did not return yet;
                        // raw bytes past it are read next from the record
                        // stream.
                        let plaintext = self.inner.get_mut().take_plaintext()?;
                        buffers.push(plaintext);
                    }
                    COMMAND_PADDING_CONTINUE => self.within_padding_buffers = true,
                    command => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown command {command}")))
                    }
                }
            } else {
                self.within_padding_buffers = self.remaining_content > 0 || self.remaining_padding > 0;
            }
            if self.packets_to_filter > 0 {
                let views: Vec<&[u8]> = buffers.iter().map(Vec::as_slice).collect();
                self.filter_tls(&views);
            }
            self.remaining.extend(buffers);
        } else {
            if self.packets_to_filter > 0 {
                self.filter_tls(&[&chunk]);
            }
            self.remaining.push_back(chunk);
        }
        Ok(())
    }
}

impl<T: TlsConn> AsyncRead for VisionStream<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            let mut copied = 0;
            while buf.remaining() > 0 {
                let Some(front) = this.remaining.front_mut() else { break };
                let count = front.len().min(buf.remaining());
                buf.put_slice(&front[..count]);
                front.drain(..count);
                copied += count;
                if front.is_empty() {
                    this.remaining.pop_front();
                }
            }
            // Empty buffers left in front carry nothing.
            while this.remaining.front().is_some_and(Vec::is_empty) {
                this.remaining.pop_front();
            }
            if copied > 0 {
                return Poll::Ready(Ok(()));
            }
            if this.direct_read {
                return Pin::new(this.raw()).poll_read(cx, buf);
            }
            let size = CHUNK_SIZE.max(buf.remaining());
            if this.chunk.len() < size {
                this.chunk.resize(size, 0);
            }
            let mut read = ReadBuf::new(&mut this.chunk[..size]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            let count = read.filled().len();
            if count == 0 {
                return Poll::Ready(Ok(()));
            }
            let chunk = this.chunk[..count].to_vec();
            this.process_chunk(chunk)?;
        }
    }
}

impl<T: TlsConn> AsyncWrite for VisionStream<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if this.is_padding {
            this.filter_and_encode(data);
            // Taken at once; the queue goes out now or on the next call.
            if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
                return Poll::Ready(Err(error));
            }
            return Poll::Ready(Ok(data.len()));
        }
        if this.packets_to_filter > 0 && !this.filtered {
            this.filter_tls(&[data]);
        }
        let result = if this.direct_write {
            Pin::new(this.raw()).poll_write(cx, data)
        } else {
            Pin::new(&mut this.inner).poll_write(cx, data)
        };
        this.filtered = result.is_pending();
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        if self.direct_write {
            Pin::new(self.raw()).poll_flush(cx)
        } else {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        if self.direct_write {
            Pin::new(self.raw()).poll_shutdown(cx)
        } else {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn record_stream_stops_at_record_ends() {
        let (mut peer, inner) = tokio::io::duplex(4096);
        let mut records = vec![0x17, 3, 3, 0, 3, b'a', b'b', b'c'];
        records.extend_from_slice(&[0x17, 3, 3, 0, 2, b'd', b'e', b'r', b'a', b'w']);
        peer.write_all(&records).await.unwrap();
        drop(peer);
        let mut stream = RecordStream::new(Box::new(inner));
        let mut reads = Vec::new();
        loop {
            let mut buffer = [0u8; 64];
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            reads.push(buffer[..count].to_vec());
        }
        assert_eq!(reads[0], &records[..8]);
        assert_eq!(reads[1], &records[8..15]);
        assert_eq!(reads.concat(), records);
    }

    #[test]
    fn reshape_like_sing_vmess() {
        assert_eq!(reshape(&[]), vec![Vec::<u8>::new()]);
        let small = vec![1u8; 8170];
        assert_eq!(reshape(&small).len(), 1);
        let big = vec![1u8; 8171];
        let parts = reshape(&big);
        assert_eq!(parts.iter().map(Vec::len).collect::<Vec<_>>(), vec![4096, 4075]);
        let mut records = vec![0u8; 10000];
        records[5000..5003].copy_from_slice(&TLS_APPLICATION_DATA_START);
        let parts = reshape(&records);
        assert_eq!(parts[0].len(), 5000);
    }
}
