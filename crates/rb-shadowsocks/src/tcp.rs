//! The encrypted TCP stream of every method, both sides.
//!
//! A [`ShadowStream`] wraps the connection: reads decrypt (the client
//! first reads the server's salt and, for 2022, its response header) and
//! writes encrypt. Writes are buffered: `poll_write` accepts data once it
//! is encrypted into the output buffer, which goes out as the connection
//! takes it and is drained by `poll_flush` and `poll_shutdown`.
//!
//! The client's request header is ready in the output buffer from
//! [`ShadowStream::client`]; flushing sends it. The server's response
//! header goes out with the first data written (sing-shadowsocks
//! `serverConn.writeResponse`).

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use rb_adapter::Socksaddr;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::cipher::{self, Aead, AeadKind, Block, StreamKind, TAG_SIZE};
use crate::{
    check_timestamp, error, random_bytes, write_address, ClientMethod, MethodKind, AEAD_MAX_CHUNK, HEADER_TYPE_CLIENT,
    HEADER_TYPE_SERVER, MAX_PADDING_LENGTH, SS2022_CLIENT_CHUNK, SS2022_MAX_CHUNK,
};

/// Length of a chunk's encrypted length (2 bytes and the tag).
const LENGTH_CHUNK: usize = 2 + TAG_SIZE;
/// Most plaintext one `poll_write` encrypts.
const WRITE_BATCH: usize = 64 * 1024;

/// What the reader does before its first chunk.
pub(crate) enum ReadInit {
    /// Nothing: the cipher is set (a server after its handshake).
    Ready,
    /// Read the server's salt (an AEAD client).
    AeadSalt { kind: AeadKind, key: Vec<u8> },
    /// Read the server's salt and response header (a 2022 client).
    Ss2022Response { kind: AeadKind, psk: Vec<u8>, request_salt: Vec<u8>, time: fn() -> i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    Salt,
    /// The 2022 response's fixed-length header chunk (no length prefix).
    Fixed,
    Length,
    Payload(usize),
}

/// The reading half of an AEAD or 2022 stream.
pub(crate) struct AeadReader {
    cipher: Option<Aead>,
    nonce: Vec<u8>,
    /// Largest chunk accepted (the AEAD server's `MaxPacketSize`).
    max_chunk: Option<usize>,
    init: ReadInit,
    state: ReadState,
    raw: Vec<u8>,
    filled: usize,
    plain: Vec<u8>,
    position: usize,
}

impl AeadReader {
    /// A client reader, which starts with the server's salt.
    pub(crate) fn client(init: ReadInit) -> Self {
        AeadReader {
            cipher: None,
            nonce: Vec::new(),
            max_chunk: None,
            init,
            state: ReadState::Salt,
            raw: Vec::new(),
            filled: 0,
            plain: Vec::new(),
            position: 0,
        }
    }

    /// A server reader after its handshake: `nonce` is where the request
    /// left it and `plain` holds the rest of the request's last chunk.
    pub(crate) fn server(cipher: Aead, nonce: Vec<u8>, plain: Vec<u8>, max_chunk: Option<usize>) -> Self {
        AeadReader {
            cipher: Some(cipher),
            nonce,
            max_chunk,
            init: ReadInit::Ready,
            state: ReadState::Length,
            raw: Vec::new(),
            filled: 0,
            plain,
            position: 0,
        }
    }

    /// Reads raw bytes until `size` are there; `Ok(false)` for an EOF
    /// before the first byte.
    fn poll_fill<S: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut S,
        size: usize,
    ) -> Poll<io::Result<bool>> {
        if self.filled == 0 {
            self.raw.clear();
            self.raw.resize(size, 0);
        }
        while self.filled < size {
            let mut buffer = ReadBuf::new(&mut self.raw[self.filled..size]);
            ready!(Pin::new(&mut *io).poll_read(cx, &mut buffer))?;
            let read = buffer.filled().len();
            if read == 0 {
                if self.filled == 0 {
                    return Poll::Ready(Ok(false));
                }
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")));
            }
            self.filled += read;
        }
        self.filled = 0;
        Poll::Ready(Ok(true))
    }

    /// Decrypts the filled raw bytes into the plaintext buffer.
    fn open_raw(&mut self) -> io::Result<()> {
        let cipher = self.cipher.as_ref().expect("cipher set");
        let length = cipher.open_slice(&self.nonce, &mut self.raw)?;
        cipher::increase_nonce(&mut self.nonce);
        std::mem::swap(&mut self.plain, &mut self.raw);
        self.plain.truncate(length);
        self.position = 0;
        Ok(())
    }

    fn poll_read<S: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut S,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.position < self.plain.len() {
                let count = (self.plain.len() - self.position).min(buffer.remaining());
                buffer.put_slice(&self.plain[self.position..self.position + count]);
                self.position += count;
                return Poll::Ready(Ok(()));
            }
            match self.state {
                ReadState::Salt => {
                    let (kind, size) = match &self.init {
                        ReadInit::AeadSalt { kind, .. } | ReadInit::Ss2022Response { kind, .. } => {
                            (*kind, kind.key_size())
                        }
                        ReadInit::Ready => unreachable!("a server reader has no salt to read"),
                    };
                    if !ready!(self.poll_fill(cx, io, size))? {
                        return Poll::Ready(Ok(()));
                    }
                    let salt = &self.raw[..size];
                    let key = match &self.init {
                        ReadInit::AeadSalt { key, .. } => cipher::aead_subkey(key, salt),
                        ReadInit::Ss2022Response { psk, .. } => cipher::session_key(psk, salt, size),
                        ReadInit::Ready => unreachable!(),
                    };
                    self.cipher = Some(Aead::new(kind, &key));
                    self.nonce = vec![0u8; kind.nonce_size()];
                    self.state = match self.init {
                        ReadInit::Ss2022Response { .. } => ReadState::Fixed,
                        _ => ReadState::Length,
                    };
                }
                ReadState::Fixed => {
                    let ReadInit::Ss2022Response { kind, request_salt, time, .. } = &self.init else {
                        unreachable!("only a 2022 client reads a response header")
                    };
                    let (salt_size, time, request_salt) = (kind.key_size(), *time, request_salt.clone());
                    let size = 1 + 8 + salt_size + 2 + TAG_SIZE;
                    if !ready!(self.poll_fill(cx, io, size))? {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")));
                    }
                    self.open_raw()?;
                    let header = std::mem::take(&mut self.plain);
                    if header[0] != HEADER_TYPE_SERVER {
                        return Poll::Ready(Err(error(format!(
                            "bad header type: expected {HEADER_TYPE_SERVER}, got {}",
                            header[0]
                        ))));
                    }
                    let epoch = u64::from_be_bytes(header[1..9].try_into().unwrap());
                    check_timestamp(epoch, time())?;
                    if header[9..9 + salt_size] != request_salt[..] {
                        return Poll::Ready(Err(error("bad request salt")));
                    }
                    let length = u16::from_be_bytes([header[9 + salt_size], header[10 + salt_size]]) as usize;
                    self.init = ReadInit::Ready;
                    self.state = ReadState::Payload(length);
                }
                ReadState::Length => {
                    if !ready!(self.poll_fill(cx, io, LENGTH_CHUNK))? {
                        return Poll::Ready(Ok(()));
                    }
                    self.open_raw()?;
                    let length = u16::from_be_bytes([self.plain[0], self.plain[1]]) as usize;
                    self.plain.clear();
                    if self.max_chunk.is_some_and(|max| length > max) {
                        return Poll::Ready(Err(error("packet too large")));
                    }
                    self.state = ReadState::Payload(length);
                }
                ReadState::Payload(length) => {
                    if !ready!(self.poll_fill(cx, io, length + TAG_SIZE))? {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")));
                    }
                    self.open_raw()?;
                    self.state = ReadState::Length;
                }
            }
        }
    }
}

pub(crate) enum Reader {
    Plain,
    /// A legacy stream cipher client: the server's salt first.
    Stream {
        kind: StreamKind,
        key: Vec<u8>,
        salt: Vec<u8>,
        filled: usize,
        cipher: Option<cipher::Stream>,
    },
    Aead(Box<AeadReader>),
}

/// What the writer sends before the first data.
pub(crate) enum WriteInit {
    Ready,
    /// The AEAD server's salt.
    AeadServer {
        kind: AeadKind,
        key: Vec<u8>,
    },
    /// The 2022 server's salt and response header.
    Ss2022Server {
        kind: AeadKind,
        psk: Vec<u8>,
        request_salt: Vec<u8>,
        time: fn() -> i64,
    },
}

pub(crate) enum WriteMode {
    Plain,
    Stream(Box<cipher::Stream>),
    Aead { cipher: Option<Aead>, nonce: Vec<u8>, max_chunk: usize },
}

pub(crate) struct Writer {
    mode: WriteMode,
    init: WriteInit,
    out: Vec<u8>,
    written: usize,
}

impl Writer {
    pub(crate) fn new(mode: WriteMode, init: WriteInit, out: Vec<u8>) -> Self {
        Writer { mode, init, out, written: 0 }
    }

    /// Appends one length-prefixed chunk.
    fn seal_chunk(cipher: &Aead, nonce: &mut [u8], data: &[u8], out: &mut Vec<u8>) {
        cipher.seal_to(nonce, &(data.len() as u16).to_be_bytes(), out);
        cipher::increase_nonce(nonce);
        cipher.seal_to(nonce, data, out);
        cipher::increase_nonce(nonce);
    }

    /// Encrypts the front of `data` into the output; returns how much.
    fn encrypt(&mut self, data: &[u8]) -> usize {
        match std::mem::replace(&mut self.init, WriteInit::Ready) {
            WriteInit::Ready => {}
            WriteInit::AeadServer { kind, key } => {
                // sing-shadowsocks `shadowaead.serverConn.writeResponse`.
                let salt = random_bytes(kind.key_size());
                let subkey = cipher::aead_subkey(&key, &salt);
                self.out.extend_from_slice(&salt);
                self.mode = WriteMode::Aead {
                    cipher: Some(Aead::new(kind, &subkey)),
                    nonce: vec![0u8; kind.nonce_size()],
                    max_chunk: AEAD_MAX_CHUNK,
                };
            }
            WriteInit::Ss2022Server { kind, psk, request_salt, time } => {
                // sing-shadowsocks `shadowaead_2022.serverConn.writeResponse`.
                let salt_size = kind.key_size();
                let salt = random_bytes(salt_size);
                let aead = Aead::new(kind, &cipher::session_key(&psk, &salt, salt_size));
                let mut nonce = vec![0u8; kind.nonce_size()];
                // The first payload fits the rest of the writer's buffer.
                let buffer_size = SS2022_MAX_CHUNK + 2 + TAG_SIZE * 2;
                let max_payload = buffer_size - salt_size - (1 + 8 + salt_size + 2) - TAG_SIZE * 2;
                let payload = data.len().min(max_payload);
                let mut fixed = Vec::with_capacity(1 + 8 + salt_size + 2);
                fixed.push(HEADER_TYPE_SERVER);
                fixed.extend_from_slice(&(time() as u64).to_be_bytes());
                fixed.extend_from_slice(&request_salt);
                fixed.extend_from_slice(&(payload as u16).to_be_bytes());
                self.out.extend_from_slice(&salt);
                aead.seal_to(&nonce, &fixed, &mut self.out);
                cipher::increase_nonce(&mut nonce);
                if payload > 0 {
                    aead.seal_to(&nonce, &data[..payload], &mut self.out);
                    cipher::increase_nonce(&mut nonce);
                }
                self.mode = WriteMode::Aead { cipher: Some(aead), nonce, max_chunk: SS2022_MAX_CHUNK };
                return payload;
            }
        }
        let data = &data[..data.len().min(WRITE_BATCH)];
        match &mut self.mode {
            WriteMode::Plain => self.out.extend_from_slice(data),
            WriteMode::Stream(stream) => {
                let start = self.out.len();
                self.out.extend_from_slice(data);
                stream.apply(&mut self.out[start..]);
            }
            WriteMode::Aead { cipher, nonce, max_chunk } => {
                let cipher = cipher.as_ref().expect("cipher set");
                for chunk in data.chunks(*max_chunk) {
                    Self::seal_chunk(cipher, nonce, chunk, &mut self.out);
                }
            }
        }
        data.len()
    }

    /// Writes out the buffered output.
    fn poll_drain<S: AsyncWrite + Unpin>(&mut self, cx: &mut Context<'_>, io: &mut S) -> Poll<io::Result<()>> {
        while self.written < self.out.len() {
            let written = ready!(Pin::new(&mut *io).poll_write(cx, &self.out[self.written..]))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += written;
        }
        self.out.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}

/// A shadowsocks TCP connection over `S`.
pub struct ShadowStream<S> {
    io: S,
    reader: Reader,
    writer: Writer,
}

impl<S> ShadowStream<S> {
    pub(crate) fn from_parts(io: S, reader: Reader, writer: Writer) -> Self {
        ShadowStream { io, reader, writer }
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// What is encrypted and not sent yet.
    #[cfg(test)]
    pub(crate) fn writer_output(&self) -> &[u8] {
        &self.writer.out[self.writer.written..]
    }

    /// The client side, with the request header to `destination` ready to
    /// be sent (sing-shadowsocks2 `Method.DialEarlyConn` with the header
    /// written by an empty first write: sing-box writes it as soon as the
    /// connection is handed over, `kickWriteHandshake`).
    pub fn client(method: &ClientMethod, io: S, destination: &Socksaddr) -> io::Result<Self> {
        let mut header = Vec::with_capacity(1024);
        let (reader, mode) = match method.kind {
            MethodKind::None => {
                write_address(&mut header, destination)?;
                (Reader::Plain, WriteMode::Plain)
            }
            MethodKind::Stream(kind) => {
                // sing-shadowsocks2 `shadowstream.clientConn.Write`.
                let salt = random_bytes(kind.salt_size());
                let mut stream = cipher::Stream::new(kind, method.key(), &salt, true);
                header.extend_from_slice(&salt);
                let start = header.len();
                write_address(&mut header, destination)?;
                stream.apply(&mut header[start..]);
                let reader =
                    Reader::Stream { kind, key: method.key().to_vec(), salt: Vec::new(), filled: 0, cipher: None };
                (reader, WriteMode::Stream(Box::new(stream)))
            }
            MethodKind::Aead(kind) => {
                // sing-shadowsocks2 `shadowaead.clientConn.writeRequest`.
                let salt = random_bytes(kind.key_size());
                let aead = Aead::new(kind, &cipher::aead_subkey(method.key(), &salt));
                let mut nonce = vec![0u8; kind.nonce_size()];
                header.extend_from_slice(&salt);
                let mut address = Vec::new();
                write_address(&mut address, destination)?;
                Writer::seal_chunk(&aead, &mut nonce, &address, &mut header);
                let reader =
                    Reader::Aead(Box::new(AeadReader::client(ReadInit::AeadSalt { kind, key: method.key().to_vec() })));
                (reader, WriteMode::Aead { cipher: Some(aead), nonce, max_chunk: AEAD_MAX_CHUNK })
            }
            MethodKind::Ss2022(kind) => {
                // sing-shadowsocks2 `shadowaead_2022.clientConn.writeRequest`
                // with no payload: random padding.
                let salt_size = kind.key_size();
                let salt = random_bytes(salt_size);
                let aead = Aead::new(kind, &cipher::session_key(method.user_psk(), &salt, salt_size));
                let mut nonce = vec![0u8; kind.nonce_size()];
                header.extend_from_slice(&salt);
                write_identity_headers(method, &salt, &mut header);
                let padding = rand::random_range(1..=MAX_PADDING_LENGTH);
                let mut variable = Vec::with_capacity(crate::address_len(destination) + 2 + padding);
                write_address(&mut variable, destination)?;
                variable.extend_from_slice(&(padding as u16).to_be_bytes());
                variable.resize(variable.len() + padding, 0);
                let mut fixed = Vec::with_capacity(11);
                fixed.push(HEADER_TYPE_CLIENT);
                fixed.extend_from_slice(&((method.time)() as u64).to_be_bytes());
                fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());
                aead.seal_to(&nonce, &fixed, &mut header);
                cipher::increase_nonce(&mut nonce);
                aead.seal_to(&nonce, &variable, &mut header);
                cipher::increase_nonce(&mut nonce);
                let reader = Reader::Aead(Box::new(AeadReader::client(ReadInit::Ss2022Response {
                    kind,
                    psk: method.user_psk().to_vec(),
                    request_salt: salt,
                    time: method.time,
                })));
                (reader, WriteMode::Aead { cipher: Some(aead), nonce, max_chunk: SS2022_CLIENT_CHUNK })
            }
        };
        Ok(ShadowStream { io, reader, writer: Writer::new(mode, WriteInit::Ready, header) })
    }
}

/// The extended identity headers of a 2022 TCP request
/// (sing-shadowsocks2 `writeExtendedIdentityHeaders`): for each PSK but the
/// last, the next PSK's hash encrypted with an identity subkey.
pub(crate) fn write_identity_headers(method: &ClientMethod, salt: &[u8], out: &mut Vec<u8>) {
    let psks = method.psks();
    let salt_size = salt.len();
    for (index, psk) in psks.iter().enumerate().take(psks.len().saturating_sub(1)) {
        let subkey = cipher::identity_subkey(psk, salt, salt_size);
        let mut header = method.psk_hashes()[index];
        Block::new(&subkey).encrypt(&mut header);
        out.extend_from_slice(&header);
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ShadowStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.reader {
            Reader::Plain => Pin::new(&mut this.io).poll_read(cx, buffer),
            Reader::Aead(reader) => reader.poll_read(cx, &mut this.io, buffer),
            Reader::Stream { kind, key, salt, filled, cipher } => {
                if cipher.is_none() {
                    // sing-shadowsocks2 `shadowstream.clientConn.readResponse`.
                    let size = kind.salt_size();
                    salt.resize(size, 0);
                    while *filled < size {
                        let mut read = ReadBuf::new(&mut salt[*filled..]);
                        ready!(Pin::new(&mut this.io).poll_read(cx, &mut read))?;
                        let count = read.filled().len();
                        if count == 0 {
                            if *filled == 0 {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        *filled += count;
                    }
                    *cipher = Some(cipher::Stream::new(*kind, key, salt, false));
                }
                let start = buffer.filled().len();
                ready!(Pin::new(&mut this.io).poll_read(cx, buffer))?;
                let stream = cipher.as_mut().expect("cipher set");
                stream.apply(&mut buffer.filled_mut()[start..]);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ShadowStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.writer.poll_drain(cx, &mut this.io))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let consumed = this.writer.encrypt(data);
        // Start sending now; what the connection does not take yet stays
        // buffered for the next write or flush.
        if let Poll::Ready(Err(error)) = this.writer.poll_drain(cx, &mut this.io) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(consumed))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.writer.poll_drain(cx, &mut this.io))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.writer.poll_drain(cx, &mut this.io))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
