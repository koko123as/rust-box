//! The VMess body (sing-vmess `CreateReader` / `CreateWriter` and the
//! chunk readers and writers): the raw stream, the AES-128-CFB stream of
//! the legacy security, and the chunk stream with its length masking
//! (SHAKE128), global padding, authenticated length and the AES-128-GCM,
//! ChaCha20-Poly1305 or FNV-1a (legacy) payloads; plus the client's reading
//! of the response header that comes before the body.
//!
//! Both halves work on bytes: the writer turns data into wire bytes, the
//! reader takes wire bytes in [`BodyReader::raw_mut`] and gives back
//! chunks, keeping its state between calls so a caller can stop waiting
//! for more bytes at any point (cancel safety).

use std::io;

use aes_gcm::aead::{Aead as _, KeyInit};
use aes_gcm::Aes128Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader};

use super::protocol::{
    self, chacha_key, fnv1a32, invalid, kdf16, CfbDecryptor, CfbEncryptor, CIPHER_OVERHEAD,
    OPTION_AUTHENTICATED_LENGTH, OPTION_CHUNK_MASKING, OPTION_CHUNK_STREAM, OPTION_GLOBAL_PADDING,
    SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_LEGACY, SECURITY_NONE, WRITE_CHUNK_SIZE,
};

/// sing-vmess `MaxPaddingSize`.
const MAX_PADDING: u16 = 64;

/// A SHAKE128 stream seeded with a body nonce.
pub struct Shake(Shake128Reader);

impl Shake {
    pub fn new(nonce: &[u8; 16]) -> Self {
        let mut hash = Shake128::default();
        hash.update(nonce);
        Shake(hash.finalize_xof())
    }

    /// The next big-endian `u16` (Go `binary.Read(shake, BigEndian, &u16)`).
    pub fn next_u16(&mut self) -> u16 {
        let mut bytes = [0u8; 2];
        self.0.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }
}

/// Global padding and chunk masking of one direction; masking shares the
/// padding's SHAKE stream when both are on.
struct Masks {
    padding: Option<Shake>,
    mask: Option<Shake>,
    shared: bool,
}

impl Masks {
    fn new(option: u8, nonce: &[u8; 16], masking: bool) -> Self {
        let padding = (option & OPTION_GLOBAL_PADDING != 0).then(|| Shake::new(nonce));
        let wants_mask = masking && option & OPTION_CHUNK_MASKING != 0;
        let shared = wants_mask && padding.is_some();
        let mask = (wants_mask && !shared).then(|| Shake::new(nonce));
        Masks { padding, mask, shared }
    }

    fn next_padding(&mut self) -> u16 {
        self.padding.as_mut().map_or(0, |shake| shake.next_u16() % MAX_PADDING)
    }

    fn next_mask(&mut self) -> Option<u16> {
        if self.shared {
            self.padding.as_mut().map(Shake::next_u16)
        } else {
            self.mask.as_mut().map(Shake::next_u16)
        }
    }
}

enum Cipher {
    Gcm(Box<Aes128Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

/// An AEAD with sing-vmess's nonce: the first 12 bytes of the body nonce
/// with a big-endian counter over the first two.
struct Sealer {
    cipher: Cipher,
    nonce: [u8; 12],
    count: u16,
}

impl Sealer {
    fn gcm(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        Sealer::new(Cipher::Gcm(Box::new(Aes128Gcm::new_from_slice(key).expect("key size"))), nonce)
    }

    fn chacha(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let key = chacha_key(key);
        Sealer::new(Cipher::Chacha(Box::new(ChaCha20Poly1305::new_from_slice(&key).expect("key size"))), nonce)
    }

    fn new(cipher: Cipher, nonce: &[u8; 16]) -> Self {
        let mut first = [0u8; 12];
        first.copy_from_slice(&nonce[..12]);
        Sealer { cipher, nonce: first, count: 0 }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        self.nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        self.count = self.count.wrapping_add(1);
        self.nonce
    }

    fn seal(&mut self, data: &[u8]) -> Vec<u8> {
        let nonce = self.next_nonce();
        match &self.cipher {
            Cipher::Gcm(cipher) => cipher.encrypt((&nonce).into(), data),
            Cipher::Chacha(cipher) => cipher.encrypt((&nonce).into(), data),
        }
        .expect("seal")
    }

    fn open(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.next_nonce();
        match &self.cipher {
            Cipher::Gcm(cipher) => cipher.decrypt((&nonce).into(), data).map_err(|_| protocol::gcm_auth_failed()),
            Cipher::Chacha(cipher) => cipher
                .decrypt((&nonce).into(), data)
                .map_err(|_| invalid("chacha20poly1305: message authentication failed")),
        }
    }
}

enum Length {
    /// Two bytes, masked when chunk masking is on.
    Plain,
    /// Two bytes sealed (authenticated length).
    Sealed(Sealer),
}

enum Payload {
    Plain,
    Sealed(Sealer),
    /// The FNV-1a checksum in front (legacy).
    Checksum,
}

struct Chunked {
    length: Length,
    payload: Payload,
    masks: Masks,
    /// Whether writes are cut into chunks of [`WRITE_CHUNK_SIZE`]
    /// (`bufio.NewChunkWriter`; not with the none security).
    split: bool,
}

enum Framing {
    Raw,
    Chunked(Box<Chunked>),
}

/// The authenticated length cipher: keyed with the request key and nonce
/// in both directions (sing-vmess passes `requestKey`, `requestNonce`).
fn auth_length(security: u8, request_key: &[u8; 16], request_nonce: &[u8; 16]) -> Sealer {
    let key = kdf16(request_key, "auth_len", &[]);
    if security == SECURITY_CHACHA20_POLY1305 {
        Sealer::chacha(&key, request_nonce)
    } else {
        Sealer::gcm(&key, request_nonce)
    }
}

/// sing-vmess `CreateReader` / `CreateWriter` without the CFB layer.
fn framing(
    security: u8,
    option: u8,
    request_key: &[u8; 16],
    request_nonce: &[u8; 16],
    key: &[u8; 16],
    nonce: &[u8; 16],
) -> Framing {
    let chunk_stream = option & OPTION_CHUNK_STREAM != 0;
    let authenticated = option & OPTION_AUTHENTICATED_LENGTH != 0;
    let length = || {
        if authenticated {
            Length::Sealed(auth_length(security, request_key, request_nonce))
        } else {
            Length::Plain
        }
    };
    match security {
        SECURITY_NONE if chunk_stream => Framing::Chunked(Box::new(Chunked {
            length: length(),
            payload: Payload::Plain,
            masks: Masks::new(option, nonce, !authenticated),
            split: false,
        })),
        SECURITY_LEGACY if chunk_stream => Framing::Chunked(Box::new(Chunked {
            length: Length::Plain,
            payload: Payload::Checksum,
            masks: Masks::new(option, nonce, true),
            split: true,
        })),
        SECURITY_AES_128_GCM | SECURITY_CHACHA20_POLY1305 => Framing::Chunked(Box::new(Chunked {
            length: length(),
            payload: Payload::Sealed(if security == SECURITY_AES_128_GCM {
                Sealer::gcm(key, nonce)
            } else {
                Sealer::chacha(key, nonce)
            }),
            masks: Masks::new(option, nonce, !authenticated),
            split: true,
        })),
        _ => Framing::Raw,
    }
}

/// The body keys of one direction.
#[derive(Clone, Copy)]
pub struct BodyKeys {
    pub security: u8,
    pub option: u8,
    pub request_key: [u8; 16],
    pub request_nonce: [u8; 16],
    pub key: [u8; 16],
    pub nonce: [u8; 16],
}

/// Writes one direction of the body; `prefix` (the request or response
/// header) goes in front of the first bytes.
pub struct BodyWriter {
    prefix: Option<Vec<u8>>,
    framing: Framing,
    cfb: Option<CfbEncryptor>,
}

impl BodyWriter {
    /// `cfb` is the legacy security's stream (a fresh one, or the
    /// response header's when the body continues it).
    pub fn new(prefix: Vec<u8>, keys: &BodyKeys, cfb: Option<CfbEncryptor>) -> Self {
        let framing =
            framing(keys.security, keys.option, &keys.request_key, &keys.request_nonce, &keys.key, &keys.nonce);
        BodyWriter { prefix: Some(prefix), framing, cfb }
    }

    /// The header if it was not sent yet.
    pub fn take_prefix(&mut self) -> Option<Vec<u8>> {
        self.prefix.take()
    }

    pub fn header_written(&self) -> bool {
        self.prefix.is_none()
    }

    /// The wire bytes of `data` (after the header the first time). Empty
    /// data writes nothing but the header.
    pub fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = self.prefix.take().unwrap_or_default();
        if data.is_empty() {
            return out;
        }
        let start = out.len();
        match &mut self.framing {
            Framing::Raw => out.extend_from_slice(data),
            Framing::Chunked(chunked) => {
                let size = if chunked.split { WRITE_CHUNK_SIZE } else { usize::MAX };
                for piece in data.chunks(size) {
                    chunked.encode(piece, &mut out);
                }
            }
        }
        if let Some(cfb) = &mut self.cfb {
            cfb.encrypt(&mut out[start..]);
        }
        out
    }
}

impl Chunked {
    fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) {
        let payload = match &mut self.payload {
            Payload::Plain => data.to_vec(),
            Payload::Sealed(sealer) => sealer.seal(data),
            Payload::Checksum => {
                let mut payload = Vec::with_capacity(4 + data.len());
                payload.extend_from_slice(&fnv1a32(data).to_be_bytes());
                payload.extend_from_slice(data);
                payload
            }
        };
        let padding = self.masks.next_padding();
        let length = (payload.len() as u16).wrapping_add(padding);
        match &mut self.length {
            Length::Plain => {
                let length = match self.masks.next_mask() {
                    Some(mask) => length ^ mask,
                    None => length,
                };
                out.extend_from_slice(&length.to_be_bytes());
            }
            Length::Sealed(sealer) => {
                let length = length.wrapping_sub(CIPHER_OVERHEAD as u16);
                out.extend_from_slice(&sealer.seal(&length.to_be_bytes()));
            }
        }
        out.extend_from_slice(&payload);
        if padding > 0 {
            let start = out.len();
            out.resize(start + padding as usize, 0);
            rand::rng().fill_bytes(&mut out[start..]);
        }
    }
}

/// One read of the body.
#[derive(Debug, PartialEq, Eq)]
pub enum Chunk {
    Data(Vec<u8>),
    /// A chunk of no data (sing-vmess returns `io.EOF`).
    Eof,
}

enum Phase {
    /// The AEAD response header (client): its length block, then the
    /// header of `length`.
    AeadResponse {
        key: [u8; 16],
        nonce: [u8; 16],
        length: Option<usize>,
    },
    /// The legacy response header (client): 4 bytes under `cipher`, which
    /// the body continues when `continues`.
    LegacyResponse {
        cipher: Box<CfbDecryptor>,
        expected: u8,
        continues: bool,
    },
    /// Command bytes after a legacy response header, skipped raw.
    Skip(usize),
    Body,
}

enum State {
    Length,
    Body { data: usize, padding: usize },
    Eof,
}

/// Reads one direction of the body.
pub struct BodyReader {
    phase: Phase,
    framing: Framing,
    cfb: Option<CfbDecryptor>,
    /// Bytes from the connection not taken yet.
    raw: Vec<u8>,
    /// Bytes taken (and CFB-decrypted) for the chunk being read.
    plain: Vec<u8>,
    state: State,
}

impl BodyReader {
    /// A reader of the body alone (the server side; `raw` holds bytes
    /// read past the request header).
    pub fn new(keys: &BodyKeys, cfb: Option<CfbDecryptor>, raw: Vec<u8>) -> Self {
        let framing =
            framing(keys.security, keys.option, &keys.request_key, &keys.request_nonce, &keys.key, &keys.nonce);
        BodyReader { phase: Phase::Body, framing, cfb, raw, plain: Vec::new(), state: State::Length }
    }

    /// The client's reader: the AEAD response header first
    /// (sing-vmess `readResponse`); the legacy security's body has a fresh
    /// CFB stream.
    pub fn aead_client(keys: &BodyKeys) -> Self {
        let cfb = (keys.security == SECURITY_LEGACY).then(|| protocol::cfb_decryptor(&keys.key, &keys.nonce));
        let mut reader = BodyReader::new(keys, cfb, Vec::new());
        reader.phase = Phase::AeadResponse { key: keys.key, nonce: keys.nonce, length: None };
        reader
    }

    /// The client's reader of a legacy (alterId) response: the header
    /// under the response key's CFB stream, which the legacy security's
    /// body continues.
    pub fn legacy_client(keys: &BodyKeys, expected: u8) -> Self {
        let mut reader = BodyReader::new(keys, None, Vec::new());
        reader.phase = Phase::LegacyResponse {
            cipher: Box::new(protocol::cfb_decryptor(&keys.key, &keys.nonce)),
            expected,
            continues: keys.security == SECURITY_LEGACY,
        };
        reader
    }

    /// Where bytes read from the connection go.
    pub fn raw_mut(&mut self) -> &mut Vec<u8> {
        &mut self.raw
    }

    /// Whether the end of the connection now is the end of the body: no
    /// part of a header or chunk was read.
    pub fn at_boundary(&self) -> bool {
        matches!(self.phase, Phase::Body)
            && self.raw.is_empty()
            && self.plain.is_empty()
            && matches!(self.state, State::Length | State::Eof)
    }

    /// Moves raw bytes into `plain` (decrypting them) until it holds `n`.
    fn take(&mut self, n: usize) -> bool {
        if self.plain.len() < n {
            let move_count = (n - self.plain.len()).min(self.raw.len());
            let start = self.plain.len();
            self.plain.extend(self.raw.drain(..move_count));
            if let Some(cfb) = &mut self.cfb {
                cfb.decrypt(&mut self.plain[start..]);
            }
        }
        self.plain.len() >= n
    }

    /// The next chunk, or `None` when more bytes are needed.
    pub fn decode(&mut self) -> io::Result<Option<Chunk>> {
        loop {
            match &mut self.phase {
                Phase::Body => break,
                Phase::AeadResponse { key, nonce, length } => match length {
                    None => {
                        if self.raw.len() < 2 + CIPHER_OVERHEAD {
                            return Ok(None);
                        }
                        let value = protocol::open_aead_response_length(key, nonce, &self.raw[..2 + CIPHER_OVERHEAD])?;
                        self.raw.drain(..2 + CIPHER_OVERHEAD);
                        *length = Some(value);
                    }
                    Some(value) => {
                        let total = *value + CIPHER_OVERHEAD;
                        if self.raw.len() < total {
                            return Ok(None);
                        }
                        protocol::open_aead_response_header(key, nonce, &self.raw[..total])?;
                        self.raw.drain(..total);
                        self.phase = Phase::Body;
                    }
                },
                Phase::LegacyResponse { cipher, expected, continues } => {
                    if self.raw.len() < 4 {
                        return Ok(None);
                    }
                    let mut header: Vec<u8> = self.raw.drain(..4).collect();
                    cipher.decrypt(&mut header);
                    if header[0] != *expected {
                        return Err(invalid("bad response header"));
                    }
                    let continues = *continues;
                    let previous = std::mem::replace(&mut self.phase, Phase::Skip(header[3] as usize));
                    if continues {
                        if let Phase::LegacyResponse { cipher, .. } = previous {
                            self.cfb = Some(*cipher);
                        }
                    }
                }
                Phase::Skip(left) => {
                    let count = (*left).min(self.raw.len());
                    self.raw.drain(..count);
                    *left -= count;
                    if *left > 0 {
                        return Ok(None);
                    }
                    self.phase = Phase::Body;
                }
            }
        }
        if matches!(self.framing, Framing::Raw) {
            self.take(self.plain.len() + self.raw.len());
            if self.plain.is_empty() {
                return Ok(None);
            }
            return Ok(Some(Chunk::Data(std::mem::take(&mut self.plain))));
        }
        let Framing::Chunked(chunked) = &mut self.framing else { unreachable!() };
        loop {
            match self.state {
                State::Eof => return Ok(Some(Chunk::Eof)),
                State::Length => {
                    let (length, padding) = match &mut chunked.length {
                        Length::Plain => {
                            if self.plain.len() < 2 {
                                let move_count = (2 - self.plain.len()).min(self.raw.len());
                                let start = self.plain.len();
                                self.plain.extend(self.raw.drain(..move_count));
                                if let Some(cfb) = &mut self.cfb {
                                    cfb.decrypt(&mut self.plain[start..]);
                                }
                                if self.plain.len() < 2 {
                                    return Ok(None);
                                }
                            }
                            let mut length = u16::from_be_bytes([self.plain[0], self.plain[1]]);
                            self.plain.drain(..2);
                            let padding = chunked.masks.next_padding();
                            if let Some(mask) = chunked.masks.next_mask() {
                                length ^= mask;
                            }
                            (length, padding)
                        }
                        Length::Sealed(sealer) => {
                            const SEALED: usize = 2 + CIPHER_OVERHEAD;
                            if self.plain.len() < SEALED {
                                let move_count = (SEALED - self.plain.len()).min(self.raw.len());
                                let start = self.plain.len();
                                self.plain.extend(self.raw.drain(..move_count));
                                if let Some(cfb) = &mut self.cfb {
                                    cfb.decrypt(&mut self.plain[start..]);
                                }
                                if self.plain.len() < SEALED {
                                    return Ok(None);
                                }
                            }
                            let opened = sealer.open(&self.plain[..SEALED])?;
                            self.plain.drain(..SEALED);
                            let length =
                                u16::from_be_bytes([opened[0], opened[1]]).wrapping_add(CIPHER_OVERHEAD as u16);
                            (length, chunked.masks.next_padding())
                        }
                    };
                    let data = length as i64 - padding as i64;
                    if data < 0 {
                        return Err(invalid(format!("bad length chunk: length={length}, padding={padding}")));
                    }
                    if data == 0 {
                        self.state = State::Eof;
                        continue;
                    }
                    self.state = State::Body { data: data as usize, padding: padding as usize };
                }
                State::Body { data, padding } => {
                    let total = data + padding;
                    if self.plain.len() < total {
                        let move_count = (total - self.plain.len()).min(self.raw.len());
                        let start = self.plain.len();
                        self.plain.extend(self.raw.drain(..move_count));
                        if let Some(cfb) = &mut self.cfb {
                            cfb.decrypt(&mut self.plain[start..]);
                        }
                        if self.plain.len() < total {
                            return Ok(None);
                        }
                    }
                    let chunk: Vec<u8> = self.plain.drain(..total).take(data).collect();
                    self.state = State::Length;
                    let payload = match &mut chunked.payload {
                        Payload::Plain => chunk,
                        Payload::Sealed(sealer) => sealer.open(&chunk)?,
                        Payload::Checksum => {
                            if chunk.len() < 4 {
                                return Err(invalid("vmess: invalid chunk checksum"));
                            }
                            let expected = u32::from_be_bytes(chunk[..4].try_into().unwrap());
                            if fnv1a32(&chunk[4..]) != expected {
                                return Err(invalid("vmess: invalid chunk checksum"));
                            }
                            chunk[4..].to_vec()
                        }
                    };
                    return Ok(Some(Chunk::Data(payload)));
                }
            }
        }
    }
}
