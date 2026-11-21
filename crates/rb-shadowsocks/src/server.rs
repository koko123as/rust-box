//! The server side (sing-shadowsocks services): the TCP handshake, the
//! decoding of UDP packets and the encoding of their replies, for one
//! user, many users, or a 2022 relay.
//!
//! - `none`: `NoneService`.
//! - AEAD: `shadowaead.Service`; with users `shadowaead.MultiService`,
//!   which tries each user's key.
//! - 2022: `shadowaead_2022.Service`; with users `MultiService` (one
//!   identity PSK, user PSKs found by the extended identity header).
//! - 2022 relay: `RelayService`, which takes the first identity header
//!   off and forwards the rest to the user's destination.
//!
//! Users are numbered by their position in the configuration.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rb_adapter::Socksaddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::cipher::{self, Aead, AeadKind, Block, TAG_SIZE};
use crate::replay::{SaltFilter, SlidingWindow};
use crate::tcp::{AeadReader, Reader, ShadowStream, WriteInit, WriteMode, Writer};
use crate::udp::{packet_padding, read_u64, too_short, PACKET_MINIMAL_HEADER_SIZE, PACKET_NONCE_SIZE};
use crate::{
    check_timestamp, decode_base64, error, random_bytes, read_address, read_address_from, unix_now, write_address,
    MethodKind, AEAD_MAX_CHUNK, AEAD_METHODS, HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER, SS2022_METHODS,
};

/// How long a 2022 salt is remembered (`replay.NewSimple(60 * time.Second)`).
const SALT_TIMEOUT: Duration = Duration::from_secs(60);
/// What the relay reads of the request at once (`buf.New()`).
const RELAY_READ_SIZE: usize = 32 * 1024;

/// A 2022 user (or relay destination): its PSK and the PSK's identity.
#[derive(Clone)]
struct Ss2022User {
    psk: Vec<u8>,
    hash: [u8; 16],
}

enum Mode {
    None,
    /// The users' keys (a single-user service has one).
    Aead {
        kind: AeadKind,
        keys: Vec<Vec<u8>>,
        multi: bool,
    },
    /// `psk` is the server PSK (the identity PSK with users).
    Ss2022 {
        kind: AeadKind,
        psk: Vec<u8>,
        users: Option<Vec<Ss2022User>>,
    },
    Relay {
        kind: AeadKind,
        psk: Vec<u8>,
        users: Vec<Ss2022User>,
    },
}

/// A 2022 server UDP session (sing-shadowsocks `serverUDPSession`), one
/// per client session id.
pub struct UdpSession {
    session_id: u64,
    remote_session_id: u64,
    packet_id: u64,
    /// AES: the cipher of the replies (from the server session id).
    cipher: Option<Aead>,
    /// AES: the cipher of the client's packets (from its session id).
    remote_cipher: Option<Aead>,
    window: SlidingWindow,
}

type SharedSession = Arc<Mutex<UdpSession>>;

/// A configured service.
pub struct Service {
    mode: Mode,
    replay: SaltFilter,
    udp_timeout: Duration,
    udp_sessions: Mutex<HashMap<u64, (SharedSession, Instant)>>,
    /// The clock of the 2022 timestamps.
    pub time: fn() -> i64,
}

/// 2022 PSK checks of `NewService` / `UpdateUsers`: too short is an
/// error, too long is hashed down.
fn ss2022_key(key: Vec<u8>, size: usize) -> Result<Vec<u8>, String> {
    if key.len() < size {
        return Err("bad key".into());
    }
    if key.len() > size {
        return Ok(cipher::sha256_key(&key, size));
    }
    Ok(key)
}

fn ss2022_users(passwords: &[String], size: usize) -> Result<Vec<Ss2022User>, String> {
    passwords
        .iter()
        .map(|password| {
            if password.is_empty() {
                return Err("missing password".to_string());
            }
            let key = decode_base64(password).map_err(|error| format!("decode psk: {error}"))?;
            let psk = ss2022_key(key, size)?;
            Ok(Ss2022User { hash: cipher::psk_hash(&psk), psk })
        })
        .collect()
}

fn decode_psk(password: &str) -> Result<Vec<u8>, String> {
    if password.is_empty() {
        return Err("missing psk".into());
    }
    decode_base64(password).map_err(|error| format!("decode psk: {error}"))
}

/// What a TCP handshake found.
#[allow(clippy::large_enum_variant)]
pub enum Accepted<S> {
    /// A request: the decrypting stream, its destination and the user.
    Stream { stream: ShadowStream<S>, destination: Socksaddr, user: Option<usize> },
    /// A relayed request: `prefix` (the request without its first identity
    /// header) goes in front of the rest of `io` to the user's destination.
    Relay { io: S, prefix: Vec<u8>, user: usize },
}

/// A decoded UDP packet.
pub struct Packet {
    pub destination: Socksaddr,
    /// Where the payload starts in the decoded buffer (for a relay, the
    /// whole buffer is the packet to forward).
    pub payload_start: usize,
    /// The NAT session: `None` for one per source address, else the
    /// client's 2022 session id.
    pub session: Option<u64>,
    pub user: Option<usize>,
    /// Encodes this session's replies.
    pub reply: ReplyEncoder,
}

/// Encodes the replies of one UDP session.
pub enum ReplyEncoder {
    None,
    Aead {
        kind: AeadKind,
        key: Vec<u8>,
    },
    Ss2022 {
        kind: AeadKind,
        session: Arc<Mutex<UdpSession>>,
        block: Option<Block>,
        psk: Vec<u8>,
        time: fn() -> i64,
    },
    /// A relay forwards the upstream's packets as they are.
    Relay,
}

impl Service {
    fn new(mode: Mode, udp_timeout: Duration) -> Self {
        Service {
            mode,
            replay: SaltFilter::new(SALT_TIMEOUT),
            udp_timeout,
            udp_sessions: Mutex::new(HashMap::new()),
            time: unix_now,
        }
    }

    /// One user: sing-box `newInbound` (`NewNoneService`,
    /// `shadowaead.NewService`, `shadowaead_2022.NewServiceWithPassword`).
    pub fn single(method: &str, password: &str, udp_timeout: Duration) -> Result<Self, String> {
        let mode = match MethodKind::parse(method) {
            Some(MethodKind::None) => Mode::None,
            Some(MethodKind::Aead(kind)) if AEAD_METHODS.contains(&method) => {
                if password.is_empty() {
                    return Err("missing password".into());
                }
                let key = cipher::evp_bytes_to_key(password.as_bytes(), kind.key_size());
                Mode::Aead { kind, keys: vec![key], multi: false }
            }
            Some(MethodKind::Ss2022(kind)) => {
                let psk = ss2022_key(decode_psk(password)?, kind.key_size())?;
                Mode::Ss2022 { kind, psk, users: None }
            }
            _ => return Err(format!("unsupported method: {method}")),
        };
        Ok(Service::new(mode, udp_timeout))
    }

    /// Users: sing-box `newMultiInbound` (`shadowaead_2022.NewMultiServiceWithPassword`
    /// or `shadowaead.NewMultiService`, then `UpdateUsersWithPasswords`).
    pub fn multi(method: &str, password: &str, users: &[String], udp_timeout: Duration) -> Result<Self, String> {
        let mode = match MethodKind::parse(method) {
            Some(MethodKind::Ss2022(kind)) if SS2022_METHODS.contains(&method) => {
                let psk = decode_psk(password)?;
                if kind == AeadKind::ChaCha20Poly1305 {
                    return Err("invalid argument".into());
                }
                let psk = ss2022_key(psk, kind.key_size())?;
                let users = ss2022_users(users, kind.key_size())?;
                Mode::Ss2022 { kind, psk, users: Some(users) }
            }
            Some(MethodKind::Aead(kind)) if AEAD_METHODS.contains(&method) => {
                let keys = users
                    .iter()
                    .map(|password| {
                        if password.is_empty() {
                            return Err("missing password".to_string());
                        }
                        Ok(cipher::evp_bytes_to_key(password.as_bytes(), kind.key_size()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Mode::Aead { kind, keys, multi: true }
            }
            _ => return Err(format!("unsupported method: {method}")),
        };
        Ok(Service::new(mode, udp_timeout))
    }

    /// A 2022 relay: sing-box `newRelayInbound`
    /// (`NewRelayServiceWithPassword`, `UpdateUsersWithPasswords`).
    pub fn relay(method: &str, password: &str, destinations: &[String], udp_timeout: Duration) -> Result<Self, String> {
        let psk = decode_psk(password)?;
        let kind = match method {
            "2022-blake3-aes-128-gcm" => AeadKind::Aes128Gcm,
            "2022-blake3-aes-256-gcm" => AeadKind::Aes256Gcm,
            _ => return Err("invalid argument".into()),
        };
        let psk = ss2022_key(psk, kind.key_size())?;
        let users = ss2022_users(destinations, kind.key_size())?;
        Ok(Service::new(Mode::Relay { kind, psk, users }, udp_timeout))
    }

    /// Reads and checks a request (sing-shadowsocks `newConnection`).
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(&self, mut io: S) -> io::Result<Accepted<S>> {
        match &self.mode {
            Mode::None => {
                let destination = read_address_from(&mut io).await?;
                let stream = ShadowStream::from_parts(
                    io,
                    Reader::Plain,
                    Writer::new(WriteMode::Plain, WriteInit::Ready, Vec::new()),
                );
                Ok(Accepted::Stream { stream, destination, user: None })
            }
            Mode::Aead { kind, keys, multi } => self.accept_aead(io, *kind, keys, *multi).await,
            Mode::Ss2022 { kind, psk, users } => self.accept_2022(io, *kind, psk, users.as_deref()).await,
            Mode::Relay { kind, psk, users } => {
                let salt_size = kind.key_size();
                let mut request = vec![0u8; RELAY_READ_SIZE];
                let read = io.read(&mut request).await?;
                if read < salt_size + 16 {
                    return Err(error("bad header"));
                }
                request.truncate(read);
                let user = find_identity(psk, &request[..salt_size], &request[salt_size..salt_size + 16], users)
                    .ok_or_else(|| error("invalid request"))?;
                let mut prefix = request[..salt_size].to_vec();
                prefix.extend_from_slice(&request[salt_size + 16..]);
                Ok(Accepted::Relay { io, prefix, user })
            }
        }
    }

    async fn accept_aead<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut io: S,
        kind: AeadKind,
        keys: &[Vec<u8>],
        multi: bool,
    ) -> io::Result<Accepted<S>> {
        if keys.is_empty() {
            return Err(error("no users"));
        }
        let salt_size = kind.key_size();
        let mut header = vec![0u8; salt_size + 2 + TAG_SIZE];
        io.read_exact(&mut header)
            .await
            .map_err(|error| io::Error::new(error.kind(), format!("read header: {error}")))?;
        let (salt, length_chunk) = header.split_at(salt_size);
        let mut found = None;
        let mut last_error = None;
        for (index, key) in keys.iter().enumerate() {
            let aead = Aead::new(kind, &cipher::aead_subkey(key, salt));
            let mut chunk = length_chunk.to_vec();
            match aead.open(&vec![0u8; kind.nonce_size()], &mut chunk) {
                Ok(()) => {
                    found = Some((index, aead, u16::from_be_bytes([chunk[0], chunk[1]]) as usize));
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let Some((index, aead, length)) = found else {
            return Err(last_error.unwrap_or_else(crate::authentication_failed));
        };
        if length > AEAD_MAX_CHUNK {
            return Err(error("packet too large"));
        }
        let mut nonce = vec![0u8; kind.nonce_size()];
        cipher::increase_nonce(&mut nonce);
        let mut payload = vec![0u8; length + TAG_SIZE];
        io.read_exact(&mut payload).await?;
        aead.open(&nonce, &mut payload)?;
        cipher::increase_nonce(&mut nonce);
        let reader = AeadReader::server(aead, nonce, payload, Some(AEAD_MAX_CHUNK));
        let writer = Writer::new(
            WriteMode::Aead { cipher: None, nonce: Vec::new(), max_chunk: AEAD_MAX_CHUNK },
            WriteInit::AeadServer { kind, key: keys[index].clone() },
            Vec::new(),
        );
        let mut stream = ShadowStream::from_parts(io, Reader::Aead(Box::new(reader)), writer);
        let destination = read_address_from(&mut stream).await?;
        Ok(Accepted::Stream { stream, destination, user: multi.then_some(index) })
    }

    async fn accept_2022<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut io: S,
        kind: AeadKind,
        psk: &[u8],
        users: Option<&[Ss2022User]>,
    ) -> io::Result<Accepted<S>> {
        let salt_size = kind.key_size();
        let identity = if users.is_some() { 16 } else { 0 };
        let mut header = vec![0u8; salt_size + identity + 11 + TAG_SIZE];
        io.read_exact(&mut header).await.map_err(|error| {
            if users.is_some() {
                error
            } else {
                io::Error::new(error.kind(), format!("read header: {error}"))
            }
        })?;
        let salt = header[..salt_size].to_vec();
        if !self.replay.check(&salt) {
            return Err(error("salt not unique"));
        }
        let (user, user_psk) = match users {
            Some(users) => {
                let index = find_identity(psk, &salt, &header[salt_size..salt_size + 16], users)
                    .ok_or_else(|| error("invalid request"))?;
                (Some(index), users[index].psk.clone())
            }
            None => (None, psk.to_vec()),
        };
        let aead = Aead::new(kind, &cipher::session_key(&user_psk, &salt, salt_size));
        let mut nonce = vec![0u8; kind.nonce_size()];
        let mut fixed = header[salt_size + identity..].to_vec();
        aead.open(&nonce, &mut fixed)?;
        cipher::increase_nonce(&mut nonce);
        if fixed[0] != HEADER_TYPE_CLIENT {
            return Err(error(format!("bad header type: expected {HEADER_TYPE_CLIENT}, got {}", fixed[0])));
        }
        let epoch = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
        check_timestamp(epoch, (self.time)())?;
        let length = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
        let mut variable = vec![0u8; length + TAG_SIZE];
        io.read_exact(&mut variable).await?;
        aead.open(&nonce, &mut variable)?;
        cipher::increase_nonce(&mut nonce);
        let (destination, address_length) = read_address(&variable)?;
        let rest = &variable[address_length..];
        let padding = rest
            .get(..2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let cached = &rest[2..];
        if cached.len() < padding {
            return Err(error(if users.is_some() {
                "bad request: damaged padding"
            } else {
                "bad request: missing payload or padding"
            }));
        }
        if padding == 0 && cached.is_empty() {
            return Err(error("bad request: missing payload or padding"));
        }
        let payload = cached[padding..].to_vec();
        let reader = AeadReader::server(aead, nonce, payload, None);
        let writer = Writer::new(
            WriteMode::Aead { cipher: None, nonce: Vec::new(), max_chunk: crate::SS2022_MAX_CHUNK },
            WriteInit::Ss2022Server { kind, psk: user_psk, request_salt: salt, time: self.time },
            Vec::new(),
        );
        let stream = ShadowStream::from_parts(io, Reader::Aead(Box::new(reader)), writer);
        Ok(Accepted::Stream { stream, destination, user })
    }

    /// Decodes a UDP packet in place (sing-shadowsocks `newPacket`).
    pub fn decode_packet(&self, packet: &mut Vec<u8>) -> io::Result<Packet> {
        match &self.mode {
            Mode::None => {
                let (destination, length) = read_address(packet)?;
                Ok(Packet { destination, payload_start: length, session: None, user: None, reply: ReplyEncoder::None })
            }
            Mode::Aead { kind, keys, multi } => {
                let salt_size = kind.key_size();
                if keys.is_empty() {
                    return Err(error("no users"));
                }
                if packet.len() < salt_size {
                    return Err(error("short buffer"));
                }
                let mut last_error = None;
                for (index, key) in keys.iter().enumerate() {
                    let aead = Aead::new(*kind, &cipher::aead_subkey(key, &packet[..salt_size]));
                    let mut data = packet[salt_size..].to_vec();
                    match aead.open(&vec![0u8; kind.nonce_size()], &mut data) {
                        Ok(()) => {
                            packet.truncate(salt_size);
                            packet.extend_from_slice(&data);
                            let (destination, length) = read_address(&packet[salt_size..])?;
                            return Ok(Packet {
                                destination,
                                payload_start: salt_size + length,
                                session: None,
                                user: multi.then_some(index),
                                reply: ReplyEncoder::Aead { kind: *kind, key: key.clone() },
                            });
                        }
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(last_error.unwrap_or_else(crate::authentication_failed))
            }
            Mode::Ss2022 { kind, psk, users } => self.decode_2022(*kind, psk, users.as_deref(), packet),
            Mode::Relay { psk, users, .. } => {
                if packet.len() < PACKET_MINIMAL_HEADER_SIZE {
                    return Err(too_short());
                }
                let block = Block::new(psk);
                let mut header = [0u8; 16];
                header.copy_from_slice(&packet[..16]);
                block.decrypt(&mut header);
                let session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
                let user = find_packet_identity(&block, &header, &packet[16..32], users)
                    .ok_or_else(|| error("invalid request"))?;
                // The header encrypted for the user takes the identity
                // header's place.
                Block::new(&users[user].psk).encrypt(&mut header);
                packet.drain(..16);
                packet[..16].copy_from_slice(&header);
                Ok(Packet {
                    destination: Socksaddr::from_host_port("0.0.0.0", 0),
                    payload_start: 0,
                    session: Some(session_id),
                    user: Some(user),
                    reply: ReplyEncoder::Relay,
                })
            }
        }
    }

    fn decode_2022(
        &self,
        kind: AeadKind,
        psk: &[u8],
        users: Option<&[Ss2022User]>,
        packet: &mut Vec<u8>,
    ) -> io::Result<Packet> {
        let chacha = kind == AeadKind::ChaCha20Poly1305;
        let mut header = [0u8; 16];
        let mut user = None;
        let mut user_psk = psk.to_vec();
        // Where the body after the header starts.
        let body_start;
        if chacha {
            if packet.len() < PACKET_NONCE_SIZE + PACKET_MINIMAL_HEADER_SIZE {
                return Err(too_short());
            }
            let aead = Aead::new(AeadKind::XChaCha20Poly1305, psk);
            let (nonce, data) = packet.split_at_mut(PACKET_NONCE_SIZE);
            let length = aead
                .open_slice(nonce, data)
                .map_err(|error| crate::error(format!("decrypt packet header: {error}")))?;
            packet.truncate(PACKET_NONCE_SIZE + length);
            header.copy_from_slice(&packet[PACKET_NONCE_SIZE..PACKET_NONCE_SIZE + 16]);
            body_start = PACKET_NONCE_SIZE + 16;
        } else {
            if packet.len() < PACKET_MINIMAL_HEADER_SIZE {
                return Err(too_short());
            }
            let block = Block::new(psk);
            header.copy_from_slice(&packet[..16]);
            block.decrypt(&mut header);
            if let Some(users) = users {
                let index = find_packet_identity(&block, &header, &packet[16..32], users)
                    .ok_or_else(|| error("invalid request"))?;
                user = Some(index);
                user_psk = users[index].psk.clone();
                body_start = 32;
            } else {
                body_start = 16;
            }
        }
        let session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(header[8..].try_into().unwrap());
        let (session, created) = self.udp_session(session_id, kind, &user_psk, &header, chacha);
        let result = self.decode_2022_body(kind, &session, &header, packet_id, body_start, chacha, packet);
        let (destination, payload_start) = match result {
            Ok(result) => result,
            Err(error) => {
                if created {
                    self.udp_sessions.lock().unwrap().remove(&session_id);
                }
                return Err(error);
            }
        };
        let block = (!chacha).then(|| Block::new(&user_psk));
        Ok(Packet {
            destination,
            payload_start,
            session: Some(session_id),
            user,
            reply: ReplyEncoder::Ss2022 { kind, session, block, psk: psk.to_vec(), time: self.time },
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_2022_body(
        &self,
        kind: AeadKind,
        session: &Arc<Mutex<UdpSession>>,
        header: &[u8; 16],
        packet_id: u64,
        body_start: usize,
        chacha: bool,
        packet: &mut Vec<u8>,
    ) -> io::Result<(Socksaddr, usize)> {
        let _ = kind;
        let mut session = session.lock().unwrap();
        if !session.window.check(packet_id) {
            return Err(error("packet id not unique"));
        }
        if !chacha {
            let aead = session.remote_cipher.as_ref().expect("remote cipher");
            let length = aead
                .open_slice(&header[4..16], &mut packet[body_start..])
                .map_err(|error| crate::error(format!("decrypt packet: {error}")))?;
            packet.truncate(body_start + length);
        }
        session.window.add(packet_id);
        let mut position = body_start;
        let header_type = *packet.get(position).ok_or_else(|| error("decrypt packet: EOF"))?;
        if header_type != HEADER_TYPE_CLIENT {
            return Err(error(format!("bad header type: expected {HEADER_TYPE_CLIENT}, got {header_type}")));
        }
        position += 1;
        let epoch = read_u64(packet, &mut position)?;
        check_timestamp(epoch, (self.time)())?;
        let padding = packet
            .get(position..position + 2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
            .ok_or_else(|| error("read padding length: unexpected EOF"))?;
        position += 2;
        if padding > packet.len() - position {
            return Err(too_short());
        }
        position += padding;
        let (destination, length) = read_address(&packet[position..])?;
        Ok((destination, position + length))
    }

    /// The 2022 session of a client session id, created when new
    /// (`udpSessions.LoadOrStore`, aged out after the UDP timeout).
    fn udp_session(
        &self,
        session_id: u64,
        kind: AeadKind,
        user_psk: &[u8],
        header: &[u8; 16],
        chacha: bool,
    ) -> (Arc<Mutex<UdpSession>>, bool) {
        let now = Instant::now();
        let mut sessions = self.udp_sessions.lock().unwrap();
        if let Some((session, used)) = sessions.get_mut(&session_id) {
            if now.duration_since(*used) <= self.udp_timeout {
                *used = now;
                return (session.clone(), false);
            }
        }
        let timeout = self.udp_timeout;
        sessions.retain(|_, (_, used)| now.duration_since(*used) <= timeout);
        let server_session_id: u64 = rand::random();
        let size = kind.key_size();
        let session = UdpSession {
            session_id: server_session_id,
            remote_session_id: session_id,
            packet_id: 0,
            cipher: (!chacha)
                .then(|| Aead::new(kind, &cipher::session_key(user_psk, &server_session_id.to_be_bytes(), size))),
            remote_cipher: (!chacha).then(|| Aead::new(kind, &cipher::session_key(user_psk, &header[..8], size))),
            window: SlidingWindow::default(),
        };
        let session = Arc::new(Mutex::new(session));
        sessions.insert(session_id, (session.clone(), now));
        (session, true)
    }
}

/// The user whose PSK hash a TCP identity header carries.
fn find_identity(psk: &[u8], salt: &[u8], identity: &[u8], users: &[Ss2022User]) -> Option<usize> {
    let subkey = cipher::identity_subkey(psk, salt, salt.len());
    let mut hash = [0u8; 16];
    hash.copy_from_slice(identity);
    Block::new(&subkey).decrypt(&mut hash);
    users.iter().position(|user| user.hash == hash)
}

/// The user whose PSK hash a UDP identity header carries (decrypted with
/// the identity PSK, XOR the plain packet header).
fn find_packet_identity(block: &Block, header: &[u8; 16], identity: &[u8], users: &[Ss2022User]) -> Option<usize> {
    let mut hash = [0u8; 16];
    hash.copy_from_slice(identity);
    block.decrypt(&mut hash);
    for (byte, header) in hash.iter_mut().zip(header.iter()) {
        *byte ^= header;
    }
    users.iter().position(|user| user.hash == hash)
}

impl ReplyEncoder {
    /// The packet carrying a reply `payload` from `source`.
    pub fn encode(&self, payload: &[u8], source: &Socksaddr) -> io::Result<Vec<u8>> {
        let mut packet = Vec::with_capacity(payload.len() + 128);
        match self {
            ReplyEncoder::None => {
                write_address(&mut packet, source)?;
                packet.extend_from_slice(payload);
            }
            ReplyEncoder::Relay => packet.extend_from_slice(payload),
            ReplyEncoder::Aead { kind, key } => {
                let salt = random_bytes(kind.key_size());
                let aead = Aead::new(*kind, &cipher::aead_subkey(key, &salt));
                let mut plain = Vec::with_capacity(payload.len() + 32);
                write_address(&mut plain, source)?;
                plain.extend_from_slice(payload);
                packet.extend_from_slice(&salt);
                aead.seal_to(&vec![0u8; kind.nonce_size()], &plain, &mut packet);
            }
            ReplyEncoder::Ss2022 { kind, session, block, psk, time } => {
                // sing-shadowsocks `serverPacketWriter.WritePacket`.
                let mut session = session.lock().unwrap();
                let packet_id = session.packet_id;
                session.packet_id = session.packet_id.wrapping_add(1);
                let mut header = [0u8; 16];
                header[..8].copy_from_slice(&session.session_id.to_be_bytes());
                header[8..].copy_from_slice(&packet_id.to_be_bytes());
                let padding = packet_padding(source, payload.len());
                let mut body = Vec::with_capacity(payload.len() + 19 + padding + 32);
                body.push(HEADER_TYPE_SERVER);
                body.extend_from_slice(&(time() as u64).to_be_bytes());
                body.extend_from_slice(&session.remote_session_id.to_be_bytes());
                body.extend_from_slice(&(padding as u16).to_be_bytes());
                body.resize(body.len() + padding, 0);
                write_address(&mut body, source)?;
                body.extend_from_slice(payload);
                if *kind == AeadKind::ChaCha20Poly1305 {
                    let nonce = random_bytes(PACKET_NONCE_SIZE);
                    let aead = Aead::new(AeadKind::XChaCha20Poly1305, psk);
                    let mut plain = header.to_vec();
                    plain.extend_from_slice(&body);
                    packet.extend_from_slice(&nonce);
                    aead.seal_to(&nonce, &plain, &mut packet);
                } else {
                    let mut encrypted_header = header;
                    block.as_ref().expect("header cipher").encrypt(&mut encrypted_header);
                    packet.extend_from_slice(&encrypted_header);
                    session.cipher.as_ref().expect("session cipher").seal_to(&header[4..16], &body, &mut packet);
                }
            }
        }
        Ok(packet)
    }
}
