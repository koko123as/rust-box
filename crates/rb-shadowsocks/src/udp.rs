//! The client's UDP packets (sing-shadowsocks2 `clientPacketConn` of each
//! method): one shadowsocks packet per datagram to the server.

use std::io;
use std::sync::Mutex;

use rb_adapter::Socksaddr;

use crate::cipher::{self, Aead, AeadKind, Block};
use crate::replay::SlidingWindow;
use crate::{
    check_timestamp, error, random_bytes, read_address, write_address, ClientMethod, MethodKind, HEADER_TYPE_CLIENT,
    HEADER_TYPE_SERVER, MAX_PADDING_LENGTH,
};

/// The nonce in front of an XChaCha20-Poly1305 2022 packet.
pub const PACKET_NONCE_SIZE: usize = 24;
/// The smallest 2022 packet after the nonce (`PacketMinimalHeaderSize`).
pub const PACKET_MINIMAL_HEADER_SIZE: usize = 30;

/// The random padding of a 2022 packet: only to port 53 and below the
/// largest padding (sing-shadowsocks `WritePacket`).
pub(crate) fn packet_padding(destination: &Socksaddr, payload: usize) -> usize {
    if destination.port == 53 && payload < MAX_PADDING_LENGTH {
        rand::random_range(0..MAX_PADDING_LENGTH - payload) + 1
    } else {
        0
    }
}

pub(crate) fn too_short() -> io::Error {
    error("packet too short")
}

/// A 2022 client UDP session (sing-shadowsocks2 `udpSession`).
struct Session {
    session_id: u64,
    packet_id: u64,
    /// The session's AES-GCM cipher (none for ChaCha20, which seals each
    /// packet with the PSK).
    cipher: Option<Aead>,
    remote_session_id: u64,
    last_remote_session_id: u64,
    last_remote_seen: i64,
    remote_cipher: Option<Aead>,
    last_remote_cipher: Option<Aead>,
    window: SlidingWindow,
    last_window: SlidingWindow,
}

/// Encodes the packets a client sends and decodes those it receives.
pub struct ClientPacketCodec {
    method: ClientMethod,
    session: Option<Mutex<Session>>,
}

impl ClientPacketCodec {
    pub fn new(method: &ClientMethod) -> Self {
        let session = match method.kind {
            MethodKind::Ss2022(kind) => {
                let session_id: u64 = rand::random();
                let cipher = (kind != AeadKind::ChaCha20Poly1305).then(|| {
                    let key = cipher::session_key(method.user_psk(), &session_id.to_be_bytes(), kind.key_size());
                    Aead::new(kind, &key)
                });
                Some(Mutex::new(Session {
                    session_id,
                    packet_id: 0,
                    cipher,
                    remote_session_id: 0,
                    last_remote_session_id: 0,
                    last_remote_seen: 0,
                    remote_cipher: None,
                    last_remote_cipher: None,
                    window: SlidingWindow::default(),
                    last_window: SlidingWindow::default(),
                }))
            }
            _ => None,
        };
        ClientPacketCodec { method: method.clone(), session }
    }

    /// The packet carrying `payload` to `destination`.
    pub fn encode(&self, payload: &[u8], destination: &Socksaddr) -> io::Result<Vec<u8>> {
        let method = &self.method;
        let mut packet = Vec::with_capacity(payload.len() + 128);
        match method.kind {
            MethodKind::None => {
                write_address(&mut packet, destination)?;
                packet.extend_from_slice(payload);
            }
            MethodKind::Stream(kind) => {
                let salt = random_bytes(kind.salt_size());
                packet.extend_from_slice(&salt);
                write_address(&mut packet, destination)?;
                packet.extend_from_slice(payload);
                cipher::Stream::new(kind, method.key(), &salt, true).apply(&mut packet[salt.len()..]);
            }
            MethodKind::Aead(kind) => {
                let salt = random_bytes(kind.key_size());
                let aead = Aead::new(kind, &cipher::aead_subkey(method.key(), &salt));
                let mut plain = Vec::with_capacity(payload.len() + 64);
                write_address(&mut plain, destination)?;
                plain.extend_from_slice(payload);
                packet.extend_from_slice(&salt);
                aead.seal_to(&vec![0u8; kind.nonce_size()], &plain, &mut packet);
            }
            MethodKind::Ss2022(kind) => {
                let mut session = self.session.as_ref().expect("2022 session").lock().unwrap();
                let packet_id = session.packet_id;
                session.packet_id = session.packet_id.wrapping_add(1);
                let mut header = [0u8; 16];
                header[..8].copy_from_slice(&session.session_id.to_be_bytes());
                header[8..].copy_from_slice(&packet_id.to_be_bytes());
                let padding = packet_padding(destination, payload.len());
                let mut body = Vec::with_capacity(payload.len() + 11 + padding + 32);
                body.push(HEADER_TYPE_CLIENT);
                body.extend_from_slice(&((method.time)() as u64).to_be_bytes());
                body.extend_from_slice(&(padding as u16).to_be_bytes());
                body.resize(body.len() + padding, 0);
                write_address(&mut body, destination)?;
                body.extend_from_slice(payload);
                if kind == AeadKind::ChaCha20Poly1305 {
                    let nonce = random_bytes(PACKET_NONCE_SIZE);
                    let aead = Aead::new(AeadKind::XChaCha20Poly1305, &method.psks()[0]);
                    let mut plain = header.to_vec();
                    plain.extend_from_slice(&body);
                    packet.extend_from_slice(&nonce);
                    aead.seal_to(&nonce, &plain, &mut packet);
                } else {
                    let mut encrypted_header = header;
                    Block::new(&method.psks()[0]).encrypt(&mut encrypted_header);
                    packet.extend_from_slice(&encrypted_header);
                    // Extended identity headers: each next PSK's hash XOR
                    // the plain header, encrypted with the PSK before it.
                    let psks = method.psks();
                    for (index, psk) in psks.iter().enumerate().take(psks.len() - 1) {
                        let mut identity = method.psk_hashes()[index];
                        for (byte, header) in identity.iter_mut().zip(header.iter()) {
                            *byte ^= header;
                        }
                        Block::new(psk).encrypt(&mut identity);
                        packet.extend_from_slice(&identity);
                    }
                    session.cipher.as_ref().expect("session cipher").seal_to(&header[4..16], &body, &mut packet);
                }
            }
        }
        Ok(packet)
    }

    /// Decodes a packet from the server in place; returns its source and
    /// where its payload starts.
    pub fn decode(&self, packet: &mut Vec<u8>) -> io::Result<(Socksaddr, usize)> {
        let method = &self.method;
        match method.kind {
            MethodKind::None => {
                let (address, length) = read_address(packet)?;
                Ok((address, length))
            }
            MethodKind::Stream(kind) => {
                let salt_size = kind.salt_size();
                if packet.len() < salt_size {
                    return Err(too_short());
                }
                let (salt, data) = packet.split_at_mut(salt_size);
                cipher::Stream::new(kind, method.key(), salt, false).apply(data);
                let (address, length) = read_address(data)?;
                Ok((address, salt_size + length))
            }
            MethodKind::Aead(kind) => {
                let salt_size = kind.key_size();
                if packet.len() < salt_size {
                    return Err(too_short());
                }
                let aead = Aead::new(kind, &cipher::aead_subkey(method.key(), &packet[..salt_size]));
                let length = aead.open_slice(&vec![0u8; kind.nonce_size()], &mut packet[salt_size..])?;
                packet.truncate(salt_size + length);
                let (address, length) = read_address(&packet[salt_size..])?;
                Ok((address, salt_size + length))
            }
            MethodKind::Ss2022(kind) => self.decode_2022(kind, packet),
        }
    }

    /// sing-shadowsocks2 `shadowaead_2022.clientPacketConn.readPacket`.
    fn decode_2022(&self, kind: AeadKind, packet: &mut Vec<u8>) -> io::Result<(Socksaddr, usize)> {
        let method = &self.method;
        let time = method.time;
        // `start` is where the 16-byte packet header begins.
        let chacha = kind == AeadKind::ChaCha20Poly1305;
        let start;
        let mut header = [0u8; 16];
        if chacha {
            if packet.len() < PACKET_NONCE_SIZE + PACKET_MINIMAL_HEADER_SIZE {
                return Err(too_short());
            }
            let aead = Aead::new(AeadKind::XChaCha20Poly1305, &method.psks()[0]);
            let (nonce, data) = packet.split_at_mut(PACKET_NONCE_SIZE);
            let length =
                aead.open_slice(nonce, data).map_err(|error| crate::error(format!("decrypt packet: {error}")))?;
            packet.truncate(PACKET_NONCE_SIZE + length);
            start = PACKET_NONCE_SIZE;
            header.copy_from_slice(&packet[start..start + 16]);
        } else {
            if packet.len() < PACKET_MINIMAL_HEADER_SIZE {
                return Err(too_short());
            }
            header.copy_from_slice(&packet[..16]);
            Block::new(method.user_psk()).decrypt(&mut header);
            packet[..16].copy_from_slice(&header);
            start = 0;
        }
        let session_id = u64::from_be_bytes(header[..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(header[8..].try_into().unwrap());
        let mut session = self.session.as_ref().expect("2022 session").lock().unwrap();
        if session_id == session.remote_session_id {
            if !session.window.check(packet_id) {
                return Err(error("packet id not unique"));
            }
        } else if session_id == session.last_remote_session_id && !session.last_window.check(packet_id) {
            return Err(error("packet id not unique"));
        }
        let mut remote_cipher = None;
        if !chacha {
            remote_cipher = if session_id == session.remote_session_id {
                session.remote_cipher.clone()
            } else if session_id == session.last_remote_session_id {
                session.last_remote_cipher.clone()
            } else {
                None
            };
            let aead = match remote_cipher.take() {
                Some(aead) => aead,
                None => Aead::new(kind, &cipher::session_key(method.user_psk(), &header[..8], kind.key_size())),
            };
            let length = aead
                .open_slice(&header[4..16], &mut packet[16..])
                .map_err(|error| crate::error(format!("decrypt packet: {error}")))?;
            packet.truncate(16 + length);
            remote_cipher = Some(aead);
        }
        let mut position = start + 16;
        let body = &packet[..];
        let header_type = *body.get(position).ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        if header_type != HEADER_TYPE_SERVER {
            return Err(error(format!("bad header type: expected {HEADER_TYPE_SERVER}, got {header_type}")));
        }
        position += 1;
        let epoch = read_u64(body, &mut position)?;
        check_timestamp(epoch, time())?;
        let now = time();
        if session_id == session.remote_session_id {
            session.window.add(packet_id);
        } else if session_id == session.last_remote_session_id {
            session.last_window.add(packet_id);
            session.last_remote_seen = now;
        } else {
            if session.remote_session_id != 0 {
                if now - session.last_remote_seen < 60 {
                    return Err(error("server session changed more than once during the last minute"));
                }
                session.last_remote_session_id = session.remote_session_id;
                session.last_window = std::mem::take(&mut session.window);
                session.last_remote_seen = now;
                session.last_remote_cipher = session.remote_cipher.take();
            }
            session.remote_session_id = session_id;
            session.remote_cipher = remote_cipher;
            session.window.add(packet_id);
        }
        let client_session_id = read_u64(body, &mut position)?;
        if client_session_id != session.session_id {
            return Err(error("bad client session id"));
        }
        let padding = body
            .get(position..position + 2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
            .ok_or_else(|| error("read padding length: unexpected EOF"))?;
        position += 2;
        if padding > body.len() - position {
            return Err(too_short());
        }
        position += padding;
        let (address, length) = read_address(&body[position..])?;
        Ok((address, position + length))
    }
}

pub(crate) fn read_u64(data: &[u8], position: &mut usize) -> io::Result<u64> {
    let bytes = data.get(*position..*position + 8).ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    *position += 8;
    Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
}
