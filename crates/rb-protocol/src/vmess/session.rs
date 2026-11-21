//! The two ends of a VMess connection: the client's request (sing-vmess
//! `rawClientConn.writeHandshake` and `readResponse`) and the server's
//! reading of it (`Service.NewConnection`, `rawServerConn.writeResponse`),
//! with the user table, the legacy alterId keys and the replay filter.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::Aes128;
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::{Rng, RngCore};
use rb_adapter::Socksaddr;
use rb_shadowsocks::replay::SaltFilter;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::codec::{BodyKeys, BodyReader, BodyWriter};
use super::protocol::{
    self, invalid, RequestHeader, CACHE_DURATION_SECONDS, CIPHER_OVERHEAD, COMMAND_MUX, COMMAND_TCP, COMMAND_UDP,
    OPTION_CHUNK_STREAM, SECURITY_AES_128_GCM, SECURITY_CHACHA20_POLY1305, SECURITY_LEGACY, SECURITY_NONE, VERSION,
};
use crate::vless::protocol::parse_address;

/// The Unix time in seconds.
pub fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs() as i64)
}

/// A client's settings (sing-vmess `Client`).
#[derive(Clone)]
pub struct ClientConfig {
    pub cmd_key: [u8; 16],
    /// The first alter id's key when `alter_id` > 0 (the legacy header).
    pub alter_key: Option<[u8; 16]>,
    pub security: u8,
    pub global_padding: bool,
    pub authenticated_length: bool,
}

impl ClientConfig {
    /// sing-vmess `NewClient` (the security name is checked there).
    pub fn new(uuid: &[u8; 16], security: u8, alter_id: i64, global_padding: bool, authenticated_length: bool) -> Self {
        ClientConfig {
            cmd_key: protocol::cmd_key(uuid),
            alter_key: (alter_id > 0).then(|| protocol::alter_id(uuid)),
            security,
            global_padding,
            authenticated_length,
        }
    }

    /// The request of a new connection and the codecs of its body: the
    /// writer starts with the request header.
    pub fn handshake(&self, command: u8, destination: &Socksaddr) -> io::Result<(BodyWriter, BodyReader)> {
        let mut rng = rand::rng();
        let mut request_key = [0u8; 16];
        let mut request_nonce = [0u8; 16];
        rng.fill_bytes(&mut request_key);
        rng.fill_bytes(&mut request_nonce);
        let response_header: u8 = rng.random();
        let padding_len: usize = rng.random_range(0..16);
        let mut padding = vec![0u8; padding_len];
        rng.fill_bytes(&mut padding);
        let option = protocol::client_option(self.security, command, self.global_padding, self.authenticated_length);
        let header = RequestHeader {
            request_nonce,
            request_key,
            response_header,
            option,
            security: self.security,
            command,
            destination: (command != COMMAND_MUX).then(|| destination.clone()),
            padding,
        }
        .encode()?;
        let now = unix_now();
        let request = match &self.alter_key {
            Some(alter_key) => protocol::seal_legacy_request(&self.cmd_key, alter_key, now as u64, &header),
            None => {
                let mut random = [0u8; 4];
                rng.fill_bytes(&mut random);
                let auth_id = protocol::auth_id(&self.cmd_key, now, random);
                let mut connection_nonce = [0u8; 8];
                rng.fill_bytes(&mut connection_nonce);
                protocol::seal_aead_request(&self.cmd_key, &auth_id, &connection_nonce, &header)
            }
        };
        let write_keys = BodyKeys {
            security: self.security,
            option,
            request_key,
            request_nonce,
            key: request_key,
            nonce: request_nonce,
        };
        let cfb = (self.security == SECURITY_LEGACY).then(|| protocol::cfb_encryptor(&request_key, &request_nonce));
        let writer = BodyWriter::new(request, &write_keys, cfb);
        let legacy = self.alter_key.is_some();
        let (response_key, response_nonce) = protocol::response_keys(legacy, &request_key, &request_nonce);
        let read_keys = BodyKeys { key: response_key, nonce: response_nonce, ..write_keys };
        let reader = if legacy {
            BodyReader::legacy_client(&read_keys, response_header)
        } else {
            BodyReader::aead_client(&read_keys)
        };
        Ok((writer, reader))
    }
}

struct ServerUser {
    cmd_key: [u8; 16],
    cipher: Aes128,
}

/// The legacy request auths of every user with an alterId (sing-vmess
/// `generateLegacyKeys`).
#[derive(Default)]
struct LegacyKeys {
    map: HashMap<[u8; 16], (usize, i64)>,
    update_time: HashMap<usize, i64>,
}

/// The users of a server (sing-vmess `Service`).
pub struct ServerUsers {
    users: Vec<ServerUser>,
    alter_ids: Vec<(usize, Vec<[u8; 16]>)>,
    legacy: Mutex<LegacyKeys>,
    replay: SaltFilter,
    /// The clock (sing-vmess `ServiceWithTimeFunc`; tests set it).
    now: fn() -> i64,
}

/// How often the legacy keys are regenerated (sing-vmess `Start`).
pub const LEGACY_UPDATE_INTERVAL: Duration = Duration::from_secs(10);

impl ServerUsers {
    /// sing-vmess `UpdateUsers`: `(uuid, alterId)` per user.
    pub fn new(users: &[([u8; 16], i64)]) -> Self {
        ServerUsers::with_time(users, unix_now)
    }

    /// [`ServerUsers::new`] with a clock of its own.
    pub fn with_time(users: &[([u8; 16], i64)], now: fn() -> i64) -> Self {
        let mut alter_ids = Vec::new();
        let users = users
            .iter()
            .enumerate()
            .map(|(index, (uuid, alter_id))| {
                let cmd_key = protocol::cmd_key(uuid);
                if *alter_id > 0 {
                    let mut ids = Vec::with_capacity(*alter_id as usize);
                    let mut current = *uuid;
                    for _ in 0..*alter_id {
                        current = protocol::alter_id(&current);
                        ids.push(current);
                    }
                    alter_ids.push((index, ids));
                }
                ServerUser { cmd_key, cipher: protocol::auth_id_cipher(&cmd_key) }
            })
            .collect();
        let users = ServerUsers {
            users,
            alter_ids,
            legacy: Mutex::new(LegacyKeys::default()),
            replay: SaltFilter::new(Duration::from_secs(120)),
            now,
        };
        users.generate_legacy_keys();
        users
    }

    /// Whether some user has an alterId (then the ticker runs).
    pub fn has_legacy(&self) -> bool {
        !self.alter_ids.is_empty()
    }

    /// sing-vmess `generateLegacyKeys`: each user's auths from its last
    /// update (at most 120 seconds back) to 120 seconds ahead.
    pub fn generate_legacy_keys(&self) {
        let now = (self.now)();
        let end = now + CACHE_DURATION_SECONDS;
        let mut legacy = self.legacy.lock().unwrap();
        let mut map = HashMap::new();
        let mut update_time = HashMap::new();
        for (user, ids) in &self.alter_ids {
            let begin = legacy.update_time.get(user).copied().unwrap_or(0).max(now - CACHE_DURATION_SECONDS);
            for id in ids {
                for timestamp in begin..=end {
                    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(id).expect("hmac key");
                    mac.update(&(timestamp as u64).to_be_bytes());
                    let hash: [u8; 16] = mac.finalize().into_bytes().into();
                    map.insert(hash, (*user, timestamp));
                }
            }
            update_time.insert(*user, now);
        }
        legacy.map = map;
        legacy.update_time = update_time;
    }
}

/// A request a server read.
pub struct ServerRequest {
    pub user: usize,
    pub command: u8,
    pub destination: Option<Socksaddr>,
    /// The request's body keys, the response keys of the client's side
    /// and whether the header was a legacy one.
    pub keys: BodyKeys,
    pub response_header: u8,
    pub legacy: bool,
    pub writer: BodyWriter,
    pub reader: BodyReader,
}

/// Bytes after the auth of a legacy request, read and decrypted on
/// demand.
struct LegacyHeader<'a, S> {
    conn: &'a mut S,
    raw: Vec<u8>,
    cipher: protocol::CfbDecryptor,
}

impl<S: AsyncRead + Unpin> LegacyHeader<'_, S> {
    async fn read(&mut self, length: usize) -> io::Result<Vec<u8>> {
        while self.raw.len() < length {
            let mut chunk = [0u8; 4096];
            let read = self.conn.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
            }
            self.raw.extend_from_slice(&chunk[..read]);
        }
        let mut data: Vec<u8> = self.raw.drain(..length).collect();
        self.cipher.decrypt(&mut data);
        Ok(data)
    }
}

/// sing-vmess `ErrBadHeader` extended with a reason.
fn bad_header(reason: &str) -> io::Error {
    invalid(format!("bad header: {reason}"))
}

/// The fields of a request header after its fixed 38 bytes are checked.
struct Fixed {
    request_nonce: [u8; 16],
    request_key: [u8; 16],
    response_header: u8,
    option: u8,
    padding_len: usize,
    security: u8,
    command: u8,
}

fn parse_fixed(header: &[u8]) -> io::Result<Fixed> {
    let version = header[0];
    if version != VERSION {
        return Err(invalid(format!("bad version: {version}")));
    }
    let security = header[35] & 0x0f;
    if !matches!(security, SECURITY_NONE | SECURITY_LEGACY | SECURITY_AES_128_GCM | SECURITY_CHACHA20_POLY1305) {
        return Err(invalid(format!("unknown security type: {security}")));
    }
    let command = header[37];
    if !matches!(command, COMMAND_TCP | COMMAND_UDP | COMMAND_MUX) {
        return Err(invalid(format!("unknown command: {command}")));
    }
    let option = header[34];
    if command == COMMAND_UDP && option == 0 {
        return Err(invalid("bad packet connection"));
    }
    Ok(Fixed {
        request_nonce: header[1..17].try_into().unwrap(),
        request_key: header[17..33].try_into().unwrap(),
        response_header: header[33],
        option,
        padding_len: (header[35] >> 4) as usize,
        security,
        command,
    })
}

/// The address length a VMess address with `head` (port and family, plus
/// the domain length byte) needs in all.
fn address_total(head: &[u8]) -> io::Result<Option<usize>> {
    match head.get(2) {
        None => Ok(None),
        Some(0x01) => Ok(Some(7)),
        Some(0x03) => Ok(Some(19)),
        Some(0x02) => Ok(head.get(3).map(|length| 4 + *length as usize)),
        Some(family) => Err(invalid(format!("unknown address family: {family}"))),
    }
}

/// The largest first read of a request (sing `buf.New`).
const FIRST_READ: usize = 32 * 1024;

impl ServerUsers {
    /// Reads and checks a request (sing-vmess `Service.NewConnection`).
    pub async fn read_request<S: AsyncRead + Unpin>(&self, conn: &mut S) -> io::Result<ServerRequest> {
        const AEAD_MIN_HEADER_LEN: usize = 16 + 2 + CIPHER_OVERHEAD + 8 + CIPHER_OVERHEAD + 42;
        let min_header_len = if self.has_legacy() { 16 + 38 } else { AEAD_MIN_HEADER_LEN };
        let mut buffer = vec![0u8; FIRST_READ];
        let read = conn.read(&mut buffer).await?;
        if read == 0 {
            return Err(crate::framed::eof());
        }
        if read < min_header_len {
            return Err(invalid("bad header"));
        }
        buffer.truncate(read);
        let auth_id: [u8; 16] = buffer[..16].try_into().unwrap();
        let mut found = None;
        for (index, user) in self.users.iter().enumerate() {
            let Some((decoded, timestamp)) = protocol::open_auth_id(&user.cipher, &auth_id) else { continue };
            if ((timestamp as f64).abs() - (self.now)() as f64).abs() > 120.0 {
                return Err(invalid("bad timestamp"));
            }
            if !self.replay.check(&decoded) {
                return Err(invalid("replayed request"));
            }
            found = Some((index, None));
            break;
        }
        if found.is_none() {
            if let Some((user, timestamp)) = self.legacy.lock().unwrap().map.get(&auth_id) {
                found = Some((*user, Some(*timestamp)));
            }
        }
        let Some((user, legacy_time)) = found else { return Err(invalid("bad request")) };
        let cmd_key = self.users[user].cmd_key;
        let (fixed, destination, leftover) = match legacy_time {
            Some(timestamp) => {
                let mut header = LegacyHeader {
                    conn,
                    raw: buffer.split_off(16),
                    cipher: protocol::cfb_decryptor(&cmd_key, &protocol::legacy_time_hash(timestamp as u64)),
                };
                let head = header.read(38).await.map_err(|_| bad_header("short buffer"))?;
                let fixed = parse_fixed(&head)?;
                let destination = if fixed.command != COMMAND_MUX {
                    let mut address = header.read(3).await?;
                    if address[2] == 0x02 {
                        address.extend(header.read(1).await?);
                    }
                    let total = address_total(&address)?.expect("address head");
                    address.extend(header.read(total - address.len()).await?);
                    Some(parse_address(&address)?.0)
                } else {
                    None
                };
                if fixed.padding_len > 0 {
                    header.read(fixed.padding_len).await.map_err(|_| bad_header("bad padding"))?;
                }
                header.read(4).await?;
                (fixed, destination, header.raw)
            }
            None => {
                if buffer.len() < AEAD_MIN_HEADER_LEN {
                    return Err(invalid("bad header"));
                }
                let length = protocol::open_aead_length(&cmd_key, &buffer[..42])?;
                let total = 42 + length + CIPHER_OVERHEAD;
                if buffer.len() < total {
                    let start = buffer.len();
                    buffer.resize(total, 0);
                    conn.read_exact(&mut buffer[start..]).await?;
                }
                let header = protocol::open_aead_header(&cmd_key, &buffer, length)?;
                if header.len() <= 38 {
                    return Err(bad_header("short buffer"));
                }
                let fixed = parse_fixed(&header)?;
                let mut position = 38;
                let destination = if fixed.command != COMMAND_MUX {
                    let (address, used) = parse_address(&header[position..])?;
                    position += used;
                    Some(address)
                } else {
                    None
                };
                if header.len() < position + fixed.padding_len {
                    return Err(bad_header("bad padding"));
                }
                position += fixed.padding_len;
                if header.len() < position + 4 {
                    return Err(crate::framed::eof());
                }
                (fixed, destination, buffer.split_off(total))
            }
        };
        let legacy = legacy_time.is_some();
        let read_keys = BodyKeys {
            security: fixed.security,
            option: fixed.option,
            request_key: fixed.request_key,
            request_nonce: fixed.request_nonce,
            key: fixed.request_key,
            nonce: fixed.request_nonce,
        };
        let read_cfb = (fixed.security == SECURITY_LEGACY)
            .then(|| protocol::cfb_decryptor(&fixed.request_key, &fixed.request_nonce));
        let reader = BodyReader::new(&read_keys, read_cfb, leftover);
        let (response_key, response_nonce) = protocol::response_keys(legacy, &fixed.request_key, &fixed.request_nonce);
        let write_keys = BodyKeys { key: response_key, nonce: response_nonce, ..read_keys };
        let fresh = || protocol::cfb_encryptor(&response_key, &response_nonce);
        let writer = if legacy {
            // The response header under the response key's CFB stream,
            // which a chunked legacy body continues.
            let mut header_cipher = fresh();
            let mut prefix = vec![fixed.response_header, fixed.option, 0, 0];
            header_cipher.encrypt(&mut prefix);
            let cfb = match fixed.security {
                SECURITY_LEGACY if fixed.option & OPTION_CHUNK_STREAM != 0 => Some(header_cipher),
                SECURITY_LEGACY => Some(fresh()),
                _ => None,
            };
            BodyWriter::new(prefix, &write_keys, cfb)
        } else {
            let prefix =
                protocol::seal_aead_response(&response_key, &response_nonce, fixed.response_header, fixed.option);
            BodyWriter::new(prefix, &write_keys, (fixed.security == SECURITY_LEGACY).then(fresh))
        };
        Ok(ServerRequest {
            user,
            command: fixed.command,
            destination,
            keys: read_keys,
            response_header: fixed.response_header,
            legacy,
            writer,
            reader,
        })
    }
}
