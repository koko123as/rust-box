//! The VMess handshake (sing-vmess `protocol.go`, `kdf.go`, the header
//! parts of `client.go` and `service.go`): user keys, the AEAD KDF, the
//! auth id, the request header (AEAD and legacy MD5/AES-128-CFB), and the
//! response header of both kinds.

use std::io;

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes128Gcm;
use hmac::{Hmac, Mac};
use md5::{Digest as _, Md5};
use rb_adapter::Socksaddr;
use sha2::Sha256;

use crate::vless::protocol::{address_len, write_address};

pub const VERSION: u8 = 1;

pub const SECURITY_LEGACY: u8 = 1;
pub const SECURITY_AUTO: u8 = 2;
pub const SECURITY_AES_128_GCM: u8 = 3;
pub const SECURITY_CHACHA20_POLY1305: u8 = 4;
pub const SECURITY_NONE: u8 = 5;
pub const SECURITY_ZERO: u8 = 6;

pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 2;
pub const COMMAND_MUX: u8 = 3;

pub const OPTION_CHUNK_STREAM: u8 = 1;
pub const OPTION_CONNECTION_REUSE: u8 = 2;
pub const OPTION_CHUNK_MASKING: u8 = 4;
pub const OPTION_GLOBAL_PADDING: u8 = 8;
pub const OPTION_AUTHENTICATED_LENGTH: u8 = 16;

pub const CIPHER_OVERHEAD: usize = 16;
/// Plaintext per chunk the writers cut (sing-vmess `WriteChunkSize`).
pub const WRITE_CHUNK_SIZE: usize = 15000;
pub const MAX_PADDING_SIZE: u16 = 64;
/// How far a legacy (alterId) request's time may be from the server's.
pub const CACHE_DURATION_SECONDS: i64 = 120;

const KDF_SALT_VMESS_AEAD_KDF: &str = "VMess AEAD KDF";
pub const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &str = "AES Auth ID Encryption";
pub const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &str = "AEAD Resp Header Len Key";
pub const KDF_SALT_AEAD_RESP_HEADER_LEN_IV: &str = "AEAD Resp Header Len IV";
pub const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &str = "AEAD Resp Header Key";
pub const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &str = "AEAD Resp Header IV";
pub const KDF_SALT_HEADER_PAYLOAD_KEY: &str = "VMess Header AEAD Key";
pub const KDF_SALT_HEADER_PAYLOAD_IV: &str = "VMess Header AEAD Nonce";
pub const KDF_SALT_HEADER_LENGTH_KEY: &str = "VMess Header AEAD Key_Length";
pub const KDF_SALT_HEADER_LENGTH_IV: &str = "VMess Header AEAD Nonce_Length";

/// The fixed part of a request header: version, nonce, key, response
/// header, option, padding and security, a reserved byte and the command.
pub const HEADER_FIXED_LEN: usize = 38;
/// sing-vmess's smallest AEAD request it reads.
pub const AEAD_MIN_HEADER_LEN: usize = 16 + 2 + CIPHER_OVERHEAD + 8 + CIPHER_OVERHEAD + 42;
/// The smallest request read when some user has an alterId.
pub const LEGACY_MIN_HEADER_LEN: usize = 16 + 38;

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Go's `cipher: message authentication failed` (AES-GCM `Open`).
pub(crate) fn gcm_auth_failed() -> io::Error {
    invalid("cipher: message authentication failed")
}

pub fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

pub fn sha256_16(data: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// The command key of a user (sing-vmess `Key`).
pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hash = Md5::new();
    hash.update(uuid);
    hash.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hash.finalize().into()
}

/// The next alter id of a user id (sing-vmess `AlterId`).
pub fn alter_id(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hash = Md5::new();
    hash.update(uuid);
    hash.update(b"16167dc8-16b6-4e6d-b8bb-65dd68113a81");
    loop {
        let next: [u8; 16] = hash.clone().finalize().into();
        if &next != uuid {
            return next;
        }
        hash.update(b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2");
    }
}

/// The ChaCha20-Poly1305 key of a 16-byte key (sing-vmess
/// `GenerateChacha20Poly1305Key`).
pub fn chacha_key(key: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let first = md5(key);
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&md5(&first));
    out
}

/// FNV-1a 32 (Go `hash/fnv.New32a`).
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// One level of the KDF's nested HMAC: level 0 is SHA-256, level `n` is
/// HMAC over level `n - 1` keyed with `keys[n - 1]` (Go's `hmac.New` with
/// the parent's constructor; the block size is SHA-256's at every level).
fn nested_hash(keys: &[&[u8]], level: usize, message: &[u8]) -> [u8; 32] {
    if level == 0 {
        return Sha256::digest(message).into();
    }
    const BLOCK: usize = 64;
    let raw_key = keys[level - 1];
    let mut key = [0u8; BLOCK];
    if raw_key.len() > BLOCK {
        key[..32].copy_from_slice(&nested_hash(keys, level - 1, raw_key));
    } else {
        key[..raw_key.len()].copy_from_slice(raw_key);
    }
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    inner.extend(key.iter().map(|byte| byte ^ 0x36));
    inner.extend_from_slice(message);
    let inner_hash = nested_hash(keys, level - 1, &inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend(key.iter().map(|byte| byte ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    nested_hash(keys, level - 1, &outer)
}

/// sing-vmess `KDF(key, salt, path...)`.
pub fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = vec![KDF_SALT_VMESS_AEAD_KDF.as_bytes(), salt.as_bytes()];
    keys.extend_from_slice(path);
    nested_hash(&keys, keys.len(), key)
}

pub(crate) fn kdf16(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&kdf(key, salt, path)[..16]);
    out
}

pub(crate) fn kdf12(key: &[u8], salt: &str, path: &[&[u8]]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.copy_from_slice(&kdf(key, salt, path)[..12]);
    out
}

/// The AES block that encrypts a user's auth ids.
pub fn auth_id_cipher(cmd_key: &[u8; 16]) -> Aes128 {
    Aes128::new_from_slice(&kdf16(cmd_key, KDF_SALT_AUTH_ID_ENCRYPTION_KEY, &[])).expect("key size")
}

/// sing-vmess `AuthID`: the time, 4 random bytes and their CRC32,
/// AES-encrypted.
pub fn auth_id(cmd_key: &[u8; 16], timestamp: i64, random: [u8; 4]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&timestamp.to_be_bytes());
    block[8..12].copy_from_slice(&random);
    let checksum = crc32fast::hash(&block[..12]);
    block[12..].copy_from_slice(&checksum.to_be_bytes());
    let mut block = aes::Block::from(block);
    auth_id_cipher(cmd_key).encrypt_block(&mut block);
    block.into()
}

/// Decrypts an auth id with a user's cipher and checks it (sing-vmess
/// `Service.NewConnection`): the timestamp when its CRC32 matches.
pub fn open_auth_id(cipher: &Aes128, auth_id: &[u8; 16]) -> Option<([u8; 16], i64)> {
    let mut block = aes::Block::from(*auth_id);
    cipher.decrypt_block(&mut block);
    let decoded: [u8; 16] = block.into();
    let checksum = u32::from_be_bytes(decoded[12..].try_into().unwrap());
    if crc32fast::hash(&decoded[..12]) != checksum {
        return None;
    }
    Some((decoded, i64::from_be_bytes(decoded[..8].try_into().unwrap())))
}

fn gcm(key: &[u8; 16]) -> Aes128Gcm {
    Aes128Gcm::new_from_slice(key).expect("key size")
}

fn gcm_seal(key: &[u8; 16], nonce: &[u8; 12], data: &[u8], aad: &[u8]) -> Vec<u8> {
    gcm(key).encrypt(nonce.into(), Payload { msg: data, aad }).expect("seal")
}

fn gcm_open(key: &[u8; 16], nonce: &[u8; 12], data: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    gcm(key).decrypt(nonce.into(), Payload { msg: data, aad }).map_err(|_| gcm_auth_failed())
}

/// The time hash of a legacy request: the IV of its header (MD5 of the
/// timestamp four times).
pub fn legacy_time_hash(timestamp: u64) -> [u8; 16] {
    let mut hash = Md5::new();
    for _ in 0..4 {
        hash.update(timestamp.to_be_bytes());
    }
    hash.finalize().into()
}

/// The auth of a legacy request: HMAC-MD5 of the timestamp keyed with the
/// alter id.
pub fn legacy_auth(alter_id: &[u8; 16], timestamp: u64) -> [u8; 16] {
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(alter_id).expect("hmac key");
    mac.update(&timestamp.to_be_bytes());
    mac.finalize().into_bytes().into()
}

pub type CfbEncryptor = cfb_mode::BufEncryptor<Aes128>;
pub type CfbDecryptor = cfb_mode::BufDecryptor<Aes128>;

pub fn cfb_encryptor(key: &[u8; 16], iv: &[u8; 16]) -> CfbEncryptor {
    CfbEncryptor::new_from_slices(key, iv).expect("key size")
}

pub fn cfb_decryptor(key: &[u8; 16], iv: &[u8; 16]) -> CfbDecryptor {
    CfbDecryptor::new_from_slices(key, iv).expect("key size")
}

/// A request header (the plaintext the client encrypts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub request_nonce: [u8; 16],
    pub request_key: [u8; 16],
    pub response_header: u8,
    pub option: u8,
    pub security: u8,
    pub command: u8,
    /// Absent for the mux command.
    pub destination: Option<Socksaddr>,
    /// The padding bytes (fewer than 16).
    pub padding: Vec<u8>,
}

impl RequestHeader {
    /// The header's length, as the AEAD length block carries it.
    pub fn len(&self) -> usize {
        HEADER_FIXED_LEN + self.destination.as_ref().map_or(0, address_len) + self.padding.len() + 4
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// sing-vmess `encodeHeader`: the fields and their FNV-1a checksum.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut header = Vec::with_capacity(self.len());
        header.push(VERSION);
        header.extend_from_slice(&self.request_nonce);
        header.extend_from_slice(&self.request_key);
        header.push(self.response_header);
        header.push(self.option);
        header.push(((self.padding.len() as u8) << 4) | self.security);
        header.push(0);
        header.push(self.command);
        if self.command != COMMAND_MUX {
            let destination = self.destination.as_ref().ok_or_else(|| invalid("missing destination"))?;
            write_address(&mut header, destination)?;
        }
        header.extend_from_slice(&self.padding);
        let checksum = fnv1a32(&header);
        header.extend_from_slice(&checksum.to_be_bytes());
        Ok(header)
    }
}

/// An AEAD request: the auth id, the sealed header length, the connection
/// nonce and the sealed header (sing-vmess `writeHandshake` without an
/// alterId).
pub fn seal_aead_request(cmd_key: &[u8; 16], auth_id: &[u8; 16], connection_nonce: &[u8; 8], header: &[u8]) -> Vec<u8> {
    let path: [&[u8]; 2] = [auth_id, connection_nonce];
    let mut request = Vec::with_capacity(16 + 18 + 8 + header.len() + CIPHER_OVERHEAD);
    request.extend_from_slice(auth_id);
    let length_key = kdf16(cmd_key, KDF_SALT_HEADER_LENGTH_KEY, &path);
    let length_nonce = kdf12(cmd_key, KDF_SALT_HEADER_LENGTH_IV, &path);
    request.extend_from_slice(&gcm_seal(&length_key, &length_nonce, &(header.len() as u16).to_be_bytes(), auth_id));
    request.extend_from_slice(connection_nonce);
    let header_key = kdf16(cmd_key, KDF_SALT_HEADER_PAYLOAD_KEY, &path);
    let header_nonce = kdf12(cmd_key, KDF_SALT_HEADER_PAYLOAD_IV, &path);
    request.extend_from_slice(&gcm_seal(&header_key, &header_nonce, header, auth_id));
    request
}

/// Opens the length block of an AEAD request (`request` holds at least
/// 42 bytes): the header length.
pub fn open_aead_length(cmd_key: &[u8; 16], request: &[u8]) -> io::Result<usize> {
    let (auth_id, connection_nonce) = (&request[..16], &request[34..42]);
    let path: [&[u8]; 2] = [auth_id, connection_nonce];
    let key = kdf16(cmd_key, KDF_SALT_HEADER_LENGTH_KEY, &path);
    let nonce = kdf12(cmd_key, KDF_SALT_HEADER_LENGTH_IV, &path);
    let length = gcm_open(&key, &nonce, &request[16..34], auth_id)?;
    Ok(u16::from_be_bytes([length[0], length[1]]) as usize)
}

/// Opens the header of an AEAD request (`request` holds the whole request
/// of `header_len`): the header plaintext.
pub fn open_aead_header(cmd_key: &[u8; 16], request: &[u8], header_len: usize) -> io::Result<Vec<u8>> {
    let (auth_id, connection_nonce) = (&request[..16], &request[34..42]);
    let path: [&[u8]; 2] = [auth_id, connection_nonce];
    let key = kdf16(cmd_key, KDF_SALT_HEADER_PAYLOAD_KEY, &path);
    let nonce = kdf12(cmd_key, KDF_SALT_HEADER_PAYLOAD_IV, &path);
    gcm_open(&key, &nonce, &request[42..42 + header_len + CIPHER_OVERHEAD], auth_id)
}

/// A legacy request: the HMAC-MD5 auth of the alter id, then the header
/// under AES-128-CFB with the command key and the time hash.
pub fn seal_legacy_request(cmd_key: &[u8; 16], alter_key: &[u8; 16], timestamp: u64, header: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(16 + header.len());
    request.extend_from_slice(&legacy_auth(alter_key, timestamp));
    let start = request.len();
    request.extend_from_slice(header);
    cfb_encryptor(cmd_key, &legacy_time_hash(timestamp)).encrypt(&mut request[start..]);
    request
}

/// The keys of the response direction: SHA-256 (AEAD) or MD5 (legacy) of
/// the request key and nonce, 16 bytes each.
pub fn response_keys(legacy: bool, request_key: &[u8; 16], request_nonce: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    if legacy {
        (md5(request_key), md5(request_nonce))
    } else {
        (sha256_16(request_key), sha256_16(request_nonce))
    }
}

/// The AEAD response header (sing-vmess `rawServerConn.writeResponse`):
/// the sealed length (4) and the sealed `[response header, option, 0, 0]`.
pub fn seal_aead_response(
    response_key: &[u8; 16],
    response_nonce: &[u8; 16],
    response_header: u8,
    option: u8,
) -> Vec<u8> {
    let mut response = gcm_seal(
        &kdf16(response_key, KDF_SALT_AEAD_RESP_HEADER_LEN_KEY, &[]),
        &kdf12(response_nonce, KDF_SALT_AEAD_RESP_HEADER_LEN_IV, &[]),
        &4u16.to_be_bytes(),
        &[],
    );
    response.extend_from_slice(&gcm_seal(
        &kdf16(response_key, KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY, &[]),
        &kdf12(response_nonce, KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV, &[]),
        &[response_header, option, 0, 0],
        &[],
    ));
    response
}

/// Opens the length block (18 bytes) of an AEAD response.
pub fn open_aead_response_length(response_key: &[u8; 16], response_nonce: &[u8; 16], data: &[u8]) -> io::Result<usize> {
    let length = gcm_open(
        &kdf16(response_key, KDF_SALT_AEAD_RESP_HEADER_LEN_KEY, &[]),
        &kdf12(response_nonce, KDF_SALT_AEAD_RESP_HEADER_LEN_IV, &[]),
        data,
        &[],
    )?;
    if length.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
    }
    Ok(u16::from_be_bytes([length[0], length[1]]) as usize)
}

/// Opens the header of an AEAD response (`length` + 16 bytes).
pub fn open_aead_response_header(
    response_key: &[u8; 16],
    response_nonce: &[u8; 16],
    data: &[u8],
) -> io::Result<Vec<u8>> {
    gcm_open(
        &kdf16(response_key, KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY, &[]),
        &kdf12(response_nonce, KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV, &[]),
        data,
        &[],
    )
}

/// The security byte of an outbound `security` option (sing-vmess
/// `NewClient`): `zero` is sent as none.
pub fn client_security(name: &str) -> Result<u8, String> {
    match name {
        "auto" => Ok(auto_security()),
        "none" | "zero" => Ok(SECURITY_NONE),
        "aes-128-cfb" => Ok(SECURITY_LEGACY),
        "aes-128-gcm" => Ok(SECURITY_AES_128_GCM),
        "chacha20-poly1305" => Ok(SECURITY_CHACHA20_POLY1305),
        other => Err(format!("vmess: unsupported security type: {other}")),
    }
}

/// sing-vmess `AutoSecurityType`: AES-128-GCM where Go has AES
/// instructions in its build (amd64, arm64, s390x), else
/// ChaCha20-Poly1305.
pub fn auto_security() -> u8 {
    if cfg!(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "s390x")) {
        SECURITY_AES_128_GCM
    } else {
        SECURITY_CHACHA20_POLY1305
    }
}

/// The request option of a client (sing-vmess `dialRaw`).
pub fn client_option(security: u8, command: u8, global_padding: bool, authenticated_length: bool) -> u8 {
    match security {
        SECURITY_NONE if command == COMMAND_UDP => OPTION_CHUNK_STREAM,
        SECURITY_NONE => 0,
        SECURITY_LEGACY => OPTION_CHUNK_STREAM,
        _ => {
            let mut option = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING;
            if global_padding {
                option |= OPTION_GLOBAL_PADDING;
            }
            if authenticated_length {
                option |= OPTION_AUTHENTICATED_LENGTH;
            }
            option
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::protocol::parse_uuid;

    #[test]
    fn keys() {
        assert_eq!(fnv1a32(b""), 0x811c9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c292c);
        let uuid = parse_uuid("bf000d23-0752-40b4-affe-68f7707a9661");
        assert_ne!(alter_id(&uuid), uuid);
        assert_eq!(chacha_key(b"0123456789abcdef")[16..], md5(&md5(b"0123456789abcdef")));
        // HMAC over SHA-256 at level 1 is plain HMAC-SHA256.
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"key").unwrap();
        mac.update(b"message");
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(nested_hash(&[b"key"], 1, b"message"), expected);
        // A key longer than the block is hashed with the parent first.
        let long = [7u8; 100];
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&long).unwrap();
        mac.update(b"m");
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(nested_hash(&[&long], 1, b"m"), expected);
    }

    #[test]
    fn aead_request_round_trip() {
        let key = cmd_key(&parse_uuid("bf000d23-0752-40b4-affe-68f7707a9661"));
        let header = RequestHeader {
            request_nonce: [1; 16],
            request_key: [2; 16],
            response_header: 3,
            option: OPTION_CHUNK_STREAM,
            security: SECURITY_AES_128_GCM,
            command: COMMAND_TCP,
            destination: Some(Socksaddr::from_host_port("example.com", 443)),
            padding: vec![9; 5],
        };
        let plain = header.encode().unwrap();
        assert_eq!(plain.len(), header.len());
        let id = auth_id(&key, 1_700_000_000, [4, 5, 6, 7]);
        let request = seal_aead_request(&key, &id, &[8; 8], &plain);
        assert_eq!(open_aead_length(&key, &request).unwrap(), plain.len());
        assert_eq!(open_aead_header(&key, &request, plain.len()).unwrap(), plain);
        let mut tampered = request.clone();
        tampered[50] ^= 1;
        assert_eq!(
            open_aead_header(&key, &tampered, plain.len()).unwrap_err().to_string(),
            "cipher: message authentication failed"
        );

        let (response_key, response_nonce) = response_keys(false, &[2; 16], &[1; 16]);
        let response = seal_aead_response(&response_key, &response_nonce, 3, 1);
        assert_eq!(response.len(), 18 + 20);
        assert_eq!(open_aead_response_length(&response_key, &response_nonce, &response[..18]).unwrap(), 4);
        assert_eq!(open_aead_response_header(&response_key, &response_nonce, &response[18..]).unwrap(), [3, 1, 0, 0]);
    }

    #[test]
    fn securities() {
        assert_eq!(client_security("zero"), Ok(SECURITY_NONE));
        assert_eq!(client_security("aes-128-cfb"), Ok(SECURITY_LEGACY));
        assert_eq!(client_security("rc4").unwrap_err(), "vmess: unsupported security type: rc4");
        assert_eq!(client_option(SECURITY_NONE, COMMAND_TCP, true, true), 0);
        assert_eq!(client_option(SECURITY_NONE, COMMAND_UDP, true, true), OPTION_CHUNK_STREAM);
        assert_eq!(client_option(SECURITY_LEGACY, COMMAND_MUX, true, true), OPTION_CHUNK_STREAM);
        assert_eq!(client_option(SECURITY_AES_128_GCM, COMMAND_TCP, true, true), 1 | 4 | 8 | 16);
    }
}
