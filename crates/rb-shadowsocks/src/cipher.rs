//! The ciphers shadowsocks uses: the AEADs of the AEAD and 2022 methods,
//! the block cipher of the 2022 identity and UDP headers, and the legacy
//! stream ciphers (sing-shadowsocks2 `shadowstream`).

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher as _};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use md5::{Digest, Md5};

use std::io;

type Aes192Gcm = AesGcm<Aes192, aes_gcm::aead::consts::U12>;

/// Size of the authentication tag every AEAD here appends.
pub const TAG_SIZE: usize = 16;

/// The AEAD algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadKind {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl AeadKind {
    pub fn key_size(self) -> usize {
        match self {
            AeadKind::Aes128Gcm => 16,
            AeadKind::Aes192Gcm => 24,
            AeadKind::Aes256Gcm | AeadKind::ChaCha20Poly1305 | AeadKind::XChaCha20Poly1305 => 32,
        }
    }

    pub fn nonce_size(self) -> usize {
        match self {
            AeadKind::XChaCha20Poly1305 => 24,
            _ => 12,
        }
    }
}

/// An AEAD with its key.
#[derive(Clone)]
pub enum Aead {
    Aes128Gcm(Box<Aes128Gcm>),
    Aes192Gcm(Box<Aes192Gcm>),
    Aes256Gcm(Box<Aes256Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
    XChaCha20Poly1305(Box<XChaCha20Poly1305>),
}

macro_rules! each_aead {
    ($self:expr, $cipher:ident => $body:expr) => {
        match $self {
            Aead::Aes128Gcm($cipher) => $body,
            Aead::Aes192Gcm($cipher) => $body,
            Aead::Aes256Gcm($cipher) => $body,
            Aead::ChaCha20Poly1305($cipher) => $body,
            Aead::XChaCha20Poly1305($cipher) => $body,
        }
    };
}

impl Aead {
    /// `key` must be `kind.key_size()` long.
    pub fn new(kind: AeadKind, key: &[u8]) -> Aead {
        match kind {
            AeadKind::Aes128Gcm => Aead::Aes128Gcm(Box::new(Aes128Gcm::new_from_slice(key).expect("key size"))),
            AeadKind::Aes192Gcm => Aead::Aes192Gcm(Box::new(Aes192Gcm::new_from_slice(key).expect("key size"))),
            AeadKind::Aes256Gcm => Aead::Aes256Gcm(Box::new(Aes256Gcm::new_from_slice(key).expect("key size"))),
            AeadKind::ChaCha20Poly1305 => {
                Aead::ChaCha20Poly1305(Box::new(ChaCha20Poly1305::new_from_slice(key).expect("key size")))
            }
            AeadKind::XChaCha20Poly1305 => {
                Aead::XChaCha20Poly1305(Box::new(XChaCha20Poly1305::new_from_slice(key).expect("key size")))
            }
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            Aead::XChaCha20Poly1305(_) => 24,
            _ => 12,
        }
    }

    /// Encrypts `buffer` in place and appends the tag.
    pub fn seal(&self, nonce: &[u8], buffer: &mut Vec<u8>) {
        let tag = each_aead!(self, cipher => cipher
            .encrypt_in_place_detached(nonce.into(), &[], buffer)
            .expect("plaintext size"));
        buffer.extend_from_slice(&tag);
    }

    /// Appends `plaintext` sealed (with its tag) to `out`.
    pub fn seal_to(&self, nonce: &[u8], plaintext: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(plaintext);
        let tag = each_aead!(self, cipher => cipher
            .encrypt_in_place_detached(nonce.into(), &[], &mut out[start..])
            .expect("plaintext size"));
        out.extend_from_slice(&tag);
    }

    /// Decrypts `buffer` (ciphertext and tag) in place; on success the
    /// tag is cut off.
    pub fn open(&self, nonce: &[u8], buffer: &mut Vec<u8>) -> io::Result<()> {
        let length = self.open_slice(nonce, buffer)?;
        buffer.truncate(length);
        Ok(())
    }

    /// Decrypts `buffer` (ciphertext and tag) in place and returns the
    /// plaintext length.
    pub fn open_slice(&self, nonce: &[u8], buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.len() < TAG_SIZE {
            return Err(crate::authentication_failed());
        }
        let length = buffer.len() - TAG_SIZE;
        let (data, tag) = buffer.split_at_mut(length);
        let tag: &[u8] = tag;
        each_aead!(self, cipher => cipher.decrypt_in_place_detached(nonce.into(), &[], data, tag.into()))
            .map_err(|_| crate::authentication_failed())?;
        Ok(length)
    }
}

/// The AES block cipher of the 2022 identity headers and UDP packet
/// headers, keyed with a 16 or 32 byte key.
#[derive(Clone)]
pub enum Block {
    Aes128(Box<Aes128>),
    Aes256(Box<Aes256>),
}

impl Block {
    pub fn new(key: &[u8]) -> Block {
        match key.len() {
            16 => Block::Aes128(Box::new(Aes128::new_from_slice(key).expect("key size"))),
            32 => Block::Aes256(Box::new(Aes256::new_from_slice(key).expect("key size"))),
            other => panic!("AES block key of {other} bytes"),
        }
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        let block = aes::Block::from_mut_slice(&mut block[..16]);
        match self {
            Block::Aes128(cipher) => cipher.encrypt_block(block),
            Block::Aes256(cipher) => cipher.encrypt_block(block),
        }
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        let block = aes::Block::from_mut_slice(&mut block[..16]);
        match self {
            Block::Aes128(cipher) => cipher.decrypt_block(block),
            Block::Aes256(cipher) => cipher.decrypt_block(block),
        }
    }
}

/// The legacy stream ciphers (outbound only, as in sing-box).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Rc4Md5,
    ChaCha20Ietf,
    XChaCha20,
}

impl StreamKind {
    pub fn key_size(self) -> usize {
        match self {
            StreamKind::Aes128Ctr | StreamKind::Aes128Cfb | StreamKind::Rc4Md5 => 16,
            StreamKind::Aes192Ctr | StreamKind::Aes192Cfb => 24,
            StreamKind::Aes256Ctr | StreamKind::Aes256Cfb | StreamKind::ChaCha20Ietf | StreamKind::XChaCha20 => 32,
        }
    }

    pub fn salt_size(self) -> usize {
        match self {
            StreamKind::ChaCha20Ietf => 12,
            StreamKind::XChaCha20 => 24,
            _ => 16,
        }
    }
}

/// RC4 (Go `crypto/rc4`), for `rc4-md5`.
#[derive(Clone)]
pub struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Rc4 {
        let mut state = [0u8; 256];
        for (index, value) in state.iter_mut().enumerate() {
            *value = index as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }
        Rc4 { state, i: 0, j: 0 }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
            let index = self.state[self.i as usize].wrapping_add(self.state[self.j as usize]);
            *byte ^= self.state[index as usize];
        }
    }
}

type Ctr128<C> = ctr::Ctr128BE<C>;

/// One direction of a legacy stream cipher, keyed with the key and salt.
pub enum Stream {
    Aes128Ctr(Box<Ctr128<Aes128>>),
    Aes192Ctr(Box<Ctr128<Aes192>>),
    Aes256Ctr(Box<Ctr128<Aes256>>),
    Aes128CfbEncrypt(Box<cfb_mode::BufEncryptor<Aes128>>),
    Aes192CfbEncrypt(Box<cfb_mode::BufEncryptor<Aes192>>),
    Aes256CfbEncrypt(Box<cfb_mode::BufEncryptor<Aes256>>),
    Aes128CfbDecrypt(Box<cfb_mode::BufDecryptor<Aes128>>),
    Aes192CfbDecrypt(Box<cfb_mode::BufDecryptor<Aes192>>),
    Aes256CfbDecrypt(Box<cfb_mode::BufDecryptor<Aes256>>),
    Rc4(Box<Rc4>),
    ChaCha20(Box<chacha20::ChaCha20>),
    XChaCha20(Box<chacha20::XChaCha20>),
}

impl Stream {
    /// The stream for `encrypt`ing or decrypting with `key` and `salt`
    /// (only CFB differs between the two).
    pub fn new(kind: StreamKind, key: &[u8], salt: &[u8], encrypt: bool) -> Stream {
        macro_rules! ctr {
            ($variant:ident, $cipher:ty) => {
                Stream::$variant(Box::new(Ctr128::<$cipher>::new_from_slices(key, salt).expect("key size")))
            };
        }
        macro_rules! cfb {
            ($encrypt:ident, $decrypt:ident, $cipher:ty) => {
                if encrypt {
                    Stream::$encrypt(Box::new(
                        cfb_mode::BufEncryptor::<$cipher>::new_from_slices(key, salt).expect("key size"),
                    ))
                } else {
                    Stream::$decrypt(Box::new(
                        cfb_mode::BufDecryptor::<$cipher>::new_from_slices(key, salt).expect("key size"),
                    ))
                }
            };
        }
        match kind {
            StreamKind::Aes128Ctr => ctr!(Aes128Ctr, Aes128),
            StreamKind::Aes192Ctr => ctr!(Aes192Ctr, Aes192),
            StreamKind::Aes256Ctr => ctr!(Aes256Ctr, Aes256),
            StreamKind::Aes128Cfb => cfb!(Aes128CfbEncrypt, Aes128CfbDecrypt, Aes128),
            StreamKind::Aes192Cfb => cfb!(Aes192CfbEncrypt, Aes192CfbDecrypt, Aes192),
            StreamKind::Aes256Cfb => cfb!(Aes256CfbEncrypt, Aes256CfbDecrypt, Aes256),
            StreamKind::Rc4Md5 => {
                let mut hash = Md5::new();
                hash.update(key);
                hash.update(salt);
                Stream::Rc4(Box::new(Rc4::new(&hash.finalize())))
            }
            StreamKind::ChaCha20Ietf => {
                Stream::ChaCha20(Box::new(chacha20::ChaCha20::new_from_slices(key, salt).expect("key size")))
            }
            StreamKind::XChaCha20 => {
                Stream::XChaCha20(Box::new(chacha20::XChaCha20::new_from_slices(key, salt).expect("key size")))
            }
        }
    }

    /// XORs the key stream into `data`.
    pub fn apply(&mut self, data: &mut [u8]) {
        match self {
            Stream::Aes128Ctr(cipher) => cipher.apply_keystream(data),
            Stream::Aes192Ctr(cipher) => cipher.apply_keystream(data),
            Stream::Aes256Ctr(cipher) => cipher.apply_keystream(data),
            Stream::Aes128CfbEncrypt(cipher) => cipher.encrypt(data),
            Stream::Aes192CfbEncrypt(cipher) => cipher.encrypt(data),
            Stream::Aes256CfbEncrypt(cipher) => cipher.encrypt(data),
            Stream::Aes128CfbDecrypt(cipher) => cipher.decrypt(data),
            Stream::Aes192CfbDecrypt(cipher) => cipher.decrypt(data),
            Stream::Aes256CfbDecrypt(cipher) => cipher.decrypt(data),
            Stream::Rc4(cipher) => cipher.apply(data),
            Stream::ChaCha20(cipher) => cipher.apply_keystream(data),
            Stream::XChaCha20(cipher) => cipher.apply_keystream(data),
        }
    }
}

/// Increments a little-endian nonce (sing `increaseNonce`).
pub fn increase_nonce(nonce: &mut [u8]) {
    for byte in nonce {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

/// OpenSSL `EVP_BytesToKey` with MD5, the key of the AEAD and stream
/// methods from a password (sing-shadowsocks `Key`, `legacykey.Key`).
pub fn evp_bytes_to_key(password: &[u8], key_size: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_size + 16);
    let mut previous: Vec<u8> = Vec::new();
    while key.len() < key_size {
        let mut hash = Md5::new();
        hash.update(&previous);
        hash.update(password);
        let digest = hash.finalize();
        key.extend_from_slice(&digest);
        previous = digest.to_vec();
    }
    key.truncate(key_size);
    key
}

/// The AEAD method's session subkey: HKDF-SHA1 with the salt and
/// `ss-subkey` (sing-shadowsocks `Kdf`).
pub fn aead_subkey(key: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut subkey = vec![0u8; key.len()];
    hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), key).expand(b"ss-subkey", &mut subkey).expect("subkey size");
    subkey
}

/// The 2022 session subkey (sing-shadowsocks `SessionKey`).
pub fn session_key(psk: &[u8], salt: &[u8], key_size: usize) -> Vec<u8> {
    derive_key("shadowsocks 2022 session subkey", &[psk, salt].concat(), key_size)
}

/// The 2022 identity subkey of the extended identity headers.
pub fn identity_subkey(psk: &[u8], salt: &[u8], key_size: usize) -> Vec<u8> {
    let mut material = vec![0u8; key_size * 2];
    let psk_len = psk.len().min(key_size);
    material[..psk_len].copy_from_slice(&psk[..psk_len]);
    let salt_len = salt.len().min(key_size);
    material[key_size..key_size + salt_len].copy_from_slice(&salt[..salt_len]);
    derive_key("shadowsocks 2022 identity subkey", &material, key_size)
}

/// BLAKE3 `derive_key` of any length (Go `blake3.DeriveKey`).
pub fn derive_key(context: &str, material: &[u8], size: usize) -> Vec<u8> {
    let mut out = vec![0u8; size];
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(material);
    hasher.finalize_xof().fill(&mut out);
    out
}

/// The first 16 bytes of the BLAKE3 hash of a PSK: its identity in the
/// extended identity headers (`blake3.Sum512(key)[:16]`).
pub fn psk_hash(psk: &[u8]) -> [u8; 16] {
    let hash = blake3::hash(psk);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash.as_bytes()[..16]);
    out
}

/// The 2022 key from a longer PSK (sing-shadowsocks `Key`: SHA-256, cut).
pub fn sha256_key(key: &[u8], size: usize) -> Vec<u8> {
    let hash = sha2::Sha256::digest(key);
    hash[..size].to_vec()
}
