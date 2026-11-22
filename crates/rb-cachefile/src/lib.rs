//! The cache file (sing-box `experimental/cachefile`): `cache.db`, a bbolt
//! file sing-box and rust-box can both open, holding the groups'
//! selections, the Clash mode, remote rule-sets, the FakeIP mappings, the
//! RDRC entries and the DNS cache.
//!
//! The layout is sing-box's: the buckets `selected`, `group_expand`,
//! `clash_mode`, `rule_set`, `rdrc2` and `dns_cache` (inside a bucket named
//! `"\0" + cache_id` when a cache ID is set, except `clash_mode`, which
//! keys the mode by cache ID instead), and `fakeip_address`,
//! `fakeip_domain4` and `fakeip_domain6` at the top level whatever the
//! cache ID.
//!
//! What sing-box saves from a goroutine (`*Async`) is queued here and
//! written by one background thread, which commits everything queued at
//! once; reads see queued values first, as sing-box's do.

mod binary;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use rb_bbolt::{Bucket, Db, Entry};
use rb_config::CacheFileOptions;
use rb_dns::{DnsCacheStore, FakeIpMetadata, FakeIpStorage, RdrcStore};
use tracing::{error, warn};

pub use binary::{fakeip_metadata_from_bytes, fakeip_metadata_to_bytes, SavedBinary};

const BUCKET_SELECTED: &[u8] = b"selected";
const BUCKET_EXPAND: &[u8] = b"group_expand";
const BUCKET_MODE: &[u8] = b"clash_mode";
const BUCKET_RULE_SET: &[u8] = b"rule_set";
const BUCKET_RDRC: &[u8] = b"rdrc2";
const BUCKET_DNS_CACHE: &[u8] = b"dns_cache";
const FAKEIP_PREFIX: &[u8] = b"fakeip_";
const BUCKET_FAKEIP: &[u8] = b"fakeip_address";
const BUCKET_FAKEIP_DOMAIN4: &[u8] = b"fakeip_domain4";
const BUCKET_FAKEIP_DOMAIN6: &[u8] = b"fakeip_domain6";
const KEY_METADATA: &[u8] = b"fakeip_metadata";
const CACHE_ID_DEFAULT: &[u8] = b"default";
/// The buckets the start keeps (`bucketNameList`); the others go.
const BUCKET_NAMES: [&[u8]; 6] =
    [BUCKET_SELECTED, BUCKET_EXPAND, BUCKET_MODE, BUCKET_RULE_SET, BUCKET_RDRC, BUCKET_DNS_CACHE];

/// `C.FakeIPMetadataSaveInterval`.
pub const FAKEIP_METADATA_SAVE_INTERVAL: Duration = Duration::from_secs(10);
/// The default `rdrc_timeout`.
pub const DEFAULT_RDRC_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 3600);
const OPEN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<rb_bbolt::Error> for Error {
    fn from(error: rb_bbolt::Error) -> Self {
        Error(error.to_string())
    }
}

type Result<T> = std::result::Result<T, Error>;

/// `(transport, question name, question type)` (`saveCacheKey`).
type CacheKey = (String, String, u16);

/// The record key of RDRC and DNS cache entries: the type (big endian),
/// then the name.
fn question_key(name: &str, query_type: u16) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + name.len());
    key.extend_from_slice(&query_type.to_be_bytes());
    key.extend_from_slice(name.as_bytes());
    key
}

fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// `M.AddrFromIP`: 4 or 16 bytes (an IPv4-mapped address stays IPv6 in
/// Go's `netip.AddrFromSlice`, then `Unmap` makes it IPv4).
fn ip_from_bytes(data: &[u8]) -> Option<IpAddr> {
    match data.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(data).ok()?)),
        16 => {
            let v6 = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?);
            Some(v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)))
        }
        _ => None,
    }
}

#[derive(Default)]
struct Pending {
    /// Queued FakeIP stores in order (`FakeIPStoreAsync`).
    fakeip: Vec<(IpAddr, String)>,
    save_domain: HashMap<IpAddr, String>,
    save_address4: HashMap<String, IpAddr>,
    save_address6: HashMap<String, IpAddr>,
    rdrc: HashMap<CacheKey, ()>,
    /// Queued DNS cache saves with a sequence number, so a save queued
    /// again while it was being written stays queued.
    dns: HashMap<CacheKey, (Vec<u8>, SystemTime, u64)>,
    dns_sequence: u64,
    /// The metadata to save and when (`FakeIPSaveMetadataAsync`, whose
    /// timer every call pushes back).
    metadata: Option<(FakeIpMetadata, Instant)>,
    next_cleanup: Option<Instant>,
    cleanup_interval: Duration,
    closed: bool,
}

impl Pending {
    fn has_writes(&self) -> bool {
        !self.fakeip.is_empty() || !self.rdrc.is_empty() || !self.dns.is_empty()
    }
}

struct Shared {
    path: PathBuf,
    cache_id: Option<Vec<u8>>,
    store_fakeip: bool,
    store_rdrc: bool,
    store_dns: bool,
    rdrc_timeout: Duration,
    optimistic_timeout: Mutex<Duration>,
    disable_expire: Mutex<bool>,
    db: Mutex<Option<Db>>,
    pending: Mutex<Pending>,
    wake: Condvar,
}

/// sing-box `cachefile.CacheFile`.
pub struct CacheFile {
    shared: Arc<Shared>,
    cache_id_text: String,
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for CacheFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheFile").field("path", &self.shared.path).finish_non_exhaustive()
    }
}

/// Opens the file the way `CacheFile.start` does: up to ten tries, waiting
/// out another holder's lock, removing a file that is not a valid bbolt
/// file or fails the check.
fn open_db(path: &Path) -> Result<Db> {
    let mut last = Error("open cache file".into());
    for _ in 0..10 {
        match Db::open(path, OPEN_TIMEOUT) {
            Ok(db) => return Ok(db),
            Err(rb_bbolt::Error::Timeout) => last = Error(rb_bbolt::Error::Timeout.to_string()),
            Err(error) => {
                let damaged = matches!(
                    error,
                    rb_bbolt::Error::Invalid
                        | rb_bbolt::Error::Checksum
                        | rb_bbolt::Error::VersionMismatch
                        | rb_bbolt::Error::Corrupted(_)
                );
                if matches!(error, rb_bbolt::Error::Corrupted(_)) {
                    error!("database corrupted: {error}: resetting");
                }
                last = Error(error.to_string());
                if damaged {
                    if std::fs::remove_file(path).is_err() && path.exists() {
                        return Err(last);
                    }
                    if matches!(error, rb_bbolt::Error::Corrupted(_)) {
                        continue;
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Err(last)
}

/// Removes what sing-box 1.14 does not keep: unknown top-level buckets
/// (except `fakeip_*`). Inside a cache ID bucket sing-box's cleanup deletes
/// a bucket named like the cache ID itself when it meets an unknown one,
/// which this follows.
fn clean(root: &mut Bucket) -> bool {
    let mut changed = false;
    for name in root.bucket_names() {
        if name.first() == Some(&0) {
            let Some(bucket) = root.bucket_mut(&name) else { continue };
            let unknown = bucket.bucket_names().iter().any(|child| !BUCKET_NAMES.contains(&child.as_slice()));
            if unknown && bucket.bucket(&name).is_some() {
                let _ = bucket.delete_bucket(&name);
                changed = true;
            }
        } else if !(BUCKET_NAMES.contains(&name.as_slice()) || name.starts_with(FAKEIP_PREFIX)) {
            let _ = root.delete_bucket(&name);
            changed = true;
        }
    }
    changed
}

impl Shared {
    fn lock_db(&self) -> MutexGuard<'_, Option<Db>> {
        self.db.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The bucket a record kind lives in for this cache ID (`bucket`).
    fn bucket<'a>(&self, root: &'a Bucket, name: &[u8]) -> Option<&'a Bucket> {
        match &self.cache_id {
            None => root.bucket(name),
            Some(id) => root.bucket(id)?.bucket(name),
        }
    }

    /// `createBucket`.
    fn create_bucket<'a>(&self, root: &'a mut Bucket, name: &[u8]) -> Result<&'a mut Bucket> {
        let parent = match &self.cache_id {
            None => root,
            Some(id) => root.create_bucket_if_not_exists(id)?,
        };
        Ok(parent.create_bucket_if_not_exists(name)?)
    }

    fn view<T>(&self, read: impl FnOnce(&Bucket) -> T) -> Option<T> {
        let db = self.lock_db();
        db.as_ref().map(|db| read(db.root()))
    }

    /// Changes the tree and commits it (`batch`/`update`). A file that
    /// turns out damaged is replaced by an empty one (`resetDB`).
    fn update<T>(&self, change: impl FnOnce(&Shared, &mut Bucket) -> Result<T>) -> Result<T> {
        let mut db = self.lock_db();
        let Some(current) = db.as_mut() else { return Err(Error("cache file closed".into())) };
        let value = change(self, current.root_mut())?;
        if let Err(error) = current.commit() {
            if error.is_damaged() {
                error!("database corrupted: {error}: resetting");
                *db = None;
                let _ = std::fs::remove_file(&self.path);
                *db = Db::open(&self.path, OPEN_TIMEOUT).ok();
            }
            return Err(error.into());
        }
        Ok(value)
    }

    fn write_fakeip(&self, root: &mut Bucket, address: IpAddr, domain: &str) -> Result<()> {
        let key = ip_bytes(address);
        let bucket = root.create_bucket_if_not_exists(BUCKET_FAKEIP)?;
        let old = bucket.get(&key).map(<[u8]>::to_vec);
        bucket.put(&key, domain.as_bytes())?;
        let index = if address.is_ipv4() { BUCKET_FAKEIP_DOMAIN4 } else { BUCKET_FAKEIP_DOMAIN6 };
        let bucket = root.create_bucket_if_not_exists(index)?;
        if let Some(old) = old {
            bucket.delete(&old)?;
        }
        bucket.put(domain.as_bytes(), &key)?;
        Ok(())
    }

    fn write_rdrc(&self, root: &mut Bucket, transport: &str, name: &str, query_type: u16) -> Result<()> {
        let expires = binary::unix_seconds(SystemTime::now() + self.rdrc_timeout) as u64;
        let bucket = self.create_bucket(root, BUCKET_RDRC)?.create_bucket_if_not_exists(transport.as_bytes())?;
        bucket.put(&question_key(name, query_type), &expires.to_be_bytes())?;
        Ok(())
    }

    fn write_dns_cache(
        &self,
        root: &mut Bucket,
        transport: &str,
        name: &str,
        query_type: u16,
        message: &[u8],
        expire_at: SystemTime,
    ) -> Result<()> {
        let mut value = Vec::with_capacity(8 + message.len());
        value.extend_from_slice(&(binary::unix_seconds(expire_at) as u64).to_be_bytes());
        value.extend_from_slice(message);
        let bucket = self.create_bucket(root, BUCKET_DNS_CACHE)?.create_bucket_if_not_exists(transport.as_bytes())?;
        bucket.put(&question_key(name, query_type), &value)?;
        Ok(())
    }

    fn write_metadata(&self, root: &mut Bucket, metadata: &FakeIpMetadata) -> Result<()> {
        root.create_bucket_if_not_exists(BUCKET_FAKEIP)?.put(KEY_METADATA, &fakeip_metadata_to_bytes(metadata))?;
        Ok(())
    }

    /// Deletes expired entries of the `rdrc2` or `dns_cache` bucket, then
    /// the server buckets left empty (`cleanupRDRC`, `cleanupDNSCache`).
    fn cleanup(&self, name: &[u8]) {
        let now = SystemTime::now();
        let optimistic = *self.optimistic_timeout.lock().unwrap();
        let disable_expire = *self.disable_expire.lock().unwrap();
        let dns = name == BUCKET_DNS_CACHE;
        let result = self.update(|shared, root| {
            let parent = match &shared.cache_id {
                None => root.bucket_mut(name),
                Some(id) => root.bucket_mut(id).and_then(|bucket| bucket.bucket_mut(name)),
            };
            let Some(parent) = parent else { return Ok(()) };
            for transport in parent.bucket_names() {
                let Some(bucket) = parent.bucket_mut(&transport) else { continue };
                let mut expired = Vec::new();
                for (key, entry) in bucket.iter() {
                    let Entry::Value(value) = entry else { continue };
                    if value.len() < 8 {
                        expired.push(key.to_vec());
                        continue;
                    }
                    if dns && disable_expire {
                        continue;
                    }
                    let at = binary::from_unix_seconds(u64::from_be_bytes(value[..8].try_into().unwrap()) as i64);
                    let deadline = if dns { at + optimistic } else { at };
                    if now > deadline {
                        expired.push(key.to_vec());
                    }
                }
                for key in expired {
                    bucket.delete(&key)?;
                }
                if bucket.is_empty() {
                    parent.delete_bucket(&transport)?;
                }
            }
            Ok(())
        });
        if let Err(error) = result {
            warn!("cleanup {}: {error}", if dns { "DNS cache" } else { "RDRC" });
        }
    }

    /// Deletes this cache ID's bucket of a kind (`ClearDNSCache`, `clearRDRC`).
    fn delete_kind(&self, name: &[u8]) -> Result<()> {
        self.update(|shared, root| {
            let parent = match &shared.cache_id {
                None => Some(root),
                Some(id) => root.bucket_mut(id),
            };
            if let Some(parent) = parent {
                if parent.bucket(name).is_some() {
                    parent.delete_bucket(name)?;
                }
            }
            Ok(())
        })
    }

    /// Writes everything queued in one commit, then drops what was written
    /// from the queue (unless it was queued again meanwhile).
    fn flush(&self, force_metadata: bool) {
        let (fakeip, rdrc, dns, metadata) = {
            let mut pending = self.pending.lock().unwrap();
            let metadata = match pending.metadata {
                Some((metadata, at)) if force_metadata || Instant::now() >= at => {
                    pending.metadata = None;
                    Some(metadata)
                }
                _ => None,
            };
            let fakeip = std::mem::take(&mut pending.fakeip);
            let rdrc: Vec<CacheKey> = pending.rdrc.keys().cloned().collect();
            let dns: Vec<(CacheKey, Vec<u8>, SystemTime, u64)> = pending
                .dns
                .iter()
                .map(|(key, (message, expire, sequence))| (key.clone(), message.clone(), *expire, *sequence))
                .collect();
            (fakeip, rdrc, dns, metadata)
        };
        if fakeip.is_empty() && rdrc.is_empty() && dns.is_empty() && metadata.is_none() {
            return;
        }
        let result = self.update(|shared, root| {
            for (address, domain) in &fakeip {
                if let Err(error) = shared.write_fakeip(root, *address, domain) {
                    warn!("save FakeIP cache: {error}");
                }
            }
            for (transport, name, query_type) in &rdrc {
                if let Err(error) = shared.write_rdrc(root, transport, name, *query_type) {
                    warn!("save RDRC: {error}");
                }
            }
            for ((transport, name, query_type), message, expire, _) in &dns {
                if let Err(error) = shared.write_dns_cache(root, transport, name, *query_type, message, *expire) {
                    warn!("save DNS cache: {error}");
                }
            }
            if let Some(metadata) = &metadata {
                shared.write_metadata(root, metadata)?;
            }
            Ok(())
        });
        if let Err(error) = result {
            warn!("save cache file: {error}");
        }
        let mut pending = self.pending.lock().unwrap();
        for (address, domain) in &fakeip {
            if pending.save_domain.get(address) == Some(domain) {
                pending.save_domain.remove(address);
                let index = if address.is_ipv4() { &mut pending.save_address4 } else { &mut pending.save_address6 };
                if index.get(domain) == Some(address) {
                    index.remove(domain);
                }
            }
        }
        for key in &rdrc {
            pending.rdrc.remove(key);
        }
        for (key, _, _, sequence) in &dns {
            if pending.dns.get(key).is_some_and(|(_, _, current)| current == sequence) {
                pending.dns.remove(key);
            }
        }
    }

    /// The writer thread: flushes queued writes, the delayed metadata and
    /// the periodic cleanup until closed.
    fn run(self: Arc<Self>) {
        loop {
            let mut pending = self.pending.lock().unwrap();
            loop {
                if pending.closed {
                    return;
                }
                let now = Instant::now();
                let metadata_due = pending.metadata.is_some_and(|(_, at)| now >= at);
                let cleanup_due = pending.next_cleanup.is_some_and(|at| now >= at);
                if pending.has_writes() || metadata_due || cleanup_due {
                    break;
                }
                let next = [pending.metadata.map(|(_, at)| at), pending.next_cleanup].into_iter().flatten().min();
                pending = match next {
                    Some(at) => self.wake.wait_timeout(pending, at.saturating_duration_since(now)).unwrap().0,
                    None => self.wake.wait(pending).unwrap(),
                };
            }
            let cleanup_due = pending.next_cleanup.is_some_and(|at| Instant::now() >= at);
            if cleanup_due {
                pending.next_cleanup = Some(Instant::now() + pending.cleanup_interval);
            }
            drop(pending);
            self.flush(false);
            if cleanup_due {
                if self.store_dns {
                    self.cleanup(BUCKET_DNS_CACHE);
                } else if self.store_rdrc {
                    self.cleanup(BUCKET_RDRC);
                }
            }
        }
    }
}

impl CacheFile {
    /// `cachefile.New`: `path` defaults to `cache.db`; relative paths are
    /// taken from the working directory.
    pub fn new(options: &CacheFileOptions) -> Self {
        let path = if options.path.is_empty() { "cache.db" } else { options.path.as_str() };
        let cache_id = (!options.cache_id.is_empty()).then(|| {
            let mut id = vec![0u8];
            id.extend_from_slice(options.cache_id.as_bytes());
            id
        });
        let rdrc_timeout = if !options.store_rdrc {
            Duration::ZERO
        } else if options.rdrc_timeout.0 > Duration::ZERO {
            options.rdrc_timeout.0
        } else {
            DEFAULT_RDRC_TIMEOUT
        };
        CacheFile {
            shared: Arc::new(Shared {
                path: PathBuf::from(path),
                cache_id,
                store_fakeip: options.store_fakeip,
                store_rdrc: options.store_rdrc,
                store_dns: options.store_dns,
                rdrc_timeout,
                optimistic_timeout: Mutex::new(Duration::ZERO),
                disable_expire: Mutex::new(false),
                db: Mutex::new(None),
                pending: Mutex::new(Pending::default()),
                wake: Condvar::new(),
            }),
            cache_id_text: options.cache_id.clone(),
            writer: Mutex::new(None),
        }
    }

    pub fn path(&self) -> &Path {
        &self.shared.path
    }

    pub fn cache_id(&self) -> &str {
        &self.cache_id_text
    }

    /// `SetOptimisticTimeout`: how long past expiry DNS cache entries are
    /// kept by the cleanup.
    pub fn set_optimistic_timeout(&self, timeout: Duration) {
        *self.shared.optimistic_timeout.lock().unwrap() = timeout;
    }

    pub fn set_disable_expire(&self, disable: bool) {
        *self.shared.disable_expire.lock().unwrap() = disable;
    }

    /// The initialize stage (`start`): creates and opens the file, drops
    /// the buckets sing-box 1.14 does not keep, and starts the writer.
    pub fn open(&self) -> Result<()> {
        let shared = &self.shared;
        if let Some(parent) = shared.path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                return Err(Error(format!("open {}: no such file or directory", shared.path.display())));
            }
        }
        let mut db = open_db(&shared.path)?;
        if clean(db.root_mut()) {
            db.commit()?;
        }
        *shared.lock_db() = Some(db);
        let thread_shared = shared.clone();
        let handle = std::thread::Builder::new()
            .name("cache-file".into())
            .spawn(move || thread_shared.run())
            .map_err(|error| Error(error.to_string()))?;
        *self.writer.lock().unwrap() = Some(handle);
        Ok(())
    }

    /// The start stage (`startCacheCleanup`): with `store_dns` the RDRC
    /// bucket is cleared and the DNS cache cleaned now and every half
    /// optimistic timeout (else hourly); with only `store_rdrc` the RDRC
    /// entries are cleaned now and every half `rdrc_timeout`.
    pub fn start(&self) {
        let shared = &self.shared;
        let interval = if shared.store_dns {
            shared.pending.lock().unwrap().rdrc.clear();
            if let Err(error) = shared.delete_kind(BUCKET_RDRC) {
                warn!("clear RDRC: {error}");
            }
            shared.cleanup(BUCKET_DNS_CACHE);
            *shared.optimistic_timeout.lock().unwrap() / 2
        } else if shared.store_rdrc {
            shared.cleanup(BUCKET_RDRC);
            shared.rdrc_timeout / 2
        } else {
            return;
        };
        let interval = if interval.is_zero() { Duration::from_secs(3600) } else { interval };
        let mut pending = shared.pending.lock().unwrap();
        pending.cleanup_interval = interval;
        pending.next_cleanup = Some(Instant::now() + interval);
        shared.wake.notify_all();
    }

    /// Writes what is queued (the FakeIP metadata included), stops the
    /// writer and releases the file.
    pub fn close(&self) {
        let shared = &self.shared;
        {
            let mut pending = shared.pending.lock().unwrap();
            pending.closed = true;
            shared.wake.notify_all();
        }
        if let Some(handle) = self.writer.lock().unwrap().take() {
            let _ = handle.join();
        }
        shared.flush(true);
        *shared.lock_db() = None;
    }

    pub fn store_fakeip(&self) -> bool {
        self.shared.store_fakeip
    }

    pub fn store_rdrc(&self) -> bool {
        self.shared.store_rdrc
    }

    pub fn rdrc_timeout(&self) -> Duration {
        self.shared.rdrc_timeout
    }

    pub fn store_dns(&self) -> bool {
        self.shared.store_dns
    }

    /// `LoadMode`: the mode saved for this cache ID (`default` without one).
    pub fn load_mode(&self) -> String {
        let key = self.shared.cache_id.clone().unwrap_or_else(|| CACHE_ID_DEFAULT.to_vec());
        self.shared
            .view(|root| root.bucket(BUCKET_MODE).and_then(|bucket| bucket.get(&key)).map(<[u8]>::to_vec))
            .flatten()
            .map(|mode| String::from_utf8_lossy(&mode).into_owned())
            .unwrap_or_default()
    }

    pub fn store_mode(&self, mode: &str) -> Result<()> {
        let key = self.shared.cache_id.clone().unwrap_or_else(|| CACHE_ID_DEFAULT.to_vec());
        self.shared.update(|_, root| Ok(root.create_bucket_if_not_exists(BUCKET_MODE)?.put(&key, mode.as_bytes())?))
    }

    /// `LoadSelected`: empty when nothing is saved.
    pub fn load_selected(&self, group: &str) -> String {
        self.shared
            .view(|root| {
                self.shared
                    .bucket(root, BUCKET_SELECTED)
                    .and_then(|bucket| bucket.get(group.as_bytes()))
                    .map(<[u8]>::to_vec)
            })
            .flatten()
            .map(|selected| String::from_utf8_lossy(&selected).into_owned())
            .unwrap_or_default()
    }

    pub fn store_selected(&self, group: &str, selected: &str) -> Result<()> {
        self.shared.update(|shared, root| {
            Ok(shared.create_bucket(root, BUCKET_SELECTED)?.put(group.as_bytes(), selected.as_bytes())?)
        })
    }

    /// `LoadGroupExpand`: `Some(expanded)` when saved.
    pub fn load_group_expand(&self, group: &str) -> Option<bool> {
        self.shared
            .view(|root| {
                let value = self.shared.bucket(root, BUCKET_EXPAND)?.get(group.as_bytes())?;
                (value.len() == 1).then(|| value[0] == 1)
            })
            .flatten()
    }

    pub fn store_group_expand(&self, group: &str, expand: bool) -> Result<()> {
        self.shared.update(|shared, root| {
            Ok(shared.create_bucket(root, BUCKET_EXPAND)?.put(group.as_bytes(), &[u8::from(expand)])?)
        })
    }

    /// `LoadRuleSet`.
    pub fn load_rule_set(&self, tag: &str) -> Option<SavedBinary> {
        self.shared
            .view(|root| {
                let value = self.shared.bucket(root, BUCKET_RULE_SET)?.get(tag.as_bytes())?;
                if value.is_empty() {
                    return None;
                }
                SavedBinary::from_bytes(value)
            })
            .flatten()
    }

    pub fn save_rule_set(&self, tag: &str, saved: &SavedBinary) -> Result<()> {
        let value = saved.to_bytes();
        self.shared
            .update(|shared, root| Ok(shared.create_bucket(root, BUCKET_RULE_SET)?.put(tag.as_bytes(), &value)?))
    }

    /// `LoadRDRC`: whether the question is rejected and not expired; an
    /// expired entry is deleted.
    pub fn load_rdrc(&self, transport: &str, name: &str, query_type: u16) -> bool {
        let shared = &self.shared;
        if shared.pending.lock().unwrap().rdrc.contains_key(&(transport.into(), name.into(), query_type)) {
            return true;
        }
        let key = question_key(name, query_type);
        let state = shared
            .view(|root| {
                let content = shared.bucket(root, BUCKET_RDRC)?.bucket(transport.as_bytes())?.get(&key)?;
                let seconds = u64::from_be_bytes(content.get(..8)?.try_into().ok()?);
                Some(SystemTime::now() <= binary::from_unix_seconds(seconds as i64))
            })
            .flatten();
        match state {
            Some(true) => true,
            Some(false) => {
                let _ = shared.update(|shared, root| {
                    let parent = match &shared.cache_id {
                        None => root.bucket_mut(BUCKET_RDRC),
                        Some(id) => root.bucket_mut(id).and_then(|bucket| bucket.bucket_mut(BUCKET_RDRC)),
                    };
                    if let Some(bucket) = parent.and_then(|bucket| bucket.bucket_mut(transport.as_bytes())) {
                        bucket.delete(&key)?;
                    }
                    Ok(())
                });
                false
            }
            None => false,
        }
    }

    /// `SaveRDRC`: expires after `rdrc_timeout`.
    pub fn save_rdrc(&self, transport: &str, name: &str, query_type: u16) -> Result<()> {
        self.shared.update(|shared, root| shared.write_rdrc(root, transport, name, query_type))
    }

    /// `SaveRDRCAsync`.
    pub fn save_rdrc_async(&self, transport: &str, name: &str, query_type: u16) {
        let mut pending = self.shared.pending.lock().unwrap();
        pending.rdrc.insert((transport.into(), name.into(), query_type), ());
        self.shared.wake.notify_all();
    }

    /// `LoadDNSCache`: the packed response and its expiry, expired or not.
    pub fn load_dns_cache(&self, transport: &str, name: &str, query_type: u16) -> Option<(Vec<u8>, SystemTime)> {
        let shared = &self.shared;
        if let Some((message, expire, _)) =
            shared.pending.lock().unwrap().dns.get(&(transport.into(), name.into(), query_type))
        {
            return Some((message.clone(), *expire));
        }
        let key = question_key(name, query_type);
        shared
            .view(|root| {
                let content = shared.bucket(root, BUCKET_DNS_CACHE)?.bucket(transport.as_bytes())?.get(&key)?;
                if content.len() < 8 {
                    return None;
                }
                let seconds = u64::from_be_bytes(content[..8].try_into().unwrap());
                Some((content[8..].to_vec(), binary::from_unix_seconds(seconds as i64)))
            })
            .flatten()
    }

    pub fn save_dns_cache(
        &self,
        transport: &str,
        name: &str,
        query_type: u16,
        message: &[u8],
        expire_at: SystemTime,
    ) -> Result<()> {
        self.shared.update(|shared, root| shared.write_dns_cache(root, transport, name, query_type, message, expire_at))
    }

    /// `SaveDNSCacheAsync`.
    pub fn save_dns_cache_async(
        &self,
        transport: &str,
        name: &str,
        query_type: u16,
        message: &[u8],
        expire_at: SystemTime,
    ) {
        let mut pending = self.shared.pending.lock().unwrap();
        pending.dns_sequence += 1;
        let sequence = pending.dns_sequence;
        pending.dns.insert((transport.into(), name.into(), query_type), (message.to_vec(), expire_at, sequence));
        self.shared.wake.notify_all();
    }

    /// `ClearDNSCache`.
    pub fn clear_dns_cache(&self) -> Result<()> {
        self.shared.pending.lock().unwrap().dns.clear();
        self.shared.delete_kind(BUCKET_DNS_CACHE)
    }

    /// `FakeIPMetadata`: the saved metadata, which loading deletes.
    pub fn fakeip_metadata(&self) -> Option<FakeIpMetadata> {
        self.shared
            .update(|_, root| {
                let Some(bucket) = root.bucket_mut(BUCKET_FAKEIP) else { return Ok(None) };
                let Some(value) = bucket.get(KEY_METADATA).filter(|value| !value.is_empty()).map(<[u8]>::to_vec) else {
                    return Ok(None);
                };
                bucket.delete(KEY_METADATA)?;
                Ok(fakeip_metadata_from_bytes(&value))
            })
            .ok()
            .flatten()
    }

    pub fn fakeip_save_metadata(&self, metadata: &FakeIpMetadata) -> Result<()> {
        self.shared.update(|shared, root| shared.write_metadata(root, metadata))
    }

    /// `FakeIPSaveMetadataAsync`: saved once no new metadata came for
    /// [`FAKEIP_METADATA_SAVE_INTERVAL`].
    pub fn fakeip_save_metadata_async(&self, metadata: &FakeIpMetadata) {
        let mut pending = self.shared.pending.lock().unwrap();
        pending.metadata = Some((*metadata, Instant::now() + FAKEIP_METADATA_SAVE_INTERVAL));
        self.shared.wake.notify_all();
    }

    pub fn fakeip_store(&self, address: IpAddr, domain: &str) -> Result<()> {
        self.shared.update(|shared, root| shared.write_fakeip(root, address, domain))
    }

    /// `FakeIPStoreAsync`.
    pub fn fakeip_store_async(&self, address: IpAddr, domain: &str) {
        let mut pending = self.shared.pending.lock().unwrap();
        if let Some(old) = pending.save_domain.insert(address, domain.to_string()) {
            if address.is_ipv4() {
                pending.save_address4.remove(&old);
            } else {
                pending.save_address6.remove(&old);
            }
        }
        if address.is_ipv4() {
            pending.save_address4.insert(domain.to_string(), address);
        } else {
            pending.save_address6.insert(domain.to_string(), address);
        }
        pending.fakeip.push((address, domain.to_string()));
        self.shared.wake.notify_all();
    }

    /// `FakeIPLoad`.
    pub fn fakeip_load(&self, address: IpAddr) -> Option<String> {
        if let Some(domain) = self.shared.pending.lock().unwrap().save_domain.get(&address) {
            return Some(domain.clone());
        }
        let key = ip_bytes(address);
        self.shared
            .view(|root| {
                root.bucket(BUCKET_FAKEIP)?.get(&key).map(|domain| String::from_utf8_lossy(domain).into_owned())
            })
            .flatten()
            .filter(|domain| !domain.is_empty())
    }

    /// `FakeIPLoadDomain`.
    pub fn fakeip_load_domain(&self, domain: &str, ipv6: bool) -> Option<IpAddr> {
        {
            let pending = self.shared.pending.lock().unwrap();
            let index = if ipv6 { &pending.save_address6 } else { &pending.save_address4 };
            if let Some(address) = index.get(domain) {
                return Some(*address);
            }
        }
        let name = if ipv6 { BUCKET_FAKEIP_DOMAIN6 } else { BUCKET_FAKEIP_DOMAIN4 };
        self.shared.view(|root| ip_from_bytes(root.bucket(name)?.get(domain.as_bytes())?)).flatten()
    }

    /// `FakeIPReset`.
    pub fn fakeip_reset(&self) -> Result<()> {
        {
            let mut pending = self.shared.pending.lock().unwrap();
            pending.fakeip.clear();
            pending.save_domain.clear();
            pending.save_address4.clear();
            pending.save_address6.clear();
        }
        self.shared.update(|_, root| {
            for name in [BUCKET_FAKEIP, BUCKET_FAKEIP_DOMAIN4, BUCKET_FAKEIP_DOMAIN6] {
                if root.bucket(name).is_some() {
                    root.delete_bucket(name)?;
                }
            }
            Ok(())
        })
    }
}

impl Drop for CacheFile {
    fn drop(&mut self) {
        if self.writer.lock().unwrap().is_some() {
            self.close();
        }
    }
}

/// The FakeIP part the DNS router uses (sing-box's FakeIP store calls
/// `FakeIPStore`, then `FakeIPSaveMetadataAsync`).
impl FakeIpStorage for CacheFile {
    fn metadata(&self) -> Option<FakeIpMetadata> {
        self.fakeip_metadata()
    }

    fn save_metadata(&self, metadata: &FakeIpMetadata) {
        if let Err(error) = self.fakeip_save_metadata(metadata) {
            warn!("save FakeIP metadata: {error}");
        }
    }

    fn save_metadata_async(&self, metadata: &FakeIpMetadata) {
        self.fakeip_save_metadata_async(metadata);
    }

    fn store(&self, address: IpAddr, domain: &str) {
        if let Err(error) = self.fakeip_store(address, domain) {
            warn!("save FakeIP cache: {error}");
        }
    }

    fn load(&self, address: IpAddr) -> Option<String> {
        self.fakeip_load(address)
    }

    fn load_domain(&self, domain: &str, ipv6: bool) -> Option<IpAddr> {
        self.fakeip_load_domain(domain, ipv6)
    }

    fn reset(&self) {
        if let Err(error) = self.fakeip_reset() {
            warn!("reset FakeIP cache: {error}");
        }
    }
}

impl RdrcStore for CacheFile {
    fn load_rdrc(&self, transport: &str, name: &str, query_type: u16) -> bool {
        CacheFile::load_rdrc(self, transport, name, query_type)
    }

    fn save_rdrc(&self, transport: &str, name: &str, query_type: u16) {
        self.save_rdrc_async(transport, name, query_type);
    }
}

impl DnsCacheStore for CacheFile {
    fn load_dns_cache(&self, transport: &str, name: &str, query_type: u16) -> Option<(Vec<u8>, SystemTime)> {
        CacheFile::load_dns_cache(self, transport, name, query_type)
    }

    fn save_dns_cache(&self, transport: &str, name: &str, query_type: u16, message: &[u8], expire_at: SystemTime) {
        self.save_dns_cache_async(transport, name, query_type, message, expire_at);
    }

    fn clear_dns_cache(&self) {
        if let Err(error) = CacheFile::clear_dns_cache(self) {
            warn!("clear DNS cache: {error}");
        }
    }
}
