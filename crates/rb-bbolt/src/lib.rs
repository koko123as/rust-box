//! A key/value file in the format of github.com/sagernet/bbolt (the bbolt
//! fork sing-box keeps `cache.db` in), so rust-box and sing-box can open
//! each other's cache file.
//!
//! The whole tree is read into memory when the file opens; a commit writes
//! the changed tree like a bbolt read-write transaction does: the pages go
//! to free pages (or past the end of the file), then the other meta page
//! is written with the next transaction id, so a commit cut short leaves
//! the previous one readable. Unlike bbolt, a commit rewrites every page of
//! the tree instead of only the touched ones, and leaf and branch pages are
//! filled up to the page size instead of bbolt's 50% fill percent; bbolt
//! reads both. Opening checks the file the way `tx.Check` does (every page
//! reachable or free, no page used twice, keys in order) and reports a
//! failure as [`Error::Corrupted`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

/// `common.Magic`.
pub const MAGIC: u32 = 0xED0C_DAED;
/// `common.Version`.
pub const VERSION: u32 = 2;

const PAGE_HEADER_SIZE: usize = 16;
const LEAF_ELEMENT_SIZE: usize = 16;
const BRANCH_ELEMENT_SIZE: usize = 16;
const BUCKET_HEADER_SIZE: usize = 16;
/// The bytes of a meta before its checksum (`unsafe.Offsetof(Meta{}.checksum)`).
const META_CHECKSUMMED: usize = 56;

const BRANCH_PAGE_FLAG: u16 = 0x01;
const LEAF_PAGE_FLAG: u16 = 0x02;
const META_PAGE_FLAG: u16 = 0x04;
const FREELIST_PAGE_FLAG: u16 = 0x10;
const BUCKET_LEAF_FLAG: u32 = 0x01;
/// `common.PgidNoFreelist`.
const PGID_NO_FREELIST: u64 = u64::MAX;

/// `common.MaxKeySize`.
pub const MAX_KEY_SIZE: usize = 32768;
/// `common.MaxValueSize`.
pub const MAX_VALUE_SIZE: usize = (1 << 31) - 2;

/// The errors of `bbolt/errors`, plus a failed open check.
#[derive(Debug)]
pub enum Error {
    /// `ErrInvalid`: not a bbolt file (or both meta pages are damaged).
    Invalid,
    /// `ErrVersionMismatch`.
    VersionMismatch,
    /// `ErrChecksum`.
    Checksum,
    /// `ErrTimeout`: another process holds the file lock.
    Timeout,
    /// What `tx.Check` (or a panic while reading pages) reports.
    Corrupted(String),
    /// `ErrKeyRequired`.
    KeyRequired,
    /// `ErrKeyTooLarge`.
    KeyTooLarge,
    /// `ErrValueTooLarge`.
    ValueTooLarge,
    /// `ErrIncompatibleValue`: a value where a bucket is, or the reverse.
    IncompatibleValue,
    /// `ErrBucketNotFound`.
    BucketNotFound,
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid => f.write_str("invalid database"),
            Error::VersionMismatch => f.write_str("version mismatch"),
            Error::Checksum => f.write_str("checksum error"),
            Error::Timeout => f.write_str("timeout"),
            Error::Corrupted(reason) => f.write_str(reason),
            Error::KeyRequired => f.write_str("key required"),
            Error::KeyTooLarge => f.write_str("key too large"),
            Error::ValueTooLarge => f.write_str("value too large"),
            Error::IncompatibleValue => f.write_str("incompatible value"),
            Error::BucketNotFound => f.write_str("bucket not found"),
            Error::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

impl Error {
    /// Whether sing-box removes the file and starts over on this open
    /// error (`ErrInvalid`, `ErrChecksum`, `ErrVersionMismatch`, or a failed
    /// check).
    pub fn is_damaged(&self) -> bool {
        matches!(self, Error::Invalid | Error::Checksum | Error::VersionMismatch | Error::Corrupted(_))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// One entry of a bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Value(Vec<u8>),
    Bucket(Bucket),
}

/// A bucket: keys in byte order, each a value or a nested bucket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bucket {
    /// The bucket's `NextSequence` counter.
    pub sequence: u64,
    entries: BTreeMap<Vec<u8>, Entry>,
}

impl Bucket {
    pub fn new() -> Self {
        Bucket::default()
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        match self.entries.get(key) {
            Some(Entry::Value(value)) => Some(value),
            _ => None,
        }
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if key.is_empty() {
            return Err(Error::KeyRequired);
        } else if key.len() > MAX_KEY_SIZE {
            return Err(Error::KeyTooLarge);
        } else if value.len() > MAX_VALUE_SIZE {
            return Err(Error::ValueTooLarge);
        }
        if let Some(Entry::Bucket(_)) = self.entries.get(key) {
            return Err(Error::IncompatibleValue);
        }
        self.entries.insert(key.to_vec(), Entry::Value(value.to_vec()));
        Ok(())
    }

    /// Removes a value; a missing key is not an error (like bbolt).
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        match self.entries.get(key) {
            Some(Entry::Bucket(_)) => Err(Error::IncompatibleValue),
            Some(Entry::Value(_)) => {
                self.entries.remove(key);
                Ok(())
            }
            None => Ok(()),
        }
    }

    pub fn bucket(&self, name: &[u8]) -> Option<&Bucket> {
        match self.entries.get(name) {
            Some(Entry::Bucket(bucket)) => Some(bucket),
            _ => None,
        }
    }

    pub fn bucket_mut(&mut self, name: &[u8]) -> Option<&mut Bucket> {
        match self.entries.get_mut(name) {
            Some(Entry::Bucket(bucket)) => Some(bucket),
            _ => None,
        }
    }

    pub fn create_bucket_if_not_exists(&mut self, name: &[u8]) -> Result<&mut Bucket> {
        if name.is_empty() {
            return Err(Error::KeyRequired);
        } else if name.len() > MAX_KEY_SIZE {
            return Err(Error::KeyTooLarge);
        }
        let entry = self.entries.entry(name.to_vec()).or_insert_with(|| Entry::Bucket(Bucket::default()));
        match entry {
            Entry::Bucket(bucket) => Ok(bucket),
            Entry::Value(_) => Err(Error::IncompatibleValue),
        }
    }

    pub fn delete_bucket(&mut self, name: &[u8]) -> Result<()> {
        match self.entries.get(name) {
            Some(Entry::Bucket(_)) => {
                self.entries.remove(name);
                Ok(())
            }
            Some(Entry::Value(_)) => Err(Error::IncompatibleValue),
            None => Err(Error::BucketNotFound),
        }
    }

    /// Every entry in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &Entry)> {
        self.entries.iter().map(|(key, entry)| (key.as_slice(), entry))
    }

    /// The keys of the values (not the nested buckets), in key order.
    pub fn value_keys(&self) -> Vec<Vec<u8>> {
        self.entries.iter().filter(|(_, entry)| matches!(entry, Entry::Value(_))).map(|(key, _)| key.clone()).collect()
    }

    /// The names of the nested buckets, in key order.
    pub fn bucket_names(&self) -> Vec<Vec<u8>> {
        self.entries.iter().filter(|(_, entry)| matches!(entry, Entry::Bucket(_))).map(|(key, _)| key.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn has_buckets(&self) -> bool {
        self.entries.values().any(|entry| matches!(entry, Entry::Bucket(_)))
    }
}

/// An open file. Dropping it releases the file lock.
pub struct Db {
    file: File,
    page_size: usize,
    txid: u64,
    /// The high water mark: pages below it are in the file.
    hwm: u64,
    /// Pages the committed tree and freelist use (beside the meta pages).
    live: BTreeSet<u64>,
    root: Bucket,
}

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Db").field("page_size", &self.page_size).field("txid", &self.txid).finish_non_exhaustive()
    }
}

/// The operating system's page size (`os.Getpagesize`), bbolt's default for
/// new files.
pub fn os_page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: sysconf has no preconditions.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size > 0 {
            return size as usize;
        }
    }
    4096
}

#[derive(Debug, Clone, Copy)]
struct Meta {
    page_size: u32,
    flags: u32,
    root: u64,
    root_sequence: u64,
    freelist: u64,
    pgid: u64,
    txid: u64,
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn fnv64a(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Decodes and validates the meta at the start of `page` (`Meta.Validate`).
fn decode_meta(page: &[u8]) -> Result<Meta> {
    if page.len() < PAGE_HEADER_SIZE + META_CHECKSUMMED + 8 {
        return Err(Error::Invalid);
    }
    let meta = &page[PAGE_HEADER_SIZE..];
    if read_u32(meta, 0) != MAGIC {
        return Err(Error::Invalid);
    }
    if read_u32(meta, 4) != VERSION {
        return Err(Error::VersionMismatch);
    }
    if read_u64(meta, META_CHECKSUMMED) != fnv64a(&meta[..META_CHECKSUMMED]) {
        return Err(Error::Checksum);
    }
    Ok(Meta {
        page_size: read_u32(meta, 8),
        flags: read_u32(meta, 12),
        root: read_u64(meta, 16),
        root_sequence: read_u64(meta, 24),
        freelist: read_u64(meta, 32),
        pgid: read_u64(meta, 40),
        txid: read_u64(meta, 48),
    })
}

fn encode_meta(page: &mut [u8], meta: &Meta) {
    page[..8].copy_from_slice(&(meta.txid % 2).to_le_bytes());
    page[8..10].copy_from_slice(&META_PAGE_FLAG.to_le_bytes());
    let out = &mut page[PAGE_HEADER_SIZE..];
    out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&VERSION.to_le_bytes());
    out[8..12].copy_from_slice(&meta.page_size.to_le_bytes());
    out[12..16].copy_from_slice(&meta.flags.to_le_bytes());
    out[16..24].copy_from_slice(&meta.root.to_le_bytes());
    out[24..32].copy_from_slice(&meta.root_sequence.to_le_bytes());
    out[32..40].copy_from_slice(&meta.freelist.to_le_bytes());
    out[40..48].copy_from_slice(&meta.pgid.to_le_bytes());
    out[48..56].copy_from_slice(&meta.txid.to_le_bytes());
    let checksum = fnv64a(&out[..META_CHECKSUMMED]);
    out[56..64].copy_from_slice(&checksum.to_le_bytes());
}

#[cfg(unix)]
fn try_lock(file: &File) -> io::Result<bool> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: flock on a file descriptor we own.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(not(unix))]
fn try_lock(_file: &File) -> io::Result<bool> {
    Ok(true)
}

/// bbolt's `flock`: tries the exclusive lock every 50 ms until the timeout
/// (zero waits forever).
fn lock(file: &File, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if try_lock(file)? {
            return Ok(());
        }
        if !timeout.is_zero() && start.elapsed() > timeout {
            return Err(Error::Timeout);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
fn write_at(file: &File, data: &[u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.write_all_at(data, offset)
}

#[cfg(windows)]
fn write_at(file: &File, mut data: &[u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !data.is_empty() {
        let written = file.seek_write(data, offset)?;
        data = &data[written..];
        offset += written as u64;
    }
    Ok(())
}

/// Reads the pages of the committed tree.
struct Reader<'a> {
    data: &'a [u8],
    page_size: usize,
    hwm: u64,
    reachable: BTreeSet<u64>,
}

impl Reader<'_> {
    fn corrupted(reason: String) -> Error {
        Error::Corrupted(reason)
    }

    /// The bytes of page `id` with its overflow pages, marking them used.
    fn page(&mut self, id: u64) -> Result<&[u8]> {
        if id >= self.hwm {
            return Err(Self::corrupted(format!("page {id}: out of bounds: {}", self.hwm)));
        }
        let start = id as usize * self.page_size;
        if start + PAGE_HEADER_SIZE > self.data.len() {
            return Err(Self::corrupted(format!("page {id}: beyond the end of the file")));
        }
        let header = &self.data[start..start + PAGE_HEADER_SIZE];
        let page_id = read_u64(header, 0);
        if page_id != id {
            return Err(Self::corrupted(format!(
                "assertion failed: Page expected to be: {id}, but self identifies as {page_id}"
            )));
        }
        let overflow = u64::from(read_u32(header, 12));
        if id + overflow >= self.hwm {
            return Err(Self::corrupted(format!("page {id}: out of bounds: {}", self.hwm)));
        }
        let end = start + (overflow as usize + 1) * self.page_size;
        if end > self.data.len() {
            return Err(Self::corrupted(format!("page {id}: beyond the end of the file")));
        }
        for page in id..=id + overflow {
            if !self.reachable.insert(page) {
                return Err(Self::corrupted(format!("page {page}: multiple references")));
            }
        }
        Ok(&self.data[start..end])
    }

    fn read_bucket(&mut self, root: u64, sequence: u64, inline: Option<&[u8]>) -> Result<Bucket> {
        let mut bucket = Bucket { sequence, entries: BTreeMap::new() };
        if root == 0 {
            let page = inline.ok_or_else(|| Self::corrupted("inline bucket without a page".into()))?;
            if page.len() < PAGE_HEADER_SIZE || read_u16(page, 8) != LEAF_PAGE_FLAG {
                return Err(Self::corrupted("inline bucket page is not a leaf".into()));
            }
            let page = page.to_vec();
            self.read_leaf(&page, &mut bucket)?;
        } else {
            self.read_node(root, &mut bucket)?;
        }
        Ok(bucket)
    }

    fn read_node(&mut self, id: u64, bucket: &mut Bucket) -> Result<()> {
        let page = self.page(id)?.to_vec();
        match read_u16(&page, 8) {
            BRANCH_PAGE_FLAG => {
                let count = usize::from(read_u16(&page, 10));
                for index in 0..count {
                    let offset = PAGE_HEADER_SIZE + index * BRANCH_ELEMENT_SIZE;
                    if offset + BRANCH_ELEMENT_SIZE > page.len() {
                        return Err(Self::corrupted(format!("page {id}: element {index} out of the page")));
                    }
                    let child = read_u64(&page, offset + 8);
                    self.read_node(child, bucket)?;
                }
                Ok(())
            }
            LEAF_PAGE_FLAG => self.read_leaf(&page, bucket),
            flags => Err(Self::corrupted(format!("page {id}: invalid type: unknown<{flags:02x}>"))),
        }
    }

    fn read_leaf(&mut self, page: &[u8], bucket: &mut Bucket) -> Result<()> {
        let count = usize::from(read_u16(page, 10));
        for index in 0..count {
            let offset = PAGE_HEADER_SIZE + index * LEAF_ELEMENT_SIZE;
            if offset + LEAF_ELEMENT_SIZE > page.len() {
                return Err(Self::corrupted(format!("leaf element {index} out of the page")));
            }
            let flags = read_u32(page, offset);
            let position = offset + read_u32(page, offset + 4) as usize;
            let key_size = read_u32(page, offset + 8) as usize;
            let value_size = read_u32(page, offset + 12) as usize;
            let end = position.checked_add(key_size).and_then(|key_end| key_end.checked_add(value_size));
            let end = match end {
                Some(end) if end <= page.len() => end,
                _ => return Err(Self::corrupted(format!("leaf element {index} out of the page"))),
            };
            let key = page[position..position + key_size].to_vec();
            let value = &page[position + key_size..end];
            if let Some((last, _)) = bucket.entries.last_key_value() {
                if *last >= key {
                    return Err(Self::corrupted(format!("key[{index}] out of order")));
                }
            }
            let entry = if flags & BUCKET_LEAF_FLAG != 0 {
                if value.len() < BUCKET_HEADER_SIZE {
                    return Err(Self::corrupted(format!("bucket {key:?}: short header")));
                }
                let root = read_u64(value, 0);
                let sequence = read_u64(value, 8);
                let inline = (root == 0).then(|| &value[BUCKET_HEADER_SIZE..]);
                Entry::Bucket(self.read_bucket(root, sequence, inline)?)
            } else {
                Entry::Value(value.to_vec())
            };
            bucket.entries.insert(key, entry);
        }
        Ok(())
    }
}

/// Allocates page ids for a commit.
struct Allocator {
    free: BTreeSet<u64>,
    hwm: u64,
    allocated: BTreeSet<u64>,
}

impl Allocator {
    /// `count` contiguous pages: the lowest free run, else past the end.
    fn allocate(&mut self, count: u64) -> u64 {
        let mut run_start = None;
        let mut run_length = 0;
        let mut previous = None;
        let mut found = None;
        for &id in &self.free {
            if previous.is_some_and(|previous: u64| previous + 1 == id) {
                run_length += 1;
            } else {
                run_start = Some(id);
                run_length = 1;
            }
            previous = Some(id);
            if run_length == count {
                found = run_start;
                break;
            }
        }
        let start = match found {
            Some(start) => {
                for id in start..start + count {
                    self.free.remove(&id);
                }
                start
            }
            None => {
                let start = self.hwm;
                self.hwm += count;
                start
            }
        };
        self.allocated.extend(start..start + count);
        start
    }
}

/// A page being written: its id and its bytes (whole pages).
struct PageWrite {
    id: u64,
    data: Vec<u8>,
}

struct Writer {
    page_size: usize,
    allocator: Allocator,
    pages: Vec<PageWrite>,
}

/// A leaf element before it is placed.
struct LeafItem {
    flags: u32,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl Writer {
    fn pages_for(&self, size: usize) -> u64 {
        size.div_ceil(self.page_size).max(1) as u64
    }

    fn encode_leaf(items: &[LeafItem], buffer: &mut [u8]) {
        buffer[8..10].copy_from_slice(&LEAF_PAGE_FLAG.to_le_bytes());
        buffer[10..12].copy_from_slice(&(items.len() as u16).to_le_bytes());
        let mut data = PAGE_HEADER_SIZE + items.len() * LEAF_ELEMENT_SIZE;
        for (index, item) in items.iter().enumerate() {
            let offset = PAGE_HEADER_SIZE + index * LEAF_ELEMENT_SIZE;
            buffer[offset..offset + 4].copy_from_slice(&item.flags.to_le_bytes());
            buffer[offset + 4..offset + 8].copy_from_slice(&((data - offset) as u32).to_le_bytes());
            buffer[offset + 8..offset + 12].copy_from_slice(&(item.key.len() as u32).to_le_bytes());
            buffer[offset + 12..offset + 16].copy_from_slice(&(item.value.len() as u32).to_le_bytes());
            buffer[data..data + item.key.len()].copy_from_slice(&item.key);
            data += item.key.len();
            buffer[data..data + item.value.len()].copy_from_slice(&item.value);
            data += item.value.len();
        }
    }

    fn leaf_size(items: &[LeafItem]) -> usize {
        PAGE_HEADER_SIZE + items.iter().map(|item| LEAF_ELEMENT_SIZE + item.key.len() + item.value.len()).sum::<usize>()
    }

    fn write_page(&mut self, size: usize, encode: impl FnOnce(&mut [u8])) -> u64 {
        let count = self.pages_for(size);
        let id = self.allocator.allocate(count);
        let mut data = vec![0u8; count as usize * self.page_size];
        data[..8].copy_from_slice(&id.to_le_bytes());
        data[12..16].copy_from_slice(&((count - 1) as u32).to_le_bytes());
        encode(&mut data);
        self.pages.push(PageWrite { id, data });
        id
    }

    /// Writes a bucket's pages; returns its root page.
    fn write_tree(&mut self, bucket: &Bucket) -> u64 {
        let mut items = Vec::with_capacity(bucket.entries.len());
        for (key, entry) in &bucket.entries {
            items.push(match entry {
                Entry::Value(value) => LeafItem { flags: 0, key: key.clone(), value: value.clone() },
                Entry::Bucket(child) => {
                    LeafItem { flags: BUCKET_LEAF_FLAG, key: key.clone(), value: self.bucket_value(child) }
                }
            });
        }
        // Split the elements into leaf pages that each fit one page (an
        // element larger than a page gets a page of its own with overflow).
        let mut nodes: Vec<Vec<LeafItem>> = vec![Vec::new()];
        let mut size = PAGE_HEADER_SIZE;
        for item in items {
            let item_size = LEAF_ELEMENT_SIZE + item.key.len() + item.value.len();
            let node = nodes.last_mut().unwrap();
            if !node.is_empty() && size + item_size > self.page_size {
                nodes.push(Vec::new());
                size = PAGE_HEADER_SIZE;
            }
            size += item_size;
            nodes.last_mut().unwrap().push(item);
        }
        let mut level: Vec<(Vec<u8>, u64)> = Vec::with_capacity(nodes.len());
        for node in nodes {
            let first = node.first().map(|item| item.key.clone()).unwrap_or_default();
            let id = self.write_page(Self::leaf_size(&node), |buffer| Self::encode_leaf(&node, buffer));
            level.push((first, id));
        }
        while level.len() > 1 {
            let mut groups: Vec<Vec<(Vec<u8>, u64)>> = vec![Vec::new()];
            let mut size = PAGE_HEADER_SIZE;
            for element in level {
                let element_size = BRANCH_ELEMENT_SIZE + element.0.len();
                let group = groups.last_mut().unwrap();
                if group.len() >= 2 && size + element_size > self.page_size {
                    groups.push(Vec::new());
                    size = PAGE_HEADER_SIZE;
                }
                size += element_size;
                groups.last_mut().unwrap().push(element);
            }
            let mut next = Vec::with_capacity(groups.len());
            for group in groups {
                let size =
                    PAGE_HEADER_SIZE + group.iter().map(|(key, _)| BRANCH_ELEMENT_SIZE + key.len()).sum::<usize>();
                let first = group[0].0.clone();
                let id = self.write_page(size, |buffer| {
                    buffer[8..10].copy_from_slice(&BRANCH_PAGE_FLAG.to_le_bytes());
                    buffer[10..12].copy_from_slice(&(group.len() as u16).to_le_bytes());
                    let mut data = PAGE_HEADER_SIZE + group.len() * BRANCH_ELEMENT_SIZE;
                    for (index, (key, child)) in group.iter().enumerate() {
                        let offset = PAGE_HEADER_SIZE + index * BRANCH_ELEMENT_SIZE;
                        buffer[offset..offset + 4].copy_from_slice(&((data - offset) as u32).to_le_bytes());
                        buffer[offset + 4..offset + 8].copy_from_slice(&(key.len() as u32).to_le_bytes());
                        buffer[offset + 8..offset + 16].copy_from_slice(&child.to_le_bytes());
                        buffer[data..data + key.len()].copy_from_slice(key);
                        data += key.len();
                    }
                });
                next.push((first, id));
            }
            level = next;
        }
        level[0].1
    }

    /// The value a bucket is stored as in its parent: its header, followed
    /// by its page when it is small enough to be inline (`inlineable`).
    fn bucket_value(&mut self, bucket: &Bucket) -> Vec<u8> {
        let mut value = Vec::with_capacity(BUCKET_HEADER_SIZE);
        if !bucket.has_buckets() {
            let items: Vec<LeafItem> = bucket
                .entries
                .iter()
                .map(|(key, entry)| match entry {
                    Entry::Value(value) => LeafItem { flags: 0, key: key.clone(), value: value.clone() },
                    Entry::Bucket(_) => unreachable!(),
                })
                .collect();
            let size = Self::leaf_size(&items);
            if size <= self.page_size / 4 {
                value.extend_from_slice(&0u64.to_le_bytes());
                value.extend_from_slice(&bucket.sequence.to_le_bytes());
                let start = value.len();
                value.resize(start + size, 0);
                Self::encode_leaf(&items, &mut value[start..]);
                return value;
            }
        }
        let root = self.write_tree(bucket);
        value.extend_from_slice(&root.to_le_bytes());
        value.extend_from_slice(&bucket.sequence.to_le_bytes());
        value
    }
}

impl Db {
    /// Opens (or creates, with mode 0666) the file and takes its lock,
    /// waiting up to `timeout` for another holder (`bbolt.Open`).
    pub fn open(path: &Path, timeout: Duration) -> Result<Db> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o666);
        }
        let file = options.open(path)?;
        lock(&file, timeout)?;
        if file.metadata()?.len() == 0 {
            Self::init(&file, os_page_size())?;
        }
        let data = std::fs::read(path)?;
        let (page_size, meta) = Self::select_meta(&data)?;
        let (root, live) = Self::load(&data, page_size, &meta)?;
        Ok(Db { file, page_size, txid: meta.txid, hwm: meta.pgid, live, root })
    }

    /// `db.init`: two meta pages, an empty freelist and an empty root leaf.
    fn init(file: &File, page_size: usize) -> Result<()> {
        let mut buffer = vec![0u8; page_size * 4];
        for txid in 0..2u64 {
            let meta =
                Meta { page_size: page_size as u32, flags: 0, root: 3, root_sequence: 0, freelist: 2, pgid: 4, txid };
            let start = txid as usize * page_size;
            encode_meta(&mut buffer[start..start + page_size], &meta);
        }
        let freelist = 2 * page_size;
        buffer[freelist..freelist + 8].copy_from_slice(&2u64.to_le_bytes());
        buffer[freelist + 8..freelist + 10].copy_from_slice(&FREELIST_PAGE_FLAG.to_le_bytes());
        let leaf = 3 * page_size;
        buffer[leaf..leaf + 8].copy_from_slice(&3u64.to_le_bytes());
        buffer[leaf + 8..leaf + 10].copy_from_slice(&LEAF_PAGE_FLAG.to_le_bytes());
        write_at(file, &buffer, 0)?;
        file.sync_data()?;
        Ok(())
    }

    /// The page size and the meta bbolt would use: the page size from the
    /// first meta (else the second one at a power-of-two offset), then the
    /// valid meta with the higher transaction id.
    fn select_meta(data: &[u8]) -> Result<(usize, Meta)> {
        let first = decode_meta(&data[..data.len().min(0x1000)]);
        let page_size = match &first {
            Ok(meta) => meta.page_size as usize,
            Err(_) => {
                let mut found = None;
                let mut size = 1024usize;
                while size <= 65536 {
                    if let Ok(meta) = decode_meta(data.get(size..).unwrap_or_default()) {
                        if meta.page_size as usize == size {
                            found = Some(size);
                            break;
                        }
                    }
                    size *= 2;
                }
                match found {
                    Some(size) => size,
                    None => return Err(first.err().unwrap_or(Error::Invalid)),
                }
            }
        };
        if page_size < 1024 || !page_size.is_power_of_two() || data.len() < page_size * 2 {
            return Err(Error::Invalid);
        }
        let meta0 = decode_meta(&data[..page_size]);
        let meta1 = decode_meta(&data[page_size..page_size * 2]);
        let meta = match (meta0, meta1) {
            (Ok(a), Ok(b)) => {
                if b.txid > a.txid {
                    b
                } else {
                    a
                }
            }
            (Ok(a), Err(_)) => a,
            (Err(_), Ok(b)) => b,
            (Err(error), Err(_)) => return Err(error),
        };
        if meta.pgid as usize > data.len() / page_size {
            return Err(Error::Invalid);
        }
        Ok((page_size, meta))
    }

    /// Reads the tree and the freelist, checking them like `tx.Check`.
    fn load(data: &[u8], page_size: usize, meta: &Meta) -> Result<(Bucket, BTreeSet<u64>)> {
        let mut reader = Reader { data, page_size, hwm: meta.pgid, reachable: BTreeSet::new() };
        let mut root = reader.read_bucket(meta.root, meta.root_sequence, None)?;
        root.sequence = meta.root_sequence;
        let mut freed = BTreeSet::new();
        if meta.freelist != PGID_NO_FREELIST {
            let page = reader.page(meta.freelist)?.to_vec();
            if read_u16(&page, 8) != FREELIST_PAGE_FLAG {
                return Err(Error::Corrupted(format!(
                    "invalid database: load freelist: page {} is not a freelist page",
                    meta.freelist
                )));
            }
            let (start, count) = match read_u16(&page, 10) {
                0xFFFF => (1usize, read_u64(&page, PAGE_HEADER_SIZE) as usize),
                count => (0, usize::from(count)),
            };
            let end = PAGE_HEADER_SIZE + (start + count) * 8;
            if end > page.len() {
                return Err(Error::Corrupted("invalid database: load freelist: count out of the page".into()));
            }
            for index in start..start + count {
                let id = read_u64(&page, PAGE_HEADER_SIZE + index * 8);
                if !freed.insert(id) {
                    return Err(Error::Corrupted(format!("page {id}: already freed")));
                }
                if reader.reachable.contains(&id) {
                    return Err(Error::Corrupted(format!("page {id}: reachable freed")));
                }
            }
        }
        for id in 2..meta.pgid {
            if !reader.reachable.contains(&id) && !freed.contains(&id) && meta.freelist != PGID_NO_FREELIST {
                return Err(Error::Corrupted(format!("page {id}: unreachable unfreed")));
            }
        }
        Ok((root, reader.reachable))
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// The top-level buckets (bbolt's root bucket, which holds only buckets).
    pub fn root(&self) -> &Bucket {
        &self.root
    }

    pub fn root_mut(&mut self) -> &mut Bucket {
        &mut self.root
    }

    /// Writes the tree as the next transaction. On an error the file still
    /// holds the previous transaction; the tree in memory is kept.
    pub fn commit(&mut self) -> Result<()> {
        if self.root.entries.values().any(|entry| matches!(entry, Entry::Value(_))) {
            return Err(Error::IncompatibleValue);
        }
        let free: BTreeSet<u64> = (2..self.hwm).filter(|id| !self.live.contains(id)).collect();
        let mut writer = Writer {
            page_size: self.page_size,
            allocator: Allocator { free, hwm: self.hwm, allocated: BTreeSet::new() },
            pages: Vec::new(),
        };
        let root = writer.write_tree(&self.root);
        // The freelist: every page that the new tree does not use,
        // including those of the previous transaction.
        let mut free: BTreeSet<u64> =
            (2..writer.allocator.hwm).filter(|id| !writer.allocator.allocated.contains(id)).collect();
        let freelist_size = |count: usize| PAGE_HEADER_SIZE + if count >= 0xFFFF { (count + 1) * 8 } else { count * 8 };
        let freelist_pages = writer.pages_for(freelist_size(free.len()));
        let freelist = writer.allocator.allocate(freelist_pages);
        for id in freelist..freelist + freelist_pages {
            free.remove(&id);
        }
        let hwm = writer.allocator.hwm;
        let ids: Vec<u64> = free.into_iter().collect();
        let size = freelist_size(ids.len());
        let mut data = vec![0u8; freelist_pages as usize * self.page_size];
        debug_assert!(size <= data.len());
        data[..8].copy_from_slice(&freelist.to_le_bytes());
        data[8..10].copy_from_slice(&FREELIST_PAGE_FLAG.to_le_bytes());
        data[12..16].copy_from_slice(&((freelist_pages - 1) as u32).to_le_bytes());
        let mut offset = PAGE_HEADER_SIZE;
        if ids.len() >= 0xFFFF {
            data[10..12].copy_from_slice(&0xFFFFu16.to_le_bytes());
            data[offset..offset + 8].copy_from_slice(&(ids.len() as u64).to_le_bytes());
            offset += 8;
        } else {
            data[10..12].copy_from_slice(&(ids.len() as u16).to_le_bytes());
        }
        for id in &ids {
            data[offset..offset + 8].copy_from_slice(&id.to_le_bytes());
            offset += 8;
        }
        writer.pages.push(PageWrite { id: freelist, data });

        let file_size = hwm * self.page_size as u64;
        if self.file.metadata()?.len() < file_size {
            self.file.set_len(file_size)?;
        }
        for page in &writer.pages {
            write_at(&self.file, &page.data, page.id * self.page_size as u64)?;
        }
        self.file.sync_data()?;
        let meta = Meta {
            page_size: self.page_size as u32,
            flags: 0,
            root,
            root_sequence: self.root.sequence,
            freelist,
            pgid: hwm,
            txid: self.txid + 1,
        };
        let mut page = vec![0u8; self.page_size];
        encode_meta(&mut page, &meta);
        write_at(&self.file, &page, (meta.txid % 2) * self.page_size as u64)?;
        self.file.sync_data()?;
        self.txid = meta.txid;
        self.hwm = hwm;
        self.live = writer.allocator.allocated;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
