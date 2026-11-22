use super::*;

use std::path::PathBuf;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/bbolt.db")
}

/// What `tests/data/bbolt.db` (written by github.com/sagernet/bbolt in two
/// transactions) holds.
fn assert_fixture(root: &Bucket) {
    let selected = root.bucket(b"selected").unwrap();
    assert_eq!(selected.get(b"proxy"), Some(&b"node-c"[..]));
    assert_eq!(selected.get(b"auto"), Some(&b"node-b"[..]));
    assert_eq!(root.bucket(b"clash_mode").unwrap().get(b"default"), Some(&b"Rule"[..]));
    let many = root.bucket(b"many").unwrap();
    assert_eq!(many.sequence, 42);
    assert_eq!(many.len(), 600);
    for index in 0..600 {
        let key = format!("key-{index:05}");
        assert_eq!(many.get(key.as_bytes()), Some(format!("value-{}", index * 7).as_bytes()), "{key}");
    }
    let blob: Vec<u8> = (0..20000usize).map(|index| (index * 31) as u8).collect();
    assert_eq!(root.bucket(b"rule_set").unwrap().get(b"geosite"), Some(&blob[..]));
    let nested = root.bucket(b"\0id").unwrap().bucket(b"selected").unwrap();
    assert_eq!(nested.get(b"g"), Some(&b"x"[..]));
    assert_eq!(root.len(), 5);
}

/// An external checker (the `check` and `dump` commands of a small program
/// built on github.com/sagernet/bbolt) for files this crate writes.
fn external_check(path: &Path) {
    let Some(tool) = std::env::var_os("RB_BBOLT_TOOL") else { return };
    let output = std::process::Command::new(&tool).arg("check").arg(path).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok", "{}", String::from_utf8_lossy(&output.stderr));
    // bbolt writes on top of the file, then this crate reads it back.
    let copy = path.with_extension("copy");
    std::fs::copy(path, &copy).unwrap();
    let status = std::process::Command::new(&tool)
        .args(["put".as_ref(), copy.as_os_str(), "from-go".as_ref(), "k".as_ref(), "v".as_ref()])
        .status()
        .unwrap();
    assert!(status.success());
    let db = Db::open(&copy, Duration::from_secs(1)).unwrap();
    assert_eq!(db.root().bucket(b"from-go").unwrap().get(b"k"), Some(&b"v"[..]));
}

#[test]
fn reads_a_bbolt_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    std::fs::copy(fixture(), &path).unwrap();
    let db = Db::open(&path, Duration::from_secs(1)).unwrap();
    assert_fixture(db.root());
}

#[test]
fn rewrites_a_bbolt_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    std::fs::copy(fixture(), &path).unwrap();
    let expected = {
        let mut db = Db::open(&path, Duration::from_secs(1)).unwrap();
        db.root_mut().create_bucket_if_not_exists(b"new").unwrap().put(b"k", b"v").unwrap();
        db.root_mut().bucket_mut(b"many").unwrap().delete(b"key-00010").unwrap();
        db.commit().unwrap();
        // A second commit reuses the pages the first one freed.
        db.root_mut().bucket_mut(b"selected").unwrap().put(b"proxy", b"node-d").unwrap();
        db.commit().unwrap();
        db.root().clone()
    };
    external_check(&path);
    let db = Db::open(&path, Duration::from_secs(1)).unwrap();
    assert_eq!(db.root(), &expected);
    assert_eq!(db.root().bucket(b"selected").unwrap().get(b"proxy"), Some(&b"node-d"[..]));
    assert_eq!(db.root().bucket(b"many").unwrap().get(b"key-00010"), None);
}

#[test]
fn creates_and_grows() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    let mut db = Db::open(&path, Duration::from_secs(1)).unwrap();
    assert!(db.root().is_empty());
    let page_size = db.page_size();
    for round in 0..5u32 {
        let bucket = db.root_mut().create_bucket_if_not_exists(b"data").unwrap();
        for index in 0..2000u32 {
            bucket.put(format!("{index:08}").as_bytes(), &round.to_le_bytes().repeat(5)).unwrap();
        }
        bucket.put(b"large", &vec![round as u8; page_size * 3 + 17]).unwrap();
        bucket.sequence = u64::from(round);
        db.root_mut().create_bucket_if_not_exists(b"inline").unwrap().put(b"a", b"b").unwrap();
        db.commit().unwrap();
    }
    let expected = db.root().clone();
    let size = std::fs::metadata(&path).unwrap().len();
    drop(db);
    external_check(&path);
    let db = Db::open(&path, Duration::from_secs(1)).unwrap();
    assert_eq!(db.root(), &expected);
    // Pages are reused: the file stays near twice the tree's size.
    assert!(size < (page_size as u64) * 200, "{size}");
}

#[test]
fn a_cut_short_commit_keeps_the_previous_one() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    let mut db = Db::open(&path, Duration::from_secs(1)).unwrap();
    db.root_mut().create_bucket_if_not_exists(b"b").unwrap().put(b"k", b"1").unwrap();
    db.commit().unwrap();
    let page_size = db.page_size();
    db.root_mut().bucket_mut(b"b").unwrap().put(b"k", b"2").unwrap();
    db.commit().unwrap();
    drop(db);
    // Damage the newest meta page (transaction 3 is on page 1).
    let mut data = std::fs::read(&path).unwrap();
    data[page_size + PAGE_HEADER_SIZE + 20] ^= 0xFF;
    std::fs::write(&path, &data).unwrap();
    let db = Db::open(&path, Duration::from_secs(1)).unwrap();
    assert_eq!(db.root().bucket(b"b").unwrap().get(b"k"), Some(&b"1"[..]));
    assert_eq!(page_size, db.page_size());
}

#[test]
fn rejects_damaged_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    std::fs::write(&path, b"not a database at all, just some bytes".repeat(200)).unwrap();
    let error = Db::open(&path, Duration::from_secs(1)).unwrap_err();
    assert!(matches!(error, Error::Invalid), "{error}");
    assert!(error.is_damaged());

    // A page of the tree pointing at a page past the end.
    std::fs::copy(fixture(), &path).unwrap();
    let mut data = std::fs::read(&path).unwrap();
    let (page_size, meta) = Db::select_meta(&data).unwrap();
    let root = meta.root as usize * page_size;
    data[root..root + 8].copy_from_slice(&999u64.to_le_bytes());
    std::fs::write(&path, &data).unwrap();
    let error = Db::open(&path, Duration::from_secs(1)).unwrap_err();
    assert!(matches!(error, Error::Corrupted(_)), "{error}");
}

#[cfg(unix)]
#[test]
fn locks_the_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    let db = Db::open(&path, Duration::from_secs(1)).unwrap();
    let error = Db::open(&path, Duration::from_millis(100)).unwrap_err();
    assert!(matches!(error, Error::Timeout), "{error}");
    drop(db);
    Db::open(&path, Duration::from_millis(100)).unwrap();
}

#[test]
fn bucket_errors() {
    let mut bucket = Bucket::new();
    assert!(matches!(bucket.put(b"", b"v"), Err(Error::KeyRequired)));
    bucket.put(b"value", b"v").unwrap();
    assert!(matches!(bucket.create_bucket_if_not_exists(b"value"), Err(Error::IncompatibleValue)));
    bucket.create_bucket_if_not_exists(b"child").unwrap();
    assert!(matches!(bucket.put(b"child", b"v"), Err(Error::IncompatibleValue)));
    assert!(matches!(bucket.delete(b"child"), Err(Error::IncompatibleValue)));
    assert!(matches!(bucket.delete_bucket(b"missing"), Err(Error::BucketNotFound)));
    bucket.delete(b"missing").unwrap();
    assert_eq!(bucket.bucket_names(), vec![b"child".to_vec()]);
    assert_eq!(bucket.value_keys(), vec![b"value".to_vec()]);
}
