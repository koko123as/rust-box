use super::*;

use std::process::Command;

fn options(path: &Path, cache_id: &str) -> CacheFileOptions {
    CacheFileOptions {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        cache_id: cache_id.into(),
        store_fakeip: true,
        store_rdrc: true,
        rdrc_timeout: rb_config::types::Duration(Duration::from_secs(3600)),
        store_dns: true,
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn metadata() -> FakeIpMetadata {
    FakeIpMetadata {
        inet4_range: Some("198.18.0.0/15".parse().unwrap()),
        inet6_range: Some("fc00::/18".parse().unwrap()),
        inet4_current: Some("198.18.0.5".parse().unwrap()),
        inet6_current: Some("fc00::5".parse().unwrap()),
    }
}

fn saved() -> SavedBinary {
    SavedBinary {
        content: b"content".to_vec(),
        last_updated: binary::from_unix_seconds(1_700_000_000),
        last_etag: "\"etag\"".into(),
        url_hash: vec![1, 2, 3, 4],
    }
}

/// Writes what `bolttool sb-write` writes through sing-box's cachefile.
fn write_all(cache: &CacheFile) {
    cache.store_selected("proxy", "node-b").unwrap();
    cache.store_group_expand("proxy", true).unwrap();
    cache.store_group_expand("auto", false).unwrap();
    cache.store_mode("Global").unwrap();
    cache.save_rule_set("geosite", &saved()).unwrap();
    cache.save_rdrc("dns-remote", "example.com.", 1).unwrap();
    cache
        .save_dns_cache("dns-remote", "example.org.", 28, &[0xde, 0xad], binary::from_unix_seconds(4_000_000_000))
        .unwrap();
    cache.fakeip_store("198.18.0.5".parse().unwrap(), "a.example").unwrap();
    cache.fakeip_store("fc00::5".parse().unwrap(), "b.example").unwrap();
    cache.fakeip_save_metadata(&metadata()).unwrap();
}

/// What `bolttool sb-read` prints for the records [`write_all`] writes.
fn read_all(cache: &CacheFile) -> String {
    let mut lines = vec![];
    let (message, expire) =
        cache.load_dns_cache("dns-remote", "example.org.", 28).unwrap_or((vec![], std::time::UNIX_EPOCH));
    lines.push(format!("dns_cache={}|{}|true", hex(&message), binary::unix_seconds(expire)));
    let expand = |group| match cache.load_group_expand(group) {
        Some(expand) => format!("{expand} true"),
        None => "false false".into(),
    };
    lines.push(format!("expand.auto={}", expand("auto")));
    lines.push(format!("expand.proxy={}", expand("proxy")));
    lines.push(format!(
        "fakeip={}|{}|{}|{}",
        cache.fakeip_load("198.18.0.5".parse().unwrap()).unwrap_or_default(),
        cache.fakeip_load("fc00::5".parse().unwrap()).unwrap_or_default(),
        cache.fakeip_load_domain("a.example", false).unwrap(),
        cache.fakeip_load_domain("b.example", true).unwrap(),
    ));
    if let Some(metadata) = cache.fakeip_metadata() {
        let prefix =
            |prefix: Option<IpPrefix>| prefix.map(|p| format!("{}/{}", p.address, p.prefix_len)).unwrap_or_default();
        lines.push(format!(
            "fakeip.metadata={}|{}|{}|{}",
            prefix(metadata.inet4_range),
            prefix(metadata.inet6_range),
            metadata.inet4_current.unwrap(),
            metadata.inet6_current.unwrap()
        ));
    }
    lines.push(format!("mode={}", cache.load_mode()));
    lines.push(format!("rdrc={}", cache.load_rdrc("dns-remote", "example.com.", 1)));
    if let Some(saved) = cache.load_rule_set("geosite") {
        lines.push(format!(
            "rule_set.geosite={}|{}|{}|{}",
            String::from_utf8_lossy(&saved.content),
            binary::unix_seconds(saved.last_updated),
            saved.last_etag,
            hex(&saved.url_hash)
        ));
    }
    lines.push(format!("selected.proxy={}", cache.load_selected("proxy")));
    lines.join("\n")
}

use rb_config::IpPrefix;

const EXPECTED: &str = "dns_cache=dead|4000000000|true
expand.auto=false true
expand.proxy=true true
fakeip=a.example|b.example|198.18.0.5|fc00::5
fakeip.metadata=198.18.0.0/15|fc00::/18|198.18.0.5|fc00::5
mode=Global
rdrc=true
rule_set.geosite=content|1700000000|\"etag\"|01020304
selected.proxy=node-b";

#[test]
fn encodings_match_sing_box() {
    // Bytes sing-box 1.14.4 wrote for the same values.
    assert_eq!(hex(&saved().to_bytes()), "0207636f6e74656e74000000006553f100062265746167220401020304");
    assert_eq!(
        hex(&fakeip_metadata_to_bytes(&metadata())),
        "0005c61200000f0011fc000000000000000000000000000000120004c61200050010fc000000000000000000000000000005"
    );
    assert_eq!(SavedBinary::from_bytes(&saved().to_bytes()), Some(saved()));
    assert_eq!(fakeip_metadata_from_bytes(&fakeip_metadata_to_bytes(&metadata())), Some(metadata()));
    // The zero prefix and address (an IPv4-only FakeIP server).
    let v4_only = FakeIpMetadata { inet6_range: None, inet6_current: None, ..metadata() };
    let bytes = fakeip_metadata_to_bytes(&v4_only);
    assert_eq!(hex(&bytes), "0005c61200000f0001ff0004c61200050000");
    assert_eq!(fakeip_metadata_from_bytes(&bytes), Some(v4_only));
    // Version 1 has no URL hash; a truncated value is rejected.
    let mut v1 = saved().to_bytes();
    v1[0] = 1;
    v1.truncate(v1.len() - 5);
    assert_eq!(SavedBinary::from_bytes(&v1), Some(SavedBinary { url_hash: vec![], ..saved() }));
    assert_eq!(SavedBinary::from_bytes(&saved().to_bytes()[..10]), None);
}

#[test]
fn round_trip_with_and_without_cache_id() {
    for cache_id in ["", "work"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache.db");
        let cache = CacheFile::new(&options(&path, cache_id));
        cache.open().unwrap();
        write_all(&cache);
        cache.close();
        let cache = CacheFile::new(&options(&path, cache_id));
        cache.open().unwrap();
        assert_eq!(read_all(&cache), EXPECTED, "cache_id {cache_id:?}");
        // Loading the metadata removed it.
        assert!(cache.fakeip_metadata().is_none());
        // Another cache ID sees none of the per-ID records, but the same
        // FakeIP buckets.
        cache.close();
        let other = CacheFile::new(&options(&path, if cache_id.is_empty() { "other" } else { "" }));
        other.open().unwrap();
        assert_eq!(other.load_selected("proxy"), "");
        assert_eq!(other.load_mode(), "");
        assert_eq!(other.fakeip_load("198.18.0.5".parse().unwrap()).as_deref(), Some("a.example"));
    }
}

#[test]
fn layout() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    let cache = CacheFile::new(&options(&path, "id"));
    cache.open().unwrap();
    write_all(&cache);
    cache.close();
    let db = Db::open(&path, OPEN_TIMEOUT).unwrap();
    let root = db.root();
    let mut names = root.bucket_names();
    names.sort();
    assert_eq!(
        names,
        [&b"\0id"[..], b"clash_mode", b"fakeip_address", b"fakeip_domain4", b"fakeip_domain6"].map(<[u8]>::to_vec)
    );
    assert_eq!(root.bucket(b"clash_mode").unwrap().get(b"\0id"), Some(&b"Global"[..]));
    let scoped = root.bucket(b"\0id").unwrap();
    assert_eq!(scoped.bucket(b"selected").unwrap().get(b"proxy"), Some(&b"node-b"[..]));
    let rdrc = scoped.bucket(b"rdrc2").unwrap().bucket(b"dns-remote").unwrap();
    assert_eq!(rdrc.get(b"\x00\x01example.com.").unwrap().len(), 8);
    let dns = scoped.bucket(b"dns_cache").unwrap().bucket(b"dns-remote").unwrap();
    assert_eq!(hex(dns.get(b"\x00\x1cexample.org.").unwrap()), "00000000ee6b2800dead");
}

#[test]
fn start_drops_unknown_buckets() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    {
        let mut db = Db::open(&path, OPEN_TIMEOUT).unwrap();
        db.root_mut().create_bucket_if_not_exists(b"rdrc").unwrap().put(b"k", b"v").unwrap();
        db.root_mut().create_bucket_if_not_exists(b"fakeip_other").unwrap().put(b"k", b"v").unwrap();
        db.root_mut().create_bucket_if_not_exists(b"selected").unwrap().put(b"g", b"x").unwrap();
        db.commit().unwrap();
    }
    let cache = CacheFile::new(&options(&path, ""));
    cache.open().unwrap();
    cache.close();
    let db = Db::open(&path, OPEN_TIMEOUT).unwrap();
    let mut names = db.root().bucket_names();
    names.sort();
    assert_eq!(names, [b"fakeip_other".to_vec(), b"selected".to_vec()]);
}

#[test]
fn damaged_file_is_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    std::fs::write(&path, vec![7u8; 9000]).unwrap();
    let cache = CacheFile::new(&options(&path, ""));
    cache.open().unwrap();
    cache.store_selected("g", "x").unwrap();
    assert_eq!(cache.load_selected("g"), "x");
}

#[test]
fn queued_writes_and_expiry() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    let cache = CacheFile::new(&options(&path, ""));
    cache.open().unwrap();
    cache.save_rdrc_async("t", "a.", 1);
    assert!(cache.load_rdrc("t", "a.", 1));
    let future = SystemTime::now() + Duration::from_secs(60);
    cache.save_dns_cache_async("t", "a.", 1, b"one", future);
    cache.save_dns_cache_async("t", "a.", 1, b"two", future);
    assert_eq!(cache.load_dns_cache("t", "a.", 1).unwrap().0, b"two");
    cache.fakeip_save_metadata_async(&metadata());
    cache.close();
    let cache = CacheFile::new(&options(&path, ""));
    cache.open().unwrap();
    assert!(cache.load_rdrc("t", "a.", 1));
    assert_eq!(cache.load_dns_cache("t", "a.", 1).unwrap().0, b"two");
    // Close wrote the delayed metadata.
    assert_eq!(cache.fakeip_metadata(), Some(metadata()));
    // An expired RDRC entry reads as absent and is deleted.
    cache
        .shared
        .update(|shared, root| {
            let bucket = shared.create_bucket(root, BUCKET_RDRC)?.create_bucket_if_not_exists(b"t")?;
            Ok(bucket.put(&question_key("old.", 1), &1u64.to_be_bytes())?)
        })
        .unwrap();
    assert!(!cache.load_rdrc("t", "old.", 1));
    assert!(cache
        .shared
        .view(|root| root.bucket(BUCKET_RDRC).unwrap().bucket(b"t").unwrap().get(b"\0\x01old.").is_none())
        .unwrap());
    // `store_dns` makes the start clear RDRC and clean expired DNS entries.
    cache.save_dns_cache("t", "gone.", 1, b"x", binary::from_unix_seconds(1)).unwrap();
    cache.start();
    assert!(!cache.load_rdrc("t", "a.", 1));
    assert!(cache.load_dns_cache("t", "gone.", 1).is_none());
    assert!(cache.load_dns_cache("t", "a.", 1).is_some());
    cache.clear_dns_cache().unwrap();
    assert!(cache.load_dns_cache("t", "a.", 1).is_none());
    cache.fakeip_store("198.18.0.1".parse().unwrap(), "x.test").unwrap();
    cache.fakeip_store("198.18.0.1".parse().unwrap(), "y.test").unwrap();
    assert_eq!(cache.fakeip_load_domain("x.test", false), None);
    assert_eq!(cache.fakeip_load_domain("y.test", false), "198.18.0.1".parse().ok());
    cache.fakeip_reset().unwrap();
    assert_eq!(cache.fakeip_load("198.18.0.1".parse().unwrap()), None);
}

#[test]
fn second_holder_times_out() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.db");
    let first = CacheFile::new(&options(&path, ""));
    first.open().unwrap();
    let second = CacheFile::new(&options(&path, ""));
    // Ten one-second tries, as sing-box makes; keep the test short by
    // releasing the first holder from another thread.
    let path_exists = path.exists();
    assert!(path_exists);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(1500));
            first.close();
        });
        second.open().unwrap();
    });
}

/// Files sing-box 1.14.4 writes and reads (`bolttool sb-write` / `sb-read`,
/// built on its `experimental/cachefile`), when `RB_BBOLT_TOOL` points to it.
#[test]
fn interoperates_with_sing_box() {
    let Some(tool) = std::env::var_os("RB_BBOLT_TOOL") else { return };
    for cache_id in ["", "work"] {
        let directory = tempfile::tempdir().unwrap();
        // sing-box writes, rust-box reads.
        let path = directory.path().join("from-go.db");
        let status = Command::new(&tool).arg("sb-write").arg(&path).arg(cache_id).status().unwrap();
        assert!(status.success());
        let cache = CacheFile::new(&options(&path, cache_id));
        cache.open().unwrap();
        assert_eq!(read_all(&cache), EXPECTED);
        cache.close();
        // rust-box writes, sing-box reads.
        let path = directory.path().join("from-rust.db");
        let cache = CacheFile::new(&options(&path, cache_id));
        cache.open().unwrap();
        write_all(&cache);
        cache.close();
        let output = Command::new(&tool).arg("sb-read").arg(&path).arg(cache_id).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), EXPECTED);
        let output = Command::new(&tool).arg("check").arg(&path).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
    }
}
