//! What the DNS router keeps in the cache file when one is configured
//! (sing-box `adapter.FakeIPStorage`, `adapter.RDRCStore` and
//! `adapter.DNSCacheStore`).

use std::net::IpAddr;
use std::time::SystemTime;

use rb_config::IpPrefix;

/// sing-box `adapter.FakeIPMetadata`: the ranges and allocation cursors,
/// saved so a restart keeps allocating after the last address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FakeIpMetadata {
    pub inet4_range: Option<IpPrefix>,
    pub inet6_range: Option<IpPrefix>,
    pub inet4_current: Option<IpAddr>,
    pub inet6_current: Option<IpAddr>,
}

/// `adapter.FakeIPStorage`.
pub trait FakeIpStorage: Send + Sync {
    /// The saved metadata, which loading removes (`FakeIPMetadata`).
    fn metadata(&self) -> Option<FakeIpMetadata>;
    fn save_metadata(&self, metadata: &FakeIpMetadata);
    /// Saves the metadata a little later, coalescing frequent saves.
    fn save_metadata_async(&self, metadata: &FakeIpMetadata);
    fn store(&self, address: IpAddr, domain: &str);
    fn load(&self, address: IpAddr) -> Option<String>;
    fn load_domain(&self, domain: &str, ipv6: bool) -> Option<IpAddr>;
    fn reset(&self);
}

/// `adapter.RDRCStore`: (server, question) pairs whose response a rule's
/// address limit rejected, skipped until they expire.
pub trait RdrcStore: Send + Sync {
    fn load_rdrc(&self, transport: &str, name: &str, query_type: u16) -> bool;
    fn save_rdrc(&self, transport: &str, name: &str, query_type: u16);
}

/// `adapter.DNSCacheStore`: responses kept across restarts, replacing the
/// in-memory cache.
pub trait DnsCacheStore: Send + Sync {
    /// The packed response and when it expires.
    fn load_dns_cache(&self, transport: &str, name: &str, query_type: u16) -> Option<(Vec<u8>, SystemTime)>;
    fn save_dns_cache(&self, transport: &str, name: &str, query_type: u16, message: &[u8], expire_at: SystemTime);
    fn clear_dns_cache(&self);
}

/// The cache-file parts the DNS router uses (each `None` when the cache
/// file does not store it).
#[derive(Clone, Default)]
pub struct DnsStorage {
    pub fakeip: Option<std::sync::Arc<dyn FakeIpStorage>>,
    pub rdrc: Option<std::sync::Arc<dyn RdrcStore>>,
    pub dns_cache: Option<std::sync::Arc<dyn DnsCacheStore>>,
}
