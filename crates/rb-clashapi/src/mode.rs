//! sing-box `experimental/clashmode.Manager`: the Clash mode with its
//! persistence and the DNS cache flush on a change.

use std::sync::Arc;

use rb_cachefile::CacheFile;
use rb_dns::DnsRouter;
use rb_rule::ClashMode;
use tracing::{error, info};

pub struct ModeManager {
    mode: Arc<ClashMode>,
    dns: Option<Arc<DnsRouter>>,
    cache_file: Option<Arc<CacheFile>>,
}

impl ModeManager {
    /// `NewManager` (the mode list comes from `rb_config::clash_mode_list`).
    pub fn new(
        default_mode: &str,
        list: Vec<String>,
        dns: Option<Arc<DnsRouter>>,
        cache_file: Option<Arc<CacheFile>>,
    ) -> Self {
        ModeManager { mode: Arc::new(ClashMode::new(default_mode, list)), dns, cache_file }
    }

    /// What `clash_mode` rule items read.
    pub fn clash_mode(&self) -> Arc<ClashMode> {
        self.mode.clone()
    }

    /// `Start`: restores the cache file's mode when the list has it.
    pub fn start(&self) {
        if let Some(cache_file) = &self.cache_file {
            self.mode.restore(&cache_file.load_mode());
        }
    }

    pub fn mode(&self) -> String {
        self.mode.mode()
    }

    pub fn mode_list(&self) -> Vec<String> {
        self.mode.list().to_vec()
    }

    /// `SetMode`: an unknown mode is ignored; a change flushes the DNS cache
    /// and is saved.
    pub fn set_mode(&self, name: &str) {
        let Some(mode) = self.mode.set(name) else { return };
        if let Some(dns) = &self.dns {
            dns.clear_cache();
        }
        if let Some(cache_file) = &self.cache_file {
            if let Err(error) = cache_file.store_mode(&mode) {
                error!("clash-mode: save mode: {error}");
            }
        }
        info!("clash-mode: updated mode: {mode}");
    }
}
