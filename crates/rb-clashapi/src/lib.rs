//! The Clash API (sing-box `experimental/clashapi`): a RESTful controller
//! for the outbound groups, the Clash mode, connections, logs, traffic,
//! DNS and the cache file, with WebSocket variants of the streams.

mod http;
pub mod log;
mod mode;
mod server;
#[cfg(test)]
mod tests;
mod traffic;
mod ui;
mod util;

use std::sync::{Arc, Mutex};

use rb_adapter::{HistoryStorage, Outbound, OutboundRegistry};
use rb_cachefile::CacheFile;
use rb_certificate::Store;
use rb_config::ClashApiOptions;
use rb_dns::DnsRouter;
use rb_route::Router;
use tokio::sync::watch;
use tracing::{error, info};

pub use log::ObservableLayer;
pub use mode::ModeManager;
pub use traffic::{TrackerMetadata, TrafficManager};

/// `os.ExpandEnv`: `$NAME` and `${NAME}` replaced by the variable (empty
/// when unset).
pub fn expand_env(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if character != '$' {
            out.push(character);
            continue;
        }
        let rest = &text[index + 1..];
        if let Some(inner) = rest.strip_prefix('{') {
            if let Some(end) = inner.find('}') {
                out.push_str(&std::env::var(&inner[..end]).unwrap_or_default());
                for _ in 0..end + 2 {
                    chars.next();
                }
                continue;
            }
            // Go drops a bad `${`.
            chars.next();
            continue;
        }
        let name: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        if name.is_empty() {
            match rest.chars().next() {
                // Special one-character names (`$1`, `$*`, ...).
                Some(special) if "*#$@!?-".contains(special) || special.is_ascii_digit() => {
                    out.push_str(&std::env::var(special.to_string()).unwrap_or_default());
                    chars.next();
                }
                Some(_) => {}
                None => out.push('$'),
            }
            continue;
        }
        out.push_str(&std::env::var(&name).unwrap_or_default());
        for _ in 0..name.len() {
            chars.next();
        }
    }
    out
}

/// What the API works with.
pub struct ApiParts {
    pub options: ClashApiOptions,
    pub router: Arc<Router>,
    pub dns: Arc<DnsRouter>,
    /// Every outbound, in configuration order.
    pub outbounds: Vec<Arc<dyn Outbound>>,
    pub registry: Arc<OutboundRegistry>,
    pub traffic: TrafficManager,
    pub history: Arc<HistoryStorage>,
    pub mode: Arc<ModeManager>,
    pub cache_file: Option<Arc<CacheFile>>,
    pub store: Arc<Store>,
    /// The log level, as sing-box numbers it (see [`log::parse_level`]).
    pub log_level: u8,
    /// What `/version` reports.
    pub version: String,
}

/// The Clash API server.
pub struct ClashApi {
    state: Arc<server::State>,
    closing: watch::Sender<bool>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl ClashApi {
    /// `NewServer`.
    pub fn new(parts: ApiParts) -> Result<Self, String> {
        let options = &parts.options;
        if options.store_mode
            || options.store_selected
            || options.store_fakeip
            || !options.cache_file.is_empty()
            || !options.cache_id.is_empty()
        {
            return Err("cache_file and related fields in Clash API is deprecated in sing-box 1.8.0, use experimental.cache_file instead.".into());
        }
        if !options.external_ui.is_empty() {
            let directory = expand_env(&options.external_ui);
            if let Err(error) = std::fs::read_dir(&directory) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(format!("read external UI directory: {error}"));
                }
            }
        }
        let (closing, receiver) = watch::channel(false);
        Ok(ClashApi { state: Arc::new(server::State::new(parts, receiver)), closing, task: Mutex::new(None) })
    }

    /// The `started` stage: downloads the external UI when its directory
    /// is empty, then listens on `external_controller` when set.
    pub async fn start(&self) -> Result<Option<std::net::SocketAddr>, String> {
        let address = self.state.options.external_controller.clone();
        if address.is_empty() {
            return Ok(None);
        }
        self.state.check_external_ui().await;
        let listener =
            server::listen(&address).await.map_err(|error| format!("external controller listen error: {error}"))?;
        let local = listener.local_addr().ok();
        if let Some(local) = local {
            info!("clash-api: restful api listening at {local}");
        }
        let state = self.state.clone();
        let mut closing = self.closing.subscribe();
        *self.task.lock().unwrap() = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = closing.changed() => return,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _)) => {
                            let _ = stream.set_nodelay(true);
                            tokio::spawn(server::serve_connection(state.clone(), stream));
                        }
                        Err(error) => {
                            error!("clash-api: external controller serve error: {error}");
                            return;
                        }
                    },
                }
            }
        }));
        Ok(local)
    }

    pub fn close(&self) {
        let _ = self.closing.send(true);
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }

    pub fn traffic(&self) -> &TrafficManager {
        &self.state.traffic
    }
}

impl Drop for ClashApi {
    fn drop(&mut self) {
        self.close();
    }
}
