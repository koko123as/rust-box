//! The certificate store, mirroring sing-box `common/certificate`: the
//! top-level `certificate` section picks the trusted roots for TLS clients
//! — `system` (the default: the operating system's roots, found the way
//! Go's `x509.SystemCertPool` finds them), `mozilla` or `chrome` (the root
//! lists sing-box embeds) or `none` — plus PEM strings, files and
//! directories, which are watched and reloaded when they change.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use rb_config::CertificateOptions;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;

pub const STORE_SYSTEM: &str = "system";
pub const STORE_MOZILLA: &str = "mozilla";
pub const STORE_CHROME: &str = "chrome";
pub const STORE_NONE: &str = "none";

/// sing-box `mozillaIncludedPEM` (Mozilla's included CA certificate list).
pub const MOZILLA_PEM: &str = include_str!("mozilla.pem");
/// sing-box `chromeIncludedPEM` (the Chrome Root Store).
pub const CHROME_PEM: &str = include_str!("chrome.pem");

#[derive(Debug)]
pub struct CertificateError(pub String);

impl std::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CertificateError {}

/// An `x509.CertPool`: certificates as DER, and the root store built from
/// them.
#[derive(Debug, Clone)]
pub struct Pool {
    certificates: Vec<CertificateDer<'static>>,
    roots: RootCertStore,
}

impl Default for Pool {
    fn default() -> Self {
        Pool { certificates: Vec::new(), roots: RootCertStore::empty() }
    }
}

impl Pool {
    /// `CertPool.AppendCertsFromPEM`: whether any certificate was added.
    pub fn append_pem(&mut self, pem: &[u8]) -> bool {
        let mut ok = false;
        for certificate in CertificateDer::pem_slice_iter(pem) {
            let Ok(certificate) = certificate else { break };
            if self.roots.add(certificate.clone()).is_ok() {
                self.certificates.push(certificate);
                ok = true;
            }
        }
        ok
    }

    pub fn len(&self) -> usize {
        self.roots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn roots(&self) -> &RootCertStore {
        &self.roots
    }

    pub fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.certificates
    }
}

// Go crypto/x509 root_linux.go.
const CERT_FILES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

fn cert_directories() -> Vec<String> {
    let mut directories = vec!["/etc/ssl/certs".to_string(), "/etc/pki/tls/certs".to_string()];
    if cfg!(target_os = "android") {
        directories.push("/system/etc/security/cacerts".into());
        directories.push("/data/misc/keychain/certs-added".into());
    }
    directories
}

/// `readUniqueDirectoryEntries`: the entries of `directory`, without
/// symlinks to files in the same directory.
fn read_unique_directory_entries(directory: &Path) -> io::Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type().map(|kind| kind.is_symlink()).unwrap_or(false) {
            if let Ok(target) = std::fs::read_link(&path) {
                if !target.to_string_lossy().contains('/') {
                    continue;
                }
            }
        }
        entries.push(path);
    }
    entries.sort();
    Ok(entries)
}

fn is_not_found(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
}

/// Go `x509.SystemCertPool` on Unix (`loadSystemRoots`), honoring
/// `SSL_CERT_FILE` and `SSL_CERT_DIR`.
pub fn system_pool() -> io::Result<Pool> {
    let mut pool = Pool::default();
    let files: Vec<String> = match std::env::var("SSL_CERT_FILE") {
        Ok(file) if !file.is_empty() => vec![file],
        _ => CERT_FILES.iter().map(|file| file.to_string()).collect(),
    };
    let mut first_error = None;
    for file in files {
        match std::fs::read(&file) {
            Ok(data) => {
                pool.append_pem(&data);
                break;
            }
            Err(error) if first_error.is_none() && !is_not_found(&error) => first_error = Some(error),
            Err(_) => {}
        }
    }
    let directories: Vec<String> = match std::env::var("SSL_CERT_DIR") {
        Ok(directories) if !directories.is_empty() => directories.split(':').map(str::to_string).collect(),
        _ => cert_directories(),
    };
    for directory in directories {
        match read_unique_directory_entries(Path::new(&directory)) {
            Ok(entries) => {
                for entry in entries {
                    if let Ok(data) = std::fs::read(entry) {
                        pool.append_pem(&data);
                    }
                }
            }
            Err(error) if first_error.is_none() && !is_not_found(&error) => first_error = Some(error),
            Err(_) => {}
        }
    }
    match first_error {
        Some(error) if pool.is_empty() => Err(error),
        _ => Ok(pool),
    }
}

/// sing-box `certificate.Store`.
pub struct Store {
    kind: String,
    system: Option<Pool>,
    certificate: String,
    certificate_paths: Vec<String>,
    certificate_directory_paths: Vec<String>,
    current: RwLock<Arc<Pool>>,
    watcher: RwLock<Option<rb_fswatch::Watcher>>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("kind", &self.kind).finish()
    }
}

impl Store {
    /// `certificate.NewStore`.
    pub fn new(options: Option<&CertificateOptions>) -> Result<Arc<Self>, CertificateError> {
        let default = CertificateOptions::default();
        let options = options.unwrap_or(&default);
        let kind = if options.store.is_empty() { STORE_SYSTEM } else { options.store.as_str() };
        let system = match kind {
            STORE_SYSTEM => Some(system_pool().map_err(|error| CertificateError(error.to_string()))?),
            STORE_MOZILLA | STORE_CHROME | STORE_NONE => None,
            _ => return Err(CertificateError(format!("unknown certificate store: {}", options.store))),
        };
        let store = Arc::new(Store {
            kind: kind.to_string(),
            system,
            certificate: options.certificate.0.join("\n"),
            certificate_paths: options.certificate_path.0.clone(),
            certificate_directory_paths: options.certificate_directory_path.0.clone(),
            current: RwLock::new(Arc::new(Pool::default())),
            watcher: RwLock::new(None),
        });
        let watch_paths: Vec<PathBuf> = store
            .certificate_paths
            .iter()
            .chain(&store.certificate_directory_paths)
            .map(|path| std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path)))
            .collect();
        if !watch_paths.is_empty() {
            let weak = Arc::downgrade(&store);
            let watcher = rb_fswatch::Watcher::new(rb_fswatch::Options {
                paths: watch_paths,
                direct: false,
                callback: Arc::new(move |_| {
                    if let Some(store) = weak.upgrade() {
                        if let Err(error) = store.update() {
                            tracing::error!("reload certificates: {error}");
                        }
                    }
                }),
                wait_timeout: None,
            })
            .map_err(|error| CertificateError(format!("fswatch: create fsnotify watcher: {error}")))?;
            *store.watcher.write().unwrap() = Some(watcher);
        }
        let pool =
            store.load().map_err(|error| CertificateError(format!("initializing certificate store: {error}")))?;
        *store.current.write().unwrap() = Arc::new(pool);
        Ok(store)
    }

    /// Starts watching the certificate files (sing-box `StartStateStart`).
    pub fn start(&self) -> Result<(), CertificateError> {
        if let Some(watcher) = self.watcher.read().unwrap().as_ref() {
            watcher.start().map_err(|error| CertificateError(error.to_string()))?;
        }
        Ok(())
    }

    pub fn close(&self) {
        if let Some(watcher) = self.watcher.write().unwrap().take() {
            watcher.close();
        }
    }

    /// `Store.Pool`: the current roots.
    pub fn pool(&self) -> Arc<Pool> {
        self.current.read().unwrap().clone()
    }

    /// `Store.StoreKind`.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    fn update(&self) -> Result<(), CertificateError> {
        let pool = self.load()?;
        *self.current.write().unwrap() = Arc::new(pool);
        Ok(())
    }

    /// `Store.load`.
    fn load(&self) -> Result<Pool, CertificateError> {
        let mut pool = self.system.clone().unwrap_or_default();
        match self.kind.as_str() {
            STORE_MOZILLA if !pool.append_pem(MOZILLA_PEM.as_bytes()) => {
                return Err(CertificateError("invalid Mozilla included certificate PEM".into()));
            }
            STORE_CHROME if !pool.append_pem(CHROME_PEM.as_bytes()) => {
                return Err(CertificateError("invalid Chrome included certificate PEM".into()));
            }
            _ => {}
        }
        if !self.certificate.is_empty() && !pool.append_pem(self.certificate.as_bytes()) {
            return Err(CertificateError("invalid certificate PEM strings".into()));
        }
        for path in &self.certificate_paths {
            let content = std::fs::read(path).map_err(|error| CertificateError(format!("open {path}: {error}")))?;
            if !pool.append_pem(&content) {
                return Err(CertificateError(format!("invalid certificate PEM file: {path}")));
            }
        }
        let mut first_error = None;
        for directory in &self.certificate_directory_paths {
            match read_unique_directory_entries(Path::new(directory)) {
                Ok(entries) => {
                    for entry in entries {
                        if let Ok(content) = std::fs::read(entry) {
                            pool.append_pem(&content);
                        }
                    }
                }
                Err(error) => {
                    if first_error.is_none() && !is_not_found(&error) {
                        first_error =
                            Some(CertificateError(format!("invalid certificate directory: {directory}: {error}")));
                    }
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(pool),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_stores() {
        for (kind, expected) in [(STORE_MOZILLA, 100), (STORE_CHROME, 50)] {
            let options = CertificateOptions { store: kind.into(), ..Default::default() };
            let store = Store::new(Some(&options)).unwrap();
            assert_eq!(store.kind(), kind);
            assert!(store.pool().len() > expected, "{kind}: {}", store.pool().len());
        }
        let options = CertificateOptions { store: STORE_NONE.into(), ..Default::default() };
        assert!(Store::new(Some(&options)).unwrap().pool().is_empty());
        let options = CertificateOptions { store: "bogus".into(), ..Default::default() };
        assert_eq!(Store::new(Some(&options)).unwrap_err().0, "unknown certificate store: bogus");
        let options = CertificateOptions {
            store: STORE_NONE.into(),
            certificate: rb_config::types::Listable(vec!["not a pem".into()]),
            ..Default::default()
        };
        assert!(Store::new(Some(&options)).unwrap_err().0.contains("invalid certificate PEM strings"));
    }

    #[test]
    fn files_reload_when_changed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ca.pem");
        let mozilla: Vec<&str> = MOZILLA_PEM.split_inclusive("-----END CERTIFICATE-----\n").collect();
        std::fs::write(&path, mozilla[0]).unwrap();
        let options = CertificateOptions {
            store: STORE_NONE.into(),
            certificate_path: rb_config::types::Listable(vec![path.to_string_lossy().into_owned()]),
            ..Default::default()
        };
        let store = Store::new(Some(&options)).unwrap();
        assert_eq!(store.pool().len(), 1);
        store.start().unwrap();
        std::fs::write(&path, mozilla[..3].concat()).unwrap();
        for _ in 0..100 {
            if store.pool().len() == 3 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
        assert_eq!(store.pool().len(), 3);
        // A broken file keeps the last good roots.
        std::fs::write(&path, "garbage").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(400));
        assert_eq!(store.pool().len(), 3);
        store.close();
    }
}
