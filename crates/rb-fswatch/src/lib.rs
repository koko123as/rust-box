//! A file watcher, mirroring github.com/sagernet/fswatch (an fsnotify
//! wrapper that sing-box uses for local rule-sets and certificate files):
//! it watches the parent directories of the paths, so a file replaced by a
//! rename is seen too, and calls back once writes to a path have been
//! quiet for the wait timeout.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use notify::event::{ModifyKind, RenameMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};

/// `fswatch.DefaultWaitTimeout`.
pub const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_millis(100);

pub type Callback = Arc<dyn Fn(&Path) + Send + Sync>;

/// `fswatch.Options`.
pub struct Options {
    /// Files (or directories) to watch; absolute paths.
    pub paths: Vec<PathBuf>,
    /// Watch the paths themselves instead of their directories (for files
    /// that are never replaced).
    pub direct: bool,
    pub callback: Callback,
    /// How long writes must be quiet before the callback; 100 ms by default.
    pub wait_timeout: Option<Duration>,
}

#[derive(Default)]
struct State {
    /// The generation of the pending callback per path.
    pending: HashMap<PathBuf, u64>,
    closed: bool,
}

/// `fswatch.Watcher`.
pub struct Watcher {
    watch_targets: Vec<PathBuf>,
    watch_paths: Arc<Vec<PathBuf>>,
    callback: Callback,
    wait_timeout: Duration,
    state: Arc<Mutex<State>>,
    watcher: Mutex<Option<RecommendedWatcher>>,
}

impl Watcher {
    /// `fswatch.NewWatcher`.
    pub fn new(options: Options) -> io::Result<Self> {
        if options.paths.is_empty() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let watch_targets = if options.direct {
            options.paths.clone()
        } else {
            let mut targets: Vec<PathBuf> = Vec::new();
            for path in &options.paths {
                let parent = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
                if !targets.contains(&parent) {
                    targets.push(parent);
                }
            }
            // As sing's fswatch: a target that is a string prefix of a
            // longer target is dropped.
            let all = targets.clone();
            targets.retain(|target| {
                let it = target.to_string_lossy();
                !all.iter().any(|other| {
                    let other = other.to_string_lossy();
                    other.len() > it.len() && other.starts_with(it.as_ref())
                })
            });
            targets
        };
        Ok(Watcher {
            watch_targets,
            watch_paths: Arc::new(options.paths),
            callback: options.callback,
            wait_timeout: options.wait_timeout.unwrap_or(DEFAULT_WAIT_TIMEOUT),
            state: Arc::new(Mutex::new(State::default())),
            watcher: Mutex::new(None),
        })
    }

    /// `Watcher.Start`.
    pub fn start(&self) -> io::Result<()> {
        let targets = self.watch_targets.clone();
        let paths = self.watch_paths.clone();
        let callback = self.callback.clone();
        let state = self.state.clone();
        let wait = self.wait_timeout;
        let mut watcher = notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
            let event = match result {
                Ok(event) => event,
                Err(error) => {
                    tracing::error!("fswatch: {error}");
                    return;
                }
            };
            let removed = matches!(event.kind, EventKind::Remove(_))
                || matches!(event.kind, EventKind::Modify(ModifyKind::Name(mode)) if mode != RenameMode::To);
            let written = matches!(event.kind, EventKind::Create(_))
                || matches!(
                    event.kind,
                    EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Any | ModifyKind::Name(RenameMode::To))
                );
            for path in &event.paths {
                if targets.contains(path) && removed {
                    tracing::error!("fswatch: watcher removed: {}", path.display());
                } else if paths.contains(path) && written {
                    schedule(&state, &callback, path.clone(), wait);
                }
            }
        })
        .map_err(|error| io::Error::other(format!("fswatch: create fsnotify watcher: {error}")))?;
        for target in &self.watch_targets {
            watcher
                .watch(target, RecursiveMode::NonRecursive)
                .map_err(|error| io::Error::other(format!("fswatch: watch {}: {error}", target.display())))?;
        }
        *self.watcher.lock().unwrap() = Some(watcher);
        Ok(())
    }

    /// `Watcher.Close`: pending callbacks are dropped.
    pub fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.pending.clear();
        drop(state);
        self.watcher.lock().unwrap().take();
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.close();
    }
}

/// `scheduleCallback` / `fireCallback`: a timer per path, restarted by each
/// event.
fn schedule(state: &Arc<Mutex<State>>, callback: &Callback, path: PathBuf, wait: Duration) {
    let generation = {
        let mut guard = state.lock().unwrap();
        if guard.closed {
            return;
        }
        let generation = guard.pending.get(&path).copied().unwrap_or(0) + 1;
        guard.pending.insert(path.clone(), generation);
        generation
    };
    let state = state.clone();
    let callback = callback.clone();
    std::thread::spawn(move || {
        std::thread::sleep(wait);
        {
            let mut guard = state.lock().unwrap();
            if guard.closed || guard.pending.get(&path) != Some(&generation) {
                return;
            }
            guard.pending.remove(&path);
        }
        callback(&path);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn wait_for(counter: &AtomicUsize, at_least: usize) -> bool {
        for _ in 0..100 {
            if counter.load(Ordering::SeqCst) >= at_least {
                return true;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        false
    }

    #[test]
    fn write_and_replace_are_seen_once_quiet() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rules.json");
        std::fs::write(&path, "a").unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let counter = count.clone();
        let watcher = Watcher::new(Options {
            paths: vec![path.clone()],
            direct: false,
            callback: Arc::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
            wait_timeout: Some(Duration::from_millis(50)),
        })
        .unwrap();
        watcher.start().unwrap();
        // Several writes in a burst give one callback.
        for content in ["b", "c", "d"] {
            std::fs::write(&path, content).unwrap();
        }
        assert!(wait_for(&count, 1));
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        // A file renamed into place is seen too.
        let staged = directory.path().join("staged.tmp");
        std::fs::write(&staged, "e").unwrap();
        std::fs::rename(&staged, &path).unwrap();
        assert!(wait_for(&count, 2));
        // Other files in the directory are not.
        std::fs::write(directory.path().join("other.json"), "x").unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(count.load(Ordering::SeqCst), 2);
        watcher.close();
        std::fs::write(&path, "f").unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}
