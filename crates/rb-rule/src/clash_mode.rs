//! The current Clash mode that `clash_mode` rule items read (sing-box
//! `experimental/clashmode.Manager`, without its persistence and DNS cache
//! flush, which its owner does).

use std::sync::RwLock;

#[derive(Debug)]
pub struct ClashMode {
    mode: RwLock<String>,
    list: Vec<String>,
}

impl ClashMode {
    /// `clashmode.NewManager`: the default mode is `Rule` when empty, and is
    /// put in front of the list when the rules do not name it.
    pub fn new(default_mode: &str, mut list: Vec<String>) -> Self {
        let default_mode = if default_mode.is_empty() { "Rule" } else { default_mode };
        if !list.iter().any(|mode| mode == default_mode) {
            list.insert(0, default_mode.to_string());
        }
        ClashMode { mode: RwLock::new(default_mode.to_string()), list }
    }

    pub fn mode(&self) -> String {
        self.mode.read().unwrap().clone()
    }

    pub fn list(&self) -> &[String] {
        &self.list
    }

    /// The listed mode a name means: itself, else the first one equal to it
    /// ignoring case.
    pub fn find(&self, name: &str) -> Option<&str> {
        self.list
            .iter()
            .find(|mode| *mode == name)
            .or_else(|| self.list.iter().find(|mode| mode.eq_ignore_ascii_case(name)))
            .map(String::as_str)
    }

    /// Restores a stored mode when the list has it (ignoring case), as
    /// `Manager.Start` does with the cache file's mode.
    pub fn restore(&self, stored: &str) {
        if self.list.iter().any(|mode| mode.eq_ignore_ascii_case(stored)) {
            *self.mode.write().unwrap() = stored.to_string();
        }
    }

    /// `Manager.SetMode` without its side effects: the new mode when it
    /// changed, `None` for an unknown or unchanged mode.
    pub fn set(&self, name: &str) -> Option<String> {
        let mode = self.find(name)?.to_string();
        let mut current = self.mode.write().unwrap();
        if *current == mode {
            return None;
        }
        *current = mode.clone();
        Some(mode)
    }

    /// Whether the current mode is `mode`, ignoring case (`ClashModeItem`).
    pub fn is(&self, mode: &str) -> bool {
        self.mode.read().unwrap().eq_ignore_ascii_case(mode)
    }
}
