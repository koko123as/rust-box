//! The log entries `/logs` streams (sing-box `log.ObservableFactory`): a
//! `tracing` layer that hands every event to the subscribers.

use std::fmt::Write as _;
use std::sync::OnceLock;

use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// One entry: its sing-box level (0 panic … 6 trace) and message.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: u8,
    pub message: String,
}

pub const LEVEL_PANIC: u8 = 0;
pub const LEVEL_FATAL: u8 = 1;
pub const LEVEL_ERROR: u8 = 2;
pub const LEVEL_WARN: u8 = 3;
pub const LEVEL_INFO: u8 = 4;
pub const LEVEL_DEBUG: u8 = 5;
pub const LEVEL_TRACE: u8 = 6;

/// `log.ParseLevel`.
pub fn parse_level(text: &str) -> Option<u8> {
    match text {
        "panic" => Some(LEVEL_PANIC),
        "fatal" => Some(LEVEL_FATAL),
        "error" => Some(LEVEL_ERROR),
        "warn" | "warning" => Some(LEVEL_WARN),
        "info" => Some(LEVEL_INFO),
        "debug" => Some(LEVEL_DEBUG),
        "trace" => Some(LEVEL_TRACE),
        _ => None,
    }
}

/// `log.FormatLevel`.
pub fn format_level(level: u8) -> &'static str {
    match level {
        LEVEL_PANIC => "panic",
        LEVEL_FATAL => "fatal",
        LEVEL_ERROR => "error",
        LEVEL_WARN => "warn",
        LEVEL_INFO => "info",
        LEVEL_DEBUG => "debug",
        _ => "trace",
    }
}

fn hub() -> &'static broadcast::Sender<LogEntry> {
    static HUB: OnceLock<broadcast::Sender<LogEntry>> = OnceLock::new();
    HUB.get_or_init(|| broadcast::channel(1024).0)
}

/// A new subscription to the log entries.
pub fn subscribe() -> broadcast::Receiver<LogEntry> {
    hub().subscribe()
}

/// Sends an entry to the subscribers (for tests and non-`tracing` sources).
pub fn publish(entry: LogEntry) {
    let _ = hub().send(entry);
}

/// The layer to add to the `tracing` subscriber.
#[derive(Debug, Default, Clone, Copy)]
pub struct ObservableLayer;

struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0.push_str(value);
        } else {
            let _ = write!(self.0, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
}

impl<S: Subscriber> Layer<S> for ObservableLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        if hub().receiver_count() == 0 {
            return;
        }
        let level = match *event.metadata().level() {
            Level::ERROR => LEVEL_ERROR,
            Level::WARN => LEVEL_WARN,
            Level::INFO => LEVEL_INFO,
            Level::DEBUG => LEVEL_DEBUG,
            Level::TRACE => LEVEL_TRACE,
        };
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        publish(LogEntry { level, message: visitor.0 });
    }
}
