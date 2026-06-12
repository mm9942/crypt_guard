//! Tracing-based logging surface for `crypt_guard`.
//!
//! # Responsibility scope
//! This module owns the `init_log` helper function that initializes a
//! `tracing_subscriber` once in the binary entry point, and the legacy
//! `initialize_logger` shim that the `activate_log` proc-macro attribute emits.
//!
//! The old `Lazy<Mutex<Log>>` global, `Log` struct, `write_log_file`, and
//! `append_log` string-buffer machinery have been removed. All diagnostic output
//! now flows through `tracing` structured events to whatever subscriber is installed.
//!
//! # API surface preserved for backward compatibility
//! The module still exports `LOGGER` (now a no-op unit value) and `initialize_logger`
//! so that existing call sites compiled against the old API continue to compile.
//! They emit a tracing `info!` event instead of writing to a string buffer.
//!
//! # Key types exported
//! - `initialize_logger` — one-shot tracing subscriber init (called by `activate_log!` expansion)
//! - `init_log` — ergonomic `tracing::Level`-typed initializer for binary entry points
//! - `LOGGER` — compatibility shim (zero-state; does nothing)
//!
//! # Concurrency
//! No global mutable state. Tracing uses lock-free internal queues.
//!
//! # Errors
//! `init_log` is infallible; it ignores the error from `try_init` when a subscriber
//! is already registered (e.g. in tests that call init multiple times).
//!
//! # Examples
//! ```rust,no_run
//! use crypt_guard::log::init_log;
//! init_log(tracing::Level::INFO);
//! tracing::info!(phase = "startup", "crypt_guard initialized");
//! ```

use std::path::PathBuf;
use tracing::Level;
use tracing_subscriber::{fmt, EnvFilter};
use tracing_subscriber::prelude::*;

// ── Compatibility shim ────────────────────────────────────────────────────────

/// Legacy compatibility stub.
///
/// # Description
/// Previously a `Lazy<Mutex<Log>>`; now a zero-size unit type. Retained so that code
/// that imports `crypt_guard::log::LOGGER` or references it in `log_activity!` macro
/// expansions still compiles. No locking, no string buffer, no I/O.
///
/// Any code that previously called `LOGGER.lock()…append_log(…)` should migrate to
/// using `tracing::info!(…)` directly, or let the `log_activity!` macro handle it.
pub struct LoggerCompat;

/// Global logger compatibility shim — zero state, never locks.
///
/// # Description
/// Replaces the old `Lazy<Mutex<Log>>`. Retained for source compatibility only.
pub static LOGGER: LoggerCompat = LoggerCompat;

impl LoggerCompat {
    /// No-op compatibility method. Logs a tracing event instead of buffering.
    ///
    /// # Arguments
    /// - `process` (`&str`): activity name / phase label.
    /// - `detail` (`&str`): detail string.
    ///
    /// # Returns
    /// `Ok(())`.
    pub fn append_log(&self, process: &str, detail: &str) -> Result<(), crate::error::CryptError> {
        tracing::info!(phase = %process, detail = %detail, "crypt_guard activity");
        Ok(())
    }

    /// No-op compatibility method for the `write_log!` macro expansion.
    ///
    /// # Returns
    /// `Ok(())`.
    pub fn write_log_file(&self) -> Result<(), crate::error::CryptError> {
        // Previously flushed the string buffer; now a no-op.
        Ok(())
    }

    /// No-op `lock()` compatibility shim.
    ///
    /// # Returns
    /// `Ok(&LoggerCompat)` — always succeeds; no actual lock is held.
    pub fn lock(&self) -> Result<&Self, std::convert::Infallible> {
        Ok(self)
    }
}

// ── Initializer ────────────────────────────────────────────────────────────────

/// Initialize the `tracing_subscriber` for binary entry points.
///
/// # Description
/// Sets up a `fmt` subscriber writing to stdout at the requested level. If a subscriber
/// is already registered (e.g. in test harnesses), the error is silently ignored.
///
/// Call this once at the top of `main` before spawning any async tasks.
///
/// # Arguments
/// - `level` (`tracing::Level`): the minimum event level to emit
///   (`TRACE`, `DEBUG`, `INFO`, `WARN`, or `ERROR`).
///
/// # Returns
/// Nothing. Infallible; errors from a double-init are silently discarded.
///
/// # Concurrency
/// May be called from any thread. Only the first call has any effect.
///
/// # Examples
/// ```rust,no_run
/// crypt_guard::log::init_log(tracing::Level::INFO);
/// ```
pub fn init_log(level: Level) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.as_str()));
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

/// Initialize the logger from a file path — called by the `activate_log` proc-macro.
///
/// # Description
/// Sets up a file-backed `tracing_appender` subscriber that writes structured events
/// to the given path. If a subscriber is already registered, the error is silently
/// ignored (subsequent log events will route to whichever subscriber was installed first).
///
/// # Arguments
/// - `log_file` (`PathBuf`): path to the log file. Parent directories will be created.
///
/// # Returns
/// Nothing. Infallible.
///
/// # Concurrency
/// Same as `init_log`.
///
/// # Examples
/// ```rust,no_run
/// crypt_guard::log::initialize_logger(std::path::PathBuf::from("./crypt.log"));
/// ```
pub fn initialize_logger(log_file: PathBuf) {
    if let (Some(parent), Some(file_name)) = (
        log_file.parent(),
        log_file.file_name().and_then(|s| s.to_str()),
    ) {
        let _ = std::fs::create_dir_all(parent);
        let appender = tracing_appender::rolling::never(parent, file_name);
        let subscriber = tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_ansi(false)
                    .with_target(false)
                    .without_time()
                    .with_level(false)
                    .with_writer(appender),
            );
        // Ignore error if a subscriber is already installed.
        let _ = tracing::subscriber::set_global_default(subscriber);
    } else {
        // Fall back to a basic stdout subscriber.
        init_log(Level::INFO);
    }
}
