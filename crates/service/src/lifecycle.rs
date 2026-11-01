//! Key-version lifecycle metadata.
//!
//! # Responsibility scope
//!
//! [`KeyLifecycle`] carries the non-secret timestamps of one key version:
//! when it was created and, optionally, the window in which it should be used
//! and the instant from which it may be destroyed. It is returned by
//! [`CryptoOperation::DescribeLifecycle`](crate::CryptoOperation::DescribeLifecycle)
//! as [`CryptoResponse::Lifecycle`](crate::CryptoResponse::Lifecycle).
//!
//! The record is additive to [`KeyMetadata`](crate::KeyMetadata) (which is
//! unchanged) and *advisory*: a provider reports it, callers decide what to
//! do with it. [`InMemoryProvider`](crate::InMemoryProvider) stamps
//! `created_at_unix_ms` when a version is generated or rotated in, never sets
//! the optional bounds, and enforces none of them.
//!
//! All instants are Unix epoch milliseconds (UTC, leap seconds ignored).
//!
//! # Key types
//!
//! - [`KeyLifecycle`]: `Copy` timestamp record, `#[non_exhaustive]`, built
//!   with [`KeyLifecycle::new`] and the `with_*` methods.
//!
//! # Concurrency
//!
//! Plain `Copy` data (`Send + Sync`); no interior mutability.
//!
//! # Errors
//!
//! Building and querying a [`KeyLifecycle`] is infallible and panic-free; all
//! comparisons are plain integer comparisons. Reading the system clock (the
//! crate-internal default clock of `InMemoryProvider`) is fallible: a clock
//! before the Unix epoch, or beyond `u64::MAX` milliseconds, yields no time,
//! which the provider reports as
//! [`CryptoServiceError::Unavailable`](crate::CryptoServiceError::Unavailable).
//! On targets without a system clock, inject one with
//! [`InMemoryProvider::with_clock`](crate::InMemoryProvider::with_clock).
//!
//! # Examples
//!
//! ```
//! use crypt_guard_service::KeyLifecycle;
//!
//! let lifecycle = KeyLifecycle::new(1_700_000_000_000)
//!     .with_not_before(1_700_000_000_000)
//!     .with_not_after(1_700_086_399_999)
//!     .with_destroy_after(1_702_678_400_000);
//!
//! assert!(lifecycle.is_within_validity(1_700_000_000_000));
//! assert!(lifecycle.is_within_validity(1_700_086_399_999));
//! assert!(!lifecycle.is_within_validity(1_700_086_400_000));
//! assert!(!lifecycle.is_destruction_due(1_700_086_400_000));
//! assert!(lifecycle.is_destruction_due(1_702_678_400_000));
//! ```

// Panic-freedom contract: see SECURITY.md
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::time::{SystemTime, UNIX_EPOCH};

/// Non-secret lifecycle timestamps of one key version.
///
/// All instants are Unix epoch milliseconds. `#[non_exhaustive]`: build it
/// with [`KeyLifecycle::new`] and the `with_*` methods; fields may be added in
/// a minor release.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KeyLifecycle {
    /// When this version was created.
    pub created_at_unix_ms: u64,
    /// Earliest instant (inclusive) at which this version should be used, if
    /// restricted.
    pub not_before_unix_ms: Option<u64>,
    /// Last instant (inclusive) at which this version should be used, if
    /// restricted.
    pub not_after_unix_ms: Option<u64>,
    /// Earliest instant (inclusive) from which this version may be destroyed,
    /// if scheduled.
    pub destroy_after_unix_ms: Option<u64>,
}

impl KeyLifecycle {
    /// A version created at `created_at_unix_ms`, with no validity window and
    /// no scheduled destruction.
    pub const fn new(created_at_unix_ms: u64) -> Self {
        Self {
            created_at_unix_ms,
            not_before_unix_ms: None,
            not_after_unix_ms: None,
            destroy_after_unix_ms: None,
        }
    }

    /// This record with `not_before_unix_ms` set.
    pub const fn with_not_before(mut self, unix_ms: u64) -> Self {
        self.not_before_unix_ms = Some(unix_ms);
        self
    }

    /// This record with `not_after_unix_ms` set.
    pub const fn with_not_after(mut self, unix_ms: u64) -> Self {
        self.not_after_unix_ms = Some(unix_ms);
        self
    }

    /// This record with `destroy_after_unix_ms` set.
    pub const fn with_destroy_after(mut self, unix_ms: u64) -> Self {
        self.destroy_after_unix_ms = Some(unix_ms);
        self
    }

    /// Whether `now_unix_ms` lies in the (inclusive) validity window
    /// `not_before_unix_ms..=not_after_unix_ms`. A missing bound is
    /// unbounded. Only the window is checked, not the key state.
    pub const fn is_within_validity(&self, now_unix_ms: u64) -> bool {
        let started = match self.not_before_unix_ms {
            Some(not_before) => now_unix_ms >= not_before,
            None => true,
        };
        let not_expired = match self.not_after_unix_ms {
            Some(not_after) => now_unix_ms <= not_after,
            None => true,
        };
        started && not_expired
    }

    /// Whether destruction is scheduled and `now_unix_ms` has reached
    /// `destroy_after_unix_ms`.
    pub const fn is_destruction_due(&self, now_unix_ms: u64) -> bool {
        match self.destroy_after_unix_ms {
            Some(destroy_after) => now_unix_ms >= destroy_after,
            None => false,
        }
    }
}

/// Current system time in Unix epoch milliseconds, or `None` when the clock
/// reads before the epoch or beyond `u64::MAX` milliseconds.
///
/// Default clock of `InMemoryProvider`. Never panics on targets with a system
/// clock (`std` panics in `SystemTime::now` only where no clock exists, e.g.
/// `wasm32-unknown-unknown`; inject a clock there).
pub(crate) fn system_unix_ms() -> Option<u64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(elapsed.as_millis()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_only_a_creation_time() {
        let lifecycle = KeyLifecycle::new(42);
        assert_eq!(lifecycle.created_at_unix_ms, 42);
        assert_eq!(lifecycle.not_before_unix_ms, None);
        assert_eq!(lifecycle.not_after_unix_ms, None);
        assert_eq!(lifecycle.destroy_after_unix_ms, None);
        assert!(lifecycle.is_within_validity(0));
        assert!(lifecycle.is_within_validity(u64::MAX));
        assert!(!lifecycle.is_destruction_due(u64::MAX));
    }

    #[test]
    fn builders_set_exactly_their_field() {
        let base = KeyLifecycle::new(10);
        assert_eq!(base.with_not_before(1).not_before_unix_ms, Some(1));
        assert_eq!(base.with_not_before(1).not_after_unix_ms, None);
        assert_eq!(base.with_not_after(2).not_after_unix_ms, Some(2));
        assert_eq!(base.with_not_after(2).destroy_after_unix_ms, None);
        assert_eq!(base.with_destroy_after(3).destroy_after_unix_ms, Some(3));
        assert_eq!(base.with_destroy_after(3).not_before_unix_ms, None);
        // Builders do not touch the creation time, and the last call wins.
        let built = base.with_not_after(2).with_not_after(5);
        assert_eq!(built.created_at_unix_ms, 10);
        assert_eq!(built.not_after_unix_ms, Some(5));
    }

    #[test]
    fn validity_window_is_inclusive_on_both_ends() {
        let lifecycle = KeyLifecycle::new(0)
            .with_not_before(100)
            .with_not_after(200);
        assert!(!lifecycle.is_within_validity(99));
        assert!(lifecycle.is_within_validity(100));
        assert!(lifecycle.is_within_validity(150));
        assert!(lifecycle.is_within_validity(200));
        assert!(!lifecycle.is_within_validity(201));

        let open_end = KeyLifecycle::new(0).with_not_before(100);
        assert!(open_end.is_within_validity(u64::MAX));
        let open_start = KeyLifecycle::new(0).with_not_after(200);
        assert!(open_start.is_within_validity(0));
    }

    #[test]
    fn destruction_is_due_from_the_scheduled_instant() {
        let lifecycle = KeyLifecycle::new(0).with_destroy_after(1_000);
        assert!(!lifecycle.is_destruction_due(999));
        assert!(lifecycle.is_destruction_due(1_000));
        assert!(lifecycle.is_destruction_due(u64::MAX));
    }

    #[test]
    fn system_clock_reads_a_plausible_time() {
        // 2020-09-13T12:26:40Z; any working clock is past it.
        let now = system_unix_ms().expect("system clock after the Unix epoch");
        assert!(now > 1_600_000_000_000);
    }
}
