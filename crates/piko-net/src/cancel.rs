//! A cooperative cancellation flag for an in-progress download.
//!
//! `AtomicFile` unlinks an uncommitted temporary on `Drop`, but that only runs when the
//! process unwinds normally. The OS's default `SIGINT` disposition does not unwind. [`Cancel`]
//! is the seam a caller (typically a signal handler) uses to ask a download to stop cleanly
//! instead. [`crate::refresh::stream_bounded`] checks it once per chunk, so a request lands
//! within one 64 KiB read rather than only between whole files. A size bound is enforced the
//! same way, as the stream goes rather than after it finishes.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// A flag shared between whoever might request cancellation and a download in progress.
///
/// Cheap to [`Clone`] — every clone shares the same underlying flag.
#[derive(Clone, Debug, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    /// A flag that has not been requested.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Idempotent.
    pub fn request(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_flag_is_not_requested() {
        assert!(!Cancel::new().is_requested());
    }

    #[test]
    fn a_request_is_visible_through_a_clone() {
        let cancel = Cancel::new();
        let clone = cancel.clone();
        cancel.request();
        assert!(clone.is_requested());
    }
}
