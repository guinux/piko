//! The lazy-loading primitive.
//!
//! Opening a local database yields every package's name and version from directory names
//! alone. The `desc`, `files` and `mtree` files behind each package are read only when a
//! caller asks for them. The result, success *or* failure, is cached.
//!
//! Caching the failure is deliberate, and matches libalpm's sticky `INFRQ_ERROR` bit: a
//! corrupt entry is not re-read and re-parsed on every access. piko differs in what happens
//! afterwards. libalpm's accessors swallow the error and return an empty list, so a package
//! with an unreadable `desc` looks exactly like a package with no dependencies. For a package
//! manager that is a dangerous lie, so [`Lazy`] hands the error back every time.

use std::{fmt, sync::OnceLock};

use crate::error::{Error, SharedError};

/// A value loaded at most once, on first access.
///
/// `Lazy<T>` is [`Sync`] whenever `T` is. Reads after the first are a plain atomic load, so
/// a `&LocalDatabase` can be shared across threads and its packages loaded in parallel
/// without a lock.
///
/// The error is stored as a [`SharedError`], because [`Error`] wraps [`std::io::Error`] and
/// so cannot be [`Clone`]. An [`std::sync::Arc`] makes handing the same failure out
/// repeatedly cheap.
pub struct Lazy<T> {
    slot: OnceLock<Result<T, SharedError>>,
}

impl<T> Lazy<T> {
    /// Creates an unloaded slot.
    #[must_use]
    pub const fn new() -> Self {
        Self { slot: OnceLock::new() }
    }

    /// Returns the loaded value, running `load` first if this is the first access.
    ///
    /// If `load` fails, the failure is cached and returned by every later call. `load` is
    /// not retried.
    ///
    /// Under contention two threads may both run `load`, since [`OnceLock::get_or_init`]
    /// gives no exclusion guarantee, and one result is discarded. That is harmless here:
    /// every loader is a pure read of an immutable file.
    ///
    /// # Errors
    ///
    /// Whatever `load` returned on the first call, as a [`SharedError`].
    pub fn get_or_load(&self, load: impl FnOnce() -> Result<T, Error>) -> Result<&T, SharedError> {
        self.slot
            .get_or_init(|| load().map_err(SharedError::new))
            .as_ref()
            .map_err(SharedError::clone)
    }

    /// Returns the loaded value if it has already been loaded, without loading it.
    ///
    /// `None` means "not yet accessed", which is distinct from "accessed and failed".
    #[must_use]
    pub fn get(&self) -> Option<Result<&T, SharedError>> {
        self.slot.get().map(|result| result.as_ref().map_err(SharedError::clone))
    }

    /// Whether this slot has been loaded, successfully or not.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.slot.get().is_some()
    }
}

impl<T> Default for Lazy<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Shows the load state without forcing a load, so debugging a database does not silently
/// read the whole of it.
impl<T: fmt::Debug> fmt::Debug for Lazy<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.slot.get() {
            None => f.write_str("Lazy(<unloaded>)"),
            Some(Ok(value)) => f.debug_tuple("Lazy").field(value).finish(),
            Some(Err(error)) => f.debug_tuple("Lazy").field(&format_args!("<{error}>")).finish(),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failing assertion in a test should abort it loudly"
)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::error::IoAction;

    fn an_error() -> Error {
        Error::io(
            "/nonexistent",
            IoAction::Open,
            std::io::Error::from(std::io::ErrorKind::NotFound),
        )
    }

    #[test]
    fn is_send_and_sync() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Lazy<String>>();
        assert_send_sync::<Lazy<Vec<u8>>>();
    }

    /// A file is read once, however often it is asked for.
    #[test]
    fn loads_at_most_once() {
        let calls = AtomicUsize::new(0);
        let lazy = Lazy::new();

        for _ in 0..10 {
            let value = lazy
                .get_or_load(|| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok("loaded".to_owned())
                })
                .unwrap();
            assert_eq!(value, "loaded");
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A broken entry must not be re-read on every access. It must keep reporting the
    /// failure instead of degrading into an empty success.
    #[test]
    fn caches_the_failure_and_does_not_retry() {
        let calls = AtomicUsize::new(0);
        let lazy: Lazy<String> = Lazy::new();

        for _ in 0..5 {
            let error = lazy
                .get_or_load(|| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(an_error())
                })
                .unwrap_err();
            assert!(error.to_string().contains("nonexistent"));
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1, "a failed load must not be retried");
    }

    /// The cached error is the same allocation each time, not a re-created lookalike.
    #[test]
    fn returns_the_identical_error_each_time() {
        let lazy: Lazy<String> = Lazy::new();
        let first = lazy.get_or_load(|| Err(an_error())).unwrap_err();
        let second = lazy.get_or_load(|| Err(an_error())).unwrap_err();
        assert!(SharedError::ptr_eq(&first, &second));
    }

    #[test]
    fn get_distinguishes_unloaded_from_failed() {
        let lazy: Lazy<String> = Lazy::new();
        assert!(lazy.get().is_none());
        assert!(!lazy.is_loaded());

        let _ = lazy.get_or_load(|| Err(an_error()));

        assert!(lazy.is_loaded());
        assert!(matches!(lazy.get(), Some(Err(_))));
    }

    /// Concurrent readers must observe one shared value, not per-thread copies.
    #[test]
    fn concurrent_readers_share_one_value() {
        let lazy = Lazy::new();
        let calls = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let value = lazy
                            .get_or_load(|| {
                                calls.fetch_add(1, Ordering::SeqCst);
                                Ok(vec![1_u8, 2, 3])
                            })
                            .unwrap();
                        // A raw pointer is not `Send`; compare addresses instead.
                        std::ptr::from_ref(value) as usize
                    })
                })
                .collect();

            let pointers: Vec<_> =
                handles.into_iter().map(|handle| handle.join().unwrap()).collect();

            let first = pointers.first().copied().unwrap();
            assert!(
                pointers.iter().all(|&pointer| pointer == first),
                "every thread must observe the same cached value"
            );
        });

        // `get_or_init` may run the initializer on more than one thread under contention.
        // Exactly one result is ever published.
        assert!(calls.load(Ordering::SeqCst) >= 1);
    }

    /// `Debug` must not trigger a load, or debugging a database would read all of it.
    #[test]
    fn debug_does_not_force_a_load() {
        let lazy: Lazy<String> = Lazy::new();
        assert_eq!(format!("{lazy:?}"), "Lazy(<unloaded>)");
        assert!(!lazy.is_loaded(), "formatting must not load");

        let _ = lazy.get_or_load(|| Ok("hi".to_owned()));
        assert_eq!(format!("{lazy:?}"), "Lazy(\"hi\")");
    }

    #[test]
    fn debug_renders_a_cached_failure() {
        let lazy: Lazy<String> = Lazy::new();
        let _ = lazy.get_or_load(|| Err(an_error()));
        assert!(format!("{lazy:?}").contains("nonexistent"));
    }
}
