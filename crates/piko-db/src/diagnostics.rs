//! A bounded collector for scan diagnostics.
//!
//! Diagnostics are the one part of opening a database whose size an attacker controls without
//! the package count growing alongside it. [`Limits::max_entries`] bounds packages and
//! [`Limits::repo_max_packages`] bounds archive members. Neither bound applies to a directory
//! of a million badly-named entries, or an archive of a million misshapen members: either one
//! yields **zero** packages and a million diagnostics.
//!
//! Overflow is deliberately not an error. A database whose packages are all readable must
//! stay readable no matter how much junk sits next to them. [`Sink`] keeps the first `max`
//! diagnostics and counts the rest. The count is surfaced through `diagnostics_dropped`
//! rather than hidden, so a caller cannot mistake a truncated result for a complete one.

use crate::limits::Limits;

/// Collects at most [`Limits::max_diagnostics`] items, counting the overflow.
#[derive(Debug)]
pub(crate) struct Sink<T> {
    collected: Vec<T>,
    dropped: usize,
    max: usize,
}

impl<T> Sink<T> {
    /// Creates a sink bounded by `limits`.
    pub(crate) const fn new(limits: &Limits) -> Self {
        Self { collected: Vec::new(), dropped: 0, max: limits.max_diagnostics }
    }

    /// Records `diagnostic`, or counts it as dropped if the bound is already reached.
    ///
    /// `push` takes a closure rather than a value. A caller that would need to allocate
    /// (cloning a path, formatting a name) to build the diagnostic then does not pay for one
    /// that is about to be discarded. That flood case is exactly what this bound exists for.
    pub(crate) fn push(&mut self, diagnostic: impl FnOnce() -> T) {
        if self.collected.len() >= self.max {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.collected.push(diagnostic());
    }

    /// The collected diagnostics, and how many more were dropped.
    pub(crate) fn finish(self) -> (Box<[T]>, usize) {
        (self.collected.into_boxed_slice(), self.dropped)
    }

    /// The number of diagnostics that were counted but not stored.
    ///
    /// Production code reads this through [`Self::finish`]; this exists for tests that need
    /// the count without consuming the sink.
    #[cfg(test)]
    pub(crate) const fn dropped(&self) -> usize {
        self.dropped
    }

    /// What has been collected so far, for tests that inspect a sink mid-flight.
    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[T] {
        &self.collected
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

    fn sink_with_max(max: usize) -> Sink<usize> {
        Sink::new(&Limits { max_diagnostics: max, ..Limits::default() })
    }

    #[test]
    fn collects_everything_below_the_bound() {
        let mut sink = sink_with_max(10);
        for index in 0..5 {
            sink.push(|| index);
        }

        let (collected, dropped) = sink.finish();
        assert_eq!(&*collected, [0, 1, 2, 3, 4]);
        assert_eq!(dropped, 0);
    }

    /// The flood case: the first `max` items are kept. The rest are counted. The open still
    /// succeeds.
    #[test]
    fn keeps_the_first_max_and_counts_the_rest() {
        let mut sink = sink_with_max(3);
        for index in 0..100 {
            sink.push(|| index);
        }

        let (collected, dropped) = sink.finish();
        assert_eq!(&*collected, [0, 1, 2], "the first ones must be the ones kept");
        assert_eq!(dropped, 97);
    }

    /// The reason `push` takes a closure: a dropped diagnostic must not pay the allocation
    /// building it would have needed.
    #[test]
    fn a_dropped_diagnostic_is_never_constructed() {
        let mut sink = sink_with_max(1);
        let mut built = 0_usize;

        for _ in 0..10 {
            sink.push(|| {
                built = built.saturating_add(1);
                0_usize
            });
        }

        assert_eq!(built, 1, "only the diagnostic that was actually stored may be built");
        assert_eq!(sink.dropped(), 9);
    }

    #[test]
    fn a_zero_bound_stores_nothing_but_still_counts() {
        let mut sink = sink_with_max(0);
        sink.push(|| 1_usize);

        assert!(sink.as_slice().is_empty());
        let (collected, dropped) = sink.finish();
        assert!(collected.is_empty());
        assert_eq!(dropped, 1);
    }
}
