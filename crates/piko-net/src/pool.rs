//! A fixed-size worker pool for running transfers concurrently.
//!
//! This is deliberately tiny and deliberately not a dependency. `std::thread::scope` plus an
//! [`AtomicUsize`] cursor is the whole mechanism. Workers borrow the input rather than owning
//! it, so nothing here needs `'static`, an `Arc`, or a channel. A download pool is a handful of
//! threads doing blocking I/O, the shape an async runtime is worst at paying for.
//!
//! # Why there is no `Mutex`
//!
//! The two pieces of shared mutable state are the queue cursor and the results. The cursor is
//! an [`AtomicUsize`] advanced with `fetch_add`. This is what makes "each item is claimed by
//! exactly one worker" true without a lock. The results are a `Vec<OnceLock<R>>`, one cell per
//! item, each written at most once by whichever worker claimed that index.
//!
//! That choice also removes the need for an `unwrap` the lint wall would refuse. An empty cell
//! at the end can only mean its item was never claimed, which can only mean the run was
//! cancelled before a worker reached it. The empty case has a real answer, not an
//! unreachable-in-theory one.

use std::sync::{
    OnceLock,
    atomic::{AtomicUsize, Ordering},
};

use crate::cancel::Cancel;

/// One item claimed by one worker.
///
/// Bundled rather than passed as three bare values, the same way `refresh`'s own `Target` and
/// `Controls` are. `index` and `worker` are both `usize` and mean entirely different things.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Job<'a, T> {
    /// The item's position in `items` — the slot its result lands in.
    pub(crate) index: usize,
    /// The item itself.
    pub(crate) item: &'a T,
    /// Which worker claimed it, counted from zero. What mirror spreading keys off.
    pub(crate) worker: usize,
}

/// Runs `task` over `items`, at most `workers` at a time, and returns one result per item, in
/// `items` order, regardless of how the transfers actually finished.
///
/// `schedule` is the order a free worker claims items in — the caller's scheduling policy
/// (largest-first, for downloads), expressed as indices into `items`. It decides when an item
/// runs, never where its result lands. The returned vector is indexed by the item's original
/// position, so a caller's reporting order is independent of its scheduling order.
///
/// `task` receives a [`Job`]: the item, its index, and which worker claimed it. The worker
/// index is what lets a caller spread work across mirrors without a semaphore. See
/// [`crate::Concurrency::servers_for`].
///
/// `cancel` is checked before a worker claims each item, so a cancelled run stops promptly
/// rather than draining the queue. Items no worker ever claimed come back as `on_cancel()`.
///
/// With `workers <= 1`, nothing is spawned. Everything runs inline on the calling thread. This
/// is the path `ParallelDownloads = 1` takes, and the reason that setting behaves exactly as a
/// serial downloader does.
pub(crate) fn run<T, R>(
    items: &[T],
    schedule: &[usize],
    workers: usize,
    cancel: &Cancel,
    task: impl Fn(Job<'_, T>) -> R + Sync,
    on_cancel: impl Fn() -> R + Sync,
) -> Vec<R>
where
    T: Sync,
    R: Send + Sync,
{
    let results: Vec<OnceLock<R>> = items.iter().map(|_| OnceLock::new()).collect();
    let cursor = AtomicUsize::new(0);

    // One worker's whole life: claim the next scheduled index, run it, and repeat until the
    // queue is empty or the run is cancelled.
    let drain = |worker: usize| {
        loop {
            if cancel.is_requested() {
                return;
            }
            let next = cursor.fetch_add(1, Ordering::Relaxed);
            let Some(&index) = schedule.get(next) else {
                return;
            };
            if let (Some(item), Some(slot)) = (items.get(index), results.get(index)) {
                // `set` can only fail if two workers claimed one index, which `fetch_add`
                // prevents. Nothing useful could be done with the returned value anyway.
                let _ = slot.set(task(Job { index, item, worker }));
            }
        }
    };

    if workers <= 1 {
        drain(0);
    } else {
        std::thread::scope(|scope| {
            // The caller's own thread is worker 0, so only the others are spawned.
            for worker in 1..workers {
                let drain = &drain;
                scope.spawn(move || drain(worker));
            }
            drain(0);
        });
    }

    results.into_iter().map(|slot| slot.into_inner().unwrap_or_else(&on_cancel)).collect()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "a test that cannot fail loudly is not a test"
)]
mod tests {
    use super::*;

    /// The scheduling order decides what runs first; it must not decide where results land.
    #[test]
    fn results_come_back_in_item_order_not_schedule_order() {
        let items = vec![10_u32, 20, 30, 40];
        let schedule = vec![3, 1, 0, 2];
        let cancel = Cancel::new();
        let out = run(&items, &schedule, 3, &cancel, |job| *job.item * 2, || 0);
        assert_eq!(out, vec![20, 40, 60, 80]);
    }

    #[test]
    fn a_single_worker_runs_everything_inline() {
        let items = vec![1_u32, 2, 3];
        let schedule = vec![0, 1, 2];
        let cancel = Cancel::new();
        let here = std::thread::current().id();
        let out = run(
            &items,
            &schedule,
            1,
            &cancel,
            |job| (*job.item, std::thread::current().id()),
            || (0, here),
        );
        for (_, id) in &out {
            assert_eq!(*id, here, "a single worker must not spawn a thread");
        }
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn every_item_runs_exactly_once() {
        let items: Vec<usize> = (0..64).collect();
        let schedule: Vec<usize> = (0..64).collect();
        let cancel = Cancel::new();
        let seen: Vec<AtomicUsize> = (0..64).map(|_| AtomicUsize::new(0)).collect();
        let out = run(
            &items,
            &schedule,
            8,
            &cancel,
            |job| {
                seen[*job.item].fetch_add(1, Ordering::Relaxed);
                assert_eq!(job.index, *job.item, "the index must address the item it was given");
                *job.item
            },
            || usize::MAX,
        );
        assert_eq!(out, items);
        for counter in &seen {
            assert_eq!(counter.load(Ordering::Relaxed), 1);
        }
    }

    /// A cancelled run stops claiming work, and the items it never reached say so rather than
    /// silently reporting a value nobody computed.
    #[test]
    fn a_cancelled_run_reports_the_items_it_never_claimed() {
        let items: Vec<usize> = (0..32).collect();
        let schedule: Vec<usize> = (0..32).collect();
        let cancel = Cancel::new();
        let out = run(
            &items,
            &schedule,
            1,
            &cancel,
            |job| {
                if *job.item == 3 {
                    cancel.request();
                }
                *job.item
            },
            || usize::MAX,
        );
        assert_eq!(out.get(0..4).unwrap(), [0, 1, 2, 3], "what ran still reports its result");
        assert!(
            out.get(4..).unwrap().iter().all(|value| *value == usize::MAX),
            "everything after the cancellation is reported as unclaimed"
        );
    }

    /// A worker index is handed to the task, since that is what mirror spreading keys off.
    #[test]
    fn workers_are_numbered_from_zero() {
        let items: Vec<usize> = (0..4).collect();
        let schedule: Vec<usize> = (0..4).collect();
        let cancel = Cancel::new();
        let out = run(&items, &schedule, 4, &cancel, |job| job.worker, || usize::MAX);
        assert!(out.iter().all(|worker| *worker < 4));
    }

    #[test]
    fn an_empty_input_spawns_nothing_and_returns_nothing() {
        let items: Vec<usize> = Vec::new();
        let cancel = Cancel::new();
        let out = run(&items, &[], 8, &cancel, |job: Job<'_, usize>| *job.item, || usize::MAX);
        assert!(out.is_empty());
    }
}
