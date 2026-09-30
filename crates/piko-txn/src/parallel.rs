//! An ordered map over a slice, run on a few threads.
//!
//! `Transaction::verify` checks each package's signature and reads each archive. The work for
//! one package does not depend on another, and a large upgrade spends most of its `verify` time
//! there. This module runs that work on several threads. The caller sees the same result that a
//! serial loop gives: the values in item order, or the first failure in item order.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc,
};

/// Runs `work` on each item of `items`, on up to `threads` threads, and returns the results in
/// item order.
///
/// The failure that this returns is the first one in item order, not the first one in time.
/// Every item before it is still processed, so the answer is the one a serial loop gives. An
/// item after a known failure is not started.
///
/// `done` runs on the calling thread once for each item that finishes, in the order the items
/// finish. So a caller whose progress callback is not `Send` can still report progress.
///
/// With one thread, or with at most one item, no thread is started.
///
/// # Errors
///
/// The first failure in item order, with the index of its item.
pub(crate) fn map_ordered<T, R, E>(
    items: &[T],
    threads: usize,
    work: impl Fn(&T) -> Result<R, E> + Sync,
    mut done: impl FnMut(),
) -> Result<Vec<R>, (usize, E)>
where
    T: Sync,
    R: Send,
    E: Send,
{
    let threads = threads.min(items.len());
    if threads <= 1 {
        let mut values = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let value = work(item).map_err(|error| (index, error))?;
            done();
            values.push(value);
        }
        return Ok(values);
    }

    let next = AtomicUsize::new(0);
    // The lowest index that failed so far. A worker does not start an item above it.
    let lowest_failure = AtomicUsize::new(usize::MAX);
    let mut slots: Vec<Option<Result<R, E>>> =
        std::iter::repeat_with(|| None).take(items.len()).collect();

    std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::channel();
        for _ in 0..threads {
            let sender = sender.clone();
            let (next, lowest_failure, work) = (&next, &lowest_failure, &work);
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(index) else { break };
                    if index > lowest_failure.load(Ordering::Relaxed) {
                        break;
                    }
                    let result = work(item);
                    if result.is_err() {
                        lowest_failure.fetch_min(index, Ordering::Relaxed);
                    }
                    if sender.send((index, result)).is_err() {
                        break;
                    }
                }
            });
        }
        // The loop below ends when the last worker drops its sender.
        drop(sender);
        for (index, result) in receiver {
            done();
            if let Some(slot) = slots.get_mut(index) {
                *slot = Some(result);
            }
        }
    });

    // An empty slot is an item that no worker started. A worker skips an item only above an
    // index that already failed, and the lowest index to fail is always processed. So the scan
    // meets that failure before any empty slot.
    let mut values = Vec::with_capacity(items.len());
    for (index, slot) in slots.into_iter().enumerate() {
        match slot {
            Some(Ok(value)) => values.push(value),
            Some(Err(error)) => return Err((index, error)),
            None => break,
        }
    }
    Ok(values)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a failing assertion in a test should abort it loudly")]
mod tests {
    use super::*;

    #[test]
    fn values_come_back_in_item_order() {
        let items: Vec<u64> = (0..200).collect();
        for threads in [1, 2, 4, 8] {
            let mut finished = 0_usize;
            let values = map_ordered(
                &items,
                threads,
                |item| Ok::<_, ()>(item.saturating_mul(3)),
                || finished = finished.saturating_add(1),
            )
            .unwrap();
            assert_eq!(values, items.iter().map(|item| item.saturating_mul(3)).collect::<Vec<_>>());
            assert_eq!(finished, items.len());
        }
    }

    /// Several items fail, and a later one fails first in time. The answer is still the lowest
    /// index, as a serial loop would give.
    #[test]
    fn the_first_failure_in_item_order_is_returned() {
        let items: Vec<u64> = (0..64).collect();
        for threads in [1, 2, 4, 8] {
            let outcome = map_ordered(
                &items,
                threads,
                |&item| {
                    if item == 17 {
                        // Fails last in time.
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        return Err(item);
                    }
                    if item == 40 || item == 41 {
                        return Err(item);
                    }
                    Ok(item)
                },
                || {},
            );
            assert_eq!(outcome.unwrap_err(), (17, 17), "with {threads} threads");
        }
    }

    #[test]
    fn nothing_to_do_is_an_empty_answer() {
        let values = map_ordered(&[] as &[u8], 4, |_| Ok::<u8, ()>(0), || {}).unwrap();
        assert!(values.is_empty());
    }
}
