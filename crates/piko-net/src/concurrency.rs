//! How many transfers run at once, and how they are spread across mirrors.
//!
//! # The numbers are measured, not inherited
//!
//! Against this repository's own mirror list and a sample drawn from a real installed set, the
//! optimum is flat. Any value in `4..=8` is indistinguishable, below 4 loses, and above 8 buys
//! nothing but connections on volunteer-run mirrors. `ParallelDownloads = 5` — what Arch's
//! shipped `pacman.conf` sets — sits in the middle of that plateau. [`Concurrency::MAX_DOWNLOADS`]
//! is therefore a safety ceiling, not a tuning knob. Past it there is measurably nothing to
//! gain, so a `pacman.conf` asking for 4000 is answered with 16 rather than obeyed.
//!
//! Two connections per mirror host measured free (1.853 s-1.866 s at five concurrent transfers,
//! whether they were spread over one, three, or five mirrors). The cap is kept for what it buys
//! elsewhere: netiquette towards mirrors nobody is paying for, and failover, where a slow
//! mirror costs one worker rather than the whole run.

/// How many transfers run at once, and how many may share one mirror host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Concurrency {
    downloads: usize,
    per_host: usize,
}

impl Concurrency {
    /// The ceiling on concurrent transfers, whatever `ParallelDownloads` asks for.
    pub const MAX_DOWNLOADS: usize = 16;

    /// How many concurrent transfers may share one mirror host.
    pub const DEFAULT_PER_HOST: usize = 2;

    /// From `pacman.conf`'s `ParallelDownloads`, clamped into `1..=MAX_DOWNLOADS`.
    ///
    /// **The clamp lives here rather than in the parser, on purpose.** `piko conf` reproduces
    /// `pacman-conf`, so it must echo back whatever the file said.
    /// A value is corrected where it is used, never where it is read.
    #[must_use]
    pub fn new(parallel_downloads: u32) -> Self {
        let downloads = usize::try_from(parallel_downloads)
            .unwrap_or(Self::MAX_DOWNLOADS)
            .clamp(1, Self::MAX_DOWNLOADS);
        Self { downloads, per_host: Self::DEFAULT_PER_HOST }
    }

    /// The same concurrency with a different per-host cap, for a caller that measured its own.
    /// Clamps to at least one, since zero would spread nothing anywhere.
    #[must_use]
    pub const fn with_per_host(self, per_host: usize) -> Self {
        Self { downloads: self.downloads, per_host: if per_host < 1 { 1 } else { per_host } }
    }

    /// How many transfers may run at once.
    #[must_use]
    pub const fn downloads(self) -> usize {
        self.downloads
    }

    /// How many of them may share one mirror host.
    #[must_use]
    pub const fn per_host(self) -> usize {
        self.per_host
    }

    /// `servers` in the order worker `worker` should try them.
    ///
    /// Every worker sees the whole list, so failover is unchanged. What differs is where each
    /// one starts. Workers are grouped [`Self::per_host`] at a time, and each group starts one
    /// mirror further down.
    ///
    /// With at least `downloads / per_host` mirrors configured, no more than [`Self::per_host`]
    /// workers open a connection to one host while nothing is failing. With fewer mirrors — one
    /// `Server`, or the single-entry `CacheServer` list that is the usual shape — the rotation
    /// is a no-op and every worker lands on the same host, exactly as `pacman` does with the
    /// same `ParallelDownloads`. The cap describes how work is spread. It is not a ceiling that
    /// idles a worker to enforce itself.
    ///
    /// The cap softens the same way once a worker falls through to its second mirror. That is
    /// the right direction: an abandoned mirror should not keep reserved capacity.
    pub(crate) fn servers_for(
        self,
        servers: &[String],
        worker: usize,
    ) -> impl Iterator<Item = &String> {
        let offset = worker
            .checked_div(self.per_host)
            .and_then(|group| group.checked_rem(servers.len()))
            .unwrap_or(0);
        servers.iter().cycle().skip(offset).take(servers.len())
    }
}

impl Default for Concurrency {
    /// libalpm's own default: one transfer at a time. A `pacman.conf` with no
    /// `ParallelDownloads` line means this.
    fn default() -> Self {
        Self { downloads: 1, per_host: Self::DEFAULT_PER_HOST }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a test that cannot fail loudly is not a test"
)]
mod tests {
    use super::*;

    fn mirrors(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("https://mirror{index}.example/arch")).collect()
    }

    #[test]
    fn the_default_is_libalpms_one_at_a_time() {
        assert_eq!(Concurrency::default().downloads(), 1);
    }

    #[test]
    fn a_configured_value_is_clamped_rather_than_obeyed() {
        assert_eq!(Concurrency::new(5).downloads(), 5);
        assert_eq!(Concurrency::new(0).downloads(), 1, "zero would download nothing at all");
        assert_eq!(Concurrency::new(u32::MAX).downloads(), Concurrency::MAX_DOWNLOADS);
    }

    /// Workers are grouped `per_host` at a time, each group starting one mirror further down.
    #[test]
    fn workers_are_spread_across_mirrors_in_groups() {
        let servers = mirrors(4);
        let concurrency = Concurrency::new(5);
        let first =
            |worker: usize| concurrency.servers_for(&servers, worker).next().unwrap().clone();
        assert_eq!(first(0), servers[0]);
        assert_eq!(first(1), servers[0], "two workers share the fastest mirror");
        assert_eq!(first(2), servers[1]);
        assert_eq!(first(3), servers[1]);
        assert_eq!(first(4), servers[2]);
    }

    /// Every worker still sees every mirror: the rotation moves the starting point, it does not
    /// shorten the failover chain.
    #[test]
    fn every_worker_still_sees_every_mirror() {
        let servers = mirrors(4);
        let concurrency = Concurrency::new(5);
        for worker in 0..8 {
            let seen: Vec<&String> = concurrency.servers_for(&servers, worker).collect();
            assert_eq!(seen.len(), servers.len(), "worker {worker} lost a fallback mirror");
            for server in &servers {
                assert!(seen.contains(&server), "worker {worker} never tries {server}");
            }
        }
    }

    #[test]
    fn the_rotation_wraps_rather_than_running_off_the_end() {
        let servers = mirrors(2);
        let concurrency = Concurrency::new(8);
        let order: Vec<&String> = concurrency.servers_for(&servers, 6).collect();
        assert_eq!(order, vec![&servers[1], &servers[0]]);
    }

    /// The `CacheServer` shape: one entry, so the rotation is a no-op rather than an error.
    #[test]
    fn a_single_mirror_rotates_to_itself() {
        let servers = mirrors(1);
        let concurrency = Concurrency::new(5);
        for worker in 0..5 {
            let order: Vec<&String> = concurrency.servers_for(&servers, worker).collect();
            assert_eq!(order, vec![&servers[0]]);
        }
    }

    #[test]
    fn an_empty_list_yields_nothing_rather_than_dividing_by_zero() {
        let servers: Vec<String> = Vec::new();
        assert_eq!(Concurrency::new(5).servers_for(&servers, 3).count(), 0);
    }

    #[test]
    fn a_per_host_cap_of_zero_is_refused() {
        assert_eq!(Concurrency::new(5).with_per_host(0).per_host(), 1);
    }
}
