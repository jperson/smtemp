//! Connection limits and per-source-IP rate limiting.
//!
//! A receive-only public MX is probed constantly: connection floods and
//! (once alias domains exist) dictionary attacks all arrive as TCP
//! connections. The [`ConnectionLimiter`] bounds each source IP by
//!
//! - **concurrent connections** (a slowloris cannot hold unlimited
//!   sockets), and
//! - **new connections per fixed window** (connection churn is capped
//!   even if each connection is instant).
//!
//! Enforcement happens in the accept loop, before any session work: a
//! denied connection is answered with `421` (RFC 5321 §4.2.1: the
//! client SHOULD retry later) and closed. Denied connections do not
//! consume capacity.
//!
//! The fixed-window counter trades precision for simplicity and O(1)
//! state per IP; memory is bounded by the sweep on each release, which
//! drops IPs with no active connections once their window has rolled
//! over.
//!
//! The [`DnsLimiter`] bounds a second resource per source IP: concurrent
//! **DNS-backed evaluations** (SPF for HELO and MAIL FROM, DKIM + DMARC
//! at end-of-data). Every session shares one resolver client, so without
//! it a client could publish records whose authoritative servers never
//! answer and fill the client's in-flight capacity with its own slow
//! lookups.

use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitReason {
    /// The IP already holds the maximum number of concurrent
    /// connections.
    TooManyConcurrent,
    /// The IP exceeded the new-connection budget for the current
    /// window.
    RateLimited,
}

impl LimitReason {
    /// Returns the complete SMTP reply line (with CRLF) for the refusal:
    /// a `421`, inviting the client to retry later.
    pub fn reply(&self) -> &'static [u8] {
        match self {
            LimitReason::TooManyConcurrent => {
                b"421 4.7.0 Too many concurrent connections from your address; try again later\r\n"
            }
            LimitReason::RateLimited => {
                b"421 4.7.0 Too many connections from your address; try again later\r\n"
            }
        }
    }
}

/// Per-IP bookkeeping: active connection count plus the fixed-window
/// admission counter.
#[derive(Debug)]
struct Entry {
    /// Connections from this IP currently admitted and not released.
    active: u32,
    /// When the current fixed window began.
    window_start: Instant,
    /// Connections admitted since `window_start`.
    window_count: u32,
}

/// Per-source-IP concurrency and rate limits, shared across the accept
/// loop. All state sits behind one mutex; the critical path per
/// admission is a map lookup and a few integer updates.
#[derive(Debug)]
pub struct ConnectionLimiter {
    /// Concurrent connections allowed per IP.
    max_per_ip: u32,
    /// New connections allowed per IP per `window`.
    max_per_window: u32,
    /// Length of the fixed rate window.
    window: Duration,
    /// Per-IP state.
    entries: Mutex<HashMap<IpAddr, Entry>>,
}

impl ConnectionLimiter {
    /// A limiter admitting at most `max_per_ip` concurrent connections
    /// and `max_per_window` new connections per `window` per source IP.
    pub fn new(max_per_ip: u32, max_per_window: u32, window: Duration) -> Self {
        ConnectionLimiter {
            max_per_ip,
            max_per_window,
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Try to admit a connection from `ip`.
    ///
    /// Returns `Ok` only when the connection is within both budgets; on
    /// success the IP's active and window counts are incremented and the
    /// caller MUST call [`ConnectionLimiter::release`] when the
    /// connection ends. Returns `Err(reason)` — without incrementing
    /// either count — when the IP is over its concurrent cap or its
    /// window budget.
    pub async fn admit(&self, ip: IpAddr) -> Result<(), LimitReason> {
        let mut entries = self.entries.lock().await;
        let now = Instant::now();
        let entry = entries.entry(ip).or_insert_with(|| Entry {
            active: 0,
            window_start: now,
            window_count: 0,
        });

        // Roll the fixed window forward if it has expired.
        if now.duration_since(entry.window_start) >= self.window {
            entry.window_start = now;
            entry.window_count = 0;
        }

        if entry.active >= self.max_per_ip {
            return Err(LimitReason::TooManyConcurrent);
        }
        if entry.window_count >= self.max_per_window {
            return Err(LimitReason::RateLimited);
        }

        entry.active += 1;
        entry.window_count += 1;
        Ok(())
    }

    /// Release one admitted connection from `ip`: decrement its active
    /// count, then sweep idle entries whose window has expired. Calling
    /// this without a matching successful `admit` (or twice) would
    /// under-count, so it must pair exactly.
    pub async fn release(&self, ip: IpAddr) {
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get_mut(&ip) {
            entry.active = entry.active.saturating_sub(1);
        }

        // Sweep: drop IPs with no active connections whose window has
        // rolled over — bounded memory against unbounded attacker IPs.
        let window = self.window;
        entries.retain(|_, entry| {
            entry.active > 0 || Instant::now().duration_since(entry.window_start) < window
        });
    }
}

/// Default concurrent DNS-backed evaluations per source IP
/// (`--max-dns-per-ip`).
pub const DEFAULT_DNS_PER_IP: usize = 4;

/// How long an evaluation waits for its IP's DNS share before the
/// command gets a temporary failure. Long enough to absorb bursts from a
/// busy legitimate sender (cached lookups free permits in milliseconds),
/// short enough that a client holding its whole share with slow lookups
/// is told to retry well inside the connection-duration cap.
pub const DNS_LIMIT_WAIT: Duration = Duration::from_secs(10);

/// The source IP's DNS share stayed exhausted for the whole wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsBusy;

/// One IP's share: its semaphore and how many evaluations hold or wait
/// for a permit (the entry is removed when that reaches zero).
#[derive(Debug)]
struct DnsShare {
    /// `per_ip` permits for this IP.
    semaphore: Arc<Semaphore>,
    /// Evaluations holding or waiting for a permit.
    users: usize,
}

/// Counters for the periodic `dns stats` log line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsLimitStats {
    /// Evaluations that found their IP's share exhausted and waited.
    pub waits: u64,
    /// Evaluations that waited the full [`DNS_LIMIT_WAIT`] and got a
    /// temporary failure.
    pub refusals: u64,
    /// IPs with an evaluation holding or waiting for a permit right now.
    pub active_ips: usize,
}

/// Per-source-IP limit on concurrent DNS-backed evaluations.
///
/// A session holds a [`DnsPermit`] around each evaluation that queries
/// the resolver. With the share exhausted, a new evaluation waits up to
/// the configured wait; if no permit frees up in that time it returns
/// [`DnsBusy`] and the caller answers with a temporary failure — never a
/// permanent one, because a rate limit must not turn into, say, a DMARC
/// rejection of legitimate mail.
///
/// IPs are tracked per address, like [`ConnectionLimiter`] (an IPv6 /64
/// is not aggregated: large senders send from many addresses within one
/// /64). Memory is bounded by the evaluations in progress: an IP's entry
/// exists only while some evaluation holds or waits for its permits.
#[derive(Debug)]
pub struct DnsLimiter {
    /// Concurrent evaluations allowed per IP.
    per_ip: usize,
    /// Longest an evaluation waits for a permit.
    wait: Duration,
    /// Shares of the IPs with an evaluation in progress.
    shares: std::sync::Mutex<HashMap<IpAddr, DnsShare>>,
    /// Running total for [`DnsLimitStats::waits`].
    waits: AtomicU64,
    /// Running total for [`DnsLimitStats::refusals`].
    refusals: AtomicU64,
}

/// A held share of an IP's DNS capacity. Releases the permit and
/// unregisters from the IP's entry when dropped — including when the
/// evaluation (or a wait for the permit) is cancelled.
#[derive(Debug)]
pub struct DnsPermit {
    /// The limiter whose share this is.
    limiter: Arc<DnsLimiter>,
    /// The source IP the share belongs to.
    ip: IpAddr,
    /// The semaphore permit; `None` while still waiting for it.
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for DnsPermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        let mut shares = self.limiter.lock_shares();
        if let Some(share) = shares.get_mut(&self.ip) {
            share.users -= 1;
            if share.users == 0 {
                shares.remove(&self.ip);
            }
        }
    }
}

impl DnsLimiter {
    /// A limiter allowing `per_ip` concurrent evaluations per source IP
    /// (at least 1), each waiting at most `wait` for a permit.
    pub fn new(per_ip: usize, wait: Duration) -> Self {
        DnsLimiter {
            per_ip: per_ip.max(1),
            wait,
            shares: std::sync::Mutex::new(HashMap::new()),
            waits: AtomicU64::new(0),
            refusals: AtomicU64::new(0),
        }
    }

    /// Returns the per-IP limit.
    pub fn per_ip(&self) -> usize {
        self.per_ip
    }

    /// Lock the share map, recovering it if a holder panicked (the map is
    /// valid after any partial update).
    fn lock_shares(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, DnsShare>> {
        self.shares
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Take one of `ip`'s permits, waiting up to the configured wait.
    ///
    /// Returns `Ok(permit)` — hold it for the whole evaluation — or
    /// `Err(DnsBusy)` if the IP's share stayed exhausted for the entire
    /// wait. Cancellation-safe: dropping the future unregisters it.
    pub async fn acquire(self: &Arc<Self>, ip: IpAddr) -> Result<DnsPermit, DnsBusy> {
        let semaphore = {
            let mut shares = self.lock_shares();
            let share = shares.entry(ip).or_insert_with(|| DnsShare {
                semaphore: Arc::new(Semaphore::new(self.per_ip)),
                users: 0,
            });
            share.users += 1;
            Arc::clone(&share.semaphore)
        };
        // Registered: from here every exit path (including cancellation)
        // must unregister, which the permit's Drop does.
        let mut held = DnsPermit {
            limiter: Arc::clone(self),
            ip,
            permit: None,
        };
        if let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() {
            held.permit = Some(permit);
            return Ok(held);
        }
        self.waits.fetch_add(1, Ordering::Relaxed);
        match tokio::time::timeout(self.wait, semaphore.acquire_owned()).await {
            Ok(Ok(permit)) => {
                held.permit = Some(permit);
                Ok(held)
            }
            // Timed out (the semaphore is never closed).
            _ => {
                self.refusals.fetch_add(1, Ordering::Relaxed);
                Err(DnsBusy)
            }
        }
    }

    /// Returns a snapshot of the current counters.
    pub fn stats(&self) -> DnsLimitStats {
        DnsLimitStats {
            waits: self.waits.load(Ordering::Relaxed),
            refusals: self.refusals.load(Ordering::Relaxed),
            active_ips: self.lock_shares().len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(max_per_ip: u32, max_per_window: u32, window: Duration) -> ConnectionLimiter {
        ConnectionLimiter::new(max_per_ip, max_per_window, window)
    }

    /// Concurrent cap: the (N+1)th simultaneous connection from one IP
    /// is refused with `TooManyConcurrent`; releasing a slot admits the
    /// next; other IPs are unaffected.
    #[tokio::test]
    async fn concurrent_cap_per_ip() {
        let limiter = limiter(2, 100, Duration::from_secs(60));
        let a = "10.0.0.1".parse().unwrap();
        let b = "10.0.0.2".parse().unwrap();

        limiter.admit(a).await.unwrap();
        limiter.admit(a).await.unwrap();
        assert_eq!(
            limiter.admit(a).await,
            Err(LimitReason::TooManyConcurrent),
            "third concurrent connection from one IP must be denied"
        );

        // A different IP has its own budget.
        limiter.admit(b).await.unwrap();

        // Release admits the next connection from the same IP.
        limiter.release(a).await;
        limiter.admit(a).await.unwrap();
        assert_eq!(limiter.admit(a).await, Err(LimitReason::TooManyConcurrent));
    }

    /// Window rate cap: connections beyond the per-window budget are
    /// refused with `RateLimited` even though the concurrent budget is
    /// not exhausted, and the budget resets once the window rolls over.
    #[tokio::test]
    async fn rate_window_per_ip() {
        let limiter = limiter(10, 3, Duration::from_millis(80));
        let a = "10.1.0.1".parse().unwrap();

        for _ in 0..3 {
            limiter.admit(a).await.unwrap();
            limiter.release(a).await;
        }
        assert_eq!(
            limiter.admit(a).await,
            Err(LimitReason::RateLimited),
            "fourth connection inside the window must be rate-limited"
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        limiter.admit(a).await.unwrap();
    }

    /// The sweep must keep the map bounded: many IPs with zero active
    /// connections and expired windows are dropped on the next release.
    #[tokio::test]
    async fn sweep_drops_idle_expired_entries() {
        let limiter = limiter(5, 5, Duration::from_millis(50));
        for i in 0..100u8 {
            let ip: IpAddr = format!("10.9.0.{i}").parse().unwrap();
            limiter.admit(ip).await.unwrap();
            limiter.release(ip).await;
        }
        tokio::time::sleep(Duration::from_millis(80)).await;

        // The next release triggers the sweep over all expired entries.
        let survivor = "10.9.0.200".parse().unwrap();
        limiter.admit(survivor).await.unwrap();
        limiter.release(survivor).await;
        limiter.admit(survivor).await.unwrap();

        let entries = limiter.entries.lock().await;
        assert!(
            entries.len() <= 2,
            "idle expired entries must be swept, got {}",
            entries.len()
        );
    }

    /// The 421 reply texts are retryable temporary failures.
    #[test]
    fn refusal_replies_are_421() {
        for reason in [LimitReason::TooManyConcurrent, LimitReason::RateLimited] {
            assert!(reason.reply().starts_with(b"421 4.7.0"));
        }
    }

    // -- DnsLimiter --------------------------------------------------------

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// An IP gets at most `per_ip` concurrent permits; a further request
    /// waits the configured time and is refused. Other IPs are
    /// unaffected.
    #[tokio::test]
    async fn dns_limit_caps_each_ip() {
        let limiter = Arc::new(DnsLimiter::new(2, Duration::from_millis(100)));
        let a = ip("192.0.2.1");
        let _p1 = limiter.acquire(a).await.unwrap();
        let _p2 = limiter.acquire(a).await.unwrap();

        let started = Instant::now();
        assert_eq!(limiter.acquire(a).await.unwrap_err(), DnsBusy);
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "it waited first"
        );

        // Another address has its own share.
        let _other = limiter.acquire(ip("192.0.2.2")).await.unwrap();
        let stats = limiter.stats();
        assert_eq!((stats.waits, stats.refusals, stats.active_ips), (1, 1, 2));
    }

    /// A waiter gets the permit as soon as a holder releases it.
    #[tokio::test]
    async fn dns_limit_waiter_proceeds_on_release() {
        let limiter = Arc::new(DnsLimiter::new(1, Duration::from_secs(5)));
        let a = ip("192.0.2.1");
        let held = limiter.acquire(a).await.unwrap();
        let waiter = tokio::spawn({
            let limiter = Arc::clone(&limiter);
            async move { limiter.acquire(a).await.map(drop) }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let released = Instant::now();
        drop(held);
        waiter.await.unwrap().unwrap();
        assert!(released.elapsed() < Duration::from_millis(500));
        assert_eq!(limiter.stats().refusals, 0);
    }

    /// Entries live only while an evaluation holds or waits for a permit
    /// — including a waiter that is cancelled — so memory stays bounded.
    #[tokio::test]
    async fn dns_limit_entries_are_removed_when_unused() {
        let limiter = Arc::new(DnsLimiter::new(1, Duration::from_secs(5)));
        let a = ip("2001:db8::1");
        let held = limiter.acquire(a).await.unwrap();
        let cancelled = tokio::spawn({
            let limiter = Arc::clone(&limiter);
            async move { limiter.acquire(a).await.map(drop) }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancelled.abort();
        let _ = cancelled.await;
        assert_eq!(
            limiter.lock_shares()[&a].users,
            1,
            "the cancelled waiter unregistered"
        );

        drop(held);
        assert_eq!(limiter.stats().active_ips, 0);

        // A fresh evaluation starts a fresh, full share.
        let _again = limiter.acquire(a).await.unwrap();
        assert_eq!(limiter.stats().active_ips, 1);
    }
}
