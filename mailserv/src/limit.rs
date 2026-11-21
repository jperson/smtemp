//! Connection limits and per-source-IP rate limiting (Phase 10).
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
//! state per IP; memory is bounded by the sweep on each admission,
//! which drops IPs with no active connections once their window has
//! rolled over.

use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

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
    /// The SMTP reply text for the refusal (a `421`, inviting the
    /// client to retry later).
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
    active: u32,
    window_start: Instant,
    window_count: u32,
}

/// Per-source-IP concurrency and rate limits, shared across the accept
/// loop. All state sits behind one mutex; the critical path per
/// admission is a map lookup and a few integer updates.
#[derive(Debug)]
pub struct ConnectionLimiter {
    max_per_ip: u32,
    max_per_window: u32,
    window: Duration,
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
    /// success the IP's active count is incremented and the caller MUST
    /// call [`ConnectionLimiter::release`] when the connection ends.
    /// Returns `Err(reason)` — with nothing recorded — when the IP is
    /// over its concurrent cap or its window budget.
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

    /// Release one admitted connection: decrement the IP's active
    /// count. Calling this without a matching successful `admit` (or
    /// twice) would under-count, so it must pair exactly.
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

        // One more admission triggers the sweep over all expired entries.
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
}
