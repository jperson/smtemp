//! DNS client: wire-format codec, DNS-over-TLS queries, and a shared
//! client with connection reuse and TTL-based result caching.
//!
//! Response parsing is total (bounds-checked everywhere): responses come
//! from the configured resolver, which may be buggy, spoofed, or
//! compromised — a malformed answer is an `Err`, never a panic.
#![warn(missing_docs)]

use anyhow::{anyhow, Context, Result};
//use rand::Rng;
use rand::prelude::*;
use rand::rngs::StdRng;
use rustls_pki_types::ServerName;
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;

/// The DNS protocol module: message/record codec and wire helpers.
pub mod proto;
use crate::proto::{DnsMessage, DnsQuestion, DnsResourceRecord, Label, QType};

/// Verify a response actually answers our query (RFC 5452 hardening
/// against resolver confusion and spoofed datagrams): the transaction ID
/// matches, it is marked as a response, and the question section echoes
/// the question.
///
/// Returns `Ok(())` when the response is trustworthy enough to parse
/// further, and `Err` naming the violated check otherwise.
fn validate_response(query: &DnsMessage, resp: &DnsMessage) -> Result<()> {
    if resp.header.transaction_id != query.header.transaction_id {
        return Err(anyhow!(
            "DNS response transaction ID mismatch ({} != {})",
            resp.header.transaction_id,
            query.header.transaction_id
        ));
    }
    if resp.header.qr != 1 {
        return Err(anyhow!("DNS response is not marked as a response"));
    }
    if resp.questions.first() != query.questions.first() {
        return Err(anyhow!("DNS response question mismatch"));
    }
    Ok(())
}

/// Query over DNS-over-TLS (port 853): the authenticated, preferred
/// transport. The response is validated (ID, QR, question echo, EDNS0
/// conformance) before it is returned.
pub async fn query_tls<'query>(
    dest: &'query Ipv4Addr,
    domain: &'query str,
    record_type: u16,
    record_class: u16,
) -> Result<DnsMessage> {
    let mut rng = StdRng::from_entropy();
    let id: u16 = rng.gen();

    let question = DnsQuestion {
        name: Label::new(domain.to_string()),
        record_type,
        record_class,
    };

    let msg = DnsMessage::new(id, vec![question]);
    let query = msg.to_vec()?;

    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(format!("{}:853", dest)).await?;
    let dnsname = ServerName::try_from(dest.to_string()).unwrap().to_owned();

    let mut stream = connector.connect(dnsname, stream).await?;

    stream.write_u16(query.len() as u16).await?;
    stream.write_all(query.as_slice()).await?;

    let len: u16 = stream.read_u16().await?;
    let mut buf = vec![0; len.into()];
    let count = stream.read_exact(&mut buf).await?;

    let (_, dq) = DnsMessage::from_bytes(&buf[0..count])?;
    validate_response(&msg, &dq)?;
    dq.edns0()?;
    Ok(dq)
}

/// Query over plain TCP (port 53). The response is validated (ID, QR,
/// question echo, EDNS0 conformance) before it is returned. No timeout
/// is applied; prefer [`query_tls`].
pub async fn query_tcp<'query>(
    dest: &'query Ipv4Addr,
    domain: &'query str,
    record_type: u16,
    record_class: u16,
) -> Result<DnsMessage> {
    let mut rng = rand::thread_rng();
    let id: u16 = rng.gen();

    let question = DnsQuestion {
        name: Label::new(domain.to_string()),
        record_type,
        record_class,
    };

    let msg = DnsMessage::new(id, vec![question]);
    let query = msg.to_vec()?;
    let mut stream = TcpStream::connect(format!("{}:53", dest)).await?;

    stream.write_u16(query.len() as u16).await?;
    stream.write_all(query.as_slice()).await?;

    let len: u16 = stream.read_u16().await?;
    let mut buf = vec![0; len.into()];
    let count = stream.read_exact(&mut buf).await?;

    let (_, dq) = DnsMessage::from_bytes(&buf[0..count])?;
    validate_response(&msg, &dq)?;
    dq.edns0()?;
    Ok(dq)
}

// -- Shared client: connection reuse + TTL result cache ---------------

/// The wire type of a pooled DNS-over-TLS connection.
type DotStream = TlsStream<TcpStream>;

/// Cache key: lowercase qname + qtype (the class is always IN for the
/// queries this client makes).
type CacheKey = (String, u16);

/// Maximum cached entries; the cache is pruned of expired entries on
/// every insert, and if it is still at capacity it is cleared wholesale
/// — bounded memory against an attacker driving many distinct lookups.
const MAX_CACHE_ENTRIES: usize = 4096;

/// Upper clamp on cached TTLs (an hour): long-lived records are
/// re-fetched at most hourly, which is plenty fresh for mail policy.
const MAX_CACHE_TTL: u64 = 3600;

/// One cached DNS response with its expiry.
#[derive(Debug)]
struct CacheEntry {
    resp: DnsMessage,
    expires: Instant,
}

/// TTL-based DNS response cache.
///
/// Lifetime follows DNS semantics (RFC 2308): a positive answer lives
/// for the minimum TTL among its records; NXDOMAIN and empty answers
/// (NODATA) live for the SOA-derived negative TTL; anything without TTL
/// information — and every other error code — is not cached at all,
/// because it may be transient.
#[derive(Debug, Default)]
struct DnsCache {
    entries: HashMap<CacheKey, CacheEntry>,
}

impl DnsCache {
    /// Look up a cached response.
    ///
    /// `now` is injected so expiry is deterministic in tests. Returns
    /// `Some(response)` while the entry is live — the stored response,
    /// already validated at insert time, so no re-validation is needed
    /// — and `None` (removing the expired entry) once its TTL has
    /// passed.
    fn get(&mut self, key: &CacheKey, now: Instant) -> Option<DnsMessage> {
        if self.entries.get(key)?.expires <= now {
            self.entries.remove(key);
            return None;
        }
        Some(self.entries.get(key)?.resp.clone())
    }

    /// Store a response under `key` if it carries cacheable TTL
    /// information.
    ///
    /// Responses without TTL information (no answers and no SOA, or a
    /// transient error code) and zero-TTL responses are silently not
    /// stored. Expired entries are pruned on every insert; at capacity
    /// the cache is cleared wholesale (see [`MAX_CACHE_ENTRIES`]).
    /// Returns without storing anything in the not-cacheable case.
    fn insert(&mut self, key: CacheKey, resp: &DnsMessage, now: Instant) {
        let Some(ttl) = cache_ttl(resp).filter(|t| !t.is_zero()) else {
            return;
        };
        self.entries.retain(|_, e| e.expires > now);
        if self.entries.len() >= MAX_CACHE_ENTRIES {
            self.entries.clear();
        }
        self.entries.insert(
            key,
            CacheEntry {
                resp: resp.clone(),
                expires: now + ttl,
            },
        );
    }
}

/// The cache lifetime for a validated response.
///
/// Returns `Some(ttl)` for cacheable answers — the minimum record TTL
/// for positive responses, the SOA-derived negative TTL for
/// NXDOMAIN/NODATA (RFC 2308 §5), clamped to [`MAX_CACHE_TTL`] — and
/// `None` for anything that must not be cached: empty answers without
/// a SOA (no TTL information) and every non-NXDOMAIN error code
/// (transient by nature).
fn cache_ttl(resp: &DnsMessage) -> Option<Duration> {
    // RFC 2308 Section 5: the negative TTL is min(SOA TTL, SOA MINIMUM).
    let negative = |authorities: &[DnsResourceRecord]| -> Option<u64> {
        authorities.iter().find_map(|rr| match &rr.rdata {
            QType::SOA(_, _, _, _, _, _, minimum) => Some(u64::from((*minimum).min(rr.ttl))),
            _ => None,
        })
    };
    let ttl: u64 = match resp.header.rcode {
        0x00 if !resp.answers.is_empty() => resp.answers.iter().map(|a| u64::from(a.ttl)).min()?,
        // NODATA and NXDOMAIN share the negative-TTL rule.
        0x00 | 0x03 => negative(&resp.authorities)?,
        // SERVFAIL and friends are transient: never cache.
        _ => return None,
    };
    Some(Duration::from_secs(ttl.min(MAX_CACHE_TTL)))
}

/// Live counters and gauges for a [`DnsClient`] (DESIGN §6.1: the
/// baseline for sizing the connection pool and measuring pipelining).
///
/// Everything is a lock-free atomic. The gauges (`waiting`, `in_flight`)
/// are maintained by drop guards, so a query whose future is cancelled
/// mid-wait or mid-exchange still decrements them.
#[derive(Debug, Default)]
struct DnsStats {
    queries: AtomicU64,
    cache_hits: AtomicU64,
    connects: AtomicU64,
    connect_failures: AtomicU64,
    exchanges_ok: AtomicU64,
    exchange_errors: AtomicU64,
    timeouts: AtomicU64,
    waits: AtomicU64,
    wait_total_us: AtomicU64,
    wait_max_us: AtomicU64,
    waiting: AtomicU64,
    in_flight: AtomicU64,
    peak_in_flight: AtomicU64,
}

/// A point-in-time copy of a [`DnsClient`]'s metrics, from
/// [`DnsClient::stats`]. Counters are cumulative since the client was
/// created; `wait_max_us` and `peak_in_flight` are peaks since the last
/// [`DnsClient::reset_peaks`] (or creation).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DnsStatsSnapshot {
    /// Calls to [`DnsClient::query`].
    pub queries: u64,
    /// Queries answered from the TTL cache (no network).
    pub cache_hits: u64,
    /// Connection attempts (TCP + TLS) started.
    pub connects: u64,
    /// Connection attempts that failed or timed out.
    pub connect_failures: u64,
    /// Exchanges that returned a validated response.
    pub exchanges_ok: u64,
    /// Exchanges that failed at the connection or protocol level (the
    /// connection was discarded).
    pub exchange_errors: u64,
    /// Exchanges (or connects) that hit the per-exchange timeout.
    pub timeouts: u64,
    /// Cache misses that found every pooled connection busy and had to
    /// wait for one.
    pub waits: u64,
    /// Total time cache misses spent waiting for a connection, in
    /// microseconds (divide by `queries - cache_hits` for the mean).
    pub wait_total_us: u64,
    /// Longest single wait for a connection, in microseconds.
    pub wait_max_us: u64,
    /// Queries waiting for a connection right now.
    pub waiting: u64,
    /// Queries holding a connection right now.
    pub in_flight: u64,
    /// Highest `in_flight` value observed.
    pub peak_in_flight: u64,
}

/// Increments a gauge on creation and decrements it on drop.
struct GaugeGuard<'a>(&'a AtomicU64);

impl<'a> GaugeGuard<'a> {
    fn new(gauge: &'a AtomicU64) -> Self {
        gauge.fetch_add(1, Ordering::Relaxed);
        GaugeGuard(gauge)
    }
}

impl Drop for GaugeGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A shared DNS-over-TLS client: a small pool of lazily-established TLS
/// connections reused across queries (previously every query paid a
/// full TCP+TLS handshake and a fresh rustls configuration), plus a
/// TTL-based result cache shared by every consumer (SPF, DKIM, DMARC).
///
/// Each pooled connection carries one exchange at a time (up to
/// [`POOL_SIZE`] queries run concurrently); a query that fails at the
/// connection level — stale idle
/// connections are common — retries once on a freshly established
/// connection. Any failed or timed-out exchange discards the
/// connection: a half-completed exchange must never be followed by
/// another query on the same stream, or responses would be mispaired.
#[derive(Debug)]
pub struct DnsClient {
    /// The resolver address (DNS-over-TLS on port 853).
    server: Ipv4Addr,
    /// Per-exchange timeout; a timeout poisons the connection.
    timeout: Duration,
    /// TLS configuration (webpki roots in production; a test root for
    /// the mock-server integration test).
    config: Arc<ClientConfig>,
    /// Endpoint override (mock DoT server on an ephemeral port);
    /// production always derives `server:853`.
    endpoint: Option<String>,
    /// Validated responses keyed by (qname, qtype).
    cache: Mutex<DnsCache>,
    /// The connection pool: [`POOL_SIZE`] independently locked slots,
    /// each holding an established connection or nothing. One exchange
    /// runs per slot at a time, so responses are never mispaired.
    conns: Vec<AsyncMutex<Option<DotStream>>>,
    /// Round-robin cursor for waiting on a slot when all are busy.
    next_slot: std::sync::atomic::AtomicUsize,
    /// Metrics (see [`DnsClient::stats`]).
    stats: DnsStats,
}

/// Concurrent DNS-over-TLS connections per [`DnsClient`] (H6, security
/// report). With a single serialized connection one slow lookup (an
/// attacker can publish records whose authoritative servers never
/// answer) held every session's DNS for the whole per-exchange
/// timeout. With a pool, a slow lookup occupies one slot while the
/// others keep serving.
pub const POOL_SIZE: usize = 8;

impl DnsClient {
    /// A client for `server` with the default 5-second per-exchange
    /// timeout.
    pub fn new(server: Ipv4Addr) -> Self {
        DnsClient::with_timeout(server, Duration::from_secs(5))
    }

    /// A client with an explicit per-exchange timeout.
    pub fn with_timeout(server: Ipv4Addr, timeout: Duration) -> Self {
        DnsClient::with_config(server, default_client_config(), timeout, None)
    }

    /// A client with an explicit TLS configuration and connect endpoint.
    ///
    /// Test seam: a mock DoT server runs on an ephemeral port with a
    /// private trust root, so tests inject both. Production code should
    /// use [`DnsClient::new`]/[`DnsClient::with_timeout`].
    pub fn with_config(
        server: Ipv4Addr,
        config: Arc<ClientConfig>,
        timeout: Duration,
        endpoint: Option<String>,
    ) -> Self {
        DnsClient {
            server,
            timeout,
            config,
            endpoint,
            cache: Mutex::new(DnsCache::default()),
            conns: (0..POOL_SIZE).map(|_| AsyncMutex::new(None)).collect(),
            next_slot: std::sync::atomic::AtomicUsize::new(0),
            stats: DnsStats::default(),
        }
    }

    /// A snapshot of this client's metrics.
    pub fn stats(&self) -> DnsStatsSnapshot {
        let s = &self.stats;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        DnsStatsSnapshot {
            queries: get(&s.queries),
            cache_hits: get(&s.cache_hits),
            connects: get(&s.connects),
            connect_failures: get(&s.connect_failures),
            exchanges_ok: get(&s.exchanges_ok),
            exchange_errors: get(&s.exchange_errors),
            timeouts: get(&s.timeouts),
            waits: get(&s.waits),
            wait_total_us: get(&s.wait_total_us),
            wait_max_us: get(&s.wait_max_us),
            waiting: get(&s.waiting),
            in_flight: get(&s.in_flight),
            peak_in_flight: get(&s.peak_in_flight),
        }
    }

    /// Reset the peak values (`wait_max_us`, `peak_in_flight`) so the
    /// next [`DnsClient::stats`] reports peaks for the new interval. The
    /// peak in-flight count restarts from the current in-flight count.
    pub fn reset_peaks(&self) {
        let s = &self.stats;
        s.wait_max_us.store(0, Ordering::Relaxed);
        s.peak_in_flight
            .store(s.in_flight.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    /// Query one name over DNS-over-TLS.
    ///
    /// Cache hits (a prior validated response for the same lowercase
    /// qname and qtype whose TTL has not expired) are returned without
    /// touching the connection. A miss serializes on the pooled
    /// connection: an existing connection is reused, a connection-level
    /// failure retries exactly once on a freshly established one, and a
    /// timed-out or otherwise failed exchange discards the connection
    /// so a half-completed response can never be mispaired with the
    /// next query.
    ///
    /// Returns `Ok(response)` — a validated response (ID, QR, question
    /// echo, EDNS0 conformance), possibly from the cache and possibly
    /// carrying a non-zero error rcode, which callers map to their own
    /// semantics — or `Err` when the resolver could not be consulted
    /// (connect failure after the retry, I/O error, protocol
    /// violation, or the per-exchange timeout elapsing).
    pub async fn query(&self, domain: &str, qtype: u16) -> Result<DnsMessage> {
        let stats = &self.stats;
        stats.queries.fetch_add(1, Ordering::Relaxed);
        let key = (domain.trim().to_ascii_lowercase(), qtype);
        if let Some(hit) = self
            .cache
            .lock()
            .expect("DNS cache poisoned")
            .get(&key, Instant::now())
        {
            stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(hit);
        }

        // Held across the exchange: one query in flight per slot, so
        // responses can never be mispaired. Take the first idle slot
        // (keeps a quiet server on one warm connection); when every slot
        // is busy, wait on one chosen round-robin.
        let mut conn = match self.conns.iter().find_map(|slot| slot.try_lock().ok()) {
            Some(guard) => guard,
            None => {
                stats.waits.fetch_add(1, Ordering::Relaxed);
                let _waiting = GaugeGuard::new(&stats.waiting);
                let started = Instant::now();
                let i = self
                    .next_slot
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    % self.conns.len();
                let guard = self.conns[i].lock().await;
                let waited = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                stats.wait_total_us.fetch_add(waited, Ordering::Relaxed);
                stats.wait_max_us.fetch_max(waited, Ordering::Relaxed);
                guard
            }
        };
        let _in_flight = GaugeGuard::new(&stats.in_flight);
        stats
            .peak_in_flight
            .fetch_max(stats.in_flight.load(Ordering::Relaxed), Ordering::Relaxed);
        for attempt in 0..2 {
            let mut stream = match conn.take() {
                Some(stream) => stream,
                // H6 (security report): the connect (TCP + TLS
                // handshake) MUST be bounded like the exchange — a
                // black-holed resolver used to hold the shared
                // connection mutex for the kernel's connect timeout
                // (~2 min), stalling every lookup in every session.
                None => {
                    stats.connects.fetch_add(1, Ordering::Relaxed);
                    match tokio::time::timeout(
                        self.timeout,
                        connect(&self.endpoint_str(), &self.config),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(e)) => {
                            stats.connect_failures.fetch_add(1, Ordering::Relaxed);
                            return Err(e.context("DNS query failed"));
                        }
                        Err(_) => {
                            stats.connect_failures.fetch_add(1, Ordering::Relaxed);
                            stats.timeouts.fetch_add(1, Ordering::Relaxed);
                            return Err(anyhow!("DNS connect timed out"));
                        }
                    }
                }
            };
            match tokio::time::timeout(self.timeout, exchange(&mut stream, domain, qtype)).await {
                Ok(Ok(resp)) => {
                    stats.exchanges_ok.fetch_add(1, Ordering::Relaxed);
                    *conn = Some(stream);
                    self.cache.lock().expect("DNS cache poisoned").insert(
                        key,
                        &resp,
                        Instant::now(),
                    );
                    return Ok(resp);
                }
                // Connection-level or protocol failure: the stream is
                // suspect (idle-closed, torn, or the peer misbehaved).
                // Poison it and retry once on a fresh connection.
                Ok(Err(e)) => {
                    stats.exchange_errors.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                    if attempt == 0 {
                        continue;
                    }
                    return Err(e.context("DNS query failed"));
                }
                // A timed-out exchange leaves the stream with unknown
                // pending state: it must never be reused.
                Err(_) => {
                    stats.timeouts.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                    return Err(anyhow!("DNS query timed out"));
                }
            }
        }
        unreachable!("each loop iteration returns")
    }

    /// The connect endpoint: `server:853`, or the test override.
    ///
    /// Returns the `ip:port` string the pooled connection dials.
    fn endpoint_str(&self) -> String {
        self.endpoint
            .clone()
            .unwrap_or_else(|| format!("{}:853", self.server))
    }
}

/// The default TLS client configuration.
///
/// Returns a configuration trusting the webpki root store with no
/// client authentication — built once per client rather than per
/// query, which matters because loading the root store dominated the
/// old per-query cost alongside the handshake itself.
fn default_client_config() -> Arc<ClientConfig> {
    let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(),
    )
}

/// Establish a DNS-over-TLS connection to `endpoint`.
///
/// Returns `Ok(stream)` once the TCP connection is up and the TLS
/// handshake has completed (the server name for SNI and verification
/// is the endpoint's host part). Returns `Err` if the TCP connect or
/// the TLS handshake fails; the error names the endpoint.
async fn connect(endpoint: &str, config: &Arc<ClientConfig>) -> Result<DotStream> {
    let stream = TcpStream::connect(endpoint)
        .await
        .with_context(|| format!("cannot connect to DNS resolver at {endpoint}"))?;
    let connector = TlsConnector::from(Arc::clone(config));
    let host = endpoint
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(endpoint);
    let dnsname = ServerName::try_from(host.to_string())
        .context("invalid resolver hostname")?
        .to_owned();
    connector
        .connect(dnsname, stream)
        .await
        .context("TLS handshake with DNS resolver failed")
}

/// One request/response exchange on an established connection.
///
/// Sends a fresh query (new random transaction ID) and reads exactly
/// one length-prefixed response. Returns `Ok(response)` only after the
/// response is validated against the query (ID, QR, question echo) and
/// passes the EDNS0 conformance check; returns `Err` on any I/O,
/// framing, parse, or validation failure — the caller treats the
/// connection as suspect and discards it.
async fn exchange(stream: &mut DotStream, domain: &str, qtype: u16) -> Result<DnsMessage> {
    let mut rng = StdRng::from_entropy();
    let id: u16 = rng.gen();

    let question = DnsQuestion {
        name: Label::new(domain.to_string()),
        record_type: qtype,
        record_class: 0x01,
    };

    let msg = DnsMessage::new(id, vec![question]);
    let query = msg.to_vec()?;

    stream.write_u16(query.len() as u16).await?;
    stream.write_all(query.as_slice()).await?;

    let len: u16 = stream.read_u16().await?;
    let mut buf = vec![0; usize::from(len)];
    let count = stream.read_exact(&mut buf).await?;

    let (_, dq) = DnsMessage::from_bytes(&buf[0..count])?;
    validate_response(&msg, &dq)?;
    dq.edns0()?;
    Ok(dq)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a response message in memory (no wire roundtrip needed
    /// for cache-semantics tests).
    fn response(
        rcode: u8,
        answers: Vec<(u32, QType)>,
        authorities: Vec<(u32, QType)>,
    ) -> DnsMessage {
        let record = |(ttl, rdata): (u32, QType)| DnsResourceRecord {
            name: Label::new(String::new()),
            record_type: 0,
            record_class: 1,
            ttl,
            rdlength: 0,
            rdata,
        };
        let mut msg = DnsMessage::new(1, vec![]);
        msg.header.rcode = rcode;
        msg.answers = answers.into_iter().map(record).collect();
        msg.authorities = authorities.into_iter().map(record).collect();
        msg
    }

    /// An A answer record fixture with the given TTL.
    fn a_record(ttl: u32) -> (u32, QType) {
        (ttl, QType::A("192.0.2.1".parse().unwrap()))
    }

    /// An SOA authority-record fixture with the given record TTL and
    /// MINIMUM field (the negative-TTL inputs).
    fn soa_record(ttl: u32, minimum: u32) -> (u32, QType) {
        (
            ttl,
            QType::SOA(
                Label::new(String::new()),
                Label::new(String::new()),
                1,
                2,
                3,
                4,
                minimum,
            ),
        )
    }

    /// Positive answers cache for the minimum record TTL.
    #[test]
    fn positive_ttl_is_the_minimum_answer_ttl() {
        let resp = response(0, vec![a_record(300), a_record(120)], vec![]);
        assert_eq!(cache_ttl(&resp), Some(Duration::from_secs(120)));
    }

    /// Very long TTLs are clamped to the one-hour cap.
    #[test]
    fn long_ttls_are_clamped() {
        let resp = response(0, vec![a_record(86_400)], vec![]);
        assert_eq!(cache_ttl(&resp), Some(Duration::from_secs(MAX_CACHE_TTL)));
    }

    /// NODATA and NXDOMAIN use the SOA-derived negative TTL
    /// (min of the SOA record TTL and the SOA MINIMUM field).
    #[test]
    fn negative_ttl_comes_from_the_soa() {
        let nodata = response(0, vec![], vec![soa_record(900, 60)]);
        assert_eq!(cache_ttl(&nodata), Some(Duration::from_secs(60)));

        let nxdomain = response(0x03, vec![], vec![soa_record(30, 900)]);
        assert_eq!(cache_ttl(&nxdomain), Some(Duration::from_secs(30)));
    }

    /// Without TTL information — no SOA for a negative answer, or a
    /// transient error code — the response is not cached.
    #[test]
    fn uncacheable_responses_have_no_ttl() {
        assert_eq!(cache_ttl(&response(0, vec![], vec![])), None);
        assert_eq!(cache_ttl(&response(0x03, vec![], vec![])), None);
        assert_eq!(
            cache_ttl(&response(0x02, vec![a_record(300)], vec![])),
            None
        );
    }

    /// Cache roundtrip: hits until expiry, gone after; zero-TTL
    /// responses are never cached.
    #[test]
    fn cache_hit_until_expiry() {
        let mut cache = DnsCache::default();
        let key: CacheKey = ("example.test".into(), 1);
        let now = Instant::now();

        cache.insert(key.clone(), &response(0, vec![a_record(50)], vec![]), now);
        assert!(cache.get(&key, now + Duration::from_secs(10)).is_some());
        assert!(cache.get(&key, now + Duration::from_secs(51)).is_none());

        // TTL 0: honored as not-cacheable.
        cache.insert(key.clone(), &response(0, vec![a_record(0)], vec![]), now);
        assert!(cache.get(&key, now).is_none());
    }

    /// The cache stays bounded: at capacity it drops everything rather
    /// than growing without limit under attacker-driven lookups.
    #[test]
    fn cache_is_bounded() {
        let mut cache = DnsCache::default();
        let now = Instant::now();
        for i in 0..MAX_CACHE_ENTRIES + 1 {
            let key: CacheKey = (format!("host{i}.test"), 1);
            cache.insert(key, &response(0, vec![a_record(300)], vec![]), now);
        }
        assert!(cache.entries.len() <= MAX_CACHE_ENTRIES);
    }

    // -- Integration: a real DoT server on loopback -------------------

    /// A minimal DNS-over-TLS test server: answers every query with a
    /// single A record (TTL 60), counts connections and wire queries,
    /// and — when `close_after_queries` is given — drops the
    /// connection after that many queries *on the same connection*,
    /// modeling an idle-timeout close so reconnect behavior can be
    /// exercised.
    ///
    /// Returns the bound address, the server's certificate (to load
    /// into the client's trust store — the client and server must share
    /// one self-signed cert), and the two counters.
    async fn spawn_mock_dot(
        close_after_queries: Option<u32>,
    ) -> (
        std::net::SocketAddr,
        rustls_pki_types::CertificateDer<'static>,
        Arc<std::sync::atomic::AtomicU32>,
        Arc<std::sync::atomic::AtomicU32>,
    ) {
        use std::sync::atomic::{AtomicU32, Ordering};

        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
            cert.key_pair.serialize_der().into(),
        );
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conns = Arc::new(AtomicU32::new(0));
        let queries = Arc::new(AtomicU32::new(0));

        let conns_task = Arc::clone(&conns);
        let queries_task = Arc::clone(&queries);
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                conns_task.fetch_add(1, Ordering::SeqCst);
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    continue;
                };
                let close_after = close_after_queries;
                let mut served_on_conn = 0u32;
                while let Ok(len) = tls.read_u16().await {
                    if len == 0 {
                        break;
                    }
                    let mut buf = vec![0; usize::from(len)];
                    if tls.read_exact(&mut buf).await.is_err() {
                        break;
                    }
                    let Ok((_, query)) = DnsMessage::from_bytes(&buf) else {
                        break;
                    };
                    let _ = queries_task.fetch_add(1, Ordering::SeqCst);
                    served_on_conn += 1;
                    let mut resp =
                        DnsMessage::new(query.header.transaction_id, query.questions.clone());
                    resp.header.qr = 1;
                    resp.answers.push(DnsResourceRecord {
                        name: Label::new(String::new()),
                        record_type: 1,
                        record_class: 1,
                        ttl: 60,
                        rdlength: 4,
                        rdata: QType::A("192.0.2.1".parse().unwrap()),
                    });
                    let bytes = resp.to_vec().unwrap();
                    if tls.write_u16(bytes.len() as u16).await.is_err()
                        || tls.write_all(&bytes).await.is_err()
                    {
                        break;
                    }
                    if close_after.is_some_and(|n| served_on_conn >= n) {
                        // Having answered, drop the connection (as an
                        // idle-timeout or restart would): the client
                        // must reconnect transparently on its next
                        // query.
                        break;
                    }
                }
            }
        });

        (addr, cert_der, conns, queries)
    }

    /// Reuse and caching against a real DoT endpoint: repeated
    /// identical queries hit the cache (no wire query), distinct
    /// queries reuse one connection, and a server-dropped connection
    /// is transparently re-established with the query retried.
    #[tokio::test]
    async fn reuses_connections_and_caches_results() {
        use std::sync::atomic::Ordering;

        let (addr, server_cert, conns, queries) = spawn_mock_dot(Some(2)).await;
        let endpoint = format!("127.0.0.1:{port}", port = addr.port());

        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(server_cert).expect("valid self-signed cert");
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let client = DnsClient::with_config(
            "127.0.0.1".parse().unwrap(),
            config,
            Duration::from_secs(5),
            Some(endpoint),
        );

        // First query: one connection, one wire query.
        let answer = client.query("a.test", 1).await.unwrap();
        assert_eq!(conns.load(Ordering::SeqCst), 1);
        assert_eq!(queries.load(Ordering::SeqCst), 1);
        assert!(
            matches!(answer.answers.first().map(|a| &a.rdata), Some(QType::A(_))),
            "expected an A answer"
        );

        // Identical query: served from the cache, nothing on the wire.
        client.query("a.test", 1).await.unwrap();
        assert_eq!(queries.load(Ordering::SeqCst), 1);

        // Distinct query: same connection (no new handshake).
        client.query("b.test", 1).await.unwrap();
        assert_eq!(conns.load(Ordering::SeqCst), 1);
        assert_eq!(queries.load(Ordering::SeqCst), 2);

        // The server drops the connection after the second query; the
        // next query must transparently reconnect and succeed.
        client.query("c.test", 1).await.unwrap();
        assert_eq!(conns.load(Ordering::SeqCst), 2);
        assert_eq!(queries.load(Ordering::SeqCst), 3);

        // And the new connection is itself reused.
        client.query("d.test", 1).await.unwrap();
        assert_eq!(conns.load(Ordering::SeqCst), 2);
        assert_eq!(queries.load(Ordering::SeqCst), 4);

        // Metrics mirror what happened: 5 queries, 1 cache hit, 2
        // connections, 4 answered exchanges, 1 discarded stale
        // connection (c.test's first attempt), nothing left in flight.
        let stats = client.stats();
        assert_eq!(
            stats,
            DnsStatsSnapshot {
                queries: 5,
                cache_hits: 1,
                connects: 2,
                connect_failures: 0,
                exchanges_ok: 4,
                exchange_errors: 1,
                timeouts: 0,
                waits: 0,
                wait_total_us: 0,
                wait_max_us: 0,
                waiting: 0,
                in_flight: 0,
                peak_in_flight: 1,
            }
        );
    }

    /// H6 (security report): a slow lookup (e.g. an attacker-published
    /// record whose authoritative server never answers) must not stall
    /// unrelated lookups. The mock answers names starting with "slow"
    /// after 1.5 s and everything else immediately; a fast query issued
    /// while the slow one is in flight completes on another pooled
    /// connection without waiting.
    #[tokio::test]
    async fn slow_lookup_does_not_block_other_lookups() {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
            cert.key_pair.serialize_der().into(),
        );
        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    while let Ok(len) = tls.read_u16().await {
                        let mut buf = vec![0; usize::from(len)];
                        if tls.read_exact(&mut buf).await.is_err() {
                            return;
                        }
                        let Ok((_, query)) = DnsMessage::from_bytes(&buf) else {
                            return;
                        };
                        let name: String = query
                            .questions
                            .first()
                            .map(|q| String::from(&q.name))
                            .unwrap_or_default();
                        if name.starts_with("slow") {
                            tokio::time::sleep(Duration::from_millis(1500)).await;
                        }
                        let mut resp =
                            DnsMessage::new(query.header.transaction_id, query.questions.clone());
                        resp.header.qr = 1;
                        let bytes = resp.to_vec().unwrap();
                        if tls.write_u16(bytes.len() as u16).await.is_err()
                            || tls.write_all(&bytes).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });

        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let client = Arc::new(DnsClient::with_config(
            "127.0.0.1".parse().unwrap(),
            config,
            Duration::from_secs(5),
            Some(format!("127.0.0.1:{}", addr.port())),
        ));

        let slow = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.query("slow.test", 1).await }
        });
        // Let the slow query take its connection first.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let started = Instant::now();
        client.query("fast.test", 1).await.unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(1000),
            "fast lookup waited {:?} behind the slow one",
            started.elapsed()
        );
        slow.await.unwrap().unwrap();

        // Both queries were in flight at once; nothing is left over.
        let stats = client.stats();
        assert_eq!(stats.peak_in_flight, 2);
        assert_eq!(stats.in_flight, 0);
        assert_eq!(stats.waiting, 0);
        assert_eq!(stats.waits, 0, "a free slot existed, so nobody waited");
        client.reset_peaks();
        assert_eq!(client.stats().peak_in_flight, 0);

        // Cancellation: a query whose future is dropped mid-exchange must
        // not leave the in-flight gauge raised (the gauges use drop
        // guards).
        let cancelled = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.query("slow2.test", 1).await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(client.stats().in_flight, 1);
        cancelled.abort();
        let _ = cancelled.await;
        assert_eq!(client.stats().in_flight, 0);
    }
}
