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
use rustls_pki_types::{CertificateDer, ServerName};
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// The DNS protocol module: message/record codec and wire helpers.
pub mod proto;
use crate::proto::{DnsMessage, DnsQuestion, DnsResourceRecord, Label, QType};

/// Whether `err` (from [`DnsClient::query`]) means the name itself is
/// invalid ([`proto::InvalidName`]): nothing was sent, and retrying can't
/// help. Callers treat it like a name that does not exist (RFC 7208 §4.3),
/// not like a transient resolver failure.
pub fn is_invalid_name(err: &anyhow::Error) -> bool {
    err.downcast_ref::<proto::InvalidName>().is_some()
}

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
        name: Label::new(proto::normalize_name(domain)?.to_string()),
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
        name: Label::new(proto::normalize_name(domain)?.to_string()),
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
    late_replies: AtomicU64,
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
    /// Query attempts that failed at the connection or protocol level
    /// (the connection was closed; the query retried once).
    pub exchange_errors: u64,
    /// Queries (or connects) that hit the per-query timeout. A timed-out
    /// query abandons its transaction ID; the connection stays usable.
    pub timeouts: u64,
    /// Responses that arrived for a transaction ID no longer in flight
    /// (the query had timed out or been cancelled); discarded.
    pub late_replies: u64,
    /// Cache misses that found every connection at its in-flight limit
    /// and had to wait for capacity.
    pub waits: u64,
    /// Total time cache misses spent waiting for capacity, in
    /// microseconds (divide by `queries - cache_hits` for the mean).
    pub wait_total_us: u64,
    /// Longest single wait for capacity, in microseconds.
    pub wait_max_us: u64,
    /// Queries waiting for capacity right now.
    pub waiting: u64,
    /// Queries in flight (holding capacity) right now.
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

/// Lock a std mutex, recovering the data if a previous holder panicked.
/// The tables guarded here stay consistent across a panic (every update
/// is a single insert/remove), and the guard types below lock in `Drop`,
/// where a second panic would abort the process.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// -- Pipelined connections (DESIGN §6.1) --------------------------------

/// Default number of pipelined DoT connections per [`DnsClient`].
pub const DEFAULT_CONNECTIONS: usize = 2;

/// Upper bound on [`DnsClient::with_connections`].
pub const MAX_CONNECTIONS: usize = 16;

/// Default limit on queries in flight on one connection
/// ([`DnsClient::with_max_in_flight`]); below the per-connection limits
/// common public resolvers enforce.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;

/// What a waiting query receives from its connection.
#[derive(Debug)]
enum Outcome {
    /// The validated response to this query.
    Response(DnsMessage),
    /// The connection failed before answering; the query may retry on a
    /// new connection.
    Failed(String),
}

/// One query waiting for its response on a pipelined connection.
#[derive(Debug)]
struct PendingQuery {
    /// Unique per submission, so a cancelled query's cleanup can never
    /// remove a later query that reused the same transaction ID.
    token: u64,
    /// The query as sent, for validating the response (question echo).
    query: DnsMessage,
    /// Where the response (or the connection failure) is delivered.
    reply: oneshot::Sender<Outcome>,
}

/// The in-flight table of one connection.
#[derive(Debug, Default)]
struct PendingTable {
    /// Waiting queries by transaction ID (unique among those in flight).
    queries: HashMap<u16, PendingQuery>,
    /// Set once the connection has failed or closed: no new submissions.
    closed: bool,
}

/// State shared between one connection's handle, its reader task, and
/// its writer task.
#[derive(Debug)]
struct Shared {
    table: Mutex<PendingTable>,
    stats: Arc<DnsStats>,
}

impl Shared {
    /// Mark the connection closed and fail every waiting query (they
    /// retry once on a new connection). Idempotent.
    fn fail_all(&self, reason: &str) {
        let drained: Vec<PendingQuery> = {
            let mut table = lock(&self.table);
            table.closed = true;
            table.queries.drain().map(|(_, p)| p).collect()
        };
        for pending in drained {
            let _ = pending.reply.send(Outcome::Failed(reason.to_string()));
        }
    }

    /// Deliver a response to the query waiting on its transaction ID.
    ///
    /// A response whose ID matches nothing in flight is a late reply to a
    /// query that already timed out or was cancelled: it is counted and
    /// discarded, and the connection stays usable. Returns `Err` when a
    /// response matches an ID but fails validation (question echo, QR,
    /// EDNS0 conformance): the resolver's view of this connection can no
    /// longer be trusted, so the caller tears the connection down.
    fn complete(&self, resp: DnsMessage) -> Result<()> {
        let pending = lock(&self.table)
            .queries
            .remove(&resp.header.transaction_id);
        let Some(pending) = pending else {
            self.stats.late_replies.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };
        if let Err(e) =
            validate_response(&pending.query, &resp).and_then(|()| resp.edns0().map(drop))
        {
            let _ = pending.reply.send(Outcome::Failed(e.to_string()));
            return Err(e);
        }
        let _ = pending.reply.send(Outcome::Response(resp));
        Ok(())
    }
}

/// Removes its query from the in-flight table when dropped — whether the
/// query got its answer, timed out, or its future was cancelled — so
/// abandoned queries never leak table entries.
struct PendingGuard {
    shared: Arc<Shared>,
    id: u16,
    token: u64,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        let mut table = lock(&self.shared.table);
        if table
            .queries
            .get(&self.id)
            .is_some_and(|p| p.token == self.token)
        {
            table.queries.remove(&self.id);
        }
    }
}

/// One pipelined DNS-over-TLS connection (RFC 7766 §6.2.1.1, RFC 7858
/// §3.4): many queries in flight at once, replies matched by
/// transaction ID and question echo, in whatever order the resolver
/// sends them.
///
/// A reader task owns the read half and a writer task owns the write
/// half. Queries hand whole frames to the writer over a channel, so a
/// query cancelled mid-send can never leave a partial frame on the wire.
/// Dropping the handle (when it is replaced in its slot and the last
/// query using it finishes) aborts both tasks and closes the connection.
#[derive(Debug)]
struct Pipeline {
    shared: Arc<Shared>,
    outbound: mpsc::UnboundedSender<Vec<u8>>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl Pipeline {
    /// Start the reader and writer tasks on an established connection.
    fn start(stream: DotStream, stats: Arc<DnsStats>) -> Self {
        let (read_half, write_half) = tokio::io::split(stream);
        let shared = Arc::new(Shared {
            table: Mutex::new(PendingTable::default()),
            stats,
        });
        let (outbound, frames) = mpsc::unbounded_channel();
        let reader = tokio::spawn(read_loop(read_half, Arc::clone(&shared)));
        let writer = tokio::spawn(write_loop(write_half, frames, Arc::clone(&shared)));
        Pipeline {
            shared,
            outbound,
            reader,
            writer,
        }
    }

    /// Whether the connection has failed or been closed by the resolver.
    fn is_closed(&self) -> bool {
        lock(&self.shared.table).closed
    }

    /// Queue one query on this connection.
    ///
    /// Returns `Ok(Some((reply, guard)))` once the query is registered and
    /// handed to the writer (keep `guard` alive while waiting), `Ok(None)`
    /// if the connection is already closed (retry on a new one), and
    /// `Err` only if the query cannot be encoded.
    fn submit(
        &self,
        domain: &str,
        qtype: u16,
        token: u64,
    ) -> Result<Option<(oneshot::Receiver<Outcome>, PendingGuard)>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let frame;
        let id;
        {
            let mut table = lock(&self.shared.table);
            if table.closed {
                return Ok(None);
            }
            id = free_transaction_id(&table.queries);
            let query = DnsMessage::new(
                id,
                vec![DnsQuestion {
                    name: Label::new(domain.to_string()),
                    record_type: qtype,
                    record_class: 0x01,
                }],
            );
            let bytes = query.to_vec()?;
            let len = u16::try_from(bytes.len()).context("DNS query too large")?;
            let mut buf = Vec::with_capacity(bytes.len() + 2);
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(&bytes);
            frame = buf;
            table.queries.insert(
                id,
                PendingQuery {
                    token,
                    query,
                    reply: reply_tx,
                },
            );
        }
        let guard = PendingGuard {
            shared: Arc::clone(&self.shared),
            id,
            token,
        };
        if self.outbound.send(frame).is_err() {
            // The writer is gone: the connection is dead. Dropping the
            // guard unregisters the query.
            self.shared.fail_all("DNS connection writer stopped");
            return Ok(None);
        }
        Ok(Some((reply_rx, guard)))
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

/// A random transaction ID not currently in flight on this connection.
/// IDs stay unpredictable (RFC 5452 hygiene, though TLS already
/// authenticates the channel); the table holds at most the in-flight
/// limit, so a free ID is found almost immediately.
fn free_transaction_id(in_flight: &HashMap<u16, PendingQuery>) -> u16 {
    let mut rng = rand::thread_rng();
    loop {
        let id: u16 = rng.gen();
        if !in_flight.contains_key(&id) {
            return id;
        }
    }
}

/// The reader task: deliver each response to its waiter until the
/// connection ends. A resolver-side close is seen here as EOF straight
/// away, so the next query reconnects instead of first failing on a dead
/// stream. Any end — EOF, I/O error, malformed frame, or a response that
/// fails validation — closes the connection and fails every waiter.
async fn read_loop(mut read_half: ReadHalf<DotStream>, shared: Arc<Shared>) {
    let reason = loop {
        let len = match read_half.read_u16().await {
            Ok(len) => len,
            Err(_) => break "DNS connection closed by resolver".to_string(),
        };
        let mut buf = vec![0; usize::from(len)];
        if read_half.read_exact(&mut buf).await.is_err() {
            break "DNS connection closed mid-response".to_string();
        }
        let resp = match DnsMessage::from_bytes(&buf) {
            Ok((_, resp)) => resp,
            Err(e) => break format!("malformed DNS response: {e}"),
        };
        if let Err(e) = shared.complete(resp) {
            break format!("invalid DNS response: {e}");
        }
    };
    shared.fail_all(&reason);
}

/// The writer task: write queued query frames, batching whatever is
/// already queued before each flush. A write failure closes the
/// connection and fails every waiter.
async fn write_loop(
    mut write_half: WriteHalf<DotStream>,
    mut frames: mpsc::UnboundedReceiver<Vec<u8>>,
    shared: Arc<Shared>,
) {
    while let Some(frame) = frames.recv().await {
        let mut result = write_half.write_all(&frame).await;
        while result.is_ok() {
            match frames.try_recv() {
                Ok(next) => result = write_half.write_all(&next).await,
                Err(_) => break,
            }
        }
        if result.is_ok() {
            result = write_half.flush().await;
        }
        if result.is_err() {
            shared.fail_all("write to DNS resolver failed");
            return;
        }
    }
}

/// One connection slot: the current pipelined connection (if any) and
/// how many queries are assigned to it.
#[derive(Debug, Default)]
struct Slot {
    /// Locked only to reuse or (re)establish the connection, so queries
    /// arriving while it connects wait for that one handshake rather
    /// than each opening their own.
    conn: AsyncMutex<Option<Arc<Pipeline>>>,
    /// Queries currently assigned to this slot (bounded by the client's
    /// in-flight limit).
    load: AtomicUsize,
}

/// A query's claim on a slot; releases its share of the slot's load when
/// dropped (including on cancellation).
struct SlotClaim<'a> {
    slot: &'a Slot,
}

impl Drop for SlotClaim<'_> {
    fn drop(&mut self) {
        self.slot.load.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A shared DNS-over-TLS client: a few lazily-established, **pipelined**
/// TLS connections (DESIGN §6.1), plus a TTL-based result cache shared
/// by every consumer (SPF, DKIM, DMARC).
///
/// Each connection carries up to [`DnsClient::max_in_flight`] queries at
/// once; a query goes to the least-loaded connection (ties prefer the
/// lowest slot, so a quiet server keeps one warm connection), and when
/// every connection is at its limit it waits for capacity. A slow lookup
/// therefore occupies one in-flight entry, not a whole connection.
///
/// A query that times out simply abandons its transaction ID — the
/// connection stays usable and a late reply is discarded. A connection
/// that fails (EOF, I/O error, malformed or invalid response) fails all
/// of its waiting queries, which retry once on a fresh connection.
#[derive(Debug)]
pub struct DnsClient {
    /// The resolver address (DNS-over-TLS on port 853).
    server: Ipv4Addr,
    /// Per-query timeout (and the connect timeout).
    timeout: Duration,
    /// TLS configuration (webpki roots in production; a test root for
    /// the mock-server integration tests).
    config: Arc<ClientConfig>,
    /// Endpoint override (mock DoT server on an ephemeral port);
    /// production always derives `server:853`.
    endpoint: Option<String>,
    /// Validated responses keyed by (qname, qtype).
    cache: Mutex<DnsCache>,
    /// The connection slots.
    slots: Vec<Slot>,
    /// Queries allowed in flight per connection.
    max_in_flight: usize,
    /// Client-wide capacity: `slots × max_in_flight` permits. A query
    /// holds one for its whole lifetime, which bounds every slot's load.
    capacity: Semaphore,
    /// Source of [`PendingQuery::token`]s.
    next_token: AtomicU64,
    /// Metrics (see [`DnsClient::stats`]).
    stats: Arc<DnsStats>,
}

impl DnsClient {
    /// A client for `server` with the default 5-second per-query
    /// timeout, [`DEFAULT_CONNECTIONS`] connections and
    /// [`DEFAULT_MAX_IN_FLIGHT`] queries in flight per connection.
    pub fn new(server: Ipv4Addr) -> Self {
        DnsClient::with_timeout(server, Duration::from_secs(5))
    }

    /// A client with an explicit per-query timeout.
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
            slots: (0..DEFAULT_CONNECTIONS).map(|_| Slot::default()).collect(),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            capacity: Semaphore::new(DEFAULT_CONNECTIONS * DEFAULT_MAX_IN_FLIGHT),
            next_token: AtomicU64::new(0),
            stats: Arc::new(DnsStats::default()),
        }
    }

    /// Also trust `roots` when verifying the resolver's certificate, so a
    /// local resolver with a private or self-signed certificate can be
    /// used (`--resolver-ca`). Call before the first query.
    ///
    /// The roots are **added** to the public webpki roots, not substituted
    /// for them, so public DoT resolvers keep working. They apply only to
    /// this DNS client. The certificate is still checked against the
    /// resolver's IP address, so it must carry that address as an IP
    /// subject alternative name. This replaces any TLS configuration given
    /// to [`DnsClient::with_config`].
    ///
    /// Returns `Err` if a certificate is not a usable trust anchor.
    pub fn with_extra_roots(mut self, roots: &[CertificateDer<'static>]) -> Result<Self> {
        self.config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store(roots)?)
                .with_no_client_auth(),
        );
        Ok(self)
    }

    /// Use `connections` pipelined connections (clamped to
    /// `1..=`[`MAX_CONNECTIONS`]). Call before the first query.
    pub fn with_connections(mut self, connections: usize) -> Self {
        let connections = connections.clamp(1, MAX_CONNECTIONS);
        self.slots = (0..connections).map(|_| Slot::default()).collect();
        self.capacity = Semaphore::new(connections * self.max_in_flight);
        self
    }

    /// Allow `max_in_flight` queries in flight per connection (at least
    /// 1). Call before the first query.
    pub fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight.max(1);
        self.capacity = Semaphore::new(self.slots.len() * self.max_in_flight);
        self
    }

    /// The number of connection slots.
    pub fn connections(&self) -> usize {
        self.slots.len()
    }

    /// The per-connection in-flight limit.
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
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
            late_replies: get(&s.late_replies),
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
    /// touching a connection. A miss takes a unit of client capacity
    /// (waiting if every connection is at its in-flight limit), claims
    /// the least-loaded connection slot, and is pipelined on that
    /// connection. A connection-level failure retries exactly once on a
    /// fresh connection; a timeout abandons the query without harming the
    /// connection.
    ///
    /// Returns `Ok(response)` — a validated response (ID, QR, question
    /// echo, EDNS0 conformance), possibly from the cache and possibly
    /// carrying a non-zero error rcode, which callers map to their own
    /// semantics — or `Err` when the resolver could not be consulted
    /// (connect failure, connection failure after the retry, protocol
    /// violation, or the per-query timeout elapsing).
    ///
    /// A name with no valid wire form (an empty label, a label over 63
    /// octets, or a name over 253) is refused **before** anything is sent,
    /// with an [`InvalidName`](crate::proto::InvalidName) error (see
    /// [`is_invalid_name`]). Such names are attacker-reachable (SPF
    /// records, DKIM `d=`/`s=`), and public resolvers silently drop the
    /// malformed query, so each one used to cost the full timeout (D3 in
    /// DEPLOYMENT.md). Surrounding whitespace and one trailing dot are
    /// removed first, so the cache key and the name sent are identical.
    pub async fn query(&self, domain: &str, qtype: u16) -> Result<DnsMessage> {
        let domain = proto::normalize_name(domain).map_err(anyhow::Error::new)?;
        let stats = &self.stats;
        stats.queries.fetch_add(1, Ordering::Relaxed);
        let key = (domain.to_ascii_lowercase(), qtype);
        if let Some(hit) = lock(&self.cache).get(&key, Instant::now()) {
            stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(hit);
        }

        // Capacity: one permit per in-flight query, client-wide. Held for
        // the query's whole lifetime (and released on cancellation).
        let _permit = match self.capacity.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                stats.waits.fetch_add(1, Ordering::Relaxed);
                let _waiting = GaugeGuard::new(&stats.waiting);
                let started = Instant::now();
                let permit = self
                    .capacity
                    .acquire()
                    .await
                    .expect("the capacity semaphore is never closed");
                let waited = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                stats.wait_total_us.fetch_add(waited, Ordering::Relaxed);
                stats.wait_max_us.fetch_max(waited, Ordering::Relaxed);
                permit
            }
        };
        let _in_flight = GaugeGuard::new(&stats.in_flight);
        stats
            .peak_in_flight
            .fetch_max(stats.in_flight.load(Ordering::Relaxed), Ordering::Relaxed);

        let claim = self.claim_slot().await;
        for attempt in 0..2 {
            let pipeline = self.get_or_connect(claim.slot).await?;
            let token = self.next_token.fetch_add(1, Ordering::Relaxed);
            let reason = match pipeline.submit(domain, qtype, token)? {
                None => "DNS connection closed".to_string(),
                Some((reply, _pending)) => match tokio::time::timeout(self.timeout, reply).await {
                    Ok(Ok(Outcome::Response(resp))) => {
                        stats.exchanges_ok.fetch_add(1, Ordering::Relaxed);
                        lock(&self.cache).insert(key, &resp, Instant::now());
                        return Ok(resp);
                    }
                    Ok(Ok(Outcome::Failed(reason))) => reason,
                    Ok(Err(_)) => "DNS connection closed".to_string(),
                    // Abandon this transaction ID; the connection stays
                    // usable and a late reply is discarded.
                    Err(_) => {
                        stats.timeouts.fetch_add(1, Ordering::Relaxed);
                        return Err(anyhow!("DNS query timed out"));
                    }
                },
            };
            // Connection-level failure: retry once on a fresh connection
            // (the slot replaces a closed connection on the next use).
            stats.exchange_errors.fetch_add(1, Ordering::Relaxed);
            if attempt == 1 {
                return Err(anyhow!("DNS query failed: {reason}"));
            }
        }
        unreachable!("the second attempt always returns")
    }

    /// Claim the least-loaded slot (ties: the lowest index). The caller
    /// holds a capacity permit, so some slot is below the in-flight
    /// limit; a claim that loses a race to a full slot is rolled back
    /// and retried.
    async fn claim_slot(&self) -> SlotClaim<'_> {
        loop {
            let slot = self
                .slots
                .iter()
                .min_by_key(|slot| slot.load.load(Ordering::Relaxed))
                .expect("a client always has at least one slot");
            if slot.load.fetch_add(1, Ordering::Relaxed) < self.max_in_flight {
                return SlotClaim { slot };
            }
            slot.load.fetch_sub(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
        }
    }

    /// The slot's open connection, or a newly established one if it has
    /// none or its connection has closed.
    ///
    /// Returns `Err` if connecting fails or exceeds the timeout. The
    /// connect (TCP + TLS handshake) is bounded like a query (H6,
    /// security report): a black-holed resolver must not hold the slot
    /// for the kernel's connect timeout.
    async fn get_or_connect(&self, slot: &Slot) -> Result<Arc<Pipeline>> {
        let mut conn = slot.conn.lock().await;
        if let Some(pipeline) = conn.as_ref() {
            if !pipeline.is_closed() {
                return Ok(Arc::clone(pipeline));
            }
        }
        // Drop a closed connection now; its tasks stop once the queries
        // still holding it finish.
        *conn = None;
        let stats = &self.stats;
        stats.connects.fetch_add(1, Ordering::Relaxed);
        match tokio::time::timeout(self.timeout, connect(&self.endpoint_str(), &self.config)).await
        {
            Ok(Ok(stream)) => {
                let pipeline = Arc::new(Pipeline::start(stream, Arc::clone(&self.stats)));
                *conn = Some(Arc::clone(&pipeline));
                Ok(pipeline)
            }
            Ok(Err(e)) => {
                stats.connect_failures.fetch_add(1, Ordering::Relaxed);
                Err(e.context("DNS query failed"))
            }
            Err(_) => {
                stats.connect_failures.fetch_add(1, Ordering::Relaxed);
                stats.timeouts.fetch_add(1, Ordering::Relaxed);
                Err(anyhow!("DNS connect timed out"))
            }
        }
    }

    /// The connect endpoint: `server:853`, or the test override.
    ///
    /// Returns the `ip:port` string the client dials.
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
    let root_cert_store = root_store(&[]).expect("no extra roots to reject");
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(),
    )
}

/// The resolver trust store: the public webpki roots **plus** `extra`.
///
/// The extra roots are added, never substituted, so a client configured
/// with a private CA for a local resolver still verifies public DoT
/// resolvers (1.1.1.1, 9.9.9.9, ...) exactly as before.
///
/// Returns `Err` if an extra certificate is not a usable trust anchor
/// (for example, not DER-encoded X.509).
fn root_store(extra: &[CertificateDer<'static>]) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for (i, cert) in extra.iter().enumerate() {
        store
            .add(cert.clone())
            .with_context(|| format!("resolver CA certificate #{} is not a usable root", i + 1))?;
    }
    Ok(store)
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

    /// `--resolver-ca` (D2, DEPLOYMENT.md): extra roots are added to the
    /// public webpki set, never substituted for it, so public DoT
    /// resolvers keep verifying when a private CA is configured.
    #[test]
    fn extra_roots_are_added_to_the_public_roots() {
        let public = webpki_roots::TLS_SERVER_ROOTS.len();
        assert_eq!(root_store(&[]).unwrap().len(), public);

        let private = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .unwrap()
            .cert
            .der()
            .clone();
        assert_eq!(root_store(&[private]).unwrap().len(), public + 1);

        // Bytes that are not a certificate are refused, not ignored.
        let garbage = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00]);
        assert!(root_store(&[garbage]).is_err());
    }

    /// D3 / L1: names are checked against the RFC 1035 limits before they
    /// can be encoded or sent.
    #[test]
    fn name_limits() {
        use crate::proto::{check_name, normalize_name};
        let label = |n: usize| "a".repeat(n);

        assert!(check_name(&format!("{}.example.com", label(63))).is_ok());
        assert!(check_name(&format!("{}.example.com", label(64))).is_err());
        // 253 octets in text form is the longest valid name.
        let long = |total: usize| {
            let mut s = String::new();
            while s.len() + 2 <= total {
                s.push_str("a.");
            }
            s.push('a');
            s.truncate(total);
            s.trim_end_matches('.').to_string()
        };
        assert_eq!(long(253).len(), 253);
        assert!(check_name(&long(253)).is_ok());
        assert!(check_name(&format!("{}a.b", long(252))).is_err());
        for bad in ["a..b", ".a", "a.", ".."] {
            assert!(check_name(bad).is_err(), "{bad:?} must be refused");
        }
        // The root name is encodable, but never queried.
        assert!(check_name("").is_ok());
        assert!(normalize_name("").is_err());
        assert!(normalize_name(".").is_err());
        // One trailing dot and surrounding whitespace are normalized away.
        assert_eq!(normalize_name(" Example.COM. ").unwrap(), "Example.COM");
        assert!(normalize_name("example.com..").is_err());
        // The error message is bounded even for a huge name.
        let err = check_name(&label(10_000)).unwrap_err().to_string();
        assert!(err.len() < 200, "{err}");
    }

    /// L1: the encoder refuses a label it can't represent instead of
    /// writing its length into the pointer/extended-label bits.
    #[test]
    fn encoder_refuses_oversized_labels() {
        let ok = Label::new(format!("{}.example.com", "a".repeat(63)));
        assert_eq!(ok.to_bytes().unwrap()[0], 63);
        for bad in [
            "a".repeat(64),
            "a".repeat(200),
            "a".repeat(300),
            "a..b".into(),
        ] {
            assert!(Label::new(bad.clone()).to_bytes().is_err(), "{bad:?}");
        }
        let question = DnsMessage::new(
            1,
            vec![DnsQuestion {
                name: Label::new("a".repeat(70)),
                record_type: 1,
                record_class: 1,
            }],
        );
        assert!(question.to_vec().is_err());
    }

    /// D3: an invalid name is refused before anything touches the
    /// network: no capacity, no connection, an `InvalidName` error.
    #[tokio::test]
    async fn invalid_names_are_refused_without_a_query() {
        let client = DnsClient::with_timeout("127.0.0.1".parse().unwrap(), Duration::from_secs(30));
        let started = Instant::now();
        for bad in [
            format!("{}.example.com", "s".repeat(70)),
            "a..b.example".to_string(),
            String::new(),
        ] {
            let err = client.query(&bad, 16).await.unwrap_err();
            assert!(is_invalid_name(&err), "{err:#}");
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        let stats = client.stats();
        assert_eq!(stats.connects, 0, "nothing may be sent for an invalid name");
        assert_eq!(stats.queries, 0);
    }

    /// The name is normalized once, so `a.test.` and `a.test` are one
    /// cache entry (and the trailing-dot form is valid; it used to encode
    /// as an empty label, i.e. a malformed query).
    #[tokio::test]
    async fn trailing_dot_names_share_the_cache_entry() {
        use std::sync::atomic::Ordering;
        let (addr, server_cert, _conns, queries) = spawn_mock_dot(None).await;
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(server_cert).unwrap();
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let client = DnsClient::with_config(
            "127.0.0.1".parse().unwrap(),
            config,
            Duration::from_secs(5),
            Some(format!("127.0.0.1:{}", addr.port())),
        );
        client.query("a.test.", 1).await.unwrap();
        client.query(" A.test ", 1).await.unwrap();
        assert_eq!(queries.load(Ordering::SeqCst), 1);
        assert_eq!(client.stats().cache_hits, 1);
    }

    /// D2: a resolver with a private (here self-signed) certificate is
    /// refused by default and trusted once its CA is added.
    #[tokio::test]
    async fn extra_root_trusts_a_private_resolver() {
        let (addr, server_cert, _conns, _queries) = spawn_mock_dot(None).await;
        let endpoint = format!("127.0.0.1:{}", addr.port());
        let client = |config| {
            DnsClient::with_config(
                "127.0.0.1".parse().unwrap(),
                config,
                Duration::from_secs(5),
                Some(endpoint.clone()),
            )
        };

        // Public roots only: the private certificate does not verify.
        let err = client(default_client_config())
            .query("a.test", 1)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("TLS handshake"),
            "expected a TLS verification failure, got {err:#}"
        );

        // With the CA added, the same resolver is trusted.
        let trusted = client(default_client_config())
            .with_extra_roots(&[server_cert])
            .unwrap();
        let resp = trusted.query("a.test", 1).await.unwrap();
        assert!(matches!(
            resp.answers.first().map(|a| &a.rdata),
            Some(QType::A(_))
        ));
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
        // connections, 4 answered exchanges, nothing left in flight. The
        // reader task normally sees the server's close as EOF before
        // c.test is sent, so c.test reconnects without a failed attempt;
        // if c.test wins that race it fails once and retries. Either way
        // at most one attempt fails.
        let stats = client.stats();
        assert!(stats.exchange_errors <= 1, "{stats:?}");
        assert_eq!(
            stats,
            DnsStatsSnapshot {
                queries: 5,
                cache_hits: 1,
                connects: 2,
                connect_failures: 0,
                exchanges_ok: 4,
                exchange_errors: stats.exchange_errors,
                timeouts: 0,
                late_replies: 0,
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

    // -- Pipelining (DESIGN §6.1) --------------------------------------

    /// A pipelining-capable mock DoT resolver.
    struct Mock {
        addr: std::net::SocketAddr,
        cert: rustls_pki_types::CertificateDer<'static>,
        conns: Arc<std::sync::atomic::AtomicU32>,
        queries: Arc<std::sync::atomic::AtomicU32>,
    }

    /// How the mock answers.
    #[derive(Clone, Copy)]
    enum MockMode {
        /// Every query is answered concurrently after `delay_for(name)`,
        /// so replies come back in completion order, not query order.
        Concurrent(fn(&str) -> Duration),
        /// Like `Concurrent` (no delay), except the first connection
        /// reads this many queries and then closes without answering.
        CloseFirstAfter(u32),
        /// Read this many queries, then answer them all in reverse order
        /// in a single write (several replies arrive in one read).
        ReverseBatch(usize),
    }

    /// A response to `query`: one A record (192.0.2.1) with TTL 0, so
    /// nothing is cached and repeated names reach the mock.
    fn mock_answer(query: &DnsMessage) -> Vec<u8> {
        let mut resp = DnsMessage::new(query.header.transaction_id, query.questions.clone());
        resp.header.qr = 1;
        resp.answers.push(DnsResourceRecord {
            name: Label::new(String::new()),
            record_type: 1,
            record_class: 1,
            ttl: 0,
            rdlength: 4,
            rdata: QType::A("192.0.2.1".parse().unwrap()),
        });
        let bytes = resp.to_vec().unwrap();
        let mut frame = (bytes.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&bytes);
        frame
    }

    async fn spawn_mock(mode: MockMode) -> Mock {
        use std::sync::atomic::{AtomicU32, Ordering};

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
        let conns = Arc::new(AtomicU32::new(0));
        let queries = Arc::new(AtomicU32::new(0));

        let (conns_task, queries_task) = (Arc::clone(&conns), Arc::clone(&queries));
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let conn_number = conns_task.fetch_add(1, Ordering::SeqCst) + 1;
                let acceptor = acceptor.clone();
                let queries = Arc::clone(&queries_task);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    let (mut rd, mut wr) = tokio::io::split(tls);
                    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    let writer = tokio::spawn(async move {
                        while let Some(frame) = rx.recv().await {
                            if wr.write_all(&frame).await.is_err() || wr.flush().await.is_err() {
                                return;
                            }
                        }
                    });
                    let mut batch: Vec<DnsMessage> = Vec::new();
                    let mut read_on_conn = 0u32;
                    while let Ok(len) = rd.read_u16().await {
                        let mut buf = vec![0; usize::from(len)];
                        if rd.read_exact(&mut buf).await.is_err() {
                            break;
                        }
                        let Ok((_, query)) = DnsMessage::from_bytes(&buf) else {
                            break;
                        };
                        queries.fetch_add(1, Ordering::SeqCst);
                        read_on_conn += 1;
                        match mode {
                            MockMode::Concurrent(delay_for) => {
                                let name = String::from(&query.questions[0].name);
                                let tx = tx.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(delay_for(&name)).await;
                                    let _ = tx.send(mock_answer(&query));
                                });
                            }
                            MockMode::CloseFirstAfter(n) => {
                                if conn_number == 1 {
                                    if read_on_conn >= n {
                                        // Close with every query unanswered.
                                        writer.abort();
                                        return;
                                    }
                                } else {
                                    let _ = tx.send(mock_answer(&query));
                                }
                            }
                            MockMode::ReverseBatch(n) => {
                                batch.push(query);
                                if batch.len() == n {
                                    let mut all = Vec::new();
                                    for q in batch.drain(..).rev() {
                                        all.extend(mock_answer(&q));
                                    }
                                    let _ = tx.send(all);
                                }
                            }
                        }
                    }
                });
            }
        });
        Mock {
            addr,
            cert: cert_der,
            conns,
            queries,
        }
    }

    /// A client trusting `mock`'s certificate and dialing its port.
    fn mock_client(mock: &Mock, timeout: Duration) -> DnsClient {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(mock.cert.clone()).unwrap();
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        DnsClient::with_config(
            "127.0.0.1".parse().unwrap(),
            config,
            timeout,
            Some(format!("127.0.0.1:{}", mock.addr.port())),
        )
    }

    /// Names starting with "slow" answer after 1.5 s; "late" after 800 ms.
    fn slow_names(name: &str) -> Duration {
        if name.starts_with("slow") {
            Duration::from_millis(1500)
        } else if name.starts_with("late") {
            Duration::from_millis(800)
        } else {
            Duration::ZERO
        }
    }

    /// Several queries on ONE connection; the resolver answers them in
    /// reverse order, all in a single write. Every query gets its own
    /// answer (matched by ID and question), on one connection.
    #[tokio::test]
    async fn out_of_order_replies_in_one_read_are_matched() {
        let mock = spawn_mock(MockMode::ReverseBatch(3)).await;
        let client = Arc::new(mock_client(&mock, Duration::from_secs(5)).with_connections(1));
        let mut tasks = Vec::new();
        for name in ["one.test", "two.test", "three.test"] {
            let client = Arc::clone(&client);
            tasks.push(tokio::spawn(async move {
                let resp = client.query(name, 1).await.unwrap();
                String::from(&resp.questions[0].name)
            }));
        }
        for (task, name) in tasks
            .into_iter()
            .zip(["one.test", "two.test", "three.test"])
        {
            assert_eq!(task.await.unwrap(), name, "each query gets its own answer");
        }
        use std::sync::atomic::Ordering::SeqCst;
        assert_eq!(
            mock.conns.load(SeqCst),
            1,
            "all three shared one connection"
        );
        assert_eq!(client.stats().exchanges_ok, 3);
    }

    /// With a single connection, a fast query sent while a slow one is
    /// pending completes first (it is not queued behind it).
    #[tokio::test]
    async fn fast_query_overtakes_slow_one_on_the_same_connection() {
        let mock = spawn_mock(MockMode::Concurrent(slow_names)).await;
        let client = Arc::new(mock_client(&mock, Duration::from_secs(5)).with_connections(1));
        let slow = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.query("slow.test", 1).await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let started = Instant::now();
        client.query("fast.test", 1).await.unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "fast query waited {:?}",
            started.elapsed()
        );
        slow.await.unwrap().unwrap();
        use std::sync::atomic::Ordering::SeqCst;
        assert_eq!(mock.conns.load(SeqCst), 1);
        assert_eq!(client.stats().peak_in_flight, 2);
    }

    /// A query that times out abandons its ID; the connection stays up,
    /// the next query uses it, and the late reply is discarded.
    #[tokio::test]
    async fn timeout_keeps_the_connection_and_discards_the_late_reply() {
        let mock = spawn_mock(MockMode::Concurrent(slow_names)).await;
        let client = mock_client(&mock, Duration::from_millis(300)).with_connections(1);

        let err = client.query("late.test", 1).await.unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        client.query("fast.test", 1).await.unwrap();

        // The late reply arrives ~800 ms after it was sent.
        tokio::time::sleep(Duration::from_millis(700)).await;
        client.query("fast2.test", 1).await.unwrap();

        use std::sync::atomic::Ordering::SeqCst;
        let stats = client.stats();
        assert_eq!(
            mock.conns.load(SeqCst),
            1,
            "the timeout did not cost a reconnect"
        );
        assert_eq!(stats.connects, 1);
        assert_eq!(stats.timeouts, 1);
        assert_eq!(stats.late_replies, 1);
        assert_eq!(stats.exchange_errors, 0);
        assert_eq!(stats.exchanges_ok, 2);
    }

    /// The resolver closes a connection with several queries pending:
    /// every waiter fails and retries once on a new connection, and all
    /// of them succeed.
    #[tokio::test]
    async fn connection_close_retries_every_pending_query() {
        let mock = spawn_mock(MockMode::CloseFirstAfter(3)).await;
        let client = Arc::new(mock_client(&mock, Duration::from_secs(5)).with_connections(1));
        let mut tasks = Vec::new();
        for name in ["a.test", "b.test", "c.test"] {
            let client = Arc::clone(&client);
            tasks.push(tokio::spawn(async move { client.query(name, 1).await }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        use std::sync::atomic::Ordering::SeqCst;
        let stats = client.stats();
        assert_eq!(mock.conns.load(SeqCst), 2);
        assert_eq!(mock.queries.load(SeqCst), 6, "3 unanswered + 3 retried");
        assert_eq!(stats.exchange_errors, 3);
        assert_eq!(stats.exchanges_ok, 3);
    }

    /// Back-pressure: with every connection at its in-flight limit, a
    /// further query waits for capacity (and is counted as a wait)
    /// instead of exceeding the limit.
    #[tokio::test]
    async fn in_flight_limit_applies_back_pressure() {
        let mock = spawn_mock(MockMode::Concurrent(slow_names)).await;
        let client = Arc::new(
            mock_client(&mock, Duration::from_secs(5))
                .with_connections(1)
                .with_max_in_flight(2),
        );
        let mut slow = Vec::new();
        for i in 0..2 {
            let client = Arc::clone(&client);
            slow.push(tokio::spawn(async move {
                client.query(&format!("slow{i}.test"), 1).await
            }));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(client.stats().in_flight, 2);

        let started = Instant::now();
        client.query("fast.test", 1).await.unwrap();
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(1000),
            "the third query should wait for capacity, waited {waited:?}"
        );
        for task in slow {
            task.await.unwrap().unwrap();
        }
        let stats = client.stats();
        assert_eq!(stats.waits, 1);
        assert_eq!(stats.peak_in_flight, 2, "the limit was never exceeded");
        assert_eq!(stats.waiting, 0);
    }

    /// A cancelled query frees its capacity, its slot load, and its
    /// in-flight table entry; its eventual reply is discarded as late.
    #[tokio::test]
    async fn cancelled_query_frees_its_in_flight_entry() {
        let mock = spawn_mock(MockMode::Concurrent(slow_names)).await;
        let client = Arc::new(mock_client(&mock, Duration::from_secs(5)).with_connections(1));
        let cancelled = tokio::spawn({
            let client = Arc::clone(&client);
            async move { client.query("slow.test", 1).await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(client.stats().in_flight, 1);
        cancelled.abort();
        let _ = cancelled.await;

        let stats = client.stats();
        assert_eq!(stats.in_flight, 0);
        assert_eq!(client.slots[0].load.load(Ordering::Relaxed), 0);
        let pipeline = client.slots[0].conn.lock().await.clone().unwrap();
        assert!(lock(&pipeline.shared.table).queries.is_empty());
        assert_eq!(
            client.capacity.available_permits(),
            client.max_in_flight(),
            "capacity returned"
        );

        // The slow reply still arrives and is discarded; the connection
        // stays usable.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        client.query("fast.test", 1).await.unwrap();
        assert_eq!(client.stats().late_replies, 1);
        assert!(!pipeline.is_closed());
    }

    /// H6 (security report, re-opened in round 4): with the old 8-slot
    /// pool, 8 slow lookups (one client IP's worth of sessions) stalled
    /// every other lookup. Pipelined, 20 slow lookups in flight still
    /// leave a fast lookup unaffected, at the default configuration.
    #[tokio::test]
    async fn many_slow_lookups_do_not_stall_others() {
        let mock = spawn_mock(MockMode::Concurrent(slow_names)).await;
        let client = Arc::new(mock_client(&mock, Duration::from_secs(5)));
        let mut slow = Vec::new();
        for i in 0..20 {
            let client = Arc::clone(&client);
            slow.push(tokio::spawn(async move {
                client.query(&format!("slow{i}.test"), 1).await
            }));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(client.stats().in_flight, 20);

        let started = Instant::now();
        client.query("fast.test", 1).await.unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "fast lookup waited {:?} behind 20 slow ones",
            started.elapsed()
        );
        for task in slow {
            task.await.unwrap().unwrap();
        }
        use std::sync::atomic::Ordering::SeqCst;
        assert!(mock.conns.load(SeqCst) <= DEFAULT_CONNECTIONS as u32);
        assert_eq!(client.stats().waits, 0);
    }
}
