//! SPF (RFC 7208): identity evaluation over an abstract DNS resolver.
//!
//! `check_host` implements the full mechanism set with the
//! RFC 7208 §4.6.4 lookup budget. The [`SpfResolver`] trait decouples
//! evaluation from DNS so tests run on fixtures and production runs on
//! DNS-over-TLS ([`DotResolver`]).
#![warn(missing_docs)]

use anyhow::Result;
use async_recursion::async_recursion;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::Serialize;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

use dns::proto::QType;
use dns::DnsClient;
pub use dns::Lookup;

/// The public module for the lexer and AST parser.
pub mod parser;
use crate::parser::parser::{
    is_spf_record, parse, DualCidr, Spf, SpfDirective, SpfMacroSubs, SpfMechanism, SpfModifier,
    SpfQualifier, SpfTerm,
};

/// The result of an SPF evaluation (RFC 7208 Section 2.6).
///
/// Serialized under its RFC 7208/8601 result name (`pass`, `softfail`,
/// `temperror`, ...; see [`SpfResult::as_str`]), a stable name stored
/// data can rely on; the variant names written by older versions (`Pass`,
/// `SoftFail`) are still read.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpfResult {
    /// No SPF record published for the checked domain.
    #[serde(alias = "None")]
    None,
    /// The domain explicitly asserts no opinion (`?all`).
    #[serde(alias = "Neutral")]
    Neutral,
    /// The sending IP is authorized.
    #[serde(alias = "Pass")]
    Pass,
    /// The sending IP is explicitly not authorized (`-all`).
    #[serde(alias = "Fail")]
    Fail,
    /// The sending IP is probably not authorized (`~all`).
    #[serde(alias = "SoftFail")]
    SoftFail,
    /// A transient DNS error; evaluation may be retried.
    #[serde(alias = "TempError")]
    TempError,
    /// The record (or the evaluation) is unusable.
    #[serde(alias = "PermError")]
    PermError,
}

impl SpfResult {
    /// Returns the result's RFC 7208 §2.6 / RFC 8601 name, as used in
    /// `Authentication-Results:` and stored data.
    pub fn as_str(&self) -> &'static str {
        match self {
            SpfResult::None => "none",
            SpfResult::Neutral => "neutral",
            SpfResult::Pass => "pass",
            SpfResult::Fail => "fail",
            SpfResult::SoftFail => "softfail",
            SpfResult::TempError => "temperror",
            SpfResult::PermError => "permerror",
        }
    }
}

/// Why an SPF evaluation could not produce a normal result. The variants
/// matter because they map to different SMTP outcomes (RFC 7208 Section
/// 4.6.1): transient DNS failures and the time limit are 4xx (TempError),
/// everything else — including both lookup limits — is 5xx (PermError).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpfError {
    /// A DNS lookup failed; the evaluation may be retried.
    #[error("transient DNS failure")]
    Temp,
    /// The record does not parse, or is otherwise unusable.
    #[error("invalid SPF record")]
    Perm,
    /// The RFC 7208 §4.6.4 10-lookup budget was exceeded.
    #[error("SPF DNS lookup limit of {0} exceeded")]
    LookupLimit(usize),
    /// The RFC 7208 §4.6.4 2-void-lookup budget was exceeded.
    #[error("SPF void lookup limit of {0} exceeded")]
    VoidLimit(usize),
    /// One `mx` mechanism needed more than the RFC 7208 §4.6.4 limit of
    /// address lookups (one per MX exchange).
    #[error("SPF mx mechanism needs more than {0} address lookups")]
    AddressLimit(usize),
    /// The whole evaluation ran past its elapsed-time limit
    /// ([`EVALUATION_DEADLINE`]); RFC 7208 §4.6.4 makes this a TempError.
    #[error("SPF evaluation exceeded its {0:?} time limit")]
    Deadline(Duration),
}

impl SpfError {
    /// Returns the SPF result this error produces: TempError for
    /// [`SpfError::Temp`] and [`SpfError::Deadline`], PermError otherwise.
    pub fn to_result(&self) -> SpfResult {
        match self {
            SpfError::Temp | SpfError::Deadline(_) => SpfResult::TempError,
            SpfError::Perm
            | SpfError::LookupLimit(_)
            | SpfError::VoidLimit(_)
            | SpfError::AddressLimit(_) => SpfResult::PermError,
        }
    }
}

/// RFC 7208 Section 4.6.4 evaluation limits, shared by one `check_host()`
/// evaluation: every DNS-querying term (`include`, `a`, `mx`, `ptr`,
/// `exists`, and `redirect`) is one lookup, and a query of one of those
/// terms that returns nothing is one void lookup. The address lookups
/// behind `mx` and `ptr` are not terms: they have their own per-mechanism
/// cap ([`MAX_ADDRESS_LOOKUPS`]) and are never void lookups.
///
/// The budget is what makes hostile records safe to evaluate: a circular
/// include/redirect chain or a record with dozens of mechanisms terminates
/// with PermError after at most [`MAX_LOOKUPS`] queries instead of
/// recursing without bound.
#[derive(Default)]
struct Budget {
    /// DNS-querying terms evaluated so far.
    lookups: usize,
    /// Lookups so far that returned no records.
    void: usize,
}

/// RFC 7208 §4.6.4: the most DNS-querying terms one evaluation may use.
const MAX_LOOKUPS: usize = 10;
/// RFC 7208 §4.6.4: the most void lookups one evaluation may make.
const MAX_VOID_LOOKUPS: usize = 2;
/// RFC 7208 §4.6.4: the most address lookups one `mx` mechanism may make
/// (more is PermError), and the most PTR names one `ptr` mechanism
/// considers (the rest are ignored).
const MAX_ADDRESS_LOOKUPS: usize = 10;

impl Budget {
    /// Account one DNS lookup.
    ///
    /// # Errors
    ///
    /// [`SpfError::LookupLimit`] once more than [`MAX_LOOKUPS`] are spent:
    /// the evaluation must abort with PermError (RFC 7208 Section 4.6.4:
    /// "If this limit is exceeded, a PermError MUST be returned").
    fn spend(&mut self) -> Result<(), SpfError> {
        self.lookups += 1;
        if self.lookups > MAX_LOOKUPS {
            return Err(SpfError::LookupLimit(MAX_LOOKUPS));
        }
        Ok(())
    }

    /// Account one void lookup — a query that returned no records at all
    /// (NXDOMAIN or an empty answer section).
    ///
    /// # Errors
    ///
    /// [`SpfError::VoidLimit`] once more than [`MAX_VOID_LOOKUPS`] occur.
    fn record_void(&mut self) -> Result<(), SpfError> {
        self.void += 1;
        if self.void > MAX_VOID_LOOKUPS {
            return Err(SpfError::VoidLimit(MAX_VOID_LOOKUPS));
        }
        Ok(())
    }
}

/// The DNS lookups SPF evaluation needs, abstracted so evaluations can run
/// against recorded fixtures in tests instead of live DNS.
///
/// Every lookup has three outcomes ([`Lookup`]): found, absent (NXDOMAIN,
/// no records of the type, or a name with no valid wire form) and a
/// temporary error, which callers must never mistake for "absent".
pub trait SpfResolver {
    /// TXT lookup (qtype 16): all strings concatenated by the codec,
    /// which is what SPF records need (they live in one TXT record but
    /// DKIM keys span multiple strings).
    fn txt(&self, domain: &str) -> impl Future<Output = Lookup<String>> + Send;
    /// A lookup (qtype 1): the IPv4 addresses of the domain.
    fn a(&self, domain: &str) -> impl Future<Output = Lookup<Ipv4Addr>> + Send;
    /// MX lookup (qtype 15): (preference, exchange) pairs in record order.
    fn mx(&self, domain: &str) -> impl Future<Output = Lookup<(u16, String)>> + Send;
    /// PTR lookup (qtype 12): the reverse-lookup names.
    fn ptr(&self, domain: &str) -> impl Future<Output = Lookup<String>> + Send;
}

/// Unwrap the lookup of a DNS-querying term (the mechanism's own query):
/// found values, or nothing (one void lookup, RFC 7208 §4.6.4).
///
/// # Errors
///
/// [`SpfError::Temp`] for a temporary error, and the budget's void limit.
fn term_lookup<T>(lookup: Lookup<T>, budget: &mut Budget) -> std::result::Result<Vec<T>, SpfError> {
    match lookup {
        Lookup::Found(values) => Ok(values),
        Lookup::Absent => {
            budget.record_void()?;
            Ok(Vec::new())
        }
        Lookup::TempError(_) => Err(SpfError::Temp),
    }
}

/// Unwrap a lookup that isn't a term (a record fetch, or an address
/// lookup behind `mx`/`ptr`): found values, or nothing.
///
/// # Errors
///
/// [`SpfError::Temp`] for a temporary error.
fn plain_lookup<T>(lookup: Lookup<T>) -> std::result::Result<Vec<T>, SpfError> {
    match lookup {
        Lookup::Found(values) => Ok(values),
        Lookup::Absent => Ok(Vec::new()),
        Lookup::TempError(_) => Err(SpfError::Temp),
    }
}

/// [`SpfResolver`] over DNS-over-TLS. Each query is bounded by the
/// client's per-query timeout; a resolver that stalls (or a black-holed
/// route) produces a transient error instead of hanging the SMTP session.
pub struct DotResolver {
    /// The shared DNS client: pooled DNS-over-TLS connection and a
    /// TTL-based result cache, shared across every consumer in the
    /// process.
    client: Arc<DnsClient>,
}

impl DotResolver {
    /// A resolver for `server` with its own client and the default
    /// 5-second per-query timeout. Prefer [`DotResolver::shared`] in a server:
    /// one client per process means one pooled connection and one warm
    /// cache instead of a fresh handshake per evaluation.
    pub fn new(server: Ipv4Addr) -> Self {
        DotResolver::with_timeout(server, Duration::from_secs(5))
    }

    /// A resolver for `server` with its own client and the per-query
    /// timeout `timeout`.
    pub fn with_timeout(server: Ipv4Addr, timeout: Duration) -> Self {
        DotResolver {
            client: Arc::new(DnsClient::with_timeout(server, timeout)),
        }
    }

    /// Wrap the already-shared `client`. This is how a server should build
    /// its resolver: the client pools the TLS connection and caches
    /// results across every SPF, DKIM, and DMARC lookup in the process.
    pub fn shared(client: Arc<DnsClient>) -> Self {
        DotResolver { client }
    }

    /// Returns the underlying shared client, for consumers outside SPF
    /// (the DKIM key lookup uses the same pooled connection and cache).
    pub fn client(&self) -> Arc<DnsClient> {
        Arc::clone(&self.client)
    }
}

/// A name with no valid wire form (an empty label, a label over 63
/// octets, or a name over 253) is looked up as [`Lookup::Absent`] without
/// sending anything: RFC 7208 §4.3 treats a malformed domain like one
/// that does not exist. As a temporary error it would give TempError
/// (`451`) and an endless retry for a name that can never resolve.
impl SpfResolver for DotResolver {
    // The A qtype is checked on the wire against a mock DoT server by
    // `wire::a_lookups_query_type_1_over_the_wire`.
    async fn txt(&self, domain: &str) -> Lookup<String> {
        // 0x10 = TXT.
        self.client
            .lookup(domain, 0x10, |r| match r {
                QType::TXT(s) => Some(s),
                _ => None,
            })
            .await
    }

    async fn a(&self, domain: &str) -> Lookup<Ipv4Addr> {
        // 0x01 = A.
        self.client
            .lookup(domain, 0x01, |r| match r {
                QType::A(ip) => Some(ip),
                _ => None,
            })
            .await
    }

    async fn mx(&self, domain: &str) -> Lookup<(u16, String)> {
        // 0x0F = MX.
        self.client
            .lookup(domain, 0x0F, |r| match r {
                QType::MX(pref, label) => Some((pref, String::from(&label))),
                _ => None,
            })
            .await
    }

    async fn ptr(&self, domain: &str) -> Lookup<String> {
        // 0x0C = PTR.
        self.client
            .lookup(domain, 0x0C, |r| match r {
                QType::PTR(label) => Some(String::from(&label)),
                _ => None,
            })
            .await
    }
}

/// Fetch the SPF record of `domain` through `resolver` and parse it with
/// the macro context `subs`.
///
/// Returns the parsed record, or `None` when the domain publishes no
/// `v=spf1` TXT record (NXDOMAIN or no matching record).
///
/// # Errors
///
/// [`SpfError::Temp`] for a failed lookup; [`SpfError::Perm`] for more
/// than one `v=spf1` record or one that does not parse (RFC 7208 §3.2).
pub async fn query_spf_record<R: SpfResolver + Sync>(
    resolver: &R,
    domain: &str,
    subs: &SpfMacroSubs,
) -> std::result::Result<Option<Spf>, SpfError> {
    // NOTE: no hostname-syntax validation here: underscore-prefixed names
    // (`_spf.example.com`, `selector._domainkey.example.com`) are valid in
    // DNS and routinely appear in SPF includes.
    let txts = plain_lookup(resolver.txt(domain).await)?;

    // RFC 7208 Section 3.2: a domain with more than one v=spf1 record is a
    // permanent error, and a record that does not parse is one too.
    let mut found: Option<Spf> = None;
    for txt in txts {
        if is_spf_record(&txt) {
            if found.is_some() {
                return Err(SpfError::Perm);
            }
            found = Some(parse(subs, txt.as_str()).map_err(|_| SpfError::Perm)?);
        }
    }

    Ok(found)
}

/// The elapsed-time limit for one whole `check_host()` evaluation,
/// across every DNS lookup it makes (DESIGN §9).
///
/// RFC 7208 §4.6.4: implementations SHOULD limit the total time spent
/// evaluating `check_host()`, the limit SHOULD allow at least 20 seconds,
/// and exceeding it SHOULD give `temperror`. Without it, a hostile record
/// tree whose authoritative servers never answer could take the full
/// lookup budget times the per-query DNS timeout (10 × 5 s, plus the
/// include TXT lookups), holding the SMTP session and DNS connections for
/// all of it.
pub const EVALUATION_DEADLINE: Duration = Duration::from_secs(20);

/// Evaluate `check_host()` (RFC 7208 Section 4) for the connecting IP
/// `peer`, the identity `sender` (`local@domain`, used for macros), its
/// `domain`, and the client's `helo` name (for the `%{h}` macro). Each
/// call gets a fresh lookup budget and the [`EVALUATION_DEADLINE`] time
/// limit.
///
/// Returns the result, including `None` (no record published) and the
/// `TempError`/`PermError` produced inside mechanisms (e.g. an `include`
/// whose lookup fails). The caller (SMTP policy) maps the result to a
/// reply code.
///
/// # Errors
///
/// Failures of the top-level record (and of a `redirect=` target): a
/// failed TXT lookup or an unusable record, an exhausted lookup budget
/// on a redirect, or [`SpfError::Deadline`] when the evaluation runs out
/// of time. Map them with [`SpfError::to_result`].
pub async fn check_host<R>(
    resolver: &R,
    peer: IpAddr,
    sender: &String,
    domain: String,
    helo: &Option<String>,
) -> std::result::Result<SpfResult, SpfError>
where
    R: SpfResolver + Sync,
{
    check_host_within(resolver, peer, sender, domain, helo, EVALUATION_DEADLINE).await
}

/// [`check_host`] with the time limit `deadline` instead of
/// [`EVALUATION_DEADLINE`] (tests use a short one). Same results and
/// errors.
pub async fn check_host_within<R>(
    resolver: &R,
    peer: IpAddr,
    sender: &String,
    domain: String,
    helo: &Option<String>,
    deadline: Duration,
) -> std::result::Result<SpfResult, SpfError>
where
    R: SpfResolver + Sync,
{
    let mut budget = Budget::default();
    tokio::time::timeout(
        deadline,
        check_host_limited(resolver, peer, sender, domain, helo, &mut budget),
    )
    .await
    .unwrap_or(Err(SpfError::Deadline(deadline)))
}

/// The recursive `check_host()` core for `domain`, carrying the RFC 7208
/// Section 4.6.4 `budget` across includes and redirects.
///
/// Returns the first matching mechanism's qualified result, else the
/// redirect target's evaluation, else `Neutral` (the default when nothing
/// matches); `None` when the domain publishes no record, and `PermError`
/// for a duplicate `redirect=` or a redirect to a domain without a record.
///
/// # Errors
///
/// As for [`check_host`], except the deadline (applied by the caller).
#[async_recursion]
async fn check_host_limited<R>(
    resolver: &R,
    peer: IpAddr,
    sender: &String,
    domain: String,
    helo: &Option<String>,
    budget: &mut Budget,
) -> std::result::Result<SpfResult, SpfError>
where
    R: SpfResolver + Sync,
{
    let mut result: Option<SpfResult> = None;
    let mut redirect: Option<&SpfModifier> = None;

    let subs = SpfMacroSubs::new(peer, sender, &domain, helo);
    let spf = match query_spf_record(resolver, domain.as_str(), &subs).await? {
        Some(spf) => spf,
        // No SPF record published: check_host() is None (RFC 7208 Section
        // 4.3). A transient lookup failure is still an Err.
        None => return Ok(SpfResult::None),
    };

    for term in spf.terms.iter() {
        match term {
            SpfTerm::Modifier(m) if m.name == "redirect" => {
                if redirect.is_some() {
                    return Ok(SpfResult::PermError);
                }
                redirect = Some(m);
            }
            SpfTerm::Modifier(m) if m.name == "exp" => {
                // Validated for uniqueness only. RFC 7208 Section 6.2: the
                // exp lookup does not count against the DNS limits, and it
                // MUST NOT change the verdict (Section 6.1) — it only
                // provides an explanation string for a Fail, which this
                // implementation does not produce yet (TODO).
                let _ = m;
            }
            SpfTerm::Modifier(_) => continue,
            SpfTerm::Directive(d) => {
                result =
                    check_directive(resolver, domain.as_str(), peer, sender, helo, d, budget).await;
                if result.is_some() {
                    break;
                }
            }
        }
    }

    if result.is_none() {
        if let Some(m) = redirect {
            // RFC 7208 Section 4.6.4: the redirect lookup counts against
            // the shared budget. Errors (including a spent budget)
            // propagate; callers map them to results.
            budget.spend()?;
            let target =
                check_host_limited(resolver, peer, sender, m.value.clone(), helo, budget).await;
            // RFC 7208 §6.1: a redirect to a domain with no SPF record is a
            // PermError, not "no policy" (which would accept the mail).
            return match target {
                Ok(SpfResult::None) => Ok(SpfResult::PermError),
                other => other,
            };
        }
    }

    match result {
        Some(r) => Ok(r),
        None => Ok(SpfResult::Neutral),
    }
}

/// Returns the result a matching directive yields for qualifier `q`.
fn qualify(q: &SpfQualifier) -> SpfResult {
    match q {
        SpfQualifier::Plus => SpfResult::Pass,
        SpfQualifier::Dash => SpfResult::Fail,
        SpfQualifier::Question => SpfResult::Neutral,
        SpfQualifier::Tilde => SpfResult::SoftFail,
    }
}

/// RFC 7208 Section 5.6: `ip4:` matches only against an IPv4 `peer`
/// address inside the CIDR `ip`. Returns `Some(result)` on match, `None`
/// otherwise (and always `None` for an IPv6 peer).
fn check_ipv4(peer: IpAddr, ip: &Ipv4Net, result: &SpfResult) -> Option<SpfResult> {
    match peer {
        IpAddr::V4(ip4) if ip.contains(&ip4) => Some(*result),
        _ => None,
    }
}

/// RFC 7208 Section 5.6: `ip6:` matches only against an IPv6 `peer`
/// address inside the CIDR `ip`. Returns `Some(result)` on match, `None`
/// otherwise (and always `None` for an IPv4 peer).
fn check_ipv6(peer: IpAddr, ip: &Ipv6Net, result: &SpfResult) -> Option<SpfResult> {
    match peer {
        IpAddr::V6(ip6) if ip.contains(&ip6) => Some(*result),
        _ => None,
    }
}

/// `a` / `a:domain` / `a:domain/cidr` (RFC 7208 Section 5.3): match `peer`
/// against the A records of the target domain `d` (the caller substitutes
/// the current domain for an empty domain-spec), each widened to
/// `cidr.v4`.
///
/// Returns `Some(m)` on a match, `None` otherwise.
///
/// # Errors
///
/// [`SpfError::Temp`] for a failed lookup; the budget's limits; or
/// [`SpfError::Perm`] for an invalid prefix length.
async fn check_a_record<R: SpfResolver + Sync>(
    resolver: &R,
    peer: IpAddr,
    d: &str,
    cidr: DualCidr,
    m: &SpfResult,
    budget: &mut Budget,
) -> std::result::Result<Option<SpfResult>, SpfError> {
    budget.spend()?;
    let ips = term_lookup(resolver.a(d).await, budget)?;

    for ip in ips {
        // The mechanism's ip4-cidr-length applies to every address.
        let ipn = Ipv4Net::new(ip, cidr.v4).map_err(|_| SpfError::Perm)?;
        if let Some(r) = check_ipv4(peer, &ipn, m) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// `mx` (RFC 7208 Section 5.4): match `peer` against the A records of
/// each MX exchange of `d`, widened to `cidr.v4`. The mechanism is one
/// budgeted lookup (and a void one when `d` has no MX); the exchanges'
/// address lookups are capped at [`MAX_ADDRESS_LOOKUPS`] per mechanism
/// instead (RFC 7208 §4.6.4), and an exchange without A records (an
/// IPv6-only host) is not a void lookup.
///
/// Returns `Some(m)` on a match, `None` otherwise.
///
/// # Errors
///
/// As for [`check_a_record`].
async fn check_mx_record<R: SpfResolver + Sync>(
    resolver: &R,
    peer: IpAddr,
    d: &str,
    cidr: DualCidr,
    m: &SpfResult,
    budget: &mut Budget,
) -> std::result::Result<Option<SpfResult>, SpfError> {
    budget.spend()?;
    let mxs = term_lookup(resolver.mx(d).await, budget)?;

    // Checked before any address lookup: an MX set that can't be
    // evaluated within the cap is PermError whatever it would match.
    if mxs.len() > MAX_ADDRESS_LOOKUPS {
        return Err(SpfError::AddressLimit(MAX_ADDRESS_LOOKUPS));
    }
    for (_, exchange) in mxs {
        let ips = plain_lookup(resolver.a(&exchange).await)?;
        for ip in ips {
            let ipn = Ipv4Net::new(ip, cidr.v4).map_err(|_| SpfError::Perm)?;
            if let Some(r) = check_ipv4(peer, &ipn, m) {
                return Ok(Some(r));
            }
        }
    }
    Ok(None)
}

/// `ptr` (RFC 7208 Section 5.5): forward-confirmed reverse DNS of the
/// connecting IPv4 `peer`, validated against the domain-spec `d` (or
/// `current_domain` when `d` is empty). The PTR lookup is one budgeted
/// lookup (void when it finds nothing); only the first
/// [`MAX_ADDRESS_LOOKUPS`] names are forward-confirmed and the rest are
/// ignored (RFC 7208 §4.6.4), and those confirmations are not charged.
/// IPv6 peers never match.
///
/// Returns `Some(m)` on a match, `None` otherwise.
///
/// # Errors
///
/// [`SpfError::Temp`] for a failed lookup, or the budget's limits.
async fn check_ptr_record<R: SpfResolver + Sync>(
    resolver: &R,
    peer: IpAddr,
    d: &str,
    current_domain: &str,
    m: &SpfResult,
    budget: &mut Budget,
) -> std::result::Result<Option<SpfResult>, SpfError> {
    let IpAddr::V4(ip4) = peer else {
        return Ok(None);
    };

    // Reverse the connecting IP, not the domain-spec.
    let o = ip4.octets();
    let rev = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
    budget.spend()?;
    let names = term_lookup(resolver.ptr(&rev).await, budget)?;

    let target = if d.is_empty() { current_domain } else { d };
    let target = target.to_ascii_lowercase();

    for name in names.into_iter().take(MAX_ADDRESS_LOOKUPS) {
        // Forward-confirm: the PTR name's A records must contain the IP.
        let ips = plain_lookup(resolver.a(&name).await)?;
        if !ips.contains(&ip4) {
            continue;
        }
        let name = name.to_ascii_lowercase();
        if name == target || name.ends_with(&format!(".{target}")) {
            return Ok(Some(*m));
        }
    }
    Ok(None)
}

/// `exists` (RFC 7208 Section 5.7): matches when the domain `d` has at
/// least one A record, regardless of the connecting IP.
///
/// Returns `Some(Pass)` on a match (the caller applies the qualifier),
/// `None` otherwise.
///
/// # Errors
///
/// [`SpfError::Temp`] for a failed lookup, or the budget's limits.
async fn check_exists<R: SpfResolver + Sync>(
    resolver: &R,
    d: &str,
    budget: &mut Budget,
) -> std::result::Result<Option<SpfResult>, SpfError> {
    budget.spend()?;
    let ips = term_lookup(resolver.a(d).await, budget)?;
    if ips.is_empty() {
        return Ok(None);
    }
    Ok(Some(SpfResult::Pass))
}

/// Evaluate one directive (mechanism + qualifier) of `domain`'s record
/// against `peer`. Returns `Some(result)` when the mechanism matches (the
/// verdict) or fails (TempError/PermError, mapped from its error), `None`
/// when it does not match (evaluation continues to the next directive).
/// DNS-dependent mechanisms consume the shared `budget`.
async fn check_directive<R: SpfResolver + Sync>(
    resolver: &R,
    domain: &str,
    peer: IpAddr,
    sender: &String,
    helo: &Option<String>,
    SpfDirective {
        qualifier: q,
        mechanism: m,
    }: &SpfDirective,
    budget: &mut Budget,
) -> Option<SpfResult> {
    match m {
        SpfMechanism::All => Some(qualify(q)),

        // include (RFC 7208 Section 5.2): matches only when the included
        // domain Passes; the include's own qualifier maps that Pass. The
        // included evaluation shares the lookup budget, so include loops
        // terminate with PermError. A missing record on the included
        // domain is a permanent error.
        SpfMechanism::Include(s) => {
            if budget.spend().is_err() {
                return Some(SpfResult::PermError);
            }
            match check_host_limited(resolver, peer, sender, s.to_string(), helo, budget).await {
                Ok(inner) => match inner {
                    SpfResult::Pass => Some(qualify(q)),
                    SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral => None,
                    SpfResult::TempError => Some(SpfResult::TempError),
                    SpfResult::PermError => Some(SpfResult::PermError),
                    SpfResult::None => Some(SpfResult::PermError),
                },
                Err(e) => Some(e.to_result()),
            }
        }

        SpfMechanism::A(s, cidr) => {
            // An empty domain-spec means the current domain (RFC 7208
            // Section 5.3).
            let target = if s.is_empty() { domain } else { s };
            match check_a_record(resolver, peer, target, *cidr, &qualify(q), budget).await {
                Ok(r) => r,
                Err(e) => Some(e.to_result()),
            }
        }
        SpfMechanism::Mx(s, cidr) => {
            // An empty domain-spec means the current domain (RFC 7208
            // Section 5.4).
            let target = if s.is_empty() { domain } else { s };
            match check_mx_record(resolver, peer, target, *cidr, &qualify(q), budget).await {
                Ok(r) => r,
                Err(e) => Some(e.to_result()),
            }
        }
        SpfMechanism::Ptr(s) => {
            match check_ptr_record(resolver, peer, s, domain, &qualify(q), budget).await {
                Ok(r) => r,
                Err(e) => Some(e.to_result()),
            }
        }
        SpfMechanism::Ip4(ip) => check_ipv4(peer, ip, &qualify(q)),
        SpfMechanism::Ip6(ip) => check_ipv6(peer, ip, &qualify(q)),

        SpfMechanism::Exists(s) => match check_exists(resolver, s, budget).await {
            Ok(Some(SpfResult::Pass)) => Some(qualify(q)),
            Ok(other) => other,
            Err(e) => Some(e.to_result()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Fixture-backed [`SpfResolver`]: a miss on TXT is a name with no SPF
    /// record (empty), matching how tests treat unrecorded domains.
    #[derive(Default, Clone)]
    struct MockResolver {
        txt: HashMap<String, Vec<String>>,
        a: HashMap<String, Vec<Ipv4Addr>>,
        mx: HashMap<String, Vec<(u16, String)>>,
        ptr: HashMap<String, Vec<String>>,
        /// Names whose every lookup is a temporary error (SERVFAIL).
        failing: std::collections::HashSet<String>,
    }

    impl MockResolver {
        /// The lookup of `domain` in `table`: a temporary error for a
        /// failing name, otherwise found or absent.
        fn answer<T: Clone>(&self, table: &HashMap<String, Vec<T>>, domain: &str) -> Lookup<T> {
            if self.failing.contains(domain) {
                return Lookup::TempError("SERVFAIL".into());
            }
            match table.get(domain) {
                Some(values) if !values.is_empty() => Lookup::Found(values.clone()),
                _ => Lookup::Absent,
            }
        }
    }

    impl SpfResolver for MockResolver {
        async fn txt(&self, domain: &str) -> Lookup<String> {
            self.answer(&self.txt, domain)
        }
        async fn a(&self, domain: &str) -> Lookup<Ipv4Addr> {
            self.answer(&self.a, domain)
        }
        async fn mx(&self, domain: &str) -> Lookup<(u16, String)> {
            self.answer(&self.mx, domain)
        }
        async fn ptr(&self, domain: &str) -> Lookup<String> {
            self.answer(&self.ptr, domain)
        }
    }

    /// reddit.com's SPF as published when the original live tests were
    /// written (retrieved 2024-11), so the fixtures stay deterministic.
    /// Every included domain carries a record, since a missing record on an
    /// included domain is a permerror (RFC 7208 Section 5.2).
    fn reddit_resolver() -> MockResolver {
        let mut m = MockResolver::default();
        m.txt.insert(
            "reddit.com".to_string(),
            vec!["v=spf1 include:amazonses.com include:_spf.google.com include:19922862.spf01.hubspotemail.net include:hs.reddit.com include:_spf.salesforce.com ip4:174.129.203.189 ip4:52.205.61.79 ip4:54.172.97.247 ip4:52.50.24.208 ~all".to_string()],
        );
        // Included domains, none of which list 52.50.24.208.
        m.txt.insert(
            "amazonses.com".to_string(),
            vec!["v=spf1 ip4:203.0.113.0/24 ~all".to_string()],
        );
        m.txt.insert(
            "_spf.google.com".to_string(),
            vec!["v=spf1 ip4:216.239.32.0/19 ~all".to_string()],
        );
        m.txt.insert(
            "19922862.spf01.hubspotemail.net".to_string(),
            vec!["v=spf1 ~all".to_string()],
        );
        m.txt.insert(
            "_spf.salesforce.com".to_string(),
            vec!["v=spf1 ~all".to_string()],
        );
        // hs.reddit.com: Fail for everything (the -all in the real record).
        m.txt.insert(
            "hs.reddit.com".to_string(),
            vec!["v=spf1 ip4:149.72.234.184 -all".to_string()],
        );
        m
    }

    /// Evaluate `check_host()` for a test sender: lowercases the
    /// domain, builds the identity, and unwraps the result for direct
    /// assertions.
    async fn check<R: SpfResolver + Sync>(
        resolver: &R,
        peer: &str,
        sender: &str,
        domain: &str,
    ) -> std::result::Result<SpfResult, SpfError> {
        check_host(
            resolver,
            peer.parse::<IpAddr>().unwrap(),
            &sender.to_string(),
            domain.to_string(),
            &Some(domain.to_string()),
        )
        .await
    }

    /// A resolver whose every lookup takes `delay` (an authoritative
    /// server that answers slowly, or never within the DNS timeout).
    struct SlowResolver {
        inner: MockResolver,
        delay: std::time::Duration,
    }

    impl SpfResolver for SlowResolver {
        async fn txt(&self, domain: &str) -> Lookup<String> {
            tokio::time::sleep(self.delay).await;
            self.inner.txt(domain).await
        }
        async fn a(&self, domain: &str) -> Lookup<Ipv4Addr> {
            tokio::time::sleep(self.delay).await;
            self.inner.a(domain).await
        }
        async fn mx(&self, domain: &str) -> Lookup<(u16, String)> {
            tokio::time::sleep(self.delay).await;
            self.inner.mx(domain).await
        }
        async fn ptr(&self, domain: &str) -> Lookup<String> {
            tokio::time::sleep(self.delay).await;
            self.inner.ptr(domain).await
        }
    }

    /// DESIGN §9 / RFC 7208 §4.6.4: the whole evaluation has an
    /// elapsed-time limit. A chain of includes whose lookups are each
    /// slow stops at the limit with TempError instead of running for
    /// lookups × per-query timeout; a fast evaluation is unaffected.
    #[tokio::test]
    async fn evaluation_deadline_gives_temperror() {
        let mut inner = MockResolver::default();
        for i in 0..8 {
            inner.txt.insert(
                format!("hop{i}.test"),
                vec![format!("v=spf1 include:hop{}.test -all", i + 1)],
            );
        }
        inner
            .txt
            .insert("hop8.test".into(), vec!["v=spf1 +all".into()]);
        let slow = SlowResolver {
            inner: inner.clone(),
            delay: std::time::Duration::from_millis(100),
        };
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let sender = "a@hop0.test".to_string();

        // 9 slow TXT lookups (~900 ms) against a 300 ms limit.
        let started = std::time::Instant::now();
        let result = check_host_within(
            &slow,
            peer,
            &sender,
            "hop0.test".into(),
            &None,
            std::time::Duration::from_millis(300),
        )
        .await;
        assert!(
            matches!(result, Err(SpfError::Deadline(_))),
            "got {result:?}"
        );
        assert_eq!(result.unwrap_err().to_result(), SpfResult::TempError);
        assert!(started.elapsed() < std::time::Duration::from_millis(600));

        // The same tree on a fast resolver finishes inside the default
        // limit and reaches the final +all.
        let result = check_host(&inner, peer, &sender, "hop0.test".into(), &None).await;
        assert_eq!(result, Ok(SpfResult::Pass));
    }

    /// Reddit's real recorded SPF record: the listed IP passes through
    /// the include chain.
    #[tokio::test]
    async fn test_check_host_reddit() {
        let result = check(
            &reddit_resolver(),
            "52.50.24.208",
            "foo@test.com",
            "reddit.com",
        )
        .await
        .unwrap();
        assert_eq!(SpfResult::Pass, result);
    }

    /// An unlisted IP falls through every include to the final `~all`
    /// (SoftFail).
    #[tokio::test]
    async fn test_check_host_reddit_unlisted_ip() {
        let result = check(&reddit_resolver(), "10.0.0.1", "foo@test.com", "reddit.com")
            .await
            .unwrap();
        // Not listed: falls through the includes to ~all.
        assert_eq!(SpfResult::SoftFail, result);
    }

    /// Google's include chain: an authorized include IP passes.
    #[tokio::test]
    async fn test_check_host_google() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "google.com".to_string(),
            vec!["v=spf1 include:_spf.google.com ~all".to_string()],
        );
        resolver.txt.insert(
            "_spf.google.com".to_string(),
            vec![
                "v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all"
                    .to_string(),
            ],
        );
        resolver.txt.insert(
            "_netblocks.google.com".to_string(),
            vec!["v=spf1 ip4:216.239.32.0/19 ~all".to_string()],
        );
        resolver.txt.insert(
            "_netblocks2.google.com".to_string(),
            vec!["v=spf1 ip4:8.34.208.0/20 ~all".to_string()],
        );

        let result = check(&resolver, "10.0.0.1", "foo@test.com", "google.com")
            .await
            .unwrap();
        assert_eq!(SpfResult::SoftFail, result);
    }

    /// A CIDR `ip4:` mechanism matches by network, not exact address.
    #[tokio::test]
    async fn test_check_host_bing() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "bing.com".to_string(),
            vec!["v=spf1 ip4:204.79.197.0/24 -all".to_string()],
        );

        // Exercises CIDR parsing: a broken ip4:/nn parse would yield
        // Neutral instead of Fail.
        let result = check(&resolver, "52.50.24.208", "foo@test.com", "bing.com")
            .await
            .unwrap();
        assert_eq!(SpfResult::Fail, result);
    }

    /// RFC 7208 Section 5.4: `mx` resolves each MX exchange to its A
    /// records and matches against them.
    #[tokio::test]
    async fn test_mx_mechanism_resolves_exchange_names() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "example.net".to_string(),
            vec!["v=spf1 mx -all".to_string()],
        );
        resolver.mx.insert(
            "example.net".to_string(),
            vec![(10, "mail.example.net".to_string())],
        );
        resolver.a.insert(
            "mail.example.net".to_string(),
            vec!["192.0.2.25".parse().unwrap()],
        );

        let pass = check(&resolver, "192.0.2.25", "foo@example.net", "example.net")
            .await
            .unwrap();
        assert_eq!(SpfResult::Pass, pass);

        let fail = check(&resolver, "192.0.2.99", "foo@example.net", "example.net")
            .await
            .unwrap();
        assert_eq!(SpfResult::Fail, fail);
    }

    /// RFC 7208 Section 5.5: `ptr` requires a forward-confirmed reverse
    /// lookup whose hostname resolves back to the peer.
    #[tokio::test]
    async fn test_ptr_mechanism_forward_confirms() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "example.net".to_string(),
            vec!["v=spf1 ptr -all".to_string()],
        );
        resolver.ptr.insert(
            "25.2.0.192.in-addr.arpa".to_string(),
            vec!["mail.example.net".to_string()],
        );
        resolver.a.insert(
            "mail.example.net".to_string(),
            vec!["192.0.2.25".parse().unwrap()],
        );

        // Forward-confirmed: matches.
        let pass = check(&resolver, "192.0.2.25", "foo@example.net", "example.net")
            .await
            .unwrap();
        assert_eq!(SpfResult::Pass, pass);

        // The PTR name does not forward-confirm to the IP: no match.
        let mut unconfirmed = resolver.clone();
        unconfirmed.a.insert(
            "mail.example.net".to_string(),
            vec!["192.0.2.1".parse().unwrap()],
        );
        let fail = check(&unconfirmed, "192.0.2.25", "foo@example.net", "example.net")
            .await
            .unwrap();
        assert_eq!(SpfResult::Fail, fail);
    }

    /// A domain with no SPF record evaluates to `None` (no policy
    /// published).
    #[tokio::test]
    async fn test_no_record_is_none() {
        let resolver = MockResolver::default();
        let result = check(
            &resolver,
            "192.0.2.1",
            "foo@nodomain.example",
            "nodomain.example",
        )
        .await
        .unwrap();
        // A domain with no SPF record evaluates to None, which verifiers
        // treat as "no assertion" (accept, no opinion).
        assert_eq!(SpfResult::None, result);
    }

    /// RFC 7208 Section 5.2: an `include:` to a domain with no SPF
    /// record is a PermError, not a no-match.
    #[tokio::test]
    async fn test_include_without_record_is_permerror() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "example.net".to_string(),
            vec!["v=spf1 include:missing.example -all".to_string()],
        );

        // RFC 7208 Section 5.2: an include that resolves to 'none' is a
        // permanent error, not a non-match.
        let result = check(&resolver, "192.0.2.1", "foo@example.net", "example.net")
            .await
            .unwrap();
        assert_eq!(SpfResult::PermError, result);
    }

    /// RFC 7208 Section 3.2: more than one `v=spf1` record on a domain
    /// is a PermError.
    #[tokio::test]
    async fn test_multiple_spf_records_are_permerror() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "example.net".to_string(),
            vec![
                "v=spf1 ip4:192.0.2.1 -all".to_string(),
                "v=spf1 ip4:192.0.2.2 +all".to_string(),
            ],
        );

        // RFC 7208 Section 3.2: more than one v=spf1 record is unusable.
        let result = check(&resolver, "192.0.2.1", "foo@example.net", "example.net").await;
        assert_eq!(SpfResult::PermError, result.unwrap_err().to_result());
    }

    // -- Lookup budget (RFC 7208 Section 4.6.4) ---------------------------

    /// Circular includes terminate with PermError via the lookup budget.
    #[tokio::test]
    async fn circular_include_terminates_with_permerror() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "a.example".to_string(),
            vec!["v=spf1 include:b.example -all".to_string()],
        );
        resolver.txt.insert(
            "b.example".to_string(),
            vec!["v=spf1 include:a.example -all".to_string()],
        );

        // Without the budget this would recurse without bound.
        let result = check(&resolver, "192.0.2.1", "foo@a.example", "a.example")
            .await
            .unwrap();
        assert_eq!(SpfResult::PermError, result);
    }

    /// A `redirect` loop terminates with PermError via the same budget.
    #[tokio::test]
    async fn redirect_loop_terminates_with_permerror() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "a.example".to_string(),
            vec!["v=spf1 redirect=b.example".to_string()],
        );
        resolver.txt.insert(
            "b.example".to_string(),
            vec!["v=spf1 redirect=a.example".to_string()],
        );

        let result = check(&resolver, "192.0.2.1", "foo@a.example", "a.example").await;
        assert_eq!(SpfResult::PermError, result.unwrap_err().to_result());
    }

    /// RFC 7208 §6.1: a `redirect=` to a domain with no SPF record is a
    /// PermError (never `None`, which would accept the mail), while a
    /// redirect to a published record evaluates that record.
    #[tokio::test]
    async fn redirect_to_a_domain_without_a_record_is_permerror() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "a.example".to_string(),
            vec!["v=spf1 redirect=nothing.example".to_string()],
        );
        resolver.txt.insert(
            "b.example".to_string(),
            vec!["v=spf1 redirect=c.example".to_string()],
        );
        resolver
            .txt
            .insert("c.example".to_string(), vec!["v=spf1 -all".to_string()]);

        let result = check(&resolver, "192.0.2.1", "foo@a.example", "a.example").await;
        assert_eq!(result.unwrap(), SpfResult::PermError);
        let result = check(&resolver, "192.0.2.1", "foo@b.example", "b.example").await;
        assert_eq!(result.unwrap(), SpfResult::Fail);
    }

    /// RFC 7208 §4.6.4 for `mx`: the mechanism is one term, its address
    /// lookups don't count against the 10 (so nine `mx` mechanisms with
    /// four exchanges each still evaluate), exchanges without A records
    /// aren't void lookups, and more than 10 exchanges is PermError.
    #[tokio::test]
    async fn mx_address_lookups_have_their_own_cap() {
        let mut resolver = MockResolver::default();
        let mut mechanisms = Vec::new();
        for i in 1..=9 {
            let domain = format!("mx{i}.example");
            // Three IPv6-only exchanges (no A) and one that doesn't match.
            let mut exchanges: Vec<(u16, String)> =
                (1..=3).map(|j| (10, format!("v6-{j}.{domain}"))).collect();
            exchanges.push((20, format!("out.{domain}")));
            resolver.a.insert(
                format!("out.{domain}"),
                vec!["198.51.100.1".parse().unwrap()],
            );
            resolver.mx.insert(domain.clone(), exchanges);
            mechanisms.push(format!("mx:{domain}"));
        }
        resolver
            .a
            .insert("in.mx9.example".into(), vec!["192.0.2.1".parse().unwrap()]);
        resolver
            .mx
            .get_mut("mx9.example")
            .unwrap()
            .push((30, "in.mx9.example".into()));
        resolver.txt.insert(
            "big.example".into(),
            vec![format!("v=spf1 {} -all", mechanisms.join(" "))],
        );
        let result = check(&resolver, "192.0.2.1", "a@big.example", "big.example").await;
        assert_eq!(
            result.unwrap(),
            SpfResult::Pass,
            "nine terms, 37 address lookups"
        );

        // Eleven exchanges in one mx: PermError, even though one matches.
        let many: Vec<(u16, String)> = (1..=11)
            .map(|j| (10, format!("h{j}.wide.example")))
            .collect();
        resolver
            .a
            .insert("h1.wide.example".into(), vec!["192.0.2.1".parse().unwrap()]);
        resolver.mx.insert("wide.example".into(), many);
        resolver
            .txt
            .insert("wide.example".into(), vec!["v=spf1 mx -all".into()]);
        let result = check(&resolver, "192.0.2.1", "a@wide.example", "wide.example").await;
        assert_eq!(
            result.unwrap(),
            SpfResult::PermError,
            "more than 10 address lookups"
        );
    }

    /// Each result is stored under its RFC name, the same one
    /// `Authentication-Results:` uses, and the variant names older
    /// versions stored still load.
    #[test]
    fn results_have_stable_names() {
        for r in [
            SpfResult::None,
            SpfResult::Neutral,
            SpfResult::Pass,
            SpfResult::Fail,
            SpfResult::SoftFail,
            SpfResult::TempError,
            SpfResult::PermError,
        ] {
            let json = serde_json::to_string(&r).unwrap();
            assert_eq!(json, format!("\"{}\"", r.as_str()));
            let old = format!("\"{r:?}\"");
            assert_eq!(serde_json::from_str::<SpfResult>(&old).unwrap(), r, "{old}");
        }
    }

    /// Fail closed: a temporary DNS error (SERVFAIL) anywhere the result
    /// depends on is TempError, never "no record" or "no match", whether
    /// it hits the record itself, an include, or a mechanism's lookup.
    #[tokio::test]
    async fn temporary_errors_are_temperror_everywhere() {
        let mut resolver = MockResolver::default();
        resolver.failing.insert("down.example".into());
        resolver.failing.insert("inc-down.example".into());
        resolver.failing.insert("host.example".into());
        for (domain, record) in [
            ("inc.example", "v=spf1 include:inc-down.example -all"),
            ("a.example", "v=spf1 a:host.example -all"),
            ("mx.example", "v=spf1 mx:host.example -all"),
        ] {
            resolver.txt.insert(domain.into(), vec![record.into()]);
        }
        for domain in ["down.example", "inc.example", "a.example", "mx.example"] {
            let result = check(&resolver, "192.0.2.1", &format!("x@{domain}"), domain).await;
            let verdict = result.unwrap_or_else(|e| e.to_result());
            assert_eq!(verdict, SpfResult::TempError, "{domain}");
        }
    }

    /// RFC 7208 §4.6.4 for `ptr`: only the first 10 PTR names are
    /// forward-confirmed, the rest ignored, and the confirmations aren't
    /// charged against the 10-term budget.
    #[tokio::test]
    async fn ptr_considers_only_the_first_ten_names() {
        let mut resolver = MockResolver::default();
        let peer: Ipv4Addr = "192.0.2.7".parse().unwrap();
        let names: Vec<String> = (1..=12).map(|i| format!("n{i}.ptr.example")).collect();
        for name in &names {
            resolver.a.insert(name.clone(), vec![peer]);
        }
        resolver.ptr.insert("7.2.0.192.in-addr.arpa".into(), names);
        // Only the 11th name is under the target domain: ignored.
        resolver.txt.insert(
            "late.example".into(),
            vec!["v=spf1 ptr:n11.ptr.example -all".into()],
        );
        let result = check(&resolver, "192.0.2.7", "a@late.example", "late.example").await;
        assert_eq!(result.unwrap(), SpfResult::Fail);
        // A name within the first ten matches, without exhausting the budget.
        resolver.txt.insert(
            "early.example".into(),
            vec!["v=spf1 ptr:ptr.example -all".into()],
        );
        let result = check(&resolver, "192.0.2.7", "a@early.example", "early.example").await;
        assert_eq!(result.unwrap(), SpfResult::Pass);
    }

    /// The 10-lookup budget: an eleventh DNS-consuming mechanism is a
    /// PermError.
    #[tokio::test]
    async fn too_many_mechanism_lookups_is_permerror() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "example.net".to_string(),
            vec![format!(
                "v=spf1 {} -all",
                (1..=11)
                    .map(|i| format!("a:host{i}.example"))
                    .collect::<Vec<_>>()
                    .join(" ")
            )],
        );
        for i in 1..=11 {
            resolver.a.insert(
                format!("host{i}.example"),
                vec![format!("192.0.2.{i}").parse().unwrap()],
            );
        }

        // 11 a: mechanisms — one past the limit. The peer only matches
        // host11, so all 11 lookups are genuinely exercised: the 11th
        // spend (before host11 is even queried) aborts. The limit error
        // is converted to a PermError result at the mechanism boundary.
        let result = check(&resolver, "192.0.2.11", "foo@example.net", "example.net")
            .await
            .unwrap();
        assert_eq!(SpfResult::PermError, result);
    }

    /// The budget boundary: exactly 10 lookups evaluate normally.
    #[tokio::test]
    async fn exactly_ten_lookups_still_pass() {
        let mut resolver = MockResolver::default();
        // A chain of exactly 10 includes reaching a matching ip4: each
        // include spends 1, and the final ip4 spends none.
        resolver.txt.insert(
            "d0.example".to_string(),
            vec!["v=spf1 include:d1.example ~all".to_string()],
        );
        for i in 1..10 {
            resolver.txt.insert(
                format!("d{i}.example"),
                vec![format!("v=spf1 include:d{}.example ~all", i + 1)],
            );
        }
        resolver.txt.insert(
            "d10.example".to_string(),
            vec!["v=spf1 ip4:192.0.2.7 +all".to_string()],
        );

        let result = check(&resolver, "192.0.2.7", "foo@d0.example", "d0.example")
            .await
            .unwrap();
        assert_eq!(SpfResult::Pass, result);
    }

    /// RFC 7208 Section 4.6.4: the third void lookup (empty answer set)
    /// is a PermError.
    #[tokio::test]
    async fn void_lookups_are_limited_to_two() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "example.net".to_string(),
            vec!["v=spf1 a:m1.example a:m2.example a:m3.example ip4:192.0.2.1 -all".to_string()],
        );
        // m1/m2/m3 exist but have no A records: three void lookups. The
        // matching ip4 never gets evaluated — the third void aborts with
        // PermError (RFC 7208 Section 4.6.4). The limit error is converted
        // to a PermError result at the mechanism boundary.
        let result = check(&resolver, "192.0.2.1", "foo@example.net", "example.net").await;
        assert_eq!(SpfResult::PermError, result.unwrap());

        // With only two voids, evaluation continues and the ip4 matches.
        resolver.txt.insert(
            "example.net".to_string(),
            vec!["v=spf1 a:m1.example a:m2.example ip4:192.0.2.1 -all".to_string()],
        );
        let result = check(&resolver, "192.0.2.1", "foo@example.net", "example.net")
            .await
            .unwrap();
        assert_eq!(SpfResult::Pass, result);
    }

    /// MX exchange A-lookups consume the budget like any other lookup.
    #[tokio::test]
    async fn mx_exchange_lookups_count_toward_the_budget() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "example.net".to_string(),
            vec!["v=spf1 mx:host.example -all".to_string()],
        );
        // One MX record whose exchanges each need an A lookup: 1 + 11 = 12
        // lookups, past the limit. The peer only matches mx12, which is
        // never reached.
        resolver.mx.insert(
            "host.example".to_string(),
            (1..=12).map(|i| (10, format!("mx{i}.example"))).collect(),
        );
        for i in 1..=12 {
            resolver.a.insert(
                format!("mx{i}.example"),
                vec![format!("10.0.0.{i}").parse().unwrap()],
            );
        }

        let result = check(&resolver, "192.0.2.1", "foo@example.net", "example.net")
            .await
            .unwrap();
        assert_eq!(SpfResult::PermError, result);
    }

    /// RFC 7208 Section 6.1/6.2: the exp= modifier must never change the
    /// verdict, even when its target domain would produce a different
    /// result.
    #[tokio::test]
    async fn exp_modifier_never_changes_the_verdict() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "example.net".to_string(),
            vec!["v=spf1 -all exp=passer.example".to_string()],
        );
        // The exp target passes for this IP. A verifier that recursed into
        // it would wrongly return Pass.
        resolver.txt.insert(
            "passer.example".to_string(),
            vec!["v=spf1 +all".to_string()],
        );

        let result = check(&resolver, "192.0.2.1", "foo@example.net", "example.net")
            .await
            .unwrap();
        assert_eq!(SpfResult::Fail, result);
    }

    /// A stalled DNS server must surface as a transient error after the
    /// resolver timeout, not hang the evaluation (or the SMTP session).
    #[tokio::test]
    async fn dot_resolver_query_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept connections and never respond: the TLS handshake stalls.
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                let _ = sock;
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });

        let resolver = DotResolver::with_timeout(
            match addr.ip() {
                std::net::IpAddr::V4(ip) => ip,
                _ => panic!("test uses v4"),
            },
            Duration::from_millis(200),
        );
        let start = std::time::Instant::now();
        let result = resolver.txt("example.test").await;
        assert!(
            matches!(result, Lookup::TempError(_)),
            "the stalled query must fail: {result:?}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the query must give up after the timeout, not hang"
        );
    }
}

#[cfg(test)]
mod wire {
    use super::*;
    use dns::proto::{DnsMessage, DnsResourceRecord, Label};
    use dns::DnsClient;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A minimal DNS-over-TLS test server: answers every query with a
    /// single A record for 192.0.2.1 and sums the qtypes of the queries it
    /// receives. Returns the bound address, the server cert (the client's
    /// trust store must contain it), and the qtype sum.
    async fn spawn_mock_dot() -> (
        std::net::SocketAddr,
        rustls_pki_types::CertificateDer<'static>,
        Arc<AtomicU32>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let qtypes = Arc::new(AtomicU32::new(0));
        let qtypes_task = Arc::clone(&qtypes);
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    continue;
                };
                loop {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    let Ok(len) = tls.read_u16().await else {
                        break;
                    };
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
                    qtypes_task.fetch_add(
                        u32::from(query.questions.first().map(|q| q.record_type).unwrap_or(0)),
                        Ordering::SeqCst,
                    );
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
                }
            }
        });
        (addr, cert_der, qtypes)
    }

    /// A name with no valid wire form is answered as
    /// "no records" without any network traffic (RFC 7208 §4.3: a
    /// malformed domain is treated like one that doesn't exist), rather
    /// than a transient error (TempError, 451, retried forever) or a
    /// 5 s timeout. The client points at a closed local port, so any
    /// attempt to send would fail the test.
    #[tokio::test]
    async fn invalid_names_are_empty_answers_not_temperrors() {
        let client = Arc::new(DnsClient::with_timeout(
            "127.0.0.1".parse().unwrap(),
            Duration::from_secs(30),
        ));
        let resolver = DotResolver::shared(Arc::clone(&client));
        let long = format!("{}.example.com", "x".repeat(64));

        let started = std::time::Instant::now();
        assert_eq!(resolver.txt(&long).await, Lookup::Absent);
        assert_eq!(resolver.a("a..b.example").await, Lookup::Absent);
        assert_eq!(resolver.mx(&long).await, Lookup::Absent);
        assert_eq!(resolver.ptr(&long).await, Lookup::Absent);

        // A MAIL FROM domain with an over-long label: SPF None, at once.
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let result = check_host(&resolver, peer, &format!("a@{long}"), long.clone(), &None).await;
        assert_eq!(result, Ok(SpfResult::None));

        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(client.stats().connects, 0, "nothing may be sent");
    }

    /// `DotResolver::a()` must query **type 1 (A)**: with any other type,
    /// `a`/`mx`/`ptr`/`exists` would never match and every lookup would
    /// count as void. This test runs the resolver against a real mock DoT
    /// server and asserts the qtype that went over the wire, plus that the
    /// A answer actually comes back.
    #[tokio::test]
    async fn a_lookups_query_type_1_over_the_wire() {
        let (addr, server_cert, qtypes) = spawn_mock_dot().await;

        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(server_cert).unwrap();
        let config = Arc::new(
            tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let client = DnsClient::with_config(
            "127.0.0.1".parse().unwrap(),
            config,
            Duration::from_secs(5),
            Some(format!("127.0.0.1:{}", addr.port())),
        );
        let resolver = DotResolver::shared(Arc::new(client));

        let ips = resolver.a("example.test").await;
        assert_eq!(
            ips,
            Lookup::Found(vec!["192.0.2.1".parse::<Ipv4Addr>().unwrap()])
        );
        assert_eq!(
            qtypes.load(Ordering::SeqCst),
            1,
            "the wire query must carry qtype 1 (A)"
        );
    }
}

/// Record-parsing edge cases evaluated end to end: case-insensitive
/// terms, malformed terms, CIDR suffixes on `a`/`mx`, duplicate
/// modifiers. None may weaken a hard fail into Neutral/None or fail a
/// legitimate sender.
#[cfg(test)]
mod record_edge_case_tests {
    use super::*;
    use std::collections::HashMap;

    /// Fixture DNS: TXT from the map; fixed A and MX answers for
    /// `v.example`, `mx.v.example` and `other.example`; no PTR records.
    struct Dns {
        /// TXT records by name.
        txt: HashMap<String, Vec<String>>,
    }

    /// Found when `values` has any, absent otherwise.
    fn found_or_absent<T>(values: Vec<T>) -> Lookup<T> {
        if values.is_empty() {
            Lookup::Absent
        } else {
            Lookup::Found(values)
        }
    }

    impl SpfResolver for Dns {
        async fn txt(&self, d: &str) -> Lookup<String> {
            found_or_absent(self.txt.get(d).cloned().unwrap_or_default())
        }
        async fn a(&self, d: &str) -> Lookup<Ipv4Addr> {
            found_or_absent(match d {
                "v.example" | "mx.v.example" | "other.example" => {
                    vec!["192.0.2.1".parse().unwrap()]
                }
                _ => vec![],
            })
        }
        async fn mx(&self, d: &str) -> Lookup<(u16, String)> {
            found_or_absent(match d {
                "v.example" => vec![(10, "mx.v.example".to_string())],
                _ => vec![],
            })
        }
        async fn ptr(&self, _: &str) -> Lookup<String> {
            Lookup::Absent
        }
    }

    /// Evaluate `record` as `v.example`'s SPF record for `peer`, mapping
    /// errors to their results.
    async fn eval(record: &str, peer: &str) -> SpfResult {
        let dns = Dns {
            txt: HashMap::from([("v.example".to_string(), vec![record.to_string()])]),
        };
        match check_host(
            &dns,
            peer.parse().unwrap(),
            &"x@v.example".to_string(),
            "v.example".to_string(),
            &None,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => e.to_result(),
        }
    }

    #[tokio::test]
    async fn hard_fail_records_are_not_weakened() {
        const OUTSIDE: &str = "198.51.100.9";
        for (record, peer, expected) in [
            ("v=spf1 ip4:192.0.2.1 -all", OUTSIDE, SpfResult::Fail),
            ("v=spf1 ip4:192.0.2.1 -ALL", OUTSIDE, SpfResult::Fail),
            ("V=SPF1 IP4:192.0.2.1 -All", OUTSIDE, SpfResult::Fail),
            (
                "v=spf1 ip4:192.0.2.1 bogus -all",
                OUTSIDE,
                SpfResult::PermError,
            ),
            (
                "v=spf1 ip4:192.0.2.1 all:x -all",
                OUTSIDE,
                SpfResult::PermError,
            ),
            ("v=spf1 mx/24 -all", OUTSIDE, SpfResult::Fail),
            ("v=spf1 MX/24 -all", "192.0.2.200", SpfResult::Pass),
            ("v=spf1 a/24 -all", "192.0.2.77", SpfResult::Pass),
            (
                "v=spf1 a:other.example/24 -all",
                "192.0.2.77",
                SpfResult::Pass,
            ),
            (
                "v=spf1 a:other.example/24//64 -all",
                "192.0.2.77",
                SpfResult::Pass,
            ),
            ("v=spf1 a//64 -all", "192.0.2.1", SpfResult::Pass),
            ("v=spf1 a/33 -all", OUTSIDE, SpfResult::PermError),
            ("v=spf1 a/ -all", OUTSIDE, SpfResult::PermError),
            ("v=spf1 a: -all", OUTSIDE, SpfResult::PermError),
            ("v=spf1 include -all", OUTSIDE, SpfResult::PermError),
            (
                "v=spf1 redirect=a.example redirect=b.example",
                OUTSIDE,
                SpfResult::PermError,
            ),
            (
                "v=spf1 unknown-mod=x ip4:192.0.2.1 -all",
                OUTSIDE,
                SpfResult::Fail,
            ),
            (
                "v=spf1 ip6:2001:db8::1 ip6:2001:db8::/32 -all",
                OUTSIDE,
                SpfResult::Fail,
            ),
        ] {
            assert_eq!(eval(record, peer).await, expected, "{record} from {peer}");
        }
    }

    #[test]
    fn spf_record_detection() {
        for yes in ["v=spf1", "v=spf1 -all", "V=SPF1 -all", "v=Spf1 a"] {
            assert!(is_spf_record(yes), "{yes}");
        }
        for no in [
            "v=spf10 -all",
            "v=spf1-all",
            "spf1",
            "",
            "v=DMARC1; p=reject",
        ] {
            assert!(!is_spf_record(no), "{no}");
        }
    }

    /// AUDIT_20261126B F4 (Low). RFC 7208 §4.5: the separator after
    /// `v=spf1` is `sep = LWSP` — a space, a tab, or foldable
    /// whitespace — so `v=spf1\t-all` is a well-formed record that
    /// authorizes nothing and must produce **Fail** for an unlisted
    /// sender. `is_spf_record` accepts only a literal space (or the end
    /// of the string) after the version token, so a tab-separated
    /// record is not recognized as a record at all: the domain looks
    /// like it publishes no SPF policy, `check_host` is `None`, and the
    /// envelope is accepted. The `-all` the domain published is never
    /// evaluated — a silent fail-open of exactly the kind §4.6.1 warns
    /// about (an unparseable record must be a PermError, never "no
    /// record"). Rare in practice (a victim-side misconfiguration, not
    /// an attacker-chosen field), but the whole point of the SPF gate
    /// is that a published hard fail can never read as "no opinion".
    #[test]
    fn tab_separated_records_are_records() {
        assert!(
            is_spf_record("v=spf1\t-all"),
            "RFC 7208 §4.5: sep is LWSP, which includes HTAB"
        );
        assert!(is_spf_record("v=spf1\t"));
    }

    /// The same record end to end: with the tab as separator, an
    /// unlisted IP must get Fail (550 at MAIL FROM), and a listed one
    /// Pass — never `None` (accepted, no assertion).
    #[tokio::test]
    async fn tab_separated_records_are_evaluated() {
        assert_eq!(
            eval("v=spf1\tip4:192.0.2.1 -all", "198.51.100.9").await,
            SpfResult::Fail,
            "a tab-separated -all must still produce Fail"
        );
        assert_eq!(
            eval("v=spf1\tip4:192.0.2.1 -all", "192.0.2.1").await,
            SpfResult::Pass
        );
    }
}
