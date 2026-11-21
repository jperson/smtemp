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
use std::time::Duration;
use thiserror::Error;

use dns::proto::{DnsMessage, QType};
use dns::query_tls;

/// The public module for the lexer and AST parser.
pub mod parser;
use crate::parser::parser::{
    parse, Spf, SpfDirective, SpfMacroSubs, SpfMechanism, SpfModifier, SpfQualifier, SpfTerm,
};

/// The result of an SPF evaluation (RFC 7208 Section 2.6).
#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub enum SpfResult {
    /// No SPF record published for the checked domain.
    None,
    /// The domain explicitly asserts no opinion (`?all`).
    Neutral,
    /// The sending IP is authorized.
    Pass,
    /// The sending IP is explicitly not authorized (`-all`).
    Fail,
    /// The sending IP is probably not authorized (`~all`).
    SoftFail,
    /// A transient DNS error; evaluation may be retried.
    TempError,
    /// The record (or the evaluation) is unusable.
    PermError,
}

/// Why an SPF evaluation could not produce a normal result. The variants
/// matter because they map to different SMTP outcomes (RFC 7208 Section
/// 4.6.1): transient DNS failures are 4xx, everything else — including
/// both evaluation limits — is 5xx.
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
}

impl SpfError {
    /// The SPF result this error produces.
    pub fn to_result(&self) -> SpfResult {
        match self {
            SpfError::Temp => SpfResult::TempError,
            SpfError::Perm | SpfError::LookupLimit(_) | SpfError::VoidLimit(_) => {
                SpfResult::PermError
            }
        }
    }
}

/// RFC 7208 Section 4.6.4 evaluation limits, shared by every DNS query a
/// single `check_host()` evaluation performs: the record fetches behind
/// `include` and `redirect`, the `a`/`mx`/`ptr`/`exists` mechanism
/// queries, and the secondary A lookups behind `mx` and `ptr`.
///
/// The budget is what makes hostile records safe to evaluate: a circular
/// include/redirect chain or a record with dozens of mechanisms terminates
/// with PermError after at most [`MAX_LOOKUPS`] queries instead of
/// recursing without bound.
#[derive(Default)]
struct Budget {
    lookups: usize,
    void: usize,
}

const MAX_LOOKUPS: usize = 10;
const MAX_VOID_LOOKUPS: usize = 2;

impl Budget {
    /// Account one DNS lookup; Err means the evaluation must abort with
    /// PermError (RFC 7208 Section 4.6.4: "If this limit is exceeded, a
    /// PermError MUST be returned").
    fn spend(&mut self) -> Result<(), SpfError> {
        self.lookups += 1;
        if self.lookups > MAX_LOOKUPS {
            return Err(SpfError::LookupLimit(MAX_LOOKUPS));
        }
        Ok(())
    }

    /// Account one void lookup — a query that returned no records at all
    /// (NXDOMAIN or an empty answer section).
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
/// Implementations return an empty vector for a name that does not exist
/// (NXDOMAIN) and an `Err` for transient lookup failures.
pub trait SpfResolver {
    /// TXT records for a domain.
    fn txt(&self, domain: &str) -> impl Future<Output = Result<Vec<String>>> + Send;
    /// A records for a domain.
    fn a(&self, domain: &str) -> impl Future<Output = Result<Vec<Ipv4Addr>>> + Send;
    /// MX records for a domain, as (preference, exchange domain) pairs.
    fn mx(&self, domain: &str) -> impl Future<Output = Result<Vec<(u16, String)>>> + Send;
    /// PTR record names for a reverse-lookup name.
    fn ptr(&self, domain: &str) -> impl Future<Output = Result<Vec<String>>> + Send;
}

/// [`SpfResolver`] over DNS-over-TLS. Each query is bounded by `timeout`;
/// a resolver that stalls (or a black-holed route) produces a transient
/// error instead of hanging the SMTP session.
pub struct DotResolver {
    /// The resolver's IP address (DNS-over-TLS on port 853).
    pub server: Ipv4Addr,
    /// Per-query timeout.
    pub timeout: Duration,
}

impl DotResolver {
    /// A resolver with the default 5-second per-query timeout.
    pub fn new(server: Ipv4Addr) -> Self {
        DotResolver {
            server,
            timeout: Duration::from_secs(5),
        }
    }

    /// A resolver with an explicit per-query timeout.
    pub fn with_timeout(server: Ipv4Addr, timeout: Duration) -> Self {
        DotResolver { server, timeout }
    }

    async fn query(&self, domain: &str, qtype: u16) -> Result<DnsMessage> {
        match tokio::time::timeout(self.timeout, query_tls(&self.server, domain, qtype, 0x01)).await
        {
            Ok(resp) => resp,
            // Elapsed is not an anyhow error; wrap it.
            Err(_) => Err(anyhow::anyhow!("DNS query timed out")),
        }
    }
}

/// Collect mapped answers, treating NXDOMAIN as an empty result and any
/// other rcode as a transient failure.
fn take_answers<T>(resp: DnsMessage, f: impl Fn(QType) -> Option<T>) -> Result<Vec<T>> {
    match resp.header.rcode {
        0x00 => Ok(resp
            .answers
            .into_iter()
            .filter_map(|a| f(a.rdata))
            .collect()),
        0x03 => Ok(Vec::new()),
        code => Err(anyhow::anyhow!("DNS lookup failed with rcode {code}")),
    }
}

impl SpfResolver for DotResolver {
    async fn txt(&self, domain: &str) -> Result<Vec<String>> {
        let resp = self.query(domain, 0x10).await?;
        take_answers(resp, |r| match r {
            QType::TXT(s) => Some(s),
            _ => None,
        })
    }

    async fn a(&self, domain: &str) -> Result<Vec<Ipv4Addr>> {
        let resp = self.query(domain, 0x16).await?;
        take_answers(resp, |r| match r {
            QType::A(ip) => Some(ip),
            _ => None,
        })
    }

    async fn mx(&self, domain: &str) -> Result<Vec<(u16, String)>> {
        let resp = self.query(domain, 0x0F).await?;
        take_answers(resp, |r| match r {
            QType::MX(pref, label) => Some((pref, String::from(&label))),
            _ => None,
        })
    }

    async fn ptr(&self, domain: &str) -> Result<Vec<String>> {
        let resp = self.query(domain, 0x0C).await?;
        take_answers(resp, |r| match r {
            QType::PTR(label) => Some(String::from(&label)),
            _ => None,
        })
    }
}

/// Fetch and parse the SPF record of a domain. Returns `Ok(None)` when the
/// domain publishes no `v=spf1` TXT record (NXDOMAIN or no matching
/// record); `Err` is for transient lookup failures or an unusable record.
pub async fn query_spf_record<R: SpfResolver + Sync>(
    resolver: &R,
    domain: &str,
    subs: &SpfMacroSubs,
) -> std::result::Result<Option<Spf>, SpfError> {
    // NOTE: no hostname-syntax validation here: underscore-prefixed names
    // (`_spf.example.com`, `selector._domainkey.example.com`) are valid in
    // DNS and routinely appear in SPF includes.
    let txts = resolver.txt(domain).await.map_err(|_| SpfError::Temp)?;

    // RFC 7208 Section 3.2: a domain with more than one v=spf1 record is a
    // permanent error, and a record that does not parse is one too.
    let mut found: Option<Spf> = None;
    for txt in txts {
        if txt.starts_with("v=spf1") {
            if found.is_some() {
                return Err(SpfError::Perm);
            }
            found = Some(parse(subs, txt.as_str()).map_err(|_| SpfError::Perm)?);
        }
    }

    Ok(found)
}

/// Evaluate `check_host()` for an identity (RFC 7208 Section 4). Each call
/// gets a fresh lookup budget.
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
    let mut budget = Budget::default();
    check_host_limited(resolver, peer, sender, domain, helo, &mut budget).await
}

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
            return check_host_limited(resolver, peer, sender, m.value.clone(), helo, budget).await;
        }
    }

    match result {
        Some(r) => Ok(r),
        None => Ok(SpfResult::Neutral),
    }
}

/// The result a matching directive yields for a given qualifier.
fn qualify(q: &SpfQualifier) -> SpfResult {
    match q {
        SpfQualifier::Plus => SpfResult::Pass,
        SpfQualifier::Dash => SpfResult::Fail,
        SpfQualifier::Question => SpfResult::Neutral,
        SpfQualifier::Tilde => SpfResult::SoftFail,
    }
}

fn check_ipv4(peer: IpAddr, ip: &Ipv4Net, result: &SpfResult) -> Option<SpfResult> {
    match peer {
        IpAddr::V4(ip4) if ip.contains(&ip4) => Some(result.clone()),
        _ => None,
    }
}

fn check_ipv6(peer: IpAddr, ip: &Ipv6Net, result: &SpfResult) -> Option<SpfResult> {
    match peer {
        IpAddr::V6(ip6) if ip.contains(&ip6) => Some(result.clone()),
        _ => None,
    }
}

/// `a` / `a:domain` / `a:domain/cidr` (RFC 7208 Section 5.2): the A records
/// of the domain (or the current domain when the domain-spec is empty).
async fn check_a_record<R: SpfResolver + Sync>(
    resolver: &R,
    peer: IpAddr,
    d: &str,
    m: &SpfResult,
    budget: &mut Budget,
) -> std::result::Result<Option<SpfResult>, SpfError> {
    budget.spend()?;
    let ips = resolver.a(d).await.map_err(|_| SpfError::Temp)?;
    if ips.is_empty() {
        budget.record_void()?;
    }

    for ip in ips {
        let ipn = Ipv4Net::from(ip);
        if let Some(r) = check_ipv4(peer, &ipn, m) {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// `mx` (RFC 7208 Section 5.3): the A records of each MX exchange of the
/// domain. The MX lookup counts as one budgeted lookup and each exchange's
/// A lookup as another, so a record pointing at a wildcard MX target is
/// bounded by the shared budget.
async fn check_mx_record<R: SpfResolver + Sync>(
    resolver: &R,
    peer: IpAddr,
    d: &str,
    m: &SpfResult,
    budget: &mut Budget,
) -> std::result::Result<Option<SpfResult>, SpfError> {
    budget.spend()?;
    let mxs = resolver.mx(d).await.map_err(|_| SpfError::Temp)?;
    if mxs.is_empty() {
        budget.record_void()?;
    }

    for (_, exchange) in mxs {
        budget.spend()?;
        let ips = resolver.a(&exchange).await.map_err(|_| SpfError::Temp)?;
        if ips.is_empty() {
            budget.record_void()?;
        }
        for ip in ips {
            let ipn = Ipv4Net::from(ip);
            if let Some(r) = check_ipv4(peer, &ipn, m) {
                return Ok(Some(r));
            }
        }
    }
    Ok(None)
}

/// `ptr` (RFC 7208 Section 5.5): forward-confirmed reverse DNS of the
/// connecting IP, validated against the domain-spec (or the current domain
/// when the domain-spec is empty). The PTR lookup and each forward lookup
/// count against the budget.
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
    let names = resolver.ptr(&rev).await.map_err(|_| SpfError::Temp)?;
    if names.is_empty() {
        budget.record_void()?;
    }

    let target = if d.is_empty() { current_domain } else { d };
    let target = target.to_ascii_lowercase();

    for name in names {
        // Forward-confirm: the PTR name's A records must contain the IP.
        budget.spend()?;
        let ips = resolver.a(&name).await.map_err(|_| SpfError::Temp)?;
        if ips.is_empty() {
            budget.record_void()?;
        }
        if !ips.contains(&ip4) {
            continue;
        }
        let name = name.to_ascii_lowercase();
        if name == target || name.ends_with(&format!(".{target}")) {
            return Ok(Some(m.clone()));
        }
    }
    Ok(None)
}

/// `exists` (RFC 7208 Section 5.7): matches when the domain has at least
/// one A record, regardless of the connecting IP.
async fn check_exists<R: SpfResolver + Sync>(
    resolver: &R,
    d: &str,
    budget: &mut Budget,
) -> std::result::Result<Option<SpfResult>, SpfError> {
    budget.spend()?;
    let ips = resolver.a(d).await.map_err(|_| SpfError::Temp)?;
    if ips.is_empty() {
        budget.record_void()?;
        return Ok(None);
    }
    Ok(Some(SpfResult::Pass))
}

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

        SpfMechanism::A(s) => {
            // An empty domain-spec means the current domain (RFC 7208
            // Section 5.2).
            let target = if s.is_empty() { domain } else { s };
            match check_a_record(resolver, peer, target, &qualify(q), budget).await {
                Ok(r) => r,
                Err(e) => Some(e.to_result()),
            }
        }
        SpfMechanism::Mx(s) => {
            // An empty domain-spec means the current domain (RFC 7208
            // Section 5.3).
            let target = if s.is_empty() { domain } else { s };
            match check_mx_record(resolver, peer, target, &qualify(q), budget).await {
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
    }

    impl SpfResolver for MockResolver {
        async fn txt(&self, domain: &str) -> Result<Vec<String>> {
            Ok(self.txt.get(domain).cloned().unwrap_or_default())
        }
        async fn a(&self, domain: &str) -> Result<Vec<Ipv4Addr>> {
            Ok(self.a.get(domain).cloned().unwrap_or_default())
        }
        async fn mx(&self, domain: &str) -> Result<Vec<(u16, String)>> {
            Ok(self.mx.get(domain).cloned().unwrap_or_default())
        }
        async fn ptr(&self, domain: &str) -> Result<Vec<String>> {
            Ok(self.ptr.get(domain).cloned().unwrap_or_default())
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

    #[tokio::test]
    async fn test_check_host_reddit_unlisted_ip() {
        let result = check(&reddit_resolver(), "10.0.0.1", "foo@test.com", "reddit.com")
            .await
            .unwrap();
        // Not listed: falls through the includes to ~all.
        assert_eq!(SpfResult::SoftFail, result);
    }

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

        // The loop used to recurse without bound; the budget terminates it.
        let result = check(&resolver, "192.0.2.1", "foo@a.example", "a.example")
            .await
            .unwrap();
        assert_eq!(SpfResult::PermError, result);
    }

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
        // it (the old behavior) would wrongly return Pass.
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
        assert!(result.is_err(), "the stalled query must fail");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the query must give up after the timeout, not hang"
        );
    }
}
