//! DMARC (RFC 7489) evaluation: record parsing, identifier alignment,
//! and policy application.
//!
//! The evaluation is pure and offline-testable; the policy-record fetch
//! is generic over [`spf::SpfResolver`], reusing the SPF crate's resolver
//! abstraction (and its fixture mocks).
//!
//! Not implemented: `rua=`/`ruf=` reporting, `pct=` gradual sampling
//! (treated as 100), and PSL-based organizational-domain discovery. Policy
//! discovery walks the From domain's ancestors instead (see
//! [`fetch_policy`]); relaxed alignment is a suffix test.
#![warn(missing_docs)]

use spf::SpfResolver;
use thiserror::Error;

/// Errors from DMARC record fetching and parsing.
#[derive(Debug, Error)]
pub enum DmarcError {
    /// The record does not parse; the payload names the offending tag
    /// (`v`, `v missing`, `p`, `adkim`, `aspf`, `pct`).
    #[error("invalid DMARC record: {0}")]
    Invalid(&'static str),
    /// More than one parseable DMARC record at the name.
    #[error("multiple DMARC records")]
    MultipleRecords,
    /// The DNS lookup itself failed (any resolver error, including
    /// timeouts).
    #[error("transient DNS failure")]
    Temp,
}

/// The `p=` (and `sp=`) policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    /// `p=none` — monitor only; mail is not quarantined or rejected.
    None,
    /// `p=quarantine` — flag failing mail for the spam pipeline.
    Quarantine,
    /// `p=reject` — refuse failing mail.
    Reject,
}

/// A parsed `_dmarc.<domain>` TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    /// `p=` — the policy for the domain.
    pub policy: DmarcPolicy,
    /// `sp=` — the policy for subdomains (defaults to `p=`).
    pub subdomain_policy: Option<DmarcPolicy>,
    /// `adkim=r|s` — DKIM alignment mode (default relaxed).
    pub adkim_strict: bool,
    /// `aspf=r|s` — SPF alignment mode (default relaxed).
    pub aspf_strict: bool,
    /// `pct=` — percentage of messages the policy applies to (0-100;
    /// this implementation treats every value as 100).
    pub pct: u8,
}

impl DmarcRecord {
    /// Parse a DMARC record from the TXT text `txt`. Requires `v=DMARC1`
    /// (case per RFC 7489 Section 6.3: the tag is case-insensitive but the
    /// value "DMARC1" is literal) and a valid `p=`. Reporting tags are
    /// ignored.
    ///
    /// # Errors
    ///
    /// [`DmarcError::Invalid`] for a missing or wrong `v=`, a missing
    /// `p=` (reported as `v`), or an unusable `p=`, `sp=`, `adkim=`,
    /// `aspf=` or `pct=` value.
    pub fn parse(txt: &str) -> Result<Self, DmarcError> {
        let mut version = None;
        let mut policy = None;
        let mut subdomain_policy = None;
        let mut adkim_strict = false;
        let mut aspf_strict = false;
        let mut pct = 100;

        for segment in txt.split(';') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            let Some((name, value)) = segment.split_once('=') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "v" => version = Some(value.to_string()),
                "p" => policy = Some(parse_policy(value)?),
                "sp" => subdomain_policy = Some(parse_policy(value)?),
                "adkim" => match value {
                    "r" => adkim_strict = false,
                    "s" => adkim_strict = true,
                    _ => return Err(DmarcError::Invalid("adkim")),
                },
                "aspf" => match value {
                    "r" => aspf_strict = false,
                    "s" => aspf_strict = true,
                    _ => return Err(DmarcError::Invalid("aspf")),
                },
                "pct" => {
                    pct = value.parse().map_err(|_| DmarcError::Invalid("pct"))?;
                }
                // rua, ruf, fo, rf, ri: reporting tags, not needed for
                // policy evaluation.
                _ => {}
            }
        }

        match (version.as_deref(), policy) {
            (Some("DMARC1"), Some(policy)) => Ok(DmarcRecord {
                policy,
                subdomain_policy,
                adkim_strict,
                aspf_strict,
                pct,
            }),
            (Some(_), _) => Err(DmarcError::Invalid("v")),
            (None, _) => Err(DmarcError::Invalid("v missing")),
        }
    }

    /// Returns the policy that applies to `domain` when this record was
    /// published for `record_domain`: `sp=` (if set) for subdomains of
    /// `record_domain`, `p=` otherwise.
    pub fn policy_for(&self, record_domain: &str, domain: &str) -> DmarcPolicy {
        let is_subdomain = domain != record_domain
            && domain
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", record_domain.to_ascii_lowercase()));
        match (is_subdomain, self.subdomain_policy) {
            (true, Some(sp)) => sp,
            _ => self.policy,
        }
    }
}

/// Parse a `p=`/`sp=` `value` (case-insensitive).
///
/// # Errors
///
/// [`DmarcError::Invalid`] (`p`) for anything but none, quarantine or
/// reject.
fn parse_policy(value: &str) -> Result<DmarcPolicy, DmarcError> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(DmarcPolicy::None),
        "quarantine" => Ok(DmarcPolicy::Quarantine),
        "reject" => Ok(DmarcPolicy::Reject),
        _ => Err(DmarcError::Invalid("p")),
    }
}

/// Relaxed alignment (RFC 7489 Section 3.1.1): returns whether domains
/// `a` and `b` are equal or one is a subdomain of the other (trimmed,
/// case-insensitive).
pub fn aligned_relaxed(a: &str, b: &str) -> bool {
    let a = a.trim().to_ascii_lowercase();
    let b = b.trim().to_ascii_lowercase();
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

/// Strict alignment: returns whether domains `a` and `b` match exactly
/// (trimmed, case-insensitive).
pub fn aligned_strict(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// The outcome of alignment evaluation for one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// SPF passed **and** its Mail From domain is aligned with the From
    /// header domain.
    pub spf_aligned: bool,
    /// At least one DKIM signature is verified **and** its `d=` domain is
    /// aligned with the From header domain.
    pub dkim_aligned: bool,
    /// At least one of the two.
    pub pass: bool,
}

/// Evaluate alignment (RFC 7489 Section 4.2; the DMARC "pass" requires
/// SPF **or** DKIM alignment) of a message with author domain
/// `from_domain` under `record`'s alignment modes. `spf` is the
/// envelope-sender domain and whether SPF evaluated to Pass (`None` with
/// no sender domain); `dkim` is each signature's `d=` domain and whether
/// it fully verified.
///
/// Returns the alignment results.
pub fn evaluate(
    record: &DmarcRecord,
    spf: Option<(&str, bool)>,
    dkim: &[(String, bool)],
    from_domain: &str,
) -> Evaluation {
    let spf_aligned =
        matches!(spf, Some((domain, true)) if spf_aligned(record, domain, from_domain));
    let dkim_aligned = dkim
        .iter()
        .any(|(domain, verified)| *verified && dkim_aligned(record, domain, from_domain));
    let pass = spf_aligned || dkim_aligned;
    Evaluation {
        spf_aligned,
        dkim_aligned,
        pass,
    }
}

/// Whether `spf_domain` aligns with `from_domain` under `record`'s
/// `aspf=` mode.
fn spf_aligned(record: &DmarcRecord, spf_domain: &str, from_domain: &str) -> bool {
    if record.aspf_strict {
        aligned_strict(spf_domain, from_domain)
    } else {
        aligned_relaxed(spf_domain, from_domain)
    }
}

/// Whether `dkim_domain` aligns with `from_domain` under `record`'s
/// `adkim=` mode.
fn dkim_aligned(record: &DmarcRecord, dkim_domain: &str, from_domain: &str) -> bool {
    if record.adkim_strict {
        aligned_strict(dkim_domain, from_domain)
    } else {
        aligned_relaxed(dkim_domain, from_domain)
    }
}

/// What the verifier does with the message (RFC 7489 Section 7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Accepted normally.
    Pass,
    /// Accepted but flagged for the spam/quarantine pipeline.
    Quarantine,
    /// Rejected at end-of-data.
    Reject,
}

/// Decide what to do with a message given its `evaluation` and the
/// `policy` that governs its From domain (see [`FoundPolicy::policy_for`]).
/// `pct` is treated as 100 (no sampling; see module docs).
///
/// Returns [`Action::Pass`] for a DMARC pass or `p=none`, otherwise the
/// policy's action.
pub fn apply(evaluation: &Evaluation, policy: DmarcPolicy) -> Action {
    if evaluation.pass {
        return Action::Pass;
    }
    match policy {
        DmarcPolicy::Reject => Action::Reject,
        DmarcPolicy::Quarantine => Action::Quarantine,
        DmarcPolicy::None => Action::Pass,
    }
}

/// A DMARC record together with the domain it was published at (needed to
/// choose between `p=` and `sp=`, RFC 7489 Section 6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundPolicy {
    /// The parsed record.
    pub record: DmarcRecord,
    /// The domain whose `_dmarc.` name carried the record (lowercase, no
    /// trailing dot).
    pub domain: String,
}

impl FoundPolicy {
    /// Returns the policy that governs `from_domain`: `sp=` (if set) when
    /// the record was found at an ancestor of it, `p=` when at the domain
    /// itself.
    pub fn policy_for(&self, from_domain: &str) -> DmarcPolicy {
        self.record.policy_for(&self.domain, from_domain)
    }
}

/// The most `_dmarc.` lookups one policy discovery may make (the DMARCbis
/// tree-walk bound): a long, attacker-chosen From domain can't turn one
/// message into dozens of queries.
pub const MAX_POLICY_QUERIES: usize = 8;

/// Returns the names [`fetch_policy`] queries for `from_domain` (trimmed,
/// lowercased, trailing dot removed), in order: the domain itself, then
/// its ancestors down to two labels. A domain with more labels than the
/// bound skips straight from the full name to its 7-label suffix (as
/// DMARCbis's tree walk does), so at most [`MAX_POLICY_QUERIES`] names are
/// returned.
pub fn policy_candidates(from_domain: &str) -> Vec<String> {
    let domain = from_domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let labels: Vec<&str> = domain.split('.').collect();
    let mut names = vec![domain.clone()];
    let first_ancestor = if labels.len() > MAX_POLICY_QUERIES {
        labels.len() - (MAX_POLICY_QUERIES - 1)
    } else {
        1
    };
    for start in first_ancestor..labels.len().saturating_sub(1) {
        names.push(labels[start..].join("."));
    }
    names
}

/// Discover the DMARC policy for the From-header domain `from_domain`
/// through `resolver`.
///
/// Returns the first record found and the domain it was published for,
/// or `None` when no candidate publishes one.
///
/// Queries `_dmarc.<domain>` for the From domain and then each ancestor
/// (see [`policy_candidates`]), stopping at the first that publishes a
/// record. Walking every ancestor can't skip the organisational domain,
/// whatever the suffix structure, and needs no Public Suffix List. Footgun:
/// don't replace this with a "last two labels" guess. For `x.victim.co.uk`
/// that asks `co.uk`, never `victim.co.uk`, so a spoof from any
/// non-existent subdomain would find no policy.
///
/// # Errors
///
/// Errors fail closed: a transient DNS failure at any step is
/// [`DmarcError::Temp`], because skipping that name could skip the policy
/// that applies, and the caller must defer the message, not deliver it.
/// [`DmarcError::MultipleRecords`] ends discovery (RFC 7489 §6.6.3: DMARC
/// is then not applied).
pub async fn fetch_policy<R: SpfResolver + Sync>(
    resolver: &R,
    from_domain: &str,
) -> Result<Option<FoundPolicy>, DmarcError> {
    for domain in policy_candidates(from_domain) {
        if let Some(record) = fetch_one(resolver, &format!("_dmarc.{domain}")).await? {
            return Ok(Some(FoundPolicy { record, domain }));
        }
    }
    Ok(None)
}

/// Look up the TXT records at `name` through `resolver`.
///
/// Returns the one record that parses as DMARC, or `None` if none does.
///
/// # Errors
///
/// [`DmarcError::Temp`] when the lookup fails,
/// [`DmarcError::MultipleRecords`] when more than one record parses.
async fn fetch_one<R: SpfResolver + Sync>(
    resolver: &R,
    name: &str,
) -> Result<Option<DmarcRecord>, DmarcError> {
    let txts = resolver.txt(name).await.map_err(|_| DmarcError::Temp)?;
    let mut found: Option<DmarcRecord> = None;
    for txt in txts {
        // A TXT record that parses as DMARC is a candidate; unrelated TXT
        // records at the same name are ignored.
        if let Ok(record) = DmarcRecord::parse(txt.trim()) {
            if found.is_some() {
                return Err(DmarcError::MultipleRecords);
            }
            found = Some(record);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn record(txt: &str) -> DmarcRecord {
        DmarcRecord::parse(txt).unwrap()
    }

    #[test]
    fn parse_valid_records() {
        let r = record("v=DMARC1; p=reject");
        assert_eq!(r.policy, DmarcPolicy::Reject);
        assert_eq!(r.subdomain_policy, None);
        assert!(!r.adkim_strict && !r.aspf_strict);
        assert_eq!(r.pct, 100);

        let r = record(
            "v=DMARC1; p=quarantine; sp=reject; adkim=s; aspf=s; pct=25; rua=mailto:agg@d.example",
        );
        assert_eq!(r.policy, DmarcPolicy::Quarantine);
        assert_eq!(r.subdomain_policy, Some(DmarcPolicy::Reject));
        assert!(r.adkim_strict && r.aspf_strict);
        assert_eq!(r.pct, 25);
    }

    #[test]
    fn parse_rejects_invalid_records() {
        assert!(DmarcRecord::parse("v=SPF1; p=reject").is_err()); // wrong version
        assert!(DmarcRecord::parse("p=reject").is_err()); // no version
        assert!(DmarcRecord::parse("v=DMARC1").is_err()); // no policy
        assert!(DmarcRecord::parse("v=DMARC1; p=nonsense").is_err());
        assert!(DmarcRecord::parse("v=DMARC1; p=reject; adkim=x").is_err());
    }

    #[test]
    fn alignment_modes() {
        assert!(aligned_relaxed("example.org", "example.org"));
        assert!(aligned_relaxed("mail.example.org", "example.org"));
        assert!(aligned_relaxed("example.org", "mail.example.org"));
        assert!(!aligned_relaxed("notexample.org", "example.org"));

        assert!(aligned_strict("Example.ORG", "example.org"));
        assert!(!aligned_strict("mail.example.org", "example.org"));
    }

    #[test]
    fn evaluate_spf_or_dkim() {
        let r = record("v=DMARC1; p=reject");

        // SPF aligned + passing.
        let e = evaluate(&r, Some(("example.org", true)), &[], "example.org");
        assert!(e.pass && e.spf_aligned && !e.dkim_aligned);

        // SPF passing but unaligned (relaxed subdomain IS aligned).
        let e = evaluate(&r, Some(("other.net", true)), &[], "example.org");
        assert!(!e.pass);

        // DKIM aligned + verified.
        let e = evaluate(
            &r,
            Some(("other.net", false)),
            &[("mail.example.org".to_string(), true)],
            "example.org",
        );
        assert!(e.pass && e.dkim_aligned);

        // DKIM aligned but NOT verified.
        let e = evaluate(
            &r,
            None,
            &[("example.org".to_string(), false)],
            "example.org",
        );
        assert!(!e.pass);

        // Strict SPF alignment rejects subdomains.
        let strict = record("v=DMARC1; p=reject; aspf=s; adkim=s");
        let e = evaluate(
            &strict,
            Some(("mail.example.org", true)),
            &[],
            "example.org",
        );
        assert!(!e.spf_aligned && !e.pass);
    }

    #[test]
    fn apply_policies() {
        let pass_eval = Evaluation {
            spf_aligned: true,
            dkim_aligned: false,
            pass: true,
        };
        let fail_eval = Evaluation {
            spf_aligned: false,
            dkim_aligned: false,
            pass: false,
        };

        assert_eq!(apply(&pass_eval, DmarcPolicy::Reject), Action::Pass);
        assert_eq!(apply(&fail_eval, DmarcPolicy::Reject), Action::Reject);
        assert_eq!(
            apply(&fail_eval, DmarcPolicy::Quarantine),
            Action::Quarantine
        );
        // p=none: monitor only, message passes.
        assert_eq!(apply(&fail_eval, DmarcPolicy::None), Action::Pass);
    }

    #[test]
    fn subdomain_policy_selection() {
        let r = record("v=DMARC1; p=none; sp=reject");
        assert_eq!(
            r.policy_for("example.org", "example.org"),
            DmarcPolicy::None
        );
        assert_eq!(
            r.policy_for("example.org", "mail.example.org"),
            DmarcPolicy::Reject
        );
        // Not a subdomain (no dot-prefix match).
        assert_eq!(
            r.policy_for("example.org", "notexample.org"),
            DmarcPolicy::None
        );
    }

    #[derive(Default, Clone)]
    struct MockResolver {
        txt: HashMap<String, Vec<String>>,
        /// Names whose TXT lookup fails (SERVFAIL, timeout).
        fail: std::collections::HashSet<String>,
        /// Every TXT name queried, in order.
        queried: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl SpfResolver for MockResolver {
        async fn txt(&self, domain: &str) -> anyhow::Result<Vec<String>> {
            self.queried.lock().unwrap().push(domain.to_string());
            if self.fail.contains(domain) {
                anyhow::bail!("SERVFAIL");
            }
            Ok(self.txt.get(domain).cloned().unwrap_or_default())
        }
        async fn a(&self, _domain: &str) -> anyhow::Result<Vec<std::net::Ipv4Addr>> {
            Ok(vec![])
        }
        async fn mx(&self, _domain: &str) -> anyhow::Result<Vec<(u16, String)>> {
            Ok(vec![])
        }
        async fn ptr(&self, _domain: &str) -> anyhow::Result<Vec<String>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn fetch_policy_direct_and_org_fallback() {
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "_dmarc.example.org".to_string(),
            vec!["v=DMARC1; p=reject".to_string()],
        );

        let r = fetch_policy(&resolver, "example.org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.record.policy, DmarcPolicy::Reject);
        assert_eq!(r.domain, "example.org");

        // A subdomain with no own record falls back to the organizational
        // domain's record.
        let r = fetch_policy(&resolver, "mail.example.org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.record.policy, DmarcPolicy::Reject);
        assert_eq!(r.domain, "example.org", "found at the ancestor");

        // Unrelated TXT records are ignored.
        let mut resolver = MockResolver::default();
        resolver.txt.insert(
            "_dmarc.example.org".to_string(),
            vec!["some unrelated TXT record".to_string()],
        );
        assert!(fetch_policy(&resolver, "example.org")
            .await
            .unwrap()
            .is_none());
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Dns {
        txt: HashMap<String, Vec<String>>,
        fail: HashSet<String>,
        queried: Arc<Mutex<Vec<String>>>,
    }

    impl SpfResolver for Dns {
        async fn txt(&self, domain: &str) -> anyhow::Result<Vec<String>> {
            self.queried.lock().unwrap().push(domain.to_string());
            if self.fail.contains(domain) {
                anyhow::bail!("SERVFAIL");
            }
            Ok(self.txt.get(domain).cloned().unwrap_or_default())
        }
        async fn a(&self, _: &str) -> anyhow::Result<Vec<std::net::Ipv4Addr>> {
            Ok(vec![])
        }
        async fn mx(&self, _: &str) -> anyhow::Result<Vec<(u16, String)>> {
            Ok(vec![])
        }
        async fn ptr(&self, _: &str) -> anyhow::Result<Vec<String>> {
            Ok(vec![])
        }
    }

    fn with(records: &[(&str, &str)]) -> Dns {
        let mut dns = Dns::default();
        for (name, txt) in records {
            dns.txt
                .entry(name.to_string())
                .or_default()
                .push(txt.to_string());
        }
        dns
    }

    /// A spoof from a non-existent subdomain of a domain under a
    /// multi-label public suffix finds the victim's policy, not `co.uk`'s.
    #[tokio::test]
    async fn multi_label_suffix_subdomain_finds_the_victims_policy() {
        let dns = with(&[("_dmarc.victim.co.uk", "v=DMARC1; p=reject")]);
        let found = fetch_policy(&dns, "anything.victim.co.uk")
            .await
            .unwrap()
            .expect("victim policy found");
        assert_eq!(found.domain, "victim.co.uk");
        assert_eq!(
            found.policy_for("anything.victim.co.uk"),
            DmarcPolicy::Reject
        );
        assert_eq!(
            *dns.queried.lock().unwrap(),
            ["_dmarc.anything.victim.co.uk", "_dmarc.victim.co.uk"]
        );
    }

    /// The walk stops at the nearest record, so an intermediate domain's
    /// own policy wins over its parent's.
    #[tokio::test]
    async fn nearest_ancestor_record_wins() {
        let dns = with(&[
            ("_dmarc.example.com", "v=DMARC1; p=none"),
            ("_dmarc.corp.example.com", "v=DMARC1; p=reject"),
        ]);
        let found = fetch_policy(&dns, "a.b.corp.example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.domain, "corp.example.com");
    }

    /// A DNS failure anywhere in the walk is a temporary error, never "no
    /// policy" — the policy might be at the name that failed.
    #[tokio::test]
    async fn dns_failure_is_temp_not_no_policy() {
        let mut dns = with(&[("_dmarc.victim.example", "v=DMARC1; p=reject")]);
        dns.fail.insert("_dmarc.victim.example".into());
        assert!(matches!(
            fetch_policy(&dns, "victim.example").await,
            Err(DmarcError::Temp)
        ));
        // A failure at the subdomain must not be skipped over either.
        let mut dns = with(&[("_dmarc.victim.example", "v=DMARC1; p=reject")]);
        dns.fail.insert("_dmarc.x.victim.example".into());
        assert!(matches!(
            fetch_policy(&dns, "x.victim.example").await,
            Err(DmarcError::Temp)
        ));
    }

    #[tokio::test]
    async fn multiple_records_end_discovery() {
        let dns = with(&[
            ("_dmarc.victim.example", "v=DMARC1; p=reject"),
            ("_dmarc.victim.example", "v=DMARC1; p=none"),
        ]);
        assert!(matches!(
            fetch_policy(&dns, "victim.example").await,
            Err(DmarcError::MultipleRecords)
        ));
    }

    /// `sp=` governs a subdomain whose policy came from an ancestor;
    /// `p=` governs the domain that published the record.
    #[tokio::test]
    async fn subdomain_policy_applies_to_inherited_records() {
        let dns = with(&[("_dmarc.example.org", "v=DMARC1; p=none; sp=reject")]);
        let sub = fetch_policy(&dns, "mail.example.org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sub.policy_for("mail.example.org"), DmarcPolicy::Reject);
        let own = fetch_policy(&dns, "example.org").await.unwrap().unwrap();
        assert_eq!(own.policy_for("example.org"), DmarcPolicy::None);
    }

    #[test]
    fn candidate_walk_is_bounded() {
        assert_eq!(policy_candidates("Example.ORG."), ["example.org"]);
        assert_eq!(
            policy_candidates("x.victim.co.uk"),
            ["x.victim.co.uk", "victim.co.uk", "co.uk"]
        );
        assert_eq!(policy_candidates("localhost"), ["localhost"]);
        let long = "a.b.c.d.e.f.g.h.i.j.k.l.example.com";
        let names = policy_candidates(long);
        assert!(names.len() <= MAX_POLICY_QUERIES, "{names:?}");
        assert_eq!(names[0], long);
        assert_eq!(names[1], "h.i.j.k.l.example.com", "skips to 7 labels");
        assert_eq!(names.last().unwrap(), "example.com");
    }
}
