use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::Serialize;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};

use dns::proto::{DnsMessage, QType};
use dns::query_tls;

pub mod parser;
use crate::parser::parser::{
    parse, Spf, SpfDirective, SpfMacroSubs, SpfMechanism, SpfModifier, SpfQualifier, SpfTerm,
};

#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub enum SpfResult {
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    TempError,
    PermError,
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

/// [`SpfResolver`] over DNS-over-TLS.
pub struct DotResolver {
    pub server: Ipv4Addr,
}

impl DotResolver {
    pub fn new(server: Ipv4Addr) -> Self {
        DotResolver { server }
    }
}

/// Collect mapped answers, treating NXDOMAIN as an empty result and any
/// other rcode as a transient failure.
fn take_answers<T>(resp: DnsMessage, f: impl Fn(QType) -> Option<T>) -> Result<Vec<T>> {
    match resp.header.rcode {
        0x00 => Ok(resp.answers.into_iter().filter_map(|a| f(a.rdata)).collect()),
        0x03 => Ok(Vec::new()),
        code => Err(anyhow!("DNS lookup failed with rcode {code}")),
    }
}

impl SpfResolver for DotResolver {
    async fn txt(&self, domain: &str) -> Result<Vec<String>> {
        let resp = query_tls(&self.server, domain, 0x10, 0x01).await?;
        take_answers(resp, |r| match r {
            QType::TXT(s) => Some(s),
            _ => None,
        })
    }

    async fn a(&self, domain: &str) -> Result<Vec<Ipv4Addr>> {
        let resp = query_tls(&self.server, domain, 0x16, 0x01).await?;
        take_answers(resp, |r| match r {
            QType::A(ip) => Some(ip),
            _ => None,
        })
    }

    async fn mx(&self, domain: &str) -> Result<Vec<(u16, String)>> {
        let resp = query_tls(&self.server, domain, 0x0F, 0x01).await?;
        take_answers(resp, |r| match r {
            QType::MX(pref, label) => Some((pref, String::from(&label))),
            _ => None,
        })
    }

    async fn ptr(&self, domain: &str) -> Result<Vec<String>> {
        let resp = query_tls(&self.server, domain, 0x0C, 0x01).await?;
        take_answers(resp, |r| match r {
            QType::PTR(label) => Some(String::from(&label)),
            _ => None,
        })
    }
}

/// Fetch and parse the SPF record of a domain. Returns `Ok(None)` when the
/// domain publishes no `v=spf1` TXT record (NXDOMAIN or no matching
/// record); `Err` is reserved for transient lookup failures.
pub async fn query_spf_record<R: SpfResolver + Sync>(
    resolver: &R,
    domain: &str,
    subs: &SpfMacroSubs,
) -> Result<Option<Spf>> {
    // NOTE: no hostname-syntax validation here: underscore-prefixed names
    // (`_spf.example.com`, `selector._domainkey.example.com`) are valid in
    // DNS and routinely appear in SPF includes.
    let txts = resolver.txt(domain).await?;

    for txt in txts {
        if txt.starts_with("v=spf1") {
            return Ok(Some(parse(subs, txt.as_str())?));
        }
    }

    Ok(None)
}

#[async_recursion]
pub async fn check_host<R>(
    resolver: &R,
    peer: IpAddr,
    sender: &String,
    domain: String,
    helo: &Option<String>,
) -> Result<SpfResult>
where
    R: SpfResolver + Sync,
{
    let mut result: Option<SpfResult> = None;
    let mut redirect: Option<&SpfModifier> = None;
    let mut exp: Option<&SpfModifier> = None;

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
                if exp.is_some() {
                    return Ok(SpfResult::PermError);
                }
                exp = Some(m);
            }
            SpfTerm::Modifier(_) => continue,
            SpfTerm::Directive(d) => {
                result = check_directive(resolver, domain.as_str(), peer, sender, helo, d).await;
                if result.is_some() {
                    break;
                }
            }
        }
    }

    if result.is_none() {
        if let Some(m) = redirect {
            result = match check_host(resolver, peer, sender, m.value.clone(), helo).await {
                Ok(r) => Some(r),
                // A failed redirect target lookup is transient.
                Err(_) => Some(SpfResult::TempError),
            };
        }
    }

    match result {
        Some(SpfResult::Fail) if exp.is_some() => {
            if let Some(d) = exp {
                check_host(resolver, peer, sender, d.value.clone(), helo).await
            } else {
                Err(anyhow!("check_host failed"))
            }
        }
        Some(r) => Ok(r.clone()),
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
) -> Option<SpfResult> {
    let ips = match resolver.a(d).await {
        Ok(ips) => ips,
        Err(_) => return Some(SpfResult::TempError),
    };

    for ip in ips {
        let ipn = Ipv4Net::from(ip);
        if let Some(r) = check_ipv4(peer, &ipn, m) {
            return Some(r);
        }
    }
    None
}

/// `mx` (RFC 7208 Section 5.3): the A records of each MX exchange of the
/// domain. The exchange names are resolved; they are not IP literals.
async fn check_mx_record<R: SpfResolver + Sync>(
    resolver: &R,
    peer: IpAddr,
    d: &str,
    m: &SpfResult,
) -> Option<SpfResult> {
    let mxs = match resolver.mx(d).await {
        Ok(mxs) => mxs,
        Err(_) => return Some(SpfResult::TempError),
    };

    for (_, exchange) in mxs {
        let ips = match resolver.a(&exchange).await {
            Ok(ips) => ips,
            Err(_) => return Some(SpfResult::TempError),
        };
        for ip in ips {
            let ipn = Ipv4Net::from(ip);
            if let Some(r) = check_ipv4(peer, &ipn, m) {
                return Some(r);
            }
        }
    }
    None
}

/// `ptr` (RFC 7208 Section 5.5): forward-confirmed reverse DNS of the
/// connecting IP, validated against the domain-spec (or the current domain
/// when the domain-spec is empty).
async fn check_ptr_record<R: SpfResolver + Sync>(
    resolver: &R,
    peer: IpAddr,
    d: &str,
    current_domain: &str,
    m: &SpfResult,
) -> Option<SpfResult> {
    let IpAddr::V4(ip4) = peer else {
        return None;
    };

    // Reverse the connecting IP, not the domain-spec.
    let o = ip4.octets();
    let rev = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
    let names = match resolver.ptr(&rev).await {
        Ok(names) => names,
        Err(_) => return Some(SpfResult::TempError),
    };

    let target = if d.is_empty() { current_domain } else { d };
    let target = target.to_ascii_lowercase();

    for name in names {
        // Forward-confirm: the PTR name's A records must contain the IP.
        let ips = match resolver.a(&name).await {
            Ok(ips) => ips,
            Err(_) => return Some(SpfResult::TempError),
        };
        if !ips.contains(&ip4) {
            continue;
        }
        let name = name.to_ascii_lowercase();
        if name == target || name.ends_with(&format!(".{target}")) {
            return Some(m.clone());
        }
    }
    None
}

/// `exists` (RFC 7208 Section 5.7): matches when the domain has at least
/// one A record, regardless of the connecting IP.
async fn check_exists<R: SpfResolver + Sync>(
    resolver: &R,
    d: &str,
) -> Option<SpfResult> {
    match resolver.a(d).await {
        Ok(ips) if ips.is_empty() => None,
        Ok(_) => Some(SpfResult::Pass),
        Err(_) => Some(SpfResult::TempError),
    }
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
) -> Option<SpfResult> {
    match m {
        SpfMechanism::All => Some(qualify(q)),

        // include (RFC 7208 Section 5.2): matches only when the included
        // domain Passes; the include's own qualifier maps that Pass. A
        // DNS failure is transient; a missing record on the included
        // domain is a permanent error.
        SpfMechanism::Include(s) => {
            match check_host(resolver, peer, sender, s.to_string(), helo).await {
                Err(_) => Some(SpfResult::TempError),
                Ok(inner) => match inner {
                    SpfResult::Pass => Some(qualify(q)),
                    SpfResult::Fail | SpfResult::SoftFail | SpfResult::Neutral => None,
                    SpfResult::TempError => Some(SpfResult::TempError),
                    SpfResult::PermError => Some(SpfResult::PermError),
                    SpfResult::None => Some(SpfResult::PermError),
                },
            }
        }

        SpfMechanism::A(s) => {
            // An empty domain-spec means the current domain (RFC 7208
            // Section 5.2).
            let target = if s.is_empty() { domain } else { s };
            check_a_record(resolver, peer, target, &qualify(q)).await
        }
        SpfMechanism::Mx(s) => {
            // An empty domain-spec means the current domain (RFC 7208
            // Section 5.3).
            let target = if s.is_empty() { domain } else { s };
            check_mx_record(resolver, peer, target, &qualify(q)).await
        }
        SpfMechanism::Ptr(s) => {
            check_ptr_record(resolver, peer, s, domain, &qualify(q)).await
        }
        SpfMechanism::Ip4(ip) => check_ipv4(peer, ip, &qualify(q)),
        SpfMechanism::Ip6(ip) => check_ipv6(peer, ip, &qualify(q)),

        SpfMechanism::Exists(s) => match check_exists(resolver, s).await {
            Some(SpfResult::Pass) => Some(qualify(q)),
            Some(other) => Some(other),
            None => None,
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
        m.txt.insert("amazonses.com".to_string(), vec!["v=spf1 ip4:203.0.113.0/24 ~all".to_string()]);
        m.txt.insert("_spf.google.com".to_string(), vec!["v=spf1 ip4:216.239.32.0/19 ~all".to_string()]);
        m.txt.insert("19922862.spf01.hubspotemail.net".to_string(), vec!["v=spf1 ~all".to_string()]);
        m.txt.insert("_spf.salesforce.com".to_string(), vec!["v=spf1 ~all".to_string()]);
        // hs.reddit.com: Fail for everything (the -all in the real record).
        m.txt.insert(
            "hs.reddit.com".to_string(),
            vec!["v=spf1 ip4:149.72.234.184 -all".to_string()],
        );
        m
    }

    #[tokio::test]
    async fn test_check_host_reddit() {
        let resolver = reddit_resolver();
        let result = check_host(
            &resolver,
            "52.50.24.208".parse::<IpAddr>().unwrap(),
            &"foo@test.com".to_string(),
            "reddit.com".to_string(),
            &Some("reddit.com".to_string()),
        )
        .await
        .unwrap();

        assert_eq!(SpfResult::Pass, result);
    }

    #[tokio::test]
    async fn test_check_host_reddit_unlisted_ip() {
        let resolver = reddit_resolver();
        let result = check_host(
            &resolver,
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            &"foo@test.com".to_string(),
            "reddit.com".to_string(),
            &Some("reddit.com".to_string()),
        )
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
            vec!["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all".to_string()],
        );
        resolver.txt.insert(
            "_netblocks.google.com".to_string(),
            vec!["v=spf1 ip4:216.239.32.0/19 ~all".to_string()],
        );
        resolver.txt.insert(
            "_netblocks2.google.com".to_string(),
            vec!["v=spf1 ip4:8.34.208.0/20 ~all".to_string()],
        );

        let result = check_host(
            &resolver,
            "10.0.0.1".parse::<IpAddr>().unwrap(),
            &"foo@test.com".to_string(),
            "google.com".to_string(),
            &Some("google.com".to_string()),
        )
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

        let result = check_host(
            &resolver,
            "52.50.24.208".parse::<IpAddr>().unwrap(),
            &"foo@test.com".to_string(),
            "bing.com".to_string(),
            &Some("bing.com".to_string()),
        )
        .await
        .unwrap();

        // Exercises CIDR parsing: a broken ip4:/nn parse would yield
        // Neutral instead of Fail.
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
        resolver
            .a
            .insert("mail.example.net".to_string(), vec!["192.0.2.25".parse().unwrap()]);

        let pass = check_host(
            &resolver,
            "192.0.2.25".parse::<IpAddr>().unwrap(),
            &"foo@example.net".to_string(),
            "example.net".to_string(),
            &Some("example.net".to_string()),
        )
        .await
        .unwrap();
        assert_eq!(SpfResult::Pass, pass);

        let fail = check_host(
            &resolver,
            "192.0.2.99".parse::<IpAddr>().unwrap(),
            &"foo@example.net".to_string(),
            "example.net".to_string(),
            &Some("example.net".to_string()),
        )
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
        resolver
            .a
            .insert("mail.example.net".to_string(), vec!["192.0.2.25".parse().unwrap()]);

        // Forward-confirmed: matches.
        let pass = check_host(
            &resolver,
            "192.0.2.25".parse::<IpAddr>().unwrap(),
            &"foo@example.net".to_string(),
            "example.net".to_string(),
            &Some("example.net".to_string()),
        )
        .await
        .unwrap();
        assert_eq!(SpfResult::Pass, pass);

        // The PTR name does not forward-confirm to the IP: no match.
        let mut unconfirmed = resolver.clone();
        unconfirmed
            .a
            .insert("mail.example.net".to_string(), vec!["192.0.2.1".parse().unwrap()]);
        let fail = check_host(
            &unconfirmed,
            "192.0.2.25".parse::<IpAddr>().unwrap(),
            &"foo@example.net".to_string(),
            "example.net".to_string(),
            &Some("example.net".to_string()),
        )
        .await
        .unwrap();
        assert_eq!(SpfResult::Fail, fail);
    }

    #[tokio::test]
    async fn test_no_record_is_none() {
        let resolver = MockResolver::default();
        let result = check_host(
            &resolver,
            "192.0.2.1".parse::<IpAddr>().unwrap(),
            &"foo@nodomain.example".to_string(),
            "nodomain.example".to_string(),
            &Some("nodomain.example".to_string()),
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

        let result = check_host(
            &resolver,
            "192.0.2.1".parse::<IpAddr>().unwrap(),
            &"foo@example.net".to_string(),
            "example.net".to_string(),
            &Some("example.net".to_string()),
        )
        .await
        .unwrap();

        // RFC 7208 Section 5.2: an include that resolves to 'none' is a
        // permanent error, not a non-match.
        assert_eq!(SpfResult::PermError, result);
    }

    #[test]
    fn it_works() {
        use fqdn::FQDN;
        let s = String::from(
            "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890.foo.",
        );
        let f = s.parse::<FQDN>();
        println!("{:?}", f);
    }
}
