use anyhow::{anyhow, Result};
use memchr;

use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// The `dual-cidr-length` of an `a` or `mx` mechanism (RFC 7208 §5.6):
/// the prefix lengths applied to each address the mechanism resolves.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DualCidr {
    /// Prefix length for IPv4 addresses (0–32; default 32).
    pub v4: u8,
    /// Prefix length for IPv6 addresses (0–128; default 128).
    pub v6: u8,
}

impl Default for DualCidr {
    fn default() -> Self {
        DualCidr { v4: 32, v6: 128 }
    }
}

/// A mechanism qualifier: the `+`/`-`/`?`/`~` prefix.
#[derive(Debug, Eq, PartialEq)]
pub enum SpfQualifier {
    /// `+` — Pass.
    Plus,
    /// `-` — Fail.
    Dash,
    /// `?` — Neutral.
    Question,
    /// `~` — SoftFail.
    Tilde,
}

/// A parsed SPF mechanism. String-valued mechanisms keep the (macro-
/// expanded) domain-spec; an empty string means "the current domain".
#[derive(Debug, Eq, PartialEq)]
pub enum SpfMechanism {
    /// `all`.
    All,
    /// `include:<domain>`.
    Include(String),
    /// `a[:domain][/v4-cidr][//v6-cidr]`.
    A(String, DualCidr),
    /// `mx[:domain][/v4-cidr][//v6-cidr]`.
    Mx(String, DualCidr),
    /// `ptr[:domain]`.
    Ptr(String),
    /// `ip4:network`.
    Ip4(Ipv4Net),
    /// `ip6:network`.
    Ip6(Ipv6Net),
    /// `exists:<domain>`.
    Exists(String),
}

impl SpfMechanism {
    /// Returns the mechanism's domain-spec, if it carries one (empty
    /// string means "the current domain").
    pub fn domain_spec(&self) -> Option<String> {
        match &self {
            SpfMechanism::All => None,
            SpfMechanism::Include(s) => Some(s.to_string()),
            SpfMechanism::A(s, _) => Some(s.to_string()),
            SpfMechanism::Mx(s, _) => Some(s.to_string()),
            SpfMechanism::Ptr(s) => Some(s.to_string()),
            SpfMechanism::Ip4(_) => None,
            SpfMechanism::Ip6(_) => None,
            SpfMechanism::Exists(s) => Some(s.to_string()),
        }
    }
}

/// A parsed SPF record: the version and its terms in record order.
#[derive(Debug, Eq, PartialEq)]
pub struct Spf {
    /// The `v=spf1` version token.
    pub version: SpfVersion,
    /// The mechanisms and modifiers, in record order.
    pub terms: Vec<SpfTerm>,
}

/// The record's version token (`"v=spf1"`).
#[derive(Debug, Eq, PartialEq)]
pub struct SpfVersion(pub String);

/// One term of an SPF record: either a mechanism or a modifier.
#[derive(Debug, Eq, PartialEq)]
pub enum SpfTerm {
    /// A mechanism directive (`+mx`, `-all`, ...).
    Directive(SpfDirective),
    /// A modifier (`redirect=`, `exp=`, or unknown name=value).
    Modifier(SpfModifier),
}

/// A mechanism directive: qualifier plus mechanism.
#[derive(Debug, Eq, PartialEq)]
pub struct SpfDirective {
    /// The qualifier (`+`/`-`/`?`/`~`).
    pub qualifier: SpfQualifier,
    /// The mechanism.
    pub mechanism: SpfMechanism,
}

/// A name=value modifier (`redirect=`, `exp=`, or unknown).
#[derive(Debug, Eq, PartialEq)]
pub struct SpfModifier {
    /// The modifier name.
    pub name: String,
    /// The (macro-expanded) value.
    pub value: String,
}

/// The macro-expansion substitutions (RFC 7208 Section 7) available while
/// evaluating one record.
#[derive(Debug, Eq, PartialEq, Default)]
pub struct SpfMacroSubs {
    /// `%{s}` — the sender identity (MAIL FROM or postmaster@HELO).
    pub s: Option<String>,
    /// `%{l}` — the local part of the sender.
    pub l: Option<String>,
    /// `%{o}` — the sender's domain.
    pub o: Option<String>,
    /// `%{d}` — the domain being evaluated.
    pub d: Option<String>,
    /// `%{i}` — the connecting IP.
    pub i: Option<String>,
    /// `%{p}` — the validated domain of the IP. Reverse DNS is not
    /// validated here, so this is always the specified fallback
    /// `"unknown"`.
    pub p: Option<String>,
    /// `%{h}` — the HELO/EHLO name.
    pub h: Option<String>,
    /// `%{c}` — the SMTP client IP (readable form).
    pub c: Option<String>,
    /// `%{r}` — the domain of the host performing the check. Set to the
    /// evaluated domain (the checking host's own name is not known here).
    pub r: Option<String>,
    /// `%{t}` — the current timestamp.
    pub t: Option<String>,
    /// `%{v}` — `"in-addr"` for IPv4, `"ip6"` for IPv6.
    pub v: Option<String>,
}

impl SpfMacroSubs {
    /// Build the substitution set for evaluating `domain` for the
    /// connecting IP `peer`, the identity `sender` (`local@domain`; an
    /// empty local-part becomes `postmaster`) and the client's `helo`
    /// name.
    pub fn new(peer: IpAddr, sender: &String, domain: &String, helo: &Option<String>) -> Self {
        let (local_part, sender_domain) = sender.split_once('@').unzip();
        // RFC 7208 Section 7.3: `t` is seconds since the epoch.
        let timestamp = jiff::Timestamp::now().as_second().to_string();
        let ip_type: &'static str = if peer.is_ipv4() { "in-addr" } else { "ip6" };
        // RFC 7208 Section 7.3: `i` is dotted-quad for IPv4 and
        // dot-separated nibbles for IPv6.
        let ip_macro = match peer {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => v6
                .octets()
                .iter()
                .flat_map(|b| [b >> 4, b & 0x0f])
                .map(|n| format!("{n:x}"))
                .collect::<Vec<_>>()
                .join("."),
        };

        SpfMacroSubs {
            s: Some(sender.to_string()),
            // RFC 7208 Section 4.3: an empty local-part is "postmaster".
            l: local_part.map(|s| {
                if s.is_empty() {
                    "postmaster".to_string()
                } else {
                    s.to_string()
                }
            }),
            o: sender_domain.map(|s| s.to_string()),
            d: Some(domain.to_string()),
            i: Some(ip_macro),
            // RFC 7208 Section 7.3: `p` is not validated here (its use is
            // discouraged); "unknown" is the specified fallback.
            p: Some("unknown".to_string()),
            h: helo.to_owned(),
            c: Some(peer.to_string()),
            r: Some(domain.to_string()),
            t: Some(timestamp),
            v: Some(ip_type.to_string()),
        }
    }
}

/// Whether the TXT string `txt` is an SPF record: it begins with `v=spf1`
/// (ASCII case-insensitive), followed by LWSP (space or tab) or the end of
/// the string (RFC 7208 §4.5). `v=spf10` and `v=spf1-all` are not.
pub fn is_spf_record(txt: &str) -> bool {
    let txt = txt.as_bytes();
    txt.len() >= 6
        && txt[..6].eq_ignore_ascii_case(b"v=spf1")
        && (txt.len() == 6 || matches!(txt[6], b' ' | b'\t'))
}

/// Parse the full SPF record `s` (`v=spf1` plus terms) into its AST,
/// expanding macros with `subs`.
///
/// Terms are separated by spaces (RFC 7208 §4.6.1), and mechanism and
/// modifier names are case-insensitive. `redirect=` and `exp=` may appear
/// at most once each (§6). Other modifiers are kept and ignored.
///
/// # Errors
///
/// A missing `v=spf1`, a duplicate `redirect=`/`exp=`, a macro error, or
/// **any** term that isn't a valid mechanism or modifier; evaluation maps
/// every one to PermError (§4.6). Footgun: never skip a term you can't
/// parse. Dropping it, and everything after it, would lose a trailing
/// `-all` and turn a hard fail into Neutral.
pub fn parse(subs: &SpfMacroSubs, s: &str) -> Result<Spf> {
    let mut terms = s.split_ascii_whitespace();
    let version = match terms.next() {
        Some(v) if v.eq_ignore_ascii_case("v=spf1") => SpfVersion("v=spf1".to_string()),
        _ => return Err(anyhow!("Failed to parse version")),
    };

    let mut parsed: Vec<SpfTerm> = Vec::new();
    let (mut redirects, mut exps) = (0, 0);
    for term in terms {
        if let Some(modifier) = parse_modifier(subs, term)? {
            match modifier.name.as_str() {
                "redirect" => redirects += 1,
                "exp" => exps += 1,
                _ => {}
            }
            if redirects > 1 || exps > 1 {
                return Err(anyhow!("duplicate {} modifier", modifier.name));
            }
            parsed.push(SpfTerm::Modifier(modifier));
        } else {
            parsed.push(SpfTerm::Directive(parse_directive(subs, term)?));
        }
    }

    Ok(Spf {
        version,
        terms: parsed,
    })
}

/// Parse `term` as a `name=value` modifier, expanding macros in the value
/// with `subs`.
///
/// Returns the modifier (name lowercased), or `None` when the term isn't
/// one (its text before the first `=` isn't a modifier name, RFC 7208
/// §12: `ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )`).
///
/// # Errors
///
/// The value's macro-string is invalid.
fn parse_modifier(subs: &SpfMacroSubs, term: &str) -> Result<Option<SpfModifier>> {
    let Some((name, value)) = term.split_once('=') else {
        return Ok(None);
    };
    let is_name = name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !is_name {
        return Ok(None);
    }
    Ok(Some(SpfModifier {
        name: name.to_ascii_lowercase(),
        value: expand_macro_string(subs, &value.to_string())?,
    }))
}

/// Parse `term` as one directive: an optional qualifier (default `+`),
/// then a mechanism whose name is matched case-insensitively, with macros
/// expanded using `subs`.
///
/// # Errors
///
/// An unknown mechanism (including `all` with an argument) or an invalid
/// argument.
fn parse_directive(subs: &SpfMacroSubs, term: &str) -> Result<SpfDirective> {
    let (qualifier, rest) = match term.as_bytes().first() {
        Some(b'+') => (SpfQualifier::Plus, &term[1..]),
        Some(b'-') => (SpfQualifier::Dash, &term[1..]),
        Some(b'?') => (SpfQualifier::Question, &term[1..]),
        Some(b'~') => (SpfQualifier::Tilde, &term[1..]),
        _ => (SpfQualifier::Plus, term),
    };
    // The mechanism name runs up to its argument (`:domain`) or its
    // dual-CIDR suffix (`/24`).
    let split = rest.find([':', '/']).unwrap_or(rest.len());
    let (name, arg) = rest.split_at(split);
    let mechanism = match name.to_ascii_lowercase().as_str() {
        "all" if arg.is_empty() => SpfMechanism::All,
        "include" => SpfMechanism::Include(required_domain(subs, arg)?),
        "exists" => SpfMechanism::Exists(required_domain(subs, arg)?),
        "ptr" => SpfMechanism::Ptr(optional_domain(subs, arg)?),
        "a" => {
            let (domain, cidr) = domain_and_cidr(subs, arg)?;
            SpfMechanism::A(domain, cidr)
        }
        "mx" => {
            let (domain, cidr) = domain_and_cidr(subs, arg)?;
            SpfMechanism::Mx(domain, cidr)
        }
        "ip4" => SpfMechanism::Ip4(parse_ip4(arg)?),
        "ip6" => SpfMechanism::Ip6(parse_ip6(arg)?),
        _ => return Err(anyhow!("unknown SPF mechanism in term {term:?}")),
    };
    Ok(SpfDirective {
        qualifier,
        mechanism,
    })
}

/// Parse `arg` as `":" domain-spec`, required (`include`, `exists`).
///
/// Returns the macro-expanded domain-spec.
///
/// # Errors
///
/// No `:`, an empty spec, a spec containing `/`, or a macro error.
fn required_domain(subs: &SpfMacroSubs, arg: &str) -> Result<String> {
    match arg.strip_prefix(':') {
        Some(spec) if !spec.is_empty() && !spec.contains('/') => {
            expand_macro_string(subs, &spec.to_string())
        }
        _ => Err(anyhow!("mechanism needs \":domain\", got {arg:?}")),
    }
}

/// Parse `arg` as `[ ":" domain-spec ]` (`ptr`); an empty `arg` gives an
/// empty string, meaning the current domain.
///
/// # Errors
///
/// As for [`required_domain`] when `arg` is non-empty.
fn optional_domain(subs: &SpfMacroSubs, arg: &str) -> Result<String> {
    if arg.is_empty() {
        Ok(String::new())
    } else {
        required_domain(subs, arg)
    }
}

/// Parse `arg` as `[ ":" domain-spec ] [ dual-cidr-length ]` (`a`, `mx`;
/// RFC 7208 §5.6). A domain-spec never contains `/`, so the first `/`
/// starts the CIDR.
///
/// Returns the domain-spec (empty for the current domain) and the CIDR.
///
/// # Errors
///
/// An invalid domain-spec or CIDR.
fn domain_and_cidr(subs: &SpfMacroSubs, arg: &str) -> Result<(String, DualCidr)> {
    let (domain_part, cidr_part) = arg.split_at(arg.find('/').unwrap_or(arg.len()));
    let domain = if domain_part.is_empty() {
        String::new()
    } else {
        required_domain(subs, domain_part)?
    };
    Ok((domain, parse_dual_cidr(cidr_part)?))
}

/// Parse `s` as `dual-cidr-length = [ "/" ip4-len ] [ "//" ip6-len ]`,
/// with ip4-len 0–32 and ip6-len 0–128. Empty means /32 and /128.
///
/// # Errors
///
/// Any other form, a non-numeric or over-long length, or one out of
/// range.
fn parse_dual_cidr(s: &str) -> Result<DualCidr> {
    let mut cidr = DualCidr::default();
    if s.is_empty() {
        return Ok(cidr);
    }
    let bad = || anyhow!("invalid dual-cidr-length {s:?}");
    let digits = |d: &str, max: u8| -> Result<u8> {
        if d.is_empty() || !d.bytes().all(|b| b.is_ascii_digit()) || d.len() > 3 {
            return Err(bad());
        }
        let n: u8 = d.parse().map_err(|_| bad())?;
        if n > max {
            return Err(bad());
        }
        Ok(n)
    };
    let rest = s.strip_prefix('/').ok_or_else(bad)?;
    let (v4, v6) = match rest.strip_prefix('/') {
        Some(v6) => (None, Some(v6)),
        None => match rest.split_once("//") {
            Some((v4, v6)) => (Some(v4), Some(v6)),
            None => (Some(rest), None),
        },
    };
    if let Some(v4) = v4 {
        cidr.v4 = digits(v4, 32)?;
    }
    if let Some(v6) = v6 {
        cidr.v6 = digits(v6, 128)?;
    }
    Ok(cidr)
}

/// Parse the `ip4` argument `arg` (`:a.b.c.d` or `:a.b.c.d/prefix`, RFC
/// 7208 §5.6) as a network.
///
/// # Errors
///
/// No leading `:`, an invalid address, or a prefix that is not 0–32.
fn parse_ip4(arg: &str) -> Result<Ipv4Net> {
    let ip = arg
        .strip_prefix(':')
        .ok_or_else(|| anyhow!("Failed to parse Ip4, missing ':'"))?;
    if let Some((addr, prefix)) = ip.split_once('/') {
        let addr: Ipv4Addr = addr.parse()?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| anyhow!("invalid ip4 prefix length"))?;
        if prefix > 32 {
            return Err(anyhow!("ip4 prefix length exceeds 32"));
        }
        return Ok(Ipv4Net::new(addr, prefix)?);
    }
    Ok(Ipv4Net::from(ip.parse::<Ipv4Addr>()?))
}

/// Parse the `ip6` argument `arg` (`:` then an address with an optional
/// `/prefix`) as a network.
///
/// # Errors
///
/// No leading `:`, or an invalid address or prefix.
fn parse_ip6(arg: &str) -> Result<Ipv6Net> {
    let ip = arg
        .strip_prefix(':')
        .ok_or_else(|| anyhow!("Failed to parse Ip6, missing ':'"))?;
    if ip.contains('/') {
        Ok(Ipv6Net::from_str(ip)?)
    } else {
        Ok(Ipv6Net::from(ip.parse::<std::net::Ipv6Addr>()?))
    }
}

/// Expand the RFC 7208 Section 7 macro-string `s` using `subs`.
///
/// ```text
/// macro-string = *( macro-expand / macro-literal )
/// macro-expand = ( "%{" macro-letter transformers *delimiter "}" )
///                / "%%" / "%_" / "%-"
/// transformers = *DIGIT [ "r" ]
/// delimiter    = "." / "-" / "+" / "," / "/" / "_" / "="
/// ```
///
/// A macro value is split on the given delimiters (default `.`),
/// optionally reversed (`r`), cut to its rightmost N parts (digits), and
/// re-joined with `.`. An upper-case macro letter URL-escapes the result.
/// An expanded domain-spec longer than 253 octets loses labels from the
/// left (Section 7.3).
///
/// # Errors
///
/// Any other use of `%`, an unterminated macro, or an invalid macro body
/// (see [`expand_one_macro`]); the caller maps these to PermError.
fn expand_macro_string(subs: &SpfMacroSubs, s: &String) -> Result<String> {
    if memchr::memchr(b'%', s.as_bytes()).is_none() {
        return Ok(s.to_string());
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('_') => out.push(' '),
            Some('-') => out.push_str("%20"),
            Some('{') => {
                let body: String = chars.by_ref().take_while(|&c| c != '}').collect();
                out.push_str(&expand_one_macro(subs, &body)?);
            }
            _ => return Err(anyhow!("invalid macro: '%' must start a macro-expand")),
        }
    }
    // A missing closing brace makes take_while consume to the end; detect
    // it by re-checking the source.
    if s.matches("%{").count() > s.matches('}').count() {
        return Err(anyhow!("unterminated macro"));
    }
    while out.len() > 253 {
        match out.split_once('.') {
            Some((_, rest)) => out = rest.to_string(),
            None => break,
        }
    }
    Ok(out)
}

/// Expand `body`, the inside of one `%{...}` macro (letter, transformers,
/// delimiters), using `subs`. An unset value expands to the empty string.
///
/// # Errors
///
/// An empty body, an unknown macro letter, an invalid delimiter, or a
/// zero (or unparseable) digit transformer.
fn expand_one_macro(subs: &SpfMacroSubs, body: &str) -> Result<String> {
    let mut it = body.chars();
    let letter = it.next().ok_or_else(|| anyhow!("empty macro"))?;
    let value = match letter.to_ascii_lowercase() {
        's' => &subs.s,
        'l' => &subs.l,
        'o' => &subs.o,
        'd' => &subs.d,
        'i' => &subs.i,
        'p' => &subs.p,
        'h' => &subs.h,
        'c' => &subs.c,
        'r' => &subs.r,
        't' => &subs.t,
        'v' => &subs.v,
        other => return Err(anyhow!("unknown macro letter {other:?}")),
    };
    let value = value.as_deref().unwrap_or("");

    let rest: String = it.collect();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let rest = &rest[digits.len()..];
    let (reverse, delimiters) = match rest.strip_prefix(['r', 'R']) {
        Some(d) => (true, d),
        None => (false, rest),
    };
    if !delimiters.chars().all(|c| ".-+,/_=".contains(c)) {
        return Err(anyhow!("invalid macro delimiter in {body:?}"));
    }
    let delimiters = if delimiters.is_empty() {
        "."
    } else {
        delimiters
    };

    let mut parts: Vec<&str> = value.split(|c| delimiters.contains(c)).collect();
    if reverse {
        parts.reverse();
    }
    if !digits.is_empty() {
        let keep: usize = digits.parse().map_err(|_| anyhow!("bad macro digits"))?;
        if keep == 0 {
            return Err(anyhow!("macro transformer digits must be non-zero"));
        }
        if keep < parts.len() {
            parts = parts.split_off(parts.len() - keep);
        }
    }
    let expanded = parts.join(".");

    if letter.is_ascii_uppercase() {
        // RFC 7208 Section 7.3: URL-escape everything outside the
        // unreserved set (RFC 3986).
        Ok(expanded
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect())
    } else {
        Ok(expanded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse() {
        let spf: &'static str =
            "v=spf1 a:127.0.0.1 a include:_foo.test.com redirect=_foo.bar.com +all";
        let subs: SpfMacroSubs = SpfMacroSubs {
            i: Some("test".to_string()),
            ..Default::default()
        };

        let result = parse(&subs, spf).unwrap();

        let expected = Spf {
            version: SpfVersion("v=spf1".to_string()),
            terms: vec![
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::A("127.0.0.1".to_string(), DualCidr::default()),
                }),
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::A("".to_string(), DualCidr::default()),
                }),
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::Include("_foo.test.com".to_string()),
                }),
                SpfTerm::Modifier(SpfModifier {
                    name: "redirect".to_string(),
                    value: "_foo.bar.com".to_string(),
                }),
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::All,
                }),
            ],
        };

        assert_eq!(expected, result);
    }

    #[test]
    fn test_reddit_spf_parse() {
        let spf: &'static str = "v=spf1 include:amazonses.com include:_spf.google.com include:19922862.spf01.hubspotemail.net include:hs.reddit.com include:_spf.salesforce.com ip4:52.50.24.208 ~all";
        let subs: SpfMacroSubs = Default::default();
        let result = parse(&subs, spf).unwrap();

        let expected = Spf {
            version: SpfVersion("v=spf1".to_string()),
            terms: vec![
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::Include("amazonses.com".to_string()),
                }),
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::Include("_spf.google.com".to_string()),
                }),
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::Include("19922862.spf01.hubspotemail.net".to_string()),
                }),
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::Include("hs.reddit.com".to_string()),
                }),
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::Include("_spf.salesforce.com".to_string()),
                }),
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::Ip4(Ipv4Net::from(
                        "52.50.24.208".parse::<Ipv4Addr>().unwrap(),
                    )),
                }),
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Tilde,
                    mechanism: SpfMechanism::All,
                }),
            ],
        };

        assert_eq!(expected, result);
    }

    #[test]
    fn test_expand_macro_str() {
        let s = "foo.%{i}.com".to_string();
        let subs: SpfMacroSubs = SpfMacroSubs {
            i: Some("test".to_string()),
            ..Default::default()
        };

        let expected = "foo.test.com".to_string();
        let result = expand_macro_string(&subs, &s).unwrap();

        assert_eq!(expected, result);
    }

    /// RFC 7208 Section 7 macro expansion. The expected values are the
    /// RFC's own examples (Section 7.4) for
    /// sender strong-bad@email.example.com, IP 192.0.2.3.
    #[test]
    fn macro_expansion_rfc_examples() {
        let subs = SpfMacroSubs::new(
            "192.0.2.3".parse().unwrap(),
            &"strong-bad@email.example.com".to_string(),
            &"email.example.com".to_string(),
            &Some("mx.example.org".to_string()),
        );
        let x = |s: &str| expand_macro_string(&subs, &s.to_string()).unwrap();

        assert_eq!(x("%{s}"), "strong-bad@email.example.com");
        assert_eq!(x("%{o}"), "email.example.com");
        assert_eq!(x("%{d}"), "email.example.com");
        assert_eq!(x("%{d4}"), "email.example.com");
        assert_eq!(x("%{d3}"), "email.example.com");
        assert_eq!(x("%{d2}"), "example.com");
        assert_eq!(x("%{d1}"), "com");
        assert_eq!(x("%{dr}"), "com.example.email");
        assert_eq!(x("%{d2r}"), "example.email");
        assert_eq!(x("%{l}"), "strong-bad");
        assert_eq!(x("%{l-}"), "strong.bad");
        assert_eq!(x("%{lr}"), "strong-bad");
        assert_eq!(x("%{lr-}"), "bad.strong");
        assert_eq!(x("%{l1r-}"), "strong");
        assert_eq!(
            x("%{ir}.%{v}._spf.%{d2}"),
            "3.2.0.192.in-addr._spf.example.com"
        );
        assert_eq!(x("%{lr-}.lp._spf.%{d2}"), "bad.strong.lp._spf.example.com");
        assert_eq!(
            x("%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}"),
            "3.2.0.192.in-addr.strong.lp._spf.example.com"
        );
        assert_eq!(
            x("%{d2}.trusted-domains.example.net"),
            "example.com.trusted-domains.example.net"
        );
        // Literal text around a macro is untouched; only the `%{...}`
        // itself is replaced.
        assert_eq!(
            x("%{i}._spf.mta.salesforce.com"),
            "192.0.2.3._spf.mta.salesforce.com"
        );
        // Escapes and URL-encoding.
        assert_eq!(x("a%%b%_c%-d"), "a%b c%20d");
        assert_eq!(x("%{S}"), "strong-bad%40email.example.com");

        // IPv6 `i` is dot-separated nibbles (RFC 7208 Section 7.4).
        let v6 = SpfMacroSubs::new(
            "2001:db8::cb01".parse().unwrap(),
            &"a@b.example".to_string(),
            &"b.example".to_string(),
            &None,
        );
        assert_eq!(
            expand_macro_string(&v6, &"%{ir}.%{v}._spf.%{d2}".to_string()).unwrap(),
            "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.b.example"
        );

        // Syntax errors are errors (PermError), never a guess.
        for bad in ["%x", "%{q}", "%{d0}", "%{d", "%{d*}", "trailing%"] {
            assert!(
                expand_macro_string(&subs, &bad.to_string()).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    /// `include:` with a macro domain-spec parses and expands.
    #[test]
    fn include_with_macro_parses() {
        let subs = SpfMacroSubs::new(
            "192.0.2.3".parse().unwrap(),
            &"user@example.com".to_string(),
            &"example.com".to_string(),
            &None,
        );
        let spf = parse(&subs, "v=spf1 include:%{d}._spf.example.net -all").unwrap();
        assert_eq!(
            spf.terms,
            vec![
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::Include("example.com._spf.example.net".into()),
                }),
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Dash,
                    mechanism: SpfMechanism::All,
                }),
            ]
        );
    }

    #[test]
    fn test_ipv4net() {
        let ip4s = Ipv4Net::from("10.0.0.25".parse::<Ipv4Addr>().unwrap());
        println!("{:?}", ip4s.hosts());
        println!(
            "{:?}",
            ip4s.contains(&"10.0.0.25".parse::<Ipv4Addr>().unwrap())
        );
    }
}
