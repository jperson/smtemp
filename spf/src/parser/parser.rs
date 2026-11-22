use anyhow::{anyhow, Result};
use logos::{Lexer, Logos};
use memchr;

use ipnet::{Ipv4Net, Ipv6Net};
use std::iter::Peekable;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use crate::parser::lexer::Token;

type SpfLexer<'source> = Peekable<Lexer<'source, Token<'source>>>;

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
    /// `a[:domain]`.
    A(String),
    /// `mx[:domain]`.
    Mx(String),
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
    /// The mechanism's domain-spec, if it carries one (empty string means
    /// "the current domain").
    pub fn domain_spec(&self) -> Option<String> {
        match &self {
            SpfMechanism::All => None,
            SpfMechanism::Include(s) => Some(s.to_string()),
            SpfMechanism::A(s) => Some(s.to_string()),
            SpfMechanism::Mx(s) => Some(s.to_string()),
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
    /// `%{p}` — the validated domain of the IP (reverse DNS; currently
    /// never populated).
    pub p: Option<String>,
    /// `%{h}` — the HELO/EHLO name.
    pub h: Option<String>,
    /// `%{c}` — the SMTP client IP (readable form).
    pub c: Option<String>,
    /// `%{r}` — the domain of the host performing the check.
    pub r: Option<String>,
    /// `%{t}` — the current timestamp.
    pub t: Option<String>,
    /// `%{v}` — `"in-addr"` for IPv4, `"ip6"` for IPv6.
    pub v: Option<String>,
}

impl SpfMacroSubs {
    /// Build the substitution set for one evaluation.
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

/// Parse a full SPF record (`v=spf1` plus terms) into its AST, expanding
/// macros with `subs`. Unknown syntax is an `Err` (which evaluation maps
/// to PermError).
pub fn parse(subs: &SpfMacroSubs, s: &str) -> Result<Spf> {
    let mut lex = Token::lexer(s).peekable();

    let version = parse_version(&mut lex)?;

    let mut terms: Vec<SpfTerm> = Vec::new();
    loop {
        if let Ok(d) = parse_directive(subs, &mut lex) {
            terms.push(SpfTerm::Directive(d));
        } else if let Ok(m) = parse_modifier(subs, &mut lex) {
            terms.push(SpfTerm::Modifier(m));
        } else {
            break;
        }
    }

    Ok(Spf { version, terms })
}

fn parse_version(lex: &mut SpfLexer) -> Result<SpfVersion> {
    match lex.next_if(|t| matches!(*t, Ok(Token::Version(_)))) {
        Some(Ok(Token::Version(v))) => Ok(SpfVersion(v.to_owned())),
        _ => Err(anyhow!("Failed to parse version")),
    }
}

fn parse_directive(subs: &SpfMacroSubs, lex: &mut SpfLexer) -> Result<SpfDirective> {
    let qualifier = match lex.next_if(|t| matches!(*t, Ok(Token::Qualifier(_)))) {
        Some(Ok(Token::Qualifier(q))) => match q {
            "+" => SpfQualifier::Plus,
            "-" => SpfQualifier::Dash,
            "?" => SpfQualifier::Question,
            "~" => SpfQualifier::Tilde,
            _ => SpfQualifier::Plus,
        },
        _ => SpfQualifier::Plus,
    };

    match lex.peek() {
        Some(Ok(Token::All(_))) => Ok(SpfDirective {
            qualifier,
            mechanism: parse_all(lex)?,
        }),
        Some(Ok(Token::Include(_))) => Ok(SpfDirective {
            qualifier,
            mechanism: parse_include(subs, lex)?,
        }),
        Some(Ok(Token::A(_))) => Ok(SpfDirective {
            qualifier,
            mechanism: parse_a(subs, lex)?,
        }),
        Some(Ok(Token::Mx(_))) => Ok(SpfDirective {
            qualifier,
            mechanism: parse_mx(subs, lex)?,
        }),
        Some(Ok(Token::Ptr(_))) => Ok(SpfDirective {
            qualifier,
            mechanism: parse_ptr(subs, lex)?,
        }),
        Some(Ok(Token::Ip4(_))) => Ok(SpfDirective {
            qualifier,
            mechanism: parse_ip4(lex)?,
        }),
        Some(Ok(Token::Ip6(_))) => Ok(SpfDirective {
            qualifier,
            mechanism: parse_ip6(lex)?,
        }),
        Some(Ok(Token::Exists(_))) => Ok(SpfDirective {
            qualifier,
            mechanism: parse_exists(subs, lex)?,
        }),

        _ => Err(anyhow!("Failed to parse directive")),
    }
}

fn parse_modifier(subs: &SpfMacroSubs, lex: &mut SpfLexer) -> Result<SpfModifier> {
    match lex.next_if(|t| matches!(*t, Ok(Token::Modifier(_)))) {
        Some(Ok(Token::Modifier(m))) => {
            let (name, value) = m
                .split_once("=")
                .ok_or(anyhow!("Failed to parse modifier"))?;

            let value = &expand_macro_string(subs, &value.to_string())?;
            Ok(SpfModifier {
                name: name.to_string(),
                value: value.to_string(),
            })
        }
        _ => Err(anyhow!("Failed to parse modifier")),
    }
}

fn parse_all(lex: &mut SpfLexer) -> Result<SpfMechanism> {
    if let Some(Ok(Token::All(_))) = lex.next() {
        Ok(SpfMechanism::All)
    } else {
        Err(anyhow!("Failed to parse All directive"))
    }
}

fn parse_include(subs: &SpfMacroSubs, lex: &mut SpfLexer) -> Result<SpfMechanism> {
    if let Some(Ok(Token::Include(s))) = lex.next() {
        let (_, value) = s
            .split_once(":")
            .ok_or(anyhow!("Failed to parse include, missing ':'"))?;
        let ds = expand_macro_string(subs, &value.to_string())?;
        Ok(SpfMechanism::Include(ds.to_owned()))
    } else {
        Err(anyhow!("Failed to parse Include directive"))
    }
}

fn parse_a(subs: &SpfMacroSubs, lex: &mut SpfLexer) -> Result<SpfMechanism> {
    if let Some(Ok(Token::A(s))) = lex.next() {
        let mut a: String = "".to_string();
        if s.contains(":") {
            let (_, ax) = s
                .split_once(":")
                .ok_or(anyhow!("Failed to parse A directive"))?;
            a = expand_macro_string(subs, &ax.to_string())?;
        }
        Ok(SpfMechanism::A(a.to_string()))
    } else {
        Err(anyhow!("Failed to parse Include directive"))
    }
}

fn parse_mx(subs: &SpfMacroSubs, lex: &mut SpfLexer) -> Result<SpfMechanism> {
    if let Some(Ok(Token::Mx(s))) = lex.next() {
        let mut value: String = "".to_string();
        if s.contains(":") {
            let (_, vx) = s
                .split_once(":")
                .ok_or(anyhow!("Failed to parse MX directive"))?;
            value = expand_macro_string(subs, &vx.to_string())?;
        }
        Ok(SpfMechanism::Mx(value.to_string()))
    } else {
        Err(anyhow!("Failed to parse Include directive"))
    }
}

fn parse_ptr(subs: &SpfMacroSubs, lex: &mut SpfLexer) -> Result<SpfMechanism> {
    if let Some(Ok(Token::Ptr(s))) = lex.next() {
        let mut value: String = "".to_string();
        if s.contains(":") {
            let (_, px) = s
                .split_once(":")
                .ok_or(anyhow!("Failed to parse PTR directive"))?;
            value = expand_macro_string(subs, &px.to_string())?;
        }
        Ok(SpfMechanism::Ptr(value.to_string()))
    } else {
        Err(anyhow!("Failed to parse Include directive"))
    }
}

fn parse_ip4(lex: &mut SpfLexer) -> Result<SpfMechanism> {
    if let Some(Ok(Token::Ip4(s))) = lex.next() {
        if let Some((_, ip)) = s.split_once(":") {
            // "a.b.c.d" or "a.b.c.d/prefix-length" (RFC 7208 Section 5.1).
            if let Some((addr, prefix)) = ip.split_once('/') {
                let addr: Ipv4Addr = addr.parse()?;
                let prefix: u8 = prefix
                    .parse()
                    .map_err(|_| anyhow!("invalid ip4 prefix length"))?;
                if prefix > 32 {
                    return Err(anyhow!("ip4 prefix length exceeds 32"));
                }
                return Ok(SpfMechanism::Ip4(Ipv4Net::new(addr, prefix)?));
            }
            return Ok(SpfMechanism::Ip4(Ipv4Net::from(ip.parse::<Ipv4Addr>()?)));
        }
        Err(anyhow!("Failed to parse Ip4, missing ':'"))
    } else {
        Err(anyhow!("Failed to parse Ip4 token"))
    }
}

fn parse_ip6(lex: &mut SpfLexer) -> Result<SpfMechanism> {
    if let Some(Ok(Token::Ip6(s))) = lex.next() {
        if let Some((_, ip)) = s.split_once(":") {
            return Ok(SpfMechanism::Ip6(Ipv6Net::from_str(ip)?));
        }
        Err(anyhow!("Failed to parse Ip6, missing ':'"))
    } else {
        Err(anyhow!("Failed to parse Ip6 token"))
    }
}

fn parse_exists(subs: &SpfMacroSubs, lex: &mut SpfLexer) -> Result<SpfMechanism> {
    if let Some(Ok(Token::Exists(s))) = lex.next() {
        let (_, value) = s
            .split_once(":")
            .ok_or(anyhow!("Failed to parse include, missing ':'"))?;
        let value = expand_macro_string(subs, &value.to_string())?;
        Ok(SpfMechanism::Exists(value.to_string()))
    } else {
        Err(anyhow!("Failed to parse Include directive"))
    }
}

/// Expand an RFC 7208 Section 7 macro-string.
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
/// Any other use of `%` is a syntax error (the caller maps it to
/// PermError). An expanded domain-spec longer than 253 octets loses
/// labels from the left (Section 7.3).
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

/// Expand the inside of one `%{...}` macro (letter, transformers,
/// delimiters).
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
                    mechanism: SpfMechanism::A("127.0.0.1".to_string()),
                }),
                SpfTerm::Directive(SpfDirective {
                    qualifier: SpfQualifier::Plus,
                    mechanism: SpfMechanism::A("".to_string()),
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

    /// H2 (security report): RFC 7208 Section 7 macro expansion. The
    /// expected values are the RFC's own examples (Section 7.4) for
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
        // Literal text with no macro letters is untouched (the old
        // implementation replaced every letter after the first '%').
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

    /// H2: `include:` with a macro domain-spec lexes and expands (the
    /// lexer used to exclude `%`, silently dropping such terms).
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
