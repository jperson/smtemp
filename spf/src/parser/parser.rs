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
        let timestamp = jiff::Timestamp::now().to_string();
        let ip_type: &'static str = if peer.is_ipv4() { "in-addr" } else { "ip6" };

        SpfMacroSubs {
            s: Some(sender.to_string()),
            l: local_part.map(|s| s.to_string()),
            o: sender_domain.map(|s| s.to_string()),
            d: Some(domain.to_string()),
            i: Some(peer.to_string()),
            p: None,
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

fn expand_macro_string(subs: &SpfMacroSubs, s: &String) -> Result<String> {
    let mut r: Vec<u8> = Vec::new();

    macro_rules! macro_sub {
        ($s:expr) => {{
            match &$s {
                Some(i) => r.extend_from_slice(i.as_bytes()),
                _ => (),
            }
        }};
    }

    if let Some(p) = memchr::memchr(b'%', s.as_bytes()) {
        r.extend_from_slice(&s.as_bytes()[..p]);
        for &c in &s.as_bytes()[p + 1..] {
            if c == b's' && subs.s.is_some() {
                macro_sub!(subs.s);
            } else if c == b'l' && subs.l.is_some() {
                macro_sub!(subs.l);
            } else if c == b'o' && subs.o.is_some() {
                macro_sub!(subs.o);
            } else if c == b'd' && subs.d.is_some() {
                macro_sub!(subs.d);
            } else if c == b'i' && subs.i.is_some() {
                macro_sub!(subs.i);
            } else if c == b'p' && subs.p.is_some() {
                macro_sub!(subs.p);
            } else if c == b'h' && subs.h.is_some() {
                macro_sub!(subs.h);
            } else if c == b'c' && subs.c.is_some() {
                macro_sub!(subs.c);
            } else if c == b'r' && subs.r.is_some() {
                macro_sub!(subs.r);
            } else if c == b't' && subs.t.is_some() {
                macro_sub!(subs.t);
            } else if c == b'v' && subs.v.is_some() {
                macro_sub!(subs.v);
            } else if c == b'{' || c == b'}' {
                continue;
            } else {
                r.push(c);
            }
        }
        String::from_utf8(r).or(Err(anyhow!("Failed to expand macro")))
    } else {
        Ok(s.to_string())
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
