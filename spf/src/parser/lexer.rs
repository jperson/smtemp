//! SPF record lexing (logos-based).

use logos::Logos;

/// The SPF record lexer: one token per version, qualifier, mechanism, or
/// modifier; token payloads are the trimmed source slices.
#[derive(Logos, Debug, PartialEq)]
pub enum Token<'source> {
    /// `v=spf1` — the version token.
    #[regex(r"v=spf1\s*", |lex| lex.slice().trim())]
    Version(&'source str),

    /// An optional mechanism qualifier (`+`, `-`, `?`, `~`).
    #[regex(r"[\+\-\?~]?", |lex| lex.slice().trim())]
    Qualifier(&'source str),

    /// `all`.
    #[regex(r"all\s*", |lex| lex.slice().trim())]
    All(&'source str),

    /// `include:<domain>`.
    #[regex(r"include:[\x21-\x7E]*\s*", |lex| lex.slice().trim())]
    Include(&'source str),

    /// `a[:domain-spec]`.
    #[regex(r"a(:|\/)?[^\s]*\s*", |lex| lex.slice().trim())]
    A(&'source str),

    /// `mx[:domain-spec]` (dual-CIDR forms like `mx/24` not yet split
    /// into domain + prefix; the trailing cidr must not reach the
    /// resolver).
    #[regex(r"mx(:[^\s]*)?\s*", |lex| lex.slice().trim())]
    Mx(&'source str),

    /// `ptr[:domain-spec]`.
    #[regex(r"ptr(:?|/?)[^\s]*\s*", |lex| lex.slice().trim())]
    Ptr(&'source str),

    /// `ip4:network[/prefix]`.
    #[regex(r"ip4:[^\s]*\s*", |lex| lex.slice().trim())]
    Ip4(&'source str),

    /// `ip6:network[/prefix]`.
    #[regex(r"ip6:[^\s]*\s*", |lex| lex.slice().trim())]
    Ip6(&'source str),

    /// `exists:domain`.
    #[regex(r"exists:[^\s]*\s*", |lex| lex.slice().trim())]
    Exists(&'source str),

    /// Any name=value modifier (`redirect=`, `exp=`, unknown).
    #[regex(r"[a-zA-Z][a-zA-Z0-9\-_\.]*=[^\s]*\s*", |lex| lex.slice().trim())]
    Modifier(&'source str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lexer() {
        let tokens: Vec<_> =
            Token::lexer("v=spf1 a:127.0.0.1 include:_foo.test.com redirect=_foo.bar.com test=%{s12r,=}.a12. +all")
                .spanned()
                .collect();

        assert_eq!(
            tokens,
            &[
                (Ok(Token::Version("v=spf1")), 0..7),
                (Ok(Token::A("a:127.0.0.1")), 7..19),
                (Ok(Token::Include("include:_foo.test.com")), 19..41),
                (Ok(Token::Modifier("redirect=_foo.bar.com")), 41..63),
                (Ok(Token::Modifier("test=%{s12r,=}.a12.")), 63..83),
                (Ok(Token::Qualifier("+")), 83..84),
                (Ok(Token::All("all")), 84..87),
            ]
        )
    }

    #[test]
    fn test_single_a() {
        let tokens: Vec<_> = Token::lexer("v=spf1 a").spanned().collect();

        assert_eq!(
            tokens,
            &[
                (Ok(Token::Version("v=spf1")), 0..7),
                (Ok(Token::A("a")), 7..8)
            ]
        )
    }

    #[test]
    fn test_single_include() {
        let tokens: Vec<_> = Token::lexer("v=spf1 include:foo.test.com")
            .spanned()
            .collect();

        assert_eq!(
            tokens,
            &[
                (Ok(Token::Version("v=spf1")), 0..7),
                (Ok(Token::Include("include:foo.test.com")), 7..27)
            ]
        )
    }

    #[test]
    fn test_ip4_cidr() {
        let tokens: Vec<_> = Token::lexer("v=spf1 ip4:10.0.0.0/24").spanned().collect();

        assert_eq!(
            tokens,
            &[
                (Ok(Token::Version("v=spf1")), 0..7),
                (Ok(Token::Ip4("ip4:10.0.0.0/24")), 7..22),
            ]
        )
    }

    #[test]
    fn test_reddit_spf() {
        let tokens: Vec<_> = Token::lexer("v=spf1 include:amazonses.com include:_spf.google.com include:19922862.spf01.hubspotemail.net include:hs.reddit.com include:_spf.salesforce.com ip4:52.50.24.208 ~all").spanned().collect();
        assert_eq!(
            tokens,
            &[
                (Ok(Token::Version("v=spf1")), 0..7),
                (Ok(Token::Include("include:amazonses.com")), 7..29),
                (Ok(Token::Include("include:_spf.google.com")), 29..53),
                (
                    Ok(Token::Include("include:19922862.spf01.hubspotemail.net")),
                    53..93
                ),
                (Ok(Token::Include("include:hs.reddit.com")), 93..115),
                (Ok(Token::Include("include:_spf.salesforce.com")), 115..143),
                (Ok(Token::Ip4("ip4:52.50.24.208")), 143..160),
                (Ok(Token::Qualifier("~")), 160..161),
                (Ok(Token::All("all")), 161..164),
            ]
        )
    }
}
