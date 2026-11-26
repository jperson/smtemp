//! Envelope syntax: MAIL FROM and RCPT TO paths and their ESMTP
//! parameters, the HELO identity check, and the character rules for
//! local-parts (which become maildir directory names).

/// Split a MAIL FROM / RCPT TO argument into the address inside the path
/// and the trailing ESMTP parameters (RFC 5321 Section 4.1.2:
/// `Path [SP Mail-parameters]`). The path is the text between `<` and the
/// first `>`; a bare unbracketed address (accepted for leniency) ends at
/// the first whitespace. An empty address is the null sender
/// (`MAIL FROM:<>`).
///
/// Returns `(address, params)`, both trimmed, or `None` for an
/// unterminated `<` or an address containing control characters (a bare
/// CR would otherwise reach the generated `Return-Path:`/`Received:`
/// headers).
pub fn clean_path(raw: &str) -> Option<(&str, &str)> {
    let raw = raw.trim();
    let (addr, params) = match raw.strip_prefix('<') {
        Some(rest) => {
            let close = rest.find('>')?;
            (rest[..close].trim(), rest[close + 1..].trim())
        }
        None => match raw.find(char::is_whitespace) {
            Some(i) => (&raw[..i], raw[i..].trim()),
            None => (raw, ""),
        },
    };
    if addr.bytes().any(|b| b.is_ascii_control()) {
        return None;
    }
    Some((addr, params))
}

/// Returns the value of the `SIZE=` ESMTP parameter (RFC 1870, key
/// matched case-insensitively) in the whitespace-separated `params`, if
/// present and numeric.
pub fn size_param(params: &str) -> Option<u64> {
    params.split_ascii_whitespace().find_map(|p| {
        let (key, value) = p.split_once('=')?;
        key.eq_ignore_ascii_case("SIZE")
            .then(|| value.parse().ok())
            .flatten()
    })
}

/// Returns the domain of the address `addr` (everything after the last
/// `@`, possibly empty), or `None` when it has no `@`.
pub fn path_domain(addr: &str) -> Option<&str> {
    addr.rsplit_once('@').map(|(_, domain)| domain)
}

/// The local-part safety check for mailbox delivery on `addr`. The
/// local-part names a maildir directory, so it must never carry path
/// semantics.
///
/// Returns `Some(reason)` when the address must be refused: the
/// local-part is empty, longer than RFC 5321's 64-octet limit, contains
/// anything outside the mailbox-safe set, or has path-oddities like a
/// leading dot or a `..` run. The safe set is RFC 5321 dot-atom text
/// (`atext` plus `.`) **minus `/`**, the one atext character with path
/// meaning — so ordinary addresses such as `o'brien@` keep working.
/// Quoted local-parts are refused (server policy). Returns `None` when
/// the local-part is safe, and also for an address with no `@` (callers
/// reject those separately).
pub fn unsafe_local_part(addr: &str) -> Option<&'static str> {
    let local = addr.rsplit_once('@')?.0;
    if local.is_empty() {
        return Some("empty local-part");
    }
    if local.len() > 64 {
        return Some("local-part exceeds 64 octets");
    }
    if local.starts_with('.') || local.contains("..") {
        return Some("dot-run in local-part");
    }
    if !local.bytes().all(is_mailbox_safe) {
        return Some("character outside the mailbox-safe set");
    }
    None
}

/// Is `addr` (brackets removed, see [`clean_path`]) an acceptable
/// non-null `MAIL FROM` address: an RFC 5321 `Mailbox` whose domain can
/// be looked up?
///
/// The local-part is a `Dot-string` (atext atoms separated by single
/// dots) or a `Quoted-string` of printable ASCII; the domain follows the
/// [`valid_helo`] domain rules (LDH labels plus `_`, one trailing dot
/// allowed) and must not be an address literal. Everything after the
/// *last* `@` is the SPF identity, so without this check an envelope such
/// as `ceo@victim.example@` or `ceo@victim.example;` would name the
/// victim domain while giving SPF nothing it can query, and skip the
/// SPF Fail rejection (AUDIT_20261126 R2).
pub fn valid_reverse_path(addr: &str) -> bool {
    let Some((local, domain)) = addr.rsplit_once('@') else {
        return false;
    };
    valid_local_part(local) && !domain.starts_with('[') && valid_helo(domain)
}

/// Is `local` an RFC 5321 `Local-part`: a `Dot-string` or a
/// `Quoted-string` (§4.1.2), ASCII only (SMTPUTF8 is not offered)?
fn valid_local_part(local: &str) -> bool {
    if let Some(inner) = local.strip_prefix('"') {
        let Some(inner) = inner.strip_suffix('"') else {
            return false;
        };
        // qtextSMTP (%d32-33 / %d35-91 / %d93-126) or a quoted-pair
        // (`\` followed by %d32-126).
        let mut bytes = inner.bytes();
        while let Some(b) = bytes.next() {
            match b {
                b'\\' => {
                    if !bytes.next().is_some_and(|q| (32..=126).contains(&q)) {
                        return false;
                    }
                }
                32..=33 | 35..=91 | 93..=126 => {}
                _ => return false,
            }
        }
        return true;
    }
    !local.is_empty()
        && local
            .split('.')
            .all(|atom| !atom.is_empty() && atom.bytes().all(|b| is_mailbox_safe(b) || b == b'/'))
}

/// Is `h` an acceptable HELO/EHLO identity?
///
/// RFC 5321 §4.1.1.1: the argument is a `Domain` or an `address-literal`.
/// It is copied into the delivered `Received:` header, so anything else —
/// above all a bare CR or another control character, which could inject
/// a header — is refused before it is stored. The domain form is deliberately
/// a little liberal (underscores, a trailing dot, single-label names such
/// as `localhost`) because misconfigured but legitimate senders use them.
pub fn valid_helo(h: &str) -> bool {
    if h.is_empty() || h.len() > 255 {
        return false;
    }
    if let Some(inner) = h.strip_prefix('[') {
        // address-literal: "[" 1*dcontent "]", dcontent = %d33-90 / %d94-126
        // (covers IPv4, "IPv6:..." and general literals).
        let Some(inner) = inner.strip_suffix(']') else {
            return false;
        };
        return !inner.is_empty() && inner.bytes().all(|b| matches!(b, 33..=90 | 94..=126));
    }
    let name = h.strip_suffix('.').unwrap_or(h);
    !name.is_empty()
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Is byte `b` in the mailbox-safe set: RFC 5321 `atext` plus `.`,
/// excluding `/` (see [`unsafe_local_part`])?
pub fn is_mailbox_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'.' | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_path_strips_brackets_and_space() {
        let addr = |raw| clean_path(raw).map(|(a, _)| a);
        assert_eq!(addr("<sender@example.org>"), Some("sender@example.org"));
        assert_eq!(addr(" <sender@example.org> "), Some("sender@example.org"));
        assert_eq!(addr("sender@example.org"), Some("sender@example.org"));
        // Null sender.
        assert_eq!(addr("<>"), Some(""));
        assert_eq!(addr(""), Some(""));
    }

    /// ESMTP parameters after the path are split off, never left inside
    /// the address; an unterminated path or a control character in the
    /// address is refused.
    #[test]
    fn clean_path_splits_esmtp_parameters() {
        assert_eq!(
            clean_path("<ceo@bank.example> SIZE=1234 BODY=8BITMIME"),
            Some(("ceo@bank.example", "SIZE=1234 BODY=8BITMIME"))
        );
        assert_eq!(clean_path("<> SIZE=1000"), Some(("", "SIZE=1000")));
        assert_eq!(
            clean_path("user@example.org SIZE=10"),
            Some(("user@example.org", "SIZE=10"))
        );
        // Unterminated path, and a bare CR inside the address.
        assert_eq!(clean_path("<user@example.org SIZE=10"), None);
        assert_eq!(clean_path("<a\rX-Injected: yes@b.example>"), None);

        assert_eq!(size_param("SIZE=1234 BODY=8BITMIME"), Some(1234));
        assert_eq!(size_param("body=7bit size=99"), Some(99));
        assert_eq!(size_param("BODY=8BITMIME"), None);
        assert_eq!(size_param(""), None);
    }

    /// Ordinary RFC 5321 local-parts are accepted; anything with path
    /// meaning (or quoting) is not.
    #[test]
    fn local_part_policy() {
        for ok in [
            "o'brien@x.test",
            "info&sales@x.test",
            "a+b=c@x.test",
            "first.last@x.test",
        ] {
            assert_eq!(unsafe_local_part(ok), None, "{ok} must be accepted");
        }
        for bad in [
            "../x@x.test",
            "/abs@x.test",
            "a/b@x.test",
            ".hidden@x.test",
            "a..b@x.test",
            "a\\b@x.test",
            "\"quoted\"@x.test",
        ] {
            assert!(unsafe_local_part(bad).is_some(), "{bad} must be refused");
        }
    }

    /// A MAIL FROM address must be a mailbox whose domain SPF can query
    /// (AUDIT_20261126 R2).
    #[test]
    fn reverse_path_validation() {
        for ok in [
            "ceo@paypal.com",
            "ceo@paypal.com.",
            "first.last+tag@sub.example.org",
            "o'brien@x.test",
            "a/b@x.test",
            "\"john doe\"@x.test",
            "\"a@b\\\"c\"@x.test",
            "bounce@localhost",
        ] {
            assert!(valid_reverse_path(ok), "{ok:?} should be accepted");
        }
        for bad in [
            "ceo@paypal.com@",
            "ceo@paypal.com;",
            "ceo@paypal.com@x",
            "@paypal.com",
            "ceo",
            "ceo@",
            "ceo@paypal..com",
            "ceo@paypal.com..",
            ".ceo@paypal.com",
            "c..eo@paypal.com",
            "ceo.@paypal.com",
            "c eo@paypal.com",
            "\"unterminated@paypal.com",
            "\"bad\\\"@paypal.com",
            "ceo@[192.0.2.1]",
            "@a,@b:ceo@paypal.com",
            "caf\u{e9}@paypal.com",
        ] {
            assert!(!valid_reverse_path(bad), "{bad:?} should be refused");
        }
    }

    #[test]
    fn path_domain_is_after_last_at() {
        assert_eq!(path_domain("sender@example.org"), Some("example.org"));
        assert_eq!(
            path_domain("local@sub.example.org"),
            Some("sub.example.org")
        );
        assert_eq!(path_domain("@example.org"), Some("example.org"));
        assert_eq!(path_domain("no-at-sign"), None);
    }

    /// The HELO identity must be a domain or an address literal; control
    /// characters (a bare CR would inject a `Received:` header line),
    /// whitespace and other junk are refused.
    #[test]
    fn helo_validation() {
        for ok in [
            "mail.example.org",
            "mail.example.org.",
            "localhost",
            "host_name.example",
            "a-b.example",
            "[192.0.2.1]",
            "[IPv6:2001:db8::1]",
        ] {
            assert!(valid_helo(ok), "{ok:?} should be accepted");
        }
        for bad in [
            "",
            "evil.example\rX-Injected: yes",
            "evil.example\nX-Injected: yes",
            "evil.example\x00",
            "two words",
            "a..b",
            ".",
            "[]",
            "[192.0.2.1",
            "[a]b]",
            "[a\\b]",
            "caf\u{e9}.example",
            "x(y).example",
            &format!("{}.example", "a".repeat(64)),
            &"a.".repeat(130),
        ] {
            assert!(!valid_helo(bad), "{bad:?} should be refused");
        }
    }
}
