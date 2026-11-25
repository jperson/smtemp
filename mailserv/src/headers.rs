//! The raw header checks run at end of data: finding the single `From:`
//! header, its authors and domain, and refusing header blocks that
//! contain a bare CR.

/// The outcome of scanning a raw message for its `From:` header. The
/// scan tolerates bytes and headers the strict `mailparse` grammar
/// rejects, so a message that fails to parse still gets a DMARC verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FromHeader {
    /// Exactly one `From:` header, with its domain extracted.
    Parsed(String),
    /// No `From:` header at all.
    None,
    /// More than one `From:` header (RFC 7489 Section 6.6.1: reject).
    Multiple,
    /// A `From:` header exists but no domain could be extracted.
    Unparseable,
}

/// Extract the From-domain from the raw header bytes.
///
/// Works on bytes, not UTF-8 (real 8-bit mail exists), and never fails:
/// every outcome is one of the [`FromHeader`] variants. Only the header
/// block is scanned (up to the first empty line), the `From` header name
/// is matched case-insensitively (including the obsolete `From :` form
/// with whitespace before the colon, RFC 5322 Section 4.5.3), folded
/// continuation lines are unfolded into the value, and the value is read
/// as an RFC 5322 mailbox-list (see [`from_domain_of`]).
pub(crate) fn from_header_domain(raw: &[u8]) -> FromHeader {
    match single_from_value(raw) {
        Ok(value) => from_domain_of(&value),
        Err(problem) => problem,
    }
}

/// Find the message's one `From:` header in the raw message `raw`.
///
/// Returns its unfolded, trimmed value, or the problem as `Err`
/// ([`FromHeader::None`] / [`FromHeader::Multiple`]). The scan rules are
/// those of [`from_header_domain`].
pub(crate) fn single_from_value(raw: &[u8]) -> Result<Vec<u8>, FromHeader> {
    // The header block ends at the first empty line.
    let end = header_block_end(raw);
    let header_block = &raw[..end];

    let mut from_values: Vec<Vec<u8>> = Vec::new();
    // Whether the most recent header line was a From header (so its
    // continuation lines belong to the last entry of `from_values`).
    let mut in_from = false;
    for line in split_header_lines(header_block) {
        if line.starts_with(b" ") || line.starts_with(b"\t") {
            // Folded continuation of the previous header (RFC 5322
            // Section 2.2.3: unfolding removes only the line break).
            if in_from {
                if let Some(value) = from_values.last_mut() {
                    value.push(b' ');
                    value.extend_from_slice(trim_header_fws(line));
                }
            }
            continue;
        }
        match from_header_value(line) {
            Some(value) => {
                from_values.push(trim_header_fws(value).to_vec());
                in_from = true;
            }
            None => in_from = false,
        }
    }

    match from_values.len() {
        0 => Err(FromHeader::None),
        1 => Ok(from_values.swap_remove(0)),
        _ => Err(FromHeader::Multiple),
    }
}

/// Whether the header block of `raw` (up to the first empty line)
/// contains a CR that is not part of a CRLF.
pub(crate) fn header_has_bare_cr(raw: &[u8]) -> bool {
    let block = &raw[..header_block_end(raw)];
    block
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'\r' && block.get(i + 1) != Some(&b'\n'))
}

/// Returns the offset of the first empty line (CRLF or bare LF) in the
/// raw message `raw` — the header block's end — or `raw.len()` when
/// there is none.
pub(crate) fn header_block_end(raw: &[u8]) -> usize {
    let mut i = 0;
    while i < raw.len() {
        let line_end = raw[i..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(raw.len(), |p| i + p);
        let content_len = if line_end > i && raw[line_end - 1] == b'\r' {
            line_end - 1 - i
        } else {
            line_end - i
        };
        if content_len == 0 {
            return i; // empty line: headers are over
        }
        i = line_end + 1;
    }
    raw.len()
}

/// If header `line` is a `From` header, returns its value (everything
/// after the colon, untrimmed); otherwise `None`. The name is matched case-insensitively and may be
/// followed by whitespace before the colon (obsolete syntax that mail
/// clients still display, so it must count as a From header).
pub(crate) fn from_header_value(line: &[u8]) -> Option<&[u8]> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = &line[..colon];
    let name_end = name
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(0, |p| p + 1);
    name[..name_end]
        .eq_ignore_ascii_case(b"From")
        .then(|| &line[colon + 1..])
}

/// Split header `block` into lines, tolerating CRLF and bare LF (the
/// raw bytes come straight off the wire; bare LF was already ruled out
/// as a DATA terminator but tolerance here costs nothing).
///
/// Returns the lines without their line endings; a final line without a
/// terminator is included.
pub(crate) fn split_header_lines(block: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut rest = block;
    while let Some(pos) = rest.iter().position(|&b| b == b'\n') {
        let (line, next) = rest.split_at(pos);
        lines.push(if line.ends_with(b"\r") {
            &line[..line.len() - 1]
        } else {
            line
        });
        rest = &next[1..];
    }
    if !rest.is_empty() {
        lines.push(rest);
    }
    lines
}

/// Returns header `value` with folding whitespace (SP, HTAB, CR, LF)
/// trimmed from both ends.
pub(crate) fn trim_header_fws(value: &[u8]) -> &[u8] {
    let is_fws = |b: &u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
    let start = value.iter().position(|b| !is_fws(b)).unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !is_fws(b))
        .map_or(start, |p| p + 1);
    &value[start..end]
}

/// Classify the author domain of From header `value`, read as an RFC 5322
/// mailbox-list (`mailbox *("," mailbox)`, each mailbox either
/// `addr-spec` or `[display-name] <addr-spec>`).
///
/// Comments (`(...)`, nestable) are removed and quoted strings are
/// opaque, so an `@` inside either can never pick the domain — the
/// domain is the one a mail client displays. Every mailbox in the list
/// must yield a plausible domain (`Unparseable` otherwise), and a list
/// whose mailboxes name more than one domain is `Multiple`: RFC 7489
/// Section 6.6.1 lets the receiver reject rather than pick one author.
pub(crate) fn from_domain_of(value: &[u8]) -> FromHeader {
    let Some(authors) = from_authors(value) else {
        return FromHeader::Unparseable;
    };
    let mut domain: Option<String> = None;
    for (_, found) in authors {
        match &domain {
            Some(d) if *d != found => return FromHeader::Multiple,
            _ => domain = Some(found),
        }
    }
    match domain {
        Some(d) => FromHeader::Parsed(d),
        None => FromHeader::Unparseable,
    }
}

/// Every author `(local-part, domain)` of a From header value, read as an
/// RFC 5322 mailbox-list with the rules of [`from_domain_of`]. `None` when
/// any mailbox is unparseable or there are none.
///
/// The local-part comes from the cleaned value: comments are removed and
/// quoted-string contents are blanked, so a quoted local-part never matches
/// a real address. For the authenticated-sender check that is fail-closed:
/// such an author is only accepted under a whole-domain grant.
pub(crate) fn from_authors(value: &[u8]) -> Option<Vec<(String, String)>> {
    // Pass 1: drop comments, blank out quoted-string contents.
    let mut clean: Vec<u8> = Vec::with_capacity(value.len());
    let (mut depth, mut in_quote, mut escaped) = (0usize, false, false);
    for &b in value {
        if escaped {
            escaped = false;
            if in_quote {
                clean.push(b'x');
            }
            continue;
        }
        match b {
            b'\\' if in_quote || depth > 0 => escaped = true,
            b'"' if depth == 0 => {
                in_quote = !in_quote;
                clean.push(b'"');
            }
            _ if in_quote => clean.push(b'x'),
            b'(' => depth += 1,
            b')' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    clean.push(b' ');
                }
            }
            _ if depth > 0 => {}
            _ => clean.push(b),
        }
    }
    if depth > 0 || in_quote || escaped {
        return None;
    }

    // Pass 2: split into mailboxes at top-level commas (commas inside
    // `<...>` belong to an obsolete route).
    let mut mailboxes: Vec<&[u8]> = Vec::new();
    let (mut angle, mut start) = (0usize, 0usize);
    for (i, &b) in clean.iter().enumerate() {
        match b {
            b'<' => angle += 1,
            b'>' => angle = angle.saturating_sub(1),
            b',' if angle == 0 => {
                mailboxes.push(&clean[start..i]);
                start = i + 1;
            }
            // From is a mailbox-list: group syntax is not allowed.
            b':' | b';' if angle == 0 => return None,
            _ => {}
        }
    }
    mailboxes.push(&clean[start..]);

    let mut authors = Vec::new();
    for mailbox in mailboxes {
        let mailbox = trim_header_fws(mailbox);
        if mailbox.is_empty() {
            continue; // obs-mbox-list permits empty elements
        }
        authors.push(mailbox_address(mailbox)?);
    }
    (!authors.is_empty()).then_some(authors)
}

/// The `(local-part, domain)` of one cleaned mailbox (comments removed,
/// quoted strings blanked): the addr-spec inside `<...>` when present,
/// otherwise the whole mailbox. Returns `None` unless the local-part is
/// non-empty and the domain is plausible. The domain is lowercased.
pub(crate) fn mailbox_address(mailbox: &[u8]) -> Option<(String, String)> {
    let addr = match mailbox.iter().position(|&b| b == b'<') {
        Some(open) => {
            let rest = &mailbox[open + 1..];
            let close = rest.iter().position(|&b| b == b'>')?;
            if !trim_header_fws(&rest[close + 1..]).is_empty() {
                return None; // trailing junk after the angle-addr
            }
            let inner = &rest[..close];
            // Obsolete route (`@a,@b:addr`): the address follows the ':'.
            match inner.iter().rposition(|&b| b == b':') {
                Some(c) => &inner[c + 1..],
                None => inner,
            }
        }
        None => mailbox,
    };
    let addr = trim_header_fws(addr);
    let at = addr.iter().rposition(|&b| b == b'@')?;
    let local = trim_header_fws(&addr[..at]);
    if local.is_empty() {
        return None; // empty local-part
    }
    let domain = trim_header_fws(&addr[at + 1..]);
    // Strip a trailing dot (fully-qualified form).
    let domain = domain.strip_suffix(b".").unwrap_or(domain);
    if domain.is_empty()
        || !domain
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some((
        String::from_utf8_lossy(local).into_owned(),
        String::from_utf8_lossy(domain).to_ascii_lowercase(),
    ))
}

/// The header names a forged copy of which is removed from incoming mail:
/// our own verdict headers (see [`strip_forged_verdicts`]).
const OUR_VERDICT_HEADERS: [&[u8]; 2] = [b"authentication-results", b"x-display-name-warning"];

/// Remove from the header block of `raw` the verdict headers a sender
/// could forge to look like ours: any `Authentication-Results:` whose
/// authserv-id is `authserv_id` (RFC 8601 §5: an MTA removes those before
/// adding its own), and any `X-Display-Name-Warning:` (only this server
/// adds that). Other headers, the body and line endings are kept
/// byte-for-byte.
///
/// Returns the message without those fields (a copy of `raw` when there
/// were none).
pub(crate) fn strip_forged_verdicts(raw: &[u8], authserv_id: &str) -> Vec<u8> {
    let end = header_block_end(raw);
    let mut out = Vec::with_capacity(raw.len());
    // Each header field is its first line plus any continuation lines
    // (starting with a space or tab); `dropping` says whether the current
    // field is being removed.
    let mut dropping = false;
    let mut i = 0;
    while i < end {
        let line_end = raw[i..end]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(end, |p| i + p + 1);
        let line = &raw[i..line_end];
        if !line.starts_with(b" ") && !line.starts_with(b"\t") {
            dropping = is_forged_verdict(raw, i, end, authserv_id);
        }
        if !dropping {
            out.extend_from_slice(line);
        }
        i = line_end;
    }
    out.extend_from_slice(&raw[end..]);
    out
}

/// Whether the header field starting at `start` (in the header block
/// ending at `end` of `raw`) is one of [`OUR_VERDICT_HEADERS`] that
/// [`strip_forged_verdicts`] removes.
fn is_forged_verdict(raw: &[u8], start: usize, end: usize, authserv_id: &str) -> bool {
    let line = &raw[start..end];
    let first_line = line.split(|&b| b == b'\n').next().unwrap_or_default();
    let Some(colon) = first_line.iter().position(|&b| b == b':') else {
        return false;
    };
    let name = trim_header_fws(&line[..colon]).to_ascii_lowercase();
    if !OUR_VERDICT_HEADERS.contains(&name.as_slice()) {
        return false;
    }
    if name.as_slice() == b"x-display-name-warning" {
        return true;
    }
    // The unfolded value: the rest of this line and its continuations.
    let mut value = Vec::new();
    for (n, l) in split_header_lines(&line[colon + 1..])
        .into_iter()
        .enumerate()
    {
        if n > 0 && !l.starts_with(b" ") && !l.starts_with(b"\t") {
            break;
        }
        value.push(b' ');
        value.extend_from_slice(l);
    }
    auth_results_id(&value).is_some_and(|id| {
        id.trim_end_matches('.')
            .eq_ignore_ascii_case(authserv_id.trim_end_matches('.'))
    })
}

/// Returns the authserv-id of an `Authentication-Results:` value (RFC 8601
/// §2.2): its first token, after any comments, up to whitespace or `;`.
/// `None` for an empty value.
fn auth_results_id(value: &[u8]) -> Option<String> {
    let mut depth = 0usize;
    let mut token = Vec::new();
    for &b in value {
        match b {
            b'(' => depth += 1,
            b')' if depth > 0 => depth -= 1,
            _ if depth > 0 => {}
            b' ' | b'\t' | b'\r' | b'\n' if token.is_empty() => {}
            b' ' | b'\t' | b'\r' | b'\n' | b';' => break,
            _ => token.push(b),
        }
        if depth == 0 && b == b';' {
            break;
        }
    }
    (!token.is_empty()).then(|| String::from_utf8_lossy(&token).into_owned())
}

/// Returns the domains that the From value `from_value` names in display
/// names or comments but that belong to none of its `authors` (from
/// [`from_authors`]), compared by organizational domain: what a reader
/// could take for the sender when it isn't, as in `"ceo@victim.example"
/// <x@attacker.example>`. Sorted and deduplicated.
///
/// RFC 2047 encoded-words (`=?utf-8?B?...?=`) are decoded first, since
/// mail clients display them decoded. An address in a different
/// organization is common in legitimate list mail too (`"alice@example.com
/// via Team" <team@lists.example>`), so this is a warning, not a refusal.
pub(crate) fn display_name_claims(from_value: &[u8], authors: &[(String, String)]) -> Vec<String> {
    let org = |d: &str| dmarc::psl::organizational_domain(d).unwrap_or_else(|| d.to_string());
    let author_orgs: Vec<String> = authors.iter().map(|(_, d)| org(d)).collect();
    let mut claims: Vec<String> = address_domains(&decode_encoded_words(from_value))
        .into_iter()
        .filter(|d| !author_orgs.contains(&org(d)))
        .collect();
    claims.sort();
    claims.dedup();
    claims
}

/// Returns the domain of every `local@domain` in `text` (lowercased, a
/// trailing dot removed): an `@` with a non-space character before it and
/// a domain of letters, digits, `-` and `.` (with at least one dot) after.
fn address_domains(text: &[u8]) -> Vec<String> {
    let mut domains = Vec::new();
    for (at, _) in text.iter().enumerate().filter(|(_, &b)| b == b'@') {
        let before_ok = at > 0 && !text[at - 1].is_ascii_whitespace() && text[at - 1] != b'<';
        let domain: Vec<u8> = text[at + 1..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
            .copied()
            .collect();
        let domain = String::from_utf8_lossy(&domain)
            .trim_matches('.')
            .to_ascii_lowercase();
        if before_ok && domain.contains('.') {
            domains.push(domain);
        }
    }
    domains
}

/// Decode the RFC 2047 encoded-words in `value` (`=?charset?B|Q?text?=`)
/// to their raw bytes, whatever the charset (only ASCII is looked at
/// afterwards, and every common charset is an ASCII superset). Anything
/// that isn't a well-formed encoded-word is kept as it is.
fn decode_encoded_words(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut i = 0;
    while i < value.len() {
        if value[i..].starts_with(b"=?") {
            if let Some((decoded, used)) = decode_one_word(&value[i..]) {
                out.extend_from_slice(&decoded);
                i += used;
                continue;
            }
        }
        out.push(value[i]);
        i += 1;
    }
    out
}

/// Decode the encoded-word at the start of `word`.
///
/// Returns the decoded bytes and the length of the encoded-word, or
/// `None` when it isn't one.
fn decode_one_word(word: &[u8]) -> Option<(Vec<u8>, usize)> {
    // =?charset?enc?text?=
    let rest = &word[2..];
    let q1 = rest.iter().position(|&b| b == b'?')?;
    let enc = *rest.get(q1 + 1)?;
    if rest.get(q1 + 2) != Some(&b'?') {
        return None;
    }
    let text_start = q1 + 3;
    let text_len = rest[text_start..].windows(2).position(|w| w == b"?=")?;
    let text = &rest[text_start..text_start + text_len];
    let used = 2 + text_start + text_len + 2;
    let decoded = match enc.to_ascii_uppercase() {
        b'B' => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .ok()?
        }
        b'Q' => {
            let mut bytes = Vec::with_capacity(text.len());
            let mut j = 0;
            while j < text.len() {
                match text[j] {
                    b'_' => bytes.push(b' '),
                    // `=XX`: a malformed escape makes the whole word not
                    // an encoded-word, kept as it is.
                    b'=' => {
                        let hex = std::str::from_utf8(text.get(j + 1..j + 3)?).ok()?;
                        bytes.push(u8::from_str_radix(hex, 16).ok()?);
                        j += 2;
                    }
                    b => bytes.push(b),
                }
                j += 1;
            }
            bytes
        }
        _ => return None,
    };
    Some((decoded, used))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The From scanner reads an RFC 5322 mailbox-list. Folded values are unfolded, comments and quoted
    /// strings never contribute an `@`, the obsolete `From :` spelling
    /// counts as a From header, and several author domains are refused.
    #[test]
    fn from_header_scanner() {
        let scan = |headers: &str| from_header_domain(format!("{headers}\r\nbody\r\n").as_bytes());
        let parsed = |d: &str| FromHeader::Parsed(d.to_string());

        // Simple and display-name forms.
        assert_eq!(scan("From: a@Example.ORG\r\n"), parsed("example.org"));
        assert_eq!(
            scan("From: \"Doe, John\" <j@example.org>\r\n"),
            parsed("example.org")
        );
        // A folded From keeps its continuation lines.
        assert_eq!(
            scan("From: \"A Rather Long Display Name\"\r\n <news@example.net>\r\nSubject: x\r\n"),
            parsed("example.net")
        );
        // 8-bit display name (not UTF-8) is fine.
        assert_eq!(
            from_header_domain(b"From: \xe9t\xe9 <a@example.org>\r\n\r\nbody\r\n"),
            parsed("example.org")
        );
        // Quoted local-part containing '@'.
        assert_eq!(scan("From: \"a@b\"@example.org\r\n"), parsed("example.org"));

        // An '@' inside a comment or quoted string never picks the domain.
        assert_eq!(
            scan("From: ceo@paypal.com (@attacker.example )\r\n"),
            parsed("paypal.com")
        );
        assert_eq!(
            scan("From: \"x@attacker.example\" <ceo@paypal.com>\r\n"),
            parsed("paypal.com")
        );
        // Several author domains are refused; one domain twice is fine.
        assert_eq!(
            scan("From: ceo@paypal.com, x@attacker.example\r\n"),
            FromHeader::Multiple
        );
        assert_eq!(
            scan("From: a@example.org, b@example.org\r\n"),
            parsed("example.org")
        );
        // `From :` (obsolete spacing) is a From header too.
        assert_eq!(
            scan("From : ceo@paypal.com\r\nFrom: x@attacker.example\r\n"),
            FromHeader::Multiple
        );
        // Missing, duplicate and unparseable From headers.
        assert_eq!(scan("Subject: none\r\n"), FromHeader::None);
        assert_eq!(
            scan("From: a@example.org\r\nfrom: b@example.org\r\n"),
            FromHeader::Multiple
        );
        assert_eq!(scan("From: no-address-here\r\n"), FromHeader::Unparseable);
        assert_eq!(
            scan("From: a@example.org (unclosed\r\n"),
            FromHeader::Unparseable
        );
        assert_eq!(
            scan("From: group: a@example.org;\r\n"),
            FromHeader::Unparseable
        );
        // A From line in the body is not a header.
        assert_eq!(
            from_header_domain(b"Subject: x\r\n\r\nFrom: a@example.org\r\n"),
            FromHeader::None
        );
    }

    /// [`from_authors`] on a string `value`.
    fn authors(value: &str) -> Option<Vec<(String, String)>> {
        from_authors(value.as_bytes())
    }

    /// The author addresses are the ones a mail client displays: comments
    /// and display names never supply them, every mailbox in the list is
    /// returned, and groups are refused.
    #[test]
    fn from_authors_extracts_displayed_addresses() {
        let own = |l: &str, d: &str| (l.to_string(), d.to_string());
        assert_eq!(
            authors("Alice <Alice@Example.ORG.>"),
            Some(vec![own("Alice", "example.org")])
        );
        assert_eq!(
            authors("\"ceo@victim.example\" (ceo@victim.example) <a@b.example>"),
            Some(vec![own("a", "b.example")])
        );
        assert_eq!(
            authors("a@b.example, Mallory <m@evil.example>"),
            Some(vec![own("a", "b.example"), own("m", "evil.example")])
        );
        // A quoted local-part is blanked, so it can't match an exact grant.
        assert_eq!(
            authors("\"alice\"@b.example"),
            Some(vec![own("\"xxxxx\"", "b.example")])
        );
        assert_eq!(authors("undisclosed: a@b.example;"), None);
        assert_eq!(authors("no address here"), None);
        assert_eq!(authors(""), None);
    }

    /// The header-smuggling shape (a bare CR hiding a second `From:`) and
    /// its variants are detected; CRLF, bare LF, and CRs in the body are not.
    #[test]
    fn bare_cr_in_header_block_is_detected() {
        for bad in [
            &b"Subject: x\rFrom: CEO <ceo@victim.example>\r\nFrom: a@evil.example\r\n\r\nbody"[..],
            b"From: a@evil.example\rFrom: ceo@victim.example\r\n\r\nbody",
            b"X-A: 1\r\r\nFrom: a@b.example\r\n\r\nbody",
            b"From: a@b.example\r\n\tfolded\rFrom: c@d.example\r\n\r\nbody",
        ] {
            assert!(
                header_has_bare_cr(bad),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        for ok in [
            &b"From: a@b.example\r\nSubject: x\r\n\r\nbody\rwith bare CR\r\n"[..],
            b"From: a@b.example\nSubject: x\n\nbody\n",
            b"From: a@b.example\r\n\r\n",
        ] {
            assert!(!header_has_bare_cr(ok), "{:?}", String::from_utf8_lossy(ok));
        }
    }
    /// Forged verdict headers are removed: an `Authentication-Results:`
    /// claiming our authserv-id (case-insensitively, after a comment,
    /// folded over lines), and any `X-Display-Name-Warning:`. Results from
    /// other servers, `ARC-Authentication-Results:`, the body and the line
    /// endings are kept exactly.
    #[test]
    fn forged_verdicts_are_stripped() {
        let raw = b"Received: from x\r\n\
Authentication-Results: MX.Example.ORG;\r\n\tspf=pass smtp.mailfrom=victim.example\r\n\
Authentication-Results: other.example; dkim=pass\r\n\
Authentication-Results: (forged) mx.example.org.; dmarc=pass\n\
ARC-Authentication-Results: i=1; mx.example.org; spf=pass\r\n\
X-Display-Name-Warning: none here\r\n\
Subject: hi\r\n\
\r\n\
Authentication-Results: mx.example.org; body text stays\r\n";
        let out = strip_forged_verdicts(raw, "mx.example.org");
        let expected = b"Received: from x\r\n\
Authentication-Results: other.example; dkim=pass\r\n\
ARC-Authentication-Results: i=1; mx.example.org; spf=pass\r\n\
Subject: hi\r\n\
\r\n\
Authentication-Results: mx.example.org; body text stays\r\n";
        assert_eq!(
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(expected)
        );
        let clean = b"Subject: hi\r\n\r\nbody\r\n";
        assert_eq!(strip_forged_verdicts(clean, "mx.example.org"), clean);
    }

    /// A display name (or comment) naming an address in another
    /// organization is reported, including when hidden in an RFC 2047
    /// encoded-word; the same organization, or no address at all, isn't.
    #[test]
    fn display_name_claims_find_other_organizations() {
        let claims = |value: &str| {
            let authors = from_authors(value.as_bytes()).unwrap();
            display_name_claims(value.as_bytes(), &authors)
        };
        assert_eq!(
            claims("\"ceo@victim.example\" <x@attacker.example>"),
            ["victim.example"]
        );
        assert_eq!(
            claims("x@attacker.example (CEO <ceo@victim.example>)"),
            ["victim.example"]
        );
        // Encoded-words, as a mail client would display them.
        assert_eq!(
            claims("=?utf-8?B?Y2VvQHZpY3RpbS5leGFtcGxl?= <x@attacker.example>"),
            ["victim.example"]
        );
        assert_eq!(
            claims("=?iso-8859-1?Q?ceo=40victim=2Eexample?= <x@attacker.example>"),
            ["victim.example"]
        );
        // List software: tagged, not refused.
        assert_eq!(
            claims("\"'alice@example.com' via Team\" <team@googlegroups.com>"),
            ["example.com"]
        );
        // Same organization, a plain name, or no display name: nothing.
        assert!(claims("\"bob@mail.example.com\" <bob@example.com>").is_empty());
        assert!(claims("Bob Smith <bob@example.com>").is_empty());
        assert!(claims("bob@example.com").is_empty());
        assert!(claims("Alice <a@one.example>, \"b@two.example\" <b@two.example>").is_empty());
        // Malformed encoded-words are left alone, not misdecoded.
        assert!(claims("=?utf-8?Q?bad=ZZ?= <x@attacker.example>").is_empty());
    }
}
