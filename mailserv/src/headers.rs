//! The raw header checks run at end of data: finding the single `From:`
//! header, its authors and domain, and refusing header blocks that
//! contain a bare CR.

/// The outcome of scanning a raw message for its `From:` header. The
/// scan tolerates bytes and headers the strict `mailparse` grammar
/// rejects, so a message that fails to parse still gets a DMARC verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromHeader {
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
pub fn from_header_domain(raw: &[u8]) -> FromHeader {
    match single_from_value(raw) {
        Ok(value) => from_domain_of(&value),
        Err(problem) => problem,
    }
}

/// Find the message's one `From:` header in the raw message `raw`.
///
/// Returns its unfolded, trimmed value, or the problem as `Err`
/// ([`FromHeader::None`] / [`FromHeader::Multiple`]). The fields are those
/// of the shared raw scanner ([`mailparse::extract_raw_headers`] over the
/// header block, see [`header_block_end`]), the same one DKIM uses, so the
/// two can't disagree about where a header starts or ends.
pub fn single_from_value(raw: &[u8]) -> Result<Vec<u8>, FromHeader> {
    let mut from_values: Vec<Vec<u8>> =
        mailparse::extract_raw_headers(&raw[..header_block_end(raw)])
            .iter()
            .filter(|h| h.name_eq("from"))
            .map(|h| trim_header_fws(&unfold(h.raw_value)).to_vec())
            .collect();
    match from_values.len() {
        0 => Err(FromHeader::None),
        1 => Ok(from_values.swap_remove(0)),
        _ => Err(FromHeader::Multiple),
    }
}

/// The header fields other than `From:` that name who sent a message
/// (RFC 5322 §3.6.2, §3.6.6). `Reply-To:` is deliberately absent: it
/// redirects replies, it does not claim authorship.
const SENDER_FIELDS: [&str; 3] = ["sender", "resent-sender", "resent-from"];

/// Every `(local-part, domain)` named by a `Sender:`, `Resent-Sender:` or
/// `Resent-From:` field of `raw`, read with the same scanner and mailbox
/// parser as the `From:` authors ([`from_authors`]), deduplicated. An
/// empty list means the message carries none of these fields. Returns
/// `None` when any such field cannot be read as a mailbox list, so a
/// caller checking grants can fail closed rather than skip it.
pub fn sender_identities(raw: &[u8]) -> Option<Vec<(String, String)>> {
    let mut identities: Vec<(String, String)> = Vec::new();
    for header in mailparse::extract_raw_headers(&raw[..header_block_end(raw)]) {
        if !SENDER_FIELDS.iter().any(|name| header.name_eq(name)) {
            continue;
        }
        let value = unfold(header.raw_value);
        for identity in from_authors(trim_header_fws(&value))? {
            if !identities.contains(&identity) {
                identities.push(identity);
            }
        }
    }
    Some(identities)
}

/// Unfold the raw header value `value` (RFC 5322 §2.2.3): remove the line
/// breaks of folded lines, keeping the whitespace after them.
fn unfold(value: &[u8]) -> Vec<u8> {
    value
        .iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect()
}

/// Whether the header block of `raw` (up to the first empty line)
/// contains a CR that is not part of a CRLF.
pub fn header_has_bare_cr(raw: &[u8]) -> bool {
    let block = &raw[..header_block_end(raw)];
    block
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'\r' && block.get(i + 1) != Some(&b'\n'))
}

/// The most header fields a message may have. Real mail has tens (a long
/// relay chain a few hundred lines, most of them continuations, which
/// don't count). The bound is for memory: every header scan
/// ([`mailparse::extract_raw_headers`]) holds an entry per field, and
/// at two bytes per field a 10 MiB message could otherwise be millions.
pub const MAX_HEADER_FIELDS: usize = 1000;

/// Whether the header block of `raw` has more than `max` fields, counting
/// every line that doesn't continue a field (malformed lines included).
/// Allocates nothing.
pub fn too_many_header_fields(raw: &[u8], max: usize) -> bool {
    let block = &raw[..header_block_end(raw)];
    let starts_field = |line_start: usize| {
        block
            .get(line_start)
            .is_some_and(|&b| b != b' ' && b != b'\t')
    };
    let fields = usize::from(starts_field(0))
        + block
            .iter()
            .enumerate()
            .filter(|&(i, &b)| b == b'\n' && starts_field(i + 1))
            .count();
    fields > max
}

/// Returns the length of the header block of the raw message `raw`: up to
/// the first empty line (the shared [`mailparse::find_separator`]), or all
/// of `raw` when there is none.
pub fn header_block_end(raw: &[u8]) -> usize {
    mailparse::find_separator(raw).map_or(raw.len(), |(header_len, _)| header_len)
}

/// Returns header `value` with folding whitespace (SP, HTAB, CR, LF)
/// trimmed from both ends.
pub fn trim_header_fws(value: &[u8]) -> &[u8] {
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
pub fn from_domain_of(value: &[u8]) -> FromHeader {
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
pub fn from_authors(value: &[u8]) -> Option<Vec<(String, String)>> {
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
    // `<...>` belong to an obsolete route), and read each one as it ends.
    let mut authors: Vec<(String, String)> = Vec::new();
    let mut add = |mailbox: &[u8]| -> Option<()> {
        let mailbox = trim_header_fws(mailbox);
        if mailbox.is_empty() {
            return Some(()); // obs-mbox-list permits empty elements
        }
        let author = mailbox_address(mailbox)?;
        // The same author twice is one author (the grant check and the
        // log need it once); more distinct ones than any real message
        // has is refused, not cut: every author must be checked.
        if !authors.contains(&author) {
            if authors.len() == MAX_AUTHORS {
                return None;
            }
            authors.push(author);
        }
        Some(())
    };
    let (mut angle, mut start) = (0usize, 0usize);
    for (i, &b) in clean.iter().enumerate() {
        match b {
            b'<' => angle += 1,
            b'>' => angle = angle.saturating_sub(1),
            b',' if angle == 0 => {
                add(&clean[start..i])?;
                start = i + 1;
            }
            // From is a mailbox-list: group syntax is not allowed.
            b':' | b';' if angle == 0 => return None,
            _ => {}
        }
    }
    add(&clean[start..])?;
    (!authors.is_empty()).then_some(authors)
}

/// The most distinct authors [`from_authors`] reads from one `From:`
/// field. A real one has a handful; without a bound, continuation lines
/// (which [`MAX_HEADER_FIELDS`] doesn't count) let one field hold
/// hundreds of thousands, each kept, checked and logged.
pub const MAX_AUTHORS: usize = 100;

/// The longest `From:` domain [`mailbox_address`] accepts: a DNS name's
/// 253 octets in text form (RFC 1035 §2.3.4), as `dmarc::psl` and DKIM
/// bound theirs.
const MAX_DOMAIN_LEN: usize = 253;

/// The longest label of a `From:` domain (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// The longest `From:` local-part [`mailbox_address`] accepts. RFC 5321
/// §4.5.3.1.1 sets 64 octets for the envelope; this is looser, since a
/// header address is only displayed, but bounded, since every author is
/// logged and checked against the sender grants.
const MAX_LOCAL_PART_LEN: usize = 256;

/// The `(local-part, domain)` of one cleaned mailbox (comments removed,
/// quoted strings blanked): the addr-spec inside `<...>` when present,
/// otherwise the whole mailbox. Returns `None` unless the local-part is
/// non-empty and at most [`MAX_LOCAL_PART_LEN`] octets, and the domain is
/// plausible and within a DNS name's length. The domain is lowercased.
pub fn mailbox_address(mailbox: &[u8]) -> Option<(String, String)> {
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
    if local.len() > MAX_LOCAL_PART_LEN {
        return None;
    }
    let domain = trim_header_fws(&addr[at + 1..]);
    // Strip a trailing dot (fully-qualified form).
    let domain = domain.strip_suffix(b".").unwrap_or(domain);
    // A DNS name's length bounds (RFC 1035 §2.3.4): a longer name has no
    // wire form, so no DMARC lookup could ever be made for it (and it
    // would be carried whole into the log and the spool metadata).
    // An empty label (`a..b`, or a second trailing dot) is not a domain
    // either (RFC 1035 §2.3.1), and the DMARC walk would trim it while
    // the policy choice saw it (AUDIT_20261126 R4).
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_LEN
        || domain
            .split(|&b| b == b'.')
            .any(|l| l.is_empty() || l.len() > MAX_LABEL_LEN)
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

use std::borrow::Cow;

/// Remove from the header block of `raw` the verdict headers a sender
/// could forge to look like ours: any `Authentication-Results:` whose
/// authserv-id is `authserv_id` (RFC 8601 §5: an MTA removes those before
/// adding its own), and any `X-Display-Name-Warning:` (only this server
/// adds that). Other headers, the body and line endings are kept
/// byte-for-byte.
///
/// Two kinds of line are removed as well, because the stored message is
/// this block placed directly under the verdict headers this server
/// writes, and folding would otherwise carry sender text into them or
/// past them:
///
/// * continuation lines (starting with SP or HTAB) before the first
///   field. RFC 5322 has no place for them, so they belong to no field
///   here, but once prepended to they would continue *our* last header
///   (AUDIT_20261126 R1);
/// * continuation lines that read, after their leading whitespace, as one
///   of [`OUR_VERDICT_HEADERS`] (`Name:`, case-insensitive). They are
///   part of the field above, so field stripping keeps them, but a reader
///   that splits header lines would see our verdict there (R7).
///
/// Returns the message without those fields and lines, borrowing `raw`
/// (no copy) when there were none, which is the usual case. Fields are
/// found by the shared raw scanner and cut out by their exact spans, so
/// other lines it doesn't count as a field (malformed ones) are kept as
/// they are.
pub fn strip_forged_verdicts<'r>(raw: &'r [u8], authserv_id: &str) -> Cow<'r, [u8]> {
    // Lines first: a removed line can change a field's authserv-id (it
    // may sit before it), so the fields are judged on what remains, and
    // stripping twice changes nothing.
    let lines = smuggling_lines(&raw[..header_block_end(raw)]);
    let raw: Cow<'r, [u8]> = if lines.is_empty() {
        Cow::Borrowed(raw)
    } else {
        Cow::Owned(without_spans(raw, &lines))
    };
    let forged: Vec<std::ops::Range<usize>> =
        mailparse::extract_raw_headers(&raw[..header_block_end(&raw)])
            .into_iter()
            .filter(|h| is_forged_verdict(h, authserv_id))
            .map(|h| h.span)
            .collect();
    if forged.is_empty() {
        return raw;
    }
    Cow::Owned(without_spans(&raw, &forged))
}

/// Returns `raw` without the bytes of `spans` (in order, non-overlapping).
fn without_spans(raw: &[u8], spans: &[std::ops::Range<usize>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut cursor = 0;
    for span in spans {
        out.extend_from_slice(&raw[cursor..span.start]);
        cursor = span.end;
    }
    out.extend_from_slice(&raw[cursor..]);
    out
}

/// The header fields only this server may write (see
/// [`strip_forged_verdicts`]), lowercased.
const OUR_VERDICT_HEADERS: [&str; 2] = ["authentication-results", "x-display-name-warning"];

/// Returns the spans (with their line terminators) of the continuation
/// lines of header block `block` that [`strip_forged_verdicts`] removes:
/// those before the first non-continuation line, and those that read as
/// one of [`OUR_VERDICT_HEADERS`]. In order, non-overlapping.
fn smuggling_lines(block: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut lines = Vec::new();
    let mut leading = true;
    let mut start = 0;
    while start < block.len() {
        let end = block[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(block.len(), |p| start + p + 1);
        let line = &block[start..end];
        let continuation = matches!(line.first(), Some(b' ' | b'\t'));
        if !continuation {
            leading = false;
        } else if leading || names_our_verdict(line) {
            lines.push(start..end);
        }
        start = end;
    }
    lines
}

/// Whether the continuation line `line` reads, after its leading
/// whitespace, as a field of one of [`OUR_VERDICT_HEADERS`]: the name
/// (case-insensitive), optional whitespace (the obsolete `Name :` form),
/// then a colon.
fn names_our_verdict(line: &[u8]) -> bool {
    let is_wsp = |b: &u8| matches!(b, b' ' | b'\t');
    let text = &line[line.iter().take_while(|b| is_wsp(b)).count()..];
    OUR_VERDICT_HEADERS.iter().any(|name| {
        text.len() >= name.len()
            && text[..name.len()].eq_ignore_ascii_case(name.as_bytes())
            && text[name.len()..]
                .iter()
                .find(|b| !is_wsp(b))
                .is_some_and(|&b| b == b':')
    })
}

/// Whether the header field `header` is one of [`OUR_VERDICT_HEADERS`]
/// that [`strip_forged_verdicts`] removes: any `X-Display-Name-Warning:`,
/// and an `Authentication-Results:` whose authserv-id is `authserv_id`.
fn is_forged_verdict(header: &mailparse::RawHeader<'_>, authserv_id: &str) -> bool {
    if header.name_eq("x-display-name-warning") {
        return true;
    }
    header.name_eq("authentication-results")
        && auth_results_id(header.raw_value).is_some_and(|id| {
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
/// <x@attacker.example>`. See [`display_name_claims_counted`], which also
/// says whether the list was cut; this is its list.
pub fn display_name_claims(from_value: &[u8], authors: &[(String, String)]) -> Vec<String> {
    display_name_claims_counted(from_value, authors).shown
}

/// The display-name claims of one From value (see
/// [`display_name_claims_counted`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims {
    /// The claimed domains reported: sorted, deduplicated, at most
    /// [`MAX_CLAIMS`], each cut to a DNS name's 253 octets (marked `...`).
    pub shown: Vec<String>,
    /// `Some(n)` when more claimed domains were found than `shown` holds:
    /// `n` is the number of addresses at another organization's domain
    /// in the whole value (repeats included). `None` when nothing was
    /// left out.
    pub truncated: Option<usize>,
}

/// The claims of [`display_name_claims`], and whether any were left out.
///
/// The claims are copied into a header, the spool metadata and the log,
/// so at most [`MAX_CLAIMS`] are kept. An over-long claim is kept, cut,
/// rather than dropped: no domain is that long, but a reader shown
/// `ceo@paypal.com.aaaa…` still sees `paypal.com`. Which ones are kept
/// when there are more is in [`claimed_domains`]; no choice of a fixed
/// number from a list the sender writes can be relied on to keep the one
/// that matters, so a cut list says so ([`Claims::truncated`]). Real mail
/// names one or two other domains at most; a cut list is a verdict of its
/// own, and a filter should act on it (and on the warning itself) rather
/// than on which domains it names.
///
/// RFC 2047 encoded-words (`=?utf-8?B?...?=`) are decoded first, since
/// mail clients display them decoded. An address in a different
/// organization is common in legitimate list mail too (`"alice@example.com
/// via Team" <team@lists.example>`), so this is a warning, not a refusal.
pub fn display_name_claims_counted(from_value: &[u8], authors: &[(String, String)]) -> Claims {
    let org = |d: &str| dmarc::psl::organizational_domain(d).unwrap_or_else(|| d.to_string());
    // A set: the authors can number up to `MAX_AUTHORS`, and the
    // candidates in the thousands.
    let author_orgs: std::collections::HashSet<String> =
        authors.iter().map(|(_, d)| org(d)).collect();
    claimed_domains(&decode_encoded_words(from_value), |d| {
        !author_orgs.contains(&org(d))
    })
}

/// The most display-name claims [`display_name_claims`] reports. One is
/// enough to warn; a few more help whoever reads the header.
pub const MAX_CLAIMS: usize = 10;

/// The longest claimed domain [`display_name_claims`] reports in full: a
/// DNS name's 253 octets.
const MAX_CLAIM_LEN: usize = 253;

/// Returns at most [`MAX_CLAIMS`] of the domains [`for_each_address_domain`]
/// finds in `text` that `keep` accepts, deduplicated and sorted, each cut
/// to [`MAX_CLAIM_LEN`] (marked with `...`), and whether any were left out.
///
/// Memory is bounded by the result, not by `text`: the candidates are
/// kept in a set of at most `MAX_CLAIMS + 1` while the text is scanned.
/// When there are more than `MAX_CLAIMS`, the domains under a suffix of
/// the public suffix list (`paypal.com`) are kept before those under an
/// unlisted one (`a0.example`, `x.invalid`), then alphabetically: no real
/// organization sits under an unlisted suffix, so filler addresses there
/// can't push a claim about a real one out of the warning. (Fillers under
/// a listed suffix can; then [`Claims::truncated`] says so.)
fn claimed_domains(text: &[u8], mut keep: impl FnMut(&str) -> bool) -> Claims {
    // Ordered by (unlisted, domain): the last entry is the first to drop.
    let mut best: std::collections::BTreeSet<(bool, String)> = Default::default();
    let (mut addresses, mut dropped) = (0usize, false);
    for_each_address_domain(text, |mut domain| {
        if !keep(&domain) {
            return;
        }
        addresses = addresses.saturating_add(1);
        // Domain characters are ASCII, so any byte is a boundary. A cut
        // name is longer than any DNS name, so it is never listed.
        if domain.len() > MAX_CLAIM_LEN {
            domain.truncate(MAX_CLAIM_LEN);
            domain.push_str("...");
        }
        // Repeats are free to send: a comparison against the few kept,
        // and no list lookup.
        if best.iter().any(|(_, kept)| *kept == domain) {
            return;
        }
        let unlisted = !dmarc::psl::has_listed_suffix(&domain);
        best.insert((unlisted, domain));
        if best.len() > MAX_CLAIMS {
            best.pop_last();
            dropped = true;
        }
    });
    let mut shown: Vec<String> = best.into_iter().map(|(_, d)| d).collect();
    shown.sort();
    Claims {
        shown,
        truncated: dropped.then_some(addresses),
    }
}

/// [`claimed_domains`] with nothing filtered out: the bounded selection
/// of every `local@domain` in `text`.
#[cfg(test)]
fn address_domains(text: &[u8]) -> Vec<String> {
    claimed_domains(text, |_| true).shown
}

/// Calls `found` with the domain of every `local@domain` in `text`
/// (lowercased, a trailing dot removed), in order: an `@` with a non-space
/// character before it and a domain of letters, digits, `-` and `.` (with
/// at least one dot) after.
fn for_each_address_domain(text: &[u8], mut found: impl FnMut(String)) {
    for (at, _) in text.iter().enumerate().filter(|(_, &b)| b == b'@') {
        let before_ok = at > 0 && !text[at - 1].is_ascii_whitespace() && text[at - 1] != b'<';
        if !before_ok {
            continue;
        }
        let rest = &text[at + 1..];
        let len = rest
            .iter()
            .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.')))
            .unwrap_or(rest.len());
        // Only ASCII bytes were taken, so this is valid UTF-8.
        let domain = String::from_utf8_lossy(&rest[..len])
            .trim_matches('.')
            .to_ascii_lowercase();
        if domain.contains('.') {
            found(domain);
        }
    }
}

/// Decode the RFC 2047 encoded-words in `value` (`=?charset?B|Q?text?=`)
/// to their raw bytes, whatever the charset (only ASCII is looked at
/// afterwards, and every common charset is an ASCII superset). Anything
/// that isn't a well-formed encoded-word is kept as it is.
///
/// Linear in `value`, which is attacker-chosen and can be megabytes (a
/// folded `From:`): a candidate that turns out not to be an encoded-word
/// never makes the scan go back over the rest of the value. The end of
/// each candidate's text (the next `?=`) comes from [`NextCloser`], which
/// only moves forward; a `B` text is checked for base64 characters
/// before it is decoded (that check stops at the next candidate's `?`);
/// a `Q` text stops decoding at the next candidate's `=?`, an invalid
/// escape.
fn decode_encoded_words(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut closer = NextCloser::new(value);
    let mut i = 0;
    while i < value.len() {
        if value[i..].starts_with(b"=?") {
            if let Some((decoded, end)) = decode_one_word(value, i, &mut closer) {
                out.extend_from_slice(&decoded);
                i = end;
                continue;
            }
        }
        out.push(value[i]);
        i += 1;
    }
    out
}

/// Finds the next `?=` in a value, for searches that start further and
/// further on: the last answer is kept and reused while it is still
/// ahead of the search, so every byte is scanned about once in all.
struct NextCloser<'v> {
    /// The value searched.
    value: &'v [u8],
    /// Where the last search started.
    from: usize,
    /// Its answer: the offset of the first `?=` at or after `from`, or
    /// `None` when there is none.
    found: Option<usize>,
}

impl<'v> NextCloser<'v> {
    fn new(value: &'v [u8]) -> Self {
        let mut closer = NextCloser {
            value,
            from: 0,
            found: None,
        };
        closer.found = closer.scan(0);
        closer
    }

    /// The offset of the first `?=` at or after `start`.
    fn at_or_after(&mut self, start: usize) -> Option<usize> {
        // The last answer holds for any later start up to it, and "none
        // after `from`" holds for any later start.
        let still_valid = start >= self.from && self.found.is_none_or(|p| p >= start);
        if !still_valid {
            self.from = start;
            self.found = self.scan(start);
        }
        self.found
    }

    fn scan(&self, start: usize) -> Option<usize> {
        self.value
            .get(start..)?
            .windows(2)
            .position(|w| w == b"?=")
            .map(|p| start + p)
    }
}

/// Decode the encoded-word that starts at `value[start..]` (with `=?`),
/// using `closer` to find where its text ends.
///
/// Returns the decoded bytes and the offset just past the encoded-word,
/// or `None` when it isn't one.
fn decode_one_word(
    value: &[u8],
    start: usize,
    closer: &mut NextCloser<'_>,
) -> Option<(Vec<u8>, usize)> {
    // =?charset?enc?text?=
    let rest = &value[start + 2..];
    // Stops at the latest at the `?` of the next `=?`.
    let q1 = rest.iter().position(|&b| b == b'?')?;
    let enc = *rest.get(q1 + 1)?;
    if rest.get(q1 + 2) != Some(&b'?') {
        return None;
    }
    let text_start = start + 2 + q1 + 3;
    let text_end = closer.at_or_after(text_start)?;
    let text = &value[text_start..text_end];
    let end = text_end + 2;
    let decoded = match enc.to_ascii_uppercase() {
        b'B' => {
            use base64::Engine as _;
            let base64_char =
                |&b: &u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=');
            if !text.iter().all(base64_char) {
                return None;
            }
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .ok()?
        }
        b'Q' => {
            let mut bytes = Vec::new();
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
    Some((decoded, end))
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
        assert!(
            matches!(strip_forged_verdicts(clean, "mx.example.org"), Cow::Borrowed(b) if b == clean),
            "no copy"
        );
    }

    /// AUDIT_20261126 R4: a `From:` domain with an empty label has no DNS
    /// form, so it is not a domain; one trailing dot is still the
    /// fully-qualified spelling.
    #[test]
    fn from_domain_has_no_empty_labels() {
        assert_eq!(
            mailbox_address(b"ceo@sub.paypal.com."),
            Some(("ceo".into(), "sub.paypal.com".into()))
        );
        for bad in [
            &b"ceo@sub.paypal.com.."[..],
            b"ceo@sub..paypal.com",
            b"ceo@.paypal.com",
            b"ceo@.",
        ] {
            assert_eq!(
                mailbox_address(bad),
                None,
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// AUDIT_20261126 R1/R7: a continuation line before the first field
    /// (it would extend the header written above the message) and a
    /// continuation line that reads as one of our verdict headers are
    /// removed; other folding is kept exactly.
    #[test]
    fn folded_lines_cannot_carry_verdicts() {
        let raw = b"\tspf=pass smtp.mailfrom=victim.example\r\n \r\n\
Subject: hi\r\n\
\tAuthentication-Results: mx.example.org; dmarc=pass\r\n\
\x20x-display-name-warning : none\n\
\tstill the subject\r\n\
From: a@x.example\r\n\
\r\n\
\tAuthentication-Results: body text stays\r\n";
        let expected = b"Subject: hi\r\n\
\tstill the subject\r\n\
From: a@x.example\r\n\
\r\n\
\tAuthentication-Results: body text stays\r\n";
        let out = strip_forged_verdicts(raw, "mx.example.org");
        assert_eq!(
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(expected)
        );
        // A line inside a removed field is removed once, with it.
        let nested =
            b"X-Display-Name-Warning: a\r\n\tAuthentication-Results: b\r\nSubject: s\r\n\r\n";
        assert_eq!(
            strip_forged_verdicts(nested, "mx.example.org").as_ref(),
            &b"Subject: s\r\n\r\n"[..]
        );
        // Ordinary folding mentioning the names elsewhere is untouched.
        let clean = b"Subject: about\r\n\tAuthentication-Results headers\r\n\r\nbody\r\n";
        assert!(matches!(
            strip_forged_verdicts(clean, "mx.example.org"),
            Cow::Borrowed(_)
        ));
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
    /// One scanner for every header check: after a malformed (colon-less)
    /// line, a continuation line belongs to no field. The From value isn't
    /// extended by it (DKIM's view agrees, being the same scanner), and
    /// stripping keeps the malformed lines exactly.
    #[test]
    fn checks_share_the_raw_scanner() {
        let raw = b"From: a@x.example\r\ngarbage\r\n ceo@victim.example\r\n\
Authentication-Results: mx.example.org; dmarc=pass\r\nSubject: s\r\n\r\nbody\r\n";
        assert_eq!(single_from_value(raw).unwrap(), b"a@x.example");
        let dkim_view = mailparse::parse_raw_message(raw).unwrap();
        let dkim_from: Vec<_> = dkim_view
            .headers
            .iter()
            .filter(|h| h.name_eq("from"))
            .collect();
        assert_eq!(dkim_from.len(), 1);
        assert_eq!(dkim_from[0].raw_value, b" a@x.example");
        assert_eq!(
            strip_forged_verdicts(raw, "mx.example.org").as_ref(),
            &b"From: a@x.example\r\ngarbage\r\n ceo@victim.example\r\nSubject: s\r\n\r\nbody\r\n"[..]
        );
    }

    /// Encoded-words next to and inside each other decode as before: an
    /// unterminated candidate, a candidate inside another's text, a `B`
    /// text with a non-base64 byte, and a `Q` text with a `?` in it.
    #[test]
    fn encoded_word_edge_cases() {
        let decode = |v: &str| String::from_utf8(decode_encoded_words(v.as_bytes())).unwrap();
        assert_eq!(decode("=?a?B?YWI=?= =?a?Q?c_d?="), "ab c d");
        assert_eq!(decode("=?a?B?YWI=?=?="), "ab?=");
        assert_eq!(decode("=?a?b?Z =?a?B?YWI=?="), "=?a?b?Z ab");
        assert_eq!(decode("=?a?B?Y?WI=?="), "=?a?B?Y?WI=?=");
        assert_eq!(decode("=?a?Q?x?y?="), "x?y");
        assert_eq!(decode("=?a?Q?x=?a?Q?y?="), "=?a?Q?xy");
        assert_eq!(decode("=?a?Q?x=4"), "=?a?Q?x=4");
        assert_eq!(decode("=?"), "=?");
        assert_eq!(decode("=?a?"), "=?a?");
        assert_eq!(decode("=?a?B?"), "=?a?B?");
    }

    /// Pathological From values cost time linear in their size: an
    /// unterminated encoded-word prefix repeated (each one rescanned the
    /// rest of the value: 896 KB took 14.5 s in a release build), a `B`
    /// text that never decodes, and thousands of claims and authors.
    #[test]
    fn display_name_claims_are_linear() {
        use std::time::{Duration, Instant};
        let authors = vec![("x".to_string(), "example.invalid".to_string())];
        let unterminated = "=?a?b?Z".repeat(300_000) + " x@example.invalid";
        let bad_base64 = "=?a?B?!".repeat(300_000) + "?= x@example.invalid";
        let long_domains = format!("{} <x@example.invalid>", "a@ab.".repeat(200_000) + "cd");
        let started = Instant::now();
        for value in [&unterminated, &bad_base64, &long_domains] {
            display_name_claims(value.as_bytes(), &authors);
        }
        let many_authors: Vec<(String, String)> = (0..20_000)
            .map(|i| (format!("u{i}"), "example.invalid".to_string()))
            .collect();
        let many_claims =
            "\"".to_string() + &"c@a.example ".repeat(20_000) + "\" <x@example.invalid>";
        assert_eq!(
            display_name_claims(many_claims.as_bytes(), &many_authors),
            ["a.example"]
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
    }

    /// Header fields are counted without parsing: continuation lines
    /// don't count, malformed lines do, and the body isn't looked at.
    #[test]
    fn header_fields_are_counted() {
        let count_over = |raw: &[u8], max| too_many_header_fields(raw, max);
        let raw = b"A: 1\r\n folded\r\n\tagain\r\nB: 2\r\nmalformed\r\n\r\nC: body\r\nD: body\r\n";
        assert!(!count_over(raw, 3));
        assert!(count_over(raw, 2));
        assert!(!count_over(b"", 0));
        assert!(!count_over(b"\r\nbody\r\n", 0));
        let mut many = "a:b\r\n".repeat(MAX_HEADER_FIELDS);
        assert!(!count_over(many.as_bytes(), MAX_HEADER_FIELDS));
        many.push_str("a:b\r\n\r\n");
        assert!(count_over(many.as_bytes(), MAX_HEADER_FIELDS));
    }

    /// The claims are bounded in number and length: they are copied into
    /// a header, the spool metadata and the log.
    #[test]
    fn display_name_claims_are_bounded() {
        let authors = vec![("x".to_string(), "attacker.example".to_string())];
        let many: String = (0..50).map(|i| format!("c@v{i:02}.example ")).collect();
        let claims = display_name_claims(
            format!("\"{many}\" <x@attacker.example>").as_bytes(),
            &authors,
        );
        assert_eq!(claims.len(), MAX_CLAIMS);
        assert_eq!(claims[0], "v00.example");

        let long = format!("paypal.com.{}", "a".repeat(60_000));
        let claims = display_name_claims(
            format!("\"ceo@{long}\" <x@attacker.example>").as_bytes(),
            &authors,
        );
        assert_eq!(claims.len(), 1, "kept, not dropped");
        assert!(claims[0].starts_with("paypal.com.aaa"));
        assert_eq!(claims[0].len(), MAX_CLAIM_LEN + 3);
        assert!(claims[0].ends_with("..."));
    }

    /// Filler claims push the claim that matters out of the warning.
    ///
    /// Q4 capped the claims at `MAX_CLAIMS` to bound the header, the
    /// metadata and the log, but it keeps the *alphabetically first* ten
    /// and drops the rest, so a sender who wants no warning about
    /// `ceo@paypal.com` writes ten throwaway addresses at domains that
    /// sort before it. The rest of the list is what the reader is shown;
    /// the spoof is silent. (The length cap right above keeps an
    /// over-long claim precisely because dropping one loses the warning;
    /// the count cap must not do the same thing.)
    #[test]
    fn filler_claims_cannot_suppress_the_warning() {
        let authors = vec![("x".to_string(), "attacker.example".to_string())];
        let pad: String = (0..MAX_CLAIMS)
            .map(|i| format!("p{i}@a{i}.example "))
            .collect();
        let claims = display_name_claims(
            format!("\"{pad}ceo@paypal.com\" <x@attacker.example>").as_bytes(),
            &authors,
        );
        assert_eq!(claims.len(), MAX_CLAIMS, "{claims:?}");
        assert!(
            claims.iter().any(|c| c == "paypal.com"),
            "{} filler claims sort first and push the real one out: {claims:?}",
            MAX_CLAIMS
        );
    }

    /// The bound a `From:` domain must have, same as
    /// [`dmarc::psl::organizational_domain`]'s `normalize` and
    /// `dkim::MAX_DNS_NAME_LEN`: a DNS name's 253 octets, 63 per label
    /// (RFC 1035 §2.3.4, RFC 6376 §3.5).
    const EXPECTED_MAX_DOMAIN_LEN: usize = 253;

    /// A `From:` domain longer than a DNS name is accepted, because
    /// `mailbox_address` bounds the characters but not the length (the
    /// data-line cap doesn't help: unfolded continuation lines join into
    /// one domain).
    ///
    /// Q4 bound DKIM's `d=`/`s=`/`i=`, the DKIM error text, the claims and
    /// `header_token`, and Q2's bound landed in `dmarc::psl::normalize`
    /// only — but this string is what `from_domain` is made of, and
    /// `from_domain` is logged (`info!(from_domain = ...)`,
    /// `warn!(from_domain = ...)` on `MultipleRecords`) and stored whole
    /// in the spool metadata (`DmarcSummary.from_domain`) whenever one of
    /// the ancestor names the sender chose has a record, so one message
    /// can carry megabytes into the log line and into the metadata file
    /// beside it. The same name has no DNS wire form, so the DMARC walk
    /// finds nothing and the message is delivered unchecked (AUDIT Q10);
    /// refusing it here closes both.
    #[test]
    fn from_domain_length_is_bounded() {
        // A label longer than DNS allows is already not a domain.
        assert!(
            mailbox_address(format!("a@x.{}.com", "a".repeat(64)).as_bytes()).is_none(),
            "a 64-octet label has no DNS wire form"
        );
        // And a name longer than a DNS name: 200 KB here, well over the
        // 253-octet bound, in one unfolded field (2 header fields, so
        // MAX_HEADER_FIELDS doesn't bite).
        let long = format!("x.example.{}cd", "ab.".repeat(100_000));
        assert!(long.len() > 10 * EXPECTED_MAX_DOMAIN_LEN);
        let raw = format!("From: a@{long}\r\nSubject: s\r\n\r\nbody\r\n");
        assert!(!too_many_header_fields(raw.as_bytes(), MAX_HEADER_FIELDS));
        assert_eq!(
            from_header_domain(raw.as_bytes()),
            FromHeader::Unparseable,
            "a {}-octet From domain must be refused, not carried",
            long.len()
        );
    }

    /// The most authors one `From:` field may yield. A real one has a
    /// handful; this is the bound Q1's "no per-item state beyond the
    /// field cap" needs, and there is none in the code today.
    const EXPECTED_MAX_AUTHORS: usize = 100;

    /// The number of authors in one `From:` field is unbounded, so a
    /// message holds its reader's memory per author, not per field.
    ///
    /// Q1 capped the header *fields*, but continuation lines are free and
    /// `from_authors` (and `address_domains` inside
    /// `display_name_claims`) keeps an entry and two `String`s per
    /// mailbox. Measured in release, straight through
    /// [`single_from_value`] + [`from_authors`] as `end_of_data` calls
    /// them: one 9 MiB folded `From:` — two header fields, far under
    /// `MAX_HEADER_FIELDS` — yields 629,146 authors and +127 MB of peak
    /// RSS for that one message (14× the message, where DESIGN §13 and
    /// DEPLOYMENT.md B2 budget 2–3×), plus a `from_authors = ?authors`
    /// record of 12 MB, which is what the fix set out to remove.
    #[test]
    fn from_author_count_is_bounded() {
        // ~800 KB of continuation lines: 60,000 mailboxes, 2 fields.
        let mut value = String::from("a@x.example");
        for _ in 1..60_000 {
            value.push_str(",\r\n a@x.example");
        }
        let raw = format!("From: {value}\r\nSubject: s\r\n\r\nbody\r\n");
        assert!(!too_many_header_fields(raw.as_bytes(), MAX_HEADER_FIELDS));
        let value = single_from_value(raw.as_bytes()).unwrap();
        let authors = from_authors(&value).unwrap();
        assert_eq!(
            from_domain_of(&value),
            FromHeader::Parsed("x.example".to_string()),
            "one author domain, so the list is accepted and used"
        );
        assert!(
            authors.len() <= EXPECTED_MAX_AUTHORS,
            "{} authors materialized from a {}-byte field",
            authors.len(),
            value.len()
        );
        // The same list is what the info! record prints, so the record
        // inherits the bound.
        assert!(
            format!("{authors:?}").len() <= 64 * 1024,
            "the from_authors record is {} MB",
            format!("{authors:?}").len() / 1_048_576
        );
    }

    /// `display_name_claims` keeps every address it finds before cutting
    /// the list to `MAX_CLAIMS`, so a folded display name costs memory
    /// per address: measured +86 MB peak for a 17 MB one (5×), with only
    /// 10 claims ever reported.
    #[test]
    fn claim_candidates_are_bounded() {
        let authors = vec![("x".to_string(), "attacker.example".to_string())];
        let mut value = String::from("\"");
        for i in 0..200_000 {
            value.push_str(&format!("c@v{i}.example "));
        }
        value.push_str("\" <x@attacker.example>");
        assert!(
            address_domains(value.as_bytes()).len() <= MAX_CLAIMS,
            "{} candidate domains held to report {} claims",
            address_domains(value.as_bytes()).len(),
            MAX_CLAIMS
        );
        let claims = display_name_claims(value.as_bytes(), &authors);
        assert!(claims.len() <= MAX_CLAIMS);
    }

    /// A cut claim list says so, with how many addresses were found, so a
    /// filter can act on the overflow when the domain that matters was
    /// left out (fillers under a listed suffix, which no fixed-size
    /// selection can rule out). A list that fits, repeats included, is
    /// not marked.
    #[test]
    fn cut_claims_are_marked() {
        let authors = vec![("x".to_string(), "attacker.example".to_string())];
        let counted = |names: &str| {
            display_name_claims_counted(
                format!("\"{names}\" <x@attacker.example>").as_bytes(),
                &authors,
            )
        };
        let pad: String = (0..MAX_CLAIMS).map(|i| format!("p@a{i}.com ")).collect();
        let claims = counted(&format!("{pad}ceo@paypal.com"));
        assert_eq!(claims.shown.len(), MAX_CLAIMS);
        assert!(
            !claims.shown.iter().any(|c| c == "paypal.com"),
            "{claims:?}"
        );
        assert_eq!(claims.truncated, Some(MAX_CLAIMS + 1));

        let fits = counted(&"ceo@paypal.com ".repeat(50));
        assert_eq!(fits.shown, ["paypal.com"]);
        assert_eq!(fits.truncated, None);
        assert_eq!(counted("Bob").truncated, None);
    }
}
