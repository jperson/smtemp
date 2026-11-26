//! The raw header scanner and the end-of-data header checks: never panic,
//! and keep their invariants on any bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mailserv::headers;

fuzz_target!(|raw: &[u8]| {
    // The scanner: spans are in order, don't overlap, and lie inside the
    // header block; the separator lies inside the message.
    let end = headers::header_block_end(raw);
    assert!(end <= raw.len());
    let mut previous_end = 0;
    for field in mailparse::extract_raw_headers(&raw[..end]) {
        assert!(field.span.start >= previous_end && field.span.end <= end);
        previous_end = field.span.end;
    }
    if let Some((header_len, body_start)) = mailparse::find_separator(raw) {
        assert!(header_len <= body_start && body_start <= raw.len());
    }
    let _ = mailparse::parse_raw_message(raw);

    // The checks run at end of data.
    let _ = headers::header_has_bare_cr(raw);
    let _ = headers::from_header_domain(raw);
    if let Ok(value) = headers::single_from_value(raw) {
        if let Some(authors) = headers::from_authors(&value) {
            let _ = headers::display_name_claims(&value, &authors);
        }
    }
    // The Sender-family grant scan (AUDIT_20261126F H1 coverage): never
    // panics, and every identity it returns is a plausible mailbox.
    if let Some(senders) = headers::sender_identities(raw) {
        for (local, domain) in &senders {
            assert!(!local.is_empty() && !domain.is_empty());
        }
    }

    // Stripping only ever removes bytes, and is idempotent.
    let stripped = headers::strip_forged_verdicts(raw, "mx.example.org");
    assert!(stripped.len() <= raw.len());
    let again = headers::strip_forged_verdicts(&stripped, "mx.example.org");
    assert_eq!(again.as_ref(), stripped.as_ref());
    // What is left can't extend or imitate the verdict headers written
    // above it: the block doesn't start with a continuation line, and no
    // continuation line reads as `Authentication-Results:` or
    // `X-Display-Name-Warning:` (AUDIT_20261126 R1/R7).
    let block = &stripped[..headers::header_block_end(&stripped)];
    assert!(!matches!(block.first(), Some(b' ' | b'\t')));
    for line in block.split(|&b| b == b'\n') {
        if matches!(line.first(), Some(b' ' | b'\t')) {
            let wsp = |b: &u8| matches!(b, b' ' | b'\t');
            let text = &line[line.iter().take_while(|b| wsp(b)).count()..];
            for name in [&b"authentication-results"[..], b"x-display-name-warning"] {
                let named = text.len() >= name.len()
                    && text[..name.len()].eq_ignore_ascii_case(name)
                    && text[name.len()..].iter().find(|b| !wsp(b)) == Some(&b':');
                assert!(!named);
            }
        }
    }

    // The typed parser, on what it accepts (UTF-8), must refuse deep
    // nesting rather than overflow the stack.
    if let Ok(text) = std::str::from_utf8(&raw[..end]) {
        let _ = mailparse::parse_headers(text);
    }
});
