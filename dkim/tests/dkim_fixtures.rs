//! Integration tests over the fixture corpus in `tests/fixtures/`.
//!
//! Every fixture's `bh=` value was computed **with openssl** (independently
//! of this crate) over the fixture's canonicalized body, so passing
//! body-hash assertions here are real conformance checks, not circular ones.
//! Fixture files are stored with LF line endings for diff-friendliness and
//! converted to CRLF by the tests, except `bare_lf.eml`, which deliberately
//! stays LF-native.

use dkim::{body_hash_matches, find_signatures, signed_header_data};
use mailparse::{parse_message, ParsedMessage};

fn crlf(fixture: &str) -> Vec<u8> {
    fixture.replace('\n', "\r\n").into_bytes()
}

/// Parse a message from owned bytes, leaking them so the returned
/// `ParsedMessage` can borrow with `'static` (fine for tests).
fn parse(bytes: Vec<u8>) -> ParsedMessage<'static> {
    parse_message(Box::leak(bytes.into_boxed_slice())).expect("fixture must parse")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn position(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or(usize::MAX)
}

const SIMPLE_SIMPLE: &str = include_str!("fixtures/simple_simple.eml");
const RELAXED_L: &str = include_str!("fixtures/relaxed_l.eml");
const EMPTY_BODY: &str = include_str!("fixtures/empty_body.eml");
const TWO_SIGNATURES: &str = include_str!("fixtures/two_signatures.eml");
const OVERSIGNED: &str = include_str!("fixtures/oversigned.eml");
const ED25519_SHA256: &str = include_str!("fixtures/ed25519_sha256.eml");
const BARE_LF: &str = include_str!("fixtures/bare_lf.eml");
const UTF8_SUBJECT: &str = include_str!("fixtures/utf8_subject.eml");

/// simple/simple: header canon is verbatim, body hash over the exact body.
#[test]
fn simple_simple_fixture() {
    let msg = parse(crlf(SIMPLE_SIMPLE));
    let sigs = find_signatures(&msg);
    assert_eq!(sigs.len(), 1);

    let sig = &sigs[0].signature;
    assert_eq!((sig.header_canon, sig.body_canon), ("simple", "simple"));
    assert!(body_hash_matches(&msg, sig).unwrap());

    let data = signed_header_data(&msg, sig, sigs[0].header).unwrap();
    // simple header canonicalization keeps original bytes: the first h=
    // entry (From) appears verbatim, folded headers keep their folds.
    assert!(data.starts_with(b"From: Alice Example <alice@example.org>\r\n"));
    assert!(contains(&data, b"Subject: Simple canonicalization test\r\n"));
    // The DKIM-Signature (b= emptied) is appended last without a CRLF.
    assert!(data.ends_with(b"b="));
}

/// A one-byte change in the body must invalidate the body hash.
#[test]
fn tampered_body_fails_body_hash() {
    let mut bytes = crlf(SIMPLE_SIMPLE);
    let pos = bytes
        .windows(5)
        .position(|w| w == b"Hello")
        .expect("body marker not found");
    bytes[pos] = b'J';

    let msg = parse(bytes);
    let sigs = find_signatures(&msg);
    assert_eq!(sigs.len(), 1);
    assert!(!body_hash_matches(&msg, &sigs[0].signature).unwrap());
}

/// relaxed/relaxed with l=: the hash covers only the first l= bytes of the
/// canonicalized body.
#[test]
fn body_length_tag_truncates_hash_input() {
    let msg = parse(crlf(RELAXED_L));
    let sigs = find_signatures(&msg);
    assert_eq!(sigs.len(), 1);

    let sig = &sigs[0].signature;
    assert_eq!(sig.body_length, Some(20));
    assert!(body_hash_matches(&msg, sig).unwrap());
}

/// A completely empty body canonicalizes to a single CRLF.
#[test]
fn empty_body_hashes_single_crlf() {
    let msg = parse(crlf(EMPTY_BODY));
    assert!(msg.body.is_empty());

    let sigs = find_signatures(&msg);
    assert_eq!(sigs.len(), 1);
    assert!(body_hash_matches(&msg, &sigs[0].signature).unwrap());
}

/// Two signatures from different domains over the same message.
#[test]
fn multiple_signatures_are_all_found_and_hashed() {
    let msg = parse(crlf(TWO_SIGNATURES));
    let sigs = find_signatures(&msg);
    assert_eq!(sigs.len(), 2);

    assert_eq!(sigs[0].signature.domain, "example.org");
    assert_eq!(sigs[0].signature.selector, "sel1");
    assert_eq!(sigs[1].signature.domain, "example.net");
    assert_eq!(sigs[1].signature.selector, "sel2");

    for parsed in &sigs {
        assert!(body_hash_matches(&msg, &parsed.signature).unwrap());
        let data = signed_header_data(&msg, &parsed.signature, parsed.header).unwrap();
        // Each signature's data ends with its own b=-emptied header; the
        // *other* DKIM-Signature header is just an unsigned bystander.
        assert!(data.ends_with(b"b="));
    }
}

/// Over-signing: duplicate names in h=, case-insensitive matching, headers
/// listed in h= but absent from the message, and bottom-up selection.
#[test]
fn oversigned_headers_selected_bottom_up_once() {
    let msg = parse(crlf(OVERSIGNED));
    let sigs = find_signatures(&msg);
    assert_eq!(sigs.len(), 1);

    let sig = &sigs[0].signature;
    // Case of h= entries is preserved by parsing.
    assert_eq!(
        sig.signed_headers,
        vec!["Received", "received", "Subject", "X-Missing", "SUBJECT", "From"]
    );
    assert!(body_hash_matches(&msg, sig).unwrap());

    let data = signed_header_data(&msg, sig, sigs[0].header).unwrap();

    // Received selected bottom-up: the b.example instance comes first.
    assert!(
        position(&data, b"received:from b.example") < position(&data, b"received:from a.example")
    );

    // One Subject instance is used once even though h= names it twice
    // (Subject and SUBJECT match case-insensitively).
    assert_eq!(
        data.windows(b"subject:".len()).filter(|w| w == b"subject:").count(),
        1,
        "subject must appear exactly once"
    );
    assert!(contains(&data, b"subject:Over-signing"));

    // X-Missing is listed in h= but absent; it contributes nothing.
    assert!(!contains(&data, b"x-missing"));

    // Only the field NAME is lowercased by relaxed canonicalization;
    // values keep their case.
    assert!(contains(&data, b"from:Gina Example <gina@example.org>"));
}

/// ed25519-sha256 uses SHA-256 for the body hash like rsa-sha256.
#[test]
fn ed25519_sha256_body_hash() {
    let msg = parse(crlf(ED25519_SHA256));
    let sigs = find_signatures(&msg);
    assert_eq!(sigs.len(), 1);

    let sig = &sigs[0].signature;
    assert_eq!(sig.algorithm, "ed25519-sha256");
    assert_eq!(sig.key_query_name(), "sel1._domainkey.example.org");
    assert!(body_hash_matches(&msg, sig).unwrap());
}

/// LF-only line endings: the body is parsed as-is and canonicalization
/// normalizes line endings for hashing.
#[test]
fn bare_lf_message() {
    // Deliberately NOT converted: the fixture is LF-native.
    let msg = parse(BARE_LF.as_bytes().to_vec());
    let sigs = find_signatures(&msg);
    assert_eq!(sigs.len(), 1);
    assert!(body_hash_matches(&msg, &sigs[0].signature).unwrap());
}

/// A raw UTF-8 (SMTPUTF8-style) subject: canonicalization is byte-oriented
/// and must preserve non-ASCII bytes untouched.
#[test]
fn utf8_subject_bytes_preserved() {
    let msg = parse(crlf(UTF8_SUBJECT));
    let sigs = find_signatures(&msg);
    assert_eq!(sigs.len(), 1);

    let sig = &sigs[0].signature;
    assert!(body_hash_matches(&msg, sig).unwrap());

    let data = signed_header_data(&msg, sig, sigs[0].header).unwrap();
    let expected = "subject:Réunion — naïve café ☕".as_bytes();
    assert!(
        contains(&data, expected),
        "canonicalized UTF-8 subject not found in signed data"
    );
    // Non-ASCII bytes must be preserved exactly, not mangled by the
    // lowercase/name handling. Only the name is lowercased.
    assert!(contains(
        &data,
        b"from:Ivan Example <ivan@example.org>"
    ));
}
