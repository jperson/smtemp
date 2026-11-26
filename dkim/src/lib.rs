//! DKIM verification (RFC 6376, RFC 8463) built on the [`mailparse`]
//! crate: canonicalization, body hashing, signed-header-data
//! construction, public-key records, and cryptographic verification
//! (RSA PKCS#1 v1.5 and Ed25519, SHA-256).
//!
//! Implemented:
//! - `DKIM-Signature` tag parsing ([`DkimSignature::parse`])
//! - relaxed/simple header and body canonicalization (RFC 6376 Section 3.4)
//! - body hash (`bh=`) computation and verification ([`body_hash`],
//!   [`body_hash_matches`], [`verify_body_hashes`])
//! - construction of the signed header data: `h=` selection bottom-up with
//!   each header instance used at most once, followed by the
//!   `DKIM-Signature` header with the `b=` value emptied
//!   ([`signed_header_data`])
//! - retrieval of the DKIM public key record over the shared DNS
//!   client ([`fetch_public_key`]), and cryptographic verification of
//!   the `b=` signature (RSA + Ed25519; [`verify_with_key`],
//!   [`verify_dkim`])
//! - `x=` expiry enforcement
#![warn(missing_docs)]

use base64::prelude::*;
use rsa::pkcs1::DecodeRsaPublicKey as _;
use rsa::pkcs1v15::{Signature as Pkcs1v15Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts as _;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use dns::DnsClient;

use mailparse::{parse_raw_message, RawHeader, RawMessage};

/// Errors from DKIM signature parsing, key handling, and verification.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum DkimError {
    /// A required tag (v/a/b/bh/d/s/h) is absent.
    #[error("missing required tag: {0}")]
    MissingTag(&'static str),

    /// A present tag with an unusable value: `v=` other than 1, `l=`,
    /// `t=` or `x=` not a number, or an `h=` that is empty, lists more
    /// than [`MAX_SIGNED_HEADERS`] names, or does not sign From; a `d=` or
    /// `s=` longer than [`MAX_DNS_NAME_LEN`], or an `i=` longer than
    /// [`MAX_IDENTITY_LEN`].
    #[error("invalid value for tag: {0}")]
    InvalidTag(&'static str),

    /// The a= or k= names an algorithm this verifier does not implement.
    #[error("unsupported hash or key algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// The DNS query for the key record failed (resolver unreachable,
    /// timeout, invalid name).
    #[error("DNS lookup for the public key failed: {0}")]
    KeyLookupFailed(String),

    /// No TXT answer at the key-record name parses as a DKIM key record
    /// (including NXDOMAIN and empty answers).
    #[error("no usable DKIM key record found at {0}")]
    NoKeyRecord(String),

    /// The key record has an empty p= tag (explicit revocation).
    #[error("public key is revoked (empty p= tag)")]
    RevokedKey,

    /// The key record does not decode to a usable public key.
    #[error("invalid public key: {0}")]
    InvalidKey(String),

    /// The key record's h= tag does not list the signature's hash.
    #[error("hash algorithm {0} is not accepted by the public key record")]
    HashNotAccepted(String),

    /// The key record's s= tag does not include "email".
    #[error("key record does not permit the email service")]
    ServiceNotPermitted,

    /// The `i=` identity's domain is neither `d=` nor (unless the key sets
    /// `t=s`) a subdomain of it.
    #[error("AUID (i=) domain does not match the signing domain (d=)")]
    DomainMismatch,

    /// The signature's x= timestamp is in the past.
    #[error("signature expired (x= is in the past)")]
    Expired,

    /// The b= value does not decode to a valid signature for the key
    /// type.
    #[error("invalid signature encoding: {0}")]
    InvalidSignature(String),

    /// The signature's `l=` does not cover the whole body, so content
    /// outside the signature could have been appended. Such a signature
    /// is never treated as verified.
    #[error("body length (l=) does not cover the whole message body")]
    PartialBody,

    /// The RSA key is shorter than RFC 8301's 1024-bit minimum.
    #[error("RSA key too short: {0} bits (RFC 8301 requires at least 1024)")]
    WeakKey(usize),

    /// A tag name occurs twice in a signature or key record, which makes
    /// the whole tag list invalid (RFC 6376 §3.2).
    #[error("duplicate tag: {0}")]
    DuplicateTag(String),

    /// The key record's `k=` is not the key algorithm of the signature's
    /// `a=` (RFC 6376 §6.1.2).
    #[error("key type {key} does not match the signature algorithm {signature}")]
    KeyTypeMismatch {
        /// The key algorithm named by the signature's `a=`.
        signature: String,
        /// The key record's `k=`.
        key: String,
    },
}

impl DkimError {
    /// Whether this outcome may change on retry: only a key lookup that
    /// got no definite answer ([`DkimError::KeyLookupFailed`]). A verifier
    /// must not treat such a signature as having failed for good (a
    /// DMARC rejection over it would refuse legitimate mail for a DNS
    /// hiccup); every other error is permanent.
    pub fn is_temporary(&self) -> bool {
        matches!(self, DkimError::KeyLookupFailed(_))
    }
}

/// Check the tag name `name` of a tag list against the names already in
/// `seen`, recording it. A set, not a list: the number of tags is
/// attacker-chosen and unbounded (unknown tags are allowed), so a linear
/// scan per tag would make parsing quadratic.
///
/// # Errors
///
/// [`DkimError::DuplicateTag`] when `name` was already seen (RFC 6376
/// §3.2).
fn note_tag<'t>(seen: &mut HashSet<&'t str>, name: &'t str) -> Result<(), DkimError> {
    if !seen.insert(name) {
        return Err(DkimError::DuplicateTag(name.to_string()));
    }
    Ok(())
}

/// A parsed `DKIM-Signature` header (RFC 6376 Section 3.5).
///
/// Tag values borrow from the raw header text. FWS inside tag values (e.g.
/// folded `b=`/`bh=` base64) is preserved in the slices; use [`strip_fws`]
/// or the comparison helpers to get the pure values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimSignature<'a> {
    /// `v=` — signature version, must be "1".
    pub version: &'a str,
    /// `a=` — algorithm, e.g. "rsa-sha256" or "ed25519-sha256".
    pub algorithm: &'a str,
    /// `b=` — signature data (base64, possibly folded).
    pub signature: &'a str,
    /// `bh=` — body hash (base64, possibly folded).
    pub body_hash: &'a str,
    /// `c=` header canonicalization ("simple" or "relaxed").
    pub header_canon: &'a str,
    /// `c=` body canonicalization ("simple" or "relaxed").
    pub body_canon: &'a str,
    /// `d=` — signing domain (SDID).
    pub domain: &'a str,
    /// `s=` — selector.
    pub selector: &'a str,
    /// `h=` — signed header field names, in signed order.
    pub signed_headers: Vec<&'a str>,
    /// `i=` — identity (AUID) of the agent on whose behalf the message is
    /// signed; its domain must match `d=`.
    pub identity: Option<&'a str>,
    /// `l=` — body length count.
    pub body_length: Option<usize>,
    /// `t=` — signature timestamp.
    pub timestamp: Option<u64>,
    /// `x=` — signature expiry.
    pub expiry: Option<u64>,
}

impl<'a> DkimSignature<'a> {
    /// Parse the tag list `raw` of a `DKIM-Signature` header value
    /// (everything after the colon). `c=` defaults to `simple/simple`.
    ///
    /// # Errors
    ///
    /// [`DkimError::MissingTag`] for an absent `v`, `a`, `b`, `bh`, `d`,
    /// `s` or `h` tag; [`DkimError::InvalidTag`] for an unusable value
    /// (see its docs).
    pub fn parse(raw: &'a str) -> Result<Self, DkimError> {
        let mut version = None;
        let mut algorithm = None;
        let mut signature = None;
        let mut body_hash = None;
        let mut canon = None;
        let mut domain = None;
        let mut selector = None;
        // Annotated explicitly: the collect target is otherwise left to a
        // diverging inference variable (rust issue #156047).
        let mut signed_headers: Option<Vec<&'a str>> = None;
        let mut identity = None;
        let mut body_length = None;
        let mut timestamp = None;
        let mut expiry = None;

        let mut seen = HashSet::new();
        for segment in raw.split(';') {
            let Some((name, value)) = segment.split_once('=') else {
                continue;
            };
            let name = trim_fws(name);
            let value = trim_fws(value);
            note_tag(&mut seen, name)?;
            match name {
                "v" => version = Some(value),
                "a" => algorithm = Some(value),
                "b" => signature = Some(value),
                "bh" => body_hash = Some(value),
                "c" => canon = Some(value),
                "d" => domain = Some(value),
                "s" => selector = Some(value),
                "i" => identity = Some(value),
                "h" => {
                    let headers: Vec<&str> = value
                        .split(':')
                        .map(trim_fws)
                        .filter(|h| !h.is_empty())
                        .collect();
                    if headers.len() > MAX_SIGNED_HEADERS {
                        return Err(DkimError::InvalidTag("h"));
                    }
                    signed_headers = Some(headers);
                }
                "l" => {
                    body_length = Some(
                        trim_fws(value)
                            .parse()
                            .map_err(|_| DkimError::InvalidTag("l"))?,
                    )
                }
                "t" => {
                    timestamp = Some(
                        trim_fws(value)
                            .parse()
                            .map_err(|_| DkimError::InvalidTag("t"))?,
                    )
                }
                "x" => {
                    expiry = Some(
                        trim_fws(value)
                            .parse()
                            .map_err(|_| DkimError::InvalidTag("x"))?,
                    )
                }
                _ => {} // q=, z= and unknown tags are not needed for verification
            }
        }

        let version = version.ok_or(DkimError::MissingTag("v"))?;
        if version != "1" {
            return Err(DkimError::InvalidTag("v"));
        }

        let (header_canon, body_canon) = match canon {
            Some(c) => match c.split_once('/') {
                Some((h, b)) => (h, b),
                None => (c, "simple"),
            },
            // RFC 6376 Section 3.5: default is "simple/simple".
            None => ("simple", "simple"),
        };

        let signed_headers = signed_headers.ok_or(DkimError::MissingTag("h"))?;
        if signed_headers.is_empty() {
            return Err(DkimError::InvalidTag("h"));
        }
        // RFC 6376 §6.1.1: a signature that doesn't sign From must be
        // ignored, or the From header could be replaced on a genuinely
        // signed message and still verify.
        if !signed_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case("from"))
        {
            return Err(DkimError::InvalidTag("h"));
        }

        // `d=` and `s=` name DNS names (the key lives at
        // `s._domainkey.d`), so neither can be longer than one: RFC 6376
        // §3.5 caps `d=` at 255 octets, and DNS caps any name at 253 in
        // text form. Refused here, before either is used: both are copied
        // into the delivered message, the spool metadata and the log.
        let domain = domain.ok_or(DkimError::MissingTag("d"))?;
        if domain.len() > MAX_DNS_NAME_LEN {
            return Err(DkimError::InvalidTag("d"));
        }
        let selector = selector.ok_or(DkimError::MissingTag("s"))?;
        if selector.len() > MAX_DNS_NAME_LEN {
            return Err(DkimError::InvalidTag("s"));
        }
        if identity.is_some_and(|i| i.len() > MAX_IDENTITY_LEN) {
            return Err(DkimError::InvalidTag("i"));
        }

        Ok(DkimSignature {
            version,
            algorithm: algorithm.ok_or(DkimError::MissingTag("a"))?,
            signature: signature.ok_or(DkimError::MissingTag("b"))?,
            body_hash: body_hash.ok_or(DkimError::MissingTag("bh"))?,
            header_canon,
            body_canon,
            domain,
            selector,
            signed_headers,
            identity,
            body_length,
            timestamp,
            expiry,
        })
    }

    /// Returns the DNS name to query for the public key:
    /// `{selector}._domainkey.{domain}`.
    pub fn key_query_name(&self) -> String {
        format!("{}._domainkey.{}", self.selector, self.domain)
    }

    /// Returns the hash algorithm named by `a=` (the part after the last
    /// '-', e.g. `sha256`).
    ///
    /// # Errors
    ///
    /// [`DkimError::UnsupportedAlgorithm`] when `a=` has no '-'.
    fn hash_algorithm(&self) -> Result<&'a str, DkimError> {
        self.algorithm
            .rsplit_once('-')
            .map(|(_, hash)| hash)
            .ok_or_else(|| DkimError::UnsupportedAlgorithm(self.algorithm.to_string()))
    }

    /// Returns the key algorithm of `a=` (`rsa` in `rsa-sha256`).
    ///
    /// # Errors
    ///
    /// [`DkimError::UnsupportedAlgorithm`] when `a=` has no `-`.
    fn key_algorithm(&self) -> Result<&'a str, DkimError> {
        self.algorithm
            .rsplit_once('-')
            .map(|(key, _)| key)
            .ok_or_else(|| DkimError::UnsupportedAlgorithm(self.algorithm.to_string()))
    }
}

/// One `DKIM-Signature` header found in a message, paired with its parsed
/// tags.
#[derive(Debug)]
pub struct ParsedSignature<'a, 'm> {
    /// The parsed signature tags.
    pub signature: DkimSignature<'m>,
    /// The raw header the signature was parsed from. Note the two
    /// lifetimes: the header lives inside the `RawMessage`, while the
    /// signature's tag values borrow from the original raw message bytes.
    pub header: &'a RawHeader<'m>,
}

/// Find every `DKIM-Signature` in `msg` (multiple are common and all must
/// be checked independently).
///
/// Returns the parsed signatures in header order (topmost first).
/// Signatures that are not valid UTF-8 or fail tag parsing are skipped.
pub fn find_signatures<'a, 'm>(msg: &'a RawMessage<'m>) -> Vec<ParsedSignature<'a, 'm>> {
    signatures(msg).collect()
}

/// The signatures of `msg`, as [`find_signatures`] finds them, parsed
/// lazily: a verifier that evaluates only the topmost [`MAX_SIGNATURES`]
/// takes them from here, so the headers after those are never parsed.
fn signatures<'a, 'm>(
    msg: &'a RawMessage<'m>,
) -> impl Iterator<Item = ParsedSignature<'a, 'm>> + 'a {
    msg.headers
        .iter()
        .filter(|h| h.name_eq("dkim-signature"))
        .filter_map(|h| {
            let raw = std::str::from_utf8(h.raw_value).ok()?;
            DkimSignature::parse(raw)
                .ok()
                .map(|signature| ParsedSignature {
                    signature,
                    header: h,
                })
        })
}

// ---------------------------------------------------------------------------
// Canonicalization (RFC 6376 Section 3.4)
// ---------------------------------------------------------------------------

/// Is byte `b` a WSP (space or tab)? RFC 6376 Section 3.4 folds
/// CRLF + WSP; WSP here is the character class test.
fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Returns `s` with folding whitespace (WSP, CR, LF) trimmed from both
/// ends.
fn trim_fws(s: &str) -> &str {
    s.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

/// Returns the tag value `s` with all folding whitespace (WSP, CR, LF)
/// removed (e.g. folded base64).
pub fn strip_fws(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect()
}

/// Returns `s` with folding whitespace (WSP, CR, LF) trimmed from both
/// ends.
fn trim_fws_bytes(s: &[u8]) -> &[u8] {
    let is_fws = |b: &u8| is_wsp(*b) || *b == b'\r' || *b == b'\n';
    let start = s.iter().position(|b| !is_fws(b)).unwrap_or(s.len());
    let end = s.iter().rposition(|b| !is_fws(b)).map_or(start, |i| i + 1);
    &s[start..end]
}

/// "relaxed" header canonicalization (RFC 6376 Section 3.4.2) of the
/// header `name` and raw `value`: lowercase the field name, delete WSP
/// around the colon, unfold, collapse WSP runs to a single SP, and delete
/// trailing WSP.
///
/// Returns `name:value` canonicalized, without a trailing CRLF.
pub fn relaxed_header(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + value.len() + 2);

    for &b in name {
        if is_wsp(b) {
            continue;
        }
        out.push(b.to_ascii_lowercase());
    }
    out.push(b':');

    // Unfold (drop CR/LF), collapse WSP runs to a single SP, drop leading
    // and trailing WSP.
    let mut pending_wsp = false;
    let mut started = false;
    for &b in value {
        match b {
            b'\r' | b'\n' => continue,
            b' ' | b'\t' => pending_wsp = true,
            _ => {
                if pending_wsp && started {
                    out.push(b' ');
                }
                out.push(b);
                started = true;
                pending_wsp = false;
            }
        }
    }
    out
}

/// "simple" header canonicalization: returns `name:value` exactly as it
/// appears, without a trailing CRLF.
pub fn simple_header(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + value.len() + 1);
    out.extend_from_slice(name);
    out.push(b':');
    out.extend_from_slice(value);
    out
}

/// Canonicalize the header `name`/`value` with the algorithm `alg`
/// ("relaxed" or "simple"; anything else falls back to "simple").
pub fn canonicalize_header(alg: &str, name: &[u8], value: &[u8]) -> Vec<u8> {
    match alg {
        "relaxed" => relaxed_header(name, value),
        _ => simple_header(name, value),
    }
}

/// "relaxed" canonicalization of `body` (RFC 6376 Section 3.4.4): per line, ignore
/// trailing WSP and reduce WSP runs to a single SP; then ignore trailing
/// whitespace-only lines. A non-empty canonicalized body ends with exactly
/// one CRLF; a completely empty body canonicalizes to a single CRLF.
pub fn relaxed_body(body: &[u8]) -> Vec<u8> {
    canonicalize_body("relaxed", body)
}

/// "simple" canonicalization of `body` (RFC 6376 Section 3.4.3): as-is,
/// except trailing empty lines are ignored and a missing final CRLF is
/// added. A completely empty body canonicalizes to a single CRLF.
pub fn simple_body(body: &[u8]) -> Vec<u8> {
    canonicalize_body("simple", body)
}

/// Canonicalize `body` with the algorithm `alg` ("relaxed" or "simple";
/// anything else falls back to "simple").
pub fn canonicalize_body(alg: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 2);
    canonical_body_into(alg, body, &mut |chunk| out.extend_from_slice(chunk));
    out
}

/// Stream the canonical form of `body` under `alg` ("relaxed"; anything
/// else is "simple") to `sink`, chunk by chunk, in one pass and without
/// allocating. Lines may end in CRLF or a bare LF.
///
/// The line structure of a body is attacker-chosen (a 10 MiB body can be
/// millions of one-byte lines), so nothing here is kept per line: trailing
/// empty lines are dropped by counting the empty lines seen and writing
/// them out only when a non-empty line follows.
fn canonical_body_into(alg: &str, body: &[u8], sink: &mut dyn FnMut(&[u8])) {
    let relaxed = alg == "relaxed";
    let mut pending_empty = 0usize;
    let mut wrote_any = false;
    for line in body.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        // Under relaxed, a line of only WSP canonicalizes to empty.
        let empty = if relaxed {
            line.iter().all(|&b| is_wsp(b))
        } else {
            line.is_empty()
        };
        if empty {
            pending_empty += 1;
            continue;
        }
        for _ in 0..pending_empty {
            sink(b"\r\n");
        }
        pending_empty = 0;
        if relaxed {
            // Each WSP run before text becomes one SP; trailing WSP is
            // never written.
            let mut pending_wsp = false;
            let mut i = 0;
            while i < line.len() {
                if is_wsp(line[i]) {
                    pending_wsp = true;
                    i += 1;
                    continue;
                }
                let start = i;
                while i < line.len() && !is_wsp(line[i]) {
                    i += 1;
                }
                if pending_wsp {
                    sink(b" ");
                    pending_wsp = false;
                }
                sink(&line[start..i]);
            }
        } else {
            sink(line);
        }
        sink(b"\r\n");
        wrote_any = true;
    }
    if !wrote_any {
        sink(b"\r\n");
    }
}

/// Returns the `DKIM-Signature` header value `raw_value` with the `b=`
/// tag's value deleted
/// (RFC 6376 Section 3.7: the signature header is included in the header
/// hash with `b=` treated as the empty string). The `b=` name and the `;`
/// separators are preserved.
fn dkim_sig_without_b(raw_value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw_value.len());
    for (i, segment) in raw_value.split(|&b| b == b';').enumerate() {
        if i > 0 {
            out.push(b';');
        }
        if let Some(eq) = segment.iter().position(|&b| b == b'=') {
            let name = trim_fws_bytes(&segment[..eq]);
            if name.eq_ignore_ascii_case(b"b") {
                // Keep everything up to and including "=", drop the value.
                out.extend_from_slice(&segment[..eq + 1]);
                continue;
            }
        }
        out.extend_from_slice(segment);
    }
    out
}

// ---------------------------------------------------------------------------
// Hashing (RFC 6376 Section 3.7)
// ---------------------------------------------------------------------------

/// Compute the base64 body hash (`bh=`) for signature `sig` over the raw
/// body of `msg`: canonicalize per the signature's body algorithm,
/// truncate to `l=` bytes if present, then hash with the algorithm named
/// by `a=`.
///
/// Returns the base64 digest.
///
/// # Errors
///
/// [`DkimError::UnsupportedAlgorithm`] for a hash other than SHA-256.
pub fn body_hash(msg: &RawMessage, sig: &DkimSignature) -> Result<String, DkimError> {
    match sig.hash_algorithm()? {
        "sha256" => {}
        other => return Err(DkimError::UnsupportedAlgorithm(other.to_string())),
    }
    // The canonical body is hashed as it is produced, never held: its
    // size and line count are the sender's choice.
    let mut hasher = Sha256::new();
    let mut remaining = sig.body_length.unwrap_or(usize::MAX);
    canonical_body_into(sig.body_canon, msg.body, &mut |chunk| {
        let take = chunk.len().min(remaining);
        hasher.update(&chunk[..take]);
        remaining -= take;
    });
    Ok(BASE64_STANDARD.encode(hasher.finalize()))
}

/// Check the body hash computed over `msg` against the `bh=` tag of
/// `sig`.
///
/// Returns `true` on an exact match, `false` on a mismatch (the classic
/// DKIM `permfail` body condition).
///
/// # Errors
///
/// The body hash itself could not be computed (see [`body_hash`]).
pub fn body_hash_matches(msg: &RawMessage, sig: &DkimSignature) -> Result<bool, DkimError> {
    Ok(body_hash(msg, sig)? == strip_fws(sig.body_hash))
}

/// Verify the body hash of every `DKIM-Signature` in `msg`.
///
/// Returns each parsed signature with its body-hash verdict (`false` also
/// when the hash can't be computed).
///
/// Note: a passing body hash alone does NOT prove the message is
/// authentic; [`verify_dkim`] also verifies `b=` against the published
/// public key.
pub fn verify_body_hashes<'m>(msg: &'m RawMessage<'m>) -> Vec<(DkimSignature<'m>, bool)> {
    find_signatures(msg)
        .into_iter()
        .map(|parsed| {
            let ok = body_hash_matches(msg, &parsed.signature).unwrap_or(false);
            (parsed.signature, ok)
        })
        .collect()
}

/// Build the byte string that the `b=` signature covers (RFC 6376
/// Sections 3.7 and 5.4.2): the canonicalized headers named by `h=`,
/// selected from the bottom of the header block upward with each header
/// instance used at most once, each followed by CRLF, and finally the
/// canonicalized `DKIM-Signature` header itself (with `b=` emptied) without
/// a trailing CRLF.
///
/// `sig` is the signature parsed from `sig_header`, a header of `msg`.
/// This never returns `Err` today; the `Result` leaves room for
/// canonicalization failures.
pub fn signed_header_data(
    msg: &RawMessage,
    sig: &DkimSignature,
    sig_header: &RawHeader,
) -> Result<Vec<u8>, DkimError> {
    // Index the header instances by lowercased name once, in message order,
    // so selection is linear in h= entries + headers. Footgun: scanning the
    // whole header list per h= entry is O(h × headers), and both are
    // attacker-controlled; one message could pin a worker for minutes. Only
    // names that h= lists are indexed.
    let wanted: HashSet<String> = sig
        .signed_headers
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    let mut instances: HashMap<String, Vec<&RawHeader>> = HashMap::new();
    for h in &msg.headers {
        let Ok(name) = std::str::from_utf8(h.name) else {
            continue; // h= names are ASCII; a non-UTF-8 name can't match
        };
        let name = name.to_ascii_lowercase();
        if wanted.contains(&name) {
            instances.entry(name).or_default().push(h);
        }
    }

    let mut selected: Vec<&RawHeader> = Vec::new();
    for want in &sig.signed_headers {
        // Bottom-up: popping takes the last unused instance of each signed
        // header. A header listed in h= but absent (or already used)
        // contributes nothing (RFC 6376 Section 5.4.2).
        if let Some(h) = instances
            .get_mut(&want.to_ascii_lowercase())
            .and_then(Vec::pop)
        {
            selected.push(h);
        }
    }

    let mut data = Vec::new();
    for h in selected {
        data.extend_from_slice(&canonicalize_header(sig.header_canon, h.name, h.raw_value));
        data.extend_from_slice(b"\r\n");
    }

    let without_b = dkim_sig_without_b(sig_header.raw_value);
    data.extend_from_slice(&canonicalize_header(
        sig.header_canon,
        sig_header.name,
        &without_b,
    ));

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mailparse::parse_raw_message;

    // A real-world-style signed message (trimmed from an actual received
    // mail). The bh= tag below is the hash of this fixture's body
    // (cross-checked against openssl), not of the original message's.
    const TEST_MESSAGE: &str = r#"Delivered-To: jrperson@gmail.com
Received: by 2002:a05:6841:8607:b0:18c1:ca90:59ae with SMTP id mh7csp748466nlc;
        Fri, 1 Nov 2024 18:16:08 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@protonmail.com header.s=protonmail3 header.b=OcGMbHQ7;
       spf=pass smtp.mailfrom=jason.person@protonmail.com
Return-Path: <jason.person@protonmail.ch>
Received: from mail-40140.protonmail.ch (mail-40140.protonmail.ch. [185.70.40.140])
        by mx.google.com with ESMTPS id ffacd0b85a97d-381c10cd3cbsi3282451f8f.50.2024.11.01.18.16.08
        for <jrperson@gmail.com>;
        Fri, 01 Nov 2024 18:16:08 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=protonmail.com; s=protonmail3; t=1730510168; x=1730769368; bh=LoQNOtBdVrW1DkKLO+B8DbyvRjaJPX2KKa3t84PnfxY=; h=Date:To:From:Subject:Message-ID:Feedback-ID:From:To:Cc:Date:
	 Subject:Reply-To:Feedback-ID:Message-ID:BIMI-Selector:
	 List-Unsubscribe:List-Unsubscribe-Post; b=OcGMbHQ7D6awrQVpP/eSLuPPz8cUpAuPS+IegdH602vdGJcgEHHGGG2VSghVbIX
	 9R51b1Jcuf23BFIClp/mpdaGQSNOJ2YLiS9iE0MG+NeO2nMTDui8mObGj5g0ZmSlCV
	 dXMlV6KdvNXpA==
Date: Sat, 02 Nov 2024 01:16:06 +0000
To: "jrperson@gmail.com" <jrperson@gmail.com>
From: Jason Person <jason.person@protonmail.com>
Subject: Test
Message-ID: <zuZRjJOl1NxzLHjkiYvxLU6XuKH9KZ2UnlMXEZmWnFTHP9Qyh5XX71DDO9WerlL4O2_feN8gF1oJ5wq3K6pZWq_7d2GZ7F8UNZOgq0Dr8g=@protonmail.com>
Feedback-ID: 3806480:user:proton
X-Pm-Message-ID: 5fe347cca9a4a7d19512d22b89519abebb39badd
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4"

--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64

VGVzdA==
--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: base64

PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PjxkaXYgZGlyPSJhdXRvPlRlc3Q8L2Rpdj48L2JvZHk
+CjwvaHRtbD4=
--b1=_DAe4ebKwgsZsACinmSR6tfFOA3greGoFYImur3b4--
"#;

    /// The test message with CRLF line endings, as DKIM canonicalization
    /// would see it on the wire.
    fn message_bytes() -> Vec<u8> {
        TEST_MESSAGE.replace('\n', "\r\n").into_bytes()
    }

    /// The parsed test message, borrowed for 'static (the backing bytes
    /// are intentionally leaked; fine for tests).
    fn parsed() -> mailparse::RawMessage<'static> {
        // Leaks the message bytes so the RawMessage can borrow them with
        // 'static; fine for tests.
        let bytes: &'static [u8] = Box::leak(message_bytes().into_boxed_slice());
        parse_raw_message(bytes).unwrap()
    }

    /// RFC 6376 Section 3.4.5's own relaxed header example, plus the
    /// collapse rules the RFC pins down.
    #[test]
    fn test_relaxed_headers_canonicalization() {
        // RFC 6376 Section 3.4.5 example: "A: X\r\nB : Y\t\r\n\t Z  \r\n"
        // canonicalizes to "a:X\r\nb:Y Z\r\n".
        assert_eq!(relaxed_header(b"A", b" X"), b"a:X");
        assert_eq!(relaxed_header(b"B ", b"Y \t\r\n\t Z  "), b"b:Y Z");
    }

    /// Simple header canonicalization keeps the header byte-exact.
    #[test]
    fn test_simple_header_canonicalization() {
        assert_eq!(simple_header(b"A", b" X\r\n"), b"A: X\r\n");
    }

    /// Relaxed body canonicalization: strip trailing WSP per line,
    /// collapse interior WSP runs, remove trailing empty lines.
    #[test]
    fn test_relaxed_body_canonicalization() {
        // RFC 6376 Section 3.4.5 example.
        let body = b" C \r\nD \t E\r\n\r\n\r\n";
        assert_eq!(relaxed_body(body), b" C\r\nD E\r\n");
    }

    /// The RFC 6376 Section 3.4.3/3.4.4 edge cases: empty bodies,
    /// missing final CRLF, and empty-line handling for both algorithms.
    #[test]
    fn test_body_canonicalization_edges() {
        // Trailing empty lines collapse to a single CRLF.
        assert_eq!(relaxed_body(b"abc\r\n\r\n\r\n"), b"abc\r\n");
        assert_eq!(simple_body(b"abc\r\n\r\n\r\n"), b"abc\r\n");
        // Missing final CRLF is added.
        assert_eq!(relaxed_body(b"abc"), b"abc\r\n");
        assert_eq!(simple_body(b"abc"), b"abc\r\n");
        // Whitespace-only lines count as empty for relaxed, but not simple.
        assert_eq!(relaxed_body(b"abc\r\n \t\r\n"), b"abc\r\n");
        assert_eq!(simple_body(b"abc\r\n \t\r\n"), b"abc\r\n \t\r\n");
        // A completely empty body is a single CRLF.
        assert_eq!(relaxed_body(b""), b"\r\n");
        assert_eq!(simple_body(b""), b"\r\n");
    }

    /// Every DKIM-Signature tag parses into the right field, including
    /// folded `b=` values.
    #[test]
    fn test_parse_signature_tags() {
        let raw = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=protonmail.com; \
                   s=protonmail3; t=1730510168; x=1730769368; \
                   bh=evU+ZAhaA7uoDunwy9tpxgyXQlVvxX0ZJTSDyRIcuew=; \
                   h=Date:To:From:Subject; i=@protonmail.com; b=OcGMbHQ7D6awrQVpP/eSLuPPz8cUpAuPS\r\n\t dXMlV6KdvNXpA==";
        let sig = DkimSignature::parse(raw).unwrap();

        assert_eq!(sig.version, "1");
        assert_eq!(sig.algorithm, "rsa-sha256");
        assert_eq!(sig.header_canon, "relaxed");
        assert_eq!(sig.body_canon, "relaxed");
        assert_eq!(sig.domain, "protonmail.com");
        assert_eq!(sig.selector, "protonmail3");
        assert_eq!(sig.timestamp, Some(1730510168));
        assert_eq!(sig.expiry, Some(1730769368));
        assert_eq!(
            sig.body_hash,
            "evU+ZAhaA7uoDunwy9tpxgyXQlVvxX0ZJTSDyRIcuew="
        );
        assert_eq!(sig.signed_headers, vec!["Date", "To", "From", "Subject"]);
        assert_eq!(sig.identity, Some("@protonmail.com"));
        assert_eq!(
            sig.key_query_name(),
            "protonmail3._domainkey.protonmail.com"
        );
        // The b= value keeps its folds; strip_fws yields pure base64.
        assert_eq!(
            strip_fws(sig.signature),
            "OcGMbHQ7D6awrQVpP/eSLuPPz8cUpAuPSdXMlV6KdvNXpA=="
        );
    }

    /// Malformed signature tag lists are rejected: wrong version,
    /// missing required tags, empty `h=`; `c=` with only the header
    /// algorithm defaults the body algorithm to simple.
    #[test]
    fn test_parse_rejects_missing_and_invalid_tags() {
        assert!(DkimSignature::parse("v=2; a=rsa-sha256; b=x; bh=x; d=d; s=s; h=From").is_err());
        assert!(DkimSignature::parse("a=rsa-sha256; b=x; bh=x; d=d; s=s; h=From").is_err());
        assert!(DkimSignature::parse("v=1; a=rsa-sha256; b=x; bh=x; d=d; s=s; h=").is_err());
        // c= with only the header algorithm defaults the body to simple.
        let sig = DkimSignature::parse("v=1; a=rsa-sha256; b=x; bh=x; d=d; s=s; h=From; c=relaxed")
            .unwrap();
        assert_eq!((sig.header_canon, sig.body_canon), ("relaxed", "simple"));
    }

    /// Removing the `b=` value for signing produces the signed form:
    /// the tag name and separators survive, the value is gone.
    #[test]
    fn test_dkim_sig_without_b() {
        let raw = b"v=1; a=rsa-sha256; d=x.com; s=s; bh=abc=; h=From; b=OcGM\r\n\t bHQ7==";
        assert_eq!(
            dkim_sig_without_b(raw),
            b"v=1; a=rsa-sha256; d=x.com; s=s; bh=abc=; h=From; b="
        );
    }

    /// The computed body hash of the test message matches the fixture's
    /// `bh=` value, and the comparison helpers agree.
    #[test]
    fn body_hash_of_signed_message() {
        let msg = parsed();
        let sigs = find_signatures(&msg);
        assert_eq!(sigs.len(), 1);

        let sig = &sigs[0].signature;
        assert_eq!(sig.domain, "protonmail.com");
        assert_eq!(sig.body_canon, "relaxed");

        let computed = body_hash(&msg, sig).unwrap();
        assert_eq!(
            computed, "LoQNOtBdVrW1DkKLO+B8DbyvRjaJPX2KKa3t84PnfxY=",
            "computed body hash must match the signature's bh= tag"
        );

        assert!(body_hash_matches(&msg, sig).unwrap());
        assert_eq!(verify_body_hashes(&msg), vec![(sig.clone(), true)]);
    }

    /// The signed header data of a real-world-shaped message is
    /// assembled in `h=` order with canonicalization and CRLF folding
    /// exactly as RFC 6376 Section 3.7 prescribes.
    #[test]
    fn signed_header_data_of_real_message() {
        let msg = parsed();
        let sigs = find_signatures(&msg);
        let parsed = &sigs[0];

        let data = signed_header_data(&msg, &parsed.signature, parsed.header).unwrap();

        // First h= entry is Date; relaxed-canonicalized, each header is
        // followed by CRLF.
        assert!(data.starts_with(b"date:Sat, 02 Nov 2024 01:16:06 +0000\r\n"));
        // The DKIM-Signature (b= emptied) is last, with no trailing CRLF.
        assert!(data.ends_with(b"b="));
        // All six distinct signed headers present in the message are
        // included exactly once each (h= lists several names twice, but the
        // message has only one instance of each).
        let expected_lines: [&[u8]; 4] = [
            b"date:Sat, 02 Nov 2024 01:16:06 +0000\r\n",
            b"to:\"jrperson@gmail.com\" <jrperson@gmail.com>\r\n",
            b"from:Jason Person <jason.person@protonmail.com>\r\n",
            b"subject:Test\r\n",
        ];
        for line in expected_lines {
            assert!(
                data.windows(line.len()).any(|w| w == line),
                "signed header data is missing: {:?}",
                String::from_utf8_lossy(line)
            );
        }
    }

    /// RFC 6376 Section 5.4.2: `h=` selects headers bottom-up, and each
    /// header instance is used at most once - over-subscription stops
    /// at the instances that exist.
    #[test]
    fn header_selection_is_bottom_up_and_single_use() {
        let raw = b"X-Test: one\r\nSubject: s\r\nX-Test: two\r\n\r\nbody\r\n";
        let msg = parse_raw_message(raw).unwrap();

        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=abc; bh=abc; d=x.com; s=sel; c=relaxed/relaxed; h=from:x-test:x-test",
        )
        .unwrap();
        // Stand-in signature header (its own b= handling is tested above).
        let stand_in = msg.headers.iter().find(|h| h.name_eq("subject")).unwrap();

        let data = signed_header_data(&msg, &sig, stand_in).unwrap();
        // Bottom-up: "two" is selected before "one".
        assert!(data.starts_with(b"x-test:two\r\nx-test:one\r\n"));
        // The signature header itself is appended last, without trailing CRLF.
        assert!(data.ends_with(b"subject:s"));
    }

    /// DKIM key record tags parse: key type, public key, service type,
    /// flags, and the hash restriction list.
    #[test]
    fn test_parse_key_record() {
        let key = DkimKeyRecord::parse("v=DKIM1; k=rsa; p=MIIBIjAN; s=email; t=s:y; h=sha256:sha1")
            .unwrap();
        assert_eq!(key.version, "DKIM1");
        assert_eq!(key.key_type, "rsa");
        assert_eq!(key.public_key, "MIIBIjAN");
        assert_eq!(key.service, vec!["email"]);
        assert_eq!(key.flags, vec!["s", "y"]);
        assert_eq!(key.hashes, vec!["sha256", "sha1"]);
        assert!(key.permits_email());
        assert!(key.accepts_hash("sha256"));
        assert!(!key.accepts_hash("sha512"));

        // Defaults per RFC 6376 Section 3.6.1.
        let default = DkimKeyRecord::parse("p=abc").unwrap();
        assert_eq!(default.key_type, "rsa");
        assert_eq!(default.service, vec!["*"]);
        assert!(default.hashes.is_empty());
        assert!(default.accepts_hash("sha256"));
        assert!(default.version_ok());
        assert!(default.permits_email());
        assert!(!default.strict_identity());

        // A missing p= tag is unusable; an empty one means revoked.
        assert!(DkimKeyRecord::parse("v=DKIM1; k=rsa").is_err());
        let revoked = DkimKeyRecord::parse("v=DKIM1; p=").unwrap();
        assert!(strip_fws(&revoked.public_key).is_empty());

        // An unknown version is rejected by verification, not parsing.
        let bad_version = DkimKeyRecord::parse("v=DKIM2; p=abc").unwrap();
        assert!(!bad_version.version_ok());
    }

    /// RFC 6376 Section 3.6.1 AUID alignment: `i=` equal to or a
    /// subdomain of `d=` aligns, unless the key record sets `t=s`.
    #[test]
    fn test_auid_matching() {
        let key = DkimKeyRecord::parse("v=DKIM1; p=abc").unwrap();
        let parse_i = |i: &'static str| DkimSignature::parse(i).unwrap();

        let sub =
            parse_i("v=1; a=rsa-sha256; b=x; bh=x; d=example.org; s=s; h=From; i=@sub.example.org");
        let same =
            parse_i("v=1; a=rsa-sha256; b=x; bh=x; d=example.org; s=s; h=From; i=@example.org");
        let upper =
            parse_i("v=1; a=rsa-sha256; b=x; bh=x; d=example.org; s=s; h=From; i=user@EXAMPLE.ORG");
        let other =
            parse_i("v=1; a=rsa-sha256; b=x; bh=x; d=example.org; s=s; h=From; i=@other.net");
        let prefix =
            parse_i("v=1; a=rsa-sha256; b=x; bh=x; d=example.org; s=s; h=From; i=@notexample.org");

        assert!(auid_matches(&sub, &key)); // subdomain
        assert!(auid_matches(&same, &key)); // exact
        assert!(auid_matches(&upper, &key)); // case-insensitive
        assert!(!auid_matches(&other, &key));
        assert!(!auid_matches(&prefix, &key)); // no prefix match

        // t=s: the AUID domain must equal d= exactly.
        let strict = DkimKeyRecord::parse("v=DKIM1; p=abc; t=s").unwrap();
        assert!(!auid_matches(&sub, &strict));
        assert!(auid_matches(&same, &strict));

        // No i= tag: always aligned.
        let no_i = DkimSignature::parse("v=1; a=rsa-sha256; b=x; bh=x; d=example.org; s=s; h=From")
            .unwrap();
        assert!(auid_matches(&no_i, &key));
    }

    /// The `x=` expiry comparison: exactly at the timestamp is not yet
    /// expired, one second later is.
    #[test]
    fn test_expiry() {
        let sig =
            DkimSignature::parse("v=1; a=rsa-sha256; b=x; bh=x; d=d; s=s; h=From; x=1000").unwrap();
        assert!(is_expired(&sig, 1001));
        assert!(!is_expired(&sig, 1000)); // x= == now is not yet expired
        assert!(!is_expired(&sig, 999));

        let no_x = DkimSignature::parse("v=1; a=rsa-sha256; b=x; bh=x; d=d; s=s; h=From").unwrap();
        assert!(!is_expired(&no_x, u64::MAX));
    }

    /// RSA end-to-end: sign the test message's DKIM-Signature with a
    /// generated RSA key, publish the matching key record, and verify -
    /// the full RFC 6376 verification path.
    #[test]
    fn rsa_sign_and_verify_end_to_end() {
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::EncodePublicKey as _;
        use rsa::signature::Signer;

        let mut rng = rand_core::OsRng;
        let private = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let public_der = private.to_public_key().to_public_key_der().unwrap();
        let key = DkimKeyRecord::parse(&format!(
            "v=DKIM1; k=rsa; p={}",
            BASE64_STANDARD.encode(public_der.as_bytes())
        ))
        .unwrap();

        let template = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=sel1;\r\n\th=From:Subject; bh=PLACEHOLDER_BH; b=PLACEHOLDER_SIG\r\nFrom: Test Sender <test@example.org>\r\nSubject: Sign test\r\n\r\nTest body.\r\n";

        // 1. Compute the real body hash and splice it in (the bh= tag is
        //    itself signed, so it must be final before signing).
        let step0 = parse_raw_message(template.as_bytes()).unwrap();
        let sig0 = &find_signatures(&step0)[0].signature;
        let bh = body_hash(&step0, sig0).unwrap();
        let step1 = template.replace("PLACEHOLDER_BH", &bh);

        // 2. Build the signed header data. The b= value is deleted from the
        //    data, so the placeholder never enters the signature.
        let msg1 = parse_raw_message(step1.as_bytes()).unwrap();
        let parsed1 = &find_signatures(&msg1)[0];
        let data = signed_header_data(&msg1, &parsed1.signature, parsed1.header).unwrap();

        // 3. Sign and splice the signature in.
        let signing_key: SigningKey<rsa::sha2::Sha256> = SigningKey::new(private);
        let signature = signing_key.sign(&data);
        let sig_bytes: Box<[u8]> = signature.into();
        let final_message = step1.replace("PLACEHOLDER_SIG", &BASE64_STANDARD.encode(sig_bytes));

        // 4. Verify the intact message.
        let final_bytes = final_message.as_bytes().to_vec();
        let msg = parse_raw_message(&final_bytes).unwrap();
        let parsed = &find_signatures(&msg)[0];
        let result = verify_with_key(&msg, parsed, &key, 0);
        assert!(result.body_hash_ok, "body hash should match");
        assert!(result.signature_ok, "signature should verify");
        assert_eq!(result.error, None);

        // 5. Tampered signed header: body hash still matches, signature
        //    fails.
        let tampered_hdr = final_message.replace("Sign test", "Sign test!");
        let msg2 = parse_raw_message(tampered_hdr.as_bytes()).unwrap();
        let parsed2 = &find_signatures(&msg2)[0];
        let r2 = verify_with_key(&msg2, parsed2, &key, 0);
        assert!(r2.body_hash_ok);
        assert!(!r2.signature_ok);

        // 6. Tampered body: body hash fails, but the signature still
        //    verifies — it covers the bh= tag as written, not the body.
        //    Overall DKIM verdict must require BOTH to pass.
        let tampered_body = final_message.replace("Test body.", "Test body tampered.");
        let msg3 = parse_raw_message(tampered_body.as_bytes()).unwrap();
        let parsed3 = &find_signatures(&msg3)[0];
        let r3 = verify_with_key(&msg3, parsed3, &key, 0);
        assert!(!r3.body_hash_ok);
        assert!(r3.signature_ok);
    }

    /// Ed25519 end-to-end (RFC 8463): sign with a generated Ed25519
    /// key and verify through the same path.
    #[test]
    fn ed25519_sign_and_verify_end_to_end() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let mut rng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let key = DkimKeyRecord::parse(&format!(
            "v=DKIM1; k=ed25519; p={}",
            BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes())
        ))
        .unwrap();

        let template = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org; s=sel1;\r\n\th=From:Subject; bh=PLACEHOLDER_BH; b=PLACEHOLDER_SIG\r\nFrom: Ed Example <ed@example.org>\r\nSubject: Ed sign test\r\n\r\nEd test body.\r\n";

        let step0 = parse_raw_message(template.as_bytes()).unwrap();
        let sig0 = &find_signatures(&step0)[0].signature;
        let bh = body_hash(&step0, sig0).unwrap();
        let step1 = template.replace("PLACEHOLDER_BH", &bh);

        let msg1 = parse_raw_message(step1.as_bytes()).unwrap();
        let parsed1 = &find_signatures(&msg1)[0];
        let data = signed_header_data(&msg1, &parsed1.signature, parsed1.header).unwrap();

        // RFC 8463: PureEdDSA over the SHA-256 digest of the canonicalized
        // signed header data.
        let signature = signing_key.sign(Sha256::digest(&data).as_slice());
        let final_message = step1.replace(
            "PLACEHOLDER_SIG",
            &BASE64_STANDARD.encode(signature.to_bytes()),
        );

        // Positive: intact message verifies.
        let final_bytes = final_message.as_bytes().to_vec();
        let msg = parse_raw_message(&final_bytes).unwrap();
        let parsed = &find_signatures(&msg)[0];
        let result = verify_with_key(&msg, parsed, &key, 0);
        assert!(result.body_hash_ok, "body hash should match");
        assert!(result.signature_ok, "signature should verify");
        assert_eq!(result.error, None);

        // Negative: tampered signed header fails verification.
        let tampered = final_message.replace("Ed sign test", "Ed sign test!");
        let msg2 = parse_raw_message(tampered.as_bytes()).unwrap();
        let parsed2 = &find_signatures(&msg2)[0];
        let r2 = verify_with_key(&msg2, parsed2, &key, 0);
        assert!(r2.body_hash_ok);
        assert!(!r2.signature_ok);

        // Negative: an Ed25519 key must not verify via an RSA key record.
        let wrong_type = DkimKeyRecord::parse(&format!(
            "v=DKIM1; k=rsa; p={}",
            BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes())
        ))
        .unwrap();
        let r3 = verify_with_key(&msg, parsed, &wrong_type, 0);
        assert!(!r3.signature_ok);
        assert_eq!(
            r3.error,
            Some(DkimError::KeyTypeMismatch {
                signature: "ed25519".into(),
                key: "rsa".into()
            }),
            "refused before any cryptography (RFC 6376 section 6.1.2)"
        );
    }

    /// RFC 6376 section 3.2: a tag that occurs twice invalidates the whole
    /// tag list, in a signature (where two `d=` could be read differently)
    /// and in a key record.
    #[test]
    fn duplicate_tags_invalidate_the_tag_list() {
        let sig = "v=1; a=rsa-sha256; d=good.example; s=s; h=From; bh=x; b=y; d=evil.example";
        assert_eq!(
            DkimSignature::parse(sig).unwrap_err(),
            DkimError::DuplicateTag("d".into())
        );
        assert!(
            DkimSignature::parse("v=1; a=rsa-sha256; d=good.example; s=s; h=From; bh=x; b=y")
                .is_ok()
        );
        assert_eq!(
            DkimKeyRecord::parse("v=DKIM1; k=rsa; p=AAAA; p=BBBB").unwrap_err(),
            DkimError::DuplicateTag("p".into())
        );
    }

    /// A signature made by a different key must not verify: the body
    /// hash may match, the signature must not.
    #[test]
    fn verify_rejects_mismatched_key() {
        use rsa::pkcs8::EncodePublicKey as _;

        // A DIFFERENT key than the one that signed: the signature must not
        // verify.
        let mut rng = rand_core::OsRng;
        let other = rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let other_der = other.to_public_key().to_public_key_der().unwrap();
        let wrong_key = DkimKeyRecord::parse(&format!(
            "v=DKIM1; k=rsa; p={}",
            BASE64_STANDARD.encode(other_der.as_bytes())
        ))
        .unwrap();

        let msg = parsed();
        let parsed = &find_signatures(&msg)[0];
        let result = verify_with_key(&msg, parsed, &wrong_key, 0);
        assert!(!result.signature_ok);
    }

    /// No matter how many signature headers a message carries, at most MAX_SIGNATURES are evaluated (each one
    /// costs a DNS lookup, a body hash, and a public-key operation). The
    /// resolver points at a closed local port, so every key lookup fails
    /// fast and offline.
    #[tokio::test]
    async fn signature_count_is_capped() {
        let mut raw = Vec::new();
        for i in 0..50 {
            raw.extend_from_slice(
                format!(
                    "DKIM-Signature: v=1; a=rsa-sha256; d=d{i}.invalid; s=s; h=From; bh=AAAA; b=AAAA\r\n"
                )
                .as_bytes(),
            );
        }
        raw.extend_from_slice(b"From: a@example.org\r\n\r\nbody\r\n");

        let resolver = DnsClient::with_timeout(
            "127.0.0.1".parse().unwrap(),
            std::time::Duration::from_millis(500),
        );
        let results = verify_dkim(&raw, &resolver).await;
        assert_eq!(results.len(), MAX_SIGNATURES);
        // The topmost signatures are the ones evaluated.
        assert_eq!(results[0].signature.domain, "d0.invalid");
    }

    /// Sign `template` (with `PLACEHOLDER_BH`/`PLACEHOLDER_SIG` in its
    /// DKIM-Signature) with a fresh Ed25519 key; returns the signed bytes
    /// and the matching key record.
    fn ed25519_signed(template: &[u8]) -> (Vec<u8>, DkimKeyRecord) {
        use ed25519_dalek::{Signer as _, SigningKey};

        fn replace(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
            let at = hay.windows(from.len()).position(|w| w == from).unwrap();
            [&hay[..at], to, &hay[at + from.len()..]].concat()
        }

        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let key = DkimKeyRecord::parse(&format!(
            "v=DKIM1; k=ed25519; p={}",
            BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes())
        ))
        .unwrap();

        let step0 = parse_raw_message(template).unwrap();
        let bh = body_hash(&step0, &find_signatures(&step0)[0].signature).unwrap();
        let step1 = replace(template, b"PLACEHOLDER_BH", bh.as_bytes());
        let msg1 = parse_raw_message(&step1).unwrap();
        let parsed1 = &find_signatures(&msg1)[0];
        let data = signed_header_data(&msg1, &parsed1.signature, parsed1.header).unwrap();
        let signature = signing_key.sign(Sha256::digest(&data).as_slice());
        let signed = replace(
            &step1,
            b"PLACEHOLDER_SIG",
            BASE64_STANDARD.encode(signature.to_bytes()).as_bytes(),
        );
        (signed, key)
    }

    /// DKIM works on the raw view, so a signed message whose headers the
    /// typed grammar rejects — non-UTF-8 bytes, or comments nested past
    /// mailparse's bound — still verifies, and deep nesting never reaches
    /// the recursive grammar at all.
    #[test]
    fn verifies_messages_the_typed_parser_rejects() {
        let deep = format!("{}{}", "(".repeat(100_000), ")".repeat(100_000));
        let templates: [Vec<u8>; 2] = [
            b"DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org; s=sel1; h=From:Subject; bh=PLACEHOLDER_BH; b=PLACEHOLDER_SIG\r\nFrom: ed@example.org\r\nSubject: caf\xe9\r\n\r\nbody\r\n".to_vec(),
            format!("DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org; s=sel1; h=From:Received; bh=PLACEHOLDER_BH; b=PLACEHOLDER_SIG\r\nReceived: {deep}a@b\r\nFrom: ed@example.org\r\n\r\nbody\r\n").into_bytes(),
        ];
        for template in templates {
            assert!(mailparse::parse_message(&template).is_err());
            let (signed, key) = ed25519_signed(&template);
            // On a worker-sized stack, as in the server.
            let ok = std::thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || {
                    let msg = parse_raw_message(&signed).unwrap();
                    let parsed = &find_signatures(&msg)[0];
                    let r = verify_with_key(&msg, parsed, &key, 0);
                    r.body_hash_ok && r.signature_ok
                })
                .unwrap()
                .join()
                .unwrap();
            assert!(ok, "signature should verify");
        }
    }

    /// Header selection with the per-name index keeps RFC 6376 §5.4.2
    /// semantics: bottom-up, each instance used once, case-insensitive,
    /// absent or exhausted names contribute nothing.
    #[test]
    fn signed_header_selection_order() {
        let raw = b"X-A: 1\r\nx-b: 2\r\nX-A: 3\r\nDKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=d; s=s; bh=x; b=; h=x-a:X-B:X-A:X-A:missing:from\r\n\r\n";
        let msg = parse_raw_message(raw).unwrap();
        let parsed = &find_signatures(&msg)[0];
        let data = signed_header_data(&msg, &parsed.signature, parsed.header).unwrap();
        let data = String::from_utf8(data).unwrap();
        assert!(
            data.starts_with("X-A: 3\r\nx-b: 2\r\nX-A: 1\r\nDKIM-Signature:"),
            "{data:?}"
        );
    }

    /// An `h=` list over MAX_SIGNED_HEADERS is refused, and selection is
    /// linear: a list at the cap against 200,000 headers finishes promptly.
    #[test]
    fn signed_header_list_is_bounded_and_linear() {
        let names = |n: usize| vec!["z"; n].join(":");
        let too_long = format!(
            "v=1; a=rsa-sha256; d=d; s=s; bh=x; b=x; h=from:{}",
            names(MAX_SIGNED_HEADERS)
        );
        assert!(matches!(
            DkimSignature::parse(&too_long),
            Err(DkimError::InvalidTag("h"))
        ));

        let mut raw = format!(
            "DKIM-Signature: v=1; a=rsa-sha256; d=d; s=s; bh=x; b=x; h=from:{}\r\n",
            names(MAX_SIGNED_HEADERS - 1)
        );
        for i in 0..200_000 {
            raw.push_str(&format!("X-F{i}: v\r\n"));
        }
        raw.push_str("\r\nbody\r\n");
        let msg = parse_raw_message(raw.as_bytes()).unwrap();
        let parsed = &find_signatures(&msg)[0];
        let started = std::time::Instant::now();
        signed_header_data(&msg, &parsed.signature, parsed.header).unwrap();
        // A quadratic scan would be ~51M comparisons here; linear is ~1 ms.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
    }

    /// Fetches protonmail's real DKIM key over DNS-over-TLS. Opt-in, because
    /// it touches the network.
    #[tokio::test]
    #[ignore = "hits live DNS (DoT to 1.1.1.1)"]
    async fn live_fetch_public_key() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=x; bh=x; d=protonmail.com; s=protonmail3; h=From",
        )
        .unwrap();
        let resolver = DnsClient::new("1.1.1.1".parse().unwrap());
        let key = fetch_public_key(&resolver, &sig).await.unwrap();
        assert_eq!(key.key_type, "rsa");
        assert!(key.public_key.len() > 100, "key material looks truncated");
    }
}

// ---------------------------------------------------------------------------
// Public key records and cryptographic verification (RFC 6376 Sections
// 3.6, 6.1)
// ---------------------------------------------------------------------------

/// A parsed DKIM key record: the TXT record at
/// `{selector}._domainkey.{domain}`. Values are owned because the record is
/// usually fetched over DNS.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DkimKeyRecord {
    /// `v=` — key record version; verifiers accept values beginning with
    /// "DKIM1" (case-insensitive).
    pub version: String,
    /// `k=` — key type; defaults to "rsa".
    pub key_type: String,
    /// `p=` — base64 public key (DER-encoded SubjectPublicKeyInfo for RSA).
    /// An empty value means the key was revoked.
    pub public_key: String,
    /// `s=` — service types; defaults to all (`*`).
    pub service: Vec<String>,
    /// `t=` — flags (`y` = testing, `s` = strict identity), `:`-separated.
    pub flags: Vec<String>,
    /// `h=` — acceptable hash algorithms; empty means all are acceptable.
    pub hashes: Vec<String>,
}

impl DkimKeyRecord {
    /// Parse the tag list `raw` of a DKIM key TXT record, applying the
    /// defaults (`k=rsa`, `s=*`). An empty `p=` (revocation) parses; it is
    /// refused at verification.
    ///
    /// # Errors
    ///
    /// [`DkimError::InvalidKey`] when there is no `p=` tag, and
    /// [`DkimError::DuplicateTag`] when a tag occurs twice.
    pub fn parse(raw: &str) -> Result<Self, DkimError> {
        let mut version = String::new();
        let mut key_type = String::new();
        let mut public_key = None;
        let mut service = Vec::new();
        let mut flags = Vec::new();
        let mut hashes = Vec::new();

        let mut seen = HashSet::new();
        for segment in raw.split(';') {
            let Some((name, value)) = segment.split_once('=') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            note_tag(&mut seen, name)?;
            match name {
                "v" => version = value.to_string(),
                "k" => key_type = value.to_string(),
                "p" => public_key = Some(value.to_string()),
                "s" => service = value.split(':').map(str::trim).map(String::from).collect(),
                "t" => flags = value.split(':').map(str::trim).map(String::from).collect(),
                "h" => hashes = value.split(':').map(str::trim).map(String::from).collect(),
                _ => {} // n= and unknown tags are irrelevant to verification
            }
        }

        let public_key = public_key.ok_or(DkimError::InvalidKey("missing p= tag".to_string()))?;

        Ok(DkimKeyRecord {
            version,
            key_type: if key_type.is_empty() {
                "rsa".to_string()
            } else {
                key_type
            },
            public_key,
            service: if service.is_empty() {
                vec!["*".to_string()]
            } else {
                service
            },
            flags,
            hashes,
        })
    }

    /// Whether the record permits use for email (RFC 6376 Section 3.6.1.4).
    fn permits_email(&self) -> bool {
        self.service
            .iter()
            .any(|s| s == "*" || s.eq_ignore_ascii_case("email"))
    }

    /// Whether `hash` (e.g. "sha256") is acceptable; an empty `h=` tag
    /// accepts all hash algorithms.
    fn accepts_hash(&self, hash: &str) -> bool {
        self.hashes.is_empty() || self.hashes.iter().any(|h| h.eq_ignore_ascii_case(hash))
    }

    /// Whether the record version is usable (absent, or begins with
    /// "DKIM1" case-insensitively).
    fn version_ok(&self) -> bool {
        self.version.is_empty() || self.version.to_ascii_lowercase().starts_with("dkim1")
    }

    /// Whether the `t=s` (strict identity) flag is set.
    fn strict_identity(&self) -> bool {
        self.flags.iter().any(|f| f == "s")
    }
}

/// Fetch the DKIM public key record for signature `sig`: TXT at
/// `{selector}._domainkey.{domain}`, through `resolver` (the shared
/// DNS-over-TLS client).
///
/// Returns the first TXT answer that parses as a key record.
///
/// # Errors
///
/// [`DkimError::KeyLookupFailed`] when the lookup gave no definite answer
/// (a failed or timed-out query, or a server error such as SERVFAIL): a
/// temporary condition, see [`DkimError::is_temporary`].
/// [`DkimError::NoKeyRecord`] when the name definitely has no key: no
/// such name, no TXT records, or none that parses.
pub async fn fetch_public_key(
    resolver: &DnsClient,
    sig: &DkimSignature<'_>,
) -> Result<DkimKeyRecord, DkimError> {
    let name = sig.key_query_name();
    let txts = match resolver
        .lookup(&name, 0x10, |r| match r {
            dns::proto::QType::TXT(txt) => Some(txt),
            _ => None,
        })
        .await
    {
        dns::Lookup::Found(txts) => txts,
        dns::Lookup::Absent => return Err(DkimError::NoKeyRecord(name)),
        dns::Lookup::TempError(reason) => return Err(DkimError::KeyLookupFailed(reason)),
    };
    txts.iter()
        .find_map(|txt| DkimKeyRecord::parse(txt.trim()).ok())
        .ok_or(DkimError::NoKeyRecord(name))
}

/// Whether the signature's AUID (`i=`) domain aligns with the signing
/// domain (`d=`): equal, or a subdomain, unless the key record sets the
/// strict `t=s` flag (RFC 6376 Section 6.1.1).
fn auid_matches(sig: &DkimSignature, key: &DkimKeyRecord) -> bool {
    let Some(identity) = sig.identity else {
        return true;
    };
    let i_domain = identity
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or(identity)
        .to_ascii_lowercase();
    let d = sig.domain.to_ascii_lowercase();

    if key.strict_identity() {
        i_domain == d
    } else {
        i_domain == d || i_domain.ends_with(&format!(".{d}"))
    }
}

/// RFC 8301 §3.2: the smallest RSA key a verifier may accept.
pub const MIN_RSA_BITS: usize = 1024;

/// Whether `sig` covers the whole canonicalised body of `msg`. With `l=`
/// shorter than the body, anything after it is unsigned: content appended to a genuinely signed message would still
/// verify and pass DMARC. With `l=` longer than the body, RFC 6376 §3.5
/// says the signature is invalid. Either way it must not count as
/// verified. [`body_hash`] still computes the `l=`-truncated hash, for
/// conformance.
fn covers_whole_body(msg: &RawMessage, sig: &DkimSignature) -> bool {
    match sig.body_length {
        None => true,
        Some(l) => {
            let mut len = 0usize;
            canonical_body_into(sig.body_canon, msg.body, &mut |chunk| len += chunk.len());
            l == len
        }
    }
}

/// Whether `sig` is expired at `now` (Unix seconds): `x=` is in the past
/// (RFC 6376 Section 3.5). Signatures without `x=` never expire.
fn is_expired(sig: &DkimSignature, now: u64) -> bool {
    sig.expiry.is_some_and(|x| x < now)
}

/// Cryptographically verify the `b=` signature of `signed_data` against the
/// public key in `key` (RFC 6376 Section 6.1, RFC 8463 for Ed25519).
/// Only `*-sha256` signatures are supported.
///
/// Returns `true` when the signature verifies, `false` when it does not
/// match.
///
/// # Errors
///
/// Structural problems: an unsupported key record version, a revoked
/// key, an unsupported or unaccepted hash, an unsupported key type, a
/// malformed or too-short key, or a malformed `b=` value.
pub fn verify_signature(
    sig: &DkimSignature,
    key: &DkimKeyRecord,
    signed_data: &[u8],
) -> Result<bool, DkimError> {
    if !key.version_ok() {
        return Err(DkimError::InvalidKey(format!(
            "unsupported key record version: {}",
            key.version
        )));
    }
    if strip_fws(&key.public_key).is_empty() {
        return Err(DkimError::RevokedKey);
    }

    // RFC 6376 §6.1.2: the key must be of the signature's algorithm
    // (otherwise an ed25519 key could be offered for an rsa-sha256 tag).
    let sig_key = sig.key_algorithm()?;
    if !sig_key.eq_ignore_ascii_case(&key.key_type) {
        return Err(DkimError::KeyTypeMismatch {
            signature: sig_key.to_string(),
            key: key.key_type.clone(),
        });
    }
    let hash = sig.hash_algorithm()?;
    // RFC 8301: SHA-1 is deprecated. Only SHA-256 is implemented, for both
    // rsa-sha256 (RFC 6376) and ed25519-sha256 (RFC 8463).
    if hash != "sha256" {
        return Err(DkimError::UnsupportedAlgorithm(hash.to_string()));
    }
    if !key.accepts_hash(hash) {
        return Err(DkimError::HashNotAccepted(hash.to_string()));
    }

    match key.key_type.to_ascii_lowercase().as_str() {
        "rsa" => verify_rsa(sig, key, signed_data),
        "ed25519" => verify_ed25519(sig, key, signed_data),
        other => Err(DkimError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Verify `sig`'s `b=` over `signed_data` with the RSA key in `key`:
/// RSA PKCS#1 v1.5 with SHA-256 (RFC 6376 Section 3.3).
///
/// Returns whether the signature matches.
///
/// # Errors
///
/// A malformed key, a key under [`MIN_RSA_BITS`], or a malformed `b=`.
fn verify_rsa(
    sig: &DkimSignature,
    key: &DkimKeyRecord,
    signed_data: &[u8],
) -> Result<bool, DkimError> {
    let key_bytes = BASE64_STANDARD
        .decode(strip_fws(&key.public_key))
        .map_err(|e| DkimError::InvalidKey(e.to_string()))?;

    // RFC 6376 specifies a DER SubjectPublicKeyInfo; accept bare PKCS#1
    // RSAPublicKey for robustness (some legacy records use it).
    let public_key = RsaPublicKey::from_public_key_der(&key_bytes)
        .or_else(|_| RsaPublicKey::from_pkcs1_der(&key_bytes))
        .map_err(|e| DkimError::InvalidKey(e.to_string()))?;
    // RFC 8301 §3.2: keys under 1024 bits MUST NOT be accepted; they are
    // cheap to factor, so anyone could forge for the domain. The rsa
    // crate already refuses keys over 4096 bits, which bounds the CPU cost.
    let bits = public_key.n().bits();
    if bits < MIN_RSA_BITS {
        return Err(DkimError::WeakKey(bits));
    }

    let sig_bytes = BASE64_STANDARD
        .decode(strip_fws(sig.signature))
        .map_err(|e| DkimError::InvalidSignature(e.to_string()))?;
    let signature = Pkcs1v15Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| DkimError::InvalidSignature(e.to_string()))?;

    let verifying_key: VerifyingKey<rsa::sha2::Sha256> = VerifyingKey::new(public_key);
    Ok(verifying_key.verify(signed_data, &signature).is_ok())
}

/// Verify `sig`'s `b=` over `signed_data` with the Ed25519 key in `key`:
/// PureEdDSA over the SHA-256 digest of the canonicalized data (RFC
/// 8463). The `p=` tag is the base64 of the raw 32-byte public key.
///
/// Returns whether the signature matches.
///
/// # Errors
///
/// A malformed or wrong-length key, or a malformed `b=`.
fn verify_ed25519(
    sig: &DkimSignature,
    key: &DkimKeyRecord,
    signed_data: &[u8],
) -> Result<bool, DkimError> {
    let key_bytes: [u8; 32] = BASE64_STANDARD
        .decode(strip_fws(&key.public_key))
        .map_err(|e| DkimError::InvalidKey(e.to_string()))?
        .try_into()
        .map_err(|_| DkimError::InvalidKey("ed25519 public key must be 32 bytes".to_string()))?;
    let public_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| DkimError::InvalidKey(e.to_string()))?;

    let sig_bytes = BASE64_STANDARD
        .decode(strip_fws(sig.signature))
        .map_err(|e| DkimError::InvalidSignature(e.to_string()))?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| DkimError::InvalidSignature(e.to_string()))?;

    let digest = Sha256::digest(signed_data);
    Ok(public_key.verify(digest.as_slice(), &signature).is_ok())
}

/// The outcome of checking one DKIM signature.
///
/// `body_hash_ok` and `signature_ok` are independent: the body hash checks
/// the message body against the `bh=` tag, while the signature check
/// verifies the signed header data (including the `bh=` tag as written)
/// against the published public key. A message is DKIM-verified only when
/// both are true.
#[derive(Debug, Clone, PartialEq)]
pub struct DkimResult<'a> {
    /// The parsed signature tags.
    pub signature: DkimSignature<'a>,
    /// The canonicalized body's hash matched the `bh=` tag.
    pub body_hash_ok: bool,
    /// The RSA/Ed25519 verification of the signed header data succeeded
    /// against the published public key.
    pub signature_ok: bool,
    /// The first structural error encountered, if any.
    pub error: Option<DkimError>,
}

/// Verify the signature `parsed` of `msg` against the key record `key`
/// at time `now` (Unix seconds). This is the DNS-free core of the
/// verifier and is fully testable offline.
///
/// Returns the result. Expiry, a partial-body `l=`, a key that doesn't
/// permit email, and a misaligned `i=` are checked first, in that order;
/// any of them records the error and skips the cryptographic check.
pub fn verify_with_key<'m>(
    msg: &RawMessage<'m>,
    parsed: &ParsedSignature<'_, 'm>,
    key: &DkimKeyRecord,
    now: u64,
) -> DkimResult<'m> {
    let sig = &parsed.signature;
    let body_hash_ok = body_hash_matches(msg, sig).unwrap_or(false);

    let mut signature_ok = false;
    let mut error = None;

    if is_expired(sig, now) {
        error = Some(DkimError::Expired);
    } else if !covers_whole_body(msg, sig) {
        error = Some(DkimError::PartialBody);
    } else if !key.permits_email() {
        error = Some(DkimError::ServiceNotPermitted);
    } else if !auid_matches(sig, key) {
        error = Some(DkimError::DomainMismatch);
    } else {
        match signed_header_data(msg, sig, parsed.header) {
            Ok(data) => match verify_signature(sig, key, &data) {
                Ok(ok) => signature_ok = ok,
                Err(e) => error = Some(e),
            },
            Err(e) => error = Some(e),
        }
    }

    DkimResult {
        signature: sig.clone(),
        body_hash_ok,
        signature_ok,
        error,
    }
}

/// The most signatures [`verify_dkim`] evaluates per message. Each
/// signature costs a key lookup, a full body canonicalization + hash, and
/// a public-key operation; without a cap a
/// 1 MiB message could carry >10,000 signature headers. Legitimate mail
/// carries a handful (author domain, ESP, a forwarder or two), so the
/// topmost (most recently added) signatures are evaluated and the rest
/// are ignored — an ignored signature simply contributes no pass.
pub const MAX_SIGNATURES: usize = 5;

/// The longest `d=` or `s=` a signature may have: a DNS name's 253
/// octets in text form (RFC 1035 §2.3.4).
pub const MAX_DNS_NAME_LEN: usize = 253;

/// The longest `i=` a signature may have: a 64-octet local-part, `@`,
/// and a DNS name (RFC 5321 §4.5.3.1).
pub const MAX_IDENTITY_LEN: usize = 64 + 1 + MAX_DNS_NAME_LEN;

/// The most `h=` entries a signature may list. Real signatures name a few
/// dozen headers even with heavy oversigning; a longer list is refused as
/// an invalid `h=` tag, so the signature contributes no pass. Header
/// selection is linear regardless, so this only bounds the work and
/// memory one signature can ask for.
pub const MAX_SIGNED_HEADERS: usize = 256;

/// Verify every DKIM signature on the raw message `raw`: fetch each
/// signer's public key through `resolver` ([`fetch_keys`]), then check the
/// body hashes and cryptographically verify the signed header data
/// ([`verify_with_keys`], at the current time). At most
/// [`MAX_SIGNATURES`] signatures (the topmost) are evaluated.
///
/// The verification step is CPU work (canonicalization, hashing, a public
/// key operation per signature); a server should call the two halves
/// itself and run [`verify_with_keys`] off its async workers.
///
/// Returns one result per evaluated signature (a failed key lookup is
/// recorded as that result's error); an empty result means the message
/// had no parseable DKIM signature or could not be split into headers
/// and body.
pub async fn verify_dkim<'m>(raw: &'m [u8], resolver: &DnsClient) -> Vec<DkimResult<'m>> {
    let keys = fetch_keys(raw, resolver).await;
    verify_with_keys(raw, &keys, unix_now())
}

/// The public-key lookup for each signature [`verify_with_keys`] will
/// evaluate, in the same order: the key record, or why it couldn't be
/// fetched.
pub type KeyLookups = Vec<Result<DkimKeyRecord, DkimError>>;

/// The DNS half of verification: find the signatures on the raw message
/// `raw` (the topmost [`MAX_SIGNATURES`]) and fetch each signer's public
/// key through `resolver`. No canonicalization or cryptography happens
/// here.
///
/// Returns one lookup per signature, in order (empty when the message has
/// no parseable signature or can't be split into headers and body); pass
/// it, with the same `raw`, to [`verify_with_keys`].
pub async fn fetch_keys(raw: &[u8], resolver: &DnsClient) -> KeyLookups {
    let Ok(msg) = parse_raw_message(raw) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    for parsed in signatures(&msg).take(MAX_SIGNATURES) {
        keys.push(fetch_public_key(resolver, &parsed.signature).await);
    }
    keys
}

/// The CPU half of verification, with no I/O: check each signature on the
/// raw message `raw` against its key from `keys` (from [`fetch_keys`] on
/// the same `raw`) at time `now` (Unix seconds; see [`verify_with_key`]).
/// A signature whose lookup failed gets that error and no signature check;
/// its body hash is still checked.
///
/// Returns one result per signature that has a lookup, in order.
pub fn verify_with_keys<'m>(
    raw: &'m [u8],
    keys: &[Result<DkimKeyRecord, DkimError>],
    now: u64,
) -> Vec<DkimResult<'m>> {
    let Ok(msg) = parse_raw_message(raw) else {
        return Vec::new();
    };
    // The same parse and the same selection as `fetch_keys`, so the
    // signatures pair up with their lookups.
    signatures(&msg)
        .take(MAX_SIGNATURES)
        .zip(keys)
        .map(|(parsed, key)| match key {
            Ok(key) => verify_with_key(&msg, &parsed, key, now),
            Err(e) => DkimResult {
                body_hash_ok: body_hash_matches(&msg, &parsed.signature).unwrap_or(false),
                signature: parsed.signature.clone(),
                signature_ok: false,
                error: Some(e.clone()),
            },
        })
        .collect()
}

/// Returns the current time in Unix seconds (0 if the clock is before
/// 1970).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Verifier policy: weak keys, partial-body `l=`, and signatures that don't
/// sign From. Each is tested by genuinely signing a message, then attacking
/// it.
#[cfg(test)]
mod verifier_policy_tests {
    use super::*;
    use rsa::pkcs8::EncodePublicKey as _;
    use rsa::signature::{SignatureEncoding as _, Signer as _};

    /// RSA-sign `template` (with `BH`/`SIG` placeholders) using a fresh key
    /// of `bits`; returns the signed message and the key record.
    fn rsa_signed(template: &str, bits: usize) -> (Vec<u8>, DkimKeyRecord) {
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, bits).unwrap();
        let der = private.to_public_key().to_public_key_der().unwrap();
        let key = DkimKeyRecord::parse(&format!(
            "v=DKIM1; k=rsa; p={}",
            BASE64_STANDARD.encode(der.as_bytes())
        ))
        .unwrap();
        let m0 = parse_raw_message(template.as_bytes()).unwrap();
        let bh = body_hash(&m0, &find_signatures(&m0)[0].signature).unwrap();
        let step1 = template.replace("BH", &bh);
        let m1 = parse_raw_message(step1.as_bytes()).unwrap();
        let p = &find_signatures(&m1)[0];
        let data = signed_header_data(&m1, &p.signature, p.header).unwrap();
        let signer: rsa::pkcs1v15::SigningKey<rsa::sha2::Sha256> =
            rsa::pkcs1v15::SigningKey::new(private);
        let sig = BASE64_STANDARD.encode(signer.sign(&data).to_vec());
        (step1.replace("SIG", &sig).into_bytes(), key)
    }

    fn verify(msg: &[u8], key: &DkimKeyRecord) -> DkimResult<'static> {
        let msg: &'static [u8] = Box::leak(msg.to_vec().into_boxed_slice());
        let m: &'static RawMessage<'static> = Box::leak(Box::new(parse_raw_message(msg).unwrap()));
        let p = &find_signatures(m)[0];
        verify_with_key(m, p, key, 0)
    }

    const SIGNED: &str = "DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=victim.example; s=s; h=From:Subject; bh=BH; b=SIG\r\nFrom: ceo@victim.example\r\nSubject: hi\r\n\r\nhello\r\n";

    /// `verify_with_keys` pairs each signature with its lookup from
    /// `fetch_keys` order: a fetched key verifies, a failed lookup records
    /// its error (with the body hash still checked), and a missing lookup
    /// means no result.
    #[test]
    fn verify_with_keys_pairs_signatures_with_lookups() {
        let (msg, key) = rsa_signed(SIGNED, 1024);
        let ok = verify_with_keys(&msg, &[Ok(key)], 0);
        assert_eq!(ok.len(), 1);
        assert!(
            ok[0].signature_ok && ok[0].body_hash_ok,
            "{:?}",
            ok[0].error
        );

        let failed = verify_with_keys(
            &msg,
            &[Err(DkimError::NoKeyRecord(
                "s._domainkey.victim.example".into(),
            ))],
            0,
        );
        assert!(!failed[0].signature_ok);
        assert!(failed[0].body_hash_ok, "the body hash is still checked");
        assert_eq!(
            failed[0].error,
            Some(DkimError::NoKeyRecord("s._domainkey.victim.example".into()))
        );

        assert!(verify_with_keys(&msg, &[], 0).is_empty());
    }

    /// RFC 8301: a 512-bit key never verifies; 1024 bits does.
    #[test]
    fn weak_rsa_keys_are_refused() {
        let (msg, key) = rsa_signed(SIGNED, 512);
        let r = verify(&msg, &key);
        assert!(!r.signature_ok);
        assert!(
            matches!(r.error, Some(DkimError::WeakKey(512))),
            "{:?}",
            r.error
        );

        let (msg, key) = rsa_signed(SIGNED, 1024);
        assert!(verify(&msg, &key).signature_ok);
    }

    /// `l=`: content appended past the signed length must not verify, and
    /// an `l=` covering exactly the body still does.
    #[test]
    fn partial_body_signatures_never_verify() {
        let template = SIGNED.replace("s=s;", "s=s; l=7;");
        let (msg, key) = rsa_signed(&template, 1024);
        assert!(
            verify(&msg, &key).signature_ok,
            "l= equal to the body length"
        );

        let mut tampered = msg.clone();
        tampered.extend_from_slice(b"ATTACKER: wire money to 1234\r\n");
        let r = verify(&tampered, &key);
        assert!(!r.signature_ok, "appended content must not verify");
        assert!(
            matches!(r.error, Some(DkimError::PartialBody)),
            "{:?}",
            r.error
        );

        // l= longer than the body is invalid too (RFC 6376 §3.5).
        let template = SIGNED
            .replace("s=s;", "s=s; l=7;")
            .replace("hello\r\n", "hi\r\n");
        let m0 = parse_raw_message(template.as_bytes()).unwrap();
        let sig = &find_signatures(&m0)[0].signature;
        assert!(!covers_whole_body(&m0, sig));
    }

    /// RFC 6376 §6.1.1: a signature that doesn't sign From is ignored, so
    /// swapping From on a genuinely signed message can't pass.
    #[test]
    fn signatures_must_sign_from() {
        assert!(matches!(
            DkimSignature::parse("v=1; a=rsa-sha256; d=d; s=s; bh=x; b=x; h=Subject:To"),
            Err(DkimError::InvalidTag("h"))
        ));
        let swapped = b"DKIM-Signature: v=1; a=rsa-sha256; d=victim.example; s=s; h=Subject; bh=x; b=x\r\nFrom: CEO <ceo@victim.example>\r\nSubject: hi\r\n\r\nhello\r\n";
        let m = parse_raw_message(swapped).unwrap();
        assert!(find_signatures(&m).is_empty(), "the signature is ignored");
        assert!(DkimSignature::parse("v=1; a=rsa-sha256; d=d; s=s; bh=x; b=x; h=FROM:to").is_ok());
    }
}

/// Bounded work over attacker-chosen structure: tag lists and body line
/// structure cost time and memory linear in the bytes, never per pair of
/// tags or per line allocated.
#[cfg(test)]
mod bounded_work_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// The canonicalization before streaming: per-line vectors, joined.
    /// Kept as an oracle for the streaming version.
    fn reference_body(alg: &str, body: &[u8]) -> Vec<u8> {
        let mut lines: Vec<Vec<u8>> = body
            .split(|&b| b == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .map(|line| {
                if alg != "relaxed" {
                    return line.to_vec();
                }
                let mut out = Vec::new();
                let mut pending_wsp = false;
                for &b in line {
                    if is_wsp(b) {
                        pending_wsp = true;
                    } else {
                        if pending_wsp {
                            out.push(b' ');
                        }
                        out.push(b);
                        pending_wsp = false;
                    }
                }
                out
            })
            .collect();
        while lines.last().is_some_and(|l| l.is_empty()) {
            lines.pop();
        }
        if lines.is_empty() {
            return b"\r\n".to_vec();
        }
        let mut out = lines.join(&b"\r\n"[..]);
        out.extend_from_slice(b"\r\n");
        out
    }

    /// The streaming canonicalization produces exactly what the per-line
    /// one did, for both algorithms, over every short combination of the
    /// bytes that matter (text, WSP, CR, LF).
    #[test]
    fn streaming_body_canonicalization_matches_reference() {
        let alphabet = *b"a \t\r\n";
        // Every string of up to 7 symbols.
        let mut bodies: Vec<Vec<u8>> = vec![Vec::new()];
        let mut last: Vec<Vec<u8>> = vec![Vec::new()];
        for _ in 0..7 {
            last = last
                .iter()
                .flat_map(|b| {
                    alphabet.iter().map(move |&c| {
                        let mut b = b.clone();
                        b.push(c);
                        b
                    })
                })
                .collect();
            bodies.extend(last.iter().cloned());
        }
        for body in &bodies {
            for alg in ["relaxed", "simple"] {
                assert_eq!(
                    canonicalize_body(alg, body),
                    reference_body(alg, body),
                    "{alg} {:?}",
                    String::from_utf8_lossy(body)
                );
            }
        }
    }

    /// `l=` hashing is unchanged: the hash covers exactly the first `l`
    /// canonical bytes.
    #[test]
    fn body_length_truncates_the_streamed_hash() {
        let raw = b"From: a@example.org\r\n\r\nline one\r\n  line   two \r\n\r\n";
        let msg = parse_raw_message(raw).unwrap();
        let canon = relaxed_body(msg.body);
        for l in [0, 1, 5, canon.len() - 1, canon.len(), canon.len() + 10] {
            let tags =
                format!("v=1; a=rsa-sha256; c=relaxed/relaxed; d=d; s=s; h=From; bh=x; b=x; l={l}");
            let sig = DkimSignature::parse(&tags).unwrap();
            let expected = BASE64_STANDARD.encode(Sha256::digest(&canon[..l.min(canon.len())]));
            assert_eq!(body_hash(&msg, &sig).unwrap(), expected, "l={l}");
        }
    }

    /// A signature with tens of thousands of distinct tags parses in
    /// linear time (the duplicate-tag check was a list scan per tag:
    /// 64,000 tags took 4.7 s in a release build).
    #[test]
    fn many_tags_parse_in_linear_time() {
        let mut raw = String::from("v=1; a=rsa-sha256; d=d; s=s; h=From; bh=x; b=x");
        for i in 0..200_000 {
            raw.push_str(&format!("; t{i}=x"));
        }
        let started = Instant::now();
        assert!(DkimSignature::parse(&raw).is_ok());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
        // A duplicate anywhere is still found.
        raw.push_str("; t7=y");
        assert_eq!(
            DkimSignature::parse(&raw),
            Err(DkimError::DuplicateTag("t7".to_string()))
        );
    }

    /// Millions of one-byte body lines under a relaxed signature cost one
    /// pass, not one allocation per line.
    #[test]
    fn many_body_lines_hash_in_one_pass() {
        let mut raw = b"From: a@example.org\r\n\r\n".to_vec();
        for _ in 0..1_000_000 {
            raw.extend_from_slice(b"x\r\n");
        }
        let msg = parse_raw_message(&raw).unwrap();
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d=d; s=s; h=From; bh=x; b=x",
        )
        .unwrap();
        let started = Instant::now();
        assert!(body_hash(&msg, &sig).is_ok());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
    }

    /// `d=`, `s=` and `i=` longer than a DNS name (or an address) can be
    /// make the signature invalid: they would only be copied, unbounded,
    /// into headers, metadata and logs.
    #[test]
    fn name_tags_are_bounded() {
        let sig = |d: &str, s: &str, i: &str| {
            DkimSignature::parse(&format!(
                "v=1; a=rsa-sha256; d={d}; s={s}; i={i}; h=From; bh=x; b=x"
            ))
            .map(|_| ())
        };
        let longest = format!("{}.example", "a".repeat(MAX_DNS_NAME_LEN - 8));
        assert_eq!(longest.len(), MAX_DNS_NAME_LEN);
        let at = |d: &str| format!("u@{d}");
        assert_eq!(sig(&longest, &longest, &at(&longest)), Ok(()));
        let over = format!("a{longest}");
        assert_eq!(sig(&over, "s", &at("x")), Err(DkimError::InvalidTag("d")));
        assert_eq!(sig("x", &over, &at("x")), Err(DkimError::InvalidTag("s")));
        let long_i = format!("{}@{longest}", "u".repeat(65));
        assert_eq!(sig("x", "s", &long_i), Err(DkimError::InvalidTag("i")));
    }
}
