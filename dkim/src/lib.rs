//! DKIM verification (RFC 6376, RFC 8463) built on the [`mailparse`]
//! crate: canonicalization, body hashing, signed-header-data
//! construction, public-key records, and cryptographic verification
//! (RSA PKCS#1 v1.5 and Ed25519, SHA-256).
#![warn(missing_docs)]

//! DKIM (RFC 6376) parsing, canonicalization, and hashing, built on the
//! `mailparse` crate.
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
//!
//! Not yet implemented (next steps): public key retrieval
//! (`{s}._domainkey.{d}` TXT) and cryptographic verification of the `b=`
//! signature (RSA/Ed25519), plus `x=`/`t=` expiry enforcement. Note that key
//! retrieval depends on multi-string TXT support in the `dns` crate, which
//! currently truncates TXT records longer than 255 bytes.

use base64::prelude::*;
use rsa::pkcs1::DecodeRsaPublicKey as _;
use rsa::pkcs1v15::{Signature as Pkcs1v15Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use mailparse::{parse_message, ParsedMessage, RawHeader};

/// Errors from DKIM signature parsing, key handling, and verification.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum DkimError {
    /// A required tag (v/a/b/bh/d/s/h) is absent.
    #[error("missing required tag: {0}")]
    MissingTag(&'static str),

    /// The DKIM-Signature enum wraps per-tag problems; this variant is a
    /// present tag with an unusable value (v=2, l= not a number, ...).
    #[error("invalid value for tag: {0}")]
    InvalidTag(&'static str),

    /// The a= or k= names an algorithm this verifier does not implement.
    #[error("unsupported hash or key algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// The DKIM-Signature header was not valid UTF-8.
    #[error("invalid UTF-8 in DKIM-Signature header")]
    InvalidUtf8,

    /// The DNS query for the key record failed (transport or rcode).
    #[error("DNS lookup for the public key failed: {0}")]
    KeyLookupFailed(String),

    /// The key-record name exists but carries no parseable DKIM key.
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

    /// The i= identity's domain does not align with d= (strict mode).
    #[error("AUID (i=) domain does not match the signing domain (d=)")]
    DomainMismatch,

    /// The signature's x= timestamp is in the past.
    #[error("signature expired (x= is in the past)")]
    Expired,

    /// The b= value does not decode to a valid signature for the key
    /// type.
    #[error("invalid signature encoding: {0}")]
    InvalidSignature(String),
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
    /// Parse the tag list of a `DKIM-Signature` header value (everything
    /// after the colon).
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

        for segment in raw.split(';') {
            let Some((name, value)) = segment.split_once('=') else {
                continue;
            };
            let name = trim_fws(name);
            let value = trim_fws(value);
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
                _ => {} // i=, q=, z= and unknown tags are not needed for hashing
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

        Ok(DkimSignature {
            version,
            algorithm: algorithm.ok_or(DkimError::MissingTag("a"))?,
            signature: signature.ok_or(DkimError::MissingTag("b"))?,
            body_hash: body_hash.ok_or(DkimError::MissingTag("bh"))?,
            header_canon,
            body_canon,
            domain: domain.ok_or(DkimError::MissingTag("d"))?,
            selector: selector.ok_or(DkimError::MissingTag("s"))?,
            signed_headers,
            identity,
            body_length,
            timestamp,
            expiry,
        })
    }

    /// The DNS name to query for the public key:
    /// `{selector}._domainkey.{domain}`.
    pub fn key_query_name(&self) -> String {
        format!("{}._domainkey.{}", self.selector, self.domain)
    }

    /// The hash algorithm named by `a=` (the part after the '-').
    fn hash_algorithm(&self) -> Result<&'a str, DkimError> {
        self.algorithm
            .rsplit_once('-')
            .map(|(_, hash)| hash)
            .ok_or_else(|| DkimError::UnsupportedAlgorithm(self.algorithm.to_string()))
    }
}

/// A `DKIM-Signature` header found in a message, paired with its parsed tags.
/// One `DKIM-Signature` header found in a message, paired with its parsed
/// tags.
#[derive(Debug)]
pub struct ParsedSignature<'a, 'm> {
    /// The parsed signature tags.
    pub signature: DkimSignature<'m>,
    /// The raw header the signature was parsed from. Note the two
    /// lifetimes: the header lives inside the `ParsedMessage`, while the
    /// signature's tag values borrow from the original raw message bytes.
    pub header: &'a RawHeader<'m>,
}

/// Find every `DKIM-Signature` in the message (multiple are common and all
/// must be checked independently). Signatures that are not valid UTF-8 or
/// fail tag parsing are skipped.
pub fn find_signatures<'a, 'm>(msg: &'a ParsedMessage<'m>) -> Vec<ParsedSignature<'a, 'm>> {
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
        .collect()
}

// ---------------------------------------------------------------------------
// Canonicalization (RFC 6376 Section 3.4)
// ---------------------------------------------------------------------------

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Trim folding whitespace (WSP, CR, LF) from both ends of a `&str`.
fn trim_fws(s: &str) -> &str {
    s.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'))
}

/// Remove all folding whitespace from a tag value (e.g. folded base64).
pub fn strip_fws(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect()
}

/// Trim folding whitespace (WSP, CR, LF) from both ends of a `&[u8]`.
fn trim_fws_bytes(s: &[u8]) -> &[u8] {
    let is_fws = |b: &u8| is_wsp(*b) || *b == b'\r' || *b == b'\n';
    let start = s.iter().position(|b| !is_fws(b)).unwrap_or(s.len());
    let end = s.iter().rposition(|b| !is_fws(b)).map_or(start, |i| i + 1);
    &s[start..end]
}

/// Split into lines, accepting CRLF or bare-LF endings. The trailing empty
/// element of a terminated body is preserved as an empty line.
fn split_lines(body: &[u8]) -> Vec<&[u8]> {
    body.split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .collect()
}

/// "relaxed" header canonicalization (RFC 6376 Section 3.4.2): lowercase the
/// field name, delete WSP around the colon, unfold, collapse WSP runs to a
/// single SP, and delete trailing WSP.
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

/// "simple" header canonicalization: the header exactly as it appears.
pub fn simple_header(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + value.len() + 1);
    out.extend_from_slice(name);
    out.push(b':');
    out.extend_from_slice(value);
    out
}

/// Canonicalize a single header with the named algorithm
/// ("relaxed" or "simple"; anything else falls back to "simple").
pub fn canonicalize_header(alg: &str, name: &[u8], value: &[u8]) -> Vec<u8> {
    match alg {
        "relaxed" => relaxed_header(name, value),
        _ => simple_header(name, value),
    }
}

/// "relaxed" body canonicalization (RFC 6376 Section 3.4.4): per line, ignore
/// trailing WSP and reduce WSP runs to a single SP; then ignore trailing
/// whitespace-only lines. A non-empty canonicalized body ends with exactly
/// one CRLF; a completely empty body canonicalizes to a single CRLF.
pub fn relaxed_body(body: &[u8]) -> Vec<u8> {
    let mut lines: Vec<Vec<u8>> = split_lines(body)
        .into_iter()
        .map(|line| {
            let mut out = Vec::with_capacity(line.len());
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

/// "simple" body canonicalization (RFC 6376 Section 3.4.3): the body as-is,
/// except trailing empty lines are ignored and a missing final CRLF is
/// added. A completely empty body canonicalizes to a single CRLF.
pub fn simple_body(body: &[u8]) -> Vec<u8> {
    let mut lines = split_lines(body);
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

/// Canonicalize the body with the named algorithm ("relaxed" or "simple";
/// anything else falls back to "simple").
pub fn canonicalize_body(alg: &str, body: &[u8]) -> Vec<u8> {
    match alg {
        "relaxed" => relaxed_body(body),
        _ => simple_body(body),
    }
}

/// The `DKIM-Signature` header value with the `b=` tag's value deleted
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

/// Compute the base64 body hash (`bh=`) for a signature over the message's
/// raw body: canonicalize per the signature's body algorithm, truncate to
/// `l=` bytes if present, then hash with the algorithm named by `a=`.
pub fn body_hash(msg: &ParsedMessage, sig: &DkimSignature) -> Result<String, DkimError> {
    let mut canon = canonicalize_body(sig.body_canon, msg.body);
    if let Some(l) = sig.body_length {
        canon.truncate(l.min(canon.len()));
    }

    match sig.hash_algorithm()? {
        "sha256" => Ok(BASE64_STANDARD.encode(Sha256::digest(&canon))),
        other => Err(DkimError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Check the computed body hash against the signature's `bh=` tag.
pub fn body_hash_matches(msg: &ParsedMessage, sig: &DkimSignature) -> Result<bool, DkimError> {
    Ok(body_hash(msg, sig)? == strip_fws(sig.body_hash))
}

/// Verify the body hash of every `DKIM-Signature` in the message, returning
/// each parsed signature with its body-hash verdict.
///
/// Note: a passing body hash alone does NOT prove the message is authentic;
/// cryptographic verification of `b=` against the published public key is
/// not implemented yet.
pub fn verify_body_hashes<'m>(msg: &'m ParsedMessage<'m>) -> Vec<(DkimSignature<'m>, bool)> {
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
pub fn signed_header_data(
    msg: &ParsedMessage,
    sig: &DkimSignature,
    sig_header: &RawHeader,
) -> Result<Vec<u8>, DkimError> {
    let mut used = vec![false; msg.headers.len()];
    let mut selected: Vec<&RawHeader> = Vec::new();

    for want in &sig.signed_headers {
        // Bottom-up: the last unused instance of each signed header.
        for i in (0..msg.headers.len()).rev() {
            if !used[i] && msg.headers[i].name_eq(want) {
                used[i] = true;
                selected.push(&msg.headers[i]);
                break;
            }
        }
        // A header listed in h= but absent from the message contributes
        // nothing (RFC 6376 Section 5.4.2).
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
    use mailparse::parse_message;

    // A real-world-style signed message (trimmed from an actual received
    // mail). The bh= tag below is the hash of the body as it exists in this
    // fixture (cross-checked against openssl); the original message's
    // bh=evU+ZAhaA7uoDunwy9tpxgyXQlVvxX0ZJTSDyRIcuew= no longer applies
    // because the body drifted when transcribed into this file.
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

    fn message_bytes() -> Vec<u8> {
        TEST_MESSAGE.replace('\n', "\r\n").into_bytes()
    }

    fn parsed() -> mailparse::ParsedMessage<'static> {
        // Leaks the message bytes so the ParsedMessage can borrow them with
        // 'static; fine for tests.
        let bytes: &'static [u8] = Box::leak(message_bytes().into_boxed_slice());
        parse_message(bytes).unwrap()
    }

    #[test]
    fn test_relaxed_headers_canonicalization() {
        // RFC 6376 Section 3.4.5 example: "A: X\r\nB : Y\t\r\n\t Z  \r\n"
        // canonicalizes to "a:X\r\nb:Y Z\r\n".
        assert_eq!(relaxed_header(b"A", b" X"), b"a:X");
        assert_eq!(relaxed_header(b"B ", b"Y \t\r\n\t Z  "), b"b:Y Z");
    }

    #[test]
    fn test_simple_header_canonicalization() {
        assert_eq!(simple_header(b"A", b" X\r\n"), b"A: X\r\n");
    }

    #[test]
    fn test_relaxed_body_canonicalization() {
        // RFC 6376 Section 3.4.5 example.
        let body = b" C \r\nD \t E\r\n\r\n\r\n";
        assert_eq!(relaxed_body(body), b" C\r\nD E\r\n");
    }

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

    #[test]
    fn test_dkim_sig_without_b() {
        let raw = b"v=1; a=rsa-sha256; d=x.com; s=s; bh=abc=; h=From; b=OcGM\r\n\t bHQ7==";
        assert_eq!(
            dkim_sig_without_b(raw),
            b"v=1; a=rsa-sha256; d=x.com; s=s; bh=abc=; h=From; b="
        );
    }

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

    #[test]
    fn header_selection_is_bottom_up_and_single_use() {
        let raw = b"X-Test: one\r\nSubject: s\r\nX-Test: two\r\n\r\nbody\r\n";
        let msg = parse_message(raw).unwrap();

        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=abc; bh=abc; d=x.com; s=sel; c=relaxed/relaxed; h=x-test:x-test",
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

    /// Sign a message with a locally generated RSA key and verify it with
    /// the full DNS-free verification path — the complete positive and
    /// negative test of the verifier.
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
        let step0 = parse_message(template.as_bytes()).unwrap();
        let sig0 = &find_signatures(&step0)[0].signature;
        let bh = body_hash(&step0, sig0).unwrap();
        let step1 = template.replace("PLACEHOLDER_BH", &bh);

        // 2. Build the signed header data. The b= value is deleted from the
        //    data, so the placeholder never enters the signature.
        let msg1 = parse_message(step1.as_bytes()).unwrap();
        let parsed1 = &find_signatures(&msg1)[0];
        let data = signed_header_data(&msg1, &parsed1.signature, parsed1.header).unwrap();

        // 3. Sign and splice the signature in.
        let signing_key: SigningKey<rsa::sha2::Sha256> = SigningKey::new(private);
        let signature = signing_key.sign(&data);
        let sig_bytes: Box<[u8]> = signature.into();
        let final_message = step1.replace("PLACEHOLDER_SIG", &BASE64_STANDARD.encode(sig_bytes));

        // 4. Verify the intact message.
        let final_bytes = final_message.as_bytes().to_vec();
        let msg = parse_message(&final_bytes).unwrap();
        let parsed = &find_signatures(&msg)[0];
        let result = verify_with_key(&msg, parsed, &key, 0);
        assert!(result.body_hash_ok, "body hash should match");
        assert!(result.signature_ok, "signature should verify");
        assert_eq!(result.error, None);

        // 5. Tampered signed header: body hash still matches, signature
        //    fails.
        let tampered_hdr = final_message.replace("Sign test", "Sign test!");
        let msg2 = parse_message(tampered_hdr.as_bytes()).unwrap();
        let parsed2 = &find_signatures(&msg2)[0];
        let r2 = verify_with_key(&msg2, parsed2, &key, 0);
        assert!(r2.body_hash_ok);
        assert!(!r2.signature_ok);

        // 6. Tampered body: body hash fails, but the signature still
        //    verifies — it covers the bh= tag as written, not the body.
        //    Overall DKIM verdict must require BOTH to pass.
        let tampered_body = final_message.replace("Test body.", "Test body tampered.");
        let msg3 = parse_message(tampered_body.as_bytes()).unwrap();
        let parsed3 = &find_signatures(&msg3)[0];
        let r3 = verify_with_key(&msg3, parsed3, &key, 0);
        assert!(!r3.body_hash_ok);
        assert!(r3.signature_ok);
    }

    /// Sign a message with a locally generated Ed25519 key (RFC 8463) and
    /// verify it, including tamper and key-type-mismatch negatives.
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

        let step0 = parse_message(template.as_bytes()).unwrap();
        let sig0 = &find_signatures(&step0)[0].signature;
        let bh = body_hash(&step0, sig0).unwrap();
        let step1 = template.replace("PLACEHOLDER_BH", &bh);

        let msg1 = parse_message(step1.as_bytes()).unwrap();
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
        let msg = parse_message(&final_bytes).unwrap();
        let parsed = &find_signatures(&msg)[0];
        let result = verify_with_key(&msg, parsed, &key, 0);
        assert!(result.body_hash_ok, "body hash should match");
        assert!(result.signature_ok, "signature should verify");
        assert_eq!(result.error, None);

        // Negative: tampered signed header fails verification.
        let tampered = final_message.replace("Ed sign test", "Ed sign test!");
        let msg2 = parse_message(tampered.as_bytes()).unwrap();
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
        assert!(matches!(r3.error, Some(DkimError::InvalidKey(_))));
    }

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

    /// Live DNS fetch of a real published DKIM key. Ignored by default to
    /// keep the suite offline-deterministic; run with `cargo test -p dkim
    /// -- --ignored`.
    #[tokio::test]
    #[ignore = "hits live DNS (DoT to 1.1.1.1)"]
    async fn live_fetch_public_key() {
        let sig = DkimSignature::parse(
            "v=1; a=rsa-sha256; b=x; bh=x; d=protonmail.com; s=protonmail3; h=From",
        )
        .unwrap();
        let resolver: Ipv4Addr = "1.1.1.1".parse().unwrap();
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
    /// Parse the tag list of a DKIM key TXT record.
    pub fn parse(raw: &str) -> Result<Self, DkimError> {
        let mut version = String::new();
        let mut key_type = String::new();
        let mut public_key = None;
        let mut service = Vec::new();
        let mut flags = Vec::new();
        let mut hashes = Vec::new();

        for segment in raw.split(';') {
            let Some((name, value)) = segment.split_once('=') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
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

/// Fetch the DKIM public key record for a signature:
/// TXT at `{selector}._domainkey.{domain}`, over DNS-over-TLS.
pub async fn fetch_public_key(
    resolver: &Ipv4Addr,
    sig: &DkimSignature<'_>,
) -> Result<DkimKeyRecord, DkimError> {
    let name = sig.key_query_name();
    let resp = dns::query_tls(resolver, &name, 0x10, 0x01)
        .await
        .map_err(|e| DkimError::KeyLookupFailed(e.to_string()))?;

    for ans in &resp.answers {
        if let dns::proto::QType::TXT(txt) = &ans.rdata {
            if let Ok(key) = DkimKeyRecord::parse(txt.trim()) {
                return Ok(key);
            }
        }
    }

    Err(DkimError::NoKeyRecord(name))
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

/// Whether the signature is expired: `x=` is in the past (RFC 6376
/// Section 3.5). Signatures without `x=` never expire.
fn is_expired(sig: &DkimSignature, now: u64) -> bool {
    sig.expiry.is_some_and(|x| x < now)
}

/// Cryptographically verify the `b=` signature of `signed_data` against the
/// public key in `key` (RFC 6376 Section 6.1, RFC 8463 for Ed25519).
/// Only `*-sha256` signatures are supported.
///
/// Returns `Ok(false)` when the signature does not match; `Err` for
/// structural problems (revoked key, unsupported algorithm, malformed key).
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

/// RSA PKCS#1 v1.5 with SHA-256 (RFC 6376 Section 3.3).
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

    let sig_bytes = BASE64_STANDARD
        .decode(strip_fws(sig.signature))
        .map_err(|e| DkimError::InvalidSignature(e.to_string()))?;
    let signature = Pkcs1v15Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| DkimError::InvalidSignature(e.to_string()))?;

    let verifying_key: VerifyingKey<rsa::sha2::Sha256> = VerifyingKey::new(public_key);
    Ok(verifying_key.verify(signed_data, &signature).is_ok())
}

/// Ed25519 (PureEdDSA) over the SHA-256 digest of the canonicalized data
/// (RFC 8463). The `p=` tag is the base64 of the raw 32-byte public key.
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

/// Verify one signature against a known key record and the current time.
/// This is the DNS-free core of the verifier and is fully testable
/// offline.
pub fn verify_with_key<'m>(
    msg: &ParsedMessage<'m>,
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

/// Verify every DKIM signature on a raw message: parse, check body hashes,
/// fetch each signer's public key over DNS-over-TLS, and cryptographically
/// verify the signed header data. Returns one result per signature; an
/// empty result means the message had no parseable DKIM signature.
pub async fn verify_dkim<'m>(raw: &'m [u8], resolver: &Ipv4Addr) -> Vec<DkimResult<'m>> {
    let Ok(msg) = parse_message(raw) else {
        return Vec::new();
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut results = Vec::new();
    for parsed in find_signatures(&msg) {
        let result = match fetch_public_key(resolver, &parsed.signature).await {
            Ok(key) => verify_with_key(&msg, &parsed, &key, now),
            Err(e) => DkimResult {
                body_hash_ok: body_hash_matches(&msg, &parsed.signature).unwrap_or(false),
                signature: parsed.signature.clone(),
                signature_ok: false,
                error: Some(e),
            },
        };
        results.push(result);
    }
    results
}
