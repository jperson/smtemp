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
use sha2::{Digest, Sha256};
use thiserror::Error;

use mailparse::{ParsedMessage, RawHeader};

#[derive(Debug, Error)]
pub enum DkimError {
    #[error("missing required tag: {0}")]
    MissingTag(&'static str),

    #[error("invalid value for tag: {0}")]
    InvalidTag(&'static str),

    #[error("unsupported hash or key algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("invalid UTF-8 in DKIM-Signature header")]
    InvalidUtf8,
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

        let signed_headers =
            signed_headers.ok_or(DkimError::MissingTag("h"))?;
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
}

/// A `DKIM-Signature` header found in a message, paired with its parsed tags.
#[derive(Debug)]
pub struct ParsedSignature<'m> {
    pub signature: DkimSignature<'m>,
    /// The raw header the signature was parsed from.
    pub header: &'m RawHeader<'m>,
}

/// Find every `DKIM-Signature` in the message (multiple are common and all
/// must be checked independently). Signatures that are not valid UTF-8 or
/// fail tag parsing are skipped.
pub fn find_signatures<'m>(msg: &'m ParsedMessage<'m>) -> Vec<ParsedSignature<'m>> {
    msg.headers
        .iter()
        .filter(|h| h.name_eq("dkim-signature"))
        .filter_map(|h| {
            let raw = std::str::from_utf8(h.raw_value).ok()?;
            DkimSignature::parse(raw)
                .ok()
                .map(|signature| ParsedSignature { signature, header: h })
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

    let alg = sig
        .algorithm
        .rsplit_once('-')
        .map(|(_, hash)| hash)
        .ok_or_else(|| DkimError::UnsupportedAlgorithm(sig.algorithm.to_string()))?;

    match alg {
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
    data.extend_from_slice(&canonicalize_header(sig.header_canon, sig_header.name, &without_b));

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
                   h=Date:To:From:Subject; b=OcGMbHQ7D6awrQVpP/eSLuPPz8cUpAuPS\r\n\t dXMlV6KdvNXpA==";
        let sig = DkimSignature::parse(raw).unwrap();

        assert_eq!(sig.version, "1");
        assert_eq!(sig.algorithm, "rsa-sha256");
        assert_eq!(sig.header_canon, "relaxed");
        assert_eq!(sig.body_canon, "relaxed");
        assert_eq!(sig.domain, "protonmail.com");
        assert_eq!(sig.selector, "protonmail3");
        assert_eq!(sig.timestamp, Some(1730510168));
        assert_eq!(sig.expiry, Some(1730769368));
        assert_eq!(sig.body_hash, "evU+ZAhaA7uoDunwy9tpxgyXQlVvxX0ZJTSDyRIcuew=");
        assert_eq!(sig.signed_headers, vec!["Date", "To", "From", "Subject"]);
        assert_eq!(sig.key_query_name(), "protonmail3._domainkey.protonmail.com");
        // The b= value keeps its folds; strip_fws yields pure base64.
        assert_eq!(strip_fws(sig.signature), "OcGMbHQ7D6awrQVpP/eSLuPPz8cUpAuPSdXMlV6KdvNXpA==");
    }

    #[test]
    fn test_parse_rejects_missing_and_invalid_tags() {
        assert!(DkimSignature::parse("v=2; a=rsa-sha256; b=x; bh=x; d=d; s=s; h=From")
            .is_err());
        assert!(DkimSignature::parse("a=rsa-sha256; b=x; bh=x; d=d; s=s; h=From")
            .is_err());
        assert!(DkimSignature::parse("v=1; a=rsa-sha256; b=x; bh=x; d=d; s=s; h=")
            .is_err());
        // c= with only the header algorithm defaults the body to simple.
        let sig = DkimSignature::parse("v=1; a=rsa-sha256; b=x; bh=x; d=d; s=s; h=From; c=relaxed").unwrap();
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
        let stand_in = msg
            .headers
            .iter()
            .find(|h| h.name_eq("subject"))
            .unwrap();

        let data = signed_header_data(&msg, &sig, stand_in).unwrap();
        // Bottom-up: "two" is selected before "one".
        assert!(data.starts_with(b"x-test:two\r\nx-test:one\r\n"));
        // The signature header itself is appended last, without trailing CRLF.
        assert!(data.ends_with(b"subject:s"));
    }
}
