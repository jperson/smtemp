//! The authentication verdicts recorded for each message: the DKIM and
//! DMARC summaries kept in spool metadata and the session log.

use serde::Serialize;

/// One DKIM verification outcome, summarized for structured logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub(crate) struct DkimSummary {
    /// Signing domain (`d=`).
    pub(crate) domain: String,
    /// Key selector (`s=`).
    pub(crate) selector: String,
    /// Whether the body hash (`bh=`) matched.
    pub(crate) body_hash_ok: bool,
    /// Whether the signature verified against the published key.
    pub(crate) signature_ok: bool,
    /// True only when both the body hash and the signature verify.
    pub(crate) verified: bool,
    /// Why verification failed, when it did.
    pub(crate) error: Option<String>,
    /// Whether that failure may change on retry (the key lookup got no
    /// definite answer; see `dkim::DkimError::is_temporary`). Absent in
    /// spool files from before this field existed.
    #[serde(default)]
    pub(crate) temporary: bool,
}

impl From<&dkim::DkimResult<'_>> for DkimSummary {
    fn from(result: &dkim::DkimResult<'_>) -> Self {
        DkimSummary {
            domain: result.signature.domain.to_string(),
            selector: result.signature.selector.to_string(),
            body_hash_ok: result.body_hash_ok,
            signature_ok: result.signature_ok,
            verified: result.body_hash_ok && result.signature_ok,
            // An error can name sender-chosen text (a key query name), so
            // the stored and logged copy is bounded.
            error: result
                .error
                .as_ref()
                .map(|e| truncated(&e.to_string(), MAX_ERROR_LEN)),
            temporary: result
                .error
                .as_ref()
                .is_some_and(dkim::DkimError::is_temporary),
        }
    }
}

/// One DMARC verification outcome, summarized for structured logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub(crate) struct DmarcSummary {
    /// The RFC 5322 From domain the policy was looked up for.
    pub(crate) from_domain: String,
    /// The applied policy (p= or sp=).
    pub(crate) policy: dmarc::DmarcPolicy,
    /// Whether an SPF pass aligned with the From domain.
    pub(crate) spf_aligned: bool,
    /// Whether a verified DKIM signature aligned with the From domain.
    pub(crate) dkim_aligned: bool,
    /// Whether DMARC passed (either alignment).
    pub(crate) pass: bool,
    /// What we did: "pass", "quarantine", or "reject".
    pub(crate) action: dmarc::Action,
}

/// The longest DKIM error text kept in a summary (the spool metadata and
/// the log).
pub(crate) const MAX_ERROR_LEN: usize = 256;

/// Returns `text`, or when it is longer than `max` bytes its first `max`
/// bytes (cut at a character boundary) followed by `...`, which marks
/// the cut (no DNS name has an empty label, so `...` can't be mistaken
/// for part of one).
pub(crate) fn truncated(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut cut = max;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}...", &text[..cut])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Short text is kept; long text is cut at a character boundary and
    /// marked.
    #[test]
    fn truncation() {
        assert_eq!(truncated("abc", 3), "abc");
        assert_eq!(truncated("abcd", 3), "abc...");
        assert_eq!(truncated("aé", 2), "a...");
        assert_eq!(truncated("", 0), "");
    }

    /// A DKIM error naming a huge key query name is stored bounded.
    #[test]
    fn dkim_error_is_bounded() {
        let raw = b"DKIM-Signature: v=1; a=rsa-sha256; d=x.example; s=s; h=From; bh=x; b=x\r\nFrom: a@x.example\r\n\r\nbody\r\n";
        let keys = vec![Err(dkim::DkimError::NoKeyRecord("q".repeat(100_000)))];
        let results = dkim::verify_with_keys(raw, &keys, 0);
        let summary = DkimSummary::from(&results[0]);
        let error = summary.error.unwrap();
        assert!(error.len() <= MAX_ERROR_LEN + 3, "{}", error.len());
        assert!(error.ends_with("..."));
    }
}
