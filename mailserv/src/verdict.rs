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
            error: result.error.as_ref().map(|e| e.to_string()),
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
