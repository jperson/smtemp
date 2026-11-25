//! DMARC record parsing, and organizational-domain lookups against the
//! Public Suffix List, over arbitrary text.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let _ = dmarc::DmarcRecord::parse(text);
    let (a, b) = text.split_once(' ').unwrap_or((text, "example.com"));
    if let Some(org) = dmarc::psl::organizational_domain(a) {
        // An organizational domain is its own organizational domain.
        assert_eq!(
            dmarc::psl::organizational_domain(&org).as_deref(),
            Some(org.as_str())
        );
    }
    let _ = dmarc::psl::public_suffix(a);
    let _ = dmarc::aligned_relaxed(a, b);
    let _ = dmarc::policy_candidates(a);
});
