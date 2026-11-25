//! Session tests: the policy driven through `SmtpSession` methods and
//! in-memory streams.

use super::*;
use crate::testutil::*;

use std::sync::Arc;
use std::time::Duration;

#[test]
fn mail_from_reply_maps_verdicts() {
    use smtp::Control;
    // Accepted: Pass, and the explicitly non-committal results.
    for result in [
        SpfResult::Pass,
        SpfResult::Neutral,
        SpfResult::SoftFail,
        SpfResult::None,
    ] {
        let control = mail_from_reply(&result);
        assert!(control.is_accept(), "{result:?} should accept");
        assert_eq!(control.reply(), UserSession::OK);
    }
    // Rejected.
    assert_eq!(mail_from_reply(&SpfResult::Fail).reply(), SPF_FAILED);
    assert_eq!(
        mail_from_reply(&SpfResult::PermError).reply(),
        SPF_PERMERROR
    );
    // Retryable.
    assert!(matches!(
        mail_from_reply(&SpfResult::TempError),
        Control::Tempfail(_)
    ));
    assert_eq!(mail_from_reply(&SpfResult::TempError).reply(), SPF_TEMPFAIL);
}

/// Per-IP DNS limit (DESIGN §9): with this source IP's share
/// exhausted, every DNS-backed stage fails *temporarily*, never
/// permanently — HELO proceeds with SPF TempError, MAIL FROM and
/// end-of-data get `451 4.7.0` — and once the share frees up the
/// checks run again. The DNS client points at a closed local port, so
/// nothing touches the network.
#[tokio::test]
async fn per_ip_dns_limit_tempfails_each_stage() {
    let dns_limit = Arc::new(limit::DnsLimiter::new(1, Duration::from_millis(100)));
    let cfg = SessionConfig {
        domain: "mail.test".to_string(),
        max_data: 1024 * 1024,
        auth: None,
        authority: Arc::new(authority::StaticAuthority::new(vec![
            "mail.test".to_string()
        ])),
        dns: Arc::new(dns::DnsClient::with_timeout(
            "127.0.0.1".parse().unwrap(),
            Duration::from_millis(500),
        )),
        dns_limit: Arc::clone(&dns_limit),
        eod_dns_deadline: END_OF_DATA_DNS_DEADLINE,
        shutdown: no_shutdown(),
        spool: None,
        sink: None,
        deadline: None,
        fast_path: Arc::new(tokio::sync::Semaphore::new(16)),
    };
    let peer: SocketAddr = "192.0.2.7:40000".parse().unwrap();
    let mut session = UserSession::new(peer, false, &cfg);

    // Another session from the same IP holds its whole share.
    let held = dns_limit.acquire(peer.ip()).await.unwrap();

    // HELO: accepted, identity recorded as TempError.
    let control = session.helo(false, "client.example").await;
    assert!(control.is_accept(), "{control:?}");
    assert_eq!(session.spf_helo, Some(SpfResult::TempError));

    // MAIL FROM: 451, nothing recorded, so it can be retried.
    let control = session.mail_from("<a@sender.example>").await;
    assert_eq!(control, smtp::Control::tempfail(DNS_BUSY));
    assert_eq!(session.mail_from, None);

    // End-of-data: 451 rather than skipping DKIM/DMARC; the envelope
    // is cleared.
    session.mail_from = Some("a@sender.example".to_string());
    session.data = b"From: a@sender.example\r\nSubject: t\r\n\r\nbody\r\n".to_vec();
    let control = session.end_data().await;
    assert_eq!(control, smtp::Control::tempfail(DNS_BUSY));
    assert_eq!(session.mail_from, None);
    assert!(session.data.is_empty());
    assert_eq!(dns_limit.stats().refusals, 3);

    // Once the share frees up, the check really runs: the unreachable
    // resolver now gives the ordinary SPF TempError reply instead.
    drop(held);
    let control = session.mail_from("<a@sender.example>").await;
    assert_eq!(control, smtp::Control::tempfail(SPF_TEMPFAIL));
    assert_eq!(
        dns_limit.stats().active_ips,
        0,
        "permit released after the check"
    );
}

/// A domain's `max-message-bytes` lowers the transaction's limit: data
/// past it is refused (552) for that domain's recipients, and the
/// discarded transfer's terminator clears the transaction.
#[tokio::test]
async fn domain_size_limit_applies_to_its_recipients() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = size_limit_session(dir.path());
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    let mut state = smtp::SmtpState::Ready;
    session.mail_from = Some("x@sender.example".into());

    assert!(session.rcpt_to("<a@small.example>").await.is_accept());
    assert_eq!(session.txn_limit, 2048);

    // 3 KiB of data crosses the 2 KiB domain limit.
    let line = format!("{}\r\n", "y".repeat(1022));
    let mut aborted = None;
    for _ in 0..3 {
        match session.recv_data(line.as_bytes()).await {
            smtp::DataControl::Continue => {}
            smtp::DataControl::Abort(reply) => {
                aborted = Some(reply);
                state = smtp::SmtpState::Discard;
                break;
            }
        }
    }
    assert_eq!(aborted.as_deref(), Some(MESSAGE_TOO_BIG));

    // The terminator of the discarded transfer ends the transaction.
    let (reply, next) = session.handler(&state, b".\r\n").await;
    assert!(reply.is_empty());
    assert_eq!(next, smtp::SmtpState::Ready);
    assert_eq!(session.mail_from, None);
    assert!(session.rcpt_to.is_empty());
    assert!(session.data.is_empty());
    assert_eq!(
        session.txn_limit, cfg.max_data,
        "limit back to the server's"
    );

    // A domain without its own limit keeps the server limit.
    session.mail_from = Some("x@sender.example".into());
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());
    assert_eq!(session.txn_limit, cfg.max_data);
}

/// Recipients with different limits never share a transaction: the
/// second gets 452 (send it separately), so a small-limit tenant can't
/// cause another tenant's mail to be refused. Same-limit recipients
/// share a transaction normally.
#[tokio::test]
async fn recipients_with_different_limits_are_split() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = size_limit_session(dir.path());
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.mail_from = Some("x@sender.example".into());

    assert!(session.rcpt_to("<a@small.example>").await.is_accept());
    assert!(session.rcpt_to("<b@small.example>").await.is_accept());
    assert_eq!(
        session.rcpt_to("<c@big.example>").await,
        smtp::Control::tempfail(
            b"452 4.5.3 Recipient has a different size limit; send it in a separate transaction\r\n"
                .to_vec()
        )
    );
    assert_eq!(session.rcpt_to.len(), 2);
    assert_eq!(session.txn_limit, 2048);

    // The other order: the big domain first, then the small one.
    session.clear_envelope();
    session.mail_from = Some("x@sender.example".into());
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());
    assert!(matches!(
        session.rcpt_to("<a@small.example>").await,
        smtp::Control::Tempfail(_)
    ));
    assert_eq!(session.txn_limit, cfg.max_data);
}

/// A SIZE declared at MAIL FROM is checked per recipient (RFC 1870
/// §6.1): over a domain's limit, that RCPT gets 552 before any data;
/// over the server limit, MAIL FROM itself does.
#[tokio::test]
async fn declared_size_is_checked_per_recipient() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = size_limit_session(dir.path());
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);

    // Over the server limit: refused at MAIL FROM (no DNS involved).
    assert_eq!(
        session.mail_from("<x@sender.example> SIZE=2000000").await,
        smtp::Control::reject(MESSAGE_TOO_BIG)
    );

    // Under the server limit but over small.example's.
    session.mail_from = Some("x@sender.example".into());
    session.declared_size = Some(4096);
    assert_eq!(
        session.rcpt_to("<a@small.example>").await,
        smtp::Control::reject(b"552 5.3.4 Message size exceeds the recipient's limit\r\n".to_vec())
    );
    assert!(session.rcpt_to.is_empty());
    // The same message is fine for the domain without a limit.
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());
}

/// End-of-data DNS work has one overall deadline.
/// Against a resolver that never answers, both the DKIM key lookup
/// and the DMARC policy fetch end at the deadline with a *temporary*
/// failure (never a permanent rejection), the transaction is cleared,
/// and the session can carry on.
#[tokio::test]
async fn end_of_data_dns_deadline_tempfails() {
    let cfg = SessionConfig {
        domain: "mail.test".to_string(),
        max_data: 1024 * 1024,
        auth: None,
        authority: Arc::new(authority::StaticAuthority::new(vec![
            "mail.test".to_string()
        ])),
        dns: spawn_silent_resolver().await,
        dns_limit: Arc::new(limit::DnsLimiter::new(
            limit::DEFAULT_DNS_PER_IP,
            limit::DNS_LIMIT_WAIT,
        )),
        eod_dns_deadline: Duration::from_millis(300),
        shutdown: no_shutdown(),
        spool: None,
        sink: None,
        deadline: None,
        fast_path: Arc::new(tokio::sync::Semaphore::new(16)),
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);

    // DKIM stage: the key lookup for the signature never answers.
    session.mail_from = Some("a@example.org".to_string());
    session.data =
        b"DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=sel; h=From; bh=AAAA; b=AAAA\r\n\
From: a@example.org\r\nSubject: t\r\n\r\nbody\r\n"
            .to_vec();
    let started = std::time::Instant::now();
    let control = session.end_data().await;
    assert_eq!(control, smtp::Control::tempfail(EOD_DNS_TIMEOUT));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(session.mail_from, None, "the transaction is over");
    assert!(session.data.is_empty());
    assert_eq!(session.message_count, 1);
    // It was the DKIM stage: one query (the key) was sent, and DKIM
    // never produced a result (a finished verification records one).
    assert_eq!(cfg.dns.stats().queries, 1);
    assert!(session.dkim.is_empty());

    // DMARC stage: no signature, so the policy fetch is what hangs.
    session.mail_from = Some("a@example.org".to_string());
    session.data = b"From: a@example.org\r\nSubject: t\r\n\r\nbody\r\n".to_vec();
    let started = std::time::Instant::now();
    let control = session.end_data().await;
    assert_eq!(control, smtp::Control::tempfail(EOD_DNS_TIMEOUT));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(session.message_count, 2);
    // It was the DMARC stage: exactly one more query (_dmarc.example.org).
    assert_eq!(cfg.dns.stats().queries, 2);
}

/// DKIM verdicts must not leak across messages on one connection: a
/// verified signature from an earlier message must not satisfy DMARC
/// alignment for a later unsigned spoof of the same domain. Here a
/// fake verified facebook.com verdict is left in the session, and an
/// unsigned message `From: someone@facebook.com` (whose mock DMARC
/// record is `p=reject`) must still be REJECTED — the DMARC evaluation
/// consumes only this message's results.
///
/// Hermetic: DMARC records come from a local mock DNS-over-TLS
/// resolver, never the live internet.
#[tokio::test]
async fn dkim_verdicts_do_not_leak_across_messages() {
    let cfg = SessionConfig {
        domain: "mail.test".to_string(),
        max_data: 1024 * 1024,
        auth: None,
        authority: Arc::new(authority::StaticAuthority::new(vec![
            "mail.test".to_string()
        ])),
        dns: spawn_mock_dmarc_resolver().await,
        dns_limit: Arc::new(limit::DnsLimiter::new(
            limit::DEFAULT_DNS_PER_IP,
            limit::DNS_LIMIT_WAIT,
        )),
        eod_dns_deadline: END_OF_DATA_DNS_DEADLINE,
        shutdown: no_shutdown(),
        spool: None,
        sink: None,
        deadline: None,
        fast_path: Arc::new(tokio::sync::Semaphore::new(16)),
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);

    // Simulate message 1 on this connection: a genuinely verified
    // facebook.com signature (e.g. a replayed newsletter).
    session.dkim.push(DkimSummary {
        domain: "facebook.com".to_string(),
        selector: "replay".to_string(),
        body_hash_ok: true,
        signature_ok: true,
        verified: true,
        error: None,
    });

    // Message 2: an unsigned spoof of the same domain.
    session.data = b"From: someone@facebook.com\r\nSubject: spoof\r\n\r\nbody\r\n".to_vec();
    let control = session.end_data().await;

    assert!(
        matches!(control, smtp::Control::Reject(_)),
        "an unsigned spoof must be rejected even after a verified facebook.com\n             signature on the same connection: {control:?}"
    );
    assert_eq!(
        session.dmarc.as_ref().map(|d| d.dkim_aligned),
        Some(false),
        "the stale verified verdict must not count for alignment"
    );
}

/// When the DMARC policy can't be fetched
/// (SERVFAIL), an unsigned spoof is deferred with 451, never delivered
/// as if the domain published no policy.
#[tokio::test]
async fn dmarc_lookup_failure_defers_instead_of_delivering() {
    let cfg = SessionConfig {
        domain: "mail.test".to_string(),
        max_data: 1024 * 1024,
        auth: None,
        authority: Arc::new(authority::StaticAuthority::new(vec![
            "mail.test".to_string()
        ])),
        dns: spawn_mock_dmarc_resolver_with(2).await,
        dns_limit: Arc::new(limit::DnsLimiter::new(
            limit::DEFAULT_DNS_PER_IP,
            limit::DNS_LIMIT_WAIT,
        )),
        eod_dns_deadline: END_OF_DATA_DNS_DEADLINE,
        shutdown: no_shutdown(),
        spool: None,
        sink: None,
        deadline: None,
        fast_path: Arc::new(tokio::sync::Semaphore::new(16)),
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.mail_from = Some("x@attacker.example".into());
    session.data = b"From: ceo@victim.example\r\nSubject: spoof\r\n\r\nbody\r\n".to_vec();
    let control = session.end_data().await;
    assert_eq!(control, smtp::Control::tempfail(DMARC_TEMPFAIL));
    assert_eq!(session.mail_from, None, "the transaction is over");
    assert_eq!(session.message_count, 1);
}

/// A refused HELO is rejected with 501 before it is recorded — and
/// before any SPF lookup, so this needs no DNS.
#[tokio::test]
async fn invalid_helo_is_rejected_and_not_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = tests::size_limit_session(dir.path());
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    let state = smtp::SmtpState::Idle;
    let (reply, next) = session
        .handler(&state, b"EHLO evil.example\rX-Injected: yes\r\n")
        .await;
    assert_eq!(reply, BAD_HELO);
    assert_eq!(next, smtp::SmtpState::Idle);
    assert_eq!(session.helo, None);
}

/// [`tests::size_limit_session`] in `dir` plus AUTH: `alice` may send
/// as `alice@example.org` and anything `@alice.example`; `carol` has
/// no grants.
fn session_cfg(dir: &std::path::Path) -> SessionConfig {
    let mut cfg = tests::size_limit_session(dir);
    cfg.auth = Some(Arc::new(
        auth::AuthConfig::from_credentials(
            &auth::test_credentials(&[("alice", "pw"), ("carol", "pw")]),
            Some("alice=alice@example.org|@alice.example"),
        )
        .unwrap(),
    ));
    cfg
}

/// A LOGIN exchange aborted with `*` leaves nothing behind: a new
/// `AUTH LOGIN` (mechanism names are case-insensitive) asks for the
/// user name again, so a line meant as the user name can never be
/// taken as the aborted user's password.
#[tokio::test]
async fn aborted_login_state_does_not_carry_over() {
    use base64::Engine as _;
    let b64 = |s: &str| {
        format!(
            "{}\r\n",
            base64::engine::general_purpose::STANDARD.encode(s)
        )
    };
    let dir = tempfile::tempdir().unwrap();
    let cfg = session_cfg(dir.path());
    let mut s = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    s.tls_active = true;
    s.mode = ListenerMode::Submission;
    let state = smtp::SmtpState::Ready;

    let (reply, next) = s.handler(&state, b"AUTH LOGIN\r\n").await;
    assert!(reply.starts_with(b"334 VXNlcm5hbWU6"), "username prompt");
    let (reply, next) = s.handler(&next, b64("alice").as_bytes()).await;
    assert!(reply.starts_with(b"334 UGFzc3dvcmQ6"), "password prompt");
    let (reply, next) = s.handler(&next, b"*\r\n").await;
    assert!(reply.starts_with(b"501"), "aborted");

    let (reply, next) = s.handler(&next, b"auth login\r\n").await;
    assert!(
        reply.starts_with(b"334 VXNlcm5hbWU6"),
        "fresh username prompt"
    );
    // alice's password, sent where the user name belongs.
    let (reply, _) = s.handler(&next, b64("pw").as_bytes()).await;
    assert!(
        reply.starts_with(b"334 UGFzc3dvcmQ6"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    assert_eq!(s.authenticated, None);
}

/// A session gets `MAX_FAILURES_PER_SESSION` wrong passwords; after
/// that every AUTH attempt, even with the right password, gets `454`
/// without a check, through both PLAIN and LOGIN.
#[tokio::test]
async fn auth_failures_are_limited_per_session() {
    use base64::Engine as _;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let dir = tempfile::tempdir().unwrap();
    let cfg = session_cfg(dir.path());
    let mut s = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    s.tls_active = true;
    s.mode = ListenerMode::Submission;

    let wrong = b64("\0alice\0wrong");
    for _ in 0..auth::MAX_FAILURES_PER_SESSION {
        let reply = s.auth("PLAIN", Some(wrong.as_bytes())).await.into_reply();
        assert_eq!(reply, b"535 5.7.8 Authentication credentials invalid\r\n");
    }
    let right = b64("\0alice\0pw");
    assert_eq!(
        s.auth("PLAIN", Some(right.as_bytes())).await.into_reply(),
        AUTH_TOO_MANY_FAILURES
    );
    // LOGIN reaches the same check at its password step.
    assert!(s.auth("LOGIN", None).await.reply().starts_with(b"334 "));
    s.auth_line(b64("alice").as_bytes()).await;
    assert_eq!(
        s.auth_line(b64("pw").as_bytes()).await.into_reply(),
        AUTH_TOO_MANY_FAILURES
    );
    assert_eq!(s.authenticated, None);
}

/// Listener policy: the MX never takes AUTH, even over TLS, and
/// doesn't advertise it; a submission listener refuses MAIL FROM
/// until the client has authenticated.
#[tokio::test]
async fn auth_is_a_submission_feature() {
    use base64::Engine as _;
    let dir = tempfile::tempdir().unwrap();
    let cfg = session_cfg(dir.path());
    let right = base64::engine::general_purpose::STANDARD.encode("\0alice\0pw");

    let mut mx = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    mx.tls_active = true;
    assert_eq!(
        mx.auth("PLAIN", Some(right.as_bytes())).await.into_reply(),
        b"502 5.5.1 Authentication not supported\r\n"
    );
    assert_eq!(mx.authenticated, None);

    let mut sub = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    sub.mode = ListenerMode::Submission;
    sub.tls_active = true;
    assert_eq!(
        sub.mail_from("<alice@example.org>").await.into_reply(),
        AUTH_REQUIRED
    );
    assert!(sub.mail_from.is_none());
    assert!(sub
        .auth("PLAIN", Some(right.as_bytes()))
        .await
        .reply()
        .starts_with(b"235 "));
}

/// MAIL FROM of an authenticated session is limited to the login's
/// grants; the null sender and logins without grants are refused.
/// Refusals happen before any DNS.
#[tokio::test]
async fn authenticated_mail_from_must_be_granted() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = session_cfg(dir.path());
    let mut s = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    s.mode = ListenerMode::Submission;

    s.authenticated = Some("alice".into());
    for refused in [
        "<ceo@victim.example>",
        "<bob@example.org>",
        "<alice@sub.alice.example>",
        "<>",
    ] {
        assert_eq!(
            s.mail_from(refused).await.into_reply(),
            SENDER_NOT_OWNED,
            "{refused}"
        );
        assert_eq!(s.mail_from, None);
    }
    assert!(s.mail_from("<ALICE@example.org>").await.is_accept());
    s.clear_envelope();
    assert!(s
        .mail_from("<anything@alice.example> SIZE=10")
        .await
        .is_accept());
    s.clear_envelope();

    // carol can authenticate but has no grants: fail closed.
    s.authenticated = Some("carol".into());
    assert_eq!(
        s.mail_from("<carol@example.org>").await.into_reply(),
        SENDER_NOT_OWNED
    );
}

/// Every From author of an authenticated message must be granted, even
/// when the envelope sender is; the refused transaction is cleared.
#[tokio::test]
async fn authenticated_from_authors_must_be_granted() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = session_cfg(dir.path());
    // Authors spanning several domains, and group syntax, are already
    // refused by the RFC 7489 malformed-From check, before this one.
    let malformed: &[u8] = b"550 5.7.1 Message rejected: missing or malformed From header\r\n";
    for (from, expected) in [
        ("From: CEO <ceo@victim.example>", FROM_NOT_OWNED),
        (
            "From: \"alice@example.org\" <ceo@victim.example>",
            FROM_NOT_OWNED,
        ),
        ("From: alice@example.org, bob@example.org", FROM_NOT_OWNED),
        ("From: alice@example.org, ceo@victim.example", malformed),
        ("From: undisclosed:;", malformed),
    ] {
        let mut s = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
        s.authenticated = Some("alice".into());
        assert!(s.mail_from("<alice@example.org>").await.is_accept());
        assert!(s.rcpt_to("<a@small.example>").await.is_accept());
        for line in [format!("{from}\r\n"), "\r\n".into(), "body\r\n".into()] {
            assert!(matches!(
                s.recv_data(line.as_bytes()).await,
                smtp::DataControl::Continue
            ));
        }
        let reply = s.end_data().await.into_reply();
        assert_eq!(reply, expected, "{from}");
        assert_eq!(s.mail_from, None, "transaction cleared");
        assert!(s.rcpt_to.is_empty());
    }
}

/// The message is refused at end-of-data with 550 before any DNS
/// work, and the transaction is cleared.
#[tokio::test]
async fn bare_cr_message_is_refused_before_dns() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = tests::size_limit_session(dir.path());
    let mut s = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    s.mail_from = Some("a@evil.example".into());
    s.data = b"Subject: x\rFrom: CEO <ceo@victim.example>\r\nFrom: a@evil.example\r\n\r\nbody\r\n"
        .to_vec();
    assert_eq!(s.end_data().await.into_reply(), BARE_CR_IN_HEADER);
    assert_eq!(s.mail_from, None);
    assert!(s.data.is_empty());
    assert_eq!(
        cfg.dns.stats().queries,
        0,
        "no DNS work for a refused message"
    );
}
