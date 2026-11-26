//! Session tests: the policy driven through `SmtpSession` methods and
//! in-memory streams.

use super::*;
use crate::testutil::*;

use std::sync::Arc;
use std::time::Duration;

impl UserSession<'_> {
    /// Start a transaction as if MAIL FROM `from` had been accepted (no
    /// SPF evaluated), for tests that begin at RCPT or DATA.
    fn begin(&mut self, from: &str) {
        self.txn = Some(Transaction::new(
            from.to_string(),
            None,
            None,
            self.max_data,
        ));
    }

    /// Returns the transaction in progress (panics without one).
    fn t(&mut self) -> &mut Transaction {
        self.txn.as_mut().expect("a transaction in progress")
    }
}

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
        storage: Arc::new(crate::quota::StorageLimits::unlimited()),
        probing: Arc::new(crate::limit::ProbeLimits::default()),
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
    assert!(session.txn.is_none());

    // End-of-data: 451 rather than skipping DKIM/DMARC; the envelope
    // is cleared.
    session.begin("a@sender.example");
    session.t().data = b"From: a@sender.example\r\nSubject: t\r\n\r\nbody\r\n".to_vec();
    let control = session.end_data().await;
    assert_eq!(control, smtp::Control::tempfail(DNS_BUSY));
    assert!(session.txn.is_none());
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
    session.begin("x@sender.example");

    assert!(session.rcpt_to("<a@small.example>").await.is_accept());
    assert_eq!(session.t().limit, 2048);

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
    assert!(session.txn.is_none());

    // A domain without its own limit keeps the server limit.
    session.begin("x@sender.example");
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());
    assert_eq!(session.t().limit, cfg.max_data);
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
    session.begin("x@sender.example");

    assert!(session.rcpt_to("<a@small.example>").await.is_accept());
    assert!(session.rcpt_to("<b@small.example>").await.is_accept());
    assert_eq!(
        session.rcpt_to("<c@big.example>").await,
        smtp::Control::tempfail(
            b"452 4.5.3 Recipient has a different size limit; send it in a separate transaction\r\n"
                .to_vec()
        )
    );
    assert_eq!(session.t().rcpt_to.len(), 2);
    assert_eq!(session.t().limit, 2048);

    // The other order: the big domain first, then the small one.
    session.clear_envelope();
    session.begin("x@sender.example");
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());
    assert!(matches!(
        session.rcpt_to("<a@small.example>").await,
        smtp::Control::Tempfail(_)
    ));
    assert_eq!(session.t().limit, cfg.max_data);
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
    session.begin("x@sender.example");
    session.t().declared_size = Some(4096);
    assert_eq!(
        session.rcpt_to("<a@small.example>").await,
        smtp::Control::reject(b"552 5.3.4 Message size exceeds the recipient's limit\r\n".to_vec())
    );
    assert!(session.t().rcpt_to.is_empty());
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
        storage: Arc::new(crate::quota::StorageLimits::unlimited()),
        probing: Arc::new(crate::limit::ProbeLimits::default()),
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);

    // DKIM stage: the key lookup for the signature never answers.
    session.begin("a@example.org");
    session.t().data =
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
    assert!(session.txn.is_none(), "the transaction is over");
    assert_eq!(session.message_count, 1);
    // It was the DKIM stage: one query (the key) was sent, and DKIM
    // never produced a result (a finished verification records one).
    assert_eq!(cfg.dns.stats().queries, 1);
    assert!(session.dkim.is_empty());

    // DMARC stage: no signature, so the policy fetch is what hangs.
    session.begin("a@example.org");
    session.t().data = b"From: a@example.org\r\nSubject: t\r\n\r\nbody\r\n".to_vec();
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
        storage: Arc::new(crate::quota::StorageLimits::unlimited()),
        probing: Arc::new(crate::limit::ProbeLimits::default()),
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
        temporary: false,
    });

    // Message 2: an unsigned spoof of the same domain.
    session.begin("x@attacker.example");
    session.t().data = b"From: someone@facebook.com\r\nSubject: spoof\r\n\r\nbody\r\n".to_vec();
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
        storage: Arc::new(crate::quota::StorageLimits::unlimited()),
        probing: Arc::new(crate::limit::ProbeLimits::default()),
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.begin("x@attacker.example");
    session.t().data = b"From: ceo@victim.example\r\nSubject: spoof\r\n\r\nbody\r\n".to_vec();
    let control = session.end_data().await;
    assert_eq!(control, smtp::Control::tempfail(DMARC_TEMPFAIL));
    assert!(session.txn.is_none(), "the transaction is over");
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
    assert!(sub.txn.is_none());
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
        assert!(s.txn.is_none());
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
        assert!(s.txn.is_none(), "transaction cleared");
    }
}

/// AUDIT_20261126C G1 (Medium, submission only). The grant check covers
/// the envelope sender and every `From:` author — but not the other
/// headers that name a sender. An authenticated login granted only
/// `alice@example.org` can submit a message carrying `Sender:`,
/// `Resent-From:` or `Resent-Sender:` naming any address at all, and it
/// is delivered under our `Authentication-Results:` `auth=pass` verdict
/// (verified against the live server). `Sender:` is the identity some
/// auto-responders, bounces and filters treat as the real sender, and
/// `Resent-From:` reads as a second, DMARC-unevaluated `From:` — so a
/// grant holder can claim an identity the operator never granted. The
/// envelope-sender check refuses these the same way (`550 5.7.1`); the
/// header sender checks must too. (`Reply-To:` stays free: redirecting
/// replies is ordinary mail practice.)
#[tokio::test]
async fn authenticated_sender_headers_must_be_granted() {
    let dir = tempfile::tempdir().unwrap();
    // NXDOMAIN for everything, so no DMARC policy exists and the
    // accepted-and-delivered path (today) answers 250, not 451.
    let mut cfg = session_cfg(dir.path());
    cfg.dns = spawn_nxdomain_resolver().await;
    for header in [
        "Sender: ceo@victim.example",
        "Resent-From: ceo@victim.example",
        "Resent-Sender: ceo@victim.example",
        // Not even the granted address itself disguised in the header is
        // the point of the check: an *ungranted* identity must refuse.
        "Sender: anyone@alice.example",
    ] {
        let mut s = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
        s.authenticated = Some("alice".into());
        assert!(s.mail_from("<alice@example.org>").await.is_accept());
        assert!(s.rcpt_to("<a@small.example>").await.is_accept());
        for line in [
            format!("From: alice@example.org\r\n{header}\r\n"),
            "\r\n".into(),
            "body\r\n".into(),
        ] {
            assert!(matches!(
                s.recv_data(line.as_bytes()).await,
                smtp::DataControl::Continue
            ));
        }
        let reply = s.end_data().await.into_reply();
        assert_eq!(reply, FROM_NOT_OWNED, "message with {header:?}");
        assert!(s.txn.is_none(), "transaction cleared");
    }
}

/// The message is refused at end-of-data with 550 before any DNS
/// work, and the transaction is cleared.
#[tokio::test]
async fn bare_cr_message_is_refused_before_dns() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = tests::size_limit_session(dir.path());
    let mut s = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    s.begin("a@evil.example");
    s.t().data =
        b"Subject: x\rFrom: CEO <ceo@victim.example>\r\nFrom: a@evil.example\r\n\r\nbody\r\n"
            .to_vec();
    assert_eq!(s.end_data().await.into_reply(), BARE_CR_IN_HEADER);
    assert!(s.txn.is_none());
    assert_eq!(
        cfg.dns.stats().queries,
        0,
        "no DNS work for a refused message"
    );
}

/// A header block of more than MAX_HEADER_FIELDS fields (two bytes
/// each, millions in a 10 MiB message, an entry apiece in every header
/// scan) is refused at end of data before DNS work or any header parse.
#[tokio::test]
async fn too_many_header_fields_are_refused_before_dns() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = tests::size_limit_session(dir.path());
    let mut s = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    s.begin("a@evil.example");
    let mut data = b"From: a@evil.example\r\n".to_vec();
    data.extend_from_slice(&b"a:b\r\n".repeat(MAX_HEADER_FIELDS));
    data.extend_from_slice(b"\r\nbody\r\n");
    s.t().data = data;
    assert_eq!(s.end_data().await.into_reply(), TOO_MANY_HEADER_FIELDS);
    assert!(s.txn.is_none());
    assert_eq!(
        cfg.dns.stats().queries,
        0,
        "no DNS work for a refused message"
    );
}

/// An accepted HELO/EHLO ends the transaction in progress, like RSET
/// (RFC 5321 §4.1.4): the next RCPT needs a new MAIL FROM.
#[tokio::test]
async fn ehlo_resets_the_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = size_limit_session(dir.path());
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.begin("x@sender.example");
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());

    assert!(session.helo(true, "client.test").await.is_accept());
    assert!(session.txn.is_none());
    assert_eq!(
        session.rcpt_to("<c@big.example>").await,
        smtp::Control::reject(b"503 5.5.1 Error: need MAIL command\r\n".to_vec())
    );
}

/// End of data takes the transaction: whatever the outcome it is gone
/// afterwards, and without one there is nothing to accept.
#[tokio::test]
async fn end_of_data_consumes_the_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = size_limit_session(dir.path());
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    assert_eq!(
        session.end_data().await,
        smtp::Control::reject(NO_RECIPIENTS)
    );
    assert_eq!(session.message_count, 0, "no message without a transaction");

    // A message refused at the first check still ends its transaction.
    session.begin("x@sender.example");
    session.t().data = b"Subject: x\rFrom: a@b.example\r\n\r\nbody\r\n".to_vec();
    assert_eq!(
        session.end_data().await,
        smtp::Control::reject(BARE_CR_IN_HEADER)
    );
    assert!(session.txn.is_none());
    assert_eq!(session.message_count, 1);
}

/// The mailbox quota is applied per recipient at RCPT: a full mailbox
/// gets `452 4.2.2` while other recipients of the same transaction are
/// accepted, and a size declared at MAIL FROM counts toward the quota.
#[tokio::test]
async fn mailbox_quota_defers_only_the_full_recipient() {
    let dir = tempfile::tempdir().unwrap();
    let sink = delivery::MaildirSink::open(dir.path().join("maildir")).unwrap();
    let rcpt = |a: &str| spool::SpoolRcpt {
        address: a.into(),
        mailbox: a.into(),
        user: None,
        public_key: None,
        key_generation: None,
    };
    use delivery::DeliverySink as _;
    sink.deliver(&rcpt("a@small.example"), "q-1", &[b'x'; 100])
        .unwrap();
    sink.deliver(&rcpt("b@small.example"), "q-1", &[b'x'; 50])
        .unwrap();
    let cfg = SessionConfig {
        sink: Some(Arc::new(sink)),
        storage: Arc::new(crate::quota::StorageLimits {
            mailbox_quota: Some(100),
            ..crate::quota::StorageLimits::unlimited()
        }),
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);

    session.begin("x@sender.example");
    assert_eq!(
        session.rcpt_to("<a@small.example>").await,
        smtp::Control::tempfail(crate::quota::MAILBOX_FULL)
    );
    assert!(session.rcpt_to("<b@small.example>").await.is_accept());
    assert_eq!(session.t().rcpt_to.len(), 1, "only b was accepted");

    // 50 stored + 60 declared is over 100.
    session.clear_envelope();
    session.begin("x@sender.example");
    session.t().declared_size = Some(60);
    assert_eq!(
        session.rcpt_to("<b@small.example>").await,
        smtp::Control::tempfail(crate::quota::MAILBOX_FULL)
    );
}

/// Copies of one message routed to one mailbox count against its quota
/// before anything is stored: each copy after the first at its declared
/// size, or, when none was declared, at its real size at end of data.
/// (All were checked against the same reading: 100 recipients put 20 MB
/// into a 10 MiB mailbox.) Counting undeclared copies at the size limit
/// instead deferred every copy after the first at the shipped defaults
/// (AUDIT_20261126 R8).
#[tokio::test]
async fn catch_all_copies_share_one_quota() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catch-authority.json");
    std::fs::write(
        &path,
        r#"{
            "version": 1,
            "domains": { "catch.example": { "mode": "catch-all",
                "catch-all-mailbox": "inbox@catch.example", "max-message-bytes": 2000 } },
            "mailboxes": {}
        }"#,
    )
    .unwrap();
    let sink = delivery::MaildirSink::open(dir.path().join("maildir")).unwrap();
    let cfg = SessionConfig {
        authority: Arc::new(authority::FileAuthority::open(&path).unwrap()),
        sink: Some(Arc::new(sink)),
        storage: Arc::new(crate::quota::StorageLimits {
            mailbox_quota: Some(5000),
            ..crate::quota::StorageLimits::unlimited()
        }),
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);

    // Declared 1500: 0, 1500 and 3000 pending fit; 4500 + 1500 doesn't.
    session.begin("x@sender.example");
    session.t().declared_size = Some(1500);
    for a in ["a", "b", "c"] {
        let reply = session.rcpt_to(&format!("<{a}@catch.example>")).await;
        assert!(reply.is_accept(), "{a}: {reply:?}");
    }
    assert_eq!(
        session.rcpt_to("<d@catch.example>").await,
        smtp::Control::tempfail(crate::quota::MAILBOX_FULL)
    );

    // Undeclared: nothing is known at RCPT, so every copy is accepted
    // there (the empty mailbox is under its quota)...
    session.clear_envelope();
    session.begin("x@sender.example");
    for a in ["a", "b", "c", "d"] {
        let reply = session.rcpt_to(&format!("<{a}@catch.example>")).await;
        assert!(reply.is_accept(), "{a}: {reply:?}");
    }
    assert_eq!(session.t().rcpt_to.len(), 4);
    // ...and the copies are counted at their real size at end of data:
    // the first is the one allowed overshoot, and 3 × 1800 more doesn't
    // fit under 5000.
    session.t().data = format!("From: x@sender.example\r\n\r\n{}", "x".repeat(1800)).into_bytes();
    assert_eq!(
        session.end_data().await,
        smtp::Control::tempfail(crate::quota::MAILBOX_FULL)
    );
}

/// A `SIZE` the sender lies about is never caught, and Q3's accounting
/// believes it: the quota is checked against the *declared* bytes only,
/// nothing compares them with the message, and the mailbox quota is not
/// asked again at end of data — so one transaction still puts
/// `MAX_RCPT` copies of the real message into one mailbox, the overshoot
/// the fix set out to remove (100 × 1.8 KB = 180 KB into a 5 KB mailbox
/// here; at the defaults, 100 × 10 MiB into a 10 MiB one).
///
/// Without `SIZE=` the fix works (each extra copy is then counted at the
/// transaction's size limit). Either a message over its declared size is
/// refused at end of data (RFC 1870 §6 lets the receiver do exactly that)
/// or the quota is re-checked with the received length before the copies
/// are committed.
#[tokio::test]
async fn a_lied_declared_size_still_defeats_one_mailbox_quota() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catch-authority.json");
    std::fs::write(
        &path,
        r#"{
            "version": 1,
            "domains": { "catch.example": { "mode": "catch-all",
                "catch-all-mailbox": "inbox@catch.example", "max-message-bytes": 2000 } },
            "mailboxes": {}
        }"#,
    )
    .unwrap();
    let maildir = dir.path().join("maildir");
    let sink = delivery::MaildirSink::open(&maildir).unwrap();
    let quota = 5_000;
    let cfg = SessionConfig {
        authority: Arc::new(authority::FileAuthority::open(&path).unwrap()),
        sink: Some(Arc::new(sink)),
        spool: Some(Arc::new(
            spool::DiskSpool::open(dir.path().join("spool"), None).unwrap(),
        )),
        // No policy anywhere, so an accepted message is delivered.
        dns: spawn_nxdomain_resolver().await,
        storage: Arc::new(crate::quota::StorageLimits {
            mailbox_quota: Some(quota),
            ..crate::quota::StorageLimits::unlimited()
        }),
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    // A real MAIL FROM, so `SIZE=10` arrives the way a sender sends it.
    assert!(
        session
            .mail_from("<x@sender.example> SIZE=10")
            .await
            .is_accept(),
        "SPF finds nothing to check, the transaction starts"
    );
    // Each copy is accounted at the declared 10 bytes, so all 100 fit.
    let mut accepted = 0;
    for i in 0..100 {
        if session
            .rcpt_to(&format!("<r{i}@catch.example>"))
            .await
            .is_accept()
        {
            accepted += 1;
        }
    }
    let message = [
        b"From: a@sender.example\r\n\r\n".as_slice(),
        &[b'x'; 1_800],
        b"\r\n".as_slice(),
    ]
    .concat();
    assert!(message.len() <= 2_000, "under the recipient's limit");
    session.t().data = message;
    let reply = session.end_data().await;

    // The fast path delivers in a spawned task; wait for its copies to
    // stop arriving.
    let new = maildir.join("catch.example/inbox/new");
    let mut stored = 0u64;
    let mut copies = 0usize;
    let mut stable = 0;
    for _ in 0..250 {
        let entries: Vec<_> = std::fs::read_dir(&new)
            .map(|d| d.filter_map(|e| e.ok()).collect())
            .unwrap_or_default();
        stable = usize::from(entries.len() == copies).saturating_add(stable);
        copies = entries.len();
        stored = entries
            .iter()
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum();
        if copies >= 100 || stable >= 10 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        stored <= quota + 2_000,
        "{stored} bytes stored in a {quota}-byte mailbox: {accepted} of 100 \
         recipients accepted, end_data {reply:?}, {copies} copies delivered. \
         The bound (DESIGN §5, the fix's own doc comment) is the quota plus one message."
    );
}

/// An over-long `From:` domain is stored whole in the spool metadata and
/// printed in the DMARC log record, because `mailbox_address` bounds its
/// characters but not its length (see `from_domain_length_is_bounded` in
/// `headers.rs`). Q4 bound the DKIM tags, the error text, the claims and
/// `header_token`, so the delivered message stays small — but the sidecar
/// beside it grows with the header: a 60 KB domain here makes a 60 KB
/// metadata file (measured), so one 10 MiB message costs 20 MiB on disk,
/// and `min-free-disk-bytes` is measured once before that.
#[tokio::test]
async fn spool_metadata_does_not_grow_with_the_from_domain() {
    let dns = spawn_mock_resolver(
        |name, qtype| match (name, qtype) {
            // The policy walk's last candidate is the domain's two-label
            // suffix, which the sender chooses, so a record is found and
            // `from_domain` is kept.
            ("_dmarc.attacker.example", 16) => MockAnswer::Txt("v=DMARC1; p=none"),
            _ => MockAnswer::Rcode(3),
        },
        Duration::from_secs(5),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let spool_dir = dir.path().join("spool");
    let cfg = SessionConfig {
        dns,
        spool: Some(Arc::new(spool::DiskSpool::open(&spool_dir, None).unwrap())),
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.begin("x@sender.example");
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());
    let junk = "ab.".repeat(20_000);
    session.t().data =
        format!("From: \"ceo@victim.example\" <a@{junk}attacker.example>\r\n\r\nbody\r\n")
            .into_bytes();
    let reply = session.end_data().await;
    // Refusing such a message (it has no DNS wire form, so DMARC is
    // skipped today) is an acceptable answer too.
    if !reply.is_accept() {
        return;
    }
    let new = spool_dir.join("new");
    let json = std::fs::read_dir(&new)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.to_string_lossy().ends_with(".json"))
        .expect("an accepted message is spooled");
    let meta: serde_json::Value = serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
    let from_domain = meta["dmarc"]["from_domain"].as_str().unwrap_or("");
    let size = std::fs::metadata(&json).unwrap().len();
    assert!(
        size <= 4 * 1024,
        "the {}-byte metadata file keeps a {}-octet from_domain: {from_domain:.80}...",
        size,
        from_domain.len()
    );
}

/// Below the free-disk floor, MAIL FROM is deferred (no transaction
/// starts), and so is a message that reaches end of data.
#[tokio::test]
async fn low_disk_defers_new_mail() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = SessionConfig {
        storage: Arc::new(crate::quota::StorageLimits {
            min_free_disk: Some(u64::MAX),
            watched: vec![dir.path().to_path_buf()],
            ..crate::quota::StorageLimits::unlimited()
        }),
        // No DMARC policy anywhere, so end of data reaches the storage check.
        dns: spawn_nxdomain_resolver().await,
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    assert_eq!(
        session.mail_from("<x@sender.example>").await,
        smtp::Control::tempfail(crate::quota::INSUFFICIENT_STORAGE)
    );
    assert!(session.txn.is_none());

    // The disk filled up mid-transaction: the message isn't spooled.
    session.begin("x@sender.example");
    session.t().data = b"From: x@sender.example\r\n\r\nbody\r\n".to_vec();
    assert_eq!(
        session.end_data().await,
        smtp::Control::tempfail(crate::quota::INSUFFICIENT_STORAGE)
    );
    assert!(session.txn.is_none());
}

/// The authority's quota beats the server default both ways: a larger
/// per-mailbox quota and an explicit "no quota" accept a mailbox the
/// default would defer, while one without its own value gets the default.
#[tokio::test]
async fn authority_quota_overrides_the_server_default() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("quota-authority.json"); // size_limit_session writes authority.json
    std::fs::write(
        &path,
        r#"{
            "version": 1,
            "domains": { "q.example": { "mode": "reject" } },
            "mailboxes": {
                "roomy@q.example": { "user": "r", "expires": null, "quota-bytes": 5000 },
                "open@q.example": { "user": "o", "expires": null, "quota-bytes": 0 },
                "std@q.example": { "user": "s", "expires": null }
            }
        }"#,
    )
    .unwrap();
    let sink = delivery::MaildirSink::open(dir.path().join("maildir")).unwrap();
    use delivery::DeliverySink as _;
    for a in ["roomy@q.example", "open@q.example", "std@q.example"] {
        let rcpt = spool::SpoolRcpt {
            address: a.into(),
            mailbox: a.into(),
            user: None,
            public_key: None,
            key_generation: None,
        };
        sink.deliver(&rcpt, "q-1", &[b'x'; 2000]).unwrap();
    }
    let cfg = SessionConfig {
        authority: Arc::new(authority::FileAuthority::open(&path).unwrap()),
        sink: Some(Arc::new(sink)),
        storage: Arc::new(crate::quota::StorageLimits {
            mailbox_quota: Some(1000),
            ..crate::quota::StorageLimits::unlimited()
        }),
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.begin("x@sender.example");
    assert!(session.rcpt_to("<roomy@q.example>").await.is_accept());
    assert!(session.rcpt_to("<open@q.example>").await.is_accept());
    assert_eq!(
        session.rcpt_to("<std@q.example>").await,
        smtp::Control::tempfail(crate::quota::MAILBOX_FULL)
    );
}

/// Address probing, per connection: each refusal up to the limit gets its
/// `550`, then the next RCPT (even a valid one) gets `421` and closes the
/// connection. RSET doesn't reset the count, and relay attempts count too.
#[tokio::test]
async fn refused_recipients_close_the_connection() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = SessionConfig {
        probing: Arc::new(crate::limit::ProbeLimits::new(3, 0)),
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.begin("x@sender.example");
    for rcpt in ["<nobody@small.example>", "<ghost@small.example>"] {
        assert_eq!(
            session.rcpt_to(rcpt).await,
            smtp::Control::reject(b"550 5.1.1 No such mailbox\r\n".to_vec())
        );
    }
    assert!(
        session.rcpt_to("<a@small.example>").await.is_accept(),
        "not a refusal"
    );

    // RSET keeps the count; a relay attempt is the third refusal.
    session.clear_envelope();
    session.begin("x@sender.example");
    assert_eq!(
        session.rcpt_to("<victim@elsewhere.example>").await,
        smtp::Control::reject(b"550 5.7.1 Relay access denied\r\n".to_vec())
    );
    assert_eq!(
        session.rcpt_to("<b@small.example>").await,
        smtp::Control::close(TOO_MANY_REFUSED),
        "a valid recipient gets the same 421"
    );
}

/// Address probing, per source IP: refusals count across connections, so
/// reconnecting doesn't reset them; another IP is unaffected.
#[tokio::test]
async fn refused_recipients_are_limited_per_ip() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = SessionConfig {
        probing: Arc::new(crate::limit::ProbeLimits::new(0, 2)),
        ..size_limit_session(dir.path())
    };
    let mut first = UserSession::new("192.0.2.5:40000".parse().unwrap(), false, &cfg);
    first.begin("x@sender.example");
    for rcpt in ["<nobody@small.example>", "<ghost@small.example>"] {
        assert!(matches!(
            first.rcpt_to(rcpt).await,
            smtp::Control::Reject(_)
        ));
    }

    let mut again = UserSession::new("192.0.2.5:40001".parse().unwrap(), false, &cfg);
    again.begin("x@sender.example");
    assert_eq!(
        again.rcpt_to("<a@small.example>").await,
        smtp::Control::close(TOO_MANY_REFUSED)
    );

    let mut other = UserSession::new("192.0.2.6:40000".parse().unwrap(), false, &cfg);
    other.begin("x@sender.example");
    assert!(other.rcpt_to("<a@small.example>").await.is_accept());
}

/// A bounce (null sender) from a `p=reject` domain, unsigned, aligns
/// through SPF on the HELO identity: the HELO host's SPF passes and
/// shares the From domain's organizational domain, so DMARC passes. A
/// HELO host of another organization still fails.
#[tokio::test]
async fn bounces_align_through_the_helo_identity() {
    let dns = spawn_mock_resolver(
        |name, qtype| match (name, qtype) {
            (n, 16) if n.starts_with("_dmarc.") => MockAnswer::Txt("v=DMARC1; p=reject"),
            ("mta.bounce-example.org" | "mta.other-example.org", 16) => {
                MockAnswer::Txt("v=spf1 ip4:127.0.0.1 -all")
            }
            _ => MockAnswer::Rcode(3),
        },
        Duration::from_secs(5),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = SessionConfig {
        dns,
        ..size_limit_session(dir.path())
    };
    let bounce = b"From: MAILER-DAEMON@bounce-example.org\r\nSubject: Undelivered\r\n\r\nbody\r\n";

    for (helo, accepted) in [
        ("mta.bounce-example.org", true),
        ("mta.other-example.org", false),
    ] {
        let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
        assert!(session.helo(true, helo).await.is_accept());
        assert!(
            session.mail_from("<>").await.is_accept(),
            "SPF passes for {helo}"
        );
        assert!(session.rcpt_to("<c@big.example>").await.is_accept());
        session.t().data = bounce.to_vec();
        let reply = session.end_data().await;
        assert_eq!(reply.is_accept(), accepted, "{helo}: {reply:?}");
        assert_eq!(
            session.dmarc.as_ref().map(|d| d.spf_aligned),
            Some(accepted)
        );
    }
}

/// End to end: the stored message carries our Authentication-Results and
/// the display-name warning, the sender's forged Authentication-Results
/// claiming our authserv-id is gone, and the metadata records the claim.
#[tokio::test]
async fn stored_message_carries_our_verdicts_only() {
    let dir = tempfile::tempdir().unwrap();
    let spool_dir = dir.path().join("spool");
    let cfg = SessionConfig {
        dns: spawn_nxdomain_resolver().await,
        spool: Some(Arc::new(spool::DiskSpool::open(&spool_dir, None).unwrap())),
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.begin("x@attacker.example");
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());
    session.t().data =
        b"Authentication-Results: mail.test; dmarc=pass header.from=victim.example\r\n\
From: \"ceo@victim.example\" <x@attacker.example>\r\n\
Subject: wire the money\r\n\r\nbody\r\n"
            .to_vec();
    assert!(session.end_data().await.is_accept());

    let new = spool_dir.join("new");
    let names = std::fs::read_dir(&new)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let eml = names.iter().find(|n| n.ends_with(".eml")).unwrap();
    let text = String::from_utf8(std::fs::read(new.join(eml)).unwrap()).unwrap();
    assert_eq!(text.matches("Authentication-Results:").count(), 1, "{text}");
    // (`begin` skips SPF, so there is no spf= result.)
    assert!(
        text.contains("Authentication-Results: mail.test;\r\n\tdkim=none;"),
        "{text}"
    );
    assert!(
        text.contains("\tdmarc=none\r\n"),
        "ours, not the forged pass: {text}"
    );
    assert!(text.contains("X-Display-Name-Warning: the From display name names victim.example"));
    let json = names.iter().find(|n| n.ends_with(".json")).unwrap();
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(new.join(json)).unwrap()).unwrap();
    assert_eq!(
        meta["display_name_claims"],
        serde_json::json!(["victim.example"])
    );
}

/// A transient DNS failure must never turn into a permanent refusal: a
/// `p=reject` domain's message whose DKIM key lookup gets SERVFAIL is
/// deferred (451, the sender retries), while the same message whose key
/// definitely doesn't exist (NXDOMAIN) is rejected (550).
#[tokio::test]
async fn dkim_key_servfail_defers_instead_of_rejecting() {
    let message =
        b"DKIM-Signature: v=1; a=rsa-sha256; d=victim.example; s=sel; h=From; bh=AAAA; b=AAAA\r\n\
From: ceo@victim.example\r\nSubject: s\r\n\r\nbody\r\n";
    for (key_rcode, expect_temp) in [(2u8, true), (3u8, false)] {
        let dns = spawn_mock_resolver(
            move |name, qtype| match (name, qtype) {
                (n, 16) if n.starts_with("_dmarc.") => MockAnswer::Txt("v=DMARC1; p=reject"),
                ("sel._domainkey.victim.example", 16) => MockAnswer::Rcode(key_rcode),
                _ => MockAnswer::Rcode(3),
            },
            Duration::from_secs(5),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let cfg = SessionConfig {
            dns,
            ..size_limit_session(dir.path())
        };
        let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
        session.begin("x@sender.example");
        assert!(session.rcpt_to("<c@big.example>").await.is_accept());
        session.t().data = message.to_vec();
        let reply = session.end_data().await;
        if expect_temp {
            assert_eq!(reply, smtp::Control::tempfail(DMARC_TEMPFAIL), "SERVFAIL");
        } else {
            assert!(
                matches!(reply, smtp::Control::Reject(_)),
                "NXDOMAIN: {reply:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Audit regression tests (2026-11-26, docs/reviews/AUDIT_20261126.md)
// ---------------------------------------------------------------------------

/// Unfold the header block of a stored message the way a mail reader
/// does: a line beginning with whitespace continues the field before it.
/// Returns the value of the named field, unfolded, lowercased.
fn delivered_header(message: &str, name: &str) -> String {
    let block = message.split("\r\n\r\n").next().unwrap_or(message);
    let mut value = String::new();
    let mut found = false;
    for line in block.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            if found {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        let Some((field, rest)) = line.split_once(':') else {
            found = false;
            continue;
        };
        found = field.trim().eq_ignore_ascii_case(name);
        if found {
            value = rest.trim().to_string();
        }
    }
    value
}

/// R1 (High). The message's own first line is placed verbatim after the
/// headers this server prepends, so when it is a folding continuation it
/// becomes part of *our* `Authentication-Results:` header. The sender can
/// then add clauses (anything after a `;`) that the next hop reads as
/// this server's authenticated verdict — the exact thing
/// [`strip_forged_verdicts`] exists to prevent, reached from the other
/// side. Nothing refuses a message that begins with a continuation line.
#[tokio::test]
async fn a_leading_continuation_cannot_extend_our_verdict_headers() {
    let dir = tempfile::tempdir().unwrap();
    let spool_dir = dir.path().join("spool");
    let cfg = SessionConfig {
        dns: spawn_nxdomain_resolver().await,
        spool: Some(Arc::new(spool::DiskSpool::open(&spool_dir, None).unwrap())),
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.begin("x@attacker.example");
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());
    assert!(session.start_data().await.is_accept());
    // RFC 5322 forbids folding the first line, so this text belongs to no
    // field of the sender's message: `strip_forged_verdicts` and the From
    // scan both ignore it. Delivered, it extends our header instead.
    for line in [
        b"\tspf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com\r\n".as_slice(),
        b"From: x@attacker.example\r\n".as_slice(),
        b"Subject: t\r\n".as_slice(),
        b"\r\n".as_slice(),
        b"body\r\n".as_slice(),
    ] {
        assert!(
            matches!(session.recv_data(line).await, smtp::DataControl::Continue),
            "{}",
            String::from_utf8_lossy(line)
        );
    }
    let reply = session.end_data().await;
    assert!(reply.is_accept(), "{reply:?}");

    let new = spool_dir.join("new");
    let eml = std::fs::read_dir(&new)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "eml"))
        .expect("a spooled message");
    let text = String::from_utf8(std::fs::read(&eml).unwrap()).unwrap();
    let ar = delivered_header(&text, "Authentication-Results");
    assert!(
        !ar.contains("paypal.com"),
        "the sender wrote clauses into our trusted header: {ar}"
    );
}

/// The same fold attaches to `X-Display-Name-Warning:` when the message
/// carries one (it is the last header written).
#[tokio::test]
async fn a_leading_continuation_cannot_extend_the_display_name_warning() {
    let dir = tempfile::tempdir().unwrap();
    let spool_dir = dir.path().join("spool");
    let cfg = SessionConfig {
        dns: spawn_nxdomain_resolver().await,
        spool: Some(Arc::new(spool::DiskSpool::open(&spool_dir, None).unwrap())),
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.begin("x@attacker.example");
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());
    session.t().data = b"\t; dmarc=pass (our mail is safe)\r\n\
          From: \"ceo@victim.example\" <x@attacker.example>\r\n\
          Subject: t\r\n\r\nbody\r\n"
        .to_vec();
    assert!(session.end_data().await.is_accept());
    let new = spool_dir.join("new");
    let eml = std::fs::read_dir(&new)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "eml"))
        .unwrap();
    let text = String::from_utf8(std::fs::read(&eml).unwrap()).unwrap();
    let warn = delivered_header(&text, "X-Display-Name-Warning");
    assert!(
        warn.contains("victim.example"),
        "our warning is missing: {warn}"
    );
    assert!(
        !warn.contains("our mail is safe"),
        "the sender appended to our warning: {warn}"
    );
}

/// R2 (Medium). A MAIL FROM whose address has no queryable domain (an
/// empty one, or one with characters DNS refuses) is accepted with SPF
/// `none`, so the sender dodges the Fail rejection this server promises
/// (DESIGN §5: "Fail or PermError -> 550") and the delivered
/// `Authentication-Results:` records `spf=none` for a domain that
/// publishes `-all`. `MAIL FROM` applies no address-syntax rule at all:
/// [`mailserv::address::clean_path`] only refuses control characters, and
/// the domain is whatever follows the last `@`. The same envelope, sent
/// as `<ceo@paypal.com>`, is refused with `550`.
#[tokio::test]
async fn a_mail_from_domain_that_cannot_be_looked_up_is_not_spf_checked() {
    let dns = spawn_mock_resolver(
        |name, qtype| match (name, qtype) {
            ("paypal.com", 16) => MockAnswer::Txt("v=spf1 -all"),
            _ => MockAnswer::Rcode(3),
        },
        Duration::from_secs(5),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = SessionConfig {
        dns,
        ..size_limit_session(dir.path())
    };
    // Measured replies, release build: 550 is the SPF refusal, 250 is an
    // accepted envelope whose sender domain was never queried.
    for path in [
        "<ceo@paypal.com@>",  // empty domain after the last '@'
        "<ceo@paypal.com;>",  // a domain DNS refuses: never queried
        "<ceo@paypal.com@x>", // a one-label domain: no record, no Fail
    ] {
        let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
        let control = session.mail_from(path).await;
        assert!(
            !control.is_accept(),
            "MAIL FROM:{path} was accepted with {:?}; the sender domain's \
             `-all` record was never evaluated",
            session.txn.as_ref().map(|t| t.spf_result)
        );
    }
    // (For reference: the plain address is refused.)
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    assert!(matches!(
        session.mail_from("<ceo@paypal.com>").await,
        smtp::Control::Reject(_)
    ));
}

/// R7 (Medium-Low). A forged verdict header survives
/// [`strip_forged_verdicts`] by sitting in a folded continuation of the
/// field before it. The shared raw scanner is right (RFC 5322: it is part
/// of `Subject:`), but the line reaches the mailbox verbatim, where a
/// consumer that splits header lines on newlines — the class of bug the
/// bare-CR refusal exists for, reached through legitimate folding — reads
/// an `Authentication-Results:` from our authserv-id that we never sent.
#[tokio::test]
async fn a_forged_verdict_cannot_hide_in_a_continuation_line() {
    let dir = tempfile::tempdir().unwrap();
    let spool_dir = dir.path().join("spool");
    let cfg = SessionConfig {
        dns: spawn_nxdomain_resolver().await,
        spool: Some(Arc::new(spool::DiskSpool::open(&spool_dir, None).unwrap())),
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.begin("x@attacker.example");
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());
    session.t().data = concat!(
        "Subject: hi\r\n",
        "\tAuthentication-Results: mail.test; dmarc=pass header.from=victim.example\r\n",
        "\tX-Display-Name-Warning: no risk here\r\n",
        "From: \"ceo@victim.example\" <x@attacker.example>\r\n",
        "\r\n",
        "body\r\n",
    )
    .as_bytes()
    .to_vec();
    assert!(session.end_data().await.is_accept());

    let new = spool_dir.join("new");
    let eml = std::fs::read_dir(&new)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "eml"))
        .unwrap();
    let text = String::from_utf8(std::fs::read(&eml).unwrap()).unwrap();
    // Exactly one AR line and one warning line, however a reader splits
    // the block: ours.
    let claimed = |name: &str| {
        text.split("\r\n")
            .filter(|l| l.trim_start().to_ascii_lowercase().starts_with(name))
            .count()
    };
    assert_eq!(
        claimed("authentication-results:"),
        1,
        "a line-splitting reader sees a second AR: {text}"
    );
    assert_eq!(
        claimed("x-display-name-warning:"),
        1,
        "a line-splitting reader sees a second warning: {text}"
    );
}

/// R3 (Medium). The per-session recipient cache is never bounded, and it
/// survives every transaction: one connection may keep an entry (with the
/// authority's `mailbox`, `user` and `public_key` clones) for every
/// distinct address it has ever been accepted for.
#[tokio::test]
async fn the_recipient_cache_is_bounded_per_connection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catch-authority.json");
    std::fs::write(
        &path,
        r#"{
            "version": 1,
            "domains": { "catch.example": { "mode": "catch-all",
                "catch-all-mailbox": "inbox@catch.example" } },
            "mailboxes": { "inbox@catch.example": { "user": "inbox",
                "public-key": "age1qyq", "key-generation": 3 } }
        }"#,
    )
    .unwrap();
    let cfg = SessionConfig {
        authority: Arc::new(authority::FileAuthority::open(&path).unwrap()),
        dns: spawn_nxdomain_resolver().await,
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    // 200 transactions, 100 distinct recipients each: MAIL FROM:<> with an
    // address-literal HELO costs no DNS, and a message with no From: is
    // refused before any lookup, so the only cost is the recipient check.
    for round in 0..200 {
        session.begin("");
        for i in 0..100 {
            let rcpt = format!("u{round}-{i}@catch.example");
            assert!(
                session.rcpt_to(&format!("<{rcpt}>")).await.is_accept(),
                "{rcpt}"
            );
        }
        session.t().data = b"Subject: no from\r\n\r\nbody\r\n".to_vec();
        session.end_data().await;
    }
    assert!(
        session.rcpt_cache.len() <= 100 * 10,
        "{} accepted recipients kept by one connection \
         (about {} KB of authority data)",
        session.rcpt_cache.len(),
        std::mem::size_of::<authority::Recipient>() * session.rcpt_cache.len() / 1024,
    );
}

/// End of data for one `From:` header, as an unauthenticated MX session.
async fn sp_policy_verdict(cfg: &SessionConfig, from: &str) -> smtp::Control {
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, cfg);
    session.begin("x@sender.example");
    assert!(session.rcpt_to("<c@big.example>").await.is_accept());
    session.t().data = format!("From: {from}\r\nSubject: t\r\n\r\nbody\r\n").into_bytes();
    session.end_data().await
}

/// R4 (Medium). `FoundPolicy::policy_for` decides "subdomain" with a
/// literal `.record_domain` suffix test, while the record was *found* by
/// the ancestor walk of `policy_candidates`, which trims trailing dots.
/// A `From:` domain that keeps a trailing dot (`x@sub.paypal.com..`,
/// which [`mailserv::headers::mailbox_address`] accepts because it checks
/// a domain's characters and length but not for empty labels) is
/// therefore treated as the record's own domain: the stricter `sp=`
/// never applies, and a `p=none; sp=reject` publisher rejects nothing.
#[tokio::test]
async fn a_subdomain_policy_applies_whatever_the_from_domain_spelling() {
    let dns = spawn_mock_resolver(
        |name, qtype| match (name, qtype) {
            ("_dmarc.paypal.com", 16) => MockAnswer::Txt("v=DMARC1; p=none; sp=reject"),
            _ => MockAnswer::Rcode(3),
        },
        Duration::from_secs(5),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = SessionConfig {
        dns,
        ..size_limit_session(dir.path())
    };

    // The plain subdomain: sp=reject applies, the message is refused.
    let plain = sp_policy_verdict(&cfg, "ceo@sub.paypal.com").await;
    assert!(
        matches!(plain, smtp::Control::Reject(_)),
        "expected the subdomain policy: {plain:?}"
    );
    // The same subdomain with a trailing dot left in the domain: the
    // parent's p=none is used instead, and the message is accepted.
    let dotted = sp_policy_verdict(&cfg, "ceo@sub.paypal.com..").await;
    assert!(
        matches!(dotted, smtp::Control::Reject(_),),
        "a trailing dot skips sp=reject and the message is delivered: {dotted:?}"
    );
}

/// R5 (Medium). Two per-connection accumulators have no bound at all:
/// `UserSession::dkim` (every signature verdict of every message on the
/// connection, kept for the session record) and the recipient cache. The
/// connection summary is then `serde_json::to_string(&session)`, so a
/// sender controls the size of one log record — and of the connection's
/// retained memory — by how many messages it sends.
#[tokio::test]
async fn the_session_record_stays_bounded_across_messages() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = SessionConfig {
        dns: spawn_mock_resolver(
            |name, qtype| match (name, qtype) {
                (n, 16) if n.starts_with("_dmarc.") => MockAnswer::Txt("v=DMARC1; p=none"),
                (n, 16) if n.ends_with("._domainkey.x.example") => {
                    MockAnswer::Txt("v=DKIM1; k=rsa; p=AAAA")
                }
                _ => MockAnswer::Rcode(3),
            },
            Duration::from_secs(5),
        )
        .await,
        ..size_limit_session(dir.path())
    };
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    let message = b"DKIM-Signature: v=1; a=rsa-sha256; d=x.example; s=sel; h=From; \
                    bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n\
                    DKIM-Signature: v=1; a=rsa-sha256; d=x.example; s=sel2; h=From; \
                    bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n\
                    DKIM-Signature: v=1; a=rsa-sha256; d=x.example; s=sel3; h=From; \
                    bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAA\r\n\
                    From: x@attacker.example\r\nSubject: t\r\n\r\nbody\r\n";
    for _ in 0..500 {
        session.begin("x@sender.example");
        assert!(session.rcpt_to("<c@big.example>").await.is_accept());
        session.t().data = message.to_vec();
        session.end_data().await;
    }
    let record = serde_json::to_string(&session).unwrap();
    assert!(
        session.dkim.len() <= 5 * 100 && record.len() < 64 * 1024,
        "{} dkim verdicts and a {} KB session record from {} messages",
        session.dkim.len(),
        record.len() / 1024,
        session.message_count,
    );
}

/// R8 (Medium). The Q3 quota fix reserves the transaction's *size limit*
/// for every copy already accepted to one mailbox. The shipped defaults
/// make that reservation equal the default mailbox quota
/// (`mailbox-quota-bytes` = `max-data-bytes` = 10 MiB), so a mailbox whose
/// quota is the default accepts exactly one recipient per transaction
/// under catch-all (or with aliases): every later one is deferred with
/// `452 4.2.2`, however small the message is, forever. Reproduced live:
/// three recipients at a catch-all domain of an idle 1-byte mailbox got
/// `250`, `452`, `452`.
#[tokio::test]
async fn catch_all_recipients_fit_the_default_quota() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catch-authority.json");
    std::fs::write(
        &path,
        r#"{
            "version": 1,
            "domains": { "catch.example": { "mode": "catch-all",
                "catch-all-mailbox": "inbox@catch.example" } },
            "mailboxes": {}
        }"#,
    )
    .unwrap();
    let max_data = 64 * 1024;
    let mut cfg = size_limit_session(dir.path());
    cfg.max_data = max_data;
    cfg.authority = Arc::new(authority::FileAuthority::open(&path).unwrap());
    cfg.dns = spawn_nxdomain_resolver().await;
    cfg.sink = Some(Arc::new(
        delivery::MaildirSink::open(dir.path().join("maildir")).unwrap(),
    ));
    cfg.storage = Arc::new(crate::quota::StorageLimits {
        mailbox_quota: Some(max_data as u64),
        ..crate::quota::StorageLimits::unlimited()
    });
    let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
    session.begin("x@sender.example");
    let mut deferred = Vec::new();
    for i in 0..3 {
        let rcpt = format!("person{i}@catch.example");
        let reply = session.rcpt_to(&format!("<{rcpt}>")).await;
        if !reply.is_accept() {
            deferred.push((rcpt, reply));
        }
    }
    assert!(
        deferred.is_empty(),
        "three recipients of one small message to a catch-all mailbox, in an \
         empty mailbox whose quota is the default (= the size limit): {deferred:?}"
    );
    // The message itself is a tenth of the limit: all three copies fit.
    session.t().data = format!(
        "From: x@sender.example\r\n\r\n{}",
        "x".repeat(max_data / 10)
    )
    .into_bytes();
    assert!(session.end_data().await.is_accept());
}
