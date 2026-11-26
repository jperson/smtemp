//! Server tests: whole connections over TCP (and TLS) against
//! [`super::handle_connection`].

use super::*;
use crate::session::*;
use crate::testutil::*;
use crate::tls::tls_acceptor_from_pem;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream as TestTcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{rustls::RootCertStore, TlsConnector as TestTlsConnector};

/// Spawn handle_connection on an ephemeral port, handling exactly
/// one connection with the given TLS `acceptor`, `auth`, `spool` and
/// `sink`. When `authority` is None, the static fallback is built
/// from `local_domains` (default `example.org`).
///
/// Returns the address to connect to.
async fn spawn_server(
    acceptor: Option<Arc<TlsAcceptor>>,
    auth: Option<Arc<auth::AuthConfig>>,
    local_domains: Option<Vec<String>>,
    spool: Option<Arc<dyn spool::SpoolWriter>>,
    sink: Option<Arc<dyn delivery::DeliverySink>>,
    authority: Option<Arc<dyn authority::RecipientResolver>>,
) -> std::net::SocketAddr {
    spawn_server_in(
        ListenerMode::Mx,
        acceptor,
        auth,
        local_domains,
        spool,
        sink,
        authority,
    )
    .await
}

/// As [`spawn_server`], for a `mode` listener.
async fn spawn_server_in(
    mode: ListenerMode,
    acceptor: Option<Arc<TlsAcceptor>>,
    auth: Option<Arc<auth::AuthConfig>>,
    local_domains: Option<Vec<String>>,
    spool: Option<Arc<dyn spool::SpoolWriter>>,
    sink: Option<Arc<dyn delivery::DeliverySink>>,
    authority: Option<Arc<dyn authority::RecipientResolver>>,
) -> std::net::SocketAddr {
    let authority: Arc<dyn authority::RecipientResolver> = match authority {
        Some(a) => a,
        None => Arc::new(authority::StaticAuthority::new(
            local_domains
                .unwrap_or_else(|| vec!["example.org".to_string()])
                .into_iter()
                .map(|d| d.to_ascii_lowercase())
                .collect::<Vec<_>>(),
        )),
    };
    let cfg = SessionConfig {
        domain: "mail.example.org".to_string(),
        max_data: 1024 * 1024,
        auth,
        authority,
        // The whole DNS path runs against a local DoT mock that says
        // NXDOMAIN, as the real DNS does for the test domains: SPF is
        // None, no DMARC policy.
        dns: spawn_nxdomain_resolver().await,
        dns_limit: Arc::new(limit::DnsLimiter::new(
            limit::DEFAULT_DNS_PER_IP,
            limit::DNS_LIMIT_WAIT,
        )),
        shutdown: no_shutdown(),
        eod_dns_deadline: END_OF_DATA_DNS_DEADLINE,
        spool,
        sink,
        deadline: None,
        fast_path: Arc::new(tokio::sync::Semaphore::new(16)),
        storage: Arc::new(crate::quota::StorageLimits::unlimited()),
        probing: Arc::new(crate::limit::ProbeLimits::default()),
    };
    spawn_server_with(mode, acceptor, cfg).await
}

/// Serve one connection on an ephemeral port as a `mode` listener with
/// TLS configuration `acceptor` and session configuration `cfg`.
///
/// Returns the address to connect to.
async fn spawn_server_with(
    mode: ListenerMode,
    acceptor: Option<Arc<TlsAcceptor>>,
    cfg: SessionConfig,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((stream, _peer)) = listener.accept().await {
            let _ = handle_connection(stream, acceptor, 5000, cfg, mode).await;
        }
    });
    addr
}

/// Wait up to 5 s for `dir` to hold at least `count` files (work that
/// finishes after the SMTP reply, like the delivery fast path).
///
/// Returns the sorted file names found (fewer than `count` on timeout,
/// for the caller's assertion to report).
async fn wait_for_files(dir: &std::path::Path, count: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        if names.len() >= count || Instant::now() >= deadline {
            return names;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn starttls_full_upgrade() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let acceptor = Arc::new(
        tls_acceptor_from_pem(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap(),
    );
    let addr = spawn_server(Some(acceptor), None, None, None, None, None).await;

    // --- Plaintext phase.
    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);

    let greet = read_reply(&mut client).await;
    assert_eq!(greet[0], "220 mail.example.org SMTP service ready\r\n");

    client.write_all(b"EHLO client.test\r\n").await.unwrap();
    let caps = read_reply(&mut client).await;
    // STARTTLS must be advertised on the plaintext connection.
    assert!(
        caps.iter().any(|l| l.starts_with("250-STARTTLS")),
        "caps: {caps:?}"
    );
    assert!(caps.iter().any(|l| l.starts_with("250-SIZE ")));
    assert_eq!(caps.last().unwrap(), "250 HELP\r\n");

    client.write_all(b"STARTTLS\r\n").await.unwrap();
    let ready = read_reply(&mut client).await;
    assert_eq!(ready[0], "220 2.0.0 Ready to start TLS\r\n");

    // --- The handshake, exactly as a driver client would.
    let tcp = client.into_inner();
    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TestTlsConnector::from(Arc::new(config));
    let tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();

    // --- Secure phase: protocol restarted, no new banner, no
    // STARTTLS advertisement, and repeated STARTTLS refused.
    let mut client = BufReader::new(tls);

    client.write_all(b"EHLO client.test\r\n").await.unwrap();
    let caps = read_reply(&mut client).await;
    assert!(caps.iter().any(|l| l.starts_with("250-SIZE ")));
    assert!(
        !caps.iter().any(|l| l.contains("STARTTLS")),
        "STARTTLS must not be advertised on an established TLS connection"
    );

    client.write_all(b"STARTTLS\r\n").await.unwrap();
    let refused = read_reply(&mut client).await;
    assert_eq!(refused[0], "503 5.5.1 TLS already active\r\n");

    // A message is submitted over the TLS connection end-to-end.
    client
        .write_all(b"MAIL FROM:<sender@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client
        .write_all(b"RCPT TO:<rcpt@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"DATA\r\n").await.unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "354 End data with <CR>.<CR><LF>\r\n"
    );
    client
        .write_all(b"Subject: over TLS\r\nFrom: sender@spfless-domain-xyz.test\r\n\r\nsecure body.\r\n.\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();
    assert_eq!(read_reply(&mut client).await[0], "221 Bye\r\n");
}

/// Without a configured certificate, STARTTLS is refused and the
/// session continues in the clear.
#[tokio::test]
async fn starttls_unavailable_is_refused() {
    let addr = spawn_server(None, None, None, None, None, None).await;
    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;

    client.write_all(b"EHLO client.test\r\n").await.unwrap();
    let caps = read_reply(&mut client).await;
    assert!(!caps.iter().any(|l| l.contains("STARTTLS")));

    client.write_all(b"STARTTLS\r\n").await.unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "454 4.7.0 TLS not available due to local problem\r\n"
    );
    // The session is still usable.
    client.write_all(b"NOOP\r\n").await.unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();
}

/// The implicit-TLS submission listener (465) handshakes before the
/// banner, offers AUTH on the first EHLO, and never offers STARTTLS.
#[tokio::test]
async fn implicit_tls_submission() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let acceptor = Arc::new(
        tls_acceptor_from_pem(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap(),
    );
    let auth =
        auth::AuthConfig::from_credentials(&auth::test_credentials(&[("alice", "secret")]), None)
            .unwrap();
    let addr = spawn_server_in(
        ListenerMode::Submissions,
        Some(acceptor),
        Some(Arc::new(auth)),
        None,
        None,
        None,
        None,
    )
    .await;

    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls = TestTlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TestTcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    let mut client = BufReader::new(tls);
    assert!(read_reply(&mut client).await[0].starts_with("220 "));
    client.write_all(b"EHLO client.test\r\n").await.unwrap();
    let caps = read_reply(&mut client).await;
    assert!(
        caps.iter().any(|l| l == "250-AUTH PLAIN LOGIN\r\n"),
        "{caps:?}"
    );
    assert!(!caps.iter().any(|l| l.contains("STARTTLS")), "{caps:?}");

    use base64::Engine as _;
    let plain = base64::engine::general_purpose::STANDARD.encode("\0alice\0secret");
    client
        .write_all(format!("AUTH PLAIN {plain}\r\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "235 2.7.0 Authentication successful\r\n"
    );
}

/// AUTH on the STARTTLS submission listener: advertisement gating,
/// AUTH required before MAIL, both mechanisms, bad
/// credentials, SPF exemption for authenticated senders, and relay
/// denial for non-local recipients.
#[tokio::test]
async fn auth_and_relay_policy() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let acceptor = Arc::new(
        tls_acceptor_from_pem(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap(),
    );
    let auth = auth::AuthConfig::from_credentials(
        &auth::test_credentials(&[("alice", "secret")]),
        Some("alice=alice@spfless-domain-xyz.test"),
    )
    .unwrap();
    let addr = spawn_server_in(
        ListenerMode::Submission,
        Some(acceptor),
        Some(Arc::new(auth)),
        None,
        None,
        None,
        None,
    )
    .await;

    // --- Plaintext: AUTH is neither advertised nor accepted.
    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;
    client.write_all(b"EHLO client.test\r\n").await.unwrap();
    let caps = read_reply(&mut client).await;
    assert!(
        !caps.iter().any(|l| l.contains("AUTH")),
        "no AUTH on plaintext: {caps:?}"
    );

    client.write_all(b"AUTH PLAIN\r\n").await.unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "538 5.7.11 Encryption required for requested authentication mechanism\r\n"
    );

    // --- Upgrade to TLS.
    client.write_all(b"STARTTLS\r\n").await.unwrap();
    read_reply(&mut client).await;
    let tcp = client.into_inner();
    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TestTlsConnector::from(Arc::new(config));
    let tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let mut client = BufReader::new(tls);

    client.write_all(b"EHLO client.test\r\n").await.unwrap();
    let caps = read_reply(&mut client).await;
    assert!(
        caps.iter().any(|l| l == "250-AUTH PLAIN LOGIN\r\n"),
        "caps: {caps:?}"
    );

    // Submission needs AUTH before a transaction.
    client
        .write_all(b"MAIL FROM:<alice@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "530 5.7.0 Authentication required\r\n"
    );

    // Bad credentials (LOGIN dance).
    use base64::Engine as _;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);

    client.write_all(b"AUTH LOGIN\r\n").await.unwrap();
    assert_eq!(read_reply(&mut client).await[0], "334 VXNlcm5hbWU6\r\n");
    client
        .write_all(format!("{}\r\n", b64("alice")).as_bytes())
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "334 UGFzc3dvcmQ6\r\n");
    client
        .write_all(format!("{}\r\n", b64("wrong")).as_bytes())
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "535 5.7.8 Authentication credentials invalid\r\n"
    );

    // Good credentials (PLAIN with initial response).
    let plain = b64("\0alice\0secret");
    client
        .write_all(format!("AUTH PLAIN {plain}\r\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "235 2.7.0 Authentication successful\r\n"
    );
    // Already authenticated.
    client.write_all(b"AUTH PLAIN x\r\n").await.unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "503 5.5.1 Already authenticated\r\n"
    );

    // From validation: an authenticated user may only use the
    // addresses granted to their login. A spoofed envelope sender and
    // the null sender are refused, and nothing is recorded.
    for spoof in [
        &b"MAIL FROM:<ceo@victim.example>\r\n"[..],
        b"MAIL FROM:<bob@spfless-domain-xyz.test>\r\n",
        b"MAIL FROM:<>\r\n",
    ] {
        client.write_all(spoof).await.unwrap();
        assert_eq!(
            read_reply(&mut client).await[0],
            "553 5.7.1 Sender address not owned by authenticated user\r\n"
        );
    }

    // A granted envelope sender with a spoofed From header: refused at
    // end-of-data, and the next transaction starts clean.
    client
        .write_all(b"MAIL FROM:<alice@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client
        .write_all(b"RCPT TO:<user@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"DATA\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"From: CEO <ceo@victim.example>\r\n\r\nwire the money\r\n.\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "550 5.7.1 From address not owned by authenticated user\r\n"
    );

    // Authenticated sender: SPF is skipped (the MUA's home IP is not
    // authorized by the sender domain's SPF record).
    client
        .write_all(b"MAIL FROM:<Alice@SPFLESS-domain-xyz.test>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");

    // Relay is closed even for authenticated users: non-local
    // recipients are refused.
    client
        .write_all(b"RCPT TO:<victim@foreign.example>\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "550 5.7.1 Relay access denied\r\n"
    );
    client
        .write_all(b"RCPT TO:<user@Example.ORG>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");

    client.write_all(b"DATA\r\n").await.unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "354 End data with <CR>.<CR><LF>\r\n"
    );
    client
        .write_all(b"From: alice@spfless-domain-xyz.test\r\n\r\nbody\r\n.\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();
    assert_eq!(read_reply(&mut client).await[0], "221 Bye\r\n");
}

/// Recipient policy without authentication: local domains accepted,
/// relay denied, malformed paths refused.
#[tokio::test]
async fn recipient_policy_unauthenticated() {
    let addr = spawn_server(
        None,
        None,
        Some(vec!["example.org".to_string(), "example.net".to_string()]),
        None,
        None,
        None,
    )
    .await;
    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;

    client.write_all(b"HELO client.test\r\n").await.unwrap();
    read_reply(&mut client).await;

    // RCPT before MAIL is a sequence error (RFC 5321 Section 3.3).
    client
        .write_all(b"RCPT TO:<user@example.net>\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "503 5.5.1 Error: need MAIL command\r\n"
    );

    client
        .write_all(b"MAIL FROM:<a@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    read_reply(&mut client).await;

    client
        .write_all(b"RCPT TO:<user@foreign.example>\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "550 5.7.1 Relay access denied\r\n"
    );
    client
        .write_all(b"RCPT TO:<user@EXAMPLE.net>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"RCPT TO:<no-at-sign>\r\n").await.unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "553 5.1.3 Bad recipient address syntax\r\n"
    );
    client.write_all(b"QUIT\r\n").await.unwrap();
}

/// The recipient cap (RFC 5321 Section 4.5.3.1.8: at least 100).
#[tokio::test]
async fn recipient_cap() {
    let addr = spawn_server(None, None, None, None, None, None).await;
    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;

    client.write_all(b"HELO client.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"MAIL FROM:<a@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    read_reply(&mut client).await;

    for i in 0..100 {
        client
            .write_all(format!("RCPT TO:<u{i}@example.org>\r\n").as_bytes())
            .await
            .unwrap();
        assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    }
    client
        .write_all(b"RCPT TO:<u100@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "452 4.5.3 Too many recipients\r\n"
    );
    client.write_all(b"QUIT\r\n").await.unwrap();
}

/// A spool backend whose writes take `delay` (a slow disk).
struct SlowSpool(spool::DiskSpool, Duration);

impl spool::SpoolWriter for SlowSpool {
    fn name(&self) -> &str {
        "slow"
    }
    fn write(&self, meta: spool::SpoolMeta, payload: Vec<u8>) -> Result<spool::StoredMessage> {
        std::thread::sleep(self.1);
        self.0.write(meta, payload)
    }
    fn remove(&self, queue_id: &str) -> Result<()> {
        self.0.remove(queue_id)
    }
}

/// The duplicate-delivery case: the connection deadline passes while
/// a message is being stored. The store completes, the client still
/// gets its 250 (so it won't send the message again), and only then
/// is the connection closed with a 421.
#[tokio::test]
async fn deadline_during_spool_write_still_replies() {
    let dir = tempfile::tempdir().unwrap();
    let disk = spool::DiskSpool::open(dir.path(), None).unwrap();
    let mut cfg = SessionConfig {
        spool: Some(Arc::new(SlowSpool(disk, Duration::from_millis(800)))),
        ..tests::size_limit_session(dir.path())
    };
    cfg.dns = spawn_nxdomain_resolver().await;
    cfg.authority = Arc::new(authority::StaticAuthority::new(vec!["example.org".into()]));
    cfg.deadline = Some(Instant::now() + Duration::from_millis(600));
    let addr = spawn_server_with(ListenerMode::Mx, None, cfg).await;

    let mut client = BufReader::new(TestTcpStream::connect(addr).await.unwrap());
    read_reply(&mut client).await;
    for cmd in [
        &b"HELO client.test\r\n"[..],
        b"MAIL FROM:<sender@spfless-domain-xyz.test>\r\n",
        b"RCPT TO:<user@example.org>\r\n",
    ] {
        client.write_all(cmd).await.unwrap();
        assert!(read_reply(&mut client).await[0].starts_with("250"));
    }
    client.write_all(b"DATA\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"From: sender@spfless-domain-xyz.test\r\n\r\nbody\r\n.\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    assert_eq!(
        read_reply(&mut client).await[0],
        "421 4.4.2 Connection time limit reached, closing\r\n"
    );
    assert_eq!(wait_for_files(&dir.path().join("new"), 2).await.len(), 2);
}

/// Accepted messages are durably spooled: payload byte-exact, metadata
/// complete, and the 250 only after the write.
#[tokio::test]
async fn accepted_message_is_spooled() {
    let dir = tempfile::tempdir().unwrap();
    let spool: Arc<dyn spool::SpoolWriter> =
        Arc::new(spool::DiskSpool::open(dir.path(), None).unwrap());
    let addr = spawn_server(None, None, None, Some(spool), None, None).await;

    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;

    client.write_all(b"HELO client.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"MAIL FROM:<sender@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client
        .write_all(b"RCPT TO:<user@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"DATA\r\n").await.unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "354 End data with <CR>.<CR><LF>\r\n"
    );
    client
        .write_all(b"Subject: spool test\r\nFrom: sender@spfless-domain-xyz.test\r\n\r\nbody line\r\n.\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();

    // Exactly one message in new/: payload + metadata, nothing in tmp/.
    let new = dir.path().join("new");
    let mut names: Vec<String> = Vec::new();
    let mut rd = tokio::fs::read_dir(&new).await.unwrap();
    while let Some(e) = rd.next_entry().await.unwrap() {
        names.push(e.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    assert_eq!(names.len(), 2, "spool contents: {names:?}");
    assert!(names[0].ends_with(".eml"));
    assert!(names[1].ends_with(".json"));
    let id = names[0].trim_end_matches(".eml");
    assert_eq!(names[1], format!("{id}.json"));

    // The payload is the final message: the trace headers (naming the
    // queue ID, and no recipient), then exactly the unstuffed DATA
    // bytes.
    let payload = tokio::fs::read(new.join(&names[0])).await.unwrap();
    let data = b"Subject: spool test\r\nFrom: sender@spfless-domain-xyz.test\r\n\r\nbody line\r\n";
    let text = String::from_utf8(payload.clone()).unwrap();
    assert!(
        text.starts_with(
            "Return-Path: <sender@spfless-domain-xyz.test>\r\nReceived: from client.test"
        ),
        "{text}"
    );
    assert!(text.contains(&format!(" with ESMTP id {id};")), "{text}");
    assert!(
        !text.contains("user@example.org"),
        "no recipient named: {text}"
    );
    assert!(payload.ends_with(data));

    // Metadata is complete and consistent.
    let meta: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(new.join(&names[1])).await.unwrap()).unwrap();
    assert_eq!(meta["queue_id"], id);
    assert_eq!(meta["helo"], "client.test");
    assert_eq!(meta["mail_from"], "sender@spfless-domain-xyz.test");
    assert_eq!(meta["rcpt_to"][0]["address"], "user@example.org");
    assert_eq!(meta["rcpt_to"][0]["mailbox"], "user@example.org");
    assert_eq!(
        meta["message_size"],
        data.len(),
        "the client's bytes, not the trace headers"
    );
    assert!(meta["received_at"].is_string());
    assert!(meta["peer"].is_string());
}

/// The authority owns recipient policy: known addresses accept and
/// route to their mailbox, unknown addresses on reject-mode domains
/// are refused with one uniform reply, unhosted domains get the
/// relay-denied reply, and accepted mail spools with the resolved
/// routing identity.
#[tokio::test]
async fn authority_governs_recipients() {
    let dir = tempfile::tempdir().unwrap();
    let authority_path = dir.path().join("authority.json");
    std::fs::write(
        &authority_path,
        r#"{
            "version": 1,
            "domains": { "example.org": { "mode": "reject" } },
            "mailboxes": {
                "alice@example.org": { "user": "alice", "public-key": "pk-alice", "key-generation": 3 }
            }
        }"#,
    )
    .unwrap();
    let spool: Arc<dyn spool::SpoolWriter> =
        Arc::new(spool::DiskSpool::open(dir.path().join("spool"), None).unwrap());
    let authority = Arc::new(authority::FileAuthority::open(&authority_path).unwrap());
    let addr = spawn_server(None, None, None, Some(spool), None, Some(authority)).await;

    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;
    client.write_all(b"HELO client.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"MAIL FROM:<sender@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");

    // Known mailbox: accepted, and resolution cached on the session.
    client
        .write_all(b"RCPT TO:<alice@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    // Case-variant of the cached address: served from the cache.
    client
        .write_all(b"RCPT TO:<ALICE@Example.ORG>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");

    // Unknown mailbox on a reject-mode domain: refused. The reply is
    // identical for every refusal reason (no address enumeration).
    client
        .write_all(b"RCPT TO:<nobody@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "550 5.1.1 No such mailbox\r\n"
    );

    // Unhosted domain: relay-denied (distinct policy reply).
    client
        .write_all(b"RCPT TO:<x@foreign.example>\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "550 5.7.1 Relay access denied\r\n"
    );

    // Deliver to the accepted recipient: the spool record carries the
    // resolved routing identity (user + key) from RCPT time.
    client.write_all(b"DATA\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"Subject: to alice\r\nFrom: sender@spfless-domain-xyz.test\r\n\r\nhi\r\n.\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();

    // Two recipients were accepted (the cache hit included).
    let json = std::fs::read_dir(dir.path().join("spool/new"))
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.path().extension().is_some_and(|x| x == "json"))
        .unwrap();
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(json.path()).unwrap()).unwrap();
    assert_eq!(meta["rcpt_to"].as_array().unwrap().len(), 2);
    assert_eq!(meta["rcpt_to"][0]["mailbox"], "alice@example.org");
    assert_eq!(meta["rcpt_to"][0]["user"], "alice");
    assert_eq!(meta["rcpt_to"][0]["public_key"], "pk-alice");
    assert_eq!(meta["rcpt_to"][0]["key_generation"], 3);
}

/// An authority that cannot be consulted fails closed: the RCPT is
/// refused with a temporary error, inviting the client to retry —
/// never accepted-and-later-failed.
#[tokio::test]
async fn authority_outage_fails_closed() {
    struct DownAuthority;

    impl authority::RecipientResolver for DownAuthority {
        fn name(&self) -> &str {
            "down"
        }

        fn resolve(
            &self,
            _address: &str,
        ) -> Result<authority::Resolution, authority::AuthorityUnavailable> {
            Err(authority::AuthorityUnavailable(
                "console unreachable".into(),
            ))
        }
    }

    let addr = spawn_server(None, None, None, None, None, Some(Arc::new(DownAuthority))).await;

    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;
    client.write_all(b"HELO client.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"MAIL FROM:<sender@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"RCPT TO:<anyone@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "451 4.3.0 Recipient resolution unavailable, try again later\r\n"
    );
    client.write_all(b"QUIT\r\n").await.unwrap();
}

/// Catch-all domains route unknown addresses to the designated
/// inbox: the delivered copy lands under the *mailbox*, while the
/// trace headers still name the envelope address.
#[tokio::test]
async fn catch_all_routes_to_designated_inbox() {
    let dir = tempfile::tempdir().unwrap();
    let authority_path = dir.path().join("authority.json");
    std::fs::write(
        &authority_path,
        r#"{
            "version": 1,
            "domains": { "example.org": { "mode": "catch-all", "catch-all-mailbox": "admin@example.org" } },
            "mailboxes": {
                "admin@example.org": { "user": "admin" }
            }
        }"#,
    )
    .unwrap();
    let spool: Arc<dyn spool::SpoolWriter> =
        Arc::new(spool::DiskSpool::open(dir.path().join("spool"), None).unwrap());
    let sink: Arc<dyn delivery::DeliverySink> =
        Arc::new(delivery::MaildirSink::open(dir.path().join("maildir")).unwrap());
    let authority = Arc::new(authority::FileAuthority::open(&authority_path).unwrap());
    let addr = spawn_server(None, None, None, Some(spool), Some(sink), Some(authority)).await;

    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;
    client.write_all(b"HELO client.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"MAIL FROM:<sender@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    read_reply(&mut client).await;

    // An unknown local-part is accepted (catch-all)...
    client
        .write_all(b"RCPT TO:<whatever-alias@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"DATA\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"Subject: caught\r\nFrom: sender@spfless-domain-xyz.test\r\n\r\nhi\r\n.\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();

    // ...and the mail lands in the admin's maildir (the fast path runs
    // after the reply, so wait for it), the copy's file name recording
    // the envelope address it was for (the message itself names no
    // recipient).
    let inbox = dir.path().join("maildir/example.org/admin/new");
    let names = wait_for_files(&inbox, 1).await;
    assert_eq!(names.len(), 1, "admin inbox: {names:?}");
    assert!(
        names[0].ends_with(".whatever-alias_example.org.eml"),
        "{names:?}"
    );
    let copy = std::fs::read(inbox.join(&names[0])).unwrap();
    let text = String::from_utf8(copy).unwrap();
    assert!(!text.contains("whatever-alias"), "{text}");
}

/// Local-parts with path semantics must be refused at RCPT time, so
/// they can never reach a maildir path (relative traversal via `..`,
/// absolute paths via `Path::join`).
#[tokio::test]
async fn path_traversal_local_parts_are_refused() {
    let addr = spawn_server(None, None, None, None, None, None).await;
    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;
    client.write_all(b"HELO client.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"MAIL FROM:<a@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    read_reply(&mut client).await;

    for rcpt in [
        "../../escape@example.org",
        "/tmp/absolute-path@example.org",
        "a..b@example.org",
        ".hidden@example.org",
        "a/b@example.org",
    ] {
        client
            .write_all(format!("RCPT TO:<{rcpt}>\r\n").as_bytes())
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut client).await[0],
            "553 5.1.3 Bad recipient address syntax\r\n",
            "rcpt {rcpt:?} must be refused"
        );
    }

    // A normal local-part is unaffected.
    client
        .write_all(b"RCPT TO:<normal.user+tag@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();
}

/// A message with no `From:` header is rejected (RFC 7489 Section
/// 6.6.1), never accepted without a DMARC check.
#[tokio::test]
async fn message_without_from_is_rejected() {
    let addr = spawn_server(None, None, None, None, None, None).await;
    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;
    client.write_all(b"HELO client.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"MAIL FROM:<a@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"RCPT TO:<user@example.org>\r\n")
        .await
        .unwrap();
    read_reply(&mut client).await;
    client.write_all(b"DATA\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"Subject: no from\r\n\r\nbody\r\n.\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "550 5.7.1 Message rejected: missing or malformed From header\r\n"
    );
    client.write_all(b"QUIT\r\n").await.unwrap();
}

/// An IPv4 client on a dual-stack listener is seen
/// as plain IPv4; real IPv6 peers are untouched.
#[test]
fn mapped_peers_are_canonical() {
    let mapped: SocketAddr = "[::ffff:192.0.2.7]:2525".parse().unwrap();
    assert_eq!(canonical_peer(mapped), "192.0.2.7:2525".parse().unwrap());
    let v6: SocketAddr = "[2001:db8::7]:25".parse().unwrap();
    assert_eq!(canonical_peer(v6), v6);
    let v4: SocketAddr = "192.0.2.7:25".parse().unwrap();
    assert_eq!(canonical_peer(v4), v4);
}

/// Grace mode: an address expired within the grace window still
/// accepts; one expired beyond it is refused with the uniform reply.
#[tokio::test]
async fn grace_accepts_recently_expired_only() {
    let dir = tempfile::tempdir().unwrap();
    let now = jiff::Timestamp::now().as_second();
    let authority_path = dir.path().join("authority.json");
    std::fs::write(
        &authority_path,
        format!(
            r#"{{
                "version": 1,
                "domains": {{ "example.org": {{ "mode": "grace", "grace-days": 7 }} }},
                "mailboxes": {{
                    "recent@example.org": {{ "user": "u", "expires": "{}" }},
                    "stale@example.org": {{ "user": "u", "expires": "{}" }}
                }}
            }}"#,
            jiff::Timestamp::from_second(now - 86_400).unwrap(),
            jiff::Timestamp::from_second(now - 30 * 86_400).unwrap(),
        ),
    )
    .unwrap();
    let authority = Arc::new(authority::FileAuthority::open(&authority_path).unwrap());
    let addr = spawn_server(None, None, None, None, None, Some(authority)).await;

    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;
    client.write_all(b"HELO client.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"MAIL FROM:<sender@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    read_reply(&mut client).await;

    client
        .write_all(b"RCPT TO:<recent@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");

    client
        .write_all(b"RCPT TO:<stale@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "550 5.1.1 No such mailbox\r\n"
    );
    client.write_all(b"QUIT\r\n").await.unwrap();
}

/// AUDIT_20261126B F1 (High). A refused connection is answered by
/// [`refuse`], whose courtesy drain does `read_to_end` — it buffers
/// every byte the peer sends until its 500 ms window ends. That path
/// runs exactly when the server is at capacity, from a pool of 32
/// concurrent tasks: one probe measured a single refused connection
/// pushing ~1 GB of loopback flood into the process's heap before the
/// timeout fires, and 32 of them can run at once. An attacker with a
/// modest bandwidth budget therefore turns a *refusal* (the cheapest
/// possible server action) into an unbounded memory allocation — an
/// OOM kill of the whole MX under load, losing every in-progress
/// session and (under systemd `Restart=always`) cycling the service.
/// The drain exists only so the client can read the 421 before close;
/// it must discard what it reads, never accumulate it. Property pinned
/// here: answering one flooded refused connection grows the process's
/// resident memory by at most a few MiB.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn refused_connections_do_not_buffer_the_peer_flood() {
    use tokio::io::AsyncWriteExt as _;

    /// This process's resident set, in bytes (/proc/self/statm field 2,
    /// which counts pages).
    fn resident_bytes() -> u64 {
        // SAFETY: sysconf has no preconditions; _SC_PAGESIZE is always valid.
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
        statm
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u64>()
            .unwrap()
            * page
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let refused = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();
        refuse(
            stream,
            b"421 4.7.0 Service not available, try again later\r\n",
        )
        .await;
    });

    let mut client = TestTcpStream::connect(addr).await.unwrap();

    // Sample RSS while the refusal runs; peak minus the starting value
    // is what the drain retained.
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let sampler = std::thread::spawn(move || {
        let base = resident_bytes();
        let mut peak = base;
        while stop_rx.try_recv().is_err() {
            peak = peak.max(resident_bytes());
            std::thread::sleep(Duration::from_millis(2));
        }
        peak - base
    });

    // Flood for longer than the 500 ms the refusal spends reading.
    let chunk = vec![b'x'; 1 << 20];
    let mut sent = 0u64;
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(900) {
        if client.write_all(&chunk).await.is_err() {
            break; // the refusal closed early: the drain was bounded
        }
        sent += chunk.len() as u64;
    }
    // Hold the connection open past the drain window, then leave.
    tokio::time::sleep(Duration::from_millis(400)).await;
    drop(client);
    let _ = refused.await;
    let _ = stop_tx.send(());
    let growth = sampler.join().unwrap();

    // With the flood unbounded (today), even a fraction of a second on
    // loopback is hundreds of MB. The bound must be small no matter how
    // much the peer managed to push.
    assert!(
        growth < 16 << 20,
        "answering one refused connection grew this process by {} MB while \
         the peer pushed {} MB: the refusal must discard the flood, not \
         buffer it",
        growth >> 20,
        sent >> 20,
    );
}

/// AUDIT_20261126C G1 (fixed), shown end-to-end through the real
/// submission listener (STARTTLS, AUTH, DATA, spool, maildir) rather than
/// at the session boundary: a login granted only
/// `alice@spfless-domain-xyz.test` submits a message whose `Sender:` and
/// `Resent-From:` name someone else. Before the fix it was delivered
/// *under this server's* `auth=pass smtp.auth=alice` verdict with those
/// identities intact; now the grant check covers the `Sender:`-family
/// headers, so DATA is refused with `550 5.7.1` and nothing is spooled or
/// delivered (the session-level twin is
/// `session::tests::authenticated_sender_headers_must_be_granted`).
#[tokio::test]
async fn ungranted_sender_headers_are_refused_under_auth() {
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let acceptor = Arc::new(
        tls_acceptor_from_pem(
            cert.cert.pem().as_bytes(),
            cert.key_pair.serialize_pem().as_bytes(),
        )
        .unwrap(),
    );
    let auth = auth::AuthConfig::from_credentials(
        &auth::test_credentials(&[("alice", "secret")]),
        Some("alice=alice@spfless-domain-xyz.test"),
    )
    .unwrap();
    let spool: Arc<dyn spool::SpoolWriter> =
        Arc::new(spool::DiskSpool::open(dir.path().join("spool"), None).unwrap());
    let sink: Arc<dyn delivery::DeliverySink> =
        Arc::new(delivery::MaildirSink::open(dir.path().join("maildir")).unwrap());
    let addr = spawn_server_in(
        ListenerMode::Submission,
        Some(acceptor),
        Some(Arc::new(auth)),
        None,
        Some(spool),
        Some(sink),
        None,
    )
    .await;

    use base64::Engine as _;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);

    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;
    client.write_all(b"EHLO client.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client.write_all(b"STARTTLS\r\n").await.unwrap();
    read_reply(&mut client).await;
    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls = TestTlsConnector::from(Arc::new(config))
        .connect(
            ServerName::try_from("localhost").unwrap(),
            client.into_inner(),
        )
        .await
        .unwrap();
    let mut client = BufReader::new(tls);

    // TLS discards the pre-upgrade state, so the identity is re-declared.
    client.write_all(b"EHLO client.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(format!("AUTH PLAIN {}\r\n", b64("\0alice\0secret")).as_bytes())
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "235 2.7.0 Authentication successful\r\n"
    );

    // The granted envelope sender, an ungranted identity in the headers
    // that name a sender, and a local recipient so the message delivers.
    client
        .write_all(b"MAIL FROM:<alice@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client
        .write_all(b"RCPT TO:<bob@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"DATA\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(
            b"From: alice@spfless-domain-xyz.test\r\n\
              Sender: ceo@victim.example\r\n\
              Resent-From: finance@victim.example\r\n\
              Subject: wire the money\r\n\r\n\
              hello\r\n.\r\n",
        )
        .await
        .unwrap();
    assert_eq!(
        read_reply(&mut client).await[0],
        "550 5.7.1 From address not owned by authenticated user\r\n"
    );
    client.write_all(b"QUIT\r\n").await.unwrap();
    read_reply(&mut client).await;

    // Refused before the spool write: nothing queued, nothing delivered.
    let queued = std::fs::read_dir(dir.path().join("spool/new"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(queued, 0, "refused message must not be spooled");
    let inbox = dir.path().join("maildir/example.org/bob/new");
    let delivered = std::fs::read_dir(&inbox).map(|d| d.count()).unwrap_or(0);
    assert_eq!(delivered, 0, "refused message must not be delivered");
}

/// AUDIT_20261126D A1 (Low): a delivered message keeps the sender's
/// `Return-Path:` alongside the one this server adds, because
/// `strip_forged_verdicts` removes only the verdict headers it names
/// (`Authentication-Results:` for our authserv-id and
/// `X-Display-Name-Warning:`). RFC 5322 §3.6.3 makes the final delivery
/// agent responsible for removing any existing `Return-Path:` before
/// adding its own, so the copy we hand the user — and the copy the drain
/// sends to another MX — carries two, the lower one naming whatever
/// address the sender chose. This pins the current behaviour: it fails
/// once the trace-header step drops the inbound `Return-Path:` (then the
/// assertion must become a count of 1, naming the envelope sender).
#[tokio::test]
async fn a_sender_return_path_survives_alongside_ours() {
    let dir = tempfile::tempdir().unwrap();
    let spool: Arc<dyn spool::SpoolWriter> =
        Arc::new(spool::DiskSpool::open(dir.path().join("spool"), None).unwrap());
    let sink: Arc<dyn delivery::DeliverySink> =
        Arc::new(delivery::MaildirSink::open(dir.path().join("maildir")).unwrap());
    let addr = spawn_server(None, None, None, Some(spool), Some(sink), None).await;

    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;
    client.write_all(b"EHLO evil.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"MAIL FROM:<actual@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client
        .write_all(b"RCPT TO:<bob@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"DATA\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(
            b"From: boss@spfless-domain-xyz.test\r\n\
              Return-Path: <claimed@bigbank.example>\r\n\
              Subject: hi\r\n\r\nbody\r\n.\r\n",
        )
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();

    let inbox = dir.path().join("maildir/example.org/bob/new");
    let names = wait_for_files(&inbox, 1).await;
    assert_eq!(names.len(), 1, "bob's inbox: {names:?}");
    let text = String::from_utf8(std::fs::read(inbox.join(&names[0])).unwrap()).unwrap();
    // Ours is first (the one an RFC 5322 reader takes), and the claimed
    // one is still in the block below it.
    assert_eq!(
        text.matches("Return-Path:").count(),
        2,
        "both Return-Path fields are delivered: {text}"
    );
    assert!(text.starts_with("Return-Path: <actual@spfless-domain-xyz.test>"));
    assert!(text.contains("Return-Path: <claimed@bigbank.example>"));
}

/// The AR strip is exact on the authserv-id: a `Return-Path`-style
/// near-miss (`"mail.example.org"` quoted, or a different id) is left in
/// place, since this server can only speak for its own id. Also pinned
/// here so a future widening of the strip is a deliberate change.
#[tokio::test]
async fn foreign_and_quoted_authserv_ids_are_not_stripped() {
    let dir = tempfile::tempdir().unwrap();
    let spool: Arc<dyn spool::SpoolWriter> =
        Arc::new(spool::DiskSpool::open(dir.path().join("spool"), None).unwrap());
    let sink: Arc<dyn delivery::DeliverySink> =
        Arc::new(delivery::MaildirSink::open(dir.path().join("maildir")).unwrap());
    let addr = spawn_server(None, None, None, Some(spool), Some(sink), None).await;

    let tcp = TestTcpStream::connect(addr).await.unwrap();
    let mut client = BufReader::new(tcp);
    read_reply(&mut client).await;
    client.write_all(b"EHLO evil.test\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(b"MAIL FROM:<a@spfless-domain-xyz.test>\r\n")
        .await
        .unwrap();
    client
        .write_all(b"RCPT TO:<bob@example.org>\r\n")
        .await
        .unwrap();
    client.write_all(b"DATA\r\n").await.unwrap();
    read_reply(&mut client).await;
    client
        .write_all(
            b"From: boss@spfless-domain-xyz.test\r\n\
              Authentication-Results: other.example; auth=pass smtp.auth=root\r\n\
              Authentication-Results: \"mail.example.org\"; auth=pass smtp.auth=root\r\n\
              Authentication-Results: mail.example.org; dmarc=pass\r\n\
              Subject: hi\r\n\r\nbody\r\n.\r\n",
        )
        .await
        .unwrap();
    assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
    client.write_all(b"QUIT\r\n").await.unwrap();

    let inbox = dir.path().join("maildir/example.org/bob/new");
    let names = wait_for_files(&inbox, 1).await;
    let text = String::from_utf8(std::fs::read(inbox.join(&names[0])).unwrap()).unwrap();
    // Ours is added; the exact-claiming forgery is removed; the two
    // near-misses survive verbatim.
    assert_eq!(
        text.matches("Authentication-Results:").count(),
        3,
        "our header plus the two untouchable forgeries: {text}"
    );
    assert!(text.contains("Authentication-Results: other.example; auth=pass"));
    assert!(text.contains("Authentication-Results: \"mail.example.org\"; auth=pass"));
    assert!(!text.contains("Authentication-Results: mail.example.org; dmarc=pass"));
}
