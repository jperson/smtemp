//! Test helpers shared by the session and server tests: mock
//! DNS-over-TLS resolvers, a size-limited session configuration, and
//! reading SMTP replies.

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio_rustls::TlsAcceptor;

use crate::session::{SessionConfig, END_OF_DATA_DNS_DEADLINE};
use crate::{authority, limit};

/// A shutdown receiver that never signals: its sender is already
/// gone, so `shutdown_signal` stays pending (tests that aren't about
/// shutdown).
pub(crate) fn no_shutdown() -> tokio::sync::watch::Receiver<bool> {
    tokio::sync::watch::channel(false).1
}

/// Read one (possibly multiline) SMTP reply: lines until the
/// `NNN ` final line (a dash after the code continues it).
pub(crate) async fn read_reply<R>(reader: &mut BufReader<R>) -> Vec<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let done = line.len() < 4 || line.as_bytes()[3] == b' ';
        lines.push(line);
        if done {
            return lines;
        }
    }
}

/// How a [`spawn_mock_resolver`] answers one query.
pub(crate) enum MockAnswer {
    /// A reply with this rcode and no records (0: an empty NOERROR,
    /// 3: NXDOMAIN, 2: SERVFAIL).
    Rcode(u8),
    /// A NOERROR reply with this one TXT record.
    Txt(&'static str),
    /// No reply at all (an upstream that never responds).
    Silent,
}

/// Start a local DNS-over-TLS resolver that answers each query with
/// `answer(name, qtype)`, so tests never depend on the network.
///
/// Returns a client wired to it (trusting its self-signed certificate)
/// with the per-query timeout `timeout`.
pub(crate) async fn spawn_mock_resolver(
    answer: impl Fn(&str, u16) -> MockAnswer + Send + Sync + 'static,
    timeout: Duration,
) -> Arc<dns::DnsClient> {
    use dns::proto::{DnsMessage, DnsResourceRecord, QType};
    use tokio::io::AsyncReadExt as _;
    use tokio_rustls::rustls::pki_types::PrivateKeyDer;

    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let answer = Arc::new(answer);
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let (acceptor, answer) = (acceptor.clone(), Arc::clone(&answer));
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                while let Ok(len) = tls.read_u16().await {
                    let mut buf = vec![0; usize::from(len)];
                    if tls.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let Ok((_, query)) = DnsMessage::from_bytes(&buf) else {
                        return;
                    };
                    let Some(q) = query.questions.first() else {
                        return;
                    };
                    let mut resp =
                        DnsMessage::new(query.header.transaction_id, query.questions.clone());
                    resp.header.qr = 1;
                    match answer(&String::from(&q.name), q.record_type) {
                        MockAnswer::Silent => continue,
                        MockAnswer::Rcode(rcode) => resp.header.rcode = rcode,
                        MockAnswer::Txt(text) => resp.answers.push(DnsResourceRecord {
                            name: q.name.clone(),
                            record_type: 16,
                            record_class: 1,
                            ttl: 60,
                            rdlength: 0,
                            rdata: QType::TXT(text.to_string()),
                        }),
                    }
                    let bytes = resp.to_vec().unwrap();
                    if tls.write_u16(bytes.len() as u16).await.is_err()
                        || tls.write_all(&bytes).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });

    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_config = Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    Arc::new(dns::DnsClient::with_config(
        "127.0.0.1".parse().unwrap(),
        client_config,
        timeout,
        Some(format!("127.0.0.1:{port}")),
    ))
}

/// A mock resolver for which every name is NXDOMAIN, as the `.test`
/// and `.example` domains the tests use are on the real DNS: SPF is
/// None, there are no DKIM keys and no DMARC policy.
pub(crate) async fn spawn_nxdomain_resolver() -> Arc<dns::DnsClient> {
    spawn_mock_resolver(|_, _| MockAnswer::Rcode(3), Duration::from_secs(5)).await
}

/// A mock resolver for hermetic DMARC tests: every `_dmarc.*` TXT
/// query is answered `v=DMARC1; p=reject`, everything else with an
/// empty NOERROR answer.
pub(crate) async fn spawn_mock_dmarc_resolver() -> Arc<dns::DnsClient> {
    spawn_mock_dmarc_resolver_with(0).await
}

/// Like [`spawn_mock_dmarc_resolver`], but `_dmarc.*` TXT queries get
/// `dmarc_rcode` (e.g. 2, SERVFAIL) with no answer when it is non-zero.
pub(crate) async fn spawn_mock_dmarc_resolver_with(dmarc_rcode: u8) -> Arc<dns::DnsClient> {
    spawn_mock_resolver(
        move |name, qtype| match (name.starts_with("_dmarc.") && qtype == 16, dmarc_rcode) {
            (true, 0) => MockAnswer::Txt("v=DMARC1; p=reject"),
            (true, rcode) => MockAnswer::Rcode(rcode),
            (false, _) => MockAnswer::Rcode(0),
        },
        Duration::from_secs(5),
    )
    .await
}

/// A mock resolver that reads queries but never answers (an
/// authoritative server that never responds, as seen through the
/// resolver). The client's own per-query timeout is 30 s, so only the
/// end-of-data deadline can end a check against it.
pub(crate) async fn spawn_silent_resolver() -> Arc<dns::DnsClient> {
    spawn_mock_resolver(|_, _| MockAnswer::Silent, Duration::from_secs(30)).await
}

/// A session over a file authority with one size-limited domain
/// (`small.example`, 2 KiB) and one without a limit (`big.example`),
/// under a 1 MiB server limit. No DNS is used: SPF is skipped because
/// the tests set the envelope sender directly.
pub(crate) fn size_limit_session(dir: &std::path::Path) -> SessionConfig {
    let path = dir.join("authority.json");
    std::fs::write(
        &path,
        r#"{
            "version": 1,
            "domains": {
                "small.example": { "mode": "reject", "max-message-bytes": 2048 },
                "big.example": { "mode": "reject" }
            },
            "mailboxes": {
                "a@small.example": { "user": "a", "expires": null },
                "b@small.example": { "user": "b", "expires": null },
                "c@big.example": { "user": "c", "expires": null }
            }
        }"#,
    )
    .unwrap();
    SessionConfig {
        domain: "mail.test".to_string(),
        max_data: 1024 * 1024,
        auth: None,
        authority: Arc::new(authority::FileAuthority::open(&path).unwrap()),
        dns: Arc::new(dns::DnsClient::with_timeout(
            "127.0.0.1".parse().unwrap(),
            Duration::from_millis(200),
        )),
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
    }
}
