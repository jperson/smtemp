use anyhow::Result;
use clap::Parser;
use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddr};
use std::str;
use std::time::Duration;
use tokio::io::BufReader;
use tokio::net::TcpListener;
use tokio::time::{timeout_at, Instant};
use tracing::{info, instrument};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Registry};
use uuid::Uuid;

use smtp::SmtpSession;
use spf::SpfResult;

/// One DKIM verification outcome, summarized for structured logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DkimSummary {
    domain: String,
    selector: String,
    body_hash_ok: bool,
    signature_ok: bool,
    /// True only when both the body hash and the signature verify.
    verified: bool,
    error: Option<String>,
}

/// Simple program to greet a person
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value_t = String::from("0.0.0.0"))]
    host: String,

    #[arg(long, default_value_t = 2525)]
    port: u16,

    #[arg(long)]
    domain: String,

    /// Number of times to greet
    #[arg(long, default_value_t = 1024*1024)]
    max_data_bytes: usize,

    #[arg(long, default_value_t = 30*1000)]
    max_conn_duration_ms: u64,

    #[arg(long, default_value_t = 15*1000)]
    max_read_duration_ms: u64,
}

/// RFC 7208 Section 8: the sender is not authorized to use the domain.
const SPF_FAILED: &[u8] = b"550 5.7.23 SPF validation failed\r\n";
/// RFC 7208 Section 8: transient failure while evaluating SPF; the client
/// may retry.
const SPF_TEMPFAIL: &[u8] = b"451 4.4.3 Temporary SPF failure\r\n";
/// RFC 7208 Section 8: the domain's SPF record is unusable.
const SPF_PERMERROR: &[u8] = b"550 5.7.7 SPF policy error\r\n";
/// Malformed address in a MAIL FROM path.
const BAD_ADDRESS: &[u8] = b"501 5.1.7 Bad sender address syntax\r\n";
/// RFC 5321 Section 3.3: DATA with no accepted recipients.
const NO_RECIPIENTS: &[u8] = b"503 5.5.1 No valid recipients\r\n";
/// RFC 5321 Section 4.2.3.4 / 6.2: the message exceeds the advertised size
/// limit; the rest of the transfer is discarded.
const MESSAGE_TOO_BIG: &[u8] = b"552 5.3.4 Message size exceeds fixed maximum message size\r\n";

/// The address inside a MAIL FROM / RCPT TO path argument: strips
/// surrounding whitespace and angle brackets. An empty result is the null
/// sender (`MAIL FROM:<>`).
fn clean_path(raw: &str) -> &str {
    raw.trim().trim_start_matches('<').trim_end_matches('>').trim()
}

/// The domain of an address path: after the last '@'.
fn path_domain(addr: &str) -> Option<&str> {
    addr.rsplit_once('@').map(|(_, domain)| domain)
}

/// The MAIL FROM verdict for an SPF evaluation of the sender identity
/// (RFC 7208 Section 8): Pass/Neutral/SoftFail/None are accepted (the
/// result is logged for downstream policy), Fail and PermError are
/// permanent rejections, TempError is retryable.
fn mail_from_reply(result: &SpfResult) -> smtp::Control {
    use smtp::Control;
    match result {
        SpfResult::Pass | SpfResult::Neutral | SpfResult::SoftFail | SpfResult::None => {
            Control::accept(UserSession::OK)
        }
        SpfResult::Fail => Control::reject(SPF_FAILED),
        SpfResult::TempError => Control::tempfail(SPF_TEMPFAIL),
        SpfResult::PermError => Control::reject(SPF_PERMERROR),
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct UserSession<'session> {
    #[serde(skip_serializing)]
    pub max_data: usize,

    #[serde(skip_serializing)]
    pub total_data: usize,

    pub session_id: Uuid,
    domain: &'session str,
    dns: Ipv4Addr,
    peer: SocketAddr,

    helo: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    data: String,
    /// SPF verdict for the MAIL FROM identity (None = no record published).
    spf_result: Option<SpfResult>,
    /// SPF verdict for the HELO/EHLO identity.
    spf_helo: Option<SpfResult>,
    dkim: Vec<DkimSummary>,
    /// Number of completed message transactions on this connection.
    message_count: usize,
}

impl<'session> UserSession<'session> {
    fn new(domain: &'session str, peer: SocketAddr, max_data: usize) -> Self {
        UserSession {
            max_data,
            total_data: 0,
            session_id: Uuid::new_v4(),

            domain,
            dns: "1.1.1.1".parse::<Ipv4Addr>().unwrap(),
            peer,

            helo: None,
            mail_from: None,
            rcpt_to: Vec::new(),
            data: String::new(),
            spf_result: None,
            spf_helo: None,
            dkim: Vec::new(),
            message_count: 0,
        }
    }

    /// Abandon the current transaction: clear the envelope and any
    /// partial message data.
    fn clear_envelope(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data.clear();
        self.total_data = 0;
        self.spf_result = None;
    }
}

impl smtp::SmtpSession for UserSession<'_> {
    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn server_greet(&self) -> Vec<u8> {
        format!("220 {} SMTP service ready\r\n", self.domain).into_bytes()
    }

    #[instrument(skip(self, arg), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn helo(&mut self, arg: &str) -> smtp::Control {
        let h = arg.trim();
        self.helo = Some(h.to_string());

        // RFC 7208 Section 2.4: evaluate the HELO identity against the
        // HELO name itself, with the macro sender postmaster@HELO.
        // Address literals publish no SPF. A definitive Fail is
        // rejected; every other outcome defers to the MAIL FROM check.
        self.spf_helo = if h.starts_with('[') {
            None
        } else {
            spf::check_host(
                &spf::DotResolver::new(self.dns),
                self.peer.ip(),
                &format!("postmaster@{h}"),
                h.to_string(),
                &self.helo,
            )
            .await
            .ok()
        };

        info!(spf_helo = ?self.spf_helo, "helo identity spf");

        match self.spf_helo {
            Some(SpfResult::Fail) => smtp::Control::reject(SPF_FAILED),
            _ => smtp::Control::accept(format!(
                "250 {} Hello [{}]\r\n",
                self.domain,
                self.peer.ip()
            )),
        }
    }

    #[instrument(skip(self, path), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn mail_from(&mut self, path: &str) -> smtp::Control {
        if self.mail_from.is_some() {
            return smtp::Control::reject(UserSession::MULTI_MAIL);
        }

        let addr = clean_path(path).to_string();

        // RFC 7208 Section 2.4: the SPF identity is the MAIL FROM
        // address; the null sender falls back to the HELO identity
        // (postmaster@HELO). Address-literal HELOs publish no SPF.
        let identity: Option<(String, String)> = if addr.is_empty() {
            match self.helo.as_deref() {
                Some(h) if !h.starts_with('[') => {
                    Some((format!("postmaster@{h}"), h.to_string()))
                }
                _ => None,
            }
        } else {
            match path_domain(&addr) {
                Some(domain) => Some((addr.clone(), domain.to_string())),
                None => return smtp::Control::reject(BAD_ADDRESS),
            }
        };

        let result = match identity {
            Some((sender, domain)) => {
                match spf::check_host(
                    &spf::DotResolver::new(self.dns),
                    self.peer.ip(),
                    &sender,
                    domain.clone(),
                    &self.helo,
                )
                .await
                {
                    Ok(result) => result,
                    // A lookup failure is transient; the client may
                    // retry (RFC 7208 Section 8).
                    Err(_) => SpfResult::TempError,
                }
            }
            // No SPF-checkable identity: nothing to assert.
            None => SpfResult::None,
        };

        self.spf_result = Some(result.clone());
        info!(spf_result = ?result, mail_from = %addr, "mail from identity spf");

        let control = mail_from_reply(&result);
        // The envelope sender is recorded only when accepted, so a
        // rejected MAIL FROM can be retried.
        if control.is_accept() {
            self.mail_from = Some(addr);
        }
        control
    }

    #[instrument(skip(self, path), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn rcpt_to(&mut self, path: &str) -> smtp::Control {
        self.rcpt_to.push(clean_path(path).to_string());
        smtp::Control::accept(UserSession::OK)
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn start_data(&mut self) -> smtp::Control {
        // RFC 5321 Section 3.3: DATA with no valid recipients is refused;
        // the session stays in Ready.
        if self.rcpt_to.is_empty() {
            return smtp::Control::reject(NO_RECIPIENTS);
        }
        smtp::Control::accept(UserSession::SEND_DATA)
    }

    #[instrument(skip(self, line), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn recv_data(&mut self, line: &str) -> smtp::DataControl {
        // Enforce the size limit across the whole message.
        self.total_data += line.len();
        if self.total_data > self.max_data {
            // The state machine replies 552 once and discards the rest of
            // the transfer.
            return smtp::DataControl::Abort(MESSAGE_TOO_BIG.to_vec());
        }
        self.data.push_str(line);
        smtp::DataControl::Continue
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn end_data(&mut self) -> smtp::Control {
        // The raw message as received: the accumulated DATA lines, with
        // line endings exactly as the client sent them.
        let raw = self.data.clone().into_bytes();
        let results = dkim::verify_dkim(&raw, &self.dns).await;

        for result in &results {
            let summary = DkimSummary {
                domain: result.signature.domain.to_string(),
                selector: result.signature.selector.to_string(),
                body_hash_ok: result.body_hash_ok,
                signature_ok: result.signature_ok,
                verified: result.body_hash_ok && result.signature_ok,
                error: result.error.as_ref().map(|e| e.to_string()),
            };
            info!(
                domain = %summary.domain,
                selector = %summary.selector,
                dkim_verified = summary.verified,
                body_hash_ok = summary.body_hash_ok,
                signature_ok = summary.signature_ok,
                dkim_error = ?summary.error,
                "dkim verification"
            );
            self.dkim.push(summary);
        }

        // The transaction is complete: clear the envelope so another
        // message can be sent on the same connection. (This also keeps
        // message bodies out of the session's structured log.)
        self.clear_envelope();
        self.message_count += 1;
        smtp::Control::accept(UserSession::OK)
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn reset(&mut self) -> smtp::Control {
        self.clear_envelope();
        smtp::Control::accept(UserSession::OK)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let app_name = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION")).to_string();

    let (non_blocking_writer, _guard) = tracing_appender::non_blocking(std::io::stdout());
    let bunyan_formatting_layer = BunyanFormattingLayer::new(app_name, non_blocking_writer);
    let subscriber = Registry::default()
        .with(EnvFilter::new("INFO"))
        .with(JsonStorageLayer)
        .with(bunyan_formatting_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Args::parse();
    let listener = TcpListener::bind(format!("{}:{}", args.host, args.port)).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let domain = args.domain.clone();

        tokio::spawn(timeout_at(
            Instant::now() + Duration::from_millis(args.max_conn_duration_ms),
            async move {
                let peer = stream.peer_addr()?;
                let mut stream = BufReader::new(stream);

                let mut session = UserSession::new(domain.as_str(), peer, args.max_data_bytes);
                session
                    .run(&mut stream, &peer, &domain, &args.max_read_duration_ms)
                    .await?;

                info!("{}", serde_json::to_string(&session)?);
                Ok::<(), anyhow::Error>(())
            },
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_path_strips_brackets_and_space() {
        assert_eq!(clean_path("<sender@example.org>"), "sender@example.org");
        assert_eq!(clean_path(" <sender@example.org> "), "sender@example.org");
        assert_eq!(clean_path("sender@example.org"), "sender@example.org");
        // Null sender.
        assert_eq!(clean_path("<>"), "");
        assert_eq!(clean_path(""), "");
    }

    #[test]
    fn path_domain_is_after_last_at() {
        assert_eq!(path_domain("sender@example.org"), Some("example.org"));
        assert_eq!(path_domain("local@sub.example.org"), Some("sub.example.org"));
        assert_eq!(path_domain("@example.org"), Some("example.org"));
        assert_eq!(path_domain("no-at-sign"), None);
    }

    #[test]
    fn mail_from_reply_maps_verdicts() {
        use smtp::Control;
        // Accepted: Pass, and the explicitly non-committal results.
        for result in [SpfResult::Pass, SpfResult::Neutral, SpfResult::SoftFail, SpfResult::None] {
            let control = mail_from_reply(&result);
            assert!(control.is_accept(), "{result:?} should accept");
            assert_eq!(control.reply(), UserSession::OK);
        }
        // Rejected.
        assert_eq!(mail_from_reply(&SpfResult::Fail).reply(), SPF_FAILED);
        assert_eq!(mail_from_reply(&SpfResult::PermError).reply(), SPF_PERMERROR);
        // Retryable.
        assert!(matches!(mail_from_reply(&SpfResult::TempError), Control::Tempfail(_)));
        assert_eq!(mail_from_reply(&SpfResult::TempError).reply(), SPF_TEMPFAIL);
    }
}
