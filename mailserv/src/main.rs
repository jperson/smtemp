use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::str;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::BufReader;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, instrument, warn};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Registry};
use uuid::Uuid;

use smtp::SmtpSession;
use spf::SpfResult;

mod spool;

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

/// A small, secure SMTP server: accepts and verifies mail (SPF, DKIM,
/// DMARC); supports STARTTLS, AUTH, and a closed relay policy.
#[derive(Parser, Debug, Clone, Default)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    host: Option<String>,

    #[arg(long)]
    port: Option<u16>,

    #[arg(long)]
    domain: Option<String>,

    /// Message size limit in bytes.
    #[arg(long)]
    max_data_bytes: Option<usize>,

    #[arg(long)]
    max_conn_duration_ms: Option<u64>,

    #[arg(long)]
    max_read_duration_ms: Option<u64>,

    /// PEM certificate for STARTTLS (requires --tls-key).
    #[arg(long)]
    tls_cert: Option<String>,

    /// PEM private key for STARTTLS (requires --tls-cert).
    #[arg(long)]
    tls_key: Option<String>,

    /// SASL credentials for AUTH PLAIN/LOGIN, as user:password pairs
    /// (comma-separated). Only offered over TLS. Example:
    /// --auth-users alice:secret,bob:hunter2
    #[arg(long)]
    auth_users: Option<String>,

    /// DNS resolver address (DNS-over-TLS on port 853) used for SPF,
    /// DKIM key, and DMARC lookups.
    #[arg(long)]
    resolver: Option<Ipv4Addr>,

    /// Queue directory where accepted messages are spooled before
    /// delivery. Spooling is part of the acceptance contract: the 250 is
    /// only sent after a durable write.
    #[arg(long, value_name = "DIR")]
    spool_dir: Option<String>,

    /// Domains whose recipients we accept mail for (comma-separated;
    /// defaults to --domain only). Relay access is closed regardless of
    /// authentication.
    #[arg(long)]
    local_domains: Option<String>,

    /// TOML configuration file; CLI flags override file values. Keys are
    /// the same as the flags in kebab-case (host, port, domain,
    /// max-data-bytes, max-conn-duration-ms, max-read-duration-ms,
    /// tls-cert, tls-key, auth-users, resolver, spool-dir,
    /// local-domains); every key
    /// optional.
    #[arg(long, value_name = "FILE")]
    config: Option<String>,
}

/// The TOML config file schema ([`Args::config`]).
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct FileConfig {
    host: Option<String>,
    port: Option<u16>,
    domain: Option<String>,
    max_data_bytes: Option<usize>,
    max_conn_duration_ms: Option<u64>,
    max_read_duration_ms: Option<u64>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    auth_users: Option<String>,
    resolver: Option<Ipv4Addr>,
    spool_dir: Option<String>,
    local_domains: Option<String>,
}

/// Fully resolved server configuration (CLI > file > built-in defaults).
#[derive(Debug, Clone)]
struct Config {
    host: String,
    port: u16,
    domain: String,
    max_data_bytes: usize,
    max_conn_duration_ms: u64,
    max_read_duration_ms: u64,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    auth_users: Option<String>,
    /// DNS-over-TLS resolver address; always resolved (default 1.1.1.1).
    resolver: Ipv4Addr,
    /// Queue directory for accepted messages (default "spool").
    spool_dir: String,
    local_domains: Option<String>,
}

/// The default DNS-over-TLS resolver.
const DEFAULT_RESOLVER: &str = "1.1.1.1";

/// Merge CLI arguments over config-file values over built-in defaults.
fn resolve_config(cli: Args, file: FileConfig) -> Result<Config> {
    Ok(Config {
        host: cli
            .host
            .or(file.host)
            .unwrap_or_else(|| "0.0.0.0".to_string()),
        port: cli.port.or(file.port).unwrap_or(2525),
        domain: cli
            .domain
            .or(file.domain)
            .ok_or_else(|| anyhow::anyhow!("a domain is required (--domain or the config file)"))?,
        max_data_bytes: cli
            .max_data_bytes
            .or(file.max_data_bytes)
            .unwrap_or(1024 * 1024),
        max_conn_duration_ms: cli
            .max_conn_duration_ms
            .or(file.max_conn_duration_ms)
            .unwrap_or(30 * 1000),
        max_read_duration_ms: cli
            .max_read_duration_ms
            .or(file.max_read_duration_ms)
            .unwrap_or(15 * 1000),
        tls_cert: cli.tls_cert.or(file.tls_cert),
        tls_key: cli.tls_key.or(file.tls_key),
        auth_users: cli.auth_users.or(file.auth_users),
        resolver: cli.resolver.or(file.resolver).unwrap_or_else(|| {
            DEFAULT_RESOLVER
                .parse()
                .expect("DEFAULT_RESOLVER is a valid IPv4 address")
        }),
        spool_dir: cli
            .spool_dir
            .or(file.spool_dir)
            .unwrap_or_else(|| "spool".to_string()),
        local_domains: cli.local_domains.or(file.local_domains),
    })
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
/// RFC 5321 Section 4.5.3.1.8: at least 100 recipients.
const MAX_RCPT: usize = 100;
/// RFC 5321 Section 3.3: DATA with no accepted recipients.
const NO_RECIPIENTS: &[u8] = b"503 5.5.1 No valid recipients\r\n";
/// RFC 5321 Section 4.2.3.4 / 6.2: the message exceeds the advertised size
/// limit; the rest of the transfer is discarded.
const MESSAGE_TOO_BIG: &[u8] = b"552 5.3.4 Message size exceeds fixed maximum message size\r\n";

/// The address inside a MAIL FROM / RCPT TO path argument: strips
/// surrounding whitespace and angle brackets. An empty result is the null
/// sender (`MAIL FROM:<>`).
fn clean_path(raw: &str) -> &str {
    raw.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
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

/// One DMARC verification outcome, summarized for structured logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DmarcSummary {
    from_domain: String,
    /// The applied policy (p= or sp=).
    policy: String,
    spf_aligned: bool,
    dkim_aligned: bool,
    pass: bool,
    /// What we did: "pass", "quarantine", or "reject".
    action: String,
}

#[derive(Debug, Serialize)]
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
    /// Partial message body, raw bytes exactly as received.
    #[serde(skip_serializing)]
    data: Vec<u8>,
    /// SPF verdict for the MAIL FROM identity (None = no record published).
    spf_result: Option<SpfResult>,
    /// SPF verdict for the HELO/EHLO identity.
    spf_helo: Option<SpfResult>,
    dkim: Vec<DkimSummary>,
    /// Number of completed message transactions on this connection.
    message_count: usize,
    /// Whether STARTTLS was accepted and the TLS handshake completed.
    tls_active: bool,
    /// Whether a TLS acceptor was configured (advertised via EHLO).
    starttls_available: bool,
    /// Accepted SASL credentials, from `--auth-users user:pass[,user:pass]`.
    #[serde(skip_serializing)]
    auth_users: Option<Arc<HashMap<String, String>>>,
    /// The authenticated identity for this connection, if any.
    authenticated: Option<String>,
    /// LOGIN continuation state.
    auth_login_user: Option<String>,
    /// The mechanism of the in-progress AUTH continuation.
    auth_pending: Option<&'static str>,
    /// Local domains we accept recipients for.
    #[serde(skip_serializing)]
    local_domains: Arc<HashSet<String>>,
    /// Disk spool for accepted messages; None drops them (tests).
    #[serde(skip_serializing)]
    spool: Option<Arc<spool::Spool>>,
    /// DMARC verdict of the last completed message, for the session log.
    dmarc: Option<DmarcSummary>,
}

impl<'session> UserSession<'session> {
    fn new(peer: SocketAddr, starttls_available: bool, cfg: &'session SessionConfig) -> Self {
        UserSession {
            max_data: cfg.max_data,
            total_data: 0,
            session_id: Uuid::new_v4(),

            domain: &cfg.domain,
            dns: cfg.resolver,
            peer,

            helo: None,
            mail_from: None,
            rcpt_to: Vec::new(),
            data: Vec::new(),
            spf_result: None,
            spf_helo: None,
            dkim: Vec::new(),
            message_count: 0,
            tls_active: false,
            starttls_available,
            auth_users: cfg.auth_users.clone(),
            authenticated: None,
            auth_login_user: None,
            auth_pending: None,
            local_domains: cfg.local_domains.clone(),
            spool: cfg.spool.clone(),
            dmarc: None,
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

    fn verify_credentials(
        &mut self,
        users: &HashMap<String, String>,
        user: &str,
        pass: &str,
    ) -> smtp::Control {
        // The comparison is a plain map lookup (local credential store, no
        // remote timing oracle worth worrying about); never log the
        // password.
        match users.get(user) {
            Some(p) if p == pass => {
                self.authenticated = Some(user.to_string());
                info!(user = %user, "authenticated");
                smtp::Control::accept(b"235 2.7.0 Authentication successful\r\n")
            }
            _ => {
                info!(user = %user, "authentication failed");
                smtp::Control::reject(b"535 5.7.8 Authentication credentials invalid\r\n")
            }
        }
    }
}

impl smtp::SmtpSession for UserSession<'_> {
    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn server_greet(&self) -> Vec<u8> {
        format!("220 {} SMTP service ready\r\n", self.domain).into_bytes()
    }

    #[instrument(skip(self, arg), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn helo(&mut self, ehlo: bool, arg: &str) -> smtp::Control {
        let h = arg.trim();
        self.helo = Some(h.to_string());

        // RFC 7208 Section 2.4: evaluate the HELO identity against the
        // HELO name itself, with the macro sender postmaster@HELO.
        // Address literals publish no SPF. A definitive Fail is
        // rejected; every other outcome defers to the MAIL FROM check.
        self.spf_helo = if h.starts_with('[') {
            None
        } else {
            match spf::check_host(
                &spf::DotResolver::new(self.dns),
                self.peer.ip(),
                &format!("postmaster@{h}"),
                h.to_string(),
                &self.helo,
            )
            .await
            {
                Ok(result) => Some(result),
                // Map evaluation errors to their results: transient DNS
                // failures are TempError, unusable records and exhausted
                // lookup budgets are PermError.
                Err(e) => Some(e.to_result()),
            }
        };

        info!(spf_helo = ?self.spf_helo, "helo identity spf");

        if self.spf_helo == Some(SpfResult::Fail) {
            return smtp::Control::reject(SPF_FAILED);
        }

        if !ehlo {
            // HELO: single-line reply (RFC 5321 Section 4.1.1.1).
            return smtp::Control::accept(format!(
                "250 {} Hello [{}]\r\n",
                self.domain,
                self.peer.ip()
            ));
        }

        // EHLO: multiline capability response (RFC 5321 Section 3.2 —
        // continuations with a dash, final line with a space).
        let mut reply = format!("250-{} Hello [{}]\r\n", self.domain, self.peer.ip());
        // RFC 1870: the size we actually enforce at DATA time.
        reply.push_str(&format!("250-SIZE {}\r\n", self.max_data));
        // RFC 3207 Section 2: advertise STARTTLS while TLS is not yet
        // active; it MUST NOT be advertised on an established TLS
        // connection.
        if self.starttls_available && !self.tls_active {
            reply.push_str("250-STARTTLS\r\n");
        }
        // RFC 8310 Section 2: only advertise (and accept) AUTH on an
        // encrypted session — credentials must not traverse plaintext.
        if self.tls_active && self.auth_users.is_some() {
            reply.push_str("250-AUTH PLAIN LOGIN\r\n");
        }
        reply.push_str("250 HELP\r\n");
        smtp::Control::accept(reply)
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn starttls(&mut self) -> smtp::Control {
        if self.tls_active {
            return smtp::Control::reject(b"503 5.5.1 TLS already active\r\n");
        }
        if !self.starttls_available {
            return smtp::Control::reject(b"454 4.7.0 TLS not available due to local problem\r\n");
        }
        smtp::Control::upgrade(b"220 2.0.0 Ready to start TLS\r\n")
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn tls_established(&mut self) {
        self.tls_active = true;
        // RFC 3207 Section 4.2: the protocol restarts; discard pre-TLS
        // knowledge (including authentication) so nothing carries over
        // into the secure session.
        self.helo = None;
        self.spf_helo = None;
        self.authenticated = None;
        self.auth_pending = None;
        self.auth_login_user = None;
        self.clear_envelope();
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>) -> smtp::Control {
        // RFC 8310 Section 2: credentials must not traverse an unencrypted
        // channel; only offer/accept AUTH on an established TLS session.
        if !self.tls_active {
            return smtp::Control::reject(
                b"538 5.7.11 Encryption required for requested authentication mechanism\r\n",
            );
        }
        if self.authenticated.is_some() {
            return smtp::Control::reject(b"503 5.5.1 Already authenticated\r\n");
        }
        let Some(users) = self.auth_users.clone() else {
            return smtp::Control::reject(b"502 5.5.1 Authentication not supported\r\n");
        };

        match mechanism {
            "PLAIN" => {
                let Some(initial) = initial else {
                    self.auth_pending = Some("PLAIN");
                    return smtp::Control::challenge(b"334 \r\n");
                };
                match smtp::decode_b64(initial)
                    .as_deref()
                    .and_then(smtp::decode_plain)
                {
                    Some((user, pass)) => self.verify_credentials(&users, &user, &pass),
                    None => smtp::Control::reject(b"501 5.5.2 Invalid base64 data\r\n"),
                }
            }
            "LOGIN" => {
                self.auth_pending = Some("LOGIN");
                match initial {
                    Some(initial) => match smtp::decode_b64(initial) {
                        Some(user) => {
                            self.auth_login_user =
                                Some(String::from_utf8_lossy(&user).into_owned());
                            smtp::Control::challenge(b"334 UGFzc3dvcmQ6\r\n")
                        }
                        None => smtp::Control::reject(b"501 5.5.2 Invalid base64 data\r\n"),
                    },
                    None => smtp::Control::challenge(b"334 VXNlcm5hbWU6\r\n"),
                }
            }
            _ => smtp::Control::reject(b"504 5.5.4 Unrecognized authentication type\r\n"),
        }
    }

    #[instrument(skip(self, line), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn auth_line(&mut self, line: &[u8]) -> smtp::Control {
        let Some(data) = smtp::decode_b64(line) else {
            return smtp::Control::reject(b"501 5.5.2 Invalid base64 data\r\n");
        };
        let Some(users) = self.auth_users.clone() else {
            return smtp::Control::reject(b"502 5.5.1 Authentication not supported\r\n");
        };
        match self.auth_pending.take() {
            Some("PLAIN") => match smtp::decode_plain(&data) {
                Some((user, pass)) => self.verify_credentials(&users, &user, &pass),
                None => smtp::Control::reject(b"501 5.5.2 Invalid PLAIN response\r\n"),
            },
            Some("LOGIN") => {
                if let Some(user) = self.auth_login_user.take() {
                    let pass = String::from_utf8_lossy(&data).into_owned();
                    self.verify_credentials(&users, &user, &pass)
                } else {
                    self.auth_login_user = Some(String::from_utf8_lossy(&data).into_owned());
                    self.auth_pending = Some("LOGIN");
                    smtp::Control::challenge(b"334 UGFzc3dvcmQ6\r\n")
                }
            }
            _ => smtp::Control::reject(b"501 5.5.2 No authentication in progress\r\n"),
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
                Some(h) if !h.starts_with('[') => Some((format!("postmaster@{h}"), h.to_string())),
                _ => None,
            }
        } else {
            match path_domain(&addr) {
                Some(domain) => Some((addr.clone(), domain.to_string())),
                None => return smtp::Control::reject(BAD_ADDRESS),
            }
        };

        // An authenticated submission (MUA -> MSA) is not subject to SPF:
        // the client's IP is the user's home network, which the sender
        // domain's SPF record will not authorize. Envelope policy for
        // authenticated users is the user's business (still logged).
        if self.authenticated.is_some() {
            self.spf_result = None;
            info!(
                auth_user = self.authenticated.as_deref().unwrap_or("?"),
                mail_from = %addr,
                "authenticated mail from (spf skipped)"
            );
            self.mail_from = Some(addr);
            return smtp::Control::accept(UserSession::OK);
        }

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
                    // Map evaluation errors to their results: transient
                    // DNS failures are TempError (retryable), unusable
                    // records and exhausted lookup budgets are PermError.
                    Err(e) => e.to_result(),
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
        // The envelope sender must come first (RFC 5321 Section 3.3: the
        // transaction is MAIL, then RCPT, then DATA).
        if self.mail_from.is_none() {
            return smtp::Control::reject(b"503 5.5.1 Error: need MAIL command\r\n");
        }
        // RFC 5321 Section 4.5.3.1.8: at least 100 recipients.
        if self.rcpt_to.len() >= MAX_RCPT {
            return smtp::Control::tempfail(b"452 4.5.3 Too many recipients\r\n");
        }

        let addr = clean_path(path).to_string();
        let Some(domain) = path_domain(&addr).map(str::to_ascii_lowercase) else {
            return smtp::Control::reject(BAD_ADDRESS);
        };

        // Relay access is closed: recipients must be in a configured local
        // domain, authenticated or not (there is no outbound relay yet;
        // this stays fail-closed).
        if !self.local_domains.contains(&domain) {
            info!(rcpt = %addr, domain = %domain, "relay access denied");
            return smtp::Control::reject(b"550 5.7.1 Relay access denied\r\n");
        }

        self.rcpt_to.push(addr);
        smtp::Control::accept(UserSession::OK)
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn start_data(&mut self) -> smtp::Control {
        // RFC 5321 Section 3.3: DATA with no valid recipients is refused;
        // the session stays in Ready.
        if self.rcpt_to.is_empty() {
            return smtp::Control::reject(NO_RECIPIENTS);
        }
        // The transaction must have a sender: the same RCPT-without-MAIL
        // hole applies to DATA via a rejected MAIL.
        if self.mail_from.is_none() {
            return smtp::Control::reject(b"503 5.5.1 Error: need MAIL command\r\n");
        }
        smtp::Control::accept(UserSession::SEND_DATA)
    }

    #[instrument(skip(self, line), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn recv_data(&mut self, line: &[u8]) -> smtp::DataControl {
        // Enforce the size limit across the whole message.
        self.total_data += line.len();
        if self.total_data > self.max_data {
            // The state machine replies 552 once and discards the rest of
            // the transfer.
            return smtp::DataControl::Abort(MESSAGE_TOO_BIG.to_vec());
        }
        self.data.extend_from_slice(line);
        smtp::DataControl::Continue
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn end_data(&mut self) -> smtp::Control {
        // The raw message as received: the accumulated DATA lines, with
        // line endings exactly as the client sent them.
        let raw = self.data.clone();
        let results = dkim::verify_dkim(&raw, &self.dns).await;
        let mut dkim_summaries: Vec<DkimSummary> = Vec::new();

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
            dkim_summaries.push(summary);
        }
        self.dkim.extend(dkim_summaries.iter().cloned());

        // DMARC (RFC 7489): evaluate the From-header domain against the
        // SPF and DKIM results, and apply the published policy. Authenticated
        // submissions (our own MSA users) are exempt from rejection — they
        // already passed local authentication; their mail is logged but
        // trusted (an MSA that rejects its own users' mail on DMARC would
        // reject legitimate submissions from networks no SPF record covers).
        let from_domain = mailparse::parse_message(&raw).ok().and_then(|m| {
            m.typed
                .from
                .and_then(|from| from.first().map(|mb| mb.domain.to_string()))
        });
        let mut dmarc_summary: Option<DmarcSummary> = None;

        if let Some(from_domain) = from_domain {
            let resolver = spf::DotResolver::new(self.dns);
            let record = match dmarc::fetch_policy(&resolver, &from_domain).await {
                Ok(Some(record)) => Some(record),
                Ok(None) => None,
                Err(e) => {
                    info!(from_domain = %from_domain, error = %e, "dmarc lookup failed");
                    None
                }
            };

            if let Some(record) = record {
                let spf_passed = matches!(self.spf_result, Some(SpfResult::Pass));
                let spf_domain = self.mail_from.as_deref().and_then(path_domain);
                let dkim: Vec<(String, bool)> = self
                    .dkim
                    .iter()
                    .map(|d| (d.domain.clone(), d.verified))
                    .collect();

                let evaluation = dmarc::evaluate(
                    &record,
                    spf_domain.map(|d| (d, spf_passed)),
                    &dkim,
                    &from_domain,
                );
                let policy = record.policy_for(&from_domain, &from_domain);
                let action = dmarc::apply(&evaluation, policy);

                let summary = DmarcSummary {
                    from_domain: from_domain.clone(),
                    policy: format!("{policy:?}"),
                    spf_aligned: evaluation.spf_aligned,
                    dkim_aligned: evaluation.dkim_aligned,
                    pass: evaluation.pass,
                    action: format!("{action:?}"),
                };
                info!(
                    from_domain = %summary.from_domain,
                    dmarc_policy = %summary.policy,
                    spf_aligned = summary.spf_aligned,
                    dkim_aligned = summary.dkim_aligned,
                    dmarc_pass = summary.pass,
                    dmarc_action = %summary.action,
                    "dmarc evaluation"
                );
                self.dmarc = Some(summary.clone());
                dmarc_summary = Some(summary);

                let exempt = self.authenticated.is_some();
                if action == dmarc::Action::Reject && !exempt {
                    // The transaction is over either way; the envelope is
                    // cleared below. Rejected mail is not spooled.
                    self.clear_envelope();
                    self.message_count += 1;
                    return smtp::Control::reject(
                        b"550 5.7.1 This message does not comply with the required DMARC policy\r\n",
                    );
                }
            }
        }

        // Spool before accepting: the 250 is only sent after a durable
        // write (Phase 7). A failed spool is a temporary failure — the
        // client is invited to retry, nothing is lost.
        if let Some(spool) = self.spool.clone() {
            let meta = spool::SpoolMeta {
                queue_id: String::new(), // assigned by the spool
                session_id: self.session_id.to_string(),
                received_at: jiff::Timestamp::now().to_string(),
                peer: self.peer.to_string(),
                helo: self.helo.clone(),
                mail_from: self.mail_from.clone(),
                rcpt_to: self.rcpt_to.clone(),
                spf_result: self.spf_result.as_ref().map(|r| format!("{r:?}")),
                spf_helo: self.spf_helo.as_ref().map(|r| format!("{r:?}")),
                dkim: dkim_summaries,
                dmarc: dmarc_summary,
                authenticated: self.authenticated.clone(),
                tls_active: self.tls_active,
                message_size: raw.len(),
            };
            match spool.write(meta, &raw).await {
                Ok(queue_id) => {
                    info!(queue_id = %queue_id, recipients = self.rcpt_to.len(), "message spooled");
                }
                Err(e) => {
                    error!(error = %e, "spool write failed; refusing with a temporary error");
                    self.clear_envelope();
                    self.message_count += 1;
                    return smtp::Control::tempfail(
                        b"451 4.3.0 Error: queueing failed, try again later\r\n",
                    );
                }
            }
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
    // RUST_LOG wins; INFO is the default (e.g. RUST_LOG=debug,
    // RUST_LOG=mailserv=trace).
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("INFO"));
    let subscriber = Registry::default()
        .with(filter)
        .with(JsonStorageLayer)
        .with(bunyan_formatting_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Args::parse();
    let file_config = match &args.config {
        Some(path) => {
            let raw = tokio::fs::read_to_string(path).await?;
            toml::from_str(&raw).map_err(|e| anyhow::anyhow!("invalid config file {path}: {e}"))?
        }
        None => FileConfig::default(),
    };
    let config = resolve_config(args, file_config)?;

    let acceptor = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => {
            let a = build_tls_acceptor(cert, key).await?;
            info!("STARTTLS available");
            Some(Arc::new(a))
        }
        (None, None) => {
            info!("STARTTLS disabled (no certificate configured)");
            None
        }
        _ => {
            anyhow::bail!("--tls-cert and --tls-key must be given together");
        }
    };

    let auth_users = match &config.auth_users {
        Some(spec) if !spec.is_empty() => {
            let mut map = HashMap::new();
            for pair in spec.split(',') {
                let Some((user, pass)) = pair.split_once(':') else {
                    anyhow::bail!("--auth-users entries must be user:password, got {pair:?}");
                };
                map.insert(user.trim().to_string(), pass.to_string());
            }
            info!("AUTH PLAIN/LOGIN available ({} user(s))", map.len());
            Some(Arc::new(map))
        }
        _ => None,
    };

    let mut local_domains: HashSet<String> = match &config.local_domains {
        Some(spec) if !spec.is_empty() => spec
            .split(',')
            .map(|d| d.trim().to_ascii_lowercase())
            .collect(),
        _ => HashSet::new(),
    };
    local_domains.insert(config.domain.to_ascii_lowercase());
    let local_domains = Arc::new(local_domains);

    let spool = Arc::new(spool::Spool::open(&config.spool_dir).await?);

    let listener = TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;

    info!(
        host = %config.host,
        port = config.port,
        domain = %config.domain,
        resolver = %config.resolver,
        spool_dir = %config.spool_dir,
        "listening"
    );

    loop {
        // A transient accept error (e.g. EMFILE under load) must not
        // terminate the server; back off briefly and keep going.
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                error!(error = %e, "accept failed; backing off");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let max_read_ms = config.max_read_duration_ms;
        let session_cfg = SessionConfig {
            domain: config.domain.clone(),
            max_data: config.max_data_bytes,
            auth_users: auth_users.clone(),
            local_domains: local_domains.clone(),
            resolver: config.resolver,
            spool: Some(spool.clone()),
        };

        tokio::spawn(async move {
            let result = timeout_at(
                Instant::now() + Duration::from_millis(config.max_conn_duration_ms),
                handle_connection(stream, acceptor, max_read_ms, session_cfg),
            )
            .await;

            // The spawned task's outcome must not be silently discarded.
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!(peer = %peer, error = %e, "connection handler failed"),
                Err(_) => warn!(peer = %peer, "connection exceeded the duration limit"),
            }
        });
    }
}

/// Per-connection policy configuration, cheap to clone from the resolved
/// server config for each accepted connection.
#[derive(Clone)]
struct SessionConfig {
    domain: String,
    max_data: usize,
    auth_users: Option<Arc<HashMap<String, String>>>,
    local_domains: Arc<HashSet<String>>,
    /// DNS-over-TLS resolver used for SPF, DKIM key, and DMARC lookups.
    resolver: Ipv4Addr,
    /// Disk spool for accepted messages; None drops them (tests).
    spool: Option<Arc<spool::Spool>>,
}

/// Serve one connection, including a possible STARTTLS upgrade: the
/// protocol loop runs over the plaintext stream, pauses for the TLS
/// handshake when the policy upgrades, and resumes over the TLS stream.
async fn handle_connection(
    stream: TcpStream,
    acceptor: Option<Arc<TlsAcceptor>>,
    max_read_ms: u64,
    cfg: SessionConfig,
) -> Result<()> {
    let peer = stream.peer_addr()?;
    let mut session = UserSession::new(peer, acceptor.is_some(), &cfg);
    let mut session_state = smtp::SessionState::default();
    let mut stream = BufReader::new(stream);

    let end = session
        .run(
            &mut stream,
            &peer,
            &cfg.domain,
            &max_read_ms,
            &mut session_state,
        )
        .await?;

    if end == smtp::EndReason::TlsHandshake {
        let Some(acceptor) = acceptor else {
            // Unreachable: the policy only upgrades when an acceptor was
            // provided.
            anyhow::bail!("STARTTLS accepted without a TLS acceptor");
        };
        // Any pipelined plaintext after the STARTTLS command is discarded
        // with the read buffer (RFC 3207 Section 4.1).
        let plain = stream.into_inner();
        let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(plain)).await
        {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => {
                info!(peer = %peer, error = %e, "TLS handshake failed");
                return Ok(());
            }
            Err(_) => {
                info!(peer = %peer, "TLS handshake timed out");
                return Ok(());
            }
        };
        info!(peer = %peer, "TLS established");

        // RFC 3207 Section 4.2: the protocol restarts after the
        // handshake — the client re-issues EHLO, no new banner.
        session.tls_established().await;
        session_state.state = smtp::SmtpState::Idle;
        session_state.greeted = true;

        let mut tls_stream = BufReader::new(tls);
        session
            .run(
                &mut tls_stream,
                &peer,
                &cfg.domain,
                &max_read_ms,
                &mut session_state,
            )
            .await?;
    }

    info!(
        tls = session.tls_active,
        messages = session.message_count,
        "{}",
        serde_json::to_string(&session)?
    );
    Ok(())
}

/// Build a TLS acceptor from PEM-encoded certificate and key files.
async fn build_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_pem = tokio::fs::read(cert_path).await?;
    let key_pem = tokio::fs::read(key_path).await?;
    tls_acceptor_from_pem(&cert_pem, &key_pem)
}

fn tls_acceptor_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsAcceptor> {
    let mut cert_cursor = std::io::Cursor::new(cert_pem);
    let certs: Vec<CertificateDer> =
        rustls_pemfile::certs(&mut cert_cursor).collect::<std::result::Result<_, _>>()?;
    let mut key_cursor = std::io::Cursor::new(key_pem);
    let key = rustls_pemfile::private_key(&mut key_cursor)?
        .ok_or_else(|| anyhow::anyhow!("no private key found"))?;

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
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
        assert_eq!(
            path_domain("local@sub.example.org"),
            Some("sub.example.org")
        );
        assert_eq!(path_domain("@example.org"), Some("example.org"));
        assert_eq!(path_domain("no-at-sign"), None);
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

    // -- STARTTLS integration: a real rustls client against the real
    //    connection driver -------------------------------------------------

    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::TcpStream as TestTcpStream;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::{rustls::RootCertStore, TlsConnector as TestTlsConnector};

    // -- Config resolution (CLI > file > defaults) -----------------------

    #[test]
    fn config_file_parses_and_precedence_holds() {
        use clap::Parser as _;

        // kebab-case keys, all optional.
        let file: FileConfig = toml::from_str(
            r#"
            host = "127.0.0.1"
            port = 2526
            domain = "file.example"
            max-data-bytes = 2048
            tls-cert = "cert.pem"
            "#,
        )
        .unwrap();

        // Defaults when neither CLI nor file provide a value.
        let resolved = resolve_config(Args::parse_from(["mailserv"]), file.clone()).unwrap();
        assert_eq!(resolved.host, "127.0.0.1");
        assert_eq!(resolved.port, 2526);
        assert_eq!(resolved.domain, "file.example");
        assert_eq!(resolved.max_data_bytes, 2048);
        assert_eq!(resolved.max_conn_duration_ms, 30 * 1000);
        assert_eq!(resolved.tls_cert.as_deref(), Some("cert.pem"));
        // The resolver defaults to 1.1.1.1 when nothing is configured.
        assert_eq!(resolved.resolver, "1.1.1.1".parse::<Ipv4Addr>().unwrap());

        // CLI flags win over the file.
        let resolved = resolve_config(
            Args::parse_from([
                "mailserv",
                "--domain",
                "cli.example",
                "--port",
                "2527",
                "--max-data-bytes",
                "4096",
                "--resolver",
                "9.9.9.9",
            ]),
            file,
        )
        .unwrap();
        assert_eq!(resolved.domain, "cli.example");
        assert_eq!(resolved.port, 2527);
        assert_eq!(resolved.max_data_bytes, 4096);
        assert_eq!(resolved.resolver, "9.9.9.9".parse::<Ipv4Addr>().unwrap());
        // File value survives where the CLI is silent.
        assert_eq!(resolved.tls_cert.as_deref(), Some("cert.pem"));

        // No domain anywhere is a hard error.
        assert!(resolve_config(Args::parse_from(["mailserv"]), FileConfig::default()).is_err());
    }

    #[test]
    fn resolver_from_config_file_wins_over_default() {
        use clap::Parser as _;

        let file: FileConfig = toml::from_str(
            r#"
            domain = "file.example"
            resolver = "8.8.8.8"
            "#,
        )
        .unwrap();
        let resolved = resolve_config(Args::parse_from(["mailserv"]), file).unwrap();
        assert_eq!(resolved.resolver, "8.8.8.8".parse::<Ipv4Addr>().unwrap());
    }

    /// Spawn handle_connection on an ephemeral port. Returns the address.
    async fn spawn_server(
        acceptor: Option<Arc<TlsAcceptor>>,
        auth_users: Option<Arc<HashMap<String, String>>>,
        local_domains: Option<Vec<String>>,
        spool: Option<Arc<spool::Spool>>,
    ) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let local: Arc<HashSet<String>> = Arc::new(
            local_domains
                .unwrap_or_else(|| vec!["example.org".to_string()])
                .into_iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
        );
        tokio::spawn(async move {
            if let Ok((stream, _peer)) = listener.accept().await {
                let _ = handle_connection(
                    stream,
                    acceptor,
                    5000,
                    SessionConfig {
                        domain: "mail.example.org".to_string(),
                        max_data: 1024 * 1024,
                        auth_users,
                        local_domains: local,
                        // The integration tests exercise the real resolver
                        // path: the sender domains used below
                        // (spfless-domain-xyz.test) are NXDOMAIN, so SPF
                        // evaluates to None and DMARC has no policy.
                        resolver: "1.1.1.1".parse().unwrap(),
                        spool,
                    },
                )
                .await;
            }
        });
        addr
    }

    /// Read one (possibly multiline) SMTP reply: lines until the
    /// `NNN ` final line (a dash after the code continues it).
    async fn read_reply<R>(reader: &mut BufReader<R>) -> Vec<String>
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
        let addr = spawn_server(Some(acceptor), None, None, None).await;

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
            .write_all(b"Subject: over TLS\r\n\r\nsecure body.\r\n.\r\n")
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
        let addr = spawn_server(None, None, None, None).await;
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

    /// AUTH over TLS: advertisement gating, both mechanisms, bad
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
        let mut users = HashMap::new();
        users.insert("alice".to_string(), "secret".to_string());
        let addr = spawn_server(Some(acceptor), Some(Arc::new(users)), None, None).await;

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

        // Authenticated sender: SPF is skipped (the MUA's home IP is not
        // authorized by the sender domain's SPF record).
        client
            .write_all(b"MAIL FROM:<alice@spfless-domain-xyz.test>\r\n")
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
            "501 5.1.7 Bad sender address syntax\r\n"
        );
        client.write_all(b"QUIT\r\n").await.unwrap();
    }

    /// The recipient cap (RFC 5321 Section 4.5.3.1.8: at least 100).
    #[tokio::test]
    async fn recipient_cap() {
        let addr = spawn_server(None, None, None, None).await;
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

    /// Accepted messages are durably spooled: payload byte-exact, metadata
    /// complete, and the 250 only after the write (Phase 7).
    #[tokio::test]
    async fn accepted_message_is_spooled() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Arc::new(spool::Spool::open(dir.path()).await.unwrap());
        let addr = spawn_server(None, None, None, Some(spool)).await;

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
            .write_all(b"Subject: spool test\r\n\r\nbody line\r\n.\r\n")
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

        // Payload is exactly the (unstuffed) DATA bytes.
        let payload = tokio::fs::read(new.join(&names[0])).await.unwrap();
        assert_eq!(payload, b"Subject: spool test\r\n\r\nbody line\r\n");

        // Metadata is complete and consistent.
        let meta: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(new.join(&names[1])).await.unwrap()).unwrap();
        assert_eq!(meta["queue_id"], id);
        assert_eq!(meta["helo"], "client.test");
        assert_eq!(meta["mail_from"], "sender@spfless-domain-xyz.test");
        assert_eq!(meta["rcpt_to"][0], "user@example.org");
        assert_eq!(meta["message_size"], payload.len());
        assert!(meta["received_at"].is_string());
        assert!(meta["peer"].is_string());
    }
}
