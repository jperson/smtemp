//! The SMTP policy for one connection. [`UserSession`] implements
//! [`smtp::SmtpSession`]: HELO, STARTTLS and AUTH, MAIL FROM (with SPF),
//! RCPT TO (through the recipient authority), and end of data (the From:
//! and bare-CR checks, DKIM, DMARC, the spool write and the fast-path
//! delivery). [`SessionConfig`] is what the server hands each session.

use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use crate::address::{clean_path, path_domain, size_param, unsafe_local_part, valid_helo};
use crate::authority::{self, Resolution};
use crate::headers::{
    from_authors, from_header_domain, header_has_bare_cr, single_from_value, FromHeader,
};
use crate::quota::{StorageLimits, INSUFFICIENT_STORAGE, MAILBOX_FULL};
use crate::verdict::{DkimSummary, DmarcSummary};
use crate::{auth, delivery, limit, spool};
use smtp::SmtpSession;
use spf::SpfResult;

/// How long a single authority lookup may take before the RCPT is
/// refused with a temporary failure (fail-closed).
pub(crate) const AUTHORITY_TIMEOUT: Duration = Duration::from_secs(5);

/// The RCPT-time authority outcome after cache/timeout handling.
pub(crate) enum AuthorityAnswer {
    /// Accept: mail routes to the resolved recipient.
    Accept(authority::Recipient),
    /// The domain is not hosted here: relay access denied.
    NotHosted,
    /// The domain is hosted but the address cannot receive mail.
    Refuse {
        /// The domain's policy mode, for the refusal log.
        mode: authority::PolicyMode,
        /// Why, for the refusal log (never revealed to the sender).
        reason: authority::RefusalReason,
    },
    /// The authority could not be consulted (the error text): fail closed
    /// with 451.
    Unavailable(String),
}

/// RFC 7208 Section 8: the sender is not authorized to use the domain.
pub(crate) const SPF_FAILED: &[u8] = b"550 5.7.23 SPF validation failed\r\n";

/// RFC 7208 Section 8: transient failure while evaluating SPF; the client
/// may retry.
pub(crate) const SPF_TEMPFAIL: &[u8] = b"451 4.4.3 Temporary SPF failure\r\n";

/// RFC 7208 Section 8: the domain's SPF record is unusable.
pub(crate) const SPF_PERMERROR: &[u8] = b"550 5.7.7 SPF policy error\r\n";

/// RFC 5321 §4.1.1.1: the HELO/EHLO argument is not a domain or address
/// literal (it would be copied into `Received:`).
pub(crate) const BAD_HELO: &[u8] = b"501 5.5.2 Invalid HELO/EHLO domain\r\n";

/// An authenticated user's MAIL FROM is not one their login may use
/// (`--auth-senders`; RFC 3463 5.7.1, delivery not authorized).
pub(crate) const SENDER_NOT_OWNED: &[u8] =
    b"553 5.7.1 Sender address not owned by authenticated user\r\n";

/// An authenticated user's message has a `From:` author their login may
/// not use (RFC 3463 5.7.1).
pub(crate) const FROM_NOT_OWNED: &[u8] =
    b"550 5.7.1 From address not owned by authenticated user\r\n";

/// AUTH refused without checking: this session or its source IP has used
/// up its failure budget (RFC 4954 §6: temporary authentication failure).
pub(crate) const AUTH_TOO_MANY_FAILURES: &[u8] =
    b"454 4.7.0 Too many failed authentication attempts, try again later\r\n";

/// Malformed address in a MAIL FROM path.
pub(crate) const BAD_ADDRESS: &[u8] = b"501 5.1.7 Bad sender address syntax\r\n";

/// Malformed or unacceptable address in a RCPT TO path (RFC 3463: 5.1.3
/// bad destination mailbox address syntax).
pub(crate) const BAD_RCPT: &[u8] = b"553 5.1.3 Bad recipient address syntax\r\n";

/// The source IP's share of DNS-backed checks stayed exhausted for the
/// whole wait ([`limit::DNS_LIMIT_WAIT`]); retryable.
pub(crate) const DNS_BUSY: &[u8] =
    b"451 4.7.0 Too many concurrent DNS checks from your address, try again later\r\n";

/// The header block has a bare CR (RFC 5322 §2.2: CR only occurs in
/// CRLF). Refused because parsers disagree on where such a line ends.
pub(crate) const BARE_CR_IN_HEADER: &[u8] = b"550 5.6.0 Message header contains a bare CR\r\n";

/// The DMARC policy lookup failed (SERVFAIL, query timeout): deferred,
/// never treated as "no policy".
pub(crate) const DMARC_TEMPFAIL: &[u8] =
    b"451 4.4.3 Temporary failure looking up the sender's DMARC policy, try again later\r\n";

/// The end-of-data DNS work (DKIM key lookups plus the DMARC policy
/// fetch) didn't finish within [`END_OF_DATA_DNS_DEADLINE`]; retryable.
pub(crate) const EOD_DNS_TIMEOUT: &[u8] =
    b"451 4.4.3 Message checks timed out waiting for DNS, try again later\r\n";

/// The overall time limit for end-of-data DNS work: every DKIM key lookup
/// and the DMARC policy fetch together. Without it,
/// up to 5 signatures (`dkim::MAX_SIGNATURES`) each waiting the 5 s
/// per-query timeout, plus the DMARC fetch, could run past the connection
/// cap, dropping the session with no reply. The same 20 s as
/// `spf::EVALUATION_DEADLINE`; running out is a temporary failure, never a
/// permanent rejection (skipping the checks would fail DMARC and reject
/// legitimate mail).
pub(crate) const END_OF_DATA_DNS_DEADLINE: Duration = Duration::from_secs(20);

/// RFC 5321 Section 4.5.3.1.8: at least 100 recipients.
pub(crate) const MAX_RCPT: usize = 100;

/// RFC 5321 Section 3.3: DATA with no accepted recipients.
pub(crate) const NO_RECIPIENTS: &[u8] = b"503 5.5.1 No valid recipients\r\n";

/// RFC 5321 Section 4.2.3.4 / 6.2: the message exceeds the advertised size
/// limit; the rest of the transfer is discarded.
pub(crate) const MESSAGE_TOO_BIG: &[u8] =
    b"552 5.3.4 Message size exceeds fixed maximum message size\r\n";

/// Returns the MAIL FROM reply for SPF `result` on the sender identity
/// (RFC 7208 Section 8): Pass/Neutral/SoftFail/None are accepted (the
/// result is logged for downstream policy), Fail and PermError are
/// permanent rejections, TempError is retryable.
pub(crate) fn mail_from_reply(result: &SpfResult) -> smtp::Control {
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

/// Log why the SPF evaluation of `identity` (helo or mail_from) for
/// `domain` ended in `error` (the error is otherwise only visible as the
/// TempError/PermError it maps to). An exceeded
/// evaluation deadline is a `warn`: it means slow or unresponsive DNS for
/// the sender's records, which operators should see.
pub(crate) fn log_spf_error(identity: &str, domain: &str, error: &spf::SpfError) {
    match error {
        spf::SpfError::Deadline(limit) => warn!(
            identity,
            domain,
            limit_ms = u64::try_from(limit.as_millis()).unwrap_or(u64::MAX),
            "spf evaluation exceeded its time limit; temperror"
        ),
        other => info!(identity, domain, error = %other, "spf evaluation error"),
    }
}

/// Log that a check was refused because its source IP's DNS share stayed
/// exhausted (`stage`: helo, mail_from, end_of_data). The session's span
/// already carries the peer.
pub(crate) fn log_dns_busy(stage: &str) {
    warn!(
        stage,
        wait_ms = u64::try_from(limit::DNS_LIMIT_WAIT.as_millis()).unwrap_or(u64::MAX),
        "per-IP DNS limit: no permit within the wait; temporary failure"
    );
}

/// Which listener a connection arrived on, which decides its policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum ListenerMode {
    /// The MX listener (port 25): inbound mail from other servers. AUTH
    /// is never offered or accepted.
    Mx,
    /// Message submission with STARTTLS (port 587, RFC 6409): AUTH is
    /// offered after STARTTLS and required before MAIL FROM; HELO SPF is
    /// not evaluated (clients send from arbitrary networks).
    Submission,
    /// Message submission over implicit TLS (port 465, RFC 8314): as
    /// [`ListenerMode::Submission`], with TLS from the first byte.
    Submissions,
}

impl ListenerMode {
    /// Whether this is a submission listener (587 or 465).
    fn is_submission(self) -> bool {
        self != ListenerMode::Mx
    }
}

/// `530`: a submission listener requires AUTH before MAIL FROM (RFC 4954
/// §6).
pub(crate) const AUTH_REQUIRED: &[u8] = b"530 5.7.0 Authentication required\r\n";

/// One mail transaction (RFC 5321 §3.3): created when MAIL FROM is
/// accepted, dropped at end of data, RSET (including the reset after an
/// aborted transfer), a new HELO/EHLO, or STARTTLS. Owning a message's
/// state in one value means ending the transaction is dropping it: no
/// field can be forgotten and carried into the next message.
#[derive(Serialize)]
pub(crate) struct Transaction {
    /// The envelope sender (brackets removed; `""` for the null sender).
    mail_from: String,
    /// The size the client declared with `MAIL FROM ... SIZE=` (RFC 1870),
    /// checked against each recipient's limit at RCPT time.
    #[serde(skip)]
    declared_size: Option<u64>,
    /// SPF verdict for the MAIL FROM identity; `None` for authenticated
    /// sessions (SPF skipped).
    spf_result: Option<SpfResult>,
    /// Accepted recipients with their authority-resolved routing.
    rcpt_to: Vec<spool::SpoolRcpt>,
    /// The size limit: the server's, lowered to the accepted recipients'
    /// domain limit (`max-message-bytes`) when their domain set one. Every
    /// recipient shares it (see `rcpt_to`).
    #[serde(skip)]
    limit: usize,
    /// The message so far, raw bytes exactly as received (only while
    /// within `limit`).
    #[serde(skip)]
    data: Vec<u8>,
    /// Bytes of message data received, including any past `limit`.
    #[serde(skip)]
    received: usize,
}

impl Transaction {
    /// A transaction for the accepted envelope sender `mail_from`, with
    /// the declared size `declared_size`, the sender's SPF verdict
    /// `spf_result`, and the server's size limit `limit`.
    fn new(
        mail_from: String,
        declared_size: Option<u64>,
        spf_result: Option<SpfResult>,
        limit: usize,
    ) -> Self {
        Transaction {
            mail_from,
            declared_size,
            spf_result,
            rcpt_to: Vec::new(),
            limit,
            data: Vec::new(),
            received: 0,
        }
    }

    /// Returns the domains of the accepted recipients, lowercased, sorted
    /// and deduplicated, for logs.
    fn rcpt_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = self
            .rcpt_to
            .iter()
            .filter_map(|r| path_domain(&r.address).map(str::to_ascii_lowercase))
            .collect();
        domains.sort();
        domains.dedup();
        domains
    }
}

/// The state of one SMTP connection: the [`smtp::SmtpSession`]
/// implementation that applies this server's policy (HELO and MAIL FROM
/// SPF, recipient authority, size limits, AUTH, end-of-data DKIM/DMARC,
/// spooling and fast-path delivery). Borrows the shared
/// [`SessionConfig`] for its lifetime; serialized fields form the session
/// log record.
#[derive(Serialize)]
pub(crate) struct UserSession<'session> {
    /// Server-wide message size limit (`max-data-bytes`).
    #[serde(skip_serializing)]
    pub max_data: usize,

    /// The mail transaction in progress, from an accepted MAIL FROM to end
    /// of data or RSET; `None` between transactions. Everything that
    /// belongs to one message lives in it, so nothing outlives the message.
    /// Logged with the session (flattened) when the connection ends
    /// mid-transaction.
    #[serde(flatten)]
    txn: Option<Transaction>,

    /// Unique ID of this connection, for log correlation.
    pub session_id: Uuid,
    /// This server's domain.
    domain: &'session str,
    /// Shared DNS client (pipelined DoT connections + TTL cache) for SPF,
    /// DKIM key, and DMARC lookups.
    #[serde(skip_serializing)]
    dns: Arc<dns::DnsClient>,
    /// Per-source-IP limit on concurrent DNS-backed checks, shared by
    /// every session.
    #[serde(skip_serializing)]
    dns_limit: Arc<limit::DnsLimiter>,
    /// The connected client.
    peer: SocketAddr,

    /// The accepted HELO/EHLO identity.
    helo: Option<String>,
    /// SPF verdict for the HELO/EHLO identity; `None` before HELO and for
    /// address-literal HELOs.
    spf_helo: Option<SpfResult>,
    /// DKIM verdicts of every message on this connection, for the session
    /// log. Never used for DMARC, which only sees the current message's.
    dkim: Vec<DkimSummary>,
    /// Number of completed message transactions on this connection.
    pub(crate) message_count: usize,
    /// Whether STARTTLS was accepted and the TLS handshake completed.
    pub(crate) tls_active: bool,
    /// Whether a TLS acceptor was configured (advertised via EHLO).
    starttls_available: bool,
    /// AUTH configuration (credentials and sender grants); `None` when
    /// AUTH is not configured.
    #[serde(skip_serializing)]
    auth: Option<Arc<auth::AuthConfig>>,
    /// The authenticated identity for this connection, if any.
    authenticated: Option<String>,
    /// The listener this connection arrived on (set by the driver;
    /// [`ListenerMode::Mx`] by default).
    pub(crate) mode: ListenerMode,
    /// Failed AUTH attempts on this connection (capped at
    /// [`auth::MAX_FAILURES_PER_SESSION`]; survives STARTTLS).
    auth_failures: u32,
    /// AUTH LOGIN continuation state: the user name already received.
    auth_login_user: Option<String>,
    /// The mechanism of the in-progress AUTH continuation.
    auth_pending: Option<&'static str>,
    /// The recipient authority: owns the hosted-domain list, per-domain
    /// policy, and the address-to-mailbox mapping.
    #[serde(skip_serializing)]
    authority: Arc<dyn authority::RecipientResolver>,
    /// Per-connection cache of *accepted* resolutions, keyed by
    /// lowercased address. Refusals are never cached — every refusal
    /// must reach the authority (the "exactly once" invariant).
    #[serde(skip_serializing)]
    rcpt_cache: HashMap<String, authority::Recipient>,
    /// Spool backend for accepted messages; None drops them (tests).
    #[serde(skip_serializing)]
    spool: Option<Arc<dyn spool::SpoolWriter>>,
    /// Local delivery sink; None leaves messages queued (tests).
    #[serde(skip_serializing)]
    sink: Option<Arc<dyn delivery::DeliverySink>>,
    /// DMARC verdict of the last completed message, for the session log.
    dmarc: Option<DmarcSummary>,
    /// Overall limit on end-of-data DNS work (DKIM + DMARC).
    #[serde(skip_serializing)]
    eod_dns_deadline: Duration,
    /// Graceful-shutdown signal (see `SmtpSession::shutdown_signal`).
    #[serde(skip_serializing)]
    shutdown: tokio::sync::watch::Receiver<bool>,
    /// When the connection must end (see `SmtpSession::deadline`).
    #[serde(skip_serializing)]
    deadline: Option<Instant>,
    /// Server-wide bound on fast-path deliveries in flight.
    #[serde(skip_serializing)]
    fast_path: Arc<tokio::sync::Semaphore>,
    /// The mailbox quota and free-disk floor.
    #[serde(skip_serializing)]
    storage: Arc<StorageLimits>,
}

impl<'session> UserSession<'session> {
    /// A fresh session for a connection from `peer`, configured from
    /// `cfg`. `starttls_available` says whether a TLS acceptor is
    /// configured (so EHLO advertises STARTTLS).
    pub(crate) fn new(
        peer: SocketAddr,
        starttls_available: bool,
        cfg: &'session SessionConfig,
    ) -> Self {
        UserSession {
            max_data: cfg.max_data,
            session_id: Uuid::new_v4(),

            domain: &cfg.domain,
            dns: cfg.dns.clone(),
            dns_limit: cfg.dns_limit.clone(),
            peer,

            helo: None,
            spf_helo: None,
            dkim: Vec::new(),
            message_count: 0,
            tls_active: false,
            starttls_available,
            auth: cfg.auth.clone(),
            authenticated: None,
            mode: ListenerMode::Mx,
            auth_failures: 0,
            auth_login_user: None,
            auth_pending: None,
            authority: cfg.authority.clone(),
            rcpt_cache: HashMap::new(),
            spool: cfg.spool.clone(),
            sink: cfg.sink.clone(),
            dmarc: None,
            eod_dns_deadline: cfg.eod_dns_deadline,
            shutdown: cfg.shutdown.clone(),
            deadline: cfg.deadline,
            fast_path: Arc::clone(&cfg.fast_path),
            storage: Arc::clone(&cfg.storage),
            txn: None,
        }
    }

    /// Abandon the transaction in progress, if any, dropping its envelope,
    /// verdicts and buffered data (the allocation too: an aborted 10 MiB
    /// transfer must not keep its memory for the rest of the session).
    fn clear_envelope(&mut self) {
        self.txn = None;
    }

    /// Log a message refused for its size (`stage`: mail_from, rcpt_to,
    /// data, or data_line), with the offending `size` if known, the
    /// `limit` it exceeded and a human-readable `detail`. Envelope and
    /// sizes only, never content.
    fn log_size_refusal(&self, stage: &str, size: Option<u64>, limit: usize, detail: &str) {
        info!(
            stage,
            size,
            limit,
            server_limit = self.max_data,
            mail_from = ?self.txn.as_ref().map(|t| &t.mail_from),
            recipients = self.txn.as_ref().map_or(0, |t| t.rcpt_to.len()),
            rcpt_domains = ?self.txn.as_ref().map(Transaction::rcpt_domains),
            detail,
            "message refused: size limit"
        );
    }

    /// Whether a watched filesystem is below the free-disk floor (logged
    /// at `warn` when it is).
    fn storage_is_low(&self) -> bool {
        match self.storage.low_disk() {
            Some((dir, free)) => {
                warn!(
                    dir = %dir.display(),
                    free_bytes = free,
                    min_free_disk_bytes = self.storage.min_free_disk,
                    "storage low; deferring new mail"
                );
                true
            }
            None => false,
        }
    }

    /// Apply the mailbox quota to the recipient `address`, routed to
    /// `mailbox`, whose authority set the quota `authority_quota` (see
    /// [`StorageLimits::quota_for`]): its stored bytes
    /// ([`delivery::DeliverySink::usage`], on the blocking pool) plus any
    /// size declared at MAIL FROM must fit.
    ///
    /// Returns `None` when the recipient may be accepted (or there is no
    /// quota or sink), `452 4.2.2` when the mailbox is full, and `451` when
    /// its usage can't be measured (fail closed: the sender retries).
    async fn check_mailbox_quota(
        &self,
        address: &str,
        mailbox: &str,
        authority_quota: Option<u64>,
    ) -> Option<smtp::Control> {
        let (Some(quota), Some(sink)) =
            (self.storage.quota_for(authority_quota), self.sink.clone())
        else {
            return None;
        };
        let incoming = self.txn.as_ref().and_then(|t| t.declared_size).unwrap_or(0);
        let lookup = mailbox.to_string();
        let usage = tokio::task::spawn_blocking(move || sink.usage(&lookup)).await;
        match usage {
            Ok(Ok(usage)) if crate::quota::has_room(quota, usage, incoming) => None,
            Ok(Ok(usage)) => {
                info!(
                    rcpt = %address,
                    mailbox = %mailbox,
                    usage_bytes = usage,
                    declared_bytes = incoming,
                    quota_bytes = quota,
                    "recipient deferred: mailbox over quota"
                );
                Some(smtp::Control::tempfail(MAILBOX_FULL))
            }
            Ok(Err(e)) => {
                warn!(rcpt = %address, mailbox = %mailbox, error = %format!("{e:#}"), "mailbox usage unavailable; refusing temporarily");
                Some(smtp::Control::tempfail(
                    b"451 4.3.0 Mailbox check failed, try again later\r\n",
                ))
            }
            Err(e) => {
                warn!(rcpt = %address, error = %e, "mailbox usage task panicked; refusing temporarily");
                Some(smtp::Control::tempfail(
                    b"451 4.3.0 Mailbox check failed, try again later\r\n",
                ))
            }
        }
    }

    /// Check `user`/`pass` against `auth` (an argon2id check on the
    /// blocking pool, rate-limited per source IP; see
    /// [`auth::AuthConfig::check`]); on a match, the session becomes
    /// authenticated as `user`.
    ///
    /// Returns `235` on success and `535` on a mismatch. Once this
    /// session has failed [`auth::MAX_FAILURES_PER_SESSION`] times, or
    /// its IP has used up its failure budget, returns `454` without
    /// checking anything.
    async fn verify_credentials(
        &mut self,
        auth: &Arc<auth::AuthConfig>,
        user: &str,
        pass: &str,
    ) -> smtp::Control {
        if self.auth_failures >= auth::MAX_FAILURES_PER_SESSION {
            return smtp::Control::tempfail(AUTH_TOO_MANY_FAILURES);
        }
        // Never log the password.
        match auth.check(self.peer.ip(), user, pass).await {
            auth::AuthCheck::Accepted => {
                self.authenticated = Some(user.to_string());
                info!(user = %user, "authenticated");
                smtp::Control::accept(b"235 2.7.0 Authentication successful\r\n")
            }
            auth::AuthCheck::Rejected => {
                self.auth_failures += 1;
                info!(user = %user, failures = self.auth_failures, "authentication failed");
                smtp::Control::reject(b"535 5.7.8 Authentication credentials invalid\r\n")
            }
            auth::AuthCheck::Blocked => {
                warn!(user = %user, "authentication refused: too many failures from this address");
                smtp::Control::tempfail(AUTH_TOO_MANY_FAILURES)
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
        if !valid_helo(h) {
            // Refused before it is recorded: the rejected HELO leaves the
            // session Idle, so nothing reaches the spool or `Received:`.
            info!(helo = ?h, "helo refused: invalid identity");
            return smtp::Control::reject(BAD_HELO);
        }
        self.helo = Some(h.to_string());

        // RFC 7208 Section 2.4: evaluate the HELO identity against the
        // HELO name itself, with the macro sender postmaster@HELO.
        // Address literals publish no SPF. A definitive Fail is
        // rejected; every other outcome defers to the MAIL FROM check.
        // Not on submission listeners: a mail client sends from whatever
        // network it is on, which no HELO record will authorize, and must
        // be able to reach AUTH.
        self.spf_helo = if h.starts_with('[') || self.mode.is_submission() {
            None
        } else {
            // The evaluation holds one of this source IP's DNS permits
            // (DESIGN §9). If none frees up in time, the HELO identity
            // is TempError, which never rejects HELO: MAIL FROM decides.
            match self.dns_limit.acquire(self.peer.ip()).await {
                Err(limit::DnsBusy) => {
                    log_dns_busy("helo");
                    Some(SpfResult::TempError)
                }
                Ok(_permit) => match spf::check_host(
                    &spf::DotResolver::shared(self.dns.clone()),
                    self.peer.ip(),
                    &format!("postmaster@{h}"),
                    h.to_string(),
                    &self.helo,
                )
                .await
                {
                    Ok(result) => Some(result),
                    // Map evaluation errors to their results: transient
                    // DNS failures and an exceeded evaluation deadline are
                    // TempError, unusable records and exhausted lookup
                    // budgets are PermError. The reason is logged — it is
                    // otherwise lost in the mapping.
                    Err(e) => {
                        log_spf_error("helo", h, &e);
                        Some(e.to_result())
                    }
                },
            }
        };

        info!(spf_helo = ?self.spf_helo, "helo identity spf");

        if self.spf_helo == Some(SpfResult::Fail) {
            return smtp::Control::reject(SPF_FAILED);
        }
        // RFC 5321 §4.1.4: an accepted HELO/EHLO resets the session as RSET
        // does, so a transaction in progress ends here.
        self.clear_envelope();

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
        // AUTH only on submission listeners, and (RFC 8310 Section 2) only
        // on an encrypted session — credentials must not traverse
        // plaintext. The MX never offers it.
        if self.mode.is_submission() && self.tls_active && self.auth.is_some() {
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
        // The MX never takes credentials: AUTH is a submission feature.
        if !self.mode.is_submission() {
            return smtp::Control::reject(b"502 5.5.1 Authentication not supported\r\n");
        }
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
        let Some(users) = self.auth.clone() else {
            return smtp::Control::reject(b"502 5.5.1 Authentication not supported\r\n");
        };
        // A new exchange starts clean, however the last one ended (a `*`
        // abort or RSET mid-exchange never reaches the policy), so a stale
        // LOGIN user name can never pair with this exchange's password.
        self.auth_pending = None;
        self.auth_login_user = None;

        // RFC 4954 §4: SASL mechanism names are case-insensitive.
        match mechanism.to_ascii_uppercase().as_str() {
            "PLAIN" => {
                let Some(initial) = initial else {
                    self.auth_pending = Some("PLAIN");
                    return smtp::Control::challenge(b"334 \r\n");
                };
                match smtp::decode_b64(initial)
                    .as_deref()
                    .and_then(smtp::decode_plain)
                {
                    Some((user, pass)) => self.verify_credentials(&users, &user, &pass).await,
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
        let Some(users) = self.auth.clone() else {
            return smtp::Control::reject(b"502 5.5.1 Authentication not supported\r\n");
        };
        match self.auth_pending.take() {
            Some("PLAIN") => match smtp::decode_plain(&data) {
                Some((user, pass)) => self.verify_credentials(&users, &user, &pass).await,
                None => smtp::Control::reject(b"501 5.5.2 Invalid PLAIN response\r\n"),
            },
            Some("LOGIN") => {
                if let Some(user) = self.auth_login_user.take() {
                    let pass = String::from_utf8_lossy(&data).into_owned();
                    self.verify_credentials(&users, &user, &pass).await
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
        if self.txn.is_some() {
            return smtp::Control::reject(UserSession::MULTI_MAIL);
        }
        // Submission is for authenticated users only (RFC 6409 §4.3).
        if self.mode.is_submission() && self.authenticated.is_none() {
            return smtp::Control::reject(AUTH_REQUIRED);
        }

        // No new transaction while storage is low: the sender retries, and
        // mail already accepted keeps the remaining space for delivery.
        if self.storage_is_low() {
            return smtp::Control::tempfail(INSUFFICIENT_STORAGE);
        }

        let Some((addr, params)) = clean_path(path) else {
            return smtp::Control::reject(BAD_ADDRESS);
        };
        // RFC 1870: a declared size over the advertised limit is refused
        // up front, before any data is transferred.
        let declared_size = size_param(params);
        if let Some(size) = declared_size.filter(|&size| size > self.max_data as u64) {
            self.log_size_refusal(
                "mail_from",
                Some(size),
                self.max_data,
                "declared SIZE over the server limit",
            );
            return smtp::Control::reject(MESSAGE_TOO_BIG);
        }
        let addr = addr.to_string();

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
        // domain's SPF record will not authorize. That skip is only safe
        // because the authenticated identity must own the address: it is
        // checked against the login's `--auth-senders` grants first, and
        // the null sender is refused (an MUA never sends a bounce). Being
        // authenticated never means "may use any sender".
        if let Some(user) = self.authenticated.as_deref() {
            let permitted = match (auth::split_address(&addr), self.auth.as_deref()) {
                (Some((local, domain)), Some(auth)) => auth.permits(user, local, domain),
                _ => false,
            };
            if !permitted {
                warn!(
                    auth_user = %user,
                    mail_from = %addr,
                    "authenticated sender refused: address not granted to this user"
                );
                return smtp::Control::reject(SENDER_NOT_OWNED);
            }
            info!(
                auth_user = self.authenticated.as_deref().unwrap_or("?"),
                mail_from = %addr,
                "authenticated mail from (spf skipped)"
            );
            self.txn = Some(Transaction::new(addr, declared_size, None, self.max_data));
            return smtp::Control::accept(UserSession::OK);
        }

        let result = match identity {
            Some((sender, domain)) => {
                // One of this source IP's DNS permits (DESIGN §9). If
                // none frees up in time, refuse temporarily: the sender
                // retries; nothing is recorded.
                let Ok(_permit) = self.dns_limit.acquire(self.peer.ip()).await else {
                    log_dns_busy("mail_from");
                    return smtp::Control::tempfail(DNS_BUSY);
                };
                match spf::check_host(
                    &spf::DotResolver::shared(self.dns.clone()),
                    self.peer.ip(),
                    &sender,
                    domain.clone(),
                    &self.helo,
                )
                .await
                {
                    Ok(result) => result,
                    // Map evaluation errors to their results: transient
                    // DNS failures and an exceeded evaluation deadline are
                    // TempError (retryable), unusable records and
                    // exhausted lookup budgets are PermError.
                    Err(e) => {
                        log_spf_error("mail_from", &domain, &e);
                        e.to_result()
                    }
                }
            }
            // No SPF-checkable identity: nothing to assert.
            None => SpfResult::None,
        };

        info!(spf_result = ?result, mail_from = %addr, "mail from identity spf");

        let control = mail_from_reply(&result);
        // The transaction starts only when MAIL FROM is accepted, so a
        // rejected one can be retried.
        if control.is_accept() {
            self.txn = Some(Transaction::new(
                addr,
                declared_size,
                Some(result),
                self.max_data,
            ));
        }
        control
    }

    #[instrument(skip(self, path), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn rcpt_to(&mut self, path: &str) -> smtp::Control {
        // The envelope sender must come first (RFC 5321 Section 3.3: the
        // transaction is MAIL, then RCPT, then DATA).
        let Some(txn) = &self.txn else {
            return smtp::Control::reject(b"503 5.5.1 Error: need MAIL command\r\n");
        };
        // RFC 5321 Section 4.5.3.1.8: at least 100 recipients.
        if txn.rcpt_to.len() >= MAX_RCPT {
            return smtp::Control::tempfail(b"452 4.5.3 Too many recipients\r\n");
        }

        let Some((addr, _params)) = clean_path(path) else {
            return smtp::Control::reject(BAD_RCPT);
        };
        let addr = addr.to_string();
        let Some(domain) = path_domain(&addr).map(str::to_ascii_lowercase) else {
            return smtp::Control::reject(BAD_RCPT);
        };

        // The local-part becomes a filesystem path in maildir delivery.
        // RFC 5321 atext technically allows `/`, but the delivery sink
        // must never place client input into a path — a local-part with
        // `/` or `..` could write files anywhere the service user can.
        // Reject anything outside the mailbox-safe character set up front
        // so the client learns immediately; the sink re-validates as
        // defense in depth. This is a documented server policy, stricter
        // than the RFC's full atext set.
        if let Some(reason) = unsafe_local_part(&addr) {
            info!(rcpt = %addr, reason, "unsafe mailbox local-part refused");
            return smtp::Control::reject(BAD_RCPT);
        }

        // Relay access is closed and policy-owned by the authority: it
        // decides whether the domain is hosted, whether this address can
        // receive mail under the domain's policy mode, and where the
        // mail routes. Fail-closed: an authority that cannot be consulted
        // means a temporary refusal, never accept-then-fail.
        let cache_key = addr.to_ascii_lowercase();
        let answer = if let Some(hit) = self.rcpt_cache.get(&cache_key) {
            AuthorityAnswer::Accept(hit.clone())
        } else {
            let authority = self.authority.clone();
            let lookup = addr.clone();
            let attempt = tokio::time::timeout(
                AUTHORITY_TIMEOUT,
                tokio::task::spawn_blocking(move || authority.resolve(&lookup)),
            )
            .await;
            match attempt {
                Ok(Ok(Ok(Resolution::Accept(recipient)))) => {
                    // Successes-only cache: refusals always re-consult
                    // the authority, so every refusal is observed by it
                    // exactly once.
                    self.rcpt_cache.insert(cache_key, recipient.clone());
                    AuthorityAnswer::Accept(recipient)
                }
                Ok(Ok(Ok(Resolution::NotHosted))) => AuthorityAnswer::NotHosted,
                Ok(Ok(Ok(Resolution::Refuse { mode, reason }))) => {
                    AuthorityAnswer::Refuse { mode, reason }
                }
                Ok(Ok(Err(e))) => AuthorityAnswer::Unavailable(e.to_string()),
                Ok(Err(e)) => AuthorityAnswer::Unavailable(format!("authority task failed: {e}")),
                Err(_) => AuthorityAnswer::Unavailable("authority timed out".into()),
            }
        };

        match answer {
            AuthorityAnswer::Accept(recipient) => {
                // The recipient's size limit: its domain's own
                // `max-message-bytes`, which can only lower the server's.
                let limit = recipient
                    .max_message_bytes
                    .map_or(self.max_data, |l| l.min(self.max_data));
                // RFC 1870 §6.1: a declared SIZE over this recipient's
                // limit is refused here, before any data is sent; the
                // sender's MTA bounces (we never self-bounce).
                let Some(txn) = &self.txn else {
                    return smtp::Control::reject(b"503 5.5.1 Error: need MAIL command\r\n");
                };
                if let Some(size) = txn.declared_size.filter(|&s| s > limit as u64) {
                    self.log_size_refusal(
                        "rcpt_to",
                        Some(size),
                        limit,
                        "declared SIZE over the recipient domain's limit",
                    );
                    return smtp::Control::reject(
                        b"552 5.3.4 Message size exceeds the recipient's limit\r\n",
                    );
                }
                // One transaction carries one size limit. A recipient whose
                // limit differs from those already accepted is deferred to
                // a separate transaction (RFC 5321 §4.5.3.1.10), so one
                // tenant's lower limit can never cause mail to another
                // tenant to be refused.
                if !txn.rcpt_to.is_empty() && limit != txn.limit {
                    info!(
                        rcpt = %addr,
                        limit,
                        transaction_limit = txn.limit,
                        "recipient deferred: different message size limit"
                    );
                    return smtp::Control::tempfail(
                        b"452 4.5.3 Recipient has a different size limit; send it in a separate transaction\r\n",
                    );
                }
                if let Some(reply) = self
                    .check_mailbox_quota(&addr, &recipient.mailbox, recipient.quota_bytes)
                    .await
                {
                    return reply;
                }
                let Some(txn) = self.txn.as_mut() else {
                    return smtp::Control::reject(b"503 5.5.1 Error: need MAIL command\r\n");
                };
                txn.limit = limit;
                txn.rcpt_to.push(spool::SpoolRcpt {
                    address: addr,
                    mailbox: recipient.mailbox,
                    user: recipient.user,
                    public_key: recipient.public_key,
                    key_generation: recipient.key_generation,
                });
                smtp::Control::accept(UserSession::OK)
            }
            AuthorityAnswer::NotHosted => {
                info!(rcpt = %addr, domain = %domain, "relay access denied");
                smtp::Control::reject(b"550 5.7.1 Relay access denied\r\n")
            }
            AuthorityAnswer::Refuse { mode, reason } => {
                // Structured refusal event (the ops-side mirror of the
                // authority's event stream). One SMTP reply for every
                // reason: distinguishing "expired" from "nonexistent"
                // to the *sender* would leak which addresses once
                // existed; the reason lives here and in the authority.
                info!(
                    peer = %self.peer,
                    mail_from = ?self.txn.as_ref().map(|t| &t.mail_from),
                    rcpt = %addr,
                    domain = %domain,
                    mode = ?mode,
                    reason = ?reason,
                    "recipient refused"
                );
                smtp::Control::reject(b"550 5.1.1 No such mailbox\r\n")
            }
            AuthorityAnswer::Unavailable(message) => {
                warn!(
                    peer = %self.peer,
                    rcpt = %addr,
                    error = %message,
                    "authority unavailable; refusing temporarily"
                );
                smtp::Control::tempfail(
                    b"451 4.3.0 Recipient resolution unavailable, try again later\r\n",
                )
            }
        }
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn start_data(&mut self) -> smtp::Control {
        // RFC 5321 Section 3.3: DATA with no valid recipients is refused;
        // the session stays in Ready.
        // Without a transaction (no MAIL, or a rejected one) there are no
        // recipients either.
        match &self.txn {
            Some(txn) if !txn.rcpt_to.is_empty() => smtp::Control::accept(UserSession::SEND_DATA),
            _ => smtp::Control::reject(NO_RECIPIENTS),
        }
    }

    // TRACE, not the INFO default: this runs once per line of message
    // data, and the bunyan layer writes a START and an END record for
    // every span it sees, so an INFO span would make logs several times
    // the size of the mail itself. At TRACE the default `RUST_LOG=info`
    // skips it.
    #[instrument(level = "trace", skip(self, line), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn recv_data(&mut self, line: &[u8]) -> smtp::DataControl {
        // Enforce the transaction's size limit (the server's, or the
        // recipients' domain limit if lower) across the whole message.
        // DATA is only accepted inside a transaction (`start_data`).
        let Some(txn) = self.txn.as_mut() else {
            return smtp::DataControl::Abort(NO_RECIPIENTS.to_vec());
        };
        txn.received += line.len();
        if txn.received > txn.limit {
            let (received, limit) = (txn.received, txn.limit);
            // The state machine replies 552 once and discards the rest of
            // the transfer; the terminator then resets the transaction.
            self.log_size_refusal(
                "data",
                Some(received as u64),
                limit,
                "message data over the size limit; rest of the transfer discarded",
            );
            return smtp::DataControl::Abort(MESSAGE_TOO_BIG.to_vec());
        }
        txn.data.extend_from_slice(line);
        smtp::DataControl::Continue
    }

    async fn data_line_too_long(&mut self) -> Vec<u8> {
        // Logged like an oversized message.
        self.log_size_refusal(
            "data_line",
            self.txn.as_ref().map(|t| t.received as u64),
            Self::MAX_DATA_LINE,
            "a message line exceeded the line-length limit; rest of the transfer discarded",
        );
        Self::DATA_LINE_TOO_LONG.to_vec()
    }

    async fn shutdown_signal(&self) {
        let mut shutdown = self.shutdown.clone();
        // A sender dropped without ever signalling means no shutdown is
        // coming: never resolve.
        if shutdown.wait_for(|&down| down).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn end_data(&mut self) -> smtp::Control {
        self.end_of_data().await
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn reset(&mut self) -> smtp::Control {
        self.clear_envelope();
        smtp::Control::accept(UserSession::OK)
    }
}

/// Per-connection policy configuration, cheap to clone from the resolved
/// server config for each accepted connection.
#[derive(Clone)]
pub(crate) struct SessionConfig {
    /// This server's domain.
    pub(crate) domain: String,
    /// Server-wide message size limit.
    pub(crate) max_data: usize,
    /// AUTH configuration; `None` when AUTH is not configured.
    pub(crate) auth: Option<Arc<auth::AuthConfig>>,
    /// Recipient authority: hosted domains, policy modes, and the
    /// address-to-mailbox mapping.
    pub(crate) authority: Arc<dyn authority::RecipientResolver>,
    /// Shared DNS client used for SPF, DKIM key, and DMARC lookups.
    pub(crate) dns: Arc<dns::DnsClient>,
    /// Per-source-IP limit on concurrent DNS-backed checks.
    pub(crate) dns_limit: Arc<limit::DnsLimiter>,
    /// Overall time limit for the DNS work at end-of-data (DKIM key
    /// lookups plus the DMARC policy fetch); [`END_OF_DATA_DNS_DEADLINE`]
    /// in production.
    pub(crate) eod_dns_deadline: Duration,
    /// Becomes true when a graceful shutdown starts (sessions then end
    /// with 421 between transactions).
    pub(crate) shutdown: tokio::sync::watch::Receiver<bool>,
    /// Spool backend for accepted messages; None drops them (tests).
    pub(crate) spool: Option<Arc<dyn spool::SpoolWriter>>,
    /// Local delivery sink; None leaves messages queued (tests).
    pub(crate) sink: Option<Arc<dyn delivery::DeliverySink>>,
    /// When the connection must end (`max-conn-duration-ms` after it was
    /// accepted); None for no limit. Enforced cooperatively, between
    /// reads (see [`smtp::SmtpSession::deadline`]).
    pub(crate) deadline: Option<Instant>,
    /// Bounds the fast-path deliveries running after their replies were
    /// sent, server-wide. When none is free the fast path is skipped and
    /// the drain delivers the message.
    pub(crate) fast_path: Arc<tokio::sync::Semaphore>,
    /// The mailbox quota and free-disk floor.
    pub(crate) storage: Arc<StorageLimits>,
}

mod message;

#[cfg(test)]
mod tests;
