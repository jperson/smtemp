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

use authority::{RecipientResolver as _, Resolution};
use smtp::SmtpSession;
use spf::SpfResult;

mod auth;
mod authority;
mod delivery;
mod fsutil;
mod limit;
mod privdrop;
mod spool;

/// One DKIM verification outcome, summarized for structured logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
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

    /// Maximum simultaneous connections, server-wide.
    #[arg(long, value_name = "N")]
    max_connections: Option<u32>,

    /// Maximum simultaneous connections from a single source IP.
    #[arg(long, value_name = "N")]
    max_conn_per_ip: Option<u32>,

    /// Maximum new connections per 60-second window from a single
    /// source IP (connection churn / flood budget).
    #[arg(long, value_name = "N")]
    max_conn_rate_per_ip: Option<u32>,

    /// Maximum concurrent DNS-backed checks (SPF, DKIM, DMARC) for one
    /// source IP. Further checks wait up to 10 s, then get a temporary
    /// failure (451).
    #[arg(long, value_name = "N")]
    max_dns_per_ip: Option<usize>,

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

    /// Addresses each AUTH login may send as (MAIL FROM and every From:
    /// author), as user=grant|grant entries (comma-separated); a grant is an
    /// exact address or @domain. A login without an entry can't send.
    /// Example: --auth-senders 'alice=alice@example.org|@example.net'
    #[arg(long)]
    auth_senders: Option<String>,

    /// DNS resolver address (DNS-over-TLS on port 853) used for SPF,
    /// DKIM key, and DMARC lookups.
    #[arg(long)]
    resolver: Option<Ipv4Addr>,

    /// PEM file of extra CA certificates to trust for the resolver's
    /// DNS-over-TLS certificate, so a local resolver with a private or
    /// self-signed certificate can be used. Added to the public roots, not
    /// substituted, so public resolvers keep working. The certificate must
    /// name the --resolver address as an IP subject alternative name.
    #[arg(long, value_name = "FILE")]
    resolver_ca: Option<String>,

    /// Pipelined DNS-over-TLS connections to the resolver (1-16, default
    /// 2). Each carries up to 64 queries in flight.
    #[arg(long, value_name = "N")]
    dns_connections: Option<usize>,

    /// Queue directory where accepted messages are spooled before
    /// delivery. Spooling is part of the acceptance contract: the 250 is
    /// only sent after a durable write.
    #[arg(long, value_name = "DIR")]
    spool_dir: Option<String>,

    /// Local delivery root: one maildir per recipient address
    /// ({root}/{domain}/{local}/). Accepted messages are delivered here
    /// and retried from the spool until they succeed.
    #[arg(long, value_name = "DIR")]
    maildir_dir: Option<String>,

    /// Domains whose recipients we accept mail for (comma-separated;
    /// defaults to --domain only; superseded by --authority when given).
    /// Relay access is closed regardless of authentication.
    #[arg(long)]
    local_domains: Option<String>,

    /// Recipient authority file (JSON): the hosted-domain list, per-
    /// domain policy modes, and the address-to-mailbox mapping. The
    /// authoritative source for recipient policy; hot-reloaded on
    /// change. Supersedes --local-domains when given. See the module
    /// docs in authority.rs for the schema.
    #[arg(long, value_name = "FILE")]
    authority: Option<String>,

    /// Unprivileged user to switch to right after binding the port, when
    /// started as root (required then: running as root without it is
    /// refused). Name or numeric uid.
    #[arg(long, value_name = "USER")]
    user: Option<String>,

    /// Group to switch to with --user (name or numeric gid; default: the
    /// user's primary group).
    #[arg(long, value_name = "GROUP")]
    group: Option<String>,

    /// On SIGTERM/SIGINT, how long sessions in progress may take to
    /// finish before the process exits (milliseconds, default 60000).
    #[arg(long, value_name = "MS")]
    shutdown_grace_ms: Option<u64>,

    /// TOML configuration file; CLI flags override file values. Keys are
    /// the same as the flags in kebab-case (host, port, domain,
    /// max-data-bytes, max-conn-duration-ms, max-read-duration-ms,
    /// tls-cert, tls-key, auth-users, auth-senders, resolver, resolver-ca,
    /// dns-connections,
    /// spool-dir, maildir-dir,
    /// max-connections, max-conn-per-ip, max-conn-rate-per-ip,
    /// max-dns-per-ip, user, group, shutdown-grace-ms,
    /// local-domains, authority); every key
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
    max_connections: Option<u32>,
    max_conn_per_ip: Option<u32>,
    max_conn_rate_per_ip: Option<u32>,
    max_dns_per_ip: Option<usize>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    auth_users: Option<String>,
    auth_senders: Option<String>,
    resolver: Option<Ipv4Addr>,
    resolver_ca: Option<String>,
    dns_connections: Option<usize>,
    spool_dir: Option<String>,
    maildir_dir: Option<String>,
    local_domains: Option<String>,
    authority: Option<String>,
    user: Option<String>,
    group: Option<String>,
    shutdown_grace_ms: Option<u64>,
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
    max_connections: u32,
    max_conn_per_ip: u32,
    max_conn_rate_per_ip: u32,
    /// Concurrent DNS-backed checks per source IP (default
    /// [`limit::DEFAULT_DNS_PER_IP`]).
    max_dns_per_ip: usize,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    auth_users: Option<String>,
    /// Sender grants for AUTH logins (`auth::SenderGrants` spec).
    auth_senders: Option<String>,
    /// DNS-over-TLS resolver address; always resolved (default 1.1.1.1).
    resolver: Ipv4Addr,
    /// Extra CA certificates (PEM file) trusted for the resolver, on top
    /// of the public roots; None trusts the public roots only.
    resolver_ca: Option<String>,
    /// Pipelined DoT connections to the resolver (default
    /// [`dns::DEFAULT_CONNECTIONS`]).
    dns_connections: usize,
    /// Queue directory for accepted messages (default "spool").
    spool_dir: String,
    /// Local delivery root (default "maildir").
    maildir_dir: String,
    local_domains: Option<String>,
    /// Recipient authority file; None uses the static fallback built
    /// from local-domains (pre-authority behavior).
    authority: Option<String>,
    /// User to drop to after binding, when started as root.
    user: Option<String>,
    /// Group for `user` (default: the user's primary group).
    group: Option<String>,
    /// How long in-progress sessions may run after SIGTERM/SIGINT.
    shutdown_grace_ms: u64,
}

/// How long a single authority lookup may take before the RCPT is
/// refused with a temporary failure (fail-closed).
const AUTHORITY_TIMEOUT: Duration = Duration::from_secs(5);

/// The RCPT-time authority outcome after cache/timeout handling.
enum AuthorityAnswer {
    /// Accept: mail routes to the resolved recipient.
    Accept(authority::Recipient),
    /// The domain is not hosted here: relay access denied.
    NotHosted,
    /// The domain is hosted but the address cannot receive mail.
    Refuse {
        mode: authority::PolicyMode,
        reason: authority::RefusalReason,
    },
    /// The authority could not be consulted: fail closed with 451.
    Unavailable(String),
}

/// The default DNS-over-TLS resolver.
const DEFAULT_RESOLVER: &str = "1.1.1.1";

/// The default listening port: 25, the MX port (RFC 5321 §4.5.4.2).
/// Binding it needs root or `CAP_NET_BIND_SERVICE`; as root, `--user` is
/// required so privileges are dropped right after binding. Use
/// `--port 2525` to test as an ordinary user.
const DEFAULT_PORT: u16 = 25;

/// The default per-message size limit: 10 MiB, in line with Postfix's
/// 10,240,000-byte `message_size_limit` default. Large enough for typical
/// attachments after base64 inflation; raise it (and size memory, see
/// DEPLOYMENT.md D5) for more. Hosted domains can set a lower limit of
/// their own (`max-message-bytes` in the authority file).
const DEFAULT_MAX_DATA_BYTES: usize = 10 * 1024 * 1024;

/// The default whole-connection time limit: 5 minutes. RFC 5321
/// §4.5.3.2 recommends a 3-minute timeout per DATA block and 10 minutes
/// for end-of-data, but this cap covers a whole session (TLS, envelope,
/// DATA, the checks) and is the backstop against clients that keep a slot
/// with slow, valid traffic. 5 minutes fits a 10 MiB message (about 84
/// Mbit) over a link of about 350 kbit/s or faster, after the DNS checks
/// (at most about 20 s each for HELO SPF, MAIL SPF and end-of-data);
/// per-read idleness is limited separately by `max-read-duration-ms`.
const DEFAULT_MAX_CONN_DURATION_MS: u64 = 5 * 60 * 1000;

/// The default server-wide connection limit: 100, the same as Postfix's
/// `default_process_limit`. Each session can buffer up to about twice
/// `max-data-bytes` during DATA (DEPLOYMENT.md D5), so 100 × 2 × 10 MiB
/// bounds message buffers at about 2 GiB in the worst case; real
/// concurrency in DATA is far lower. Over the limit, connections get
/// `421` and retry.
const DEFAULT_MAX_CONNECTIONS: u32 = 100;

/// The default shutdown grace period: 60 s. After SIGTERM/SIGINT, idle
/// sessions get `421` at once and sessions mid-message finish theirs;
/// whatever is still running after this long is closed. Below systemd's
/// default `TimeoutStopSec` (90 s), so mailserv exits on its own terms.
const DEFAULT_SHUTDOWN_GRACE_MS: u64 = 60 * 1000;

/// The default spool directory. Absolute, so it never depends on the
/// working directory (systemd's default is `/`).
const DEFAULT_SPOOL_DIR: &str = "/var/lib/mailserv/spool";

/// The default maildir root. Absolute for the same reason.
const DEFAULT_MAILDIR_DIR: &str = "/var/lib/mailserv/maildir";

/// Merge CLI arguments over config-file values over built-in defaults.
fn resolve_config(cli: Args, file: FileConfig) -> Result<Config> {
    let cli_or_file_user_set = cli.user.is_some() || file.user.is_some();
    Ok(Config {
        host: cli
            .host
            .or(file.host)
            .unwrap_or_else(|| "0.0.0.0".to_string()),
        port: cli.port.or(file.port).unwrap_or(DEFAULT_PORT),
        domain: cli
            .domain
            .or(file.domain)
            .ok_or_else(|| anyhow::anyhow!("a domain is required (--domain or the config file)"))?,
        max_data_bytes: cli
            .max_data_bytes
            .or(file.max_data_bytes)
            .unwrap_or(DEFAULT_MAX_DATA_BYTES),
        max_conn_duration_ms: cli
            .max_conn_duration_ms
            .or(file.max_conn_duration_ms)
            .unwrap_or(DEFAULT_MAX_CONN_DURATION_MS),
        max_read_duration_ms: cli
            .max_read_duration_ms
            .or(file.max_read_duration_ms)
            .unwrap_or(15 * 1000),
        max_connections: cli
            .max_connections
            .or(file.max_connections)
            .unwrap_or(DEFAULT_MAX_CONNECTIONS),
        max_conn_per_ip: cli.max_conn_per_ip.or(file.max_conn_per_ip).unwrap_or(10),
        max_conn_rate_per_ip: cli
            .max_conn_rate_per_ip
            .or(file.max_conn_rate_per_ip)
            .unwrap_or(60),
        max_dns_per_ip: match cli.max_dns_per_ip.or(file.max_dns_per_ip) {
            None => limit::DEFAULT_DNS_PER_IP,
            Some(0) => anyhow::bail!("max-dns-per-ip must be at least 1"),
            Some(n) => n,
        },
        tls_cert: cli.tls_cert.or(file.tls_cert),
        tls_key: cli.tls_key.or(file.tls_key),
        auth_users: cli.auth_users.or(file.auth_users),
        auth_senders: cli.auth_senders.or(file.auth_senders),
        resolver: cli.resolver.or(file.resolver).unwrap_or_else(|| {
            DEFAULT_RESOLVER
                .parse()
                .expect("DEFAULT_RESOLVER is a valid IPv4 address")
        }),
        resolver_ca: cli.resolver_ca.or(file.resolver_ca),
        dns_connections: match cli.dns_connections.or(file.dns_connections) {
            None => dns::DEFAULT_CONNECTIONS,
            Some(n) if (1..=dns::MAX_CONNECTIONS).contains(&n) => n,
            Some(n) => anyhow::bail!(
                "dns-connections must be between 1 and {}, got {n}",
                dns::MAX_CONNECTIONS
            ),
        },
        spool_dir: cli
            .spool_dir
            .or(file.spool_dir)
            .unwrap_or_else(|| DEFAULT_SPOOL_DIR.to_string()),
        maildir_dir: cli
            .maildir_dir
            .or(file.maildir_dir)
            .unwrap_or_else(|| DEFAULT_MAILDIR_DIR.to_string()),
        local_domains: cli.local_domains.or(file.local_domains),
        authority: cli.authority.or(file.authority),
        user: cli.user.or(file.user),
        group: match (cli.group.or(file.group), cli_or_file_user_set) {
            (Some(_), false) => anyhow::bail!("--group requires --user"),
            (group, _) => group,
        },
        shutdown_grace_ms: cli
            .shutdown_grace_ms
            .or(file.shutdown_grace_ms)
            .unwrap_or(DEFAULT_SHUTDOWN_GRACE_MS),
    })
}

/// RFC 7208 Section 8: the sender is not authorized to use the domain.
const SPF_FAILED: &[u8] = b"550 5.7.23 SPF validation failed\r\n";
/// RFC 7208 Section 8: transient failure while evaluating SPF; the client
/// may retry.
const SPF_TEMPFAIL: &[u8] = b"451 4.4.3 Temporary SPF failure\r\n";
/// RFC 7208 Section 8: the domain's SPF record is unusable.
const SPF_PERMERROR: &[u8] = b"550 5.7.7 SPF policy error\r\n";
/// RFC 5321 §4.1.1.1: the HELO/EHLO argument is not a domain or address
/// literal (M8: it would be copied into `Received:`).
const BAD_HELO: &[u8] = b"501 5.5.2 Invalid HELO/EHLO domain\r\n";
/// An authenticated user's MAIL FROM is not one their login may use
/// (`--auth-senders`; RFC 3463 5.7.1, delivery not authorized).
const SENDER_NOT_OWNED: &[u8] = b"553 5.7.1 Sender address not owned by authenticated user\r\n";
/// An authenticated user's message has a `From:` author their login may
/// not use (RFC 3463 5.7.1).
const FROM_NOT_OWNED: &[u8] = b"550 5.7.1 From address not owned by authenticated user\r\n";
/// Malformed address in a MAIL FROM path.
const BAD_ADDRESS: &[u8] = b"501 5.1.7 Bad sender address syntax\r\n";
/// Malformed or unacceptable address in a RCPT TO path (RFC 3463: 5.1.3
/// bad destination mailbox address syntax).
const BAD_RCPT: &[u8] = b"553 5.1.3 Bad recipient address syntax\r\n";
/// The source IP's share of DNS-backed checks stayed exhausted for the
/// whole wait ([`limit::DNS_LIMIT_WAIT`]); retryable.
const DNS_BUSY: &[u8] =
    b"451 4.7.0 Too many concurrent DNS checks from your address, try again later\r\n";
/// The end-of-data DNS work (DKIM key lookups plus the DMARC policy
/// fetch) didn't finish within [`END_OF_DATA_DNS_DEADLINE`]; retryable.
/// The header block has a bare CR (F3, SECURITY-AUDIT.md; RFC 5322 §2.2).
const BARE_CR_IN_HEADER: &[u8] = b"550 5.6.0 Message header contains a bare CR\r\n";
/// The DMARC policy lookup failed (SERVFAIL, query timeout): deferred,
/// never treated as "no policy" (F1, SECURITY-AUDIT.md).
const DMARC_TEMPFAIL: &[u8] =
    b"451 4.4.3 Temporary failure looking up the sender's DMARC policy, try again later\r\n";
const EOD_DNS_TIMEOUT: &[u8] =
    b"451 4.4.3 Message checks timed out waiting for DNS, try again later\r\n";
/// The overall time limit for end-of-data DNS work: every DKIM key lookup
/// and the DMARC policy fetch together (D3, DEPLOYMENT.md). Without it,
/// up to 5 signatures (`dkim::MAX_SIGNATURES`) each waiting the 5 s
/// per-query timeout, plus the DMARC fetch, could run past the connection
/// cap, dropping the session with no reply. The same 20 s as
/// `spf::EVALUATION_DEADLINE`; running out is a temporary failure, never a
/// permanent rejection (skipping the checks would fail DMARC and reject
/// legitimate mail).
const END_OF_DATA_DNS_DEADLINE: Duration = Duration::from_secs(20);
/// RFC 5321 Section 4.5.3.1.8: at least 100 recipients.
const MAX_RCPT: usize = 100;
/// RFC 5321 Section 3.3: DATA with no accepted recipients.
const NO_RECIPIENTS: &[u8] = b"503 5.5.1 No valid recipients\r\n";
/// RFC 5321 Section 4.2.3.4 / 6.2: the message exceeds the advertised size
/// limit; the rest of the transfer is discarded.
const MESSAGE_TOO_BIG: &[u8] = b"552 5.3.4 Message size exceeds fixed maximum message size\r\n";

/// Split a MAIL FROM / RCPT TO argument into the address inside the path
/// and the trailing ESMTP parameters (RFC 5321 Section 4.1.2:
/// `Path [SP Mail-parameters]`). The path is the text between `<` and the
/// first `>`; a bare unbracketed address (accepted for leniency) ends at
/// the first whitespace. An empty address is the null sender
/// (`MAIL FROM:<>`).
///
/// Returns `None` for an unterminated `<` or an address containing
/// control characters (a bare CR would otherwise reach the generated
/// `Return-Path:`/`Received:` headers).
fn clean_path(raw: &str) -> Option<(&str, &str)> {
    let raw = raw.trim();
    let (addr, params) = match raw.strip_prefix('<') {
        Some(rest) => {
            let close = rest.find('>')?;
            (rest[..close].trim(), rest[close + 1..].trim())
        }
        None => match raw.find(char::is_whitespace) {
            Some(i) => (&raw[..i], raw[i..].trim()),
            None => (raw, ""),
        },
    };
    if addr.bytes().any(|b| b.is_ascii_control()) {
        return None;
    }
    Some((addr, params))
}

/// The value of the `SIZE=` ESMTP parameter (RFC 1870), if present and
/// numeric.
fn size_param(params: &str) -> Option<u64> {
    params.split_ascii_whitespace().find_map(|p| {
        let (key, value) = p.split_once('=')?;
        key.eq_ignore_ascii_case("SIZE")
            .then(|| value.parse().ok())
            .flatten()
    })
}

/// The domain of an address path: after the last '@'.
fn path_domain(addr: &str) -> Option<&str> {
    addr.rsplit_once('@').map(|(_, domain)| domain)
}

/// The local-part safety check for mailbox delivery (C1, security
/// report). The local-part names a maildir directory, so it must never
/// carry path semantics.
///
/// Returns `Some(reason)` when the address must be refused: the
/// local-part is empty, longer than RFC 5321's 64-octet limit, contains
/// anything outside the mailbox-safe set, or has path-oddities like a
/// leading dot or a `..` run. The safe set is RFC 5321 dot-atom text
/// (`atext` plus `.`) **minus `/`**, the one atext character with path
/// meaning — so ordinary addresses such as `o'brien@` keep working.
/// Quoted local-parts are refused (server policy).
fn unsafe_local_part(addr: &str) -> Option<&'static str> {
    let local = addr.rsplit_once('@')?.0;
    if local.is_empty() {
        return Some("empty local-part");
    }
    if local.len() > 64 {
        return Some("local-part exceeds 64 octets");
    }
    if local.starts_with('.') || local.contains("..") {
        return Some("dot-run in local-part");
    }
    if !local.bytes().all(is_mailbox_safe) {
        return Some("character outside the mailbox-safe set");
    }
    None
}

/// Is `h` an acceptable HELO/EHLO identity (M8, SECURITY.md)?
///
/// RFC 5321 §4.1.1.1: the argument is a `Domain` or an `address-literal`.
/// It is copied into the delivered `Received:` header, so anything else —
/// above all a bare CR or another control character, which once injected a
/// header — is refused before it is stored. The domain form is deliberately
/// a little liberal (underscores, a trailing dot, single-label names such
/// as `localhost`) because misconfigured but legitimate senders use them.
fn valid_helo(h: &str) -> bool {
    if h.is_empty() || h.len() > 255 {
        return false;
    }
    if let Some(inner) = h.strip_prefix('[') {
        // address-literal: "[" 1*dcontent "]", dcontent = %d33-90 / %d94-126
        // (covers IPv4, "IPv6:..." and general literals).
        let Some(inner) = inner.strip_suffix(']') else {
            return false;
        };
        return !inner.is_empty() && inner.bytes().all(|b| matches!(b, 33..=90 | 94..=126));
    }
    let name = h.strip_suffix('.').unwrap_or(h);
    !name.is_empty()
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// RFC 5321 `atext` plus `.`, excluding `/` (see [`unsafe_local_part`]).
fn is_mailbox_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'.' | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

/// The outcome of scanning a raw message for its `From:` header (C4:
/// this scan must be tolerant of bytes and headers the strict parser
/// rejects, because a parse failure used to skip DMARC entirely).
#[derive(Debug, Clone, PartialEq, Eq)]
enum FromHeader {
    /// Exactly one `From:` header, with its domain extracted.
    Parsed(String),
    /// No `From:` header at all.
    None,
    /// More than one `From:` header (RFC 7489 Section 6.6.1: reject).
    Multiple,
    /// A `From:` header exists but no domain could be extracted.
    Unparseable,
}

/// Extract the From-domain from the raw header bytes.
///
/// Works on bytes, not UTF-8 (real 8-bit mail exists), and never fails:
/// every outcome is one of the [`FromHeader`] variants. Only the header
/// block is scanned (up to the first empty line), the `From` header name
/// is matched case-insensitively (including the obsolete `From :` form
/// with whitespace before the colon, RFC 5322 Section 4.5.3), folded
/// continuation lines are unfolded into the value, and the value is read
/// as an RFC 5322 mailbox-list (see [`from_domain_of`]).
fn from_header_domain(raw: &[u8]) -> FromHeader {
    match single_from_value(raw) {
        Ok(value) => from_domain_of(&value),
        Err(problem) => problem,
    }
}

/// The unfolded value of the message's one `From:` header, or the
/// problem ([`FromHeader::None`] / [`FromHeader::Multiple`]). The scan
/// rules are those of [`from_header_domain`].
fn single_from_value(raw: &[u8]) -> Result<Vec<u8>, FromHeader> {
    // The header block ends at the first empty line.
    let end = header_block_end(raw);
    let header_block = &raw[..end];

    let mut from_values: Vec<Vec<u8>> = Vec::new();
    // Whether the most recent header line was a From header (so its
    // continuation lines belong to the last entry of `from_values`).
    let mut in_from = false;
    for line in split_header_lines(header_block) {
        if line.starts_with(b" ") || line.starts_with(b"\t") {
            // Folded continuation of the previous header (RFC 5322
            // Section 2.2.3: unfolding removes only the line break).
            if in_from {
                if let Some(value) = from_values.last_mut() {
                    value.push(b' ');
                    value.extend_from_slice(trim_header_fws(line));
                }
            }
            continue;
        }
        match from_header_value(line) {
            Some(value) => {
                from_values.push(trim_header_fws(value).to_vec());
                in_from = true;
            }
            None => in_from = false,
        }
    }

    match from_values.len() {
        0 => Err(FromHeader::None),
        1 => Ok(from_values.swap_remove(0)),
        _ => Err(FromHeader::Multiple),
    }
}

/// Whether the header block (up to the first empty line) contains a CR
/// that is not part of a CRLF (F3, SECURITY-AUDIT.md).
fn header_has_bare_cr(raw: &[u8]) -> bool {
    let block = &raw[..header_block_end(raw)];
    block
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'\r' && block.get(i + 1) != Some(&b'\n'))
}

/// The offset of the first empty line in the raw message (the header
/// block's end), or `raw.len()` when there is none.
fn header_block_end(raw: &[u8]) -> usize {
    let mut i = 0;
    while i < raw.len() {
        let line_end = raw[i..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(raw.len(), |p| i + p);
        let content_len = if line_end > i && raw[line_end - 1] == b'\r' {
            line_end - 1 - i
        } else {
            line_end - i
        };
        if content_len == 0 {
            return i; // empty line: headers are over
        }
        i = line_end + 1;
    }
    raw.len()
}

/// If this header line is a `From` header, its value (everything after
/// the colon). The name is matched case-insensitively and may be
/// followed by whitespace before the colon (obsolete syntax that mail
/// clients still display, so it must count as a From header).
fn from_header_value(line: &[u8]) -> Option<&[u8]> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = &line[..colon];
    let name_end = name
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(0, |p| p + 1);
    name[..name_end]
        .eq_ignore_ascii_case(b"From")
        .then(|| &line[colon + 1..])
}

/// Split a header block into lines, tolerating CRLF and bare LF (the
/// raw bytes come straight off the wire; bare LF was already ruled out
/// as a DATA terminator but tolerance here costs nothing).
fn split_header_lines(block: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut rest = block;
    while let Some(pos) = rest.iter().position(|&b| b == b'\n') {
        let (line, next) = rest.split_at(pos);
        lines.push(if line.ends_with(b"\r") {
            &line[..line.len() - 1]
        } else {
            line
        });
        rest = &next[1..];
    }
    if !rest.is_empty() {
        lines.push(rest);
    }
    lines
}

/// Trim folding whitespace (WSP/CR/LF) from both ends of a header value.
fn trim_header_fws(value: &[u8]) -> &[u8] {
    let is_fws = |b: &u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
    let start = value.iter().position(|b| !is_fws(b)).unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !is_fws(b))
        .map_or(start, |p| p + 1);
    &value[start..end]
}

/// The author domain of a From header value, read as an RFC 5322
/// mailbox-list (`mailbox *("," mailbox)`, each mailbox either
/// `addr-spec` or `[display-name] <addr-spec>`).
///
/// Comments (`(...)`, nestable) are removed and quoted strings are
/// opaque, so an `@` inside either can never pick the domain — the
/// domain is the one a mail client displays. Every mailbox in the list
/// must yield a plausible domain (`Unparseable` otherwise), and a list
/// whose mailboxes name more than one domain is `Multiple`: RFC 7489
/// Section 6.6.1 lets the receiver reject rather than pick one author.
fn from_domain_of(value: &[u8]) -> FromHeader {
    let Some(authors) = from_authors(value) else {
        return FromHeader::Unparseable;
    };
    let mut domain: Option<String> = None;
    for (_, found) in authors {
        match &domain {
            Some(d) if *d != found => return FromHeader::Multiple,
            _ => domain = Some(found),
        }
    }
    match domain {
        Some(d) => FromHeader::Parsed(d),
        None => FromHeader::Unparseable,
    }
}

/// Every author `(local-part, domain)` of a From header value, read as an
/// RFC 5322 mailbox-list with the rules of [`from_domain_of`]. `None` when
/// any mailbox is unparseable or there are none.
///
/// The local-part comes from the cleaned value: comments are removed and
/// quoted-string contents are blanked, so a quoted local-part never matches
/// a real address. For the authenticated-sender check that is fail-closed:
/// such an author is only accepted under a whole-domain grant.
fn from_authors(value: &[u8]) -> Option<Vec<(String, String)>> {
    // Pass 1: drop comments, blank out quoted-string contents.
    let mut clean: Vec<u8> = Vec::with_capacity(value.len());
    let (mut depth, mut in_quote, mut escaped) = (0usize, false, false);
    for &b in value {
        if escaped {
            escaped = false;
            if in_quote {
                clean.push(b'x');
            }
            continue;
        }
        match b {
            b'\\' if in_quote || depth > 0 => escaped = true,
            b'"' if depth == 0 => {
                in_quote = !in_quote;
                clean.push(b'"');
            }
            _ if in_quote => clean.push(b'x'),
            b'(' => depth += 1,
            b')' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    clean.push(b' ');
                }
            }
            _ if depth > 0 => {}
            _ => clean.push(b),
        }
    }
    if depth > 0 || in_quote || escaped {
        return None;
    }

    // Pass 2: split into mailboxes at top-level commas (commas inside
    // `<...>` belong to an obsolete route).
    let mut mailboxes: Vec<&[u8]> = Vec::new();
    let (mut angle, mut start) = (0usize, 0usize);
    for (i, &b) in clean.iter().enumerate() {
        match b {
            b'<' => angle += 1,
            b'>' => angle = angle.saturating_sub(1),
            b',' if angle == 0 => {
                mailboxes.push(&clean[start..i]);
                start = i + 1;
            }
            // From is a mailbox-list: group syntax is not allowed.
            b':' | b';' if angle == 0 => return None,
            _ => {}
        }
    }
    mailboxes.push(&clean[start..]);

    let mut authors = Vec::new();
    for mailbox in mailboxes {
        let mailbox = trim_header_fws(mailbox);
        if mailbox.is_empty() {
            continue; // obs-mbox-list permits empty elements
        }
        authors.push(mailbox_address(mailbox)?);
    }
    (!authors.is_empty()).then_some(authors)
}

/// The `(local-part, domain)` of one cleaned mailbox (comments removed,
/// quoted strings blanked): the addr-spec inside `<...>` when present,
/// otherwise the whole mailbox. Returns `None` unless the local-part is
/// non-empty and the domain is plausible. The domain is lowercased.
fn mailbox_address(mailbox: &[u8]) -> Option<(String, String)> {
    let addr = match mailbox.iter().position(|&b| b == b'<') {
        Some(open) => {
            let rest = &mailbox[open + 1..];
            let close = rest.iter().position(|&b| b == b'>')?;
            if !trim_header_fws(&rest[close + 1..]).is_empty() {
                return None; // trailing junk after the angle-addr
            }
            let inner = &rest[..close];
            // Obsolete route (`@a,@b:addr`): the address follows the ':'.
            match inner.iter().rposition(|&b| b == b':') {
                Some(c) => &inner[c + 1..],
                None => inner,
            }
        }
        None => mailbox,
    };
    let addr = trim_header_fws(addr);
    let at = addr.iter().rposition(|&b| b == b'@')?;
    let local = trim_header_fws(&addr[..at]);
    if local.is_empty() {
        return None; // empty local-part
    }
    let domain = trim_header_fws(&addr[at + 1..]);
    // Strip a trailing dot (fully-qualified form).
    let domain = domain.strip_suffix(b".").unwrap_or(domain);
    if domain.is_empty()
        || !domain
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some((
        String::from_utf8_lossy(local).into_owned(),
        String::from_utf8_lossy(domain).to_ascii_lowercase(),
    ))
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

/// Log why an SPF evaluation ended in an error (the error is otherwise
/// only visible as the TempError/PermError it maps to). An exceeded
/// evaluation deadline is a `warn`: it means slow or unresponsive DNS for
/// the sender's records, which operators should see.
fn log_spf_error(identity: &str, domain: &str, error: &spf::SpfError) {
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
fn log_dns_busy(stage: &str) {
    warn!(
        stage,
        wait_ms = u64::try_from(limit::DNS_LIMIT_WAIT.as_millis()).unwrap_or(u64::MAX),
        "per-IP DNS limit: no permit within the wait; temporary failure"
    );
}

/// How often the DNS client's metrics are logged.
const DNS_STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Log the DNS client's metrics once per [`DNS_STATS_INTERVAL`] while it
/// is being used, together with the per-source-IP DNS limiter's counters
/// (DESIGN §9: the signals for sizing `--dns-connections` and
/// `--max-dns-per-ip`). Counters are cumulative; the peaks cover the
/// interval just ended. Quiet intervals (no new queries) are skipped.
async fn report_dns_stats(dns: Arc<dns::DnsClient>, dns_limit: Arc<limit::DnsLimiter>) {
    let mut ticker = tokio::time::interval(DNS_STATS_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // the first tick fires immediately
    let mut last_queries = 0;
    loop {
        ticker.tick().await;
        let s = dns.stats();
        let l = dns_limit.stats();
        dns.reset_peaks();
        if s.queries == last_queries {
            continue;
        }
        last_queries = s.queries;
        let misses = s.queries - s.cache_hits;
        info!(
            queries = s.queries,
            cache_hits = s.cache_hits,
            connects = s.connects,
            connect_failures = s.connect_failures,
            exchanges_ok = s.exchanges_ok,
            exchange_errors = s.exchange_errors,
            timeouts = s.timeouts,
            late_replies = s.late_replies,
            waits = s.waits,
            wait_mean_us = s.wait_total_us.checked_div(misses).unwrap_or(0),
            wait_max_us = s.wait_max_us,
            waiting = s.waiting,
            in_flight = s.in_flight,
            peak_in_flight = s.peak_in_flight,
            connections = dns.connections(),
            max_in_flight = dns.max_in_flight(),
            ip_limit_waits = l.waits,
            ip_limit_refusals = l.refusals,
            ip_limit_active_ips = l.active_ips,
            max_dns_per_ip = dns_limit.per_ip(),
            "dns stats"
        );
    }
}

/// One DMARC verification outcome, summarized for structured logging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
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

#[derive(Serialize)]
struct UserSession<'session> {
    #[serde(skip_serializing)]
    pub max_data: usize,

    #[serde(skip_serializing)]
    pub total_data: usize,

    /// This transaction's size limit: `max_data`, lowered to the
    /// accepted recipients' domain limit (`max-message-bytes`) when their
    /// domain set one. Every recipient in one transaction shares the same
    /// limit (see `rcpt_to`).
    #[serde(skip_serializing)]
    txn_limit: usize,

    /// The size the client declared with `MAIL FROM ... SIZE=` (RFC 1870),
    /// checked against each recipient's limit at RCPT time.
    #[serde(skip_serializing)]
    declared_size: Option<u64>,

    pub session_id: Uuid,
    domain: &'session str,
    /// Shared DNS client (pipelined DoT connections + TTL cache) for SPF,
    /// DKIM key, and DMARC lookups.
    #[serde(skip_serializing)]
    dns: Arc<dns::DnsClient>,
    /// Per-source-IP limit on concurrent DNS-backed checks, shared by
    /// every session.
    #[serde(skip_serializing)]
    dns_limit: Arc<limit::DnsLimiter>,
    peer: SocketAddr,

    helo: Option<String>,
    mail_from: Option<String>,
    /// Accepted recipients with their authority-resolved routing.
    rcpt_to: Vec<spool::SpoolRcpt>,
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
    auth: Option<Arc<auth::AuthConfig>>,
    /// The authenticated identity for this connection, if any.
    authenticated: Option<String>,
    /// LOGIN continuation state.
    auth_login_user: Option<String>,
    /// The mechanism of the in-progress AUTH continuation.
    auth_pending: Option<&'static str>,
    /// The recipient authority (Phase 12 gap 1): owns the hosted-domain
    /// list, per-domain policy, and the address-to-mailbox mapping.
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
}

impl<'session> UserSession<'session> {
    fn new(peer: SocketAddr, starttls_available: bool, cfg: &'session SessionConfig) -> Self {
        UserSession {
            max_data: cfg.max_data,
            total_data: 0,
            txn_limit: cfg.max_data,
            declared_size: None,
            session_id: Uuid::new_v4(),

            domain: &cfg.domain,
            dns: cfg.dns.clone(),
            dns_limit: cfg.dns_limit.clone(),
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
            auth: cfg.auth.clone(),
            authenticated: None,
            auth_login_user: None,
            auth_pending: None,
            authority: cfg.authority.clone(),
            rcpt_cache: HashMap::new(),
            spool: cfg.spool.clone(),
            sink: cfg.sink.clone(),
            dmarc: None,
            eod_dns_deadline: cfg.eod_dns_deadline,
            shutdown: cfg.shutdown.clone(),
        }
    }

    /// Abandon the current transaction: clear the envelope and any
    /// partial message data.
    fn clear_envelope(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
        // Release the buffer, not just its contents: an aborted 10 MiB
        // transfer must not keep its allocation for the rest of the session.
        self.data = Vec::new();
        self.total_data = 0;
        self.txn_limit = self.max_data;
        self.declared_size = None;
        self.spf_result = None;
    }

    /// The domains of this transaction's accepted recipients, for logs.
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

    /// Log a message refused for its size (`stage`: mail_from, rcpt_to,
    /// data, or data_line). Envelope and sizes only, never content.
    fn log_size_refusal(&self, stage: &str, size: Option<u64>, limit: usize, detail: &str) {
        info!(
            stage,
            size,
            limit,
            server_limit = self.max_data,
            mail_from = ?self.mail_from,
            recipients = self.rcpt_to.len(),
            rcpt_domains = ?self.rcpt_domains(),
            detail,
            "message refused: size limit"
        );
    }

    /// End the transaction with a temporary failure because the
    /// end-of-data DNS work ran past [`UserSession::eod_dns_deadline`]
    /// (`stage`: dkim or dmarc). Logged at `warn`, like an SPF deadline.
    fn eod_dns_timed_out(&mut self, stage: &str) -> smtp::Control {
        warn!(
            stage,
            limit_ms = u64::try_from(self.eod_dns_deadline.as_millis()).unwrap_or(u64::MAX),
            "end-of-data DNS checks exceeded their time limit; temporary failure"
        );
        self.clear_envelope();
        self.message_count += 1;
        smtp::Control::tempfail(EOD_DNS_TIMEOUT)
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
        self.spf_helo = if h.starts_with('[') {
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
        if self.tls_active && self.auth.is_some() {
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
        let Some(users) = self.auth.clone() else {
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
                    Some((user, pass)) => self.verify_credentials(&users.credentials, &user, &pass),
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
                Some((user, pass)) => self.verify_credentials(&users.credentials, &user, &pass),
                None => smtp::Control::reject(b"501 5.5.2 Invalid PLAIN response\r\n"),
            },
            Some("LOGIN") => {
                if let Some(user) = self.auth_login_user.take() {
                    let pass = String::from_utf8_lossy(&data).into_owned();
                    self.verify_credentials(&users.credentials, &user, &pass)
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
                (Some((local, domain)), Some(auth)) => auth.senders.permits(user, local, domain),
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
            self.spf_result = None;
            info!(
                auth_user = self.authenticated.as_deref().unwrap_or("?"),
                mail_from = %addr,
                "authenticated mail from (spf skipped)"
            );
            self.mail_from = Some(addr);
            self.declared_size = declared_size;
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

        self.spf_result = Some(result.clone());
        info!(spf_result = ?result, mail_from = %addr, "mail from identity spf");

        let control = mail_from_reply(&result);
        // The envelope sender is recorded only when accepted, so a
        // rejected MAIL FROM can be retried.
        if control.is_accept() {
            self.mail_from = Some(addr);
            self.declared_size = declared_size;
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

        let Some((addr, _params)) = clean_path(path) else {
            return smtp::Control::reject(BAD_RCPT);
        };
        let addr = addr.to_string();
        let Some(domain) = path_domain(&addr).map(str::to_ascii_lowercase) else {
            return smtp::Control::reject(BAD_RCPT);
        };

        // C1 (security report): the local-part becomes a filesystem path
        // in maildir delivery. RFC 5321 atext technically allows `/`, but
        // the delivery sink must never place client input into a path —
        // a local-part with `/`, `..`, or an absolute path used to write
        // files anywhere the service user could write. Reject anything
        // outside the mailbox-safe character set up front (501) so the
        // client learns immediately; the sink re-validates as defense in
        // depth. This is a documented server policy, stricter than the
        // RFC's full atext set.
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
                if let Some(size) = self.declared_size.filter(|&s| s > limit as u64) {
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
                if !self.rcpt_to.is_empty() && limit != self.txn_limit {
                    info!(
                        rcpt = %addr,
                        limit,
                        transaction_limit = self.txn_limit,
                        "recipient deferred: different message size limit"
                    );
                    return smtp::Control::tempfail(
                        b"452 4.5.3 Recipient has a different size limit; send it in a separate transaction\r\n",
                    );
                }
                self.txn_limit = limit;
                self.rcpt_to.push(spool::SpoolRcpt {
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
                    mail_from = ?self.mail_from,
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

    // TRACE, not the INFO default (D1, DEPLOYMENT.md): this runs once per
    // line of message data, and the bunyan layer writes a START and an END
    // record for every span it sees, so an INFO span made logs ~7x the size
    // of the mail itself. At TRACE the default `RUST_LOG=info` skips it.
    #[instrument(level = "trace", skip(self, line), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn recv_data(&mut self, line: &[u8]) -> smtp::DataControl {
        // Enforce the transaction's size limit (the server's, or the
        // recipients' domain limit if lower) across the whole message.
        self.total_data += line.len();
        if self.total_data > self.txn_limit {
            // The state machine replies 552 once and discards the rest of
            // the transfer; the terminator then resets the transaction.
            self.log_size_refusal(
                "data",
                Some(self.total_data as u64),
                self.txn_limit,
                "message data over the size limit; rest of the transfer discarded",
            );
            return smtp::DataControl::Abort(MESSAGE_TOO_BIG.to_vec());
        }
        self.data.extend_from_slice(line);
        smtp::DataControl::Continue
    }

    /// A message line exceeded the protocol's line cap: the transfer is
    /// aborted like an oversized message, and logged the same way.
    async fn data_line_too_long(&mut self) -> Vec<u8> {
        self.log_size_refusal(
            "data_line",
            Some(self.total_data as u64),
            Self::MAX_DATA_LINE,
            "a message line exceeded the line-length limit; rest of the transfer discarded",
        );
        Self::DATA_LINE_TOO_LONG.to_vec()
    }

    /// Resolves when `main` starts a graceful shutdown. If the sender is
    /// gone without ever signalling, it never resolves.
    async fn shutdown_signal(&self) {
        let mut shutdown = self.shutdown.clone();
        if shutdown.wait_for(|&down| down).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    #[instrument(skip(self), fields(session = self.session_id.to_string(), peer = self.peer.to_string()))]
    async fn end_data(&mut self) -> smtp::Control {
        // The raw message as received: the accumulated DATA lines, with
        // line endings exactly as the client sent them.
        let raw = self.data.clone();

        // F3 (SECURITY-AUDIT.md): a CR not followed by LF is never valid in
        // an RFC 5322 header block, and readers disagree on it. This
        // server's scanner treats it as ordinary text, while others
        // (Python's `email`, many webmail pipelines) treat it as a line
        // break, so `Subject: x\rFrom: ceo@victim` would hide a second
        // From from the DMARC check while a mail reader shows it. Refuse
        // the message before any other work. The body is not checked.
        if header_has_bare_cr(&raw) {
            warn!("message refused: bare CR in the header block");
            self.clear_envelope();
            self.message_count += 1;
            return smtp::Control::reject(BARE_CR_IN_HEADER);
        }

        // DKIM key lookups and the DMARC policy fetch hold one of this
        // source IP's DNS permits (DESIGN §9). If none frees up in
        // time, the message is refused *temporarily*: skipping the checks
        // instead would fail DMARC and permanently reject legitimate mail.
        let Ok(dns_permit) = self.dns_limit.acquire(self.peer.ip()).await else {
            log_dns_busy("end_of_data");
            self.clear_envelope();
            self.message_count += 1;
            return smtp::Control::tempfail(DNS_BUSY);
        };
        // One deadline covers all of this message's DNS work: the DKIM key
        // lookups here and the DMARC policy fetch below (D3).
        let dns_deadline = Instant::now() + self.eod_dns_deadline;
        let results = match timeout_at(dns_deadline, dkim::verify_dkim(&raw, &self.dns)).await {
            Ok(results) => results,
            Err(_) => return self.eod_dns_timed_out("dkim"),
        };
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
        // submissions (our own MSA users) are exempt from rejection: an MSA
        // that rejected its own users' mail on DMARC would reject legitimate
        // submissions from networks no SPF record covers. The exemption is
        // conditional by construction: an authenticated message only gets
        // here once its MAIL FROM and every From author passed the login's
        // `--auth-senders` grants (above and in `mail_from`).
        //
        // C4 (security report): the From domain is extracted from the raw
        // header bytes, never from the typed parser — a duplicate `From:`,
        // an 8-bit byte in any header, or a grammar failure used to make
        // the whole parse fail, which skipped DMARC and accepted the
        // message. RFC 7489 Section 6.6.1: a message with no `From:` or
        // with multiple `From:` headers is rejected, never let through.
        let from_domain = match from_header_domain(&raw) {
            FromHeader::Parsed(domain) => Some(domain),
            problem => {
                warn!(
                    problem = ?problem,
                    "message has no unambiguous From header; rejecting (RFC 7489 Section 6.6.1)"
                );
                self.clear_envelope();
                self.message_count += 1;
                return smtp::Control::reject(
                    b"550 5.7.1 Message rejected: missing or malformed From header\r\n",
                );
            }
        };

        // An authenticated session is exempt from DMARC rejection below,
        // which is only safe because every From author must be an address
        // the login owns (`--auth-senders`). Checked on the same tolerant
        // raw scan DMARC uses, so the author checked is the one a mail
        // client displays.
        if let Some(user) = self.authenticated.as_deref() {
            let authors = single_from_value(&raw)
                .ok()
                .and_then(|value| from_authors(&value));
            let permitted = match (&authors, self.auth.as_deref()) {
                (Some(authors), Some(auth)) => authors
                    .iter()
                    .all(|(local, domain)| auth.senders.permits(user, local, domain)),
                _ => false,
            };
            if !permitted {
                warn!(
                    auth_user = %user,
                    from_authors = ?authors,
                    "authenticated message refused: From author not granted to this user"
                );
                self.clear_envelope();
                self.message_count += 1;
                return smtp::Control::reject(FROM_NOT_OWNED);
            }
        }
        let mut dmarc_summary: Option<DmarcSummary> = None;

        if let Some(from_domain) = from_domain {
            let resolver = spf::DotResolver::shared(self.dns.clone());
            let found = match timeout_at(dns_deadline, dmarc::fetch_policy(&resolver, &from_domain))
                .await
            {
                Err(_) => return self.eod_dns_timed_out("dmarc"),
                Ok(Ok(found)) => found,
                // RFC 7489 §6.6.3: several records at one name means DMARC
                // is not applied. The domain owner's misconfiguration, so
                // loud, but not a reason to defer.
                Ok(Err(dmarc::DmarcError::MultipleRecords)) => {
                    warn!(from_domain = %from_domain, "multiple DMARC records; DMARC not applied");
                    None
                }
                // F1 (SECURITY-AUDIT.md): a failed lookup (SERVFAIL, query
                // timeout) used to count as "no policy", so a spoof of a
                // p=reject domain was delivered whenever its policy couldn't
                // be fetched — which an attacker can provoke by loading the
                // shared resolver. Fail closed: defer, the sender retries.
                Ok(Err(e)) => {
                    warn!(
                        from_domain = %from_domain,
                        error = %e,
                        "dmarc policy lookup failed; temporary failure"
                    );
                    self.clear_envelope();
                    self.message_count += 1;
                    return smtp::Control::tempfail(DMARC_TEMPFAIL);
                }
            };

            if let Some(found) = found {
                let record = &found.record;
                let spf_passed = matches!(self.spf_result, Some(SpfResult::Pass));
                let spf_domain = self.mail_from.as_deref().and_then(path_domain);
                // C3 (security report): DMARC consumes ONLY this
                // message's DKIM results. `self.dkim` accumulates across
                // the connection for the session log; reusing it here let
                // a replayed genuine signature from an earlier message
                // make a later unsigned spoof pass DMARC.
                let dkim: Vec<(String, bool)> = dkim_summaries
                    .iter()
                    .map(|d| (d.domain.clone(), d.verified))
                    .collect();

                let evaluation = dmarc::evaluate(
                    record,
                    spf_domain.map(|d| (d, spf_passed)),
                    &dkim,
                    &from_domain,
                );
                // `sp=` governs a subdomain whose record was inherited
                // from an ancestor (RFC 7489 §6.3; M4).
                let policy = found.policy_for(&from_domain);
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
        // DNS work for this message is done; the spool write and delivery
        // below must not hold the source IP's DNS share.
        drop(dns_permit);

        // Spool before accepting: the 250 is only sent after a durable
        // write (Phase 7). The backend is blocking (fsync, and object
        // storage later), so it runs on the blocking pool. A failed
        // spool is a temporary failure — the client is invited to
        // retry, nothing is lost.
        if let Some(spool) = self.spool.clone() {
            let mut meta = spool::SpoolMeta {
                queue_id: String::new(), // assigned by the backend
                session_id: self.session_id.to_string(),
                server_domain: self.domain.to_string(),
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
                encryption: None, // set by the backend's encryptor, if any
            };
            // The backend runs on the blocking pool and takes owned
            // data; the session keeps its copies for the delivery fast
            // path below.
            let write_meta = meta.clone();
            let write_raw = raw.clone();
            let write_spool = spool.clone();
            let write =
                tokio::task::spawn_blocking(move || write_spool.write(write_meta, &write_raw));
            match write.await {
                Ok(Ok(queue_id)) => {
                    info!(queue_id = %queue_id, recipients = self.rcpt_to.len(), "message spooled");
                    meta.queue_id = queue_id;
                }
                Ok(Err(e)) => {
                    error!(error = %e, "spool write failed; refusing with a temporary error");
                    self.clear_envelope();
                    self.message_count += 1;
                    return smtp::Control::tempfail(
                        b"451 4.3.0 Error: queueing failed, try again later\r\n",
                    );
                }
                Err(e) => {
                    error!(error = %e, "spool task panicked; refusing with a temporary error");
                    self.clear_envelope();
                    self.message_count += 1;
                    return smtp::Control::tempfail(
                        b"451 4.3.0 Error: queueing failed, try again later\r\n",
                    );
                }
            }

            // Delivery fast path: attempt each recipient copy immediately
            // for low latency. Failures are not fatal — the message is
            // durably queued and the drain loop retries (delivery is
            // idempotent per (recipient, queue_id), so overlapping
            // attempts never duplicate mail). If every recipient copy is
            // delivered, dequeue immediately instead of waiting for the
            // next drain pass.
            if let Some(sink) = self.sink.clone() {
                let mut delivered_count = 0usize;
                for rcpt in self.rcpt_to.clone() {
                    // Trace headers name the envelope address; the copy
                    // goes to the authority-resolved routing mailbox.
                    let message = delivery::prepare_for_delivery(&meta, &rcpt.address, &raw);
                    let logged_address = rcpt.address.clone();
                    let logged_mailbox = rcpt.mailbox.clone();
                    let attempt = tokio::task::spawn_blocking({
                        let sink = sink.clone();
                        let queue_id = meta.queue_id.clone();
                        move || sink.deliver(&rcpt.mailbox, &queue_id, &message)
                    })
                    .await;
                    match attempt {
                        Ok(Ok(())) => {
                            delivered_count += 1;
                            info!(queue_id = %meta.queue_id, recipient = %logged_address, mailbox = %logged_mailbox, "message delivered");
                        }
                        Ok(Err(e)) => {
                            warn!(queue_id = %meta.queue_id, recipient = %logged_address, error = %e, "fast-path delivery failed; queued for retry");
                        }
                        Err(e) => {
                            warn!(queue_id = %meta.queue_id, recipient = %logged_address, error = %e, "delivery task panicked; queued for retry");
                        }
                    }
                }
                if delivered_count == self.rcpt_to.len() {
                    let _ = tokio::task::spawn_blocking({
                        let spool = spool.clone();
                        let queue_id = meta.queue_id.clone();
                        move || spool.remove(&queue_id)
                    })
                    .await;
                    info!(queue_id = %meta.queue_id, "all recipients delivered; dequeued");
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

    // Anything created without an explicit mode is private to the service
    // user (D4). The spool and maildirs also set 0600/0700 explicitly.
    privdrop::restrict_umask();

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

    // One shared DNS client for the whole process (Phase 10): pipelined
    // DNS-over-TLS connections and a TTL result cache serve SPF, DKIM, and
    // DMARC alike. Built before the listener binds, so a bad --resolver-ca
    // file stops startup instead of surfacing as DNS failures in sessions.
    // The CA (D2, DEPLOYMENT.md) is added to the public roots, so public
    // resolvers keep working with it set.
    let dns_client = dns::DnsClient::new(config.resolver).with_connections(config.dns_connections);
    let dns_client = Arc::new(match &config.resolver_ca {
        Some(path) => {
            let roots = load_resolver_ca(path).await?;
            info!(
                resolver_ca = %path,
                certificates = roots.len(),
                "resolver CA loaded (trusted in addition to the public roots)"
            );
            dns_client
                .with_extra_roots(&roots)
                .map_err(|e| anyhow::anyhow!("invalid resolver CA file {path}: {e:#}"))?
        }
        None => dns_client,
    });

    let auth = match &config.auth_users {
        Some(spec) if !spec.is_empty() => {
            let auth = auth::AuthConfig::parse(spec, config.auth_senders.as_deref())?;
            info!(
                "AUTH PLAIN/LOGIN available ({} user(s))",
                auth.credentials.len()
            );
            let unable = auth.users_without_grants();
            if !unable.is_empty() {
                warn!(
                    users = ?unable,
                    "AUTH users without --auth-senders grants can authenticate but not send"
                );
            }
            Some(Arc::new(auth))
        }
        _ => {
            if config
                .auth_senders
                .as_deref()
                .is_some_and(|s| !s.is_empty())
            {
                anyhow::bail!("--auth-senders needs --auth-users");
            }
            None
        }
    };

    let mut local_domains: HashSet<String> = match &config.local_domains {
        Some(spec) if !spec.is_empty() => spec
            .split(',')
            .map(|d| d.trim().to_ascii_lowercase())
            .collect(),
        _ => HashSet::new(),
    };
    local_domains.insert(config.domain.to_ascii_lowercase());

    // Privileges (D4). Decide before binding, so a misconfiguration (root
    // without --user, an unknown user) stops startup without touching the
    // port.
    let target = match &config.user {
        Some(user) => Some(privdrop::lookup(user, config.group.as_deref())?),
        None => None,
    };
    let drop_to = privdrop::plan(privdrop::effective_uid(), target)?;

    // Bind while still privileged: port 25 needs root or
    // CAP_NET_BIND_SERVICE. The TLS key, resolver CA and config file were
    // read above, also with the starting privileges.
    let listener = TcpListener::bind(format!("{}:{}", config.host, config.port))
        .await
        .map_err(|e| anyhow::anyhow!("cannot listen on {}:{}: {e}", config.host, config.port))?;

    if let Some(id) = &drop_to {
        // The service user must own the storage it writes: root creates
        // any missing spool/maildir directories owned by it, then drops.
        for dir in [&config.spool_dir, &config.maildir_dir] {
            fsutil::create_owned_dir_all(std::path::Path::new(dir), id.uid, id.gid)
                .map_err(|e| anyhow::anyhow!("cannot create {dir} for user {}: {e}", id.user))?;
        }
        privdrop::drop_to(id)
            .map_err(|e| anyhow::anyhow!("could not drop root privileges: {e:#}"))?;
        info!(
            user = %id.user,
            uid = id.uid,
            gid = id.gid,
            "privileges dropped after binding the port"
        );
    }
    // Everything from here on (authority, spool, maildirs, every
    // connection) runs without root.

    // The recipient authority (Phase 12 gap 1): a JSON file when
    // configured — the console's publishing format, hot-reloaded —
    // otherwise the static fallback that preserves the pre-authority
    // behavior for --local-domains (every local-part accepts).
    if config.authority.is_some() && config.local_domains.is_some() {
        warn!("--local-domains is ignored: the authority file owns the hosted-domain list");
    }
    let authority: Arc<dyn authority::RecipientResolver> = match &config.authority {
        Some(path) => {
            let a = authority::FileAuthority::open(path)?;
            info!(backend = a.name(), file = %path, "recipient authority ready");
            Arc::new(a)
        }
        None => {
            let a =
                authority::StaticAuthority::new(local_domains.iter().cloned().collect::<Vec<_>>());
            info!(
                backend = a.name(),
                domains = local_domains.len(),
                "no authority file; static per-address fallback (any local-part accepts)"
            );
            Arc::new(a)
        }
    };

    // V1: local disk spool, no payload encryption. Real providers
    // (user-held keys via the console) land with Phase 12; the backend
    // trait is already in place.
    let disk_spool = Arc::new(spool::DiskSpool::open(&config.spool_dir, None)?);
    let spool: Arc<dyn spool::SpoolWriter> = disk_spool.clone();
    info!(backend = spool.name(), spool_dir = %config.spool_dir, "spool ready");

    let sink: Arc<dyn delivery::DeliverySink> =
        Arc::new(delivery::MaildirSink::open(&config.maildir_dir)?);
    info!(backend = sink.name(), maildir_dir = %config.maildir_dir, "delivery ready");

    // Storage paths (D4): say where mail really goes, and flag setups that
    // would surprise an operator.
    for (what, dir) in [
        ("spool", &config.spool_dir),
        ("maildir", &config.maildir_dir),
    ] {
        let resolved = std::path::absolute(dir).unwrap_or_else(|_| dir.into());
        if std::path::Path::new(dir).is_relative() {
            warn!(
                what,
                configured = %dir,
                resolved = %resolved.display(),
                "storage path is relative to the working directory; configure an absolute path"
            );
        }
        if let Some(bits) = fsutil::shared_bits(&resolved) {
            warn!(
                what,
                path = %resolved.display(),
                open_bits = %format!("{bits:03o}"),
                "storage directory is accessible to other users; consider chmod 700"
            );
        }
    }

    // The drain is the retry engine: it delivers whatever the fast path
    // could not (crashes, sink failures), removes fully delivered
    // messages, retries failures with backoff, and dead-letters messages
    // still failing after the queue lifetime (F7). The
    // first pass runs immediately at startup (recovering anything queued
    // before a restart); later passes run on a fixed interval. Per-message
    // failures inside a pass are logged and counted, never fatal.
    {
        let spool = disk_spool.clone();
        let sink = sink.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let pass = tokio::task::spawn_blocking({
                    let spool = spool.clone();
                    let sink = sink.clone();
                    move || delivery::drain_once(&spool, &*sink)
                })
                .await;
                match pass {
                    // Logged whenever the queue is not empty, so a backlog
                    // (a delivery outage) is visible every pass and can be
                    // alerted on (`queued` > 0 for a sustained period).
                    Ok(Ok(stats))
                        if stats.delivered
                            + stats.retrying
                            + stats.dead_lettered
                            + stats.deferred
                            > 0 =>
                    {
                        info!(
                            delivered = stats.delivered,
                            retrying = stats.retrying,
                            deferred = stats.deferred,
                            dead_lettered = stats.dead_lettered,
                            queued = stats.retrying + stats.deferred,
                            "drain pass"
                        );
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => warn!(error = %e, "drain pass failed"),
                    Err(e) => warn!(error = %e, "drain task panicked"),
                }
            }
        });
    }

    info!(
        resolver = %config.resolver,
        resolver_ca = config.resolver_ca.as_deref().unwrap_or("(public roots only)"),
        connections = dns_client.connections(),
        max_in_flight = dns_client.max_in_flight(),
        spf_deadline_ms = u64::try_from(spf::EVALUATION_DEADLINE.as_millis()).unwrap_or(u64::MAX),
        max_dns_per_ip = config.max_dns_per_ip,
        "DNS-over-TLS client ready (pipelined connections, TTL cache)"
    );
    // Per-source-IP share of DNS work (DESIGN §9, H6): one client must
    // not fill the shared resolver capacity with its own slow lookups.
    let dns_limit = Arc::new(limit::DnsLimiter::new(
        config.max_dns_per_ip,
        limit::DNS_LIMIT_WAIT,
    ));
    tokio::spawn(report_dns_stats(dns_client.clone(), dns_limit.clone()));

    // Connection caps (Phase 10): a server-wide semaphore plus per-IP
    // concurrency and connection-rate budgets, enforced in the accept
    // loop before any session work.
    let limiter = Arc::new(limit::ConnectionLimiter::new(
        config.max_conn_per_ip,
        config.max_conn_rate_per_ip,
        Duration::from_secs(60),
    ));
    let global_capacity = Arc::new(tokio::sync::Semaphore::new(config.max_connections as usize));
    // H5 (security report): refusals must never run inline in the accept
    // loop — each one used to stall every subsequent accept for up to
    // ~2.5 s (the courtesy write + drain), so an attacker holding the
    // connection budgets could starve all legitimate senders almost for
    // free. Refusals run in spawned tasks, capped by this small permit
    // pool; when it is exhausted the socket is simply closed.
    let refuse_capacity = Arc::new(tokio::sync::Semaphore::new(32));

    info!(
        host = %config.host,
        port = config.port,
        domain = %config.domain,
        resolver = %config.resolver,
        spool_dir = %config.spool_dir,
        max_connections = config.max_connections,
        max_conn_per_ip = config.max_conn_per_ip,
        max_conn_rate_per_ip = config.max_conn_rate_per_ip,
        "listening"
    );

    // Graceful shutdown (D4): SIGTERM or SIGINT stops the accept loop;
    // sessions are told through `shutdown_rx` (see `shutdown_signal`).
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut signals = ShutdownSignals::new()?;

    let signal = loop {
        // A transient accept error (e.g. EMFILE under load) must not
        // terminate the server; back off briefly and keep going.
        let accepted = tokio::select! {
            biased;
            signal = signals.recv() => break signal,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                error!(error = %e, "accept failed; backing off");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let peer = canonical_peer(peer);

        let ip = peer.ip();

        // Server-wide concurrency cap: over-capacity connections get a
        // 421 and are closed without entering a session.
        let permit = match global_capacity.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(peer = %peer, "connection refused: server at capacity");
                refuse_async(
                    stream,
                    b"421 4.7.0 Service not available, try again later\r\n",
                    &refuse_capacity,
                )
                .await;
                continue;
            }
        };

        // Per-IP concurrency and connection-rate budgets.
        if let Err(reason) = limiter.admit(ip).await {
            warn!(peer = %peer, "connection refused: per-IP limit reached");
            refuse_async(stream, reason.reply(), &refuse_capacity).await;
            drop(permit);
            continue;
        }

        let acceptor = acceptor.clone();
        let max_read_ms = config.max_read_duration_ms;
        let limiter = limiter.clone();
        let session_cfg = SessionConfig {
            domain: config.domain.clone(),
            max_data: config.max_data_bytes,
            auth: auth.clone(),
            authority: authority.clone(),
            dns: dns_client.clone(),
            dns_limit: dns_limit.clone(),
            eod_dns_deadline: END_OF_DATA_DNS_DEADLINE,
            shutdown: shutdown_rx.clone(),
            spool: Some(spool.clone()),
            sink: Some(sink.clone()),
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

            // Free the connection's capacity, whoever ended it.
            drop(permit);
            limiter.release(ip).await;
        });
    };

    // Graceful shutdown (D4). Stop accepting: closing the listener makes
    // the kernel refuse new connections, and other MXs or a later retry
    // take the mail. Then tell every session: idle ones get 421 now, and
    // sessions mid-message finish it, get their reply, then the 421.
    drop(listener);
    let _ = shutdown_tx.send(true);
    let max = config.max_connections;
    let active = |capacity: &tokio::sync::Semaphore| max as usize - capacity.available_permits();
    info!(
        signal,
        active_sessions = active(&global_capacity),
        grace_ms = config.shutdown_grace_ms,
        "shutdown: stopped accepting; waiting for sessions to finish"
    );
    // Every session holds one permit of the global capacity, so having
    // them all back means every session has ended. A second signal skips
    // the wait.
    let grace = Duration::from_millis(config.shutdown_grace_ms);
    tokio::select! {
        finished = tokio::time::timeout(grace, global_capacity.acquire_many(max)) => match finished {
            Ok(_) => info!("shutdown complete: all sessions finished"),
            Err(_) => warn!(
                remaining_sessions = active(&global_capacity),
                "shutdown grace period over; closing the remaining sessions"
            ),
        },
        second = signals.recv() => warn!(
            signal = second,
            remaining_sessions = active(&global_capacity),
            "second signal during shutdown; exiting now"
        ),
    }
    // Returning drops the runtime, which still waits for blocking work
    // already running (an fsync in a spool write or a delivery), so files
    // are never left half-written.
    Ok(())
}

/// SIGTERM and SIGINT: the requests for a graceful shutdown. Registered
/// once, so a signal that arrives while the server is busy is not lost.
struct ShutdownSignals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
}

impl ShutdownSignals {
    /// Install the handlers. Returns `Err` if the OS refuses.
    fn new() -> Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(ShutdownSignals {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
        })
    }

    /// Wait for the next SIGTERM or SIGINT; returns its name.
    async fn recv(&mut self) -> &'static str {
        tokio::select! {
            _ = self.term.recv() => "SIGTERM",
            _ = self.int.recv() => "SIGINT",
        }
    }
}

/// Hand a refused connection to a spawned task (H5, security report):
/// returns immediately, so a burst of refusals never stalls the accept
/// loop. Bounded by the refusal permit pool; when it is saturated the
/// socket is closed without the courtesy reply.
async fn refuse_async(stream: TcpStream, reply: &[u8], capacity: &Arc<tokio::sync::Semaphore>) {
    match Arc::clone(capacity).try_acquire_owned() {
        Ok(permit) => {
            let reply = reply.to_vec();
            tokio::spawn(async move {
                refuse(stream, &reply).await;
                drop(permit);
            });
        }
        // Refusal capacity is saturated (an active flood): the fastest
        // possible close is the only remaining courtesy.
        Err(_) => drop(stream),
    }
}

/// Answer a refused connection with an SMTP error and close it. The
/// write is capped so a client that never reads cannot stall; afterwards
/// the socket is drained briefly so the client can read the reply before
/// close — dropping a socket with unread inbound data makes Linux send
/// RST, which discards the client's pending receive buffer (it would
/// never see the 421). Failures are ignored — the connection is being
/// dropped anyway. Runs only in spawned tasks (see [`refuse_async`]).
async fn refuse(stream: TcpStream, reply: &[u8]) {
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = stream;
        if tokio::io::AsyncWriteExt::write_all(&mut stream, reply)
            .await
            .is_err()
        {
            return;
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stream).await;
        // Read until EOF (or the cap) so no inbound data triggers RST.
        let mut sink = Vec::new();
        let _ = tokio::time::timeout(Duration::from_millis(500), async {
            use tokio::io::AsyncReadExt as _;
            let _ = stream.read_to_end(&mut sink).await;
        })
        .await;
    })
    .await;
}

/// Per-connection policy configuration, cheap to clone from the resolved
/// server config for each accepted connection.
#[derive(Clone)]
struct SessionConfig {
    domain: String,
    max_data: usize,
    auth: Option<Arc<auth::AuthConfig>>,
    /// Recipient authority: hosted domains, policy modes, and the
    /// address-to-mailbox mapping (Phase 12 gap 1).
    authority: Arc<dyn authority::RecipientResolver>,
    /// Shared DNS client used for SPF, DKIM key, and DMARC lookups.
    dns: Arc<dns::DnsClient>,
    /// Per-source-IP limit on concurrent DNS-backed checks.
    dns_limit: Arc<limit::DnsLimiter>,
    /// Overall time limit for the DNS work at end-of-data (DKIM key
    /// lookups plus the DMARC policy fetch); [`END_OF_DATA_DNS_DEADLINE`]
    /// in production.
    eod_dns_deadline: Duration,
    /// Becomes true when a graceful shutdown starts (sessions then end
    /// with 421 between transactions).
    shutdown: tokio::sync::watch::Receiver<bool>,
    /// Spool backend for accepted messages; None drops them (tests).
    spool: Option<Arc<dyn spool::SpoolWriter>>,
    /// Local delivery sink; None leaves messages queued (tests).
    sink: Option<Arc<dyn delivery::DeliverySink>>,
}

/// The peer address with an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`,
/// what a dual-stack `[::]` listener reports for IPv4 clients) turned back
/// into plain IPv4 (N19, SECURITY.md). Without this, SPF `ip4:`/`a`/`mx`
/// never match IPv4 senders, and an IPv4 client's per-IP limits, logs and
/// `Received:` show the mapped form.
fn canonical_peer(peer: SocketAddr) -> SocketAddr {
    SocketAddr::new(peer.ip().to_canonical(), peer.port())
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
    let peer = canonical_peer(stream.peer_addr()?);
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

/// Read the `--resolver-ca` PEM file (D2, DEPLOYMENT.md).
///
/// Returns every certificate in the file, in order. Returns `Err` if the
/// file can't be read, isn't valid PEM, or holds no certificate at all —
/// an empty or mistyped CA file must stop startup, not silently leave the
/// local resolver untrusted.
async fn load_resolver_ca(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let pem = tokio::fs::read(path)
        .await
        .map_err(|e| anyhow::anyhow!("cannot read resolver CA file {path}: {e}"))?;
    resolver_ca_from_pem(&pem).map_err(|e| anyhow::anyhow!("invalid resolver CA file {path}: {e}"))
}

/// Parse PEM certificates for [`load_resolver_ca`].
fn resolver_ca_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = std::io::Cursor::new(pem);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cursor).collect::<std::result::Result<_, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no PEM certificates found");
    }
    Ok(certs)
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

    /// A shutdown receiver that never signals: its sender is already
    /// gone, so `shutdown_signal` stays pending (tests that aren't about
    /// shutdown).
    fn no_shutdown() -> tokio::sync::watch::Receiver<bool> {
        tokio::sync::watch::channel(false).1
    }

    #[test]
    fn clean_path_strips_brackets_and_space() {
        let addr = |raw| clean_path(raw).map(|(a, _)| a);
        assert_eq!(addr("<sender@example.org>"), Some("sender@example.org"));
        assert_eq!(addr(" <sender@example.org> "), Some("sender@example.org"));
        assert_eq!(addr("sender@example.org"), Some("sender@example.org"));
        // Null sender.
        assert_eq!(addr("<>"), Some(""));
        assert_eq!(addr(""), Some(""));
    }

    /// H3 (security report): ESMTP parameters after the path are split
    /// off — they used to end up inside the address (SPF evaluated a
    /// bogus `domain> SIZE=…` and bounces with `SIZE=` were refused).
    #[test]
    fn clean_path_splits_esmtp_parameters() {
        assert_eq!(
            clean_path("<ceo@bank.example> SIZE=1234 BODY=8BITMIME"),
            Some(("ceo@bank.example", "SIZE=1234 BODY=8BITMIME"))
        );
        assert_eq!(clean_path("<> SIZE=1000"), Some(("", "SIZE=1000")));
        assert_eq!(
            clean_path("user@example.org SIZE=10"),
            Some(("user@example.org", "SIZE=10"))
        );
        // Unterminated path, and a bare CR inside the address.
        assert_eq!(clean_path("<user@example.org SIZE=10"), None);
        assert_eq!(clean_path("<a\rX-Injected: yes@b.example>"), None);

        assert_eq!(size_param("SIZE=1234 BODY=8BITMIME"), Some(1234));
        assert_eq!(size_param("body=7bit size=99"), Some(99));
        assert_eq!(size_param("BODY=8BITMIME"), None);
        assert_eq!(size_param(""), None);
    }

    /// N4 (security report): ordinary RFC 5321 local-parts are accepted;
    /// anything with path meaning is not.
    #[test]
    fn local_part_policy() {
        for ok in [
            "o'brien@x.test",
            "info&sales@x.test",
            "a+b=c@x.test",
            "first.last@x.test",
        ] {
            assert_eq!(unsafe_local_part(ok), None, "{ok} must be accepted");
        }
        for bad in [
            "../x@x.test",
            "/abs@x.test",
            "a/b@x.test",
            ".hidden@x.test",
            "a..b@x.test",
            "a\\b@x.test",
            "\"quoted\"@x.test",
        ] {
            assert!(unsafe_local_part(bad).is_some(), "{bad} must be refused");
        }
    }

    /// N2/N3 (security report): the From scanner reads an RFC 5322
    /// mailbox-list. Folded values are unfolded, comments and quoted
    /// strings never contribute an `@`, the obsolete `From :` spelling
    /// counts as a From header, and several author domains are refused.
    #[test]
    fn from_header_scanner() {
        let scan = |headers: &str| from_header_domain(format!("{headers}\r\nbody\r\n").as_bytes());
        let parsed = |d: &str| FromHeader::Parsed(d.to_string());

        // Simple and display-name forms.
        assert_eq!(scan("From: a@Example.ORG\r\n"), parsed("example.org"));
        assert_eq!(
            scan("From: \"Doe, John\" <j@example.org>\r\n"),
            parsed("example.org")
        );
        // N2: a folded From keeps its continuation lines.
        assert_eq!(
            scan("From: \"A Rather Long Display Name\"\r\n <news@example.net>\r\nSubject: x\r\n"),
            parsed("example.net")
        );
        // 8-bit display name (not UTF-8) is fine.
        assert_eq!(
            from_header_domain(b"From: \xe9t\xe9 <a@example.org>\r\n\r\nbody\r\n"),
            parsed("example.org")
        );
        // Quoted local-part containing '@'.
        assert_eq!(scan("From: \"a@b\"@example.org\r\n"), parsed("example.org"));

        // N3: an '@' inside a comment or quoted string never picks the domain.
        assert_eq!(
            scan("From: ceo@paypal.com (@attacker.example )\r\n"),
            parsed("paypal.com")
        );
        assert_eq!(
            scan("From: \"x@attacker.example\" <ceo@paypal.com>\r\n"),
            parsed("paypal.com")
        );
        // N3: several author domains are refused; one domain twice is fine.
        assert_eq!(
            scan("From: ceo@paypal.com, x@attacker.example\r\n"),
            FromHeader::Multiple
        );
        assert_eq!(
            scan("From: a@example.org, b@example.org\r\n"),
            parsed("example.org")
        );
        // N3: `From :` (obsolete spacing) is a From header too.
        assert_eq!(
            scan("From : ceo@paypal.com\r\nFrom: x@attacker.example\r\n"),
            FromHeader::Multiple
        );
        // C4 outcomes.
        assert_eq!(scan("Subject: none\r\n"), FromHeader::None);
        assert_eq!(
            scan("From: a@example.org\r\nfrom: b@example.org\r\n"),
            FromHeader::Multiple
        );
        assert_eq!(scan("From: no-address-here\r\n"), FromHeader::Unparseable);
        assert_eq!(
            scan("From: a@example.org (unclosed\r\n"),
            FromHeader::Unparseable
        );
        assert_eq!(
            scan("From: group: a@example.org;\r\n"),
            FromHeader::Unparseable
        );
        // A From line in the body is not a header.
        assert_eq!(
            from_header_domain(b"Subject: x\r\n\r\nFrom: a@example.org\r\n"),
            FromHeader::None
        );
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
        assert_eq!(resolved.max_conn_duration_ms, DEFAULT_MAX_CONN_DURATION_MS);
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

    /// `max-dns-per-ip`: default, file, CLI precedence; 0 is an error.
    #[test]
    fn max_dns_per_ip_resolution() {
        use clap::Parser as _;
        let args = |extra: &[&str]| {
            let mut argv = vec!["mailserv", "--domain", "d.example"];
            argv.extend_from_slice(extra);
            Args::parse_from(argv)
        };
        let resolved = resolve_config(args(&[]), FileConfig::default()).unwrap();
        assert_eq!(resolved.max_dns_per_ip, limit::DEFAULT_DNS_PER_IP);
        let file: FileConfig = toml::from_str("max-dns-per-ip = 8").unwrap();
        assert_eq!(
            resolve_config(args(&[]), file.clone())
                .unwrap()
                .max_dns_per_ip,
            8
        );
        assert_eq!(
            resolve_config(args(&["--max-dns-per-ip", "2"]), file)
                .unwrap()
                .max_dns_per_ip,
            2
        );
        let err =
            resolve_config(args(&["--max-dns-per-ip", "0"]), FileConfig::default()).unwrap_err();
        assert!(err.to_string().contains("max-dns-per-ip"), "{err}");
    }

    /// Per-IP DNS limit (DESIGN §9, H6): with this source IP's share
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

    /// `dns-connections`: defaults to the dns crate's default, the file
    /// value applies, the CLI wins, and out-of-range values are a startup
    /// error rather than being silently clamped.
    #[test]
    fn dns_connections_resolution() {
        use clap::Parser as _;
        let args = |extra: &[&str]| {
            let mut argv = vec!["mailserv", "--domain", "d.example"];
            argv.extend_from_slice(extra);
            Args::parse_from(argv)
        };

        let resolved = resolve_config(args(&[]), FileConfig::default()).unwrap();
        assert_eq!(resolved.dns_connections, dns::DEFAULT_CONNECTIONS);

        let file: FileConfig = toml::from_str("dns-connections = 4").unwrap();
        let resolved = resolve_config(args(&[]), file.clone()).unwrap();
        assert_eq!(resolved.dns_connections, 4);
        let resolved = resolve_config(args(&["--dns-connections", "3"]), file).unwrap();
        assert_eq!(resolved.dns_connections, 3);

        for bad in ["0", "17"] {
            let err = resolve_config(args(&["--dns-connections", bad]), FileConfig::default())
                .unwrap_err();
            assert!(err.to_string().contains("dns-connections"), "{err}");
        }
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

    /// D2 (DEPLOYMENT.md): `resolver-ca` resolves CLI > file > none; unset
    /// means public roots only (the previous behavior).
    #[test]
    fn resolver_ca_resolution() {
        use clap::Parser as _;
        let args = |extra: &[&str]| {
            let mut argv = vec!["mailserv", "--domain", "d.example"];
            argv.extend_from_slice(extra);
            Args::parse_from(argv)
        };

        let resolved = resolve_config(args(&[]), FileConfig::default()).unwrap();
        assert_eq!(resolved.resolver_ca, None);

        let file: FileConfig = toml::from_str(r#"resolver-ca = "/etc/ca/file.pem""#).unwrap();
        let resolved = resolve_config(args(&[]), file.clone()).unwrap();
        assert_eq!(resolved.resolver_ca.as_deref(), Some("/etc/ca/file.pem"));

        let resolved = resolve_config(args(&["--resolver-ca", "/etc/ca/cli.pem"]), file).unwrap();
        assert_eq!(resolved.resolver_ca.as_deref(), Some("/etc/ca/cli.pem"));
    }

    /// D4 (DEPLOYMENT.md): production-safe defaults. Port 25 (2525 is
    /// for unprivileged testing), absolute storage paths, a 10 MiB message
    /// limit, a 5-minute connection cap, 100 connections, 60 s shutdown
    /// grace, and no user switch unless configured.
    #[test]
    fn production_defaults() {
        use clap::Parser as _;
        let resolved = resolve_config(
            Args::parse_from(["mailserv", "--domain", "d.example"]),
            FileConfig::default(),
        )
        .unwrap();
        assert_eq!(resolved.port, 25);
        assert_eq!(resolved.spool_dir, "/var/lib/mailserv/spool");
        assert_eq!(resolved.maildir_dir, "/var/lib/mailserv/maildir");
        assert!(std::path::Path::new(&resolved.spool_dir).is_absolute());
        assert!(std::path::Path::new(&resolved.maildir_dir).is_absolute());
        assert_eq!(resolved.max_data_bytes, 10 * 1024 * 1024);
        assert_eq!(resolved.max_conn_duration_ms, 300_000);
        assert_eq!(resolved.max_connections, 100);
        assert_eq!(resolved.shutdown_grace_ms, 60_000);
        assert_eq!(resolved.user, None);
        assert_eq!(resolved.group, None);
    }

    /// D4: `user`, `group` and `shutdown-grace-ms` resolve CLI > file;
    /// `group` without `user` is a configuration error.
    #[test]
    fn user_group_and_grace_resolution() {
        use clap::Parser as _;
        let args = |extra: &[&str]| {
            let mut argv = vec!["mailserv", "--domain", "d.example"];
            argv.extend_from_slice(extra);
            Args::parse_from(argv)
        };
        let file: FileConfig =
            toml::from_str("user = \"mailserv\"\ngroup = \"mail\"\nshutdown-grace-ms = 5000")
                .unwrap();
        let resolved = resolve_config(args(&[]), file.clone()).unwrap();
        assert_eq!(resolved.user.as_deref(), Some("mailserv"));
        assert_eq!(resolved.group.as_deref(), Some("mail"));
        assert_eq!(resolved.shutdown_grace_ms, 5000);

        let resolved = resolve_config(
            args(&["--user", "other", "--shutdown-grace-ms", "100"]),
            file,
        )
        .unwrap();
        assert_eq!(resolved.user.as_deref(), Some("other"));
        assert_eq!(resolved.shutdown_grace_ms, 100);

        let err = resolve_config(args(&["--group", "mail"]), FileConfig::default()).unwrap_err();
        assert!(err.to_string().contains("--group requires --user"), "{err}");
    }

    /// D2: the CA file loads every certificate it holds, and a missing,
    /// empty, or non-certificate file is a startup error, never a silent
    /// fallback to "local resolver untrusted".
    #[tokio::test]
    async fn resolver_ca_file_loading() {
        let a = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let b = rcgen::generate_simple_self_signed(vec!["10.0.0.53".into()]).unwrap();
        let pem = format!("{}{}", a.cert.pem(), b.cert.pem());

        let certs = resolver_ca_from_pem(pem.as_bytes()).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].as_ref(), a.cert.der().as_ref());

        // The loaded roots are accepted by the DNS client (and public
        // roots stay; see the dns crate's extra_roots tests).
        dns::DnsClient::new("127.0.0.1".parse().unwrap())
            .with_extra_roots(&certs)
            .unwrap();

        assert!(resolver_ca_from_pem(b"").is_err());
        // A private key alone is not a CA file.
        assert!(resolver_ca_from_pem(a.key_pair.serialize_pem().as_bytes()).is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        std::fs::write(&path, &pem).unwrap();
        assert_eq!(
            load_resolver_ca(path.to_str().unwrap())
                .await
                .unwrap()
                .len(),
            2
        );
        let missing = dir.path().join("missing.pem");
        let err = load_resolver_ca(missing.to_str().unwrap())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot read resolver CA file"),
            "{err}"
        );
    }

    /// Spawn handle_connection on an ephemeral port, handling exactly
    /// one connection. When `authority` is None, the static fallback is
    /// built from `local_domains` (the pre-authority behavior: every
    /// local-part at a hosted domain accepts).
    async fn spawn_server(
        acceptor: Option<Arc<TlsAcceptor>>,
        auth: Option<Arc<auth::AuthConfig>>,
        local_domains: Option<Vec<String>>,
        spool: Option<Arc<dyn spool::SpoolWriter>>,
        sink: Option<Arc<dyn delivery::DeliverySink>>,
        authority: Option<Arc<dyn authority::RecipientResolver>>,
    ) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
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
        tokio::spawn(async move {
            if let Ok((stream, _peer)) = listener.accept().await {
                let _ = handle_connection(
                    stream,
                    acceptor,
                    5000,
                    SessionConfig {
                        domain: "mail.example.org".to_string(),
                        max_data: 1024 * 1024,
                        auth,
                        authority,
                        // The integration tests exercise the real resolver
                        // path: the sender domains used below
                        // (spfless-domain-xyz.test) are NXDOMAIN, so SPF
                        // evaluates to None and DMARC has no policy.
                        // The integration tests exercise the real resolver
                        // path: the sender domains used below
                        // (spfless-domain-xyz.test) are NXDOMAIN, so SPF
                        // evaluates to None and DMARC has no policy.
                        dns: Arc::new(dns::DnsClient::new("1.1.1.1".parse().unwrap())),
                        dns_limit: Arc::new(limit::DnsLimiter::new(
                            limit::DEFAULT_DNS_PER_IP,
                            limit::DNS_LIMIT_WAIT,
                        )),
                        shutdown: no_shutdown(),
                        eod_dns_deadline: END_OF_DATA_DNS_DEADLINE,
                        spool,
                        sink,
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
        let auth =
            auth::AuthConfig::parse("alice:secret", Some("alice=alice@spfless-domain-xyz.test"))
                .unwrap();
        let addr = spawn_server(Some(acceptor), Some(Arc::new(auth)), None, None, None, None).await;

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

    /// Accepted messages are durably spooled: payload byte-exact, metadata
    /// complete, and the 250 only after the write (Phase 7).
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

        // Payload is exactly the (unstuffed) DATA bytes.
        let payload = tokio::fs::read(new.join(&names[0])).await.unwrap();
        assert_eq!(
            payload,
            b"Subject: spool test\r\nFrom: sender@spfless-domain-xyz.test\r\n\r\nbody line\r\n"
        );

        // Metadata is complete and consistent.
        let meta: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(new.join(&names[1])).await.unwrap()).unwrap();
        assert_eq!(meta["queue_id"], id);
        assert_eq!(meta["helo"], "client.test");
        assert_eq!(meta["mail_from"], "sender@spfless-domain-xyz.test");
        assert_eq!(meta["rcpt_to"][0]["address"], "user@example.org");
        assert_eq!(meta["rcpt_to"][0]["mailbox"], "user@example.org");
        assert_eq!(meta["message_size"], payload.len());
        assert!(meta["received_at"].is_string());
        assert!(meta["peer"].is_string());
    }

    // -- Recipient authority (Phase 12 gap 1) ---------------------------

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
            .write_all(
                b"Subject: to alice\r\nFrom: sender@spfless-domain-xyz.test\r\n\r\nhi\r\n.\r\n",
            )
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
            .write_all(
                b"Subject: caught\r\nFrom: sender@spfless-domain-xyz.test\r\n\r\nhi\r\n.\r\n",
            )
            .await
            .unwrap();
        assert_eq!(read_reply(&mut client).await[0], "250 Ok\r\n");
        client.write_all(b"QUIT\r\n").await.unwrap();

        // ...and the mail lands in the admin's maildir, addressed to the
        // envelope recipient in the trace headers.
        let inbox = dir.path().join("maildir/example.org/admin/new");
        let mut rd = tokio::fs::read_dir(&inbox).await.unwrap();
        let mut names = Vec::new();
        while let Some(e) = rd.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(names.len(), 1, "admin inbox: {names:?}");
        let copy = std::fs::read(inbox.join(&names[0])).unwrap();
        let text = String::from_utf8(copy).unwrap();
        assert!(text.contains("for <whatever-alias@example.org>"));
    }

    // -- Security-report regressions ------------------------------------

    /// C1 (security report): local-parts with path semantics must be
    /// refused at RCPT time — `/` in an RFC-atext local-part used to be
    /// copied into maildir paths (relative traversal via `..`, absolute
    /// paths via `Path::join`).
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

    /// C4 (security report): a message with no `From:` header is
    /// rejected (RFC 7489 Section 6.6.1) — it used to skip DMARC and be
    /// accepted.
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

    /// A local DNS-over-TLS resolver for hermetic DMARC tests: every
    /// `_dmarc.*` TXT query is answered `v=DMARC1; p=reject`, everything
    /// else with an empty NOERROR answer. Returns a client wired to it.
    async fn spawn_mock_dmarc_resolver() -> Arc<dns::DnsClient> {
        spawn_mock_dmarc_resolver_with(0).await
    }

    /// Like [`spawn_mock_dmarc_resolver`], but `_dmarc.*` TXT queries get
    /// `dmarc_rcode` (e.g. 2, SERVFAIL) with no answer when it is non-zero.
    async fn spawn_mock_dmarc_resolver_with(dmarc_rcode: u8) -> Arc<dns::DnsClient> {
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
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
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
                        let mut resp =
                            DnsMessage::new(query.header.transaction_id, query.questions.clone());
                        resp.header.qr = 1;
                        if let Some(q) = query.questions.first() {
                            if String::from(&q.name).starts_with("_dmarc.") && q.record_type == 16 {
                                if dmarc_rcode != 0 {
                                    resp.header.rcode = dmarc_rcode;
                                } else {
                                    resp.answers.push(DnsResourceRecord {
                                        name: q.name.clone(),
                                        record_type: 16,
                                        record_class: 1,
                                        ttl: 60,
                                        rdlength: 0,
                                        rdata: QType::TXT("v=DMARC1; p=reject".to_string()),
                                    });
                                }
                            }
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
            Duration::from_secs(5),
            Some(format!("127.0.0.1:{port}")),
        ))
    }

    /// A DNS-over-TLS resolver that accepts connections and reads queries
    /// but never answers (an authoritative server that never responds, as
    /// seen through the resolver). The client's own per-query timeout is
    /// 30 s, so only the end-of-data deadline can end a check against it.
    async fn spawn_silent_resolver() -> Arc<dns::DnsClient> {
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
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    // Swallow queries; never reply.
                    let mut buf = [0u8; 4096];
                    while matches!(tls.read(&mut buf).await, Ok(n) if n > 0) {}
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
            Duration::from_secs(30),
            Some(format!("127.0.0.1:{port}")),
        ))
    }

    /// A session over a file authority with one size-limited domain
    /// (`small.example`, 2 KiB) and one without a limit (`big.example`),
    /// under a 1 MiB server limit. No DNS is used: SPF is skipped because
    /// the tests set the envelope sender directly.
    pub(super) fn size_limit_session(dir: &std::path::Path) -> SessionConfig {
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
        }
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
            smtp::Control::reject(
                b"552 5.3.4 Message size exceeds the recipient's limit\r\n".to_vec()
            )
        );
        assert!(session.rcpt_to.is_empty());
        // The same message is fine for the domain without a limit.
        assert!(session.rcpt_to("<c@big.example>").await.is_accept());
    }

    /// D3 (DEPLOYMENT.md): end-of-data DNS work has one overall deadline.
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

    /// C3 (security report): DKIM verdicts must not leak across messages
    /// on one connection. A verified signature from an earlier message
    /// used to satisfy DMARC alignment for a later unsigned spoof of the
    /// same domain. Here a fake verified facebook.com verdict is left in
    /// the session, and an unsigned message `From: someone@facebook.com`
    /// (a domain whose DMARC record is `p=reject`) must still be REJECTED —
    /// the DMARC evaluation consumes only this message's results.
    ///
    /// N6 (security report): hermetic — DMARC records come from a local
    /// mock DNS-over-TLS resolver, never the live internet.
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

    /// F1 (SECURITY-AUDIT.md): when the DMARC policy can't be fetched
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
        };
        let mut session = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);
        session.mail_from = Some("x@attacker.example".into());
        session.data = b"From: ceo@victim.example\r\nSubject: spoof\r\n\r\nbody\r\n".to_vec();
        let control = session.end_data().await;
        assert_eq!(control, smtp::Control::tempfail(DMARC_TEMPFAIL));
        assert_eq!(session.mail_from, None, "the transaction is over");
        assert_eq!(session.message_count, 1);
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
}

#[cfg(test)]
mod helo_and_peer_tests {
    use super::*;

    /// M8 (SECURITY.md): the HELO identity must be a domain or an address
    /// literal; control characters (the bare-CR `Received:` injection),
    /// whitespace and other junk are refused.
    #[test]
    fn helo_validation() {
        for ok in [
            "mail.example.org",
            "mail.example.org.",
            "localhost",
            "host_name.example",
            "a-b.example",
            "[192.0.2.1]",
            "[IPv6:2001:db8::1]",
        ] {
            assert!(valid_helo(ok), "{ok:?} should be accepted");
        }
        for bad in [
            "",
            "evil.example\rX-Injected: yes",
            "evil.example\nX-Injected: yes",
            "evil.example\x00",
            "two words",
            "a..b",
            ".",
            "[]",
            "[192.0.2.1",
            "[a]b]",
            "[a\\b]",
            "caf\u{e9}.example",
            "x(y).example",
            &format!("{}.example", "a".repeat(64)),
            &"a.".repeat(130),
        ] {
            assert!(!valid_helo(bad), "{bad:?} should be refused");
        }
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

    /// N19 (SECURITY.md): an IPv4 client on a dual-stack listener is seen
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
}

#[cfg(test)]
mod from_validation_tests {
    use super::*;

    fn authors(value: &str) -> Option<Vec<(String, String)>> {
        from_authors(value.as_bytes())
    }

    /// The author addresses are the ones a mail client displays: comments
    /// and display names never supply them, every mailbox in the list is
    /// returned, and groups are refused.
    #[test]
    fn from_authors_extracts_displayed_addresses() {
        let own = |l: &str, d: &str| (l.to_string(), d.to_string());
        assert_eq!(
            authors("Alice <Alice@Example.ORG.>"),
            Some(vec![own("Alice", "example.org")])
        );
        assert_eq!(
            authors("\"ceo@victim.example\" (ceo@victim.example) <a@b.example>"),
            Some(vec![own("a", "b.example")])
        );
        assert_eq!(
            authors("a@b.example, Mallory <m@evil.example>"),
            Some(vec![own("a", "b.example"), own("m", "evil.example")])
        );
        // A quoted local-part is blanked, so it can't match an exact grant.
        assert_eq!(
            authors("\"alice\"@b.example"),
            Some(vec![own("\"xxxxx\"", "b.example")])
        );
        assert_eq!(authors("undisclosed: a@b.example;"), None);
        assert_eq!(authors("no address here"), None);
        assert_eq!(authors(""), None);
    }

    fn session_cfg(dir: &std::path::Path) -> SessionConfig {
        let mut cfg = tests::size_limit_session(dir);
        cfg.auth = Some(Arc::new(
            auth::AuthConfig::parse(
                "alice:pw,carol:pw",
                Some("alice=alice@example.org|@alice.example"),
            )
            .unwrap(),
        ));
        cfg
    }

    /// MAIL FROM of an authenticated session is limited to the login's
    /// grants; the null sender and logins without grants are refused.
    /// Refusals happen before any DNS.
    #[tokio::test]
    async fn authenticated_mail_from_must_be_granted() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = session_cfg(dir.path());
        let mut s = UserSession::new("127.0.0.1:40000".parse().unwrap(), false, &cfg);

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
}

#[cfg(test)]
mod bare_cr_tests {
    use super::*;

    /// F3 (SECURITY-AUDIT.md): the confirmed attack shape and its
    /// variants are detected; CRLF, bare LF, and CRs in the body are not.
    #[test]
    fn bare_cr_in_header_block_is_detected() {
        for bad in [
            &b"Subject: x\rFrom: CEO <ceo@victim.example>\r\nFrom: a@evil.example\r\n\r\nbody"[..],
            b"From: a@evil.example\rFrom: ceo@victim.example\r\n\r\nbody",
            b"X-A: 1\r\r\nFrom: a@b.example\r\n\r\nbody",
            b"From: a@b.example\r\n\tfolded\rFrom: c@d.example\r\n\r\nbody",
        ] {
            assert!(
                header_has_bare_cr(bad),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        for ok in [
            &b"From: a@b.example\r\nSubject: x\r\n\r\nbody\rwith bare CR\r\n"[..],
            b"From: a@b.example\nSubject: x\n\nbody\n",
            b"From: a@b.example\r\n\r\n",
        ] {
            assert!(!header_has_bare_cr(ok), "{:?}", String::from_utf8_lossy(ok));
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
        s.data =
            b"Subject: x\rFrom: CEO <ceo@victim.example>\r\nFrom: a@evil.example\r\n\r\nbody\r\n"
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
}
