//! Settings: the command-line arguments, the TOML config file, their
//! merge into [`Config`] (CLI over file over built-in defaults), and the
//! startup checks on the result.

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;
use std::net::Ipv4Addr;

use crate::limit;

/// A small, secure SMTP server: accepts and verifies mail (SPF, DKIM,
/// DMARC); supports STARTTLS, AUTH, and a closed relay policy.
#[derive(Parser, Debug, Clone, Default)]
#[command(version, about, long_about = None)]
pub(crate) struct Args {
    /// A utility to run instead of the server.
    #[command(subcommand)]
    pub(crate) command: Option<Command>,

    /// Address to listen on (default 0.0.0.0).
    #[arg(long)]
    pub(crate) host: Option<String>,

    /// Port to listen on (default 25).
    #[arg(long)]
    pub(crate) port: Option<u16>,

    /// Also listen for message submission with STARTTLS on this port
    /// (normally 587). AUTH is offered only on submission ports, and is
    /// required there; needs --tls-cert/--tls-key and --auth-users-file.
    #[arg(long, value_name = "PORT")]
    pub(crate) submission_port: Option<u16>,

    /// Also listen for message submission over implicit TLS on this port
    /// (normally 465, RFC 8314); same requirements as --submission-port.
    #[arg(long, value_name = "PORT")]
    pub(crate) submissions_port: Option<u16>,

    /// This server's domain, used in the greeting and `Received:` headers
    /// (required, here or in the config file).
    #[arg(long)]
    pub(crate) domain: Option<String>,

    /// Message size limit in bytes.
    #[arg(long)]
    pub(crate) max_data_bytes: Option<usize>,

    /// Default storage quota for each mailbox, in bytes (default 10 MiB; 0
    /// for no default), used when the authority file sets no `quota-bytes`
    /// for the mailbox or its domain. A recipient whose mailbox holds its
    /// quota gets `452 4.2.2 Mailbox full` at RCPT, so the sender retries.
    #[arg(long, value_name = "BYTES")]
    pub(crate) mailbox_quota_bytes: Option<u64>,

    /// Free space the spool and maildir filesystems must keep, in bytes
    /// (default 1 GiB; 0 for no check). Below it, new mail gets
    /// `452 4.3.1 Insufficient system storage`.
    #[arg(long, value_name = "BYTES")]
    pub(crate) min_free_disk_bytes: Option<u64>,

    /// Whole-connection time limit in milliseconds (default 300000).
    #[arg(long)]
    pub(crate) max_conn_duration_ms: Option<u64>,

    /// Per-read idle time limit in milliseconds (default 15000).
    #[arg(long)]
    pub(crate) max_read_duration_ms: Option<u64>,

    /// Maximum simultaneous connections, server-wide.
    #[arg(long, value_name = "N")]
    pub(crate) max_connections: Option<u32>,

    /// Maximum simultaneous connections from a single source IP.
    #[arg(long, value_name = "N")]
    pub(crate) max_conn_per_ip: Option<u32>,

    /// Maximum new connections per 60-second window from a single
    /// source IP (connection churn / flood budget).
    #[arg(long, value_name = "N")]
    pub(crate) max_conn_rate_per_ip: Option<u32>,

    /// Maximum concurrent DNS-backed checks (SPF, DKIM, DMARC) for one
    /// source IP. Further checks wait up to 10 s, then get a temporary
    /// failure (451).
    #[arg(long, value_name = "N")]
    pub(crate) max_dns_per_ip: Option<usize>,

    /// PEM certificate for STARTTLS (requires --tls-key).
    #[arg(long)]
    pub(crate) tls_cert: Option<String>,

    /// PEM private key for STARTTLS (requires --tls-cert).
    #[arg(long)]
    pub(crate) tls_key: Option<String>,

    /// File of SASL credentials for AUTH PLAIN/LOGIN: one user:hash per
    /// line, where hash is an argon2id string from `mailserv
    /// hash-password`; # comments allowed. Must not be accessible to other
    /// users (chmod 600 or 640). Read at startup, before privileges are
    /// dropped, and again on SIGHUP (as the service user: give it owner
    /// root, group the service group and mode 0640 for that). AUTH is
    /// only offered on the submission ports, over TLS.
    #[arg(long, value_name = "FILE")]
    pub(crate) auth_users_file: Option<String>,

    /// Addresses each AUTH login may send as (MAIL FROM and every From:
    /// author), as user=grant|grant entries (comma-separated); a grant is an
    /// exact address or @domain. A login without an entry can't send.
    /// Example: --auth-senders 'alice=alice@example.org|@example.net'
    #[arg(long)]
    pub(crate) auth_senders: Option<String>,

    /// DNS resolver address (DNS-over-TLS on port 853) used for SPF,
    /// DKIM key, and DMARC lookups.
    #[arg(long)]
    pub(crate) resolver: Option<Ipv4Addr>,

    /// PEM file of extra CA certificates to trust for the resolver's
    /// DNS-over-TLS certificate, so a local resolver with a private or
    /// self-signed certificate can be used. Added to the public roots, not
    /// substituted, so public resolvers keep working. The certificate must
    /// name the --resolver address as an IP subject alternative name.
    #[arg(long, value_name = "FILE")]
    pub(crate) resolver_ca: Option<String>,

    /// Pipelined DNS-over-TLS connections to the resolver (1-16, default
    /// 2). Each carries up to 64 queries in flight.
    #[arg(long, value_name = "N")]
    pub(crate) dns_connections: Option<usize>,

    /// Queue directory where accepted messages are spooled before
    /// delivery. Spooling is part of the acceptance contract: the 250 is
    /// only sent after a durable write.
    #[arg(long, value_name = "DIR")]
    pub(crate) spool_dir: Option<String>,

    /// Local delivery root: one maildir per recipient address
    /// ({root}/{domain}/{local}/). Accepted messages are delivered here
    /// and retried from the spool until they succeed.
    #[arg(long, value_name = "DIR")]
    pub(crate) maildir_dir: Option<String>,

    /// Domains whose recipients we accept mail for (comma-separated;
    /// defaults to --domain only; superseded by --authority when given).
    /// Relay access is closed regardless of authentication.
    #[arg(long)]
    pub(crate) local_domains: Option<String>,

    /// Recipient authority file (JSON): the hosted-domain list, per-
    /// domain policy modes, and the address-to-mailbox mapping. The
    /// authoritative source for recipient policy; hot-reloaded on
    /// change. Supersedes --local-domains when given. See the module
    /// docs in authority.rs for the schema.
    #[arg(long, value_name = "FILE")]
    pub(crate) authority: Option<String>,

    /// Unprivileged user to switch to right after binding the port, when
    /// started as root (required then: running as root without it is
    /// refused). Name or numeric uid.
    #[arg(long, value_name = "USER")]
    pub(crate) user: Option<String>,

    /// Group to switch to with --user (name or numeric gid; default: the
    /// user's primary group).
    #[arg(long, value_name = "GROUP")]
    pub(crate) group: Option<String>,

    /// On SIGTERM/SIGINT, how long sessions in progress may take to
    /// finish before the process exits (milliseconds, default 60000).
    #[arg(long, value_name = "MS")]
    pub(crate) shutdown_grace_ms: Option<u64>,

    /// TOML configuration file; CLI flags override file values. Keys are
    /// the same as the flags in kebab-case (host, port, submission-port,
    /// submissions-port, domain,
    /// max-data-bytes, mailbox-quota-bytes, min-free-disk-bytes,
    /// max-conn-duration-ms, max-read-duration-ms,
    /// tls-cert, tls-key, auth-users-file, auth-senders, resolver, resolver-ca,
    /// dns-connections, spool-dir, maildir-dir, max-connections,
    /// max-conn-per-ip, max-conn-rate-per-ip, max-dns-per-ip, user, group,
    /// shutdown-grace-ms, local-domains, authority); every key optional.
    #[arg(long, value_name = "FILE")]
    pub(crate) config: Option<String>,
}

/// Utilities run instead of the server.
#[derive(clap::Subcommand, Debug, Clone)]
pub(crate) enum Command {
    /// Read a password from stdin (hidden when it's a terminal) and print
    /// its argon2id hash for a line `user:<hash>` in --auth-users-file.
    HashPassword,
}

/// The TOML config file schema ([`Args::config`]). Every field except
/// `auth_users` mirrors the [`Args`] flag of the same name (kebab-case in
/// the file) and is optional; unknown keys are ignored.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub(crate) struct FileConfig {
    pub(crate) host: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) submission_port: Option<u16>,
    pub(crate) submissions_port: Option<u16>,
    pub(crate) domain: Option<String>,
    pub(crate) max_data_bytes: Option<usize>,
    pub(crate) mailbox_quota_bytes: Option<u64>,
    pub(crate) min_free_disk_bytes: Option<u64>,
    pub(crate) max_conn_duration_ms: Option<u64>,
    pub(crate) max_read_duration_ms: Option<u64>,
    pub(crate) max_connections: Option<u32>,
    pub(crate) max_conn_per_ip: Option<u32>,
    pub(crate) max_conn_rate_per_ip: Option<u32>,
    pub(crate) max_dns_per_ip: Option<usize>,
    pub(crate) tls_cert: Option<String>,
    pub(crate) tls_key: Option<String>,
    /// The removed inline-credentials key. Parsed only so that an old
    /// config file is refused with a pointer to `auth-users-file`, rather
    /// than silently ignored (which would turn AUTH off).
    pub(crate) auth_users: Option<toml::Value>,
    pub(crate) auth_users_file: Option<String>,
    pub(crate) auth_senders: Option<String>,
    pub(crate) resolver: Option<Ipv4Addr>,
    pub(crate) resolver_ca: Option<String>,
    pub(crate) dns_connections: Option<usize>,
    pub(crate) spool_dir: Option<String>,
    pub(crate) maildir_dir: Option<String>,
    pub(crate) local_domains: Option<String>,
    pub(crate) authority: Option<String>,
    pub(crate) user: Option<String>,
    pub(crate) group: Option<String>,
    pub(crate) shutdown_grace_ms: Option<u64>,
}

/// Fully resolved server configuration (CLI > file > built-in defaults).
#[derive(Debug, Clone)]
pub(crate) struct Config {
    /// Listen address (default 0.0.0.0).
    pub(crate) host: String,
    /// Listen port (default [`DEFAULT_PORT`]).
    pub(crate) port: u16,
    /// STARTTLS submission port, if enabled (normally 587).
    pub(crate) submission_port: Option<u16>,
    /// Implicit-TLS submission port, if enabled (normally 465).
    pub(crate) submissions_port: Option<u16>,
    /// This server's domain.
    pub(crate) domain: String,
    /// Server-wide message size limit (default [`DEFAULT_MAX_DATA_BYTES`]).
    pub(crate) max_data_bytes: usize,
    /// Default per-mailbox storage quota (default
    /// [`DEFAULT_MAILBOX_QUOTA_BYTES`]), for mailboxes the authority sets
    /// none for; `None` when set to 0.
    pub(crate) mailbox_quota_bytes: Option<u64>,
    /// Free-space floor for the spool and maildir filesystems (default
    /// [`DEFAULT_MIN_FREE_DISK_BYTES`]); `None` when set to 0.
    pub(crate) min_free_disk_bytes: Option<u64>,
    /// Whole-connection time limit (default
    /// [`DEFAULT_MAX_CONN_DURATION_MS`]).
    pub(crate) max_conn_duration_ms: u64,
    /// Per-read idle time limit (default 15 s).
    pub(crate) max_read_duration_ms: u64,
    /// Server-wide concurrent connections (default
    /// [`DEFAULT_MAX_CONNECTIONS`]).
    pub(crate) max_connections: u32,
    /// Concurrent connections per source IP (default 10).
    pub(crate) max_conn_per_ip: u32,
    /// New connections per source IP per 60 s window (default 60).
    pub(crate) max_conn_rate_per_ip: u32,
    /// Concurrent DNS-backed checks per source IP (default
    /// [`limit::DEFAULT_DNS_PER_IP`]).
    pub(crate) max_dns_per_ip: usize,
    /// PEM certificate for STARTTLS.
    pub(crate) tls_cert: Option<String>,
    /// PEM private key for STARTTLS.
    pub(crate) tls_key: Option<String>,
    /// AUTH credentials file (see `auth::AuthConfig::load`); reloaded on
    /// SIGHUP.
    pub(crate) auth_users_file: Option<String>,
    /// Sender grants for AUTH logins (`auth::SenderGrants` spec).
    pub(crate) auth_senders: Option<String>,
    /// DNS-over-TLS resolver address; always resolved (default 1.1.1.1).
    pub(crate) resolver: Ipv4Addr,
    /// Extra CA certificates (PEM file) trusted for the resolver, on top
    /// of the public roots; None trusts the public roots only.
    pub(crate) resolver_ca: Option<String>,
    /// Pipelined DoT connections to the resolver (default
    /// [`dns::DEFAULT_CONNECTIONS`]).
    pub(crate) dns_connections: usize,
    /// Queue directory for accepted messages (default
    /// [`DEFAULT_SPOOL_DIR`]).
    pub(crate) spool_dir: String,
    /// Local delivery root (default [`DEFAULT_MAILDIR_DIR`]).
    pub(crate) maildir_dir: String,
    /// Comma-separated hosted domains for the static authority; None
    /// means `domain` only.
    pub(crate) local_domains: Option<String>,
    /// Recipient authority file; None uses the static fallback built
    /// from `local_domains`.
    pub(crate) authority: Option<String>,
    /// User to drop to after binding, when started as root.
    pub(crate) user: Option<String>,
    /// Group for `user` (default: the user's primary group).
    pub(crate) group: Option<String>,
    /// How long in-progress sessions may run after SIGTERM/SIGINT.
    pub(crate) shutdown_grace_ms: u64,
}

/// The default DNS-over-TLS resolver.
pub(crate) const DEFAULT_RESOLVER: &str = "1.1.1.1";

/// The default listening port: 25, the MX port (RFC 5321 §4.5.4.2).
/// Binding it needs root or `CAP_NET_BIND_SERVICE`; as root, `--user` is
/// required so privileges are dropped right after binding. Use
/// `--port 2525` to test as an ordinary user.
pub(crate) const DEFAULT_PORT: u16 = 25;

/// The default per-message size limit: 10 MiB, in line with Postfix's
/// 10,240,000-byte `message_size_limit` default. Large enough for typical
/// attachments after base64 inflation; raise it (and size memory: a
/// session buffers about twice this during DATA, see DEPLOYMENT.md) for
/// more. Hosted domains can set a lower limit of
/// their own (`max-message-bytes` in the authority file).
pub(crate) const DEFAULT_MAX_DATA_BYTES: usize = 10 * 1024 * 1024;

/// The default per-mailbox storage quota: 10 MiB, deliberately small until
/// the server has run live. Mailboxes and domains can set their own in the
/// authority file (`quota-bytes`).
pub(crate) const DEFAULT_MAILBOX_QUOTA_BYTES: u64 = 10 * 1024 * 1024;

/// The default free-space floor for the spool and maildir filesystems:
/// 1 GiB, enough headroom for mail already accepted to be delivered.
pub(crate) const DEFAULT_MIN_FREE_DISK_BYTES: u64 = 1024 * 1024 * 1024;

/// The default whole-connection time limit: 5 minutes. RFC 5321
/// §4.5.3.2 recommends a 3-minute timeout per DATA block and 10 minutes
/// for end-of-data, but this cap covers a whole session (TLS, envelope,
/// DATA, the checks) and is the backstop against clients that keep a slot
/// with slow, valid traffic. 5 minutes fits a 10 MiB message (about 84
/// Mbit) over a link of about 350 kbit/s or faster, after the DNS checks
/// (at most about 20 s each for HELO SPF, MAIL SPF and end-of-data);
/// per-read idleness is limited separately by `max-read-duration-ms`.
pub(crate) const DEFAULT_MAX_CONN_DURATION_MS: u64 = 5 * 60 * 1000;

/// The default server-wide connection limit: 100, the same as Postfix's
/// `default_process_limit`. Each session can buffer up to about twice
/// `max-data-bytes` during DATA, so 100 × 2 × 10 MiB
/// bounds message buffers at about 2 GiB in the worst case; real
/// concurrency in DATA is far lower. Over the limit, connections get
/// `421` and retry.
pub(crate) const DEFAULT_MAX_CONNECTIONS: u32 = 100;

/// The default shutdown grace period: 60 s. After SIGTERM/SIGINT, idle
/// sessions get `421` at once and sessions mid-message finish theirs;
/// whatever is still running after this long is closed. Below systemd's
/// default `TimeoutStopSec` (90 s), so mailserv exits on its own terms.
pub(crate) const DEFAULT_SHUTDOWN_GRACE_MS: u64 = 60 * 1000;

/// The default spool directory. Absolute, so it never depends on the
/// working directory (systemd's default is `/`).
pub(crate) const DEFAULT_SPOOL_DIR: &str = "/var/lib/mailserv/spool";

/// The default maildir root. Absolute for the same reason.
pub(crate) const DEFAULT_MAILDIR_DIR: &str = "/var/lib/mailserv/maildir";

/// Read the config file named by `args` (if any) and resolve it with
/// `args` (see [`resolve_config`]).
///
/// Returns the fully resolved [`Config`].
///
/// # Errors
///
/// The config file can't be read or isn't valid TOML for [`FileConfig`],
/// or [`resolve_config`] fails.
pub(crate) async fn load(args: Args) -> Result<Config> {
    let file_config = match &args.config {
        Some(path) => {
            let raw = tokio::fs::read_to_string(path)
                .await
                .map_err(|e| anyhow::anyhow!("cannot read config file {path}: {e}"))?;
            toml::from_str(&raw).map_err(|e| anyhow::anyhow!("invalid config file {path}: {e}"))?
        }
        None => FileConfig::default(),
    };
    resolve_config(args, file_config)
}

/// Merge `cli` arguments over `file` config values over built-in
/// defaults.
///
/// Returns the fully resolved [`Config`].
///
/// # Errors
///
/// No domain is configured, `max-dns-per-ip` is 0, `dns-connections` is
/// outside `1..=dns::MAX_CONNECTIONS`, a group is given without a user,
/// the file uses the removed `auth-users` key, or the listeners are
/// inconsistent (see [`check_listeners`]).
pub(crate) fn resolve_config(cli: Args, file: FileConfig) -> Result<Config> {
    if file.auth_users.is_some() {
        anyhow::bail!(
            "the auth-users config key has been removed: put one user:hash line per login \
             (hash from `mailserv hash-password`) in a file readable only by root or the \
             service user, and set auth-users-file"
        );
    }
    let cli_or_file_user_set = cli.user.is_some() || file.user.is_some();
    let config = Config {
        host: cli
            .host
            .or(file.host)
            .unwrap_or_else(|| "0.0.0.0".to_string()),
        port: cli.port.or(file.port).unwrap_or(DEFAULT_PORT),
        submission_port: cli.submission_port.or(file.submission_port),
        submissions_port: cli.submissions_port.or(file.submissions_port),
        domain: cli
            .domain
            .or(file.domain)
            .ok_or_else(|| anyhow::anyhow!("a domain is required (--domain or the config file)"))?,
        max_data_bytes: cli
            .max_data_bytes
            .or(file.max_data_bytes)
            .unwrap_or(DEFAULT_MAX_DATA_BYTES),
        // 0 disables either limit.
        mailbox_quota_bytes: Some(
            cli.mailbox_quota_bytes
                .or(file.mailbox_quota_bytes)
                .unwrap_or(DEFAULT_MAILBOX_QUOTA_BYTES),
        )
        .filter(|&q| q > 0),
        min_free_disk_bytes: Some(
            cli.min_free_disk_bytes
                .or(file.min_free_disk_bytes)
                .unwrap_or(DEFAULT_MIN_FREE_DISK_BYTES),
        )
        .filter(|&q| q > 0),
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
        auth_users_file: cli.auth_users_file.or(file.auth_users_file),
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
    };
    check_listeners(&config)?;
    Ok(config)
}

/// Check that the submission listeners in `config` can work: each needs
/// a TLS certificate and key and a credentials file (AUTH is what they
/// are for), and no two listeners may share a port.
///
/// # Errors
///
/// A submission port without TLS or without `auth-users-file`, or a
/// port used twice.
pub(crate) fn check_listeners(config: &Config) -> Result<()> {
    let submission = [
        ("submission-port", config.submission_port),
        ("submissions-port", config.submissions_port),
    ];
    for (name, port) in submission {
        if port.is_none() {
            continue;
        }
        if config.tls_cert.is_none() || config.tls_key.is_none() {
            anyhow::bail!("{name} needs tls-cert and tls-key");
        }
        if config.auth_users_file.is_none() {
            anyhow::bail!("{name} needs auth-users-file (submission requires AUTH)");
        }
    }
    let mut ports = vec![("port", config.port)];
    ports.extend(submission.iter().filter_map(|&(n, p)| p.map(|p| (n, p))));
    for (i, (name, port)) in ports.iter().enumerate() {
        if let Some((other, _)) = ports[..i].iter().find(|(_, p)| p == port) {
            anyhow::bail!("{name} and {other} are both {port}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// `resolver-ca` resolves CLI > file > none; unset means public roots
    /// only.
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

    /// Production-safe defaults. Port 25 (2525 is
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
        assert_eq!(resolved.mailbox_quota_bytes, Some(10 * 1024 * 1024));
        assert_eq!(resolved.min_free_disk_bytes, Some(1024 * 1024 * 1024));
        assert_eq!(resolved.max_conn_duration_ms, 300_000);
        assert_eq!(resolved.max_connections, 100);
        assert_eq!(resolved.shutdown_grace_ms, 60_000);
        assert_eq!(resolved.user, None);
        assert_eq!(resolved.group, None);
        assert_eq!(resolved.submission_port, None);
        assert_eq!(resolved.submissions_port, None);
    }

    /// The storage limits resolve CLI > file > default, and 0 disables
    /// each.
    #[test]
    fn storage_limit_resolution() {
        use clap::Parser as _;
        let file = FileConfig {
            mailbox_quota_bytes: Some(5000),
            min_free_disk_bytes: Some(0),
            ..FileConfig::default()
        };
        let resolved = resolve_config(
            Args::parse_from(["mailserv", "--domain", "d.example"]),
            file.clone(),
        )
        .unwrap();
        assert_eq!(resolved.mailbox_quota_bytes, Some(5000));
        assert_eq!(resolved.min_free_disk_bytes, None, "0 disables the check");

        let resolved = resolve_config(
            Args::parse_from([
                "mailserv",
                "--domain",
                "d.example",
                "--mailbox-quota-bytes",
                "0",
                "--min-free-disk-bytes",
                "77",
            ]),
            file,
        )
        .unwrap();
        assert_eq!(resolved.mailbox_quota_bytes, None);
        assert_eq!(resolved.min_free_disk_bytes, Some(77));
    }

    /// Submission ports resolve CLI > file, and each needs TLS and a
    /// credentials file; no two listeners may share a port.
    #[test]
    fn submission_listener_requirements() {
        use clap::Parser as _;
        let resolve = |argv: &[&str], file: FileConfig| {
            let mut full = vec!["mailserv", "--domain", "d.example"];
            full.extend_from_slice(argv);
            resolve_config(Args::parse_from(full), file)
        };
        let tls = ["--tls-cert", "c.pem", "--tls-key", "k.pem"];
        let file = FileConfig {
            auth_users_file: Some("/etc/mailserv/users".into()),
            submissions_port: Some(465),
            ..FileConfig::default()
        };

        let ok = resolve(
            &[&tls[..], &["--submission-port", "587"]].concat(),
            file.clone(),
        )
        .unwrap();
        assert_eq!(ok.submission_port, Some(587));
        assert_eq!(ok.submissions_port, Some(465));

        let err = resolve(&["--submission-port", "587"], file.clone()).unwrap_err();
        assert!(
            err.to_string().contains("needs tls-cert and tls-key"),
            "{err}"
        );

        let no_auth = FileConfig {
            auth_users_file: None,
            ..file.clone()
        };
        let err = resolve(&tls, no_auth).unwrap_err();
        assert!(err.to_string().contains("needs auth-users-file"), "{err}");

        let err = resolve(&[&tls[..], &["--submission-port", "465"]].concat(), file).unwrap_err();
        assert!(err.to_string().contains("are both 465"), "{err}");
    }

    /// `auth-users-file` resolves CLI > file, and a config file that still
    /// uses the removed inline `auth-users` key is a startup error rather
    /// than AUTH silently turning off. The CLI flag no longer exists.
    #[test]
    fn auth_users_file_resolution() {
        use clap::Parser as _;
        let args = |extra: &[&str]| {
            let mut argv = vec!["mailserv", "--domain", "d.example"];
            argv.extend_from_slice(extra);
            Args::parse_from(argv)
        };
        let file: FileConfig = toml::from_str(r#"auth-users-file = "/etc/a""#).unwrap();
        let resolved = resolve_config(args(&[]), file.clone()).unwrap();
        assert_eq!(resolved.auth_users_file.as_deref(), Some("/etc/a"));
        let resolved = resolve_config(args(&["--auth-users-file", "/etc/b"]), file).unwrap();
        assert_eq!(resolved.auth_users_file.as_deref(), Some("/etc/b"));

        let old: FileConfig = toml::from_str(r#"auth-users = "alice:secret""#).unwrap();
        let err = resolve_config(args(&[]), old).unwrap_err().to_string();
        assert!(err.contains("auth-users-file"), "{err}");
        assert!(!err.contains("secret"), "never echoes the old value: {err}");

        assert!(Args::try_parse_from(["mailserv", "--auth-users", "a:b"]).is_err());
    }

    /// `user`, `group` and `shutdown-grace-ms` resolve CLI > file;
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
}
