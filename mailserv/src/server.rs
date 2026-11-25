//! The server: startup (TLS, DNS, AUTH, authority, spool and delivery),
//! the listeners and privilege drop, the accept loop and its connection
//! limits, signal handling (graceful shutdown, credentials reload), and
//! [`handle_connection`], which drives one session over its connection.

use anyhow::Result;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout_at, Instant};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::authority::RecipientResolver as _;
use crate::config::Config;
use crate::session::{ListenerMode, SessionConfig, UserSession, END_OF_DATA_DNS_DEADLINE};
use crate::tls::{build_tls_acceptor, load_resolver_ca, tls_handshake};
use crate::{auth, authority, delivery, fsutil, limit, privdrop, spool};
use smtp::SmtpSession as _;

/// How long past its `max-conn-duration-ms` deadline a connection task
/// may run before it is dropped. The session ends itself at the deadline
/// (at its next read); this only catches a task stuck in a write or a
/// handshake. It must exceed the longest end-of-data processing (the DNS
/// deadline plus storage), or the drop could fall between a spool commit
/// and its reply.
pub(crate) const CONNECTION_BACKSTOP_GRACE: Duration = Duration::from_secs(120);

/// Fast-path deliveries that may run at once, server-wide, after their
/// replies were sent. Beyond this the drain delivers.
pub(crate) const MAX_FAST_PATH_DELIVERIES: usize = 64;

/// How often the DNS client's metrics are logged.
pub(crate) const DNS_STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Log the metrics of DNS client `dns` once per [`DNS_STATS_INTERVAL`]
/// while it is being used, together with the counters of `dns_limit`
/// (DESIGN §9: the signals for sizing `--dns-connections` and
/// `--max-dns-per-ip`). Counters are cumulative; the peaks cover the
/// interval just ended. Quiet intervals (no new queries) are skipped.
/// Runs forever; spawn it as a task.
pub(crate) async fn report_dns_stats(dns: Arc<dns::DnsClient>, dns_limit: Arc<limit::DnsLimiter>) {
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

/// Run the server with `config`: build the TLS acceptor and DNS client,
/// load the credentials, bind the listeners (dropping root privileges
/// right after), open the authority, spool and maildirs, start the drain
/// and DNS-stats tasks, then accept connections until SIGTERM/SIGINT and
/// shut down gracefully. SIGHUP reloads the credentials file.
///
/// # Errors
///
/// Any startup failure: an unreadable or invalid TLS certificate,
/// resolver CA, credentials or authority file; a failed bind or privilege
/// drop; or a spool or maildir that cannot be created. Once accepting,
/// per-connection errors are logged, not returned.
pub(crate) async fn run(config: Config) -> Result<()> {
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

    // One shared DNS client for the whole process: pipelined DNS-over-TLS
    // connections and a TTL result cache serve SPF, DKIM, and DMARC
    // alike. Built before the listener binds, so a bad --resolver-ca file
    // stops startup instead of surfacing as DNS failures in sessions. The
    // CA is added to the public roots, so public resolvers keep working
    // with it set.
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

    // AUTH credentials are read here, while still privileged, so the file
    // can be root-owned and private.
    let auth = match &config.auth_users_file {
        Some(path) => {
            let path = std::path::Path::new(path);
            let auth = auth::AuthConfig::load(path, config.auth_senders.as_deref())?;
            info!(
                file = %path.display(),
                "AUTH PLAIN/LOGIN available ({} user(s))",
                auth.user_count()
            );
            log_login_warnings(&auth);
            Some(Arc::new(auth))
        }
        _ => {
            if config
                .auth_senders
                .as_deref()
                .is_some_and(|s| !s.is_empty())
            {
                anyhow::bail!("--auth-senders needs --auth-users-file");
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

    // Privileges. Decide before binding, so a misconfiguration (root
    // without --user, an unknown user) stops startup without touching the
    // port.
    let target = match &config.user {
        Some(user) => Some(privdrop::lookup(user, config.group.as_deref())?),
        None => None,
    };
    let drop_to = privdrop::plan(privdrop::effective_uid(), target)?;

    // Bind while still privileged: ports 25, 465 and 587 need root or
    // CAP_NET_BIND_SERVICE. The TLS key, resolver CA and config file were
    // read above, also with the starting privileges.
    let listener = bind(&config.host, config.port).await?;
    let submission = match config.submission_port {
        Some(port) => Some(bind(&config.host, port).await?),
        None => None,
    };
    let submissions = match config.submissions_port {
        Some(port) => Some(bind(&config.host, port).await?),
        None => None,
    };
    if auth.is_some() && submission.is_none() && submissions.is_none() {
        warn!(
            "auth-users-file is set but no submission port is: AUTH is only offered on \
             submission-port/submissions-port, so these logins can't be used"
        );
    }

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

    // A SIGHUP reload re-reads the credentials file as the current user;
    // say now if that will fail, rather than at the first revocation.
    if let Some(path) = &config.auth_users_file {
        if std::fs::File::open(path).is_err() {
            warn!(
                file = %path,
                "the credentials file isn't readable after dropping privileges, so SIGHUP \
                 can't reload it (logins change only on restart); make it root:<service group> \
                 mode 0640 to allow reloads"
            );
        }
    }

    // The recipient authority: a JSON file when configured — the
    // console's publishing format, hot-reloaded — otherwise the static
    // fallback for --local-domains (every local-part accepts).
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

    // Local disk spool, no payload encryption (`spool::PayloadEncryptor`
    // is the seam for user-held keys; none is configured).
    let disk_spool = Arc::new(spool::DiskSpool::open(&config.spool_dir, None)?);
    let spool: Arc<dyn spool::SpoolWriter> = disk_spool.clone();
    info!(backend = spool.name(), spool_dir = %config.spool_dir, "spool ready");

    let sink: Arc<dyn delivery::DeliverySink> =
        Arc::new(delivery::MaildirSink::open(&config.maildir_dir)?);
    info!(backend = sink.name(), maildir_dir = %config.maildir_dir, "delivery ready");

    // Storage paths: say where mail really goes, and flag setups that
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
    // still failing after the queue lifetime; each pass also sweeps old
    // uncommitted crash debris from the spool. The first pass runs
    // immediately at startup (recovering anything queued before a
    // restart); later passes run every 60 s. Delivery failures inside a
    // pass leave the message queued; a spool I/O error ends that pass,
    // is logged here, and the next pass retries.
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
                    move || delivery::drain_once(&*spool, &*sink)
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
                            + stats.debris_removed
                            > 0 =>
                    {
                        info!(
                            delivered = stats.delivered,
                            retrying = stats.retrying,
                            deferred = stats.deferred,
                            dead_lettered = stats.dead_lettered,
                            debris_removed = stats.debris_removed,
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
    // Per-source-IP share of DNS work (DESIGN §9): one client must
    // not fill the shared resolver capacity with its own slow lookups.
    let dns_limit = Arc::new(limit::DnsLimiter::new(
        config.max_dns_per_ip,
        limit::DNS_LIMIT_WAIT,
    ));
    tokio::spawn(report_dns_stats(dns_client.clone(), dns_limit.clone()));

    // Connection caps: a server-wide semaphore plus per-IP
    // concurrency and connection-rate budgets, enforced in the accept
    // loop before any session work.
    let limiter = Arc::new(limit::ConnectionLimiter::new(
        config.max_conn_per_ip,
        config.max_conn_rate_per_ip,
        Duration::from_secs(60),
    ));
    let global_capacity = Arc::new(tokio::sync::Semaphore::new(config.max_connections as usize));
    // Refusals must never run inline in the accept loop: each can take
    // up to ~2.5 s (the courtesy write + drain), so an attacker holding
    // the connection budgets could stall every subsequent accept and
    // starve legitimate senders almost for free. Refusals run in spawned
    // tasks, capped by this small permit pool; when it is exhausted the
    // socket is simply closed.
    let refuse_capacity = Arc::new(tokio::sync::Semaphore::new(32));
    let fast_path = Arc::new(tokio::sync::Semaphore::new(MAX_FAST_PATH_DELIVERIES));

    info!(
        host = %config.host,
        port = config.port,
        submission_port = ?config.submission_port,
        submissions_port = ?config.submissions_port,
        domain = %config.domain,
        resolver = %config.resolver,
        spool_dir = %config.spool_dir,
        max_connections = config.max_connections,
        max_conn_per_ip = config.max_conn_per_ip,
        max_conn_rate_per_ip = config.max_conn_rate_per_ip,
        "listening"
    );

    // Graceful shutdown: SIGTERM or SIGINT stops the accept loop;
    // sessions are told through `shutdown_rx` (see `shutdown_signal`).
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut signals = ShutdownSignals::new()?;
    // SIGHUP reloads the credentials file. Installing the handler also
    // stops SIGHUP from terminating the process.
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    let signal = loop {
        // A transient accept error (e.g. EMFILE under load) must not
        // terminate the server; back off briefly and keep going.
        // All listeners share one loop, so they share the connection
        // limits below and stop together on shutdown.
        let (accepted, mode) = tokio::select! {
            biased;
            signal = signals.recv() => break signal,
            Some(()) = hup.recv() => {
                reload_credentials(auth.clone());
                continue;
            }
            accepted = listener.accept() => (accepted, ListenerMode::Mx),
            accepted = accept_on(submission.as_ref()) => (accepted, ListenerMode::Submission),
            accepted = accept_on(submissions.as_ref()) => (accepted, ListenerMode::Submissions),
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
        let deadline = Instant::now() + Duration::from_millis(config.max_conn_duration_ms);
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
            deadline: Some(deadline),
            fast_path: Arc::clone(&fast_path),
        };

        tokio::spawn(async move {
            // The session enforces `deadline` itself, between reads, so a
            // message is never cut off between its spool commit and its
            // reply. This outer limit only stops a task that is stuck
            // (a TLS handshake or a reply write that never completes).
            let result = timeout_at(
                deadline + CONNECTION_BACKSTOP_GRACE,
                handle_connection(stream, acceptor, max_read_ms, session_cfg, mode),
            )
            .await;

            // The spawned task's outcome must not be silently discarded.
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!(peer = %peer, error = %e, "connection handler failed"),
                Err(_) => warn!(peer = %peer, "connection stuck past its duration limit; dropped"),
            }

            // Free the connection's capacity, whoever ended it.
            drop(permit);
            limiter.release(ip).await;
        });
    };

    // Graceful shutdown. Stop accepting: closing the listener makes
    // the kernel refuse new connections, and other MXs or a later retry
    // take the mail. Then tell every session: idle ones get 421 now, and
    // sessions mid-message finish it, get their reply, then the 421.
    drop(listener);
    drop(submission);
    drop(submissions);
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
pub(crate) struct ShutdownSignals {
    /// The SIGTERM stream.
    term: tokio::signal::unix::Signal,
    /// The SIGINT stream.
    int: tokio::signal::unix::Signal,
}

impl ShutdownSignals {
    /// Install the handlers.
    ///
    /// # Errors
    ///
    /// The OS refuses to install a signal handler.
    fn new() -> Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(ShutdownSignals {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
        })
    }

    /// Wait for the next SIGTERM or SIGINT.
    ///
    /// Returns the signal's name (`"SIGTERM"` or `"SIGINT"`).
    async fn recv(&mut self) -> &'static str {
        tokio::select! {
            _ = self.term.recv() => "SIGTERM",
            _ = self.int.recv() => "SIGINT",
        }
    }
}

/// Warn about logins in `auth` that are configured but weak or unusable:
/// no sender grants (they can authenticate but not send), or a hash below
/// OWASP's minimum cost.
pub(crate) fn log_login_warnings(auth: &auth::AuthConfig) {
    let unable = auth.users_without_grants();
    if !unable.is_empty() {
        warn!(
            users = ?unable,
            "AUTH users without --auth-senders grants can authenticate but not send"
        );
    }
    let weak = auth.weak_hash_users();
    if !weak.is_empty() {
        warn!(
            users = ?weak,
            "AUTH password hashes below OWASP's minimum argon2id cost; \
             re-hash with `mailserv hash-password`"
        );
    }
}

/// Handle a SIGHUP: reload the credentials in `auth` on the blocking
/// pool, in a spawned task so the accept loop never waits, and log the
/// outcome. A failed reload keeps the current logins. Without AUTH
/// configured there is nothing to reload.
pub(crate) fn reload_credentials(auth: Option<Arc<auth::AuthConfig>>) {
    let Some(auth) = auth else {
        info!("SIGHUP: no auth-users-file configured; nothing to reload");
        return;
    };
    tokio::spawn(async move {
        let reloaded = tokio::task::spawn_blocking({
            let auth = Arc::clone(&auth);
            move || auth.reload()
        })
        .await;
        match reloaded {
            Ok(Ok(summary)) => {
                info!(
                    users = summary.users,
                    added = ?summary.added,
                    removed = ?summary.removed,
                    "credentials reloaded"
                );
                if !summary.orphaned_grants.is_empty() {
                    warn!(
                        users = ?summary.orphaned_grants,
                        "--auth-senders grants for logins no longer in the credentials file \
                         are inert; remove them before the next restart (they are a startup error)"
                    );
                }
                log_login_warnings(&auth);
            }
            Ok(Err(e)) => {
                error!(error = %format!("{e:#}"), "credentials reload failed; keeping the current logins");
            }
            Err(e) => error!(error = %e, "credentials reload panicked; keeping the current logins"),
        }
    });
}

/// Hand the refused connection `stream` to a spawned task that sends
/// `reply` and closes it (see [`refuse`]). Returns immediately, so a
/// burst of refusals never stalls the accept loop. Bounded by the
/// `capacity` permit pool; when it is saturated the socket is closed
/// without the courtesy reply.
pub(crate) async fn refuse_async(
    stream: TcpStream,
    reply: &[u8],
    capacity: &Arc<tokio::sync::Semaphore>,
) {
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

/// Answer the refused connection `stream` with the SMTP error `reply`
/// and close it. The whole exchange is capped at 2 s: the write is capped so a client that never reads cannot stall; afterwards
/// the socket is drained briefly so the client can read the reply before
/// close — dropping a socket with unread inbound data makes Linux send
/// RST, which discards the client's pending receive buffer (it would
/// never see the 421). Failures are ignored — the connection is being
/// dropped anyway. Runs only in spawned tasks (see [`refuse_async`]).
pub(crate) async fn refuse(stream: TcpStream, reply: &[u8]) {
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

/// Bind a TCP listener on `host`:`port`.
///
/// # Errors
///
/// The address can't be bound (in use, or a privileged port without the
/// privilege); the message names the address.
pub(crate) async fn bind(host: &str, port: u16) -> Result<TcpListener> {
    TcpListener::bind(format!("{host}:{port}"))
        .await
        .map_err(|e| anyhow::anyhow!("cannot listen on {host}:{port}: {e}"))
}

/// Accept the next connection on `listener`, or wait forever when there
/// is none (a disabled listener in the accept loop's `select!`).
///
/// # Errors
///
/// As [`TcpListener::accept`].
pub(crate) async fn accept_on(
    listener: Option<&TcpListener>,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    match listener {
        Some(l) => l.accept().await,
        None => std::future::pending().await,
    }
}

/// Returns `peer` with an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`,
/// what a dual-stack `[::]` listener reports for IPv4 clients) turned back
/// into plain IPv4; other addresses are unchanged. Without this, SPF `ip4:`/`a`/`mx`
/// never match IPv4 senders, and an IPv4 client's per-IP limits, logs and
/// `Received:` show the mapped form.
pub(crate) fn canonical_peer(peer: SocketAddr) -> SocketAddr {
    SocketAddr::new(peer.ip().to_canonical(), peer.port())
}

/// Serve the connection `stream`, which arrived on a `mode` listener,
/// with the TLS configuration `acceptor`. Each read may take at most
/// `max_read_ms`; `cfg` configures the session. The session record is
/// logged when the connection ends.
///
/// On an implicit-TLS listener ([`ListenerMode::Submissions`]) the TLS
/// handshake comes first and the whole session runs over TLS. Otherwise
/// the protocol loop runs over the plaintext stream, pauses for the TLS
/// handshake when the policy accepts STARTTLS, and resumes over TLS.
/// A failed or timed-out handshake ends the connection quietly (`Ok`).
///
/// # Errors
///
/// The peer address is unavailable, an implicit-TLS listener has no
/// acceptor, the protocol loop fails (I/O error), or the session record
/// cannot be serialized.
pub(crate) async fn handle_connection(
    stream: TcpStream,
    acceptor: Option<Arc<TlsAcceptor>>,
    max_read_ms: u64,
    cfg: SessionConfig,
    mode: ListenerMode,
) -> Result<()> {
    let peer = canonical_peer(stream.peer_addr()?);
    let implicit_tls = mode == ListenerMode::Submissions;
    let mut session = UserSession::new(peer, acceptor.is_some() && !implicit_tls, &cfg);
    session.mode = mode;
    let mut session_state = smtp::SessionState::default();

    if implicit_tls {
        let Some(acceptor) = acceptor else {
            anyhow::bail!("implicit-TLS listener without a TLS acceptor");
        };
        let Some(tls) = tls_handshake(&acceptor, stream, peer).await else {
            return Ok(());
        };
        // TLS from the first byte: the banner goes out over TLS.
        session.tls_established().await;
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
    } else {
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
                // Unreachable: the policy only upgrades when an acceptor
                // was provided.
                anyhow::bail!("STARTTLS accepted without a TLS acceptor");
            };
            // Any pipelined plaintext after the STARTTLS command is
            // discarded with the read buffer (RFC 3207 Section 4.1).
            let Some(tls) = tls_handshake(&acceptor, stream.into_inner(), peer).await else {
                return Ok(());
            };

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
    }

    info!(
        tls = session.tls_active,
        messages = session.message_count,
        "{}",
        serde_json::to_string(&session)?
    );
    Ok(())
}

#[cfg(test)]
mod tests;
