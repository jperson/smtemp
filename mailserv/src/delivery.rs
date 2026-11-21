//! Local delivery (Phase 7): the `DeliverySink` seam and the maildir
//! implementation, plus the message fixing (trace headers) applied when
//! a message leaves the queue and the drain/retry loop.
//!
//! Two layers:
//!
//! - [`DeliverySink`] — where mail goes. `MaildirSink` writes one
//!   message copy per recipient into a per-recipient maildir
//!   (`{root}/{domain}/{local}/new`). Implementations MUST be
//!   idempotent per (recipient, queue_id): the session attempts
//!   immediate delivery for low latency, and the drain loop re-attempts
//!   queued messages periodically — both paths may race, and a retry
//!   after partial failure must never duplicate mail.
//! - [`drain_once`] — the retry engine. Scans the committed spool,
//!   delivers each message to each recipient, removes fully delivered
//!   messages, counts failed attempts, and dead-letters messages that
//!   exceed the attempt budget.
//!
//! Message fixing happens in [`prepare_for_delivery`]: the final MTA
//! prepends `Return-Path` (RFC 5321 §4.5.2) and a `Received:` trace
//! header (RFC 5321 §4.4). The `for <rcpt>` clause names only the
//! recipient of this copy, so other envelope recipients stay private.

use anyhow::{Context, Result};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::spool::{DiskSpool, SpoolMeta};

/// Where accepted mail goes. Blocking methods (filesystem, and later
/// object storage); callers run them on a blocking thread pool.
pub trait DeliverySink: Send + Sync {
    /// Backend name for logs (e.g. `"maildir"`).
    fn name(&self) -> &str;

    /// Deliver one copy of `message` to `recipient`.
    ///
    /// Idempotency contract: for a given (recipient, queue_id) pair this
    /// MUST deliver at most once — calling again after success (or
    /// racing a concurrent attempt) returns `Ok` without duplicating
    /// mail. Returns `Err` on transient failure; the drain loop retries.
    fn deliver(&self, recipient: &str, queue_id: &str, message: &[u8]) -> Result<()>;
}

/// Maildir delivery: one maildir per recipient address, under
/// `{root}/{domain}/{local}/` with `tmp/`, `new/`, `cur/` subdirectories
/// (RFC 6158-style layout). Delivered files land in `new/` named
/// `{queue_id}.{sanitized-recipient}.eml`.
#[derive(Debug, Clone)]
pub struct MaildirSink {
    root: PathBuf,
}

impl MaildirSink {
    /// Open (creating if needed) the maildir root directory.
    ///
    /// Returns the ready-to-use sink on success. Returns `Err` if the
    /// root cannot be created; the server should refuse to start rather
    /// than accept mail it cannot deliver.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("cannot create maildir root {}", root.display()))?;
        Ok(MaildirSink { root })
    }
}

impl DeliverySink for MaildirSink {
    fn name(&self) -> &str {
        "maildir"
    }

    fn deliver(&self, recipient: &str, queue_id: &str, message: &[u8]) -> Result<()> {
        let (local, domain) = split_recipient(recipient)
            .with_context(|| format!("cannot deliver to malformed recipient {recipient:?}"))?;
        let maildir = self.root.join(&domain).join(&local);
        let tmp = maildir.join("tmp");
        let new = maildir.join("new");
        std::fs::create_dir_all(&tmp)
            .with_context(|| format!("cannot create maildir {}", maildir.display()))?;
        std::fs::create_dir_all(&new)
            .with_context(|| format!("cannot create maildir {}", maildir.display()))?;

        // Idempotency is per (recipient, queue_id) as *addresses* — case
        // variants of the same address must map to the same file, so the
        // tag is built from the normalized address.
        let normalized = format!("{local}@{domain}");
        let filename = format!("{queue_id}.{}.eml", sanitize(&normalized));
        let target = new.join(&filename);

        // Idempotency: an existing delivery of this (recipient, queue_id)
        // pair is success, not an error — the drain loop and the inline
        // fast path may both attempt the same copy.
        if target.exists() {
            return Ok(());
        }

        let staged = tmp.join(&filename);
        write_durable(&staged, message)?;
        std::fs::rename(&staged, &target)
            .with_context(|| format!("cannot commit delivery to {}", target.display()))?;
        Ok(())
    }
}

/// Split an address into (local-part, domain), both lowercased. Returns
/// `Err` for addresses without an `@`.
fn split_recipient(recipient: &str) -> Result<(String, String)> {
    let (local, domain) = recipient
        .rsplit_once('@')
        .ok_or_else(|| anyhow::anyhow!("no '@' in recipient {recipient:?}"))?;
    Ok((local.to_ascii_lowercase(), domain.to_ascii_lowercase()))
}

/// Filesystem-safe recipient tag for maildir filenames: alphanumerics,
/// `.`, `_`, `-` kept, everything else replaced with `_`.
fn sanitize(recipient: &str) -> String {
    recipient
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Write bytes to `path` and fsync before returning: callers can rely on
/// the bytes surviving a crash once this resolves.
///
/// Returns `Ok(())` once the bytes are durable on disk. Returns `Err`
/// if the file cannot be created, written, or fsynced — the error
/// message names the path.
fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f =
        std::fs::File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("cannot write {}", path.display()))?;
    f.sync_all()
        .with_context(|| format!("cannot fsync {}", path.display()))?;
    Ok(())
}

/// RFC 5322 date-time for the `Received:` header; falls back to the RFC
/// 3339 form if the strict formatting fails (still machine-parseable).
fn rfc5322_date(ts: jiff::Timestamp) -> String {
    let zoned = ts.to_zoned(jiff::tz::TimeZone::UTC);
    jiff::fmt::rfc2822::to_string(&zoned).unwrap_or_else(|_| ts.to_string())
}

/// Prepend the final-delivery trace headers to the raw message.
///
/// Produces one recipient's delivery copy: `Return-Path:` (envelope
/// sender in `<>`, `<>` for the null sender), then a `Received:` header
/// (from HELO/peer, by our domain, with ESMTP or ESMTPS, queue ID, `for`
/// this recipient only — RFC 5321 §4.4 says include `for` for a single
/// recipient so other envelope recipients are not disclosed), then the
/// original bytes verbatim.
pub fn prepare_for_delivery(meta: &SpoolMeta, recipient: &str, raw: &[u8]) -> Vec<u8> {
    let sender = match meta.mail_from.as_deref() {
        Some(addr) if !addr.is_empty() => format!("<{addr}>"),
        _ => "<>".to_string(),
    };
    // The peer is recorded as "ip:port"; the trace header convention is
    // the address in parentheses.
    let peer_ip = meta
        .peer
        .rsplit_once(':')
        .map(|(ip, _)| ip)
        .unwrap_or(&meta.peer);
    let protocol = if meta.tls_active { "ESMTPS" } else { "ESMTP" };
    let helo = meta.helo.as_deref().unwrap_or("unknown");
    let date = rfc5322_date(
        meta.received_at
            .parse()
            .unwrap_or(jiff::Timestamp::UNIX_EPOCH),
    );

    let mut out = Vec::with_capacity(raw.len() + 512);
    out.extend_from_slice(format!("Return-Path: {sender}\r\n").as_bytes());
    out.extend_from_slice(
        format!(
            "Received: from {helo} ({peer_ip})\r\n\tby {} ({}) with {protocol} id {}\r\n\tfor <{recipient}>; {date}\r\n",
            meta.server_domain,
            env!("CARGO_PKG_NAME"),
            meta.queue_id,
        )
        .as_bytes(),
    );
    out.extend_from_slice(raw);
    out
}

/// What one drain pass did, for logging.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DrainStats {
    /// Messages fully delivered to every recipient and removed from the
    /// queue.
    pub delivered: usize,
    /// Messages still queued after failed (or partially failed)
    /// delivery attempts.
    pub retrying: usize,
    /// Messages moved to the dead-letter directory after exhausting
    /// the attempt budget.
    pub dead_lettered: usize,
}

/// Retry budget per message before dead-lettering.
pub const MAX_DELIVERY_ATTEMPTS: u32 = 5;

/// One pass of the queue drain: attempt delivery of every committed
/// spool message, remove fully delivered ones, count attempts, and
/// dead-letter messages past [`MAX_DELIVERY_ATTEMPTS`].
///
/// Blocking; callers run it on a blocking thread pool. Per-message
/// failures are logged and counted, never fatal to the pass — the drain
/// is designed to run forever.
pub fn drain_once(spool: &DiskSpool, sink: &dyn DeliverySink) -> Result<DrainStats> {
    let mut stats = DrainStats::default();
    for queued in spool.list()? {
        let meta = &queued.meta;
        let mut all_delivered = true;
        for recipient in &meta.rcpt_to {
            let message = prepare_for_delivery(meta, recipient, &queued.payload);
            if let Err(e) = sink.deliver(recipient, &meta.queue_id, &message) {
                all_delivered = false;
                tracing::warn!(
                    queue_id = %meta.queue_id,
                    recipient = %recipient,
                    error = %e,
                    "delivery failed; message stays queued"
                );
            }
        }

        if all_delivered {
            spool.remove(&queued)?;
            stats.delivered += 1;
            tracing::info!(queue_id = %meta.queue_id, "message delivered and dequeued");
            continue;
        }

        let attempts = spool.record_attempt(&queued)?;
        if attempts >= MAX_DELIVERY_ATTEMPTS {
            spool.dead_letter(&queued)?;
            stats.dead_lettered += 1;
            tracing::warn!(
                queue_id = %meta.queue_id,
                attempts,
                "delivery attempts exhausted; message dead-lettered"
            );
        } else {
            stats.retrying += 1;
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spool::{SpoolMeta, SpoolWriter as _};

    /// A metadata record with plausible values; tests override the
    /// fields they care about via struct update syntax.
    fn sample_meta() -> SpoolMeta {
        SpoolMeta {
            queue_id: "00006b01.test.queue".into(),
            session_id: "session-1".into(),
            server_domain: "mail.test".into(),
            received_at: jiff::Timestamp::now().to_string(),
            peer: "127.0.0.1:40000".into(),
            helo: Some("client.test".into()),
            mail_from: Some("sender@example.test".into()),
            rcpt_to: vec!["user@example.org".into()],
            spf_result: Some("Pass".into()),
            spf_helo: None,
            dkim: Vec::new(),
            dmarc: None,
            authenticated: None,
            tls_active: false,
            message_size: 0,
            encryption: None,
        }
    }

    /// prepare_for_delivery prepends Return-Path and Received, keeps the
    /// raw bytes verbatim, and puts the per-copy recipient in the `for`
    /// clause only.
    #[test]
    fn delivery_copy_carries_trace_headers() {
        let raw = b"Subject: hi\r\n\r\nbody\r\n".to_vec();
        let meta = sample_meta();
        let copy = prepare_for_delivery(&meta, "user@example.org", &raw);
        let text = String::from_utf8(copy.clone()).unwrap();

        assert!(text.starts_with("Return-Path: <sender@example.test>\r\n"));
        assert!(text.contains("Received: from client.test (127.0.0.1)\r\n"));
        assert!(text.contains("\tby mail.test (mailserv) with ESMTP id "));
        assert!(text.contains("\tfor <user@example.org>; "));
        assert!(text.contains(&meta.queue_id));
        // Raw message follows verbatim after the trace headers.
        assert!(text.ends_with("Subject: hi\r\n\r\nbody\r\n"));

        // Null sender renders as the empty path.
        let mut null = sample_meta();
        null.mail_from = Some(String::new());
        let copy = prepare_for_delivery(&null, "user@example.org", &raw);
        assert!(String::from_utf8(copy)
            .unwrap()
            .starts_with("Return-Path: <>\r\n"));

        // TLS upgrades the protocol token.
        let mut tls = sample_meta();
        tls.tls_active = true;
        let copy = prepare_for_delivery(&tls, "user@example.org", &raw);
        assert!(String::from_utf8(copy)
            .unwrap()
            .contains(" with ESMTPS id "));
    }

    /// The maildir sink writes one copy per recipient under
    /// {root}/{domain}/{local}/new, and redelivery of the same
    /// (recipient, queue_id) is idempotent.
    #[tokio::test]
    async fn maildir_delivery_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let sink = MaildirSink::open(dir.path()).unwrap();

        let message = b"Return-Path: <s@x.test>\r\nReceived: ...\r\nSubject: hi\r\n".to_vec();
        sink.deliver("User@Example.ORG", "q-1", &message).unwrap();

        // Address is lowercased; file lands in new/ with a name built
        // from the normalized address, so case variants share one file.
        let delivered = dir
            .path()
            .join("example.org/user/new/q-1.user_example.org.eml");
        assert_eq!(std::fs::read(&delivered).unwrap(), message);

        // Redelivery (crash recovery, drain race) does not duplicate.
        sink.deliver("user@example.org", "q-1", &message).unwrap();
        let mut names = Vec::new();
        let mut rd = tokio::fs::read_dir(delivered.parent().unwrap())
            .await
            .unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(names, vec!["q-1.user_example.org.eml"]);
    }

    /// drain_once delivers every recipient copy of a queued message and
    /// removes it from the spool; a second pass finds nothing.
    #[tokio::test]
    async fn drain_delivers_and_dequeues() {
        let dir = tempfile::tempdir().unwrap();
        let spool = DiskSpool::open(dir.path().join("spool"), None).unwrap();
        let sink = MaildirSink::open(dir.path().join("maildir")).unwrap();

        let raw = b"Subject: hi\r\n\r\nbody\r\n".to_vec();
        spool
            .write(
                SpoolMeta {
                    rcpt_to: vec!["a@example.org".into(), "b@example.org".into()],
                    ..sample_meta()
                },
                &raw,
            )
            .unwrap();

        let stats = drain_once(&spool, &sink).unwrap();
        assert_eq!(
            stats,
            DrainStats {
                delivered: 1,
                retrying: 0,
                dead_lettered: 0
            }
        );

        // Both copies exist with trace headers; the queue is empty.
        for rcpt in ["a", "b"] {
            let path = dir.path().join(format!("maildir/example.org/{rcpt}/new"));
            let mut rd = tokio::fs::read_dir(&path).await.unwrap();
            let mut names = Vec::new();
            while let Some(e) = rd.next_entry().await.unwrap() {
                names.push(e.file_name().to_string_lossy().into_owned());
            }
            assert_eq!(names.len(), 1, "{path:?}: {names:?}");
            let bytes = std::fs::read(path.join(&names[0])).unwrap();
            assert!(bytes.starts_with(b"Return-Path: <sender@example.test>\r\n"));
        }
        assert!(spool.list().unwrap().is_empty());

        // Second pass is a no-op.
        let stats = drain_once(&spool, &sink).unwrap();
        assert_eq!(stats, DrainStats::default());
    }

    /// A sink that always fails: attempts accumulate in the sidecar and
    /// the message dead-letters after MAX_DELIVERY_ATTEMPTS passes.
    #[tokio::test]
    async fn drain_retries_then_dead_letters() {
        struct FailingSink;

        impl DeliverySink for FailingSink {
            fn name(&self) -> &str {
                "failing"
            }

            fn deliver(&self, _r: &str, _q: &str, _m: &[u8]) -> Result<()> {
                Err(anyhow::anyhow!("disk on fire"))
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let spool = DiskSpool::open(dir.path().join("spool"), None).unwrap();
        let sink = FailingSink;

        let raw = b"payload".to_vec();
        let queue_id = spool.write(sample_meta(), &raw).unwrap();

        for expected_attempts in 1..=(MAX_DELIVERY_ATTEMPTS - 1) {
            let stats = drain_once(&spool, &sink).unwrap();
            assert_eq!(
                stats,
                DrainStats {
                    delivered: 0,
                    retrying: 1,
                    dead_lettered: 0
                }
            );
            let queued = &spool.list().unwrap()[0];
            assert_eq!(queued.attempts, expected_attempts);
        }

        // Final failing pass dead-letters the message.
        let stats = drain_once(&spool, &sink).unwrap();
        assert_eq!(
            stats,
            DrainStats {
                delivered: 0,
                retrying: 0,
                dead_lettered: 1
            }
        );
        assert!(spool.list().unwrap().is_empty());

        // All three files preserved for operator inspection.
        let dead = dir.path().join("spool/dead-letter");
        let mut names = Vec::new();
        let mut rd = tokio::fs::read_dir(&dead).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        assert_eq!(
            names,
            vec![
                format!("{queue_id}.attempts"),
                format!("{queue_id}.eml"),
                format!("{queue_id}.json"),
            ]
        );
    }
}
