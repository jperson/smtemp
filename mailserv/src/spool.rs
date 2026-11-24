//! Disk spool: durable staging of accepted messages.
//!
//! On end-of-data acceptance the session writes the raw message plus its
//! envelope/verdict metadata to a [`SpoolWriter`] backend, and the SMTP
//! `250` is only returned after a successful write — accepted mail is
//! never silently dropped by a failed write. The default backend is
//! [`DiskSpool`], a maildir-style queue directory: everything is written
//! under `tmp/` first, fsynced, and then renamed into `new/`, with the
//! metadata file renamed **last**. A `{id}.json` in `new/` is therefore
//! the commit point: a payload without metadata is an incomplete write
//! from a crashed process, and [`DiskSpool::list`] (so the drain) ignores
//! it.
//!
//! [`SpoolWriter`] abstracts writes only: the drain's read side (list,
//! load, record attempt, remove, dead-letter) uses [`DiskSpool`] directly,
//! so a second backend needs that split out first. Payloads can pass
//! through an optional [`PayloadEncryptor`] before any bytes reach storage.
//! Metadata stays plaintext so the queue can always be routed and expired.

use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

use crate::{DkimSummary, DmarcSummary};

/// Shared removal body for [`DiskSpool::remove`] and
/// [`DiskSpool::remove_committed`]: remove `meta_path` first, then
/// `payload_path` and `attempts_path`.
///
/// Missing files are tolerated (a concurrent drain pass may have removed
/// the message already), and failures removing the payload or sidecar
/// are ignored: once the metadata is gone they are crash debris.
///
/// # Errors
///
/// Removing the metadata file fails for any reason other than it not
/// existing.
fn remove_committed_at(meta_path: &Path, payload_path: &Path, attempts_path: &Path) -> Result<()> {
    match std::fs::remove_file(meta_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("cannot remove {}", meta_path.display()));
        }
    }
    let _ = std::fs::remove_file(payload_path);
    let _ = std::fs::remove_file(attempts_path);
    Ok(())
}

/// Storage backend for the message queue.
///
/// Methods are deliberately **blocking** (fsync now, object-storage
/// uploads later); callers run them on a blocking thread pool. The
/// returned queue ID must be unique per backend and stable for the
/// lifetime of the stored message — it is the storage key, the log
/// correlation ID, and (later) the idempotency key for replication.
pub trait SpoolWriter: Send + Sync {
    /// Returns the backend name for logs and metadata (e.g. `"disk"`).
    fn name(&self) -> &str;

    /// Durably store one accepted message: its `meta`data (the backend
    /// fills in [`SpoolMeta::queue_id`]) and the raw `payload` as
    /// received.
    ///
    /// Returns the new queue ID once the message is committed.
    ///
    /// # Errors
    ///
    /// The message could not be stored. On error no complete message may
    /// be observable through the backend (partial staging files are
    /// acceptable debris, a committed message is not). Callers treat
    /// `Err` as a temporary failure and refuse the message with `451`.
    fn write(&self, meta: SpoolMeta, payload: &[u8]) -> Result<String>;

    /// Remove the fully handled message `queue_id` from the backend (all
    /// recipients delivered).
    ///
    /// Removing a queue ID that no longer exists is **not** an error —
    /// the inline delivery fast path and the drain loop race, and either
    /// may remove first.
    ///
    /// # Errors
    ///
    /// Removal genuinely fails (I/O error); the message then stays
    /// queued and is retried later.
    fn remove(&self, queue_id: &str) -> Result<()>;
}

/// Encrypts a message payload before it reaches the spool backend.
///
/// The plaintext never touches storage: the backend stores exactly the
/// bytes `encrypt` returns. Decryption is *not* part of this trait: with
/// user-held keys the server can't decrypt. The trait seals the payload
/// once per message and has no recipient parameter.
///
/// Footgun: production configures no encryptor, and two paths assume
/// plaintext. The drain builds each delivery copy by *prepending*
/// plaintext trace headers to the stored payload, which would corrupt a
/// sealed one. The session's fast path delivers the plaintext copy
/// directly. Both must change before an encryptor is configured.
pub trait PayloadEncryptor: Send + Sync {
    /// Returns the identifier stored in the message metadata (algorithm +
    /// key id) so readers can tell how a payload was sealed and which key
    /// rotation generation applies.
    fn id(&self) -> String;

    /// Seal `payload`.
    ///
    /// Returns the bytes to store in place of the plaintext.
    ///
    /// # Errors
    ///
    /// Encryption cannot be performed (e.g. key unavailable); the message
    /// is then refused with a temporary error rather than stored in the
    /// clear.
    fn encrypt(&self, payload: &[u8]) -> Result<Vec<u8>>;
}

/// One accepted recipient with its authority-resolved routing target. The
/// identity is resolved at RCPT time and travels with the message through
/// the queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct SpoolRcpt {
    /// Envelope address exactly as the client sent it (used for the
    /// `for <...>` clause of the generated `Received:` header).
    pub address: String,
    /// Routing mailbox chosen by the authority: the addressed mailbox
    /// itself, or the designated inbox under catch-all. This is where
    /// delivery goes.
    pub mailbox: String,
    /// Owning account (platform user), when the authority knows one.
    pub user: Option<String>,
    /// Public key registered for this mailbox. Carried, not used yet.
    pub public_key: Option<String>,
    /// Key-rotation generation for [`SpoolRcpt::public_key`].
    pub key_generation: Option<u32>,
}

/// Envelope and verdict metadata for one accepted message.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SpoolMeta {
    /// Set by the backend during [`SpoolWriter::write`]; the queue
    /// identity of this message.
    pub queue_id: String,
    /// The SMTP session that accepted the message.
    pub session_id: String,
    /// The server's own domain for this connection (the `by` clause of
    /// the `Received:` header generated at delivery).
    pub server_domain: String,
    /// RFC 3339 reception timestamp.
    pub received_at: String,
    /// The connected peer (`ip:port`).
    pub peer: String,
    /// HELO/EHLO identity, if given.
    pub helo: Option<String>,
    /// Envelope sender, brackets removed; `Some("")` for the null sender.
    /// Always set for a spooled message (a transaction cannot reach DATA
    /// without an accepted MAIL FROM).
    pub mail_from: Option<String>,
    /// Accepted envelope recipients with their authority-resolved
    /// routing targets.
    pub rcpt_to: Vec<SpoolRcpt>,
    /// SPF verdict for the MAIL FROM identity; `None` for authenticated
    /// submissions, where SPF is skipped.
    pub spf_result: Option<String>,
    /// SPF verdict for the HELO/EHLO identity.
    pub spf_helo: Option<String>,
    /// Per-signature DKIM verdicts for this message.
    pub dkim: Vec<DkimSummary>,
    /// DMARC verdict, if a From-domain was determinable.
    pub dmarc: Option<DmarcSummary>,
    /// Authenticated submitter, if any.
    pub authenticated: Option<String>,
    /// Whether the message arrived over TLS.
    pub tls_active: bool,
    /// Plaintext payload size in bytes (the size the SMTP client sent,
    /// independent of any encryption applied at rest).
    pub message_size: usize,
    /// [`PayloadEncryptor::id`] of the provider that sealed the payload,
    /// or None when stored in the clear.
    pub encryption: Option<String>,
}

/// Maildir-style disk queue: the default [`SpoolWriter`].
///
/// Layout under the root directory:
/// - `tmp/` — staging; in-progress writes, fsynced before rename.
/// - `new/` — committed messages: `{queue_id}.eml` (payload, possibly
///   ciphertext) plus `{queue_id}.json` (metadata, always plaintext).
///
/// Writes seal the payload with the configured [`PayloadEncryptor`] (if
/// any) before the first byte reaches disk. Payload and metadata are each
/// written under `tmp/` and fsynced, then renamed into `new/` — metadata
/// last. The metadata rename is the commit point, so a `.eml` without
/// its `.json` in `new/` is debris from a crashed write, never a valid
/// message.
///
/// Known simplifications versus a fully hardened production queue (no
/// write-ahead journal, single-disk assumption, best-effort rollback on
/// error paths) are deliberate.
#[derive(Clone)]
pub struct DiskSpool {
    /// Staging area: in-progress writes land here and are fsynced before
    /// being renamed into [`DiskSpool::new_dir`]. Leftover files here
    /// after a crash are incomplete writes.
    tmp: PathBuf,
    /// Committed area: a message is complete (and its ID valid) only
    /// when both `{id}.eml` and `{id}.json` are present here.
    new_dir: PathBuf,
    /// Payload encryptor applied before every write; None stores
    /// plaintext.
    encryptor: Option<Arc<dyn PayloadEncryptor>>,
}

impl std::fmt::Debug for DiskSpool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskSpool")
            .field("tmp", &self.tmp)
            .field("new_dir", &self.new_dir)
            .field(
                "encryptor",
                &self.encryptor.as_ref().map(|_| "<dyn PayloadEncryptor>"),
            )
            .finish()
    }
}

impl DiskSpool {
    /// Open (creating if needed) a queue directory at `root`, with
    /// `tmp/` and `new/` subdirectories, storing payloads encrypted by
    /// `encryptor` when given.
    ///
    /// Returns the ready-to-use spool.
    ///
    /// # Errors
    ///
    /// Either directory cannot be created (e.g. missing permissions, or
    /// the path exists as a regular file); the server should refuse to
    /// start rather than accept mail it cannot store.
    pub fn open(
        root: impl Into<PathBuf>,
        encryptor: Option<Arc<dyn PayloadEncryptor>>,
    ) -> Result<Self> {
        let root = root.into();
        let tmp = root.join("tmp");
        let new_dir = root.join("new");
        crate::fsutil::create_private_dir_all(&tmp)
            .with_context(|| format!("cannot create spool dir {}", tmp.display()))?;
        crate::fsutil::create_private_dir_all(&new_dir)
            .with_context(|| format!("cannot create spool dir {}", new_dir.display()))?;
        Ok(DiskSpool {
            tmp,
            new_dir,
            encryptor,
        })
    }

    /// Best-effort cleanup after a failed metadata write or commit for
    /// `queue_id`: remove the already renamed payload in `new/` and any
    /// leftover metadata staging file in `tmp/`. Errors are ignored by
    /// design — this runs on a failure path, and a payload without
    /// metadata is never a valid committed message.
    fn rollback(&self, queue_id: &str) {
        let _ = std::fs::remove_file(self.new_dir.join(format!("{queue_id}.eml")));
        let _ = std::fs::remove_file(self.tmp.join(format!("{queue_id}.json")));
    }

    /// List all committed messages, oldest queue ID first, with their parsed
    /// metadata and delivery-attempt record. Payloads are **not** read:
    /// [`QueuedMessage::load_payload`] loads one when the drain is about to
    /// deliver it. Mail can stay queued for days during an outage, and loading
    /// the whole backlog every pass would turn that into an out-of-memory
    /// crash.
    ///
    /// A malformed or incomplete entry (unreadable or unparseable
    /// metadata, a `.eml` without `.json` or the reverse) is skipped —
    /// that is crash debris, not a message. A missing or unreadable
    /// attempt sidecar counts as no attempts.
    ///
    /// # Errors
    ///
    /// The queue directory cannot be read or listed.
    pub fn list(&self) -> Result<Vec<QueuedMessage>> {
        let mut queued = Vec::new();
        for entry in std::fs::read_dir(&self.new_dir)
            .with_context(|| format!("cannot read spool dir {}", self.new_dir.display()))?
        {
            let path = entry.with_context(|| "cannot list spool dir")?.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let Some(queue_id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let payload_path = self.new_dir.join(format!("{queue_id}.eml"));
            let Ok(meta_bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(meta) = serde_json::from_slice::<SpoolMeta>(&meta_bytes) else {
                continue;
            };
            if !payload_path.exists() {
                continue;
            }
            let attempts_path = self.new_dir.join(format!("{queue_id}.attempts"));
            let record = std::fs::read_to_string(&attempts_path)
                .map(|s| AttemptRecord::parse(&s))
                .unwrap_or_default();
            queued.push(QueuedMessage {
                queue_id: queue_id.to_string(),
                meta,
                payload_path,
                meta_path: path,
                attempts_path,
                attempts: record.attempts,
                first_failure: record.first_failure,
                last_failure: record.last_failure,
            });
        }
        queued.sort_by(|a, b| a.queue_id.cmp(&b.queue_id));
        Ok(queued)
    }

    /// Record one failed delivery attempt for `queued` at `now` (Unix
    /// seconds), building on the attempt state `queued` was listed with.
    ///
    /// Returns the updated record. It is persisted in the `{id}.attempts`
    /// sidecar as `count first_failure last_failure`, so the retry schedule
    /// and the queue lifetime survive restarts. A missing sidecar means no
    /// prior attempts. A count-only sidecar keeps its count and starts the
    /// lifetime clock now.
    ///
    /// # Errors
    ///
    /// The sidecar cannot be written durably.
    pub fn record_attempt(&self, queued: &QueuedMessage, now: u64) -> Result<AttemptRecord> {
        let record = AttemptRecord {
            attempts: queued.attempts + 1,
            first_failure: Some(queued.first_failure.unwrap_or(now)),
            last_failure: Some(now),
        };
        write_durable(&queued.attempts_path, record.to_string().as_bytes())?;
        Ok(record)
    }

    /// Remove the fully handled message `queued` (payload, metadata,
    /// attempt sidecar) from the queue. Metadata is removed first: a
    /// half-removed message is crash debris, never a committed message.
    /// Missing files are tolerated — a concurrent drain pass may have
    /// removed the message already.
    ///
    /// # Errors
    ///
    /// The metadata file exists but cannot be removed.
    pub fn remove(&self, queued: &QueuedMessage) -> Result<()> {
        remove_committed_at(
            &queued.meta_path,
            &queued.payload_path,
            &queued.attempts_path,
        )
    }

    /// Remove a queued message by `queue_id` alone (used by the session's
    /// inline delivery fast path, which has no `QueuedMessage` handle).
    /// Same semantics as [`DiskSpool::remove`], tolerating a concurrent
    /// drain pass having removed it first.
    ///
    /// # Errors
    ///
    /// The metadata file exists but cannot be removed.
    pub fn remove_committed(&self, queue_id: &str) -> Result<()> {
        remove_committed_at(
            &self.new_dir.join(format!("{queue_id}.json")),
            &self.new_dir.join(format!("{queue_id}.eml")),
            &self.new_dir.join(format!("{queue_id}.attempts")),
        )
    }

    /// Move `queued`, which exhausted its delivery budget, to the
    /// `dead-letter/` directory under the spool root (created if needed),
    /// preserving its metadata, payload and attempt sidecar (when present)
    /// for operator inspection.
    ///
    /// # Errors
    ///
    /// The directory cannot be created or a file cannot be moved. The
    /// metadata moves first, so a partial failure leaves the message out
    /// of the queue.
    pub fn dead_letter(&self, queued: &QueuedMessage) -> Result<()> {
        let dead = self
            .new_dir
            .parent()
            .unwrap_or(Path::new("."))
            .join("dead-letter");
        crate::fsutil::create_private_dir_all(&dead)
            .with_context(|| format!("cannot create dead-letter dir {}", dead.display()))?;
        // Metadata first again: a dead-lettered message is "complete"
        // only with its metadata present.
        std::fs::rename(
            &queued.meta_path,
            dead.join(queued.meta_path.file_name().context("missing file name")?),
        )?;
        for path in [&queued.payload_path, &queued.attempts_path] {
            if path.exists() {
                std::fs::rename(
                    path,
                    dead.join(path.file_name().context("missing file name")?),
                )
                .with_context(|| format!("cannot move {} to dead-letter", path.display()))?;
            }
        }
        Ok(())
    }
}

/// One committed message in the queue, as returned by [`DiskSpool::list`].
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    /// Queue identity (also the file stem of the pair).
    pub queue_id: String,
    /// Parsed acceptance metadata.
    pub meta: SpoolMeta,
    /// Path of the payload file.
    pub payload_path: PathBuf,
    /// Path of the metadata file.
    pub meta_path: PathBuf,
    /// Path of the delivery-attempt sidecar (may not exist yet).
    pub attempts_path: PathBuf,
    /// Recorded failed delivery attempts (0 if none).
    pub attempts: u32,
    /// When the first failed attempt happened (Unix seconds), if recorded.
    /// The queue lifetime is measured from here.
    pub first_failure: Option<u64>,
    /// When the latest failed attempt happened (Unix seconds), if recorded.
    /// The next retry is due a backoff interval after this.
    pub last_failure: Option<u64>,
}

impl QueuedMessage {
    /// Read the payload from disk.
    ///
    /// Returns the bytes as stored (ciphertext if an encryptor was
    /// configured at write time).
    ///
    /// # Errors
    ///
    /// The payload file cannot be read.
    pub fn load_payload(&self) -> Result<Vec<u8>> {
        std::fs::read(&self.payload_path)
            .with_context(|| format!("cannot read {}", self.payload_path.display()))
    }
}

/// A message's delivery-attempt record, as kept in its `{id}.attempts`
/// sidecar: `count first_failure last_failure` (Unix seconds).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AttemptRecord {
    /// Failed delivery attempts so far.
    pub attempts: u32,
    /// Time of the first failed attempt.
    pub first_failure: Option<u64>,
    /// Time of the latest failed attempt.
    pub last_failure: Option<u64>,
}

impl AttemptRecord {
    /// Parse sidecar contents `s`; never fails.
    ///
    /// Unparseable fields are treated as absent (a count of 0): a damaged
    /// record makes a message due now and restarts its lifetime clock, so
    /// it can only delay giving up, never lose mail early.
    pub fn parse(s: &str) -> Self {
        let mut fields = s.split_ascii_whitespace();
        AttemptRecord {
            attempts: fields.next().and_then(|f| f.parse().ok()).unwrap_or(0),
            first_failure: fields.next().and_then(|f| f.parse().ok()),
            last_failure: fields.next().and_then(|f| f.parse().ok()),
        }
    }
}

impl std::fmt::Display for AttemptRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.attempts)?;
        if let (Some(first), Some(last)) = (self.first_failure, self.last_failure) {
            write!(f, " {first} {last}")?;
        }
        Ok(())
    }
}

impl SpoolWriter for DiskSpool {
    fn name(&self) -> &str {
        "disk"
    }

    fn write(&self, mut meta: SpoolMeta, raw: &[u8]) -> Result<String> {
        // Hex Unix seconds first, so lexical order (`list`) is roughly
        // arrival order; the UUID makes it unique.
        let queue_id = format!(
            "{:012x}.{}",
            jiff::Timestamp::now().as_second(),
            Uuid::new_v4().simple()
        );
        meta.queue_id = queue_id.clone();

        // Seal the payload first: an encryption failure means nothing
        // was written and there is nothing to roll back.
        let payload = match &self.encryptor {
            Some(e) => {
                let sealed = e.encrypt(raw).context("spool payload encryption failed")?;
                meta.encryption = Some(e.id());
                sealed
            }
            None => raw.to_vec(),
        };

        // Payload first. A failure here leaves at most a staging file in
        // tmp/ and nothing in new/.
        let payload_tmp = self.tmp.join(format!("{queue_id}.eml"));
        write_durable(&payload_tmp, &payload)?;
        std::fs::rename(&payload_tmp, self.new_dir.join(format!("{queue_id}.eml")))?;

        // Metadata second: its presence in new/ is the commit point. On
        // failure, roll back the payload already renamed into new/.
        let meta_tmp = self.tmp.join(format!("{queue_id}.json"));
        let meta_result = match serde_json::to_vec_pretty(&meta)
            .context("serialize spool metadata")
            .map(|mut v| {
                v.push(b'\n');
                v
            }) {
            Ok(bytes) => write_durable(&meta_tmp, &bytes),
            Err(e) => Err(e),
        };
        if let Err(e) = meta_result {
            self.rollback(&queue_id);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&meta_tmp, self.new_dir.join(format!("{queue_id}.json")))
            .with_context(|| format!("cannot commit spool metadata for {queue_id}"))
        {
            self.rollback(&queue_id);
            return Err(e);
        }

        // Best-effort directory fsync so the renames survive a power cut.
        // (sync_all on a directory fd is an fsync on Linux.)
        #[cfg(unix)]
        if let Ok(dir) = std::fs::File::open(&self.new_dir) {
            let _ = dir.sync_all();
        }

        Ok(queue_id)
    }

    fn remove(&self, queue_id: &str) -> Result<()> {
        self.remove_committed(queue_id)
    }
}

/// Write `bytes` to a new private file at `path` (truncating any
/// existing file), fsync it, and only then return: callers can rely on
/// the bytes surviving a crash once this returns `Ok`.
///
/// # Errors
///
/// The file cannot be created, written, or fsynced. The error message
/// names the path, and the caller decides whether partial state at
/// `path` needs cleanup.
fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = crate::fsutil::create_private_file(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("cannot write {}", path.display()))?;
    f.sync_all()
        .with_context(|| format!("cannot fsync {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A metadata record with plausible values; tests override the
    /// fields they care about via struct update syntax.
    fn sample_meta() -> SpoolMeta {
        SpoolMeta {
            queue_id: String::new(),
            session_id: "session-1".into(),
            server_domain: "mail.test".into(),
            received_at: jiff::Timestamp::now().to_string(),
            peer: "127.0.0.1:40000".into(),
            helo: Some("client.test".into()),
            mail_from: Some("sender@example.test".into()),
            rcpt_to: vec![SpoolRcpt {
                address: "user@example.org".into(),
                mailbox: "user@example.org".into(),
                user: Some("alice".into()),
                public_key: None,
                key_generation: None,
            }],
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

    /// XOR "encryption": deterministic, invertible, and obviously not
    /// real — just enough to prove the spool stores ciphertext and
    /// records the provider identity.
    struct XorEncryptor(u8);

    impl PayloadEncryptor for XorEncryptor {
        fn id(&self) -> String {
            format!("xor-{}", self.0)
        }

        fn encrypt(&self, payload: &[u8]) -> Result<Vec<u8>> {
            Ok(payload.iter().map(|b| b ^ self.0).collect())
        }
    }

    /// Always fails: models an unavailable key. The spool must refuse
    /// the message without writing anything.
    struct FailingEncryptor;

    impl PayloadEncryptor for FailingEncryptor {
        fn id(&self) -> String {
            "failing".into()
        }

        fn encrypt(&self, _payload: &[u8]) -> Result<Vec<u8>> {
            Err(anyhow::anyhow!("key unavailable"))
        }
    }

    /// Write one record and verify the maildir-style contract: both
    /// files committed under `new/`, `tmp/` empty, payload byte-exact,
    /// and metadata that parses and carries the queue identity.
    #[tokio::test]
    async fn write_is_durable_and_complete() {
        let dir = tempfile::tempdir().unwrap();
        let spool = DiskSpool::open(dir.path(), None).unwrap();

        let raw = b"Subject: test\r\n\r\nbody\r\n".to_vec();
        let queue_id = spool
            .write(
                SpoolMeta {
                    message_size: raw.len(),
                    ..sample_meta()
                },
                &raw,
            )
            .unwrap();

        // Both files committed under new/, nothing left in tmp/.
        let new = dir.path().join("new");
        let mut names: Vec<String> = Vec::new();
        let mut rd = tokio::fs::read_dir(&new).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        assert_eq!(
            names,
            vec![format!("{queue_id}.eml"), format!("{queue_id}.json")]
        );
        let mut tmp_names = Vec::new();
        let mut rd = tokio::fs::read_dir(dir.path().join("tmp")).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            tmp_names.push(e.file_name().to_string_lossy().into_owned());
        }
        assert!(tmp_names.is_empty(), "tmp/ must be empty: {tmp_names:?}");

        // Payload is byte-exact.
        let stored = tokio::fs::read(new.join(format!("{queue_id}.eml")))
            .await
            .unwrap();
        assert_eq!(stored, raw);

        // Metadata parses and carries the queue identity.
        let meta: serde_json::Value = serde_json::from_slice(
            &tokio::fs::read(new.join(format!("{queue_id}.json")))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(meta["queue_id"], queue_id.as_str());
        assert_eq!(meta["rcpt_to"][0]["address"], "user@example.org");
        assert_eq!(meta["spf_result"], "Pass");
        assert_eq!(meta["message_size"], raw.len());
        assert!(meta["encryption"].is_null());
    }

    /// With an encryptor configured, the stored payload is ciphertext
    /// (not the plaintext), and the metadata records the provider id
    /// while `message_size` keeps the plaintext length.
    #[tokio::test]
    async fn payload_is_encrypted_before_write() {
        let dir = tempfile::tempdir().unwrap();
        let spool = DiskSpool::open(dir.path(), Some(Arc::new(XorEncryptor(0x5a)))).unwrap();

        let raw = b"Subject: secret\r\n\r\nbody\r\n".to_vec();
        let queue_id = spool
            .write(
                SpoolMeta {
                    message_size: raw.len(),
                    ..sample_meta()
                },
                &raw,
            )
            .unwrap();

        let stored = tokio::fs::read(dir.path().join("new").join(format!("{queue_id}.eml")))
            .await
            .unwrap();
        let expected: Vec<u8> = raw.iter().map(|b| b ^ 0x5a).collect();
        assert_eq!(stored, expected, "stored bytes must be ciphertext");
        assert_ne!(stored, raw);

        let meta: serde_json::Value = serde_json::from_slice(
            &tokio::fs::read(dir.path().join("new").join(format!("{queue_id}.json")))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(meta["encryption"], "xor-90");
        assert_eq!(meta["message_size"], raw.len());
    }

    /// A failing encryptor aborts the write before any bytes reach
    /// disk: `Err` is returned and `new/` stays empty.
    #[tokio::test]
    async fn encryption_failure_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let spool = DiskSpool::open(dir.path(), Some(Arc::new(FailingEncryptor))).unwrap();

        let result = spool.write(sample_meta(), b"payload");
        assert!(result.is_err());

        for sub in ["new", "tmp"] {
            let mut names = Vec::new();
            let mut rd = tokio::fs::read_dir(dir.path().join(sub)).await.unwrap();
            while let Some(e) = rd.next_entry().await.unwrap() {
                names.push(e.file_name().to_string_lossy().into_owned());
            }
            assert!(names.is_empty(), "{sub}/ must be empty: {names:?}");
        }
    }

    /// Queue IDs must never collide: they are the storage key for the
    /// message pair and part of the delivery idempotency key.
    #[tokio::test]
    async fn queue_ids_are_unique() {
        let dir = tempfile::tempdir().unwrap();
        let spool = DiskSpool::open(dir.path(), None).unwrap();
        let raw: Vec<u8> = b"payload".to_vec();
        let a = spool.write(sample_meta(), &raw).unwrap();
        let b = spool.write(sample_meta(), &raw).unwrap();
        assert_ne!(a, b);
    }

    /// A failure after the payload rename must not leave an orphan
    /// committed payload: `rollback` removes it, so `new/` stays empty.
    #[tokio::test]
    async fn rollback_removes_committed_payload() {
        let dir = tempfile::tempdir().unwrap();
        let spool = DiskSpool::open(dir.path(), None).unwrap();

        // Simulate the post-rename failure state directly.
        let id = "deadbeef.test".to_string();
        tokio::fs::write(dir.path().join("new").join(format!("{id}.eml")), b"x")
            .await
            .unwrap();
        spool.rollback(&id);

        let mut names = Vec::new();
        let mut rd = tokio::fs::read_dir(dir.path().join("new")).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        assert!(names.is_empty(), "orphan payload left behind: {names:?}");
    }

    /// `remove` (the [`SpoolWriter`] contract) tolerates unknown and
    /// already-removed queue IDs: the inline fast path and the drain
    /// race, and either may remove first.
    #[tokio::test]
    async fn remove_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let spool = DiskSpool::open(dir.path(), None).unwrap();

        // Unknown queue ID: fine.
        SpoolWriter::remove(&spool, "no-such-message").unwrap();

        // Removing twice: the second call finds nothing and still succeeds.
        let raw = b"payload".to_vec();
        let id = spool.write(sample_meta(), &raw).unwrap();
        SpoolWriter::remove(&spool, &id).unwrap();
        assert!(spool.list().unwrap().is_empty());
        SpoolWriter::remove(&spool, &id).unwrap();
    }
}
