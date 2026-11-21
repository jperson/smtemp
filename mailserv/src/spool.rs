//! Disk spool: durable staging of accepted messages (Phase 7).
//!
//! On end-of-data acceptance the session writes the raw message plus its
//! envelope/verdict metadata to a [`SpoolWriter`] backend, and the SMTP
//! `250` is only returned after a successful write — accepted mail is
//! never silently dropped by a failed write. The default backend is
//! [`DiskSpool`], a maildir-style queue directory: everything is written
//! under `tmp/` first, fsynced, and then renamed into `new/`, with the
//! metadata file renamed **last**. A `{id}.json` in `new/` is therefore
//! the commit point: a payload without metadata is an incomplete write
//! from a crashed process and may be cleaned up by a future drain pass.
//!
//! Backends are pluggable (PLAN.md Phase 12, gap 9): `DiskSpool` is the
//! first implementation; an object-storage backend follows the same
//! trait. Payloads pass through an optional [`PayloadEncryptor`] at this
//! boundary — after SMTP processing, before any bytes reach storage — so
//! user-held-key encryption (Phase 12, gap 3) never leaks plaintext to
//! the storage layer. Metadata stays plaintext so the queue can always
//! be routed and expired.

use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

use crate::{DkimSummary, DmarcSummary};

/// Storage backend for the message queue.
///
/// Methods are deliberately **blocking** (fsync now, object-storage
/// uploads later); callers run them on a blocking thread pool. The
/// returned queue ID must be unique per backend and stable for the
/// lifetime of the stored message — it is the storage key, the log
/// correlation ID, and (later) the idempotency key for replication.
pub trait SpoolWriter: Send + Sync {
    /// Backend name for logs and metadata (e.g. `"disk"`).
    fn name(&self) -> &str;

    /// Durably store one accepted message.
    ///
    /// Returns `Ok(queue_id)` once the message is committed. Returns
    /// `Err` if the message could not be stored; on error no complete
    /// message may be observable through the backend (partial staging
    /// files are acceptable debris for a future drain pass, a committed
    /// message is not). Callers treat `Err` as a temporary failure and
    /// refuse the message with `451`.
    fn write(&self, meta: SpoolMeta, payload: &[u8]) -> Result<String>;
}

/// Encrypts a message payload before it reaches the spool backend.
///
/// The plaintext never touches storage: the backend stores exactly the
/// bytes `encrypt` returns. Decryption is *not* part of this trait —
/// with user-held keys (Phase 12) the server cannot decrypt, and the
/// front-end does it client-side.
///
/// Multi-recipient messages: the current trait seals the payload once
/// per message. The decided Phase 12 direction is a multi-recipient
/// container (PGP/age-style: one content key, wrapped per recipient —
/// see PLAN.md, gap 3); this trait widens to take the recipient key
/// set once the console authority supplies recipient keys.
pub trait PayloadEncryptor: Send + Sync {
    /// Identifier stored in the message metadata (algorithm + key id)
    /// so readers can tell how a payload was sealed and which key
    /// rotation generation applies.
    fn id(&self) -> String;

    /// Seal the payload. Returns `Err` if encryption cannot be
    /// performed (e.g. key unavailable); the message is then refused
    /// with a temporary error rather than stored in the clear.
    fn encrypt(&self, payload: &[u8]) -> Result<Vec<u8>>;
}

/// Envelope and verdict metadata for one accepted message.
#[derive(Debug, Clone, Serialize)]
pub struct SpoolMeta {
    /// Set by the backend during [`SpoolWriter::write`]; the queue
    /// identity of this message.
    pub queue_id: String,
    /// The SMTP session that accepted the message.
    pub session_id: String,
    /// RFC 3339 reception timestamp.
    pub received_at: String,
    /// The connected peer (`ip:port`).
    pub peer: String,
    /// HELO/EHLO identity, if given.
    pub helo: Option<String>,
    /// Envelope sender (None only for authenticated submissions, where
    /// SPF was skipped).
    pub mail_from: Option<String>,
    /// Accepted envelope recipients.
    pub rcpt_to: Vec<String>,
    /// SPF verdict for the MAIL FROM identity.
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
/// The metadata rename is the commit point, so a `.eml` without its
/// `.json` in `new/` is debris from a crashed write, never a valid
/// message.
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
    /// Returns the ready-to-use spool on success. Returns `Err` if
    /// either directory cannot be created (e.g. missing permissions, or
    /// the path exists as a regular file); the server should refuse to
    /// start rather than accept mail it cannot store.
    pub fn open(
        root: impl Into<PathBuf>,
        encryptor: Option<Arc<dyn PayloadEncryptor>>,
    ) -> Result<Self> {
        let root = root.into();
        let tmp = root.join("tmp");
        let new_dir = root.join("new");
        std::fs::create_dir_all(&tmp)
            .with_context(|| format!("cannot create spool dir {}", tmp.display()))?;
        std::fs::create_dir_all(&new_dir)
            .with_context(|| format!("cannot create spool dir {}", new_dir.display()))?;
        Ok(DiskSpool {
            tmp,
            new_dir,
            encryptor,
        })
    }

    /// Best-effort cleanup after a failed `write`: remove the already
    /// committed payload and any leftover metadata staging file so no
    /// orphan pair is left behind. Errors are ignored by design — this
    /// runs on a failure path, and leftover files are recoverable by a
    /// future drain pass (a payload without metadata is never a valid
    /// committed message).
    fn rollback(&self, queue_id: &str) {
        let _ = std::fs::remove_file(self.new_dir.join(format!("{queue_id}.eml")));
        let _ = std::fs::remove_file(self.tmp.join(format!("{queue_id}.json")));
    }
}

impl SpoolWriter for DiskSpool {
    fn name(&self) -> &str {
        "disk"
    }

    /// Durable write of one accepted message. Returns the queue ID.
    ///
    /// The payload is sealed by the configured [`PayloadEncryptor`]
    /// (if any) *before* the first write; an encryption failure aborts
    /// before any bytes reach disk, so there is nothing to roll back.
    ///
    /// Crash safety (per the Phase 7 plan): payload and metadata are
    /// each written under `tmp/` and fsynced, then renamed into `new/`
    /// — metadata last. Only the final rename is the commit; anything
    /// left in `tmp/` is an incomplete write. Known simplifications
    /// versus a fully hardened production queue (no write-ahead journal,
    /// single-disk assumption, best-effort rollback on error paths) are
    /// deliberate scope cuts tracked for later hardening.
    ///
    /// Returns `Ok(queue_id)` once both files are committed under
    /// `new/`. Returns `Err` if any step fails (encryption,
    /// serialization, I/O, fsync); in that case **no complete pair is
    /// ever committed** — `new/` never contains the `.json` marker, and
    /// partial state (a committed payload, leftover files in `tmp/`) is
    /// rolled back on a best-effort basis. Callers treat `Err` as a
    /// temporary failure and refuse the message with `451`; a crash
    /// between steps can still leave recoverable debris in `tmp/` or an
    /// uncommitted `.eml` in `new/` for a future drain pass to clean.
    fn write(&self, mut meta: SpoolMeta, raw: &[u8]) -> Result<String> {
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

        // Payload first.
        let payload_tmp = self.tmp.join(format!("{queue_id}.eml"));
        write_durable(&payload_tmp, &payload)?;
        std::fs::rename(&payload_tmp, self.new_dir.join(format!("{queue_id}.eml")))?;

        // Metadata second: its presence in new/ is the commit point.
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
}

/// Write bytes to `path`, fsync the file, and only then return: callers
/// can rely on the bytes surviving a crash once this resolves.
///
/// Returns `Ok(())` once the bytes are durable on disk. Returns `Err`
/// if the file cannot be created, written, or fsynced — the error
/// message names the path, and the caller decides whether partial state
/// at `path` needs cleanup.
fn write_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f =
        std::fs::File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
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
        assert_eq!(meta["rcpt_to"][0], "user@example.org");
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
    /// message pair and, later, the idempotency key for object-storage
    /// upload (Phase 12, gap 9).
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
}
