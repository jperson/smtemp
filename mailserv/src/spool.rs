//! Disk spool: durable staging of accepted messages (Phase 7).
//!
//! On end-of-data acceptance the session writes the raw message plus its
//! envelope/verdict metadata here, and the SMTP `250` is only returned
//! after a successful write — accepted mail is never silently dropped by
//! a failed write. The layout is maildir-style: everything is written
//! under `tmp/` first, fsynced, and then renamed into `new/`, with the
//! metadata file renamed **last**. A `{id}.json` in `new/` is therefore
//! the commit point: a payload without metadata is an incomplete write
//! from a crashed process and may be cleaned up by a future drain pass.
//!
//! The payload file is exactly the raw bytes the client sent (the same
//! bytes DKIM verified). Phase 12's user-held encryption keys wrap the
//! payload at this boundary; the metadata stays plaintext so the queue
//! can always be routed and expired.

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt as _;
use uuid::Uuid;

use crate::{DkimSummary, DmarcSummary};

/// Envelope and verdict metadata for one accepted message.
#[derive(Debug, Clone, Serialize)]
pub struct SpoolMeta {
    /// Set by [`Spool::write`]; the queue identity of this message.
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
    /// Payload size in bytes.
    pub message_size: usize,
}

/// A queue directory with `tmp/` and `new/` subdirectories.
#[derive(Debug, Clone)]
pub struct Spool {
    /// Staging area: in-progress writes land here and are fsynced before
    /// being renamed into [`Spool::new_dir`]. Leftover files here after a
    /// crash are incomplete writes.
    tmp: PathBuf,
    /// Committed area: a message is complete (and its ID valid) only when
    /// both `{id}.eml` and `{id}.json` are present here.
    new: PathBuf,
}

impl Spool {
    /// Open (creating if needed) a queue directory at `root`, with
    /// `tmp/` and `new/` subdirectories.
    ///
    /// Returns the ready-to-use spool on success. Returns `Err` if
    /// either directory cannot be created (e.g. missing permissions, or
    /// the path exists as a regular file); the server should refuse to
    /// start rather than accept mail it cannot store.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        let tmp = root.join("tmp");
        let new = root.join("new");
        tokio::fs::create_dir_all(&tmp)
            .await
            .with_context(|| format!("cannot create spool dir {}", tmp.display()))?;
        tokio::fs::create_dir_all(&new)
            .await
            .with_context(|| format!("cannot create spool dir {}", new.display()))?;
        Ok(Spool { tmp, new })
    }

    /// Durable write of one accepted message. Returns the queue ID.
    ///
    /// Crash safety (PoC-grade, per the Phase 7 plan): payload and
    /// metadata are each written under `tmp/` and fsynced, then renamed
    /// into `new/` — metadata last. Only the final rename is the commit;
    /// anything left in `tmp/` is an incomplete write.
    ///
    /// Returns `Ok(queue_id)` once both files are committed under
    /// `new/`. Returns `Err` if any step fails (serialization, I/O,
    /// fsync); in that case **no complete pair is ever committed** —
    /// `new/` never contains the `.json` marker, and partial state (a
    /// committed payload, leftover files in `tmp/`) is rolled back on a
    /// best-effort basis. Callers treat `Err` as a temporary failure and
    /// refuse the message with `451`; a crash between steps can still
    /// leave recoverable debris in `tmp/` or an uncommitted `.eml` in
    /// `new/` for a future drain pass to clean.
    pub async fn write(&self, mut meta: SpoolMeta, raw: &[u8]) -> Result<String> {
        let queue_id = format!(
            "{:012x}.{}",
            jiff::Timestamp::now().as_second(),
            Uuid::new_v4().simple()
        );
        meta.queue_id = queue_id.clone();

        // Payload first.
        let payload_tmp = self.tmp.join(format!("{queue_id}.eml"));
        write_durable(&payload_tmp, raw).await?;
        tokio::fs::rename(&payload_tmp, self.new.join(format!("{queue_id}.eml"))).await?;

        // Metadata second: its presence in new/ is the commit point.
        let meta_tmp = self.tmp.join(format!("{queue_id}.json"));
        let meta_result = match serde_json::to_vec_pretty(&meta)
            .context("serialize spool metadata")
            .map(|mut v| {
                v.push(b'\n');
                v
            }) {
            Ok(bytes) => write_durable(&meta_tmp, &bytes).await,
            Err(e) => Err(e),
        };
        if let Err(e) = meta_result {
            self.rollback(&queue_id).await;
            return Err(e);
        }
        if let Err(e) = tokio::fs::rename(&meta_tmp, self.new.join(format!("{queue_id}.json")))
            .await
            .with_context(|| format!("cannot commit spool metadata for {queue_id}"))
        {
            self.rollback(&queue_id).await;
            return Err(e);
        }

        // Best-effort directory fsync so the renames survive a power cut.
        // (sync_all on a directory fd is an fsync on Linux.)
        #[cfg(unix)]
        if let Ok(dir) = std::fs::File::open(&self.new) {
            let _ = dir.sync_all();
        }

        Ok(queue_id)
    }

    /// Best-effort cleanup after a failed `write`: remove the already
    /// committed payload and any leftover metadata staging file so no
    /// orphan pair is left behind. Errors are ignored by design — this
    /// runs on a failure path, and leftover files are recoverable by a
    /// future drain pass (a payload without metadata is never a valid
    /// committed message).
    async fn rollback(&self, queue_id: &str) {
        let _ = tokio::fs::remove_file(self.new.join(format!("{queue_id}.eml"))).await;
        let _ = tokio::fs::remove_file(self.tmp.join(format!("{queue_id}.json"))).await;
    }
}

/// Write bytes to `path`, fsync the file, and only then return: callers
/// can rely on the bytes surviving a crash once this resolves.
///
/// Returns `Ok(())` once the bytes are durable on disk. Returns `Err`
/// if the file cannot be created, written, or fsynced — the error
/// message names the path, and the caller decides whether partial state
/// at `path` needs cleanup.
async fn write_durable(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let mut f = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("cannot create {}", path.display()))?;
    f.write_all(bytes)
        .await
        .with_context(|| format!("cannot write {}", path.display()))?;
    f.sync_all()
        .await
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
        }
    }

    /// Write one record and verify the maildir-style contract: both
    /// files committed under `new/`, `tmp/` empty, payload byte-exact,
    /// and metadata that parses and carries the queue identity.
    #[tokio::test]
    async fn write_is_durable_and_complete() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path()).await.unwrap();

        let raw = b"Subject: test\r\n\r\nbody\r\n".to_vec();
        let queue_id = spool
            .write(
                SpoolMeta {
                    message_size: raw.len(),
                    ..sample_meta()
                },
                &raw,
            )
            .await
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
    }

    /// Queue IDs must never collide: they are the storage key for the
    /// message pair and, later, the idempotency key for object-storage
    /// upload (Phase 12, gap 9).
    #[tokio::test]
    async fn queue_ids_are_unique() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path()).await.unwrap();
        let raw: Vec<u8> = b"payload".to_vec();
        let a = spool.write(sample_meta(), &raw).await.unwrap();
        let b = spool.write(sample_meta(), &raw).await.unwrap();
        assert_ne!(a, b);
    }

    /// A failure after the payload rename must not leave an orphan
    /// committed payload: `rollback` removes it, so `new/` stays empty.
    #[tokio::test]
    async fn rollback_removes_committed_payload() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path()).await.unwrap();

        // Simulate the post-rename failure state directly.
        let id = "deadbeef.test".to_string();
        tokio::fs::write(dir.path().join("new").join(format!("{id}.eml")), b"x")
            .await
            .unwrap();
        spool.rollback(&id).await;

        let mut names = Vec::new();
        let mut rd = tokio::fs::read_dir(dir.path().join("new")).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            names.push(e.file_name().to_string_lossy().into_owned());
        }
        assert!(names.is_empty(), "orphan payload left behind: {names:?}");
    }
}
