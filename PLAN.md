# PLAN.md — Remaining work

**As of 2026-11-23:** 273 tests pass (1 ignored), and clippy and fmt are
clean on Rust 1.100.0.

This file lists only what is **left to do**. How things work is in
[DESIGN.md](DESIGN.md) (its §13 describes every current gap), and go-live
steps are in [DEPLOYMENT.md](DEPLOYMENT.md). Past security reviews are
archived in [docs/reviews/](docs/reviews/README.md), which maps their
finding IDs to where each item stands now.

**V1 scope:** a receive-only hosted MX. Customers point their domain's MX
at us, and addresses are created in an external management console. V1 has
no relaying, sending, submission or bounces. Send-side work is post-V1
(§6).

---

## 1. Status at a glance

| Area | Status |
|---|---|
| SMTP core, STARTTLS, framing and smuggling defences | ✅ Done |
| SPF, DKIM, DMARC verification (fail-closed) | ✅ Done. Open: the SPF lookup budget, relaxed alignment without a Public Suffix List, bounce alignment, and `redirect=` to a domain without a record (§2.4 item 4) |
| Recipient authority (file-backed, hot-reloaded, `reject`/`catch-all`/`grace`, per-domain size limits) | ✅ Done. A console-backed authority is not started (§5) |
| Durable spool, maildir delivery, retry with backoff for 5 days, crash-debris sweep | ✅ Done. Open: duplicates on timeout, catch-all copies, maildir fsync and `tmp/` debris (§2.4) |
| Connection, per-IP and DNS limits; privilege drop; graceful shutdown | ✅ Done. Open: storage quotas and recipient probing (§2.4) |
| AUTH with sender grants | ⚠️ Works: argon2id-hashed credentials file, attempt limits. Still advertised on port 25, so don't enable it on the MX (§2.3) |
| Pilot deployment | ⏳ Code ready. The DEPLOYMENT.md checklist is not done (§2.1) |
| S3 storage, per-user encryption, multiple MX hosts | 📐 Designed, not started (§5) |

---

## 2. Before V1

### 2.1 Pilot go-live (DEPLOYMENT.md)

- [ ] Run a dependency audit (`cargo install cargo-audit && cargo audit`)
  and resolve its findings. This has never been run (DEPLOYMENT.md A2).
- [ ] Complete the DEPLOYMENT.md checklist (Phases A–H) and the §4
  sign-off.

### 2.2 Refactors that keep later features additive

Small changes; do them before V1 so §5 doesn't become a rewrite.

- [ ] **Extract a `SpoolQueue` trait** from `DiskSpool`: list,
  `load_payload`, `record_attempt`, `remove`, `dead_letter`,
  `sweep_debris`. It must carry the attempt record
  (`count first_failure last_failure`) and lazy payload loading. Today the
  drain takes `&DiskSpool` directly.
- [ ] **Fix the trace-header-versus-encryption ordering.**
  - The drain prepends plaintext `Return-Path:`/`Received:` to the stored
    payload, which would corrupt mail once an encryptor is configured.
  - Decide whether trace headers go inside the sealed container (they must
    then name no recipient, or Bcc recipients would see each other) or sit
    beside it as plaintext metadata.
  - Send the fast path through the same sealed form.

### 2.3 Decide: AUTH in V1

- [ ] Either **remove AUTH from the V1 build**, or keep it documented as
  "never set `auth-users-file`".

Done so far: credentials are argon2id hashes in a private file
(`--auth-users-file`, made with `mailserv hash-password`, refused if
other users can read it), never passwords and never argv. Checks run on
the blocking pool with bounded concurrency, an unknown login costs the
same as a wrong password, and failures are limited per session (3) and
per source IP (10 per 15 minutes).

Still missing before AUTH can face the internet:
- AUTH is advertised on any TLS listener, including port 25 (a
  submission-only listener is §6);
- the credentials file is read only at startup (no reload on SIGHUP);
- mechanism names are matched case-sensitively, and a client `*` abort
  leaves the LOGIN user name behind (a later `AUTH LOGIN` then takes its
  next line as the password for that old name).

### 2.4 Before general availability

Fix these after the pilot starts and before GA, in this order:

1. **Storage quotas:** per-message, per-mailbox and per-domain caps on
   stored bytes, plus a free-disk tempfail (`452 4.3.1`). After that, and
   item 5, `catch-all` can be offered.
2. **Recipient probing:** close the session after N refused RCPTs, and keep
   a refused-RCPT budget per IP (`RSET` resets today's 100-recipient cap).
3. **Duplicates on timeout:** never let the connection cap fire between the
   spool commit and the `250`; move fast-path delivery after the reply.
4. **SPF and DMARC correctness** (the first three reject legitimate mail):
   - stop charging the address lookups behind `mx` and `ptr` to SPF's
     10-term budget, but add RFC 7208 §4.6.4's 10-address cap per
     `mx`/`ptr`;
   - organisational-domain relaxed DMARC alignment. This needs a Public
     Suffix List; vendor a dated snapshot;
   - HELO-identity SPF alignment for bounces (null sender);
   - SPF `redirect=` to a domain with no SPF record must be PermError
     (RFC 7208 §6.1). Today it evaluates to `None`, so a misconfigured
     domain's mail is accepted instead of refused.
5. **Catch-all copies:** make the delivery idempotency key and file name
   include the envelope address, so several catch-all recipients in one
   transaction don't collapse into one file.
6. **What users are shown:**
   - add our `Authentication-Results:` and strip forged ones that claim our
     authserv-id;
   - a display-name check, or document that display names are unverified.
7. **Robustness:**
   - an RAII guard for the per-IP connection count;
   - fsync the maildir directory after the rename, and sweep old files from
     the maildirs' `tmp/` (the spool's debris is already swept);
   - `503` for commands before EHLO; EHLO resets the envelope; allow long
     AUTH PLAIN initial responses;
   - refuse duplicate DKIM tags; check the key's `k=` against the
     signature's `a=`;
   - `create_owned_dir_all`: `fchown` and `O_NOFOLLOW` instead of
     path-based `chown`;
   - fewer copies of the message buffer (peak memory is about 2× the
     message size per session during DATA and up to 6× at end of data).
8. **Assurance:** fuzz the SMTP framing, the header scanners, and the
   SPF/DMARC/DNS parsers; get an independent security review.

---

## 3. Open gaps index

One line per open item; DESIGN.md §13 has the impact of each.

| Gap | DESIGN §13 area | Planned in |
|---|---|---|
| No storage quotas or free-disk check | Abuse resistance | §2.4.1 |
| Unlimited recipient probing per session | Abuse resistance | §2.4.2 |
| Duplicate delivery if the connection cap fires after commit | Correctness and delivery | §2.4.3 |
| SPF budget over-counts `mx`/`ptr` address lookups | Correctness and delivery | §2.4.4 |
| Relaxed alignment is a suffix test (no PSL) | Correctness and delivery | §2.4.4 |
| No SPF alignment for the null sender | Correctness and delivery | §2.4.4 |
| SPF `redirect=` to a domain without a record gives `None`, not PermError | Correctness and delivery | §2.4.4 |
| Catch-all copies collapse | Correctness and delivery | §2.4.5 |
| No `Authentication-Results:` | What users are shown | §2.4.6 |
| Display-name spoofing | What users are shown | §2.4.6 |
| Per-IP count release, maildir fsync and `tmp/`, pre-EHLO replies, DKIM tag checks, `chown` by path, memory copies | Abuse resistance; Correctness and delivery | §2.4.7 |
| AUTH hardening | AUTH | §2.3, §6 |
| SPF `a`/`mx` don't query AAAA; per-IP limits not aggregated per IPv6 /64 | Correctness; Abuse resistance | §6 (IPv6 readiness) |
| `quarantine` delivered as normal mail | Correctness and delivery | Out of V1 scope (decided) |

---

## 4. Code quality

From the design and code assessment in
[docs/reviews/FINDINGS.md](docs/reviews/FINDINGS.md). None blocks the
pilot; items 1–3 most reduce the kind of bug the reviews kept finding.

| # | Change | Why | Effort |
|---|---|---|---|
| 1 | Split `mailserv/src/main.rs` (about 4,800 lines) into `config`, `server` (accept loop, limits, shutdown), `session` (`UserSession`), `headers` (From extraction, bare-CR check) and `tls` modules; introduce a `Transaction` type created at an accepted MAIL and dropped at end of data, RSET or abort | Per-message state is loose fields reset by hand in `clear_envelope`, which is how a DKIM verdict once leaked across messages | Medium |
| 2 | One raw header scanner, in `mailparse`, used by DKIM, the From extraction and the bare-CR check; one shared mailbox-safe character set for RCPT validation and the maildir sink | Two scanners can disagree about line boundaries; two copies of a rule can drift | Small–medium |
| 3 | Run DKIM canonicalisation and verification on the blocking pool (fetch keys first, async) | Attacker-controlled CPU work currently runs on async workers | Small |
| 4 | Fuzz targets; make the `mailserv` integration tests use the mock DoT resolver instead of live 1.1.1.1; `cargo audit` in CI | No fuzzing; CI fails offline; dependencies unaudited | Small to set up |
| 5 | Total lookup results (`Found / Absent / TempError`) for SPF and DKIM key lookups, matched exhaustively | Fail-closed is enforced case by case, not by the types | Medium |
| 6 | Typed errors in `dns`/`spf`; `serde` enums with stable names for the verdicts in spool metadata (today `format!("{:?}")`) | Renaming a variant silently changes stored data | Small–medium |

---

## 5. Feature work: hosted address service

The server is the **MX edge** of a platform. Which domains, users and
addresses exist lives in the external console. Order: recipient authority
→ delivery backend → multi-domain → scale hardening.

| Feature | Status | Next step / blockers |
|---|---|---|
| **Console-backed authority** | Not started; the `RecipientResolver` seam is ready | HTTP/gRPC implementation behind the same trait, plus a shared TTL cache beyond the per-session one |
| **Refusal and admin event stream** | Server side done (structured refusal and delivery logs) | The console aggregates them; possibly a server-side ingest queue if refusal volume demands it |
| **S3 final storage** (`DeliverySink`) | Not started; the seam is ready | An S3 sink keyed by (mailbox, queue ID), idempotent by construction |
| **S3 spool backend** | Not started | Needs `SpoolQueue` (§2.2). Staged sync (below) |
| **Per-user encryption at rest** | Designed (decision below), not started | Needs the ordering fix (§2.2). Then `PayloadEncryptor::encrypt` takes the recipient key set; keys are already carried in `SpoolRcpt` |
| **Multiple MX hosts** (mx1, mx2 for the same domains) | Not started | Needs the shared S3 sink, the duplicate-on-timeout fix (§2.4.3), `Message-ID` + recipient deduplication in the shared store, and authority distribution (console resolver, or atomic publish to every host). Per-host limits are acceptable at first |
| **Per-domain MX identities** (white-label) | Optional | The banner and EHLO come before RCPT, so identity must come from the listening address (needs several listeners; `--host` is one) or from SNI, which chooses the certificate (rustls `ResolvesServerCert`). `Received: by` can be per-domain. Most services use one shared MX hostname and don't need this |
| **Verdict policy profiles** | Not started | Per-domain choice of reject versus accept-and-tag, instead of hard-coded MSA-style behaviour |

**Decisions to keep:**

- **Never self-bounce.** Undeliverable mail is refused at RCPT, so the
  sender's server bounces it. This holds in V1 and later.
- **Refusals.**
  - The SMTP reply is the same for every reason, so senders can't tell
    which addresses exist.
  - The reason goes to the log and the console, which is the system of
    record.
  - The per-session cache holds **successes only**, so every refusal
    reaches the authority exactly once.
- **Encryption design: a multi-recipient container.** A random content key
  encrypts the payload once, and that key is wrapped for each recipient's
  public key, giving one blob per message. The format is age-style X25519.
  - Sealing happens after SMTP processing and before storage. Routing
    metadata stays plaintext.
  - A rotated-out key generation must remain readable by its owner for at
    least the queue lifetime (5 days), because the server can't re-wrap.
  - The honest guarantee is *encrypted at rest, not end-to-end*. There is no
    server-side search or scanning, and a lost private key means the mail
    can't be read.
  - Alternative kept on file: encrypt per recipient inside the sink.
- **S3 spool: staged sync.** The `250` still depends only on the local
  durable spool. A background uploader sends each message (key = queue ID)
  and deletes the local copy once the upload is confirmed. The local disk
  becomes a cache with an upload backlog, which needs monitoring. Never
  stage in `/tmp`.

---

## 6. Later work

**Sending and submission (post-V1, low priority):**
- DKIM signing.
- Submission-only listener (587, implicit TLS 465); AUTH only there.
- **Credential storage (decided):**
  - **Done:** a credentials file separate from the sender grants
    (`--auth-users-file`) holding argon2id hashes only, refused if other
    users can read it; never in argv; per-session and per-IP attempt
    limits.
  - **Next:** reload on SIGHUP (so a login can be revoked without a
    restart); optionally make the attempt limits configurable.
  - **Two seams:** `CredentialVerifier` (later backed by the console) and
    `SenderAuthorizer` (stays in the app).
  - **Backend constraints:** fail closed for AUTH only (never block inbound
    delivery), TTL cache, revocation without restart, and timeouts plus a
    circuit breaker.
- AUTH hardening: case-insensitive mechanism names, reset LOGIN state on
  `*`.
- Sender grants from the console instead of `--auth-senders`.
- OAUTHBEARER.

**Protocol:**
- Advertise `8BITMIME`, `SMTPUTF8`, `PIPELINING`. Pipelining already works;
  add a test.
- `VRFY` → `252`, `EXPN` → `502`. Both reply `250` today.
- Refuse unadvertised ESMTP parameters with `555` (RFC 5321). Today
  everything except `SIZE=` is ignored.

**Operations:**
- DNS: resolver back-off when it's down, shared duplicate misses, IPv6
  resolver addresses, a second upstream.
- IPv6 listener readiness: SPF AAAA lookups, and per-IP limits aggregated
  per /64.
- TLS hot reload, and SNI certificate selection.
- A metrics endpoint to replace the log-only `dns stats` and `drain pass`.

**Standards and parsing:**
- DMARC aggregate and failure reports (`rua`/`ruf`), `pct` sampling.
- SPF `exp=` explanations (parsed and validated, not used).
- ARC (needed before any forwarding role).
- CHUNKING/BDAT, a Milter interface.
- mailparse: RFC 2047 decoding, `Content-Disposition` (for user-facing
  tools).

**Tools:**
- `smtp-client` sends bare-LF line endings and doesn't read the greeting
  first, so each printed reply belongs to the previous command.
- `dnsq --tcp` is a no-op flag (TCP is already the default).
