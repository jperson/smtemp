# PLAN.md — Remaining work

**As of 2026-11-24:** 297 tests pass (1 ignored) with no network beyond
loopback; clippy, fmt, rustdoc and `cargo audit` are clean on Rust 1.100.0.

This file lists only what is **left to do**. How things work is in
[DESIGN.md](DESIGN.md) (its §13 describes every current gap), and go-live
steps are in [DEPLOYMENT.md](DEPLOYMENT.md). Past security reviews are
archived in [docs/reviews/](docs/reviews/README.md), which maps their
finding IDs to where each item stands now.

**V1 scope:** a receive-only hosted MX. Customers point their domain's MX
at us, and addresses are created in an external management console. V1 has
no relaying, sending or bounces; submission (587/465, AUTH) is built but
optional. Send-side work is post-V1 (§6).

---

## 1. Status at a glance

| Area | Status |
|---|---|
| SMTP core, STARTTLS, framing and smuggling defences | ✅ Done |
| SPF, DKIM, DMARC verification (fail-closed) | ✅ Done. Open: the SPF lookup budget, relaxed alignment without a Public Suffix List, and bounce alignment (§2.4 item 3) |
| Recipient authority (file-backed, hot-reloaded, `reject`/`catch-all`/`grace`, per-domain size limits) | ✅ Done. A console-backed authority is not started (§5) |
| Durable spool, maildir delivery, retry with backoff for 5 days, crash-debris sweep | ✅ Done. Open: maildir fsync and `tmp/` debris (§2.4) |
| Connection, per-IP and DNS limits; privilege drop; graceful shutdown | ✅ Done, with per-mailbox quotas (authority file, server default) and a free-disk floor. Open: recipient probing (§2.4) |
| Submission (587 STARTTLS, 465 implicit TLS) with AUTH and sender grants | ✅ Done: AUTH only on submission listeners and required there; argon2id-hashed credentials file reloaded on SIGHUP, attempt limits |
| Pilot deployment | ⏳ Code ready. The DEPLOYMENT.md checklist is not done (§2.1) |
| S3 storage, per-user encryption, multiple MX hosts | 📐 Designed, not started (§5) |

---

## 2. Before V1

### 2.1 Pilot go-live (DEPLOYMENT.md)

- [ ] Re-run `cargo audit --deny warnings` on the release commit
  (DEPLOYMENT.md A2). CI runs it on every push and weekly; the one
  accepted advisory is recorded in `.cargo/audit.toml`.
- [ ] Complete the DEPLOYMENT.md checklist (Phases A–H) and the §4
  sign-off.

### 2.2 Refactors that keep later features additive

Done: the drain works through the `SpoolQueue` trait (not `DiskSpool`),
and trace headers are written once into the stored payload at acceptance,
naming no recipient, so a sealed payload is delivered verbatim (DESIGN
§10). Nothing is left in this section.

### 2.3 Submission

Done: `submission-port` (587, STARTTLS) and `submissions-port` (465,
implicit TLS). AUTH is offered and accepted only there, and is required
before MAIL FROM; the MX listener answers AUTH with `502`. Credentials
are argon2id hashes in a private file (`--auth-users-file`, made with
`mailserv hash-password`), checked on the blocking pool, with an unknown
login costing the same as a wrong password and failures limited per
session (3) and per source IP (10 per 15 minutes). SIGHUP reloads the
credentials file, so a login is revoked by removing it and reloading.

- [ ] Decide whether the pilot enables submission at all. It is off unless
  a submission port is set.

### 2.4 Before general availability

Fix these after the pilot starts and before GA, in this order:

1. **Storage quotas.** Done: per-mailbox quotas from the authority file
   (`quota-bytes` on a mailbox or its domain, falling back to the server's
   `mailbox-quota-bytes`; `452 4.2.2` at RCPT) and a free-disk floor
   (`min-free-disk-bytes`, `452 4.3.1`). Open: count mail still queued for
   a mailbox, and a total cap per domain (today each mailbox is capped, not
   the tenant as a whole). `catch-all` can be offered.
2. **Recipient probing:** close the session after N refused RCPTs, and keep
   a refused-RCPT budget per IP (`RSET` resets today's 100-recipient cap).
3. **SPF and DMARC correctness** (the first three reject legitimate mail):
   - stop charging the address lookups behind `mx` and `ptr` to SPF's
     10-term budget, but add RFC 7208 §4.6.4's 10-address cap per
     `mx`/`ptr`;
   - organisational-domain relaxed DMARC alignment. This needs a Public
     Suffix List; vendor a dated snapshot;
   - HELO-identity SPF alignment for bounces (null sender).
4. **What users are shown:**
   - add our `Authentication-Results:` and strip forged ones that claim our
     authserv-id;
   - a display-name check, or document that display names are unverified.
5. **Robustness:**
   - an RAII guard for the per-IP connection count;
   - fsync the maildir directory after the rename, and sweep old files from
     the maildirs' `tmp/` (the spool's debris is already swept);
   - `503` for commands before EHLO; allow long AUTH PLAIN initial
     responses;
   - refuse duplicate DKIM tags; check the key's `k=` against the
     signature's `a=`;
   - `create_owned_dir_all`: `fchown` and `O_NOFOLLOW` instead of
     path-based `chown`;
   - fewer copies of the message buffer (peak memory is about 2× the
     message size per session during DATA and up to 6× at end of data).
6. **Assurance:** fuzz the SMTP framing, the header scanners, and the
   SPF/DMARC/DNS parsers; get an independent security review.

---

## 3. Open gaps index

One line per open item; DESIGN.md §13 has the impact of each.

| Gap | DESIGN §13 area | Planned in |
|---|---|---|
| Quotas are soft and don't count queued mail; no per-domain total | Abuse resistance | §2.4.1 |
| Unlimited recipient probing per session | Abuse resistance | §2.4.2 |
| SPF budget over-counts `mx`/`ptr` address lookups | Correctness and delivery | §2.4.3 |
| Relaxed alignment is a suffix test (no PSL) | Correctness and delivery | §2.4.3 |
| No SPF alignment for the null sender | Correctness and delivery | §2.4.3 |
| No `Authentication-Results:` | What users are shown | §2.4.4 |
| Display-name spoofing | What users are shown | §2.4.4 |
| Per-IP count release, maildir fsync and `tmp/`, pre-EHLO replies, DKIM tag checks, `chown` by path, memory copies | Abuse resistance; Correctness and delivery | §2.4.5 |
| Sender grants read only at startup | Submission and AUTH | §6 |
| SPF `a`/`mx` don't query AAAA; per-IP limits not aggregated per IPv6 /64 | Correctness; Abuse resistance | §6 (IPv6 readiness) |
| `quarantine` delivered as normal mail | Correctness and delivery | Out of V1 scope (decided) |

---

## 4. Code quality

From the design and code assessment in
[docs/reviews/FINDINGS.md](docs/reviews/FINDINGS.md). None blocks the
pilot; items 1 and 2 most reduce the kind of bug the reviews kept finding.

Done: `mailserv/src/main.rs` is split into `config`, `server`, `session`
(with `session/message.rs` for end of data), `address`, `headers`, `tls`
and `verdict` (DESIGN §2); the `mailserv` tests are hermetic; per-message
state is one `Transaction` value; DKIM verification runs on the blocking
pool.

| # | Change | Why | Effort |
|---|---|---|---|
| 1 | One raw header scanner, in `mailparse`, used by DKIM, the From extraction and the bare-CR check; one shared mailbox-safe character set for RCPT validation and the maildir sink | Two scanners can disagree about line boundaries; two copies of a rule can drift | Small–medium |
| 2 | Fuzz targets | No fuzzing | Small to set up |
| 3 | Total lookup results (`Found / Absent / TempError`) for SPF and DKIM key lookups, matched exhaustively | Fail-closed is enforced case by case, not by the types | Medium |
| 4 | Typed errors in `dns`/`spf`; `serde` enums with stable names for the verdicts in spool metadata (today `format!("{:?}")`) | Renaming a variant silently changes stored data | Small–medium |

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
| **S3 spool backend** | Not started; the `SpoolWriter`/`SpoolQueue` seams are ready | Staged sync (below) |
| **Per-user encryption at rest** | Designed (decision below), not started | `PayloadEncryptor::encrypt` takes the recipient key set (keys are already carried in `SpoolRcpt`); the stored payload is already the final message, delivered verbatim |
| **Multiple MX hosts** (mx1, mx2 for the same domains) | Not started | Needs the shared S3 sink, the duplicate-on-timeout fix (§2.4.3), `Message-ID` + recipient deduplication in the shared store, and authority distribution (console resolver, or atomic publish to every host). Per-host limits are acceptable at first |
| **Per-domain MX identities** (white-label) | Optional | The banner and EHLO come before RCPT, so identity must come from the listening address (needs a listener per address; `--host` is one) or from SNI, which chooses the certificate (rustls `ResolvesServerCert`). `Received: by` can be per-domain. Most services use one shared MX hostname and don't need this |
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
  - Sealing happens after SMTP processing and before storage. The trace
    headers are inside the container and name no recipient; the envelope
    address of each copy travels as sink metadata. Routing metadata stays
    plaintext.
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
- DKIM signing, and relaying submitted mail to other domains (today a
  submitted message can only go to hosted recipients).
- **Credential storage (decided):**
  - **Done:** a credentials file separate from the sender grants
    (`--auth-users-file`) holding argon2id hashes only, refused if other
    users can read it; never in argv; per-session and per-IP attempt
    limits; reloaded on SIGHUP.
  - **Next:** reload `--auth-senders` grants too (they live in the config,
    which isn't reloaded); optionally make the attempt limits
    configurable.
  - **Two seams:** `CredentialVerifier` (later backed by the console) and
    `SenderAuthorizer` (stays in the app).
  - **Backend constraints:** fail closed for AUTH only (never block inbound
    delivery), TTL cache, revocation without restart, and timeouts plus a
    circuit breaker.
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
