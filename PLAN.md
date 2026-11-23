# PLAN.md — Remaining work

**As of 2026-11-22** (`8e3a643` + the F7 queue-retry change): 261 tests
pass, and clippy and fmt are clean on Rust 1.100.0.

This file lists only what is **left to do**. Finished work is in git
history, how things work is in [DESIGN.md](DESIGN.md) (its §13 lists every
current gap), and go-live steps are in [DEPLOYMENT.md](DEPLOYMENT.md).
Finding IDs: F-/L- are from SECURITY-AUDIT.md, S- from SECURITY.md, and
M-/N-/H- from REPORT.md.

**V1 scope:** a receive-only hosted MX. Customers point their domain's MX
at us, and addresses are created in an external management console. V1 has
no relaying, sending, submission or bounces. Send-side work is post-V1
(§5).

---

## 1. Status at a glance

| Area | Status |
|---|---|
| SMTP core, STARTTLS, framing and smuggling defences | ✅ Done |
| SPF, DKIM, DMARC verification (fail-closed) | ✅ Done. Open: M2, M5, N16 (§3) |
| Recipient authority (file-backed, hot-reloaded, `reject`/`catch-all`/`grace`, per-domain size limits) | ✅ Done. A console-backed authority is not started (§4) |
| Durable spool, maildir delivery, retry with backoff for 5 days | ✅ Done. Open: F6, M9, M14 (§3) |
| Connection, per-IP and DNS limits; privilege drop; graceful shutdown | ✅ Done. Open: F9, N10 (§3) |
| AUTH with sender grants | ⚠️ Works, but unsafe to enable (§2.3) |
| Pilot deployment | ⏳ Code ready. The DEPLOYMENT.md checklist is not done (§2.1) |
| S3 storage, per-user encryption, multiple MX hosts | 📐 Designed, not started (§4) |

---

## 2. Before V1

### 2.1 Pilot go-live (DEPLOYMENT.md)

- [ ] Commit the F7 change and `SECURITY-AUDIT.md`; build the release from
  that commit and record its hash (DEPLOYMENT A3–A4).
- [ ] Run a dependency audit (`cargo install cargo-audit && cargo audit`)
  and resolve its findings. This has never been run.
- [ ] Complete DEPLOYMENT.md Phases B–H and the §6 sign-off.

### 2.2 Refactors that keep later features additive

Small changes; do them before V1 so §4 doesn't become a rewrite.

- [ ] **Extract a `SpoolQueue` trait** from `DiskSpool`: list,
  `load_payload`, `record_attempt`, `remove`, `dead_letter`. It must carry
  the F7 attempt record (`count first_failure last_failure`) and lazy
  payload loading. Today the drain takes `&DiskSpool` directly.
- [ ] **Fix the trace-header-versus-encryption ordering.**
  - The drain prepends plaintext `Return-Path:`/`Received:` to the stored
    payload, which would corrupt mail once an encryptor is configured.
  - Decide whether trace headers go inside the sealed container (they must
    then name no recipient, or Bcc recipients would see each other) or sit
    beside it as plaintext metadata.
  - Send the fast path through the same sealed form.

### 2.3 Decide: AUTH in V1

- [ ] Either **remove AUTH from the V1 build**, or keep it documented as
  "never set `auth-users`". Enabling it needs all of §5's AUTH items first.
  Today AUTH is advertised on any TLS listener, including port 25, with
  plaintext credentials and no limit on failed attempts (F10, M16).

### 2.4 Before general availability

Fix these after the pilot starts and before GA, in this order:

1. **Storage quotas (N10 / F8):** per-message, per-mailbox and per-domain
   caps, plus a free-disk tempfail (`452 4.3.1`). After that, and M9,
   `catch-all` can be offered.
2. **Recipient probing (F9):** close the session after N refused RCPTs,
   and keep a refused-RCPT budget per IP.
3. **Duplicate on timeout (F6 / M11):** never let the connection cap fire
   between the spool commit and the `250`; move fast-path delivery after
   the reply.
4. **Mail-loss group:**
   - **M2:** stop charging MX/PTR address lookups to the 10-term budget,
     but add RFC 7208 §4.6.4's 10-address cap per `mx`/`ptr`.
   - **M5:** organisational-domain relaxed alignment. This needs a Public
     Suffix List; vendor a dated snapshot.
   - **N16:** HELO-identity alignment for bounces.
5. **Catch-all copies (M9):** make the idempotency key and file name include
   the envelope address.
6. **What users are shown:**
   - **M7:** add our `Authentication-Results:` and strip forged ones that
     claim our authserv-id;
   - **N9:** a display-name check, or document that display names are
     unverified.
7. **Robustness:**
   - **M12:** an RAII guard for the per-IP connection count;
   - **M14:** fsync the maildir directory after the rename; clean `tmp/`
     debris;
   - **M10:** `503` for commands before EHLO; EHLO resets the envelope;
     allow long AUTH PLAIN initial responses;
   - **M17:** refuse duplicate DKIM tags; check the key's `k=` against the
     signature's `a=`;
   - **L1–L9** (SECURITY-AUDIT.md), including fchown/`O_NOFOLLOW` in
     `create_owned_dir_all`.
8. **Assurance:** fuzz the SMTP framing, the header scanners, and the
   SPF/DMARC/DNS parsers; get an independent security review.

---

## 3. Open findings index

One line per open item; the detail is in DESIGN.md §13.

| ID | Summary | Planned in |
|---|---|---|
| N10 / F8 | No storage quotas or free-disk check | §2.4.1 |
| F9 | Unlimited recipient probing per session | §2.4.2 |
| F6 / M11 | Duplicate delivery if the cap fires after commit | §2.4.3 |
| M2 | SPF budget over-counts MX/PTR lookups | §2.4.4 |
| M5 | Relaxed alignment is a suffix test (no PSL) | §2.4.4 |
| N16 | No SPF alignment for the null sender | §2.4.4 |
| M9 | Catch-all copies collapse | §2.4.5 |
| M7 | No `Authentication-Results:` | §2.4.6 |
| N9 | Display-name spoofing | §2.4.6 |
| M12, M14, M10, M17, L1–L9 | Robustness and conformance | §2.4.7 |
| F10 / M16 | AUTH hardening | §2.3, §5 |
| M6 (rest) | `quarantine` delivered as normal mail | Out of V1 scope (decided) |

---

## 4. Feature work: hosted address service (Phase 12)

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
| **Multiple MX hosts** (mx1, mx2 for the same domains) | Not started | Needs the shared S3 sink, the F6 fix, `Message-ID` + recipient deduplication in the shared store, and authority distribution (console resolver, or atomic publish to every host). Per-host limits are acceptable at first |
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

## 5. Later work

**Sending and submission (post-V1, low priority):**
- DKIM signing.
- Submission-only listener (587, implicit TLS 465); AUTH only there.
- **Credential storage (decided):**
  - **Now:** an interim secrets file, separate from the sender grants, with
    argon2id hashes. It must be `0600`, and mailserv refuses to start if
    others can read it. Credentials never go in argv. SIGHUP reloads it.
  - **Two seams:** `CredentialVerifier` (later backed by the console) and
    `SenderAuthorizer` (stays in the app).
  - **Backend constraints:** fail closed for AUTH only (never block inbound
    delivery), TTL cache, revocation without restart, and timeouts plus a
    circuit breaker.
- AUTH hardening: attempt limiting, constant-time comparison,
  case-insensitive mechanism names, reset LOGIN state on `*`.
- Sender grants from the console instead of `--auth-senders`.
- OAUTHBEARER.

**Protocol (Phase 9):**
- Advertise `8BITMIME`, `SMTPUTF8`, `PIPELINING`. Pipelining already works;
  add a test.
- `VRFY` → `252`, `EXPN` → `502`. Both reply `250` today.
- Refuse unadvertised ESMTP parameters with `555` (RFC 5321). Today
  everything except `SIZE=` is ignored.

**Operations (Phase 10):**
- DNS: resolver back-off when it's down, shared duplicate misses, IPv6
  resolver addresses, a second upstream.
- IPv6 listener readiness: SPF AAAA lookups, and per-IP limits aggregated
  per /64.
- TLS hot reload (L10), and SNI certificate selection.
- A metrics endpoint to replace the log-only `dns stats` and `drain pass`.

**Standards and parsing (Phase 11):**
- DMARC aggregate and failure reports (`rua`/`ruf`), `pct` sampling.
- ARC (needed before any forwarding role).
- CHUNKING/BDAT, a Milter interface.
- mailparse: RFC 2047 decoding, `Content-Disposition` (for user-facing
  tools).
