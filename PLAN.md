# PLAN.md — Remaining work

**As of 2026-11-24:** 328 tests pass (1 ignored) with no network beyond
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
| SPF, DKIM, DMARC verification (fail-closed) | ✅ Done: RFC 7208 lookup limits, PSL-based relaxed alignment, bounce alignment; our `Authentication-Results:` and display-name warnings on delivered mail |
| Recipient authority (file-backed, hot-reloaded, `reject`/`catch-all`/`grace`, per-domain size limits) | ✅ Done. A console-backed authority is not started (§5) |
| Durable spool, maildir delivery, retry with backoff for 5 days, crash-debris sweep | ✅ Done, maildir directories fsynced and their `tmp/` swept |
| Connection, per-IP and DNS limits; privilege drop; graceful shutdown | ✅ Done, with per-mailbox quotas (authority file, server default) and a free-disk floor. Recipient probing limited per connection and per IP |
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
2. **Recipient probing.** Done: refused recipients close the connection
   past `max-refused-rcpt-per-session` (20; RSET doesn't reset it) and are
   budgeted per source IP across connections (`max-refused-rcpt-per-ip`,
   100 per 15 minutes). Open: aggregate the per-IP budget per IPv6 /64
   (§6, IPv6 readiness), and watch whether large providers' shared
   outbound IPs need an allow-list.
3. **SPF and DMARC correctness.** Done: `mx`/`ptr` cost one term each,
   with RFC 7208 §4.6.4's per-mechanism address cap; relaxed alignment
   compares organizational domains from a vendored Public Suffix List
   (`dmarc/data/public_suffix_list.dat`); bounces align through the HELO
   identity. Open: refresh the PSL snapshot regularly (DEPLOYMENT.md H7).
4. **What users are shown.** Done: our `Authentication-Results:` (forged
   ones claiming our authserv-id are removed), and an
   `X-Display-Name-Warning:` when the From display name names another
   organization (tagged, never refused, since list software does it).
   Open: lookalike display names without an address (`PayPal Support`),
   and lookalike Unicode characters.
5. **Robustness.** Done: a drop guard for the per-IP connection count;
   maildir directory fsync after each delivery and an hourly `tmp/`
   sweep; `503` for MAIL/RCPT/DATA before EHLO and 12288-octet AUTH lines;
   duplicate DKIM tags and `k=`/`a=` mismatches refused; ownership handed
   over with `fchown` through an `O_NOFOLLOW` handle; end of data down
   from about 5 copies of a message to about 3 at peak.
6. **Assurance.** Done: libFuzzer targets for the SMTP framing, the
   header scanner and end-of-data checks, DKIM, SPF, DMARC (with the PSL)
   and the DNS decoder (`fuzz/`), run for 30 s each in CI; the first runs
   found one bug (an unstable organizational domain for names with
   control characters, fixed). Open: an independent security review, and
   longer fuzzing campaigns (with AddressSanitizer, on a nightly host).

---

## 3. Open gaps index

One line per open item; DESIGN.md §13 has the impact of each.

| Gap | DESIGN §13 area | Planned in |
|---|---|---|
| Quotas are soft and don't count queued mail; no per-domain total | Abuse resistance | §2.4.1 |
| Display names without an address, and lookalike characters, aren't checked | What users are shown | §2.4.4 |
| Sender grants read only at startup | Submission and AUTH | §6 |
| SPF `a`/`mx` don't query AAAA; per-IP limits not aggregated per IPv6 /64 | Correctness; Abuse resistance | §6 (IPv6 readiness) |
| `quarantine` delivered as normal mail | Correctness and delivery | Out of V1 scope (decided) |

---

## 4. Code quality

From the design and code assessment in
[docs/reviews/FINDINGS.md](docs/reviews/FINDINGS.md). Done:

- `mailserv/src/main.rs` split into `config`, `server`, `session` (with
  `session/message.rs` for end of data), `address`, `headers`, `tls` and
  `verdict` (DESIGN §2); per-message state is one `Transaction` value;
  DKIM verification runs on the blocking pool; the tests are hermetic.
- One raw header scanner (`mailparse::extract_raw_headers` and
  `find_separator`) for DKIM, the From scan, the bare-CR check and
  verdict stripping; one mailbox-safe character set
  (`address::is_mailbox_safe`) for RCPT and the maildir sink.
- Every DNS lookup is a `dns::Lookup` (found / absent / temporary error),
  classified in one place and matched exhaustively by SPF, DMARC and the
  DKIM key fetch. This fixed a fail-open: a DKIM key lookup that got
  SERVFAIL was "no key", so a `p=reject` domain's legitimate mail got a
  permanent `550` over a DNS hiccup; it is now deferred.
- Typed DNS errors (`dns::QueryError`), and verdicts stored under stable
  names (`pass`, `softfail`, `reject`, ...; older spool files still load).
- Fuzz targets (`fuzz/`, §2.4.6).

Nothing is open in this section.

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
- **Outbound reputation** (design these in with sending, not after). Our
  sending IPs and domains are scored by every receiver, and on shared IPs
  one tenant's behaviour affects all of them:
  - **Bounces:** suppress addresses that hard-bounced (`5xx`), so they
    aren't sent to again; a high rate of sends to nonexistent addresses is
    one of the strongest spam signals.
  - **Complaints:** Gmail and Yahoo expect a spam-complaint rate under 0.3%
    (ideally under 0.1%); process feedback loops where providers offer
    them, and suppress complainers.
  - **Authentication:** SPF and DKIM on every message, a DMARC record, and
    alignment with the From domain (required for bulk senders since 2024).
  - **Infrastructure:** reverse DNS (PTR) that matches the HELO name and
    resolves back (forward-confirmed), TLS to every receiver that offers
    it, and new IPs warmed up gradually.
  - **Bulk mail:** one-click unsubscribe (`List-Unsubscribe` and
    `List-Unsubscribe-Post`, RFC 8058).
  - **Multi-tenant controls:** per-tenant sending limits, and possibly
    separate IP pools for transactional and bulk mail, so one bad list
    can't damage every customer's delivery.
  - **Monitoring:** watch bounce and complaint rates per tenant, and the
    providers' reputation tools (Google Postmaster Tools, Microsoft SNDS).
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
