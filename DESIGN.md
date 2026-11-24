# DESIGN.md — Architecture of mailserv

This document describes how mailserv works **today** and where its design
falls short (§13). Remaining work is in [PLAN.md](PLAN.md). Running and
configuring it is covered in [README.md](README.md), and going live in
[DEPLOYMENT.md](DEPLOYMENT.md).

---

## 1. Overview

mailserv is an inbound SMTP server (MX) in Rust. For every message it:

- accepts it over plaintext or STARTTLS SMTP;
- checks SPF, DKIM and DMARC;
- accepts recipients only if the **recipient authority** hosts them;
- durably spools it before replying `250`;
- delivers it to a local maildir, retrying failures;
- logs each decision as structured JSON.

**V1 scope is receive-only**: a hosted service for inbound mail to
user-owned addresses on customer domains, with no relaying, sending or
bounces. Optional submission listeners (587 STARTTLS, 465 implicit TLS)
take authenticated mail for hosted recipients (§10); they're off unless
configured.

Design goals, in order:

1. **Correctness over features.** Protocol behaviour is pinned by tests, and
   replies cite the RFC they follow.
2. **Binding policy.** The policy layer's verdicts are enforced by the
   protocol layer, not advisory (§3).
3. **Fail closed.** If a policy input is unknown (DNS error, authority
   unavailable, unparseable header), the answer is a temporary failure or a
   refusal, never an accept.
4. **Byte fidelity.** Mail is bytes. Bodies, folded headers and
   canonicalisation inputs are preserved exactly where checks depend on them.
5. **Deterministic tests.** The suite runs offline, apart from the
   exceptions noted in §12.

---

## 2. Workspace layout

```
mailserv/     the binary: policy (UserSession), authority, auth grants,
              spool, delivery, limits, privilege drop, TLS, driver
smtp/         wire protocol: state machine, framing, DATA transparency
spf/          RFC 7208 evaluation over an abstract resolver (SpfResolver)
dmarc/        RFC 7489 records, policy discovery, alignment, policy
dkim/         RFC 6376/8463 verification (RSA, Ed25519)
mailparse/    RFC 5322/2045 headers: raw byte view + typed (pest) view
dns/          DNS wire codec, pipelined DNS-over-TLS client, TTL cache
dnsq/         DNS query CLI
smtp-client/  demo SMTP client
```

Dependencies only point downward:

```
mailserv → smtp, spf, dkim, dmarc
spf      → dns
dkim     → mailparse, dns
dmarc    → spf      (the SpfResolver trait only)
```

The `smtp` crate depends on nothing but `anyhow`, `tokio` and `base64`, so
it can't see policy internals.

---

## 3. Protocol versus policy

The `smtp` crate owns *what SMTP is*: verbs, states, sequencing, framing.
Every decision is delegated to the `SmtpSession` trait, which `mailserv`
implements as `UserSession`:

```rust
pub trait SmtpSession {
    fn helo(&mut self, ehlo: bool, arg: &str) -> Control;
    fn mail_from(&mut self, path: &str) -> Control;
    fn rcpt_to(&mut self, path: &str) -> Control;
    fn start_data(&mut self) -> Control;
    fn recv_data(&mut self, line: &[u8]) -> DataControl;
    fn end_data(&mut self) -> Control;
    fn reset(&mut self) -> Control;
    fn starttls(&mut self) -> Control;
    fn auth(&mut self, mechanism: &str, initial: Option<&[u8]>) -> Control;
    fn auth_line(&mut self, line: &[u8]) -> Control;
    // … plus the greeting, data_line_too_long, shutdown_signal
}
```

The verdict binds the state machine:

- `Accept`: the command succeeds, and the state advances where the protocol
  allows (HELO → Ready, DATA → Data).
- `Reject` / `Tempfail` (5xx/4xx): **the state does not advance**. A client
  that ignores a `550` to HELO still can't reach MAIL.
- `Upgrade`: STARTTLS. The loop writes the `220` and returns
  `EndReason::TlsHandshake`; the driver does the handshake and resumes the
  loop over TLS.
- `Challenge`: an AUTH continuation. The machine enters
  `SmtpState::Auth(return_to)` and feeds lines to `auth_line` until a final
  verdict, or until the client sends `*`.

`SessionState` (the state plus a `greeted` flag) is owned by the connection
driver, so it survives the STARTTLS pause. `run()` is generic over the
stream, so the same loop serves TCP, TLS and in-memory test duplexes. A
small `TestSession` drives the whole state machine with no policy at all.

---

## 4. Connection lifecycle

```
accept loop (MX port, plus submission-port and submissions-port when set;
             one loop, so all share the limits below)
  canonical_peer(): ::ffff:a.b.c.d → a.b.c.d
  limits: server-wide semaphore, per-IP concurrency, per-IP rate (60 s window)
    over a limit → 421, sent from a bounded pool of 32 refusal tasks
  spawn: timeout_at(max-conn-duration) {
    handle_connection(mode):
      Submissions (465): TLS handshake first, then run(TLS), banner over TLS
      otherwise:
      run(plaintext)
        Upgrade → TLS handshake (rustls, 10 s cap)
                  buffered plaintext after STARTTLS is dropped
                  session.tls_established(): pre-TLS state discarded,
                  authenticated identity cleared, state = Idle, no new banner
        run(TLS)
      log the session summary (never the body)
  }
  release limits
```

**Graceful shutdown** (SIGTERM or SIGINT):
- the listeners close, so new connections are refused;
- sessions are signalled through `shutdown_signal`. The read loop acts on
  it only between transactions: idle sessions get `421 4.3.2`, and a session
  in DATA or AUTH finishes first;
- the process exits when every session has ended, after
  `shutdown-grace-ms`, or on a second signal.

### 4.1 Framing

- **Line caps.** Command lines are capped at 512 octets and data lines at
  64 KiB.
  - An over-long command gets `500` and is drained, and the session
    continues.
  - An over-long data line gets `552` and the session enters `Discard`,
    which swallows everything up to the terminator. The terminator then
    resets the transaction.
- **The DATA terminator is exactly `<CRLF>.<CRLF>`.** In `Data`/`Discard`,
  every line is message data: `RSET`, `QUIT` and all other verbs are
  content (the SMTP-smuggling class, CVE-2023-51764/51765/51766).
  - A bare-LF `.` is data.
  - `.<CRLF>` after a bare-LF line is data too (the `<LF>.<CRLF>` variant).
    The read loop tracks the previous line ending to catch it.
- **Dot-unstuffing** (RFC 5321 §4.5.2) happens in the protocol layer.
  `recv_data` gets raw, unstuffed bytes with their original line ending; it
  is 8-bit safe.
- **`RSET`** clears the envelope but keeps the session greeted. Unknown verbs
  get `500`, and the state is kept.

---

## 5. The message pipeline

| Step | Policy (`UserSession`) |
|---|---|
| **HELO/EHLO** | The argument must be a domain (letters, digits, `-`, `_`; 1–63-octet labels, ≤ 255 total) or an address literal, else `501 5.5.2`, refused *before* it is recorded, because it's copied into `Received:` (a bare CR there would inject a header). SPF is evaluated for the HELO identity under a per-IP DNS permit: Fail → `550`, anything else is just recorded. On a submission listener HELO SPF isn't evaluated (clients send from any network). The EHLO reply advertises `SIZE`, `STARTTLS` (plaintext only) and `AUTH` (submission listeners only, over TLS, when configured). |
| **MAIL FROM** | The path is parsed as `<path> [params]`. Control characters are refused, and `SIZE=` over the server limit gets `552`. A submission listener requires AUTH first (`530 5.7.0`). For an authenticated session, the address must be granted (§10). Otherwise SPF is checked for the sender, or `postmaster@<HELO>` for `<>`: Fail or PermError → `550`, TempError → `451`. |
| **RCPT TO** | MAIL must come first, and at most 100 recipients are allowed. The local-part must be RFC 5321 dot-atom text without `/` or a leading dot (it becomes a directory name), else `553 5.1.3`. Then the authority decides (§7). The recipient's size limit is applied: a declared `SIZE=` over it gets `552`, and a recipient whose limit differs from the transaction's gets `452 4.5.3`. |
| **DATA** | Needs a sender and at least one recipient. Bytes are counted against the transaction's limit; going over it gets `552` and `Discard`. |
| **End of data** | See below. |

**End of data**, in order:

```
1. bare CR in the header block?      → 550 5.6.0   (no DNS work spent)
2. take a per-IP DNS permit          → 451 4.7.0 if none frees within 10 s
   ── one 20 s deadline (END_OF_DATA_DNS_DEADLINE) covers 3 and 6 ──
3. DKIM verify (raw view)            → per-signature verdicts
4. exactly one From:, one domain     → 550 5.7.1 otherwise
5. authenticated? every From author granted (§10) → 550 5.7.1 otherwise
6. DMARC: discover policy, evaluate  → p=reject fail: 550 5.7.1
                                       lookup error:  451 4.4.3
   deadline exceeded at 3 or 6       → 451 4.4.3
7. release the DNS permit
8. spool (durable write)             → 451 4.3.0 if it fails
9. fast-path delivery to each recipient (failures stay queued)
10. clear the envelope; reply 250
```

How the ordering is constrained:

- DKIM runs before DMARC, which consumes its results. DMARC uses **only this
  message's** DKIM results, so a verified signature from an earlier message
  on the connection can't help a later spoof.
- Rejected mail is never spooled.
- The `250` is sent only after the durable write, so accepted mail is never
  silently dropped.
- Every exit clears the envelope, so the next transaction starts with MAIL
  again.

---

## 6. Sender authentication

### 6.1 SPF (`spf`)

- **Parser.** It works term by term (RFC 7208 §4.6.1).
  - Mechanism and modifier names are case-insensitive.
  - Any unknown or malformed term makes the record **PermError**: nothing is
    ever silently skipped.
  - `a`/`mx` take a dual-CIDR suffix (`a/24`, `mx//64`).
  - `redirect=` and `exp=` may each appear at most once.
  - A TXT string counts as a record only if it starts `v=spf1`
    (case-insensitive) followed by a space or the end; `v=spf10` doesn't
    count.
- **Evaluation.** All mechanisms are supported.
  - The RFC 7208 §4.6.4 budget applies: 10 DNS-querying terms and 2 void
    lookups, shared across `include`/`redirect`.
  - A `redirect=` to a domain with no SPF record is PermError (RFC 7208
    §6.1), like an `include:` of one.
  - Macros are expanded per RFC 7208 §7.
  - A whole evaluation has a 20 s deadline (`EVALUATION_DEADLINE`).
  - DNS goes through the `SpfResolver` trait (TXT, A, MX, PTR). Production
    uses the shared DoT client; tests use fixture mocks.
- **Results.** Fail and PermError reject at MAIL. TempError → `451`. Pass,
  Neutral, SoftFail and None are accepted and recorded for DMARC.

### 6.2 DKIM (`dkim`)

- **Input.** DKIM reads only the **raw** message view
  (`mailparse::parse_raw_message`), so untrusted bytes never reach the pest
  grammar (§11). Non-UTF-8 headers still verify.
- **Limits.**
  - At most 5 signatures (the topmost) are evaluated per message.
  - A signature may list at most 256 `h=` entries.
  - Header selection indexes headers by name once, so it is linear
    (RFC 6376 §5.4.2 bottom-up, each instance used once).
- **A signature counts only if all of these hold:**
  - it signs `From` (RFC 6376 §6.1.1);
  - its RSA key is ≥ 1024 bits (RFC 8301; the `rsa` crate caps keys at
    4096 bits);
  - any `l=` equals the canonical body length, so appended content can't
    verify;
  - it hasn't expired (`x=`);
  - its `i=` matches `d=`;
  - the key permits email.
- **Algorithms:** rsa-sha256 and ed25519-sha256. SHA-1 is refused.

### 6.3 DMARC (`dmarc`)

- **From domain.** It comes from a tolerant byte scan of the raw headers,
  which reads the value as an RFC 5322 mailbox-list.
  - Comments and quoted strings never supply the domain.
  - Folding and the obsolete `From :` spelling are understood.
  - Zero, several, multi-domain or unparseable `From:` headers → `550 5.7.1`
    (RFC 7489 §6.6.1).
- **Policy discovery** (`policy_candidates`, `fetch_policy`): query
  `_dmarc.` at the From domain, then at each parent down to two labels,
  making at most 8 queries; stop at the first record.
  - This finds `victim.co.uk` for `x.victim.co.uk` without a Public Suffix
    List.
  - A long name skips straight to its 7-label suffix (the DMARCbis
    tree-walk bound).
  - The result, `FoundPolicy`, records where the record was found, so `sp=`
    applies to inherited policies.
- **Fails closed.** Any lookup error is `DmarcError::Temp` → `451 4.4.3`:
  skipping a name could skip the policy that applies. Several records at one
  name means DMARC isn't applied (RFC 7489 §6.6.3), logged at `warn`.
- **Alignment.** Strict (`adkim`/`aspf=s`) is an exact match. Relaxed is a
  **suffix test**, which is safe but rejects sibling subdomains (§13).
- **Policy.** A `reject` failure → `550`. `quarantine` and `none` are
  delivered. `pct` is treated as 100. Authenticated senders are exempt from
  rejection, but only after the grant check (§10).

---

## 7. Recipient authority

The `RecipientResolver` trait is consulted at RCPT, on the blocking pool
with a 5 s timeout. It answers `NotHosted` (`550 5.7.1`),
`Accept(Recipient)`, or `Refuse { mode, reason }` (`550 5.1.1`, the same
reply for every reason, so addresses can't be enumerated from the reply
text). If the authority can't answer: `451`.

A `Recipient` carries:
- the routing **mailbox** (the address itself, or the catch-all inbox);
- the owning user;
- `public_key` and `key_generation`, reserved for encryption;
- the domain's `max-message-bytes`.

All of this travels with the message in the spool metadata (`SpoolRcpt`).

- **`FileAuthority`** is the production implementation: a strict JSON
  schema (unknown fields rejected), hot-reloaded when the file's mtime or
  size changes.
  - A bad publish keeps the last good snapshot in force and logs at `error`.
    The failed version is remembered, so it isn't re-parsed on every RCPT.
  - Domain modes:
    - `reject`: listed, unexpired mailboxes only;
    - `catch-all`: unknown addresses go to a designated inbox;
    - `grace`: an expired address accepts for N ≤ 366 days.
- **`StaticAuthority`** is the development fallback: every local-part at a
  `--local-domains` domain is accepted and routed to itself.
- **Caching.** Each session caches **successful** lookups only, so every
  refusal reaches the authority. That keeps the console's refusal stream
  complete.

---

## 8. Storage and delivery

**Spool** (`DiskSpool`, `--spool-dir`):
- **Layout.** Maildir-style `tmp/` → `new/`. The payload is written and
  fsynced first, the `.json` metadata last: its presence in `new/` is the
  commit point.
- **Queue IDs** are `<hex seconds>.<uuid>`: sortable and globally unique.
- **Metadata** holds the envelope, peer, HELO, verdicts, TLS state, the
  authenticated identity and the resolved recipients.
- **Seams.** `SpoolWriter` (`write`, `remove`) is the write side, and
  `SpoolQueue` (`list`, `load_payload`, `record_attempt`, `dequeue`,
  `dead_letter`, `sweep_debris`) the read side the drain uses; `DiskSpool`
  implements both. A `PayloadEncryptor` hook exists on the write side, but
  production configures no encryptor (§13).
- **The stored payload is the final message.** At end of data the queue ID
  is assigned, the trace headers are prepended, and that is what is
  written (and would be sealed). The fast path and the drain deliver it
  verbatim, so delivery never touches the message bytes.

**Delivery** (`DeliverySink`, `MaildirSink`, `--maildir-dir`):
- **Path.** One maildir per routing mailbox: `{root}/{domain}/{local}/new`.
  The sink re-validates each path component, as defence in depth against
  path traversal.
- **Idempotent** per (envelope address, queue ID): the file name is
  `{queue ID}.{address}.eml`, so the fast path and the drain can race
  safely, and several catch-all addresses routed to one inbox get one copy
  each. The sink receives the envelope address as metadata.
- **Trace headers** (`with_trace_headers`), written once at acceptance:
  `Return-Path:` and a `Received:` (HELO, peer, `by` host, queue ID, and
  `ESMTP`/`ESMTPS`/`ESMTPA`/`ESMTPSA` per RFC 3848). There is **no `for`
  clause**: one payload serves every recipient, so naming one would
  disclose Bcc recipients to the others. Non-printable bytes in a stored
  HELO are replaced with `?`.
- **Fast path.** Delivery is attempted inside end-of-data, before the
  `250`. A failure is logged, and the message stays queued.

**Queue drain** (startup, then every 60 s, on the blocking pool;
`delivery::drain_at`):
- **Retry schedule.** A message that isn't due yet is skipped without
  reading its payload. "Due" means a backoff of 1 min, doubling to 1 h,
  since its last failure.
- **Attempt record.** Each due message is attempted for every recipient. A
  failure is recorded in `{id}.attempts` as
  `count first_failure last_failure` (a count-only record also loads,
  with the lifetime clock starting at the next failure).
- **Dead-lettering.** A message still failing `MAX_QUEUE_LIFETIME` (5 days)
  after its first failure moves to `spool/dead-letter/` with all its files,
  logged at `error`. Requeuing it is a file move (DEPLOYMENT.md H2).
- **Crash debris.** Each pass first deletes uncommitted files older than
  an hour (`DEBRIS_MIN_AGE`): anything in `tmp/`, and any `.eml` or
  `.attempts` in `new/` without its `.json`. None of these ever got a
  `250`. Age comes from the file's ctime, which a rename updates, so a
  write in progress or a payload just moved back for requeuing is never
  swept. Each removal is logged at `warn`; `dead-letter/` is never touched.
- **Visibility.** A `drain pass` log line with a `queued` count is emitted
  while the queue isn't empty (or when the pass removed debris).

**File modes.** Files are `0600` and directories `0700`, set explicitly,
with `umask 077` as a backstop. Existing directories that are open to other
users produce a startup warning.

---

## 9. DNS layer (`dns`)

- **Codec.** Parsing is **total**: every index is bounds-checked, rdata is
  bounded by `rdlength`, and compression pointers are range-checked and
  depth-limited. This is tested by every truncation length and about 5,800
  bit-flips of a real response.
  - Responses are validated: ID, QR flag, question echo, and EDNS0 (one OPT
    record, root owner, version 0).
  - Queries advertise a 1232-byte EDNS0 payload.
  - Query names over the label/length limits are refused before sending,
    and treated as non-existent by SPF.
- **Transport.** DNS-over-TLS only; UDP was removed. The resolver's
  certificate is verified against the `--resolver` IP using the web PKI
  roots, plus any `--resolver-ca` certificates, which are added rather than
  substituted. There's one upstream, IPv4 only.
- **Pipelining.** `--dns-connections` connections (default 2), each with up
  to 64 queries in flight.
  - Replies are matched by transaction ID, and IDs are never reused while in
    flight.
  - A timed-out query releases its slot without harming the connection.
  - A connection failure fails every waiter, and each retries once on a
    fresh connection.
  - Every per-query resource is released by a drop guard, so cancellation
    leaks nothing.
- **Cache.** TTL-based, holding up to 4,096 entries. Positive answers use
  the minimum answer TTL; NXDOMAIN and NODATA use the SOA negative TTL. Both
  are clamped to 1 h, and SERVFAIL is never cached.
- **Per-source-IP limit** (`DnsLimiter`, `--max-dns-per-ip`, default 4).
  - A session holds one of its IP's permits around each DNS-backed check:
    the HELO SPF check, the MAIL FROM SPF check, and end-of-data DKIM +
    DMARC.
  - If no permit frees within 10 s, the result is temporary, never a
    permanent reject: HELO records TempError; MAIL FROM and end-of-data get
    `451 4.7.0`.
- **Metrics.** A `dns stats` log line is emitted every 60 s while DNS is in
  use: queries, cache hits, connects, failures, timeouts, late replies,
  waits, in-flight peaks and per-IP limiter counts.

---

## 10. Submission, AUTH and sender grants

- **Listeners.** `submission-port` (normally 587: plaintext, then STARTTLS;
  RFC 6409) and `submissions-port` (normally 465: implicit TLS; RFC 8314).
  Each needs `tls-cert`/`tls-key` and `auth-users-file`, and no two
  listeners may share a port (startup errors). All are bound while still
  privileged. Setting `auth-users-file` without a submission port is
  warned about: the logins can't be used.
- **Where AUTH is offered.** Only on submission listeners, and only over
  TLS (`538` on plaintext; RFC 8310). The MX listener never advertises it
  and answers `502 5.5.1`. On submission, MAIL FROM before AUTH gets `530
  5.7.0`.
- **Mechanisms.** AUTH PLAIN and LOGIN (RFC 4954/4616), matched
  case-insensitively, with challenge continuation and `*` to abort. Each
  AUTH command starts from a clean state, so an aborted LOGIN leaves
  nothing behind.
- **Credentials.** `--auth-users-file` names a file of `user:hash` lines
  (`#` comments allowed), read once at startup while still privileged.
  - Each hash is an argon2id PHC string, made with `mailserv
    hash-password` (default cost: 19 MiB, 2 passes, 1 lane). Anything
    else, including a plaintext password, is a startup error; hashes
    below OWASP's minimum cost load with a warning.
  - The file is refused if "other" users can read it, and a
    group-readable file is warned about. The old inline `auth-users`
    config key is a startup error.
- **Checking a password** (`AuthConfig::check`):
  - a session gets 3 wrong passwords, then every AUTH gets `454 4.7.0`
    without a check;
  - each source IP gets 10 failures per 15 minutes, counted across
    sessions (success doesn't reset it); past that, `454` without a check;
  - checks run on the blocking pool, at most one per CPU at a time;
  - an unknown login is checked against a dummy hash with the same
    parameters, and the argon2 comparison is constant-time, so timing
    reveals neither whether a login exists nor how close a guess was.
- **Grants.** `--auth-senders` (`auth.rs`, `SenderGrants`) maps each login to
  exact addresses and `@domain` grants.
  - An authenticated `MAIL FROM` must be granted, or the reply is `553
    5.7.1`; the null sender is always refused.
  - Every `From:` author must be granted, or the reply is `550 5.7.1`.
  - Matching is case-insensitive. A quoted local-part matches only a
    whole-domain grant.
  - A login without grants can authenticate but can't send. A grant for a
    login without credentials is a startup error.
- **Exemptions.** Authenticated sessions skip SPF and are exempt from DMARC
  rejection. Both apply only after the grant checks pass, so being
  authenticated never means "may use any From".
- **Relay stays closed** even for authenticated sessions: submitted mail
  can go only to hosted recipients. Sending to other domains is post-V1.

---

## 11. Header parsing (`mailparse`)

There are two views of a message:

- **Raw:** `parse_raw_message` returns a `RawMessage { headers, body }`. It
  keeps every header in order, duplicates included, byte-exact with folding.
  It is built by an iterative byte scan, accepts non-UTF-8, and can't fail on
  header syntax.
- **Typed:** `parse_message` returns `ParsedMessage::typed` (`MailHeaders`),
  produced by a pest grammar: addresses, dates, MIME parameters, trace
  entries. Headers the grammar can't match degrade to `optional_field`,
  but building the view is strict: a repeated singleton field (`From`,
  `Subject`, ...), an unparseable date, or an address field without a
  mailbox fails the typed parse. Because the
  grammar's `comment` rule is recursive, `parse_headers` first runs a
  conservative pre-scan and refuses more than 64 levels of nesting
  (`TooDeeplyNested`). A stack overflow aborts the process; it isn't a
  panic, so nothing could catch it.

**Invariant:** untrusted mail is parsed only through the raw view. In the
server, DKIM takes `&RawMessage`, and the From-domain and bare-CR scans
work on bytes. Nothing in the server calls the typed parser. The depth
bound only protects library callers that use it.

---

## 12. Configuration, operations and testing

- **Configuration.** Values come from CLI flags, then the `--config` TOML
  file (kebab-case keys), then defaults. A pure, unit-tested
  `resolve_config` handles this.
  - Defaults are production defaults: port 25, `/var/lib/mailserv`, 10 MiB
    messages, a 5-minute connection cap, 100 connections.
  - Only `--domain` is required.
- **Privileges.** Started as root, mailserv:
  1. binds the port;
  2. reads the TLS key, resolver CA and AUTH credentials file;
  3. creates missing storage directories owned by `--user`;
  4. drops supplementary groups, gid and uid, and verifies that root can't
     be regained;
  5. only then opens the authority, spool and maildirs, and accepts
     connections.

  Root without `--user` is refused.
- **Logging.** bunyan JSON on stdout, filtered by `RUST_LOG` (default
  `info`). Bodies are never logged, and the per-line `recv_data` span is at
  `trace`. The accept loop survives transient errors (log and back off), and
  every connection task's outcome is logged.
- **Testing.** 273 tests in four layers:
  1. **unit**, per crate;
  2. **protocol**, driving the state machine through `handler`;
  3. **framing**, running `run()` over in-memory duplexes;
  4. **integration**, with a real rustls client against the real driver
     over loopback.

  Conformance anchors are external, never circular: DKIM hashes come from
  openssl or the RFC's own examples, SPF fixtures from recorded real
  records, and DNS hostile-input tests mutate a real response. Every fixed
  security finding has a test that reproduces its attack; the tests are
  named for the property they check (the archived reviews in
  `docs/reviews/` record which finding each property came from).

  The DMARC tests use a local mock DoT resolver. Two things touch the
  network:
  - the `mailserv` integration tests use the real resolver (1.1.1.1);
  - one `#[ignore]`d test fetches a live DKIM key.

---

## 13. Gap assessment

Current design gaps, by area. Impact assumes the V1 receive-only pilot.
The Plan column is the section of [PLAN.md](PLAN.md) that tracks the fix.

### Abuse resistance

| Gap | Impact | Plan |
|---|---|---|
| No storage quotas (per message, mailbox or domain) and no free-disk tempfail | A sender can fill the disk. Contained only by a dedicated filesystem and alerts | §2.4.1 |
| No session-wide limit on refused RCPTs (`RSET` resets the 100 cap) | Unlimited probing for which addresses exist; a privacy problem for disposable addresses | §2.4.2 |
| Per-IP limits are per address (no IPv6 /64 aggregation) | An IPv6 sender escapes them; relevant only with an IPv6 listener | §6 |
| The per-IP connection count is released manually, not by a drop guard | A panicking session leaks it (no remote panic is known) | §2.4.6 |

### Correctness and delivery

| Gap | Impact | Plan |
|---|---|---|
| The connection cap can fire between the spool commit and the `250`; the fast path runs before the reply | The client retries, and the message is delivered twice | §2.4.3 |
| No fsync of the maildir directory after the rename; crash leftovers in a maildir's `tmp/` aren't swept (the spool's are) | A crash can lose a just-delivered file (it's still in the spool unless it was dequeued); `tmp/` debris accumulates | §2.4.6 |
| SPF budget charges MX-host and PTR-name address lookups against the 10-term limit | Large legitimate records can hit PermError → `550` | §2.4.4 |
| Relaxed DMARC alignment is a suffix test, not an organisational-domain comparison (no PSL) | Sibling subdomains fail alignment → legitimate mail rejected under `p=reject` | §2.4.4 |
| No SPF alignment for the null sender | Unsigned bounces from `p=reject` domains are rejected | §2.4.4 |
| SPF `a`/`mx` don't query AAAA | IPv6 senders authorised only that way fail SPF | §6 |
| Commands before EHLO get `500`, not `503`; EHLO doesn't reset an in-flight envelope; the 512-octet cap truncates long AUTH PLAIN responses | Protocol conformance | §2.4.6 |
| DKIM accepts duplicate tags; the key's `k=` isn't checked against the signature's `a=` | Low (the cryptography must still verify) | §2.4.6 |
| `quarantine` is delivered as normal mail | Out of V1 scope by decision | — |

### What users are shown

| Gap | Impact | Plan |
|---|---|---|
| No `Authentication-Results:` header is added, and forged inbound ones aren't stripped | Readers that trust A-R can be misled | §2.4.5 |
| Display names aren't checked against the author domain | `From: "ceo@victim" <x@attacker>` passes | §2.4.5 |

### Storage and encryption seams

| Gap | Impact | Plan |
|---|---|---|
| `PayloadEncryptor` has no recipient parameter and isn't configured | Per-user encryption isn't available; mail is stored as plaintext | §5 |
| Final storage is local maildir only | Blocks multiple MX hosts sharing mailboxes | §5 |

### Operations

| Gap | Impact | Plan |
|---|---|---|
| One listen address (`--host`), one identity (`--domain`), one certificate; no SNI selection; no TLS hot reload | A restart is needed to change certificates; there are no per-domain MX identities | §5, §6 |
| One IPv4 resolver; no back-off when it's down; concurrent misses aren't shared | A resolver outage defers all mail (safe, but nothing is received) | §6 |
| Metrics are log lines only (`dns stats`, `drain pass`) | Monitoring has to parse logs | §6 |
| No DNSSEC validation in mailserv | It relies on the resolver; use a validating local resolver | — |

### Submission and AUTH

| Gap | Impact | Plan |
|---|---|---|
| The credentials file is read only at startup | Revoking a login needs a restart | §2.3 |
| Submitted mail can only go to hosted recipients | No outbound relay; not a full MSA | §6 |

### Parsing

| Gap | Impact | Plan |
|---|---|---|
| The typed `mailparse` view: no RFC 2047 decoding; `Content-Disposition` is recognised but not extracted; `Received:` with comments falls back to raw; more than 64 unclosed `(` in a header block is refused | Affects only library and future UI use, not the server | §6 |
