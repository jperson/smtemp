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
mailserv/     the binary (modules below)
smtp/         wire protocol: state machine, framing, DATA transparency
spf/          RFC 7208 evaluation over an abstract resolver (SpfResolver)
dmarc/        RFC 7489 records, policy discovery, alignment, policy
dkim/         RFC 6376/8463 verification (RSA, Ed25519)
mailparse/    RFC 5322/2045 headers: raw byte view + typed (pest) view
dns/          DNS wire codec, pipelined DNS-over-TLS client, TTL cache
dnsq/         DNS query CLI
smtp-client/  demo SMTP client
fuzz/         libFuzzer targets (a separate workspace; see fuzz/README.md)
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

Inside `mailserv`:

```
main.rs        entry point: arguments, logging, then config::load and server::run
lib.rs         the library part: address and headers, pure functions over
               untrusted bytes (so they can be fuzzed)
config.rs      CLI flags, the TOML file, their merge (resolve_config), startup checks
server.rs      startup, listeners, privilege drop, accept loop, limits, signals,
               handle_connection (drives one session over TCP/TLS)
session.rs     UserSession: the SmtpSession policy (HELO, AUTH, MAIL, RCPT, DATA);
               Transaction: one message's envelope, verdicts and data
session/message.rs   end of data: header checks, DKIM, DMARC, spool, fast path
address.rs     envelope syntax: paths, ESMTP parameters, HELO, local-part rules
headers.rs     raw header checks: the single From:, its authors, bare CRs
tls.rs         certificates, resolver CA, handshakes
verdict.rs     DKIM/DMARC summaries recorded with each message
quota.rs       storage limits: mailbox quota, free-disk floor
auth.rs        credentials (argon2id), reload, sender grants
authority.rs   recipient authority (file-backed, hot-reloaded)
spool.rs       durable queue (SpoolWriter, SpoolQueue, DiskSpool)
delivery.rs    trace headers, DeliverySink, MaildirSink, the drain
limit.rs       per-IP connection, DNS and AUTH-failure limits
privdrop.rs, fsutil.rs, hashpw.rs   privileges, file modes, `hash-password`
```

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
    // … plus the greeting, data_line_too_long, shutdown_signal, deadline
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
  limits: server-wide semaphore, per-IP concurrency, per-IP rate (60 s window);
          both held as guards (a permit, a ConnectionSlot) that release on drop
    over a limit → 421, sent from a bounded pool of 32 refusal tasks
  spawn: timeout_at(deadline + 120 s backstop) {
    handle_connection(mode):        deadline = accept + max-conn-duration
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

**Connection deadline.** `max-conn-duration-ms` is enforced by the session
itself (`SmtpSession::deadline`), not by cancelling it: every read waits at
most until the deadline, and when it's reached the client gets `421 4.4.2`
and the connection closes. Handling a line and writing its reply are never
cut short, so a message whose terminator has arrived is always processed and
answered. That matters because the spool commit happens inside end of data:
cancelling between the commit and the `250` would make the client send the
message again. A slow-drip DATA transfer is still cut off at the deadline,
before end of data, so nothing is committed. The outer `timeout_at`, 120 s
later, only stops a task stuck in a handshake or a write.

**Graceful shutdown** (SIGTERM or SIGINT):
- the listeners close, so new connections are refused;
- sessions are signalled through `shutdown_signal`. The read loop acts on
  it only between transactions: idle sessions get `421 4.3.2`, and a session
  in DATA or AUTH finishes first;
- the process exits when every session has ended, after
  `shutdown-grace-ms`, or on a second signal.

**SIGHUP** reloads the credentials file (§10). It never stops the server.

### 4.1 Framing

- **Line caps.** Command lines are capped at 512 octets and data lines at
  64 KiB. AUTH commands and the lines of an AUTH exchange may be up to
  12288 octets (RFC 4954 §4), for long initial responses and tokens.
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
- **`RSET`** ends the transaction but keeps the session greeted (so does
  an accepted HELO/EHLO, RFC 5321 §4.1.4). MAIL, RCPT and DATA before
  HELO/EHLO get `503 5.5.1`; NOOP, HELP, VRFY and EXPN work in any state
  outside DATA (RFC 5321 §4.1.4). Unknown verbs get `500`, and the state
  is kept.

---

## 5. The message pipeline

**The transaction.** Everything that belongs to one message (envelope
sender and its SPF verdict, declared size, recipients, size limit, data)
lives in one `Transaction`, created when MAIL FROM is accepted and held as
`UserSession::txn`. It ends by being dropped: at end of data (which takes
it out of the session first, whatever the outcome), at RSET and the reset
after an aborted transfer, at an accepted HELO/EHLO, and at STARTTLS. No
per-message field is reset by hand, so none can leak into the next
message.

| Step | Policy (`UserSession`) |
|---|---|
| **HELO/EHLO** | The argument must be a domain (letters, digits, `-`, `_`; 1–63-octet labels, ≤ 255 total) or an address literal, else `501 5.5.2`, refused *before* it is recorded, because it's copied into `Received:` (a bare CR there would inject a header). SPF is evaluated for the HELO identity under a per-IP DNS permit: Fail → `550`, anything else is just recorded. On a submission listener HELO SPF isn't evaluated (clients send from any network). The EHLO reply advertises `SIZE`, `STARTTLS` (plaintext only) and `AUTH` (submission listeners only, over TLS, when configured). |
| **MAIL FROM** | Below the free-disk floor (`min-free-disk-bytes`, on the spool and maildir filesystems) → `452 4.3.1`, and no transaction starts. The path is parsed as `<path> [params]`. Control characters are refused, and `SIZE=` over the server limit gets `552`. A submission listener requires AUTH first (`530 5.7.0`). For an authenticated session, the address must be granted (§10). Otherwise SPF is checked for the sender, or `postmaster@<HELO>` for `<>`: Fail or PermError → `550`, TempError → `451`. |
| **RCPT TO** | MAIL must come first. A connection that has had `max-refused-rcpt-per-session` refused recipients, or whose IP has had `max-refused-rcpt-per-ip` in the last 15 minutes, gets `421 4.7.0` and is closed (`Control::Close`), before the authority is asked; valid recipients get the same `421`, so probing learns nothing more. At most 100 recipients are allowed. The local-part must be RFC 5321 dot-atom text without `/` or a leading dot (it becomes a directory name), else `553 5.1.3`. Then the authority decides (§7). The recipient's size limit is applied: a declared `SIZE=` over it gets `552`, and a recipient whose limit differs from the transaction's gets `452 4.5.3`. Then the mailbox quota (the authority's `quota_bytes` for the routing mailbox, else `mailbox-quota-bytes`): the routing mailbox's stored bytes (`DeliverySink::usage`) must be under the quota, with room for any declared `SIZE=`, else `452 4.2.2` for that recipient only. |
| **DATA** | Needs a sender and at least one recipient. Bytes are counted against the transaction's limit; going over it gets `552` and `Discard`. |
| **End of data** | See below. |

**End of data**, in order:

```
1. bare CR in the header block?      → 550 5.6.0   (no DNS work spent)
2. take a per-IP DNS permit          → 451 4.7.0 if none frees within 10 s
   ── one 20 s deadline (END_OF_DATA_DNS_DEADLINE) covers 3 and 6 ──
3. DKIM: fetch the keys (async), then verify on the blocking pool
                                     → per-signature verdicts
4. exactly one From:, one domain     → 550 5.7.1 otherwise
5. authenticated? every From author granted (§10) → 550 5.7.1 otherwise
6. DMARC: discover policy, evaluate  → p=reject fail: 550 5.7.1
                                       lookup error:  451 4.4.3
   deadline exceeded at 3 or 6       → 451 4.4.3
7. release the DNS permit
8. free-disk floor still met?        → 452 4.3.1 otherwise
9. spool (durable write)             → 451 4.3.0 if it fails
   reply 250
10. fast-path delivery to each recipient, in the background (failures
    stay queued for the drain)

(The transaction was taken out of the session before step 1, so every
exit has already ended it.)
```

How the ordering is constrained:

- DKIM runs before DMARC, which consumes its results. DMARC uses **only this
  message's** DKIM results, so a verified signature from an earlier message
  on the connection can't help a later spoof.
- Rejected mail is never spooled.
- The `250` is sent only after the durable write, so accepted mail is never
  silently dropped.
- DKIM verification is attacker-controlled CPU work (canonicalising and
  hashing the whole message, a public-key operation per signature), so only
  the key lookups run on the async workers (`dkim::fetch_keys`); the checks
  run on the blocking pool (`dkim::verify_with_keys`).
- Refused recipients count against two budgets: the connection's (on the
  session, not the transaction, so RSET doesn't reset it) and the source
  IP's (a `FailureLimiter`, the same fixed window the AUTH failures use).
  Only authority refusals and relay attempts count; deferrals (quota,
  size, authority outage) don't. Closing with `421` is temporary: a real
  MTA has already bounced the recipients that got `550`, and retries the
  rest later.
- The quota is soft: it is checked at RCPT, before the data, so a mailbox
  can exceed it by at most one message (whose size wasn't declared).
  Deferring a full mailbox's recipient with `452` does reveal that the
  address exists, unlike the uniform `550` for refused addresses; quotas
  should rarely be reached.

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
    lookups, shared across `include`/`redirect`. `mx` and `ptr` are one
    term each: the address lookups behind them aren't terms or void
    lookups (an IPv6-only MX host has no A records). Instead, one `mx`
    with more than 10 exchanges is PermError, and `ptr` considers only
    the first 10 names.
  - A `redirect=` to a domain with no SPF record is PermError (RFC 7208
    §6.1), like an `include:` of one.
  - Macros are expanded per RFC 7208 §7.
  - A whole evaluation has a 20 s deadline (`EVALUATION_DEADLINE`).
  - DNS goes through the `SpfResolver` trait (TXT, A, MX, PTR), whose
    lookups return `dns::Lookup`: found, absent (NXDOMAIN, no records,
    an invalid name) or a temporary error, matched exhaustively, so no
    lookup can mistake a SERVFAIL for "no record". Production uses the
    shared DoT client; tests use fixture mocks.
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
  - the key permits email;
  - the key's `k=` is the algorithm of the signature's `a=` (RFC 6376
    §6.1.2).
- **Tag lists.** A tag that occurs twice invalidates the whole signature
  or key record (RFC 6376 §3.2), so two `d=` can't be read two ways.
- **Algorithms:** rsa-sha256 and ed25519-sha256. SHA-1 is refused.
- **Key lookups** are `dns::Lookup`s: absent is `NoKeyRecord` (permanent),
  a temporary error (SERVFAIL, timeout) is `KeyLookupFailed`, which the
  summary records as `temporary`. A DMARC rejection that such a signature
  could have avoided (its domain aligns with From) is deferred with `451`
  instead: a DNS hiccup must not refuse legitimate mail for good.

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
- **Alignment.** Strict (`adkim`/`aspf=s`) is an exact match. Relaxed
  compares **organizational domains** (RFC 7489 §3.2) from a vendored,
  dated Public Suffix List (`dmarc::psl`, ICANN and private sections), so
  `mail.example.com` aligns with `news.example.com` while
  `alice.github.io` and `bob.github.io` don't. It is parsed at startup
  (the log records its version); Unicode rules are converted to `xn--`
  form.
- **The SPF identity.** The MAIL FROM domain, or for the null sender (a
  bounce) the HELO name, which is what SPF evaluated (RFC 7208 §2.4), so
  an unsigned bounce from a `p=reject` domain aligns when its HELO host
  passes SPF in the same organization.
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
- the domain's `max-message-bytes`;
- the routing mailbox's quota (`quota_bytes`): its own `quota-bytes`, else
  its domain's, else `None` (the server's `mailbox-quota-bytes` applies);
  `Some(0)` means no quota. The authority resolves this, so a console or
  database backend only has to supply the same field.

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
  authenticated identity and the resolved recipients. Verdicts are stored
  under stable names (`pass`, `softfail`, `temperror`; `reject`,
  `quarantine`), never Rust variant names; files written with the older
  variant names still load.
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
- **Usage** (`DeliverySink::usage`, for the mailbox quota). The maildir
  sink sums the files in `new/` and `cur/` and caches the result for 60 s
  (at most 10,000 mailboxes); deliveries through the sink add to the cached
  value at once, so only changes made by other tools wait for a rescan.
- **Durable.** Each copy is written to `tmp/` and fsynced, renamed into
  `new/`, and then `new/` itself is fsynced, so the rename survives a power
  cut before the message is dequeued. Crash leftovers in a maildir's
  `tmp/` older than an hour are swept at startup and hourly
  (`DeliverySink::sweep_debris`).
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
- **Verdict headers**, after `Received:`:
  - `Authentication-Results:` (RFC 8601), authserv-id `--domain`: `auth`
    for a submission, `spf` with `smtp.mailfrom` (or `smtp.helo` for a
    bounce), one `dkim` per signature, `dmarc` with `header.from` (or
    `none`). Sender-chosen values (selectors, names) are reduced to
    `[A-Za-z0-9.-_+@]`.
  - `X-Display-Name-Warning:` when the From display name or a comment
    contains an address whose organizational domain is none of the
    authors' (encoded-words decoded first). A warning, not a refusal:
    list software (Google Groups' "alice@example.com via Team") does
    this legitimately. The claims are also in the spool metadata
    (`display_name_claims`) and the log.
  - Before these are added, the message's own `Authentication-Results:`
    claiming our authserv-id, and any `X-Display-Name-Warning:`, are
    removed (RFC 8601 §5), so a sender can't plant a "pass".
- **Fast path.** After the spool commit, delivery to each recipient
  starts in a background task and the `250` goes out at once. A failure is
  logged and the message stays queued for the drain; when every copy is
  delivered the message is dequeued. At most 64 fast-path deliveries run at
  once, server-wide; past that the drain delivers. A fast path cut off by a
  restart is harmless: the message is still queued and delivery is
  idempotent.

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

- **Lookups.** `DnsClient::lookup` is the one place a reply becomes a
  `Lookup`: NOERROR with answers of the type is found; NOERROR without,
  NXDOMAIN and an invalid name are absent; every other rcode, a timeout
  and a failure are a temporary error. `DnsClient::query` reports why it
  got no reply as a typed `QueryError`.
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
  (`#` comments allowed), read at startup while still privileged.
  - Each hash is an argon2id PHC string, made with `mailserv
    hash-password` (default cost: 19 MiB, 2 passes, 1 lane). Anything
    else, including a plaintext password, is a startup error; hashes
    below OWASP's minimum cost load with a warning.
  - The file is refused if "other" users can read it. The old inline
    `auth-users` config key is a startup error.
  - **SIGHUP reloads it** (`AuthConfig::reload`, on the blocking pool).
    The new logins replace the old as a whole; a file that fails any check
    is refused and the current logins stay. A removed login can't
    authenticate again and can't send, even on a session that
    authenticated before the reload (each grant check requires the login
    to still exist). Failure counts carry over. A grant for a removed login
    is inert and logged (at startup it would be an error). The reload runs
    as the service user, so the file must be readable by it: owner root,
    group the service group, mode `0640`. Startup warns if it isn't.
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
  - Grants come from `--auth-senders` and change only on restart.
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

**One scanner.** Every check that looks at headers uses the same raw
scanner (`find_separator` for where headers end, `extract_raw_headers`
for the fields and their byte spans): DKIM, the From scan, the bare-CR
check and verdict stripping. They can't disagree about where a field
starts or ends, the parser differential that lets one check see a header
another misses. A line that is neither a field nor a continuation ends
the field before it, so a continuation after it belongs to no field.

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
  2. reads the TLS key, resolver CA and AUTH credentials file (a SIGHUP
     reload later reads the credentials again, as the service user);
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
- **Testing.** 328 tests in four layers:
  1. **unit**, per crate;
  2. **protocol**, driving the state machine through `handler`;
  3. **framing**, running `run()` over in-memory duplexes;
  4. **integration**, with a real rustls client against the real driver
     over loopback.

  **Fuzzing** (`fuzz/`): libFuzzer targets for the SMTP session, the
  header scanner and checks, DKIM, SPF, DMARC with the PSL, and the DNS
  decoder, each checking invariants as well as crashes. CI runs each for
  30 seconds over its seeds; past findings are kept as seeds.

  Conformance anchors are external, never circular: DKIM hashes come from
  openssl or the RFC's own examples, SPF fixtures from recorded real
  records, and DNS hostile-input tests mutate a real response. Every fixed
  security finding has a test that reproduces its attack; the tests are
  named for the property they check (the archived reviews in
  `docs/reviews/` record which finding each property came from).

  Every DNS-backed test uses a local mock DoT resolver on loopback
  (`testutil::spawn_mock_resolver` in `mailserv`; the integration tests'
  one answers NXDOMAIN, as the real DNS does for the `.test` and
  `.example` names they use). The suite needs no network beyond loopback;
  only one `#[ignore]`d test fetches a live DKIM key.

---

## 13. Gap assessment

Current design gaps, by area. Impact assumes the V1 receive-only pilot.
The Plan column is the section of [PLAN.md](PLAN.md) that tracks the fix.

### Abuse resistance

| Gap | Impact | Plan |
|---|---|---|
| The mailbox quota is soft (one message over) and doesn't count mail still queued for the mailbox | A mailbox can exceed its quota by one message plus its queue backlog | §2.4.1 |
| The refused-recipient budget is per IP address (no IPv6 /64 aggregation), and a large provider's shared outbound IP can exhaust it with legitimate refusals | An IPv6 prober can rotate addresses; mail from a busy shared IP can be deferred for up to 15 minutes | §2.4.2, §6 |
| Per-IP limits are per address (no IPv6 /64 aggregation) | An IPv6 sender escapes them; relevant only with an IPv6 listener | §6 |

### Correctness and delivery

| Gap | Impact | Plan |
|---|---|---|
| The Public Suffix List is a snapshot | A suffix added after it was taken isn't known; alignment there falls back to the last-two-labels rule | §2.4.3 (refresh) |
| SPF `a`/`mx` don't query AAAA | IPv6 senders authorised only that way fail SPF | §6 |
| `quarantine` is delivered as normal mail | Out of V1 scope by decision | — |

### What users are shown

| Gap | Impact | Plan |
|---|---|---|
| Only display names containing an address are checked; lookalike characters (`＠`, Cyrillic letters) and brand names aren't | `From: "PayPal Support" <x@attacker>` gets no warning | §2.4.4 |
| The display-name warning is a header; mail clients don't show it | Protection depends on a UI (the console) surfacing it | §2.4.4 |

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
| `--auth-senders` grants are read only at startup | Changing what a login may send as needs a restart (revoking the login itself doesn't) | §6 |
| Submitted mail can only go to hosted recipients | No outbound relay; not a full MSA | §6 |

### Parsing

| Gap | Impact | Plan |
|---|---|---|
| The typed `mailparse` view: no RFC 2047 decoding; `Content-Disposition` is recognised but not extracted; `Received:` with comments falls back to raw; more than 64 unclosed `(` in a header block is refused | Affects only library and future UI use, not the server | §6 |
