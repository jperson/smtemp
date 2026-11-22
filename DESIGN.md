# DESIGN.md — Architecture of mailserv

This document describes the system as it stands today: the crate layout,
the core design idea, the request pipeline, the security model, and the
testing strategy. For the work backlog, see [PLAN.md](PLAN.md); this
document explains *why the code is shaped the way it is*.

---

## 1. Overview

**mailserv** is a small SMTP server written in Rust: it accepts mail over
(plaintext or STARTTLS) SMTP, evaluates SPF, DKIM, and DMARC, enforces a
closed-relay recipient policy, optionally authenticates submitters, and
structurally logs every decision. Accepted mail is durably spooled and
delivered to local maildirs (PLAN §Phase 7); the hosted per-user mailbox
backend arrives with the platform (PLAN §Phase 12).

**V1 product scope is receive-only**: a hosted email service —
inbound MX delivery to user-owned addresses on BYO domains (permanent
by default, optional per-address expiry), no sending. Send-side
features (submission/MSA, DKIM signing) are post-V1 and low priority;
the architecture keeps their hooks so they can be added later (PLAN
§Phase 8, §Phase 12).

Design goals, in order:

1. **Correctness over features.** Every protocol behavior is pinned by a
   test; every reply is justified by an RFC citation in a comment.
2. **Binding policy.** The policy layer's verdicts are enforced by the
   protocol layer, not advisory (see §3).
3. **Byte fidelity.** Mail is bytes: bodies, folded headers, and
   canonicalization inputs are preserved exactly where security checks
   depend on them.
4. **Deterministic tests.** The suite (229 tests) runs offline; live
   network behavior is behind `#[ignore]` opt-ins and fixture mocks
   (the `mailserv` integration tests exercise the real resolver path —
   see README, Testing).

---

## 2. Workspace layout

Crate-per-component, each independently testable:

```
mailserv/       the binary: policy (UserSession), TLS acceptor, driver loop
smtp/           wire protocol: state machine, framing, DATA transparency
spf/            RFC 7208 evaluation over an abstract DNS resolver
dmarc/          RFC 7489 record parsing, alignment, policy application
dkim/           RFC 6376/8463 verification (canonicalization, hashing, RSA/Ed25519)
mailparse/      RFC 5322/2045 header parsing: raw + typed views (pest grammar)
dns/            DNS wire codec + DNS-over-TLS queries (hostile-input hardened)
dnsq/           CLI query tool (uses the dns crate)
smtp-client/    CLI test client
```

Dependency direction is strictly downward: `mailserv → {smtp, spf, dkim,
dmarc, mailparse}` → `spf → dns`, `dkim → {mailparse, dns}`. The `smtp`
crate depends on nothing but `anyhow`/`tokio`/`base64` — it cannot see
policy internals.

---

## 3. The core idea: protocol vs. policy

The central design is a strict seam between *what SMTP is* and *what this
server is*. The `smtp` crate owns the former — verbs, states, sequencing,
framing — and delegates every decision to a policy trait:

```rust
pub trait SmtpSession {
    // One callback per decision point, each returning a Control:
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
    ...
}
```

The currency across the seam is the **verdict**, and it binds:

- `Control::Accept` — the command succeeds; the state machine advances
  where the protocol allows (HELO → Ready, DATA → Data).
- `Control::Reject` / `Tempfail` — refused (5xx/4xx); **the state does not
  advance**. A client that ignores a `550` HELO rejection still cannot
  reach MAIL (this is enforced and tested, not assumed).
- `Control::Upgrade` — STARTTLS: the loop writes the `220`, returns
  `EndReason::TlsHandshake`, and the driver performs the handshake and
  resumes `run()` over the TLS stream.
- `Control::Challenge` — AUTH continuation: the machine enters
  `SmtpState::Auth(return_to)` and feeds lines to `auth_line` until a
  final verdict (or the client's `*` abort).

Why this shape works: across three rewrites of everything above the seam
(SPF policy rewritten twice, DKIM added, STARTTLS + AUTH added), the seam
itself barely moved — the migration to verdict-based control was
mechanical. It also makes the protocol layer testable without any policy:
a 40-line `TestSession` drives the full state machine in-process.

The state is carried in `SessionState` (state + `greeted` flag), owned by
the **connection driver** (`mailserv::handle_connection`) rather than
`run()`, so it survives the STARTTLS pause. `run` is generic over
`AsyncRead + AsyncWrite + Unpin + Send`, which is what allows the same
loop to serve `TcpStream`, a TLS stream, and in-memory duplexes in tests.

---

## 4. The connection lifecycle

```
accept → handle_connection:
    UserSession::new(policy state)                    ← policy config
    run(BufReader<TcpStream>, SessionState)           ← plaintext loop
      │ QUIT/EOF/timeout  → end
      │ Control::Upgrade  → TLS handshake (rustls, 10 s cap)
      │                     session.tls_established()   ← discard pre-TLS state
      │                     state = Idle, no re-banner  ← RFC 3207 §4.2
      └─── run(BufReader<TlsStream>, SessionState)      ← secure loop
    log session summary (envelope verdicts; never bodies)
```

Session policy state (`UserSession`): HELO identity + its SPF verdict,
envelope sender + SPF verdict, recipients, accumulated raw body, DKIM
results, DMARC verdict, authenticated identity, TLS state.

### 4.1 Framing

- Command lines capped at **512 octets** (RFC 5321 §4.5.3.1.4), data
  lines at **64 KiB** (deliberately above the RFC's 1000-octet
  interop guidance; the cap is a per-implementation constant). Over-long
  lines get `500`/`552`, are drained (under the read timeout), and the
  session continues — a data-mode overflow aborts into a `Discard` state
  that swallows until the terminator. That terminator ends the failed
  transaction: the protocol layer calls `reset()`, so the envelope and any
  buffered data are cleared (RFC 5321 §4.1.1.4) and the next MAIL works.
  The policy is told about an over-long line through `data_line_too_long`,
  so the dropped message is logged.
- DATA: the terminator is **exactly `<CRLF>.<CRLF>`**. In `Data` and
  `Discard` states every line is message data — `RSET`, `QUIT`, and all
  other verbs are content, never commands (the SMTP-smuggling class,
  CVE-2023-51764/51765/51766). A bare-LF `.` is an empty data line,
  never a terminator, and a `.<CRLF>` line only terminates when the line
  before it also ended with CRLF: after a bare-LF line, `.<CRLF>` is
  message data (the `<LF>.<CRLF>` smuggling variant). The read loop
  tracks this and hands such a line to the handler dot-stuffed, so
  unstuffing delivers it as a literal `.`. Bare LF remains legal
  message data (byte fidelity). Dot-unstuffing (RFC 5321 §4.5.2) happens in the
  protocol layer before the policy sees a line. `recv_data` receives the
  *unstuffed* line with its original line ending, as raw bytes (8-bit
  safe — invalid UTF-8 in DATA never drops the session).
- `RSET` clears the envelope but keeps the session greeted (the next
  `MAIL` needs no new EHLO, RFC 5321 §4.1.1.5). Unknown verbs are
  refused with `500` and the state is preserved. `RSET`/`QUIT` are only
  verbs outside DATA.

### 4.2 The end-of-data pipeline

```
"." → end_data():
    1. dkim::verify_dkim(raw bytes)          → per-signature verdicts
    2. dmarc::fetch_policy + evaluate        → alignment + policy action
    3. spool (if configured)                 → durable write, queue ID
    4. clear envelope; message_count += 1
    5. return Control (Accept, Reject on DMARC p=reject, or
       Tempfail if the spool write failed or the DNS deadline ran out)
```

Steps 1 and 2 share **one DNS deadline**, `END_OF_DATA_DNS_DEADLINE`
(20 s, the same as SPF's), covering every DKIM key lookup and the DMARC
policy fetch. Running out ends the transaction with `451 4.4.3`, a
temporary failure and never a rejection, since skipping the checks would
fail DMARC on legitimate mail. It is logged at `warn` with the stage
(`dkim` or `dmarc`). Without it, five signatures (`dkim::MAX_SIGNATURES`)
each waiting the 5 s per-query timeout, plus the DMARC fetch, could
outlast the connection cap and drop the session with no reply (D3 in
DEPLOYMENT.md).

Ordering matters: DKIM runs first (DMARC consumes its results), and the
spool write happens on the acceptance path only — the `250` is sent
after a durable write, so accepted mail is never silently dropped (a
failed write is a `451` retryable tempfail). Rejected mail (DMARC
`p=reject`) is never spooled. The envelope is cleared before the verdict
is returned (a rejected transaction is still over — the state machine
enforces MAIL-before-RCPT again next time).

---

## 5. Security model

**Sender authentication stack** (evaluated per message at end-of-data):

| Check | What it proves | Fail result |
|---|---|---|
| SPF (MAIL FROM identity; HELO for the null sender) | the connecting IP is authorized by the *sender's* policy | envelope-level: `550`/`451` at MAIL time |
| DKIM | the message (signed headers + body) is unchanged since a holder of the domain's key signed it (at most 5 signatures, the topmost, are evaluated per message) | logged per signature; feeds DMARC |
| DMARC (From-header domain) | at least one aligned pass exists; else apply `p=` | `550 5.7.1` at end-of-data for `p=reject` |
| From header (RFC 7489 §6.6.1) | exactly one `From` header naming one author domain, read as an RFC 5322 mailbox-list from the raw bytes (comments and quoted strings never supply the domain; folding and the obsolete `From :` spelling are understood) | `550 5.7.1` when missing, duplicated, multi-domain, or unparseable |
| Alignment | SPF/DKIM identity matches the **From** header domain (relaxed/strict per record) | — |

**Transport & access:**

- **STARTTLS** (RFC 3207): rustls; pre-TLS state discarded at upgrade;
  repeated STARTTLS → `503`; never advertised on a TLS connection.
- **AUTH** (RFC 4954, RFC 8310): PLAIN/LOGIN, **TLS-only** (`538` on
  plaintext, advertised only over TLS), credentials via `--auth-users`.
  Authenticated senders (MSA semantics): SPF skipped, DMARC rejection
  exempt (they passed local authentication), relay still closed.
  *Known limitation:* credentials are stored in plaintext (CLI/config
  file) — an interim design, to be replaced by hashed storage or an
  external auth backend before production submission use (PLAN.md,
  Phase 8).
  **Requirement:** `From:` validation (constrain the authenticated user's
  `MAIL FROM`/`From:` to domains they own; PLAN.md Phase 8) is a
  prerequisite for enabling AUTH. The SPF/DMARC exemptions above are
  unconditional, so without it an authenticated session is a spoofing
  channel into hosted mailboxes — and a receive-only server has no sending
  use for AUTH at all. Do not enable `--auth-users` until the validation
  lands.
- **Recipient policy**: owned by the **recipient authority** (Phase 12
  gap 1, now a seam): at RCPT time a `RecipientResolver` decides
  hosted-domain membership, per-domain policy (`reject` / `catch-all` /
  `grace`), and the address→mailbox routing — with user and public key
  attached for later encryption. V1 ships a JSON `FileAuthority`
  (hot-reloaded; the console's publishing contract) and a
  `StaticAuthority` fallback for `--local-domains`. Failure is
  fail-closed (`451`); a malformed authority publish keeps the last good
  policy in force and is logged at `error`; refusals are logged as structured events with
  one uniform SMTP reply (no address enumeration). Plus the
  100-recipient cap and MAIL-before-RCPT sequence enforcement. Envelope
  paths are parsed as `<path> [ESMTP-parameters]` (RFC 5321 §4.1.2);
  `SIZE=` over the advertised limit is refused with `552` at MAIL time,
  and paths containing control characters are refused. Recipient
  local-parts must be RFC 5321 dot-atom text without `/` (they name
  maildir directories); others get `553 5.1.3`.
- **Framing DoS**: line caps, per-message size accounting, accept-loop
  backoff.
- **Message size**: the server-wide `max-data-bytes` (default 10 MiB),
  lowered per hosted domain by `max-message-bytes` in the authority file.
  A transaction carries one limit: a recipient whose domain limit differs
  from those already accepted gets `452 4.5.3` (deliver separately, RFC
  5321 §4.5.3.1.10), so one tenant's limit never refuses another's mail. A
  declared `SIZE=` is checked at MAIL (server limit) and RCPT (domain
  limit); data over the limit gets `552`. Every refusal is logged as
  `message refused: size limit` (stage, size, limit, recipient domains).
- **Privileges**: started as root, mailserv binds the port, reads the TLS
  key and resolver CA, creates missing storage directories owned by
  `--user`, then drops supplementary groups, gid and uid and verifies that
  root can't be regained (`privdrop.rs`), all before opening the
  authority, the spool or the maildirs, and before any connection. Root
  without `--user` is refused; an unprivileged start (systemd with
  `CAP_NET_BIND_SERVICE`, or port 2525 for testing) needs no switch.
- **Storage permissions**: files `0600`, directories `0700`, set explicitly
  (`fsutil.rs`) whatever the umask, plus `umask 077` at startup. Existing
  directories that other users can access get a startup warning.
- **DNS DoS**: pipelined resolver connections, a 20 s SPF evaluation
  deadline, and a per-source-IP limit on concurrent DNS-backed checks
  (`--max-dns-per-ip`, which tempfails with `451` when exhausted); see
  §6.1.

**Known, deliberate exemptions** (documented policy choices, not bugs):
authenticated submissions skip SPF/DMARC rejection; `p=none` DMARC logs
but passes; `pct=` is treated as 100. The authenticated-sender exemption
is safe only with `From:` validation (see AUTH above); without it, it is a
bypass of the receive-side spoofing checks.

---

## 6. DNS layer

`dns` is a hostile-input-hardened wire codec plus two transports (DoT
preferred, TCP; the unauthenticated single-datagram UDP path was retired
— it could not be made production-safe). Queries advertise a 1232-byte
EDNS0 payload (flag day 2020), and responses are validated for EDNS0
conformance on every transport (one OPT, root owner name, version 0).
**Query names are checked before sending** (`proto::check_name`,
`normalize_name`): an empty label, a label over 63 octets, or a name over
253 octets is refused with `InvalidName` (`dns::is_invalid_name`) before
any capacity is taken or a connection is opened, and the wire encoder
refuses them too. Such names are attacker-reachable through SPF records
and DKIM `d=`/`s=` tags; the encoder used to write them anyway, and
public resolvers silently drop the malformed query, so each one cost the
full timeout. SPF treats an invalid name as a name that doesn't exist
(RFC 7208 §4.3); DKIM reports the key lookup as failed straight away.
Names are normalized once (whitespace and one trailing dot removed), so
the cache key and the name sent are the same.

Response parsing is **total**: every index and
slice is bounds-checked; rdata is bounded by the record's own `rdlength`;
compression pointers are range-checked and depth-limited. The property is
tested systematically (every truncation length + ~5,800 bit-flips of a
real response must parse to Ok/Err, never panic).

SPF evaluation goes through the `SpfResolver` **trait** (`txt`, `a`, `mx`,
`ptr`): production uses `DotResolver` around one process-wide `DnsClient`
(pipelined DoT connections, TTL cache; §6.1) built from the resolver address chosen
at startup (`--resolver` / config-file `resolver` key, default 1.1.1.1,
threaded through `SessionConfig` into
`UserSession`); tests use fixture mocks — the same property that makes
DKIM's fixture corpus openssl-anchored makes the SPF suite deterministic. The RFC 7208 §4.6.4
budget (10 lookups / 2 void, shared across include/redirect/a/mx/ptr/
exists) bounds every evaluation regardless of record hostility.

**Resolver trust.** The resolver's DoT certificate is verified against
the `--resolver` IP address, using the public web PKI roots
(`webpki_roots`), so public DoT services such as 1.1.1.1, 9.9.9.9 and
8.8.8.8 work with no extra configuration. To use a local resolver with a
private or self-signed certificate, `--resolver-ca <PEM>` (config key
`resolver-ca`) **adds** its CA certificates to that root set
(`DnsClient::with_extra_roots`). It never replaces the set, so a public
resolver still verifies with the option set. The extra roots apply only
to resolver connections, not to the SMTP listener's TLS. The resolver
still has to present a certificate with its IP address as a subject
alternative name. The file is loaded before the listener binds, and a
missing, empty or invalid file is a startup error.

DMARC reuses `SpfResolver` for its record fetch, which is why the `dmarc`
crate is pure logic with no DNS dependency of its own.

### 6.1 DNS connections: pipelining

Every SPF, DKIM-key and DMARC lookup in the process goes through one
`DnsClient`, so its connection handling sets how much DNS the whole
server can do at once. It also sets how much harm one hostile domain can
do: an attacker can publish records whose authoritative servers never
answer, so each of their lookups stays outstanding for the full 5 s
timeout.

**How it works** (`dns/src/lib.rs`). This replaced an 8-slot pool that
carried one exchange per connection: eight slow lookups, which one client
IP could hold, stalled every other session's DNS (H6 in REPORT.md).

- **Connections:** a few pipelined DoT connections (RFC 7766 §6.2.1.1,
  RFC 7858 §3.4). The default is 2, set with `--dns-connections` /
  `dns-connections` (1–16; an out-of-range value is a startup error).
  Each carries up to 64 queries in flight (`DEFAULT_MAX_IN_FLIGHT`).
  Connections open lazily. A slot is locked while connecting, so queries
  arriving during a handshake wait for that one handshake instead of each
  opening their own.
- **Choosing a connection:** a query takes a unit of client-wide capacity
  (a semaphore of connections × in-flight limit), then the least-loaded
  connection; ties go to the lowest slot, so a quiet server keeps one
  warm connection. When every connection is at its limit, the query waits
  for capacity. That wait is what the `waits` / `wait_*` metrics measure.
- **One reader task and one writer task per connection.** Queries hand
  whole frames to the writer over a channel, so a query cancelled
  mid-send can never leave a partial frame on the wire. The writer
  batches whatever is queued before each flush.
- **Matching replies:** each reply goes to the waiter registered under its
  transaction ID, then must pass `validate_response` (QR flag, question
  echo) and the EDNS0 conformance check.
  - IDs are random and never reused while still in flight on that
    connection.
  - A reply that matches an ID but fails validation means the resolver's
    view of the connection can't be trusted, so the connection is torn
    down.
- **Timeouts** no longer cost the connection. The waiter gives up, its
  entry is removed, and a late reply is counted (`late_replies`) and
  discarded.
- **Connection failure** (EOF, I/O error, malformed frame, invalid reply)
  fails every waiting query at once, and each retries once on a fresh
  connection. The reader sees a resolver-side close as EOF straight away
  and marks the connection closed, so the next query reconnects without
  first failing on a dead stream. That is why no client-side idle timer
  was needed.
- **Cancellation:** each pending entry is removed by a drop guard. The
  guard carries a per-query token, so it can't remove a later query that
  reused the same transaction ID. Capacity, slot load and the
  `in_flight` gauge are drop guards too.
- **Lifecycle:** a closed connection is replaced in its slot on next use.
  The old connection's tasks are aborted when the last query holding it
  finishes; dropping the `DnsClient` closes everything.
- **Unchanged:** connecting (TCP + TLS) and each query are both limited to
  the timeout, and the `DnsClient::query` signature is the same, so
  `spf`, `dkim` and `dmarc` didn't change.

**Metrics:** `DnsClient::stats()` returns a `DnsStatsSnapshot`:
- cumulative counters: queries, cache hits, connects, connect failures,
  replies OK, failed attempts (`exchange_errors`), timeouts,
  `late_replies`, waits for capacity, and total wait time;
- gauges: `waiting` and `in_flight`;
- peaks: `wait_max_us` and `peak_in_flight`, cleared by `reset_peaks()`.

`mailserv` logs these as a `dns stats` line every 60 s while DNS is in
use, together with `connections` and `max_in_flight`. Use it to size
`--dns-connections`. Sustained `waits` mean every connection is at its
in-flight limit.

**SPF evaluation deadline:** `spf::check_host` limits a whole evaluation
to `spf::EVALUATION_DEADLINE` (20 s), across every lookup it makes.
Running out gives `TempError` → `451`, logged at `warn`.
- RFC 7208 §4.6.4 says the limit SHOULD allow at least 20 s, so 20 s is
  the floor. It is still well below the old worst case of 10 × 5 s plus
  the include TXT lookups.
- `check_host_within` takes an explicit limit, which tests use.
- *Interaction to note:* the default 30 s whole-connection cap (M11 in
  REPORT.md) is shorter than a HELO evaluation plus a MAIL FROM
  evaluation that both run to the limit. That cap should become
  per-phase (M11).

**Tests** (mock DoT resolvers in `dns` tests):
- replies out of order, several in one read, on one connection;
- a fast query overtaking a slow one on the same connection;
- a timeout that keeps the connection and discards the late reply;
- a connection closed with three queries pending (each retries once and
  succeeds);
- back-pressure at the in-flight limit;
- a cancelled query freeing its capacity, slot load and table entry;
- 20 slow lookups in flight not delaying an unrelated one (this test
  fails if the in-flight limit is set back to 1, i.e. the old behaviour).

**Per-source-IP DNS limit** (`mailserv/src/limit.rs`, `DnsLimiter`):
pipelining raised the bar for H6 from 8 slow lookups to `connections ×
64` (128 by default). That is more than one IP's sessions could hold
before this limit existed, but enough IPs could still fill it. A
per-session limit wouldn't help, since an attacker just opens more
sessions, so the limit is per source IP.
- A session holds one of its IP's permits around each DNS-backed check:
  the HELO SPF evaluation, the MAIL FROM SPF evaluation, and DKIM +
  DMARC together at end-of-data. The permit is released before the spool
  write, so disk I/O never holds DNS capacity.
- The limit is `--max-dns-per-ip` / `max-dns-per-ip`, default 4 (0 is a
  startup error). Since each SPF evaluation makes its lookups one after
  another, this bounds one IP to about 4 lookups in flight out of the
  client's 128.
- With the share exhausted, a check waits up to 10 s
  (`limit::DNS_LIMIT_WAIT`). That absorbs bursts from busy legitimate
  senders: cached lookups free permits in milliseconds. A live burst of 6
  concurrent sessions from one IP at a limit of 2 saw 4 short waits and
  no refusals.
- If no permit frees up in time, the outcome is always **temporary**:
  - HELO proceeds with SPF `TempError` (which never rejects HELO);
  - MAIL FROM gets `451 4.7.0`;
  - end-of-data gets `451 4.7.0`.

  Skipping DKIM/DMARC instead would fail DMARC and permanently reject
  legitimate mail.
- IPs are keyed per address, like the connection limiter. An IPv6 /64
  isn't aggregated, because large senders send from many addresses
  within one /64.
- An IP's entry exists only while some check holds or waits for its
  permits, and is removed on the last release, including a cancelled
  wait. Memory is bounded by the checks in progress.
- The `dns stats` log line carries `ip_limit_waits`, `ip_limit_refusals`,
  `ip_limit_active_ips` and `max_dns_per_ip`.

#### Still open

1. **Back-off when the resolver is down.** With the resolver unreachable,
   every cache miss tries to connect and waits the full timeout. After N
   consecutive connect failures, new queries should fail straight away
   for a short cool-down. SPF/DMARC already treat that as `TempError` →
   `451`, so this is safe. Log the state change, and add it to the
   metrics.
2. **Share duplicate misses.** Concurrent misses for the same
   `(name, type)` each send their own query. A map from key to a shared
   in-flight result would let later callers wait for the first answer.
   Do this once the `dns stats` log shows enough repeated-miss traffic to
   matter.
3. **One upstream.** There is a single resolver address (IPv4 only) and
   no failover.

`edns-tcp-keepalive` (RFC 7828) negotiation remains optional. EOF
detection already handles resolver-side idle closes.

---

## 7. Parsing (mailparse)

One pest grammar (`mail.pest`) covers RFC 5322 + MIME + DKIM-Signature
tag structure. One parse, two views:

- `ParsedMessage::headers` — `RawHeader`s in message order, duplicates
  preserved, values byte-exact including folding. This is the *security*
  view: DKIM canonicalization hashes these bytes.
- `ParsedMessage::typed` — `MailHeaders`: addresses, dates (jiff), MIME
  parameters, trace entries. This is the *application* view; malformed
  headers degrade to `optional_field` rather than failing.

The body is a raw byte slice after the blank line (`ParsedMessage::body`)
— DKIM's `bh=` hashes exactly those bytes.

---

## 8. Configuration & operations

- `--config <file>` (TOML) with CLI-over-file-over-default precedence,
  resolved by a pure, unit-tested `resolve_config`.
- `--tls-cert`/`--tls-key` enable STARTTLS; `--auth-users` enables AUTH;
  `--local-domains` sets the accepted recipient domains.
- `RUST_LOG` governs verbosity (default INFO); bunyan-JSON on stdout.
  Envelope verdicts, TLS state, and message counts are logged; message
  bodies never are. The per-line `recv_data` span is at TRACE, so a
  message produces a fixed handful of records rather than two per line
  of DATA (D1, DEPLOYMENT.md).
- The accept loop survives transient errors (log + backoff) and logs
  every connection task's outcome.
- Defaults are production defaults: port 25, storage under
  `/var/lib/mailserv` (absolute, so independent of the working directory;
  a relative path is warned about), 10 MiB messages, a 5-minute connection
  cap, 100 connections.
- **Graceful shutdown** (SIGTERM/SIGINT): the listener closes, so new
  connections are refused; every session is signalled through
  `SmtpSession::shutdown_signal`. The read loop only acts on it between
  transactions: idle sessions get `421 4.3.2` at once, and a session
  mid-message or mid-AUTH finishes, gets its reply, then the `421`. The
  process exits when all sessions have ended (each holds a permit of the
  global connection semaphore), after `shutdown-grace-ms` (default 60 s,
  below systemd's 90 s stop timeout), or at a second signal. Blocking
  work already running (spool fsync, delivery) completes before exit.

---

## 9. Testing strategy

229 tests, four layers:

1. **Unit** — pure logic per crate (canonicalization RFC examples, DMARC
   alignment, config resolution, SASL decoding).
2. **Protocol** — the state machine driven by a test session
   (`handler(&state, line)`): every verb, every rejection path, sequence
   enforcement, DATA transparency.
3. **Framing** — `run()` over in-memory duplexes: full sessions, cap
   overflows, STARTTLS pause/resume, silent-client timeouts, EOF.
4. **Integration** — a real rustls client against the real connection
   driver over loopback TCP: STARTTLS dance, AUTH flows, relay policy,
   DMARC logging.

Conformance anchors are external, never circular: DKIM expected hashes
come from openssl (or the RFC's own examples), SPF fixtures come from
recorded real records, DNS hostile-input tests mutate a real response.
One opt-in live test (`#[ignore]`) fetches protonmail's real DKIM key.

---

## 10. Known limitations

Honest, tracked list (details in PLAN):

- **No hosted delivery backend** — mail is delivered to local maildirs
  (`--maildir-dir`, one per recipient address, with `Return-Path:`/
  `Received:` trace headers); the platform backend (API/queue/LMTP to
  the console's mailboxes) replaces the maildir sink via the
  `DeliverySink` trait (Phase 12).
- DKIM signing does not exist (Phase 8); the crate verifies only.
- SPF macros follow RFC 7208 §7 (letters, digit/`r` transformers,
  delimiters, `%%`/`%_`/`%-`, URL-escaping); `%{p}` expands to the
  specified `unknown` (no PTR validation) and `exp=` explanations are
  not fetched.
- DNS: no resolver back-off and no sharing of duplicate misses yet
  (§6.1, "Still open"); the resolver address
  is configurable (`--resolver`/config file, default 1.1.1.1) but IPv4-only;
  a local resolver with a private certificate needs `--resolver-ca`.
- Per-IP limits are per-address, not per-subnet (IPv6 prefix aggregation
  is future hardening); no RCPT-command rate limiting inside a session.
- No metrics endpoint (the DNS client's counters are logged every 60 s,
  §6.1), no ARC.
- mailparse: `Content-Disposition` is a stub; no RFC 2047 decoding;
  `Received` with comments/IPv6 literals falls back to the raw view.
