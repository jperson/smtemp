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
4. **Deterministic tests.** The suite (193 tests) runs offline; live
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
  that swallows until the terminator.
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
       Tempfail if the spool write failed)
```

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

**Known, deliberate exemptions** (documented policy choices, not bugs):
authenticated submissions skip SPF/DMARC rejection; `p=none` DMARC logs
but passes; `pct=` is treated as 100.

---

## 6. DNS layer

`dns` is a hostile-input-hardened wire codec plus two transports (DoT
preferred, TCP; the unauthenticated single-datagram UDP path was retired
— it could not be made production-safe). Queries advertise a 1232-byte
EDNS0 payload (flag day 2020), and responses are validated for EDNS0
conformance on every transport (one OPT, root owner name, version 0).
Response parsing is **total**: every index and
slice is bounds-checked; rdata is bounded by the record's own `rdlength`;
compression pointers are range-checked and depth-limited. The property is
tested systematically (every truncation length + ~5,800 bit-flips of a
real response must parse to Ok/Err, never panic).

SPF evaluation goes through the `SpfResolver` **trait** (`txt`, `a`, `mx`,
`ptr`): production uses `DotResolver` around one process-wide `DnsClient`
(a small pool of DoT connections, TTL cache) built from the resolver address chosen
at startup (`--resolver` / config-file `resolver` key, default 1.1.1.1,
threaded through `SessionConfig` into
`UserSession`); tests use fixture mocks — the same property that makes
DKIM's fixture corpus openssl-anchored makes the SPF suite deterministic. The RFC 7208 §4.6.4
budget (10 lookups / 2 void, shared across include/redirect/a/mx/ptr/
exists) bounds every evaluation regardless of record hostility.

DMARC reuses `SpfResolver` for its record fetch, which is why the `dmarc`
crate is pure logic with no DNS dependency of its own.

### 6.1 DNS connections: the current pool and the pipelining plan

Every SPF, DKIM-key and DMARC lookup in the process goes through one
`DnsClient`, so its connection handling sets how much DNS the whole
server can do at once. It also sets how much harm one hostile domain can
do: an attacker can publish records whose authoritative servers never
answer, and each lookup then holds a connection for the full 5 s timeout.

**What exists today** (`dns/src/lib.rs`, added for H6 in REPORT.md):

- `POOL_SIZE` (8) slots, each an `AsyncMutex<Option<DotStream>>`.
  Connections open lazily, the first time a slot is used.
- A query takes the first idle slot (`try_lock`). If all are busy, it
  waits on one slot chosen round-robin.
- Each connection carries **one exchange at a time**, which is what
  keeps replies from being matched to the wrong query. A failed or
  timed-out exchange throws the connection away. A failure on a reused
  connection is retried once on a fresh one, because idle connections
  are often closed by the resolver.
- Connecting (TCP + TLS) and each exchange are both limited to the
  timeout.
- **Safe to cancel:** the stream is taken out of its slot for the length
  of the exchange. If a session's future is dropped mid-query (e.g. the
  connection-duration cap fires), the stream is dropped with it and the
  slot is left empty, never half-used.
- The pool sits behind the unchanged `DnsClient::query`, so `spf`,
  `dkim` and `dmarc` didn't change.

**Where it falls short:**

1. **Waiting is tied to one slot.** When all 8 are busy, a query waits
   on its round-robin slot even if another slot frees sooner. If its
   slot is held by a slow lookup, it waits up to the full timeout.
2. **No fairness between sessions.** Eight concurrent slow lookups (one
   attacker with a few connections, each SPF evaluation allowed up to 10
   lookups) still fill the whole pool, so legitimate sessions queue
   behind them. The pool narrows this from one stalled connection to
   eight; it doesn't remove it.
3. **Fixed size.** `POOL_SIZE` is a constant. It isn't tied to
   `--max-connections` and can't be configured.
4. **No back-off when the resolver is down.** With 1.1.1.1 unreachable,
   every cache miss tries its own connect and waits the full timeout.
   Nothing marks the resolver as down, so sessions pile up on connect
   attempts.
5. **No sharing of duplicate misses.** Concurrent misses for the same
   `(name, type)` (e.g. a burst of mail from one sender domain) each send
   their own query, and up to 8 can run at once.
6. **Idle connections are only noticed on use.** A connection closed by
   the resolver is discovered on the next query, which costs a wasted
   write and the retry. A burst after a quiet spell can also open up to 8
   TLS handshakes at once.
7. **One upstream.** There's a single resolver address (IPv4 only) and
   no failover.

#### The plan: pipelining

**Decision:** the DNS client moves to pipelining (several queries in
flight on one connection), because DNS throughput is on the critical
path at MX volume. Finishing the slot pool first is **not** a
prerequisite. The work splits into two groups:

- **Needed either way.** These fix problems pipelining doesn't touch
  (shortfalls 2, 4, 5, 6), so they are part of the plan.
- **Only without pipelining.** These are slot-pool improvements that
  pipelining makes unnecessary (shortfalls 1, 3). They're recorded at the
  end in case the plan changes, but aren't planned.

#### Needed either way

Each item is small and independent. All but two live in
`dns/src/lib.rs`: the deadline is in `spf`, and fairness belongs in
`mailserv`.

- **Metrics/logs — DONE.** `DnsClient::stats()` returns a
  `DnsStatsSnapshot`:
  - cumulative counters: queries, cache hits, connects, connect failures,
    exchanges OK, exchange errors (discarded connections), timeouts,
    waits for a connection, and total wait time;
  - gauges: `waiting` and `in_flight`, kept by drop guards, so a
    cancelled query can't leave them raised;
  - peaks: `wait_max_us` and `peak_in_flight`, cleared by
    `reset_peaks()`.

  `mailserv` logs a `dns stats` line every 60 s while DNS is in use,
  with the interval's peaks and the mean wait. This is the baseline to
  measure pipelining against, and the signal for sizing it. Back-off
  state gets added with back-off.
- **Per-evaluation deadline — DONE.** `spf::check_host` limits a whole
  evaluation to `spf::EVALUATION_DEADLINE` (20 s), across every lookup
  it makes, and running out gives `TempError` → `451`.
  - RFC 7208 §4.6.4 says the limit SHOULD allow at least 20 s, so 20 s
    is the floor, not the 10 s an earlier draft suggested. It is still
    well below the old worst case of 10 × 5 s plus the include TXT
    lookups.
  - `check_host_within` takes an explicit limit, which tests use.
    `mailserv` logs a hit at `warn` (`spf evaluation exceeded its time
    limit`).
  - *Interaction to note:* the default 30 s whole-connection cap (M11 in
    REPORT.md) is shorter than a HELO evaluation plus a MAIL FROM
    evaluation that both run to the limit. A connection held by a
    hostile record tree can still hit the 30 s cap first. That cap
    should become per-phase (M11).
- **Per-session fairness (2) — open:** cap how many lookups one SMTP
  session can have in flight (e.g. 2). The simplest form is a
  per-`UserSession` semaphore held around each `check_host` /
  `verify_dkim` / `fetch_policy` call, which needs no `DnsClient` change.
  Pipelining raises the bar from "fill 8 connections" to "fill the
  in-flight limit", but doesn't remove the need for it.
- **Back-off when the resolver is down (4):** after N consecutive
  connect failures, fail new queries straight away for a short cool-down
  instead of each one connecting. SPF/DMARC already treat that as
  `TempError` → `451`, so this is safe. Log the state change. Pipelining
  can't help when the connection can't be made at all.
- **Share duplicate misses (5):** a map from `(name, type)` to a shared
  in-flight result (`futures::future::Shared` or a `tokio::sync::watch`).
  Later callers wait for the first query's answer instead of sending
  their own, and the cache still fills from the one response. This is a
  cache concern, independent of how queries travel.
- **Idle handling (6):** close a connection idle for longer than a
  configured timeout (e.g. 10 s, below typical resolver idle timeouts)
  rather than finding out on the next write. Optionally send the RFC 7828
  `edns-tcp-keepalive` option to learn the resolver's idle timeout. With
  pipelining, the reader task also sees a resolver-side close as EOF
  straight away (see below).

#### Pipelining

RFC 7766 §6.2.1.1 and RFC 7858 §3.4 expect DoT clients to send several
queries on one connection and match the replies, which may come back
out of order. This is a change of structure inside `dns`, not a
contained edit. It's roughly 250–350 lines, mostly new, and the
`DnsClient::query` signature stays the same, so `spf`, `dkim` and `dmarc`
don't change.

- **One reader task and one writer task per connection**, plus a
  pending map from transaction ID to a `oneshot` sender. Replies are
  matched by ID **and** the question echo (`validate_response` already
  checks both). That is what makes pairing safe without the
  one-exchange-per-connection rule.
- **Transaction IDs** come from a per-connection allocator that never
  reuses an ID still in flight (16-bit space, random start).
- **A timeout no longer poisons the connection:** the waiter gives up,
  its map entry is removed, and a late reply is discarded by ID. A real
  connection failure (EOF, TLS error, malformed frame) fails every
  pending waiter at once, and they retry once on a new connection, as
  today.
- **A limit on queries in flight per connection** (back-pressure; e.g.
  64, below common resolver limits). When a connection is full, new
  queries go to the next connection. The outer structure is a small
  `Vec` of pipelined connections (default 2, configurable as
  `--dns-connections` / `dns-connections`) with simple
  least-loaded-first selection. It replaces the 8 slot mutexes and
  doesn't need the slot-pool rework below.
- **Cancellation:** dropping a waiting future must remove its map entry
  (a drop guard), so cancelled sessions can't leak entries. Today's
  guarantee (a cancelled query never leaves a connection half-used)
  carries over, because the connection itself never belongs to one
  query.
- **Lifecycle:** tasks are spawned per connection, so `DnsClient` needs
  shutdown on drop and must survive the resolver closing the connection
  under it (reconnect lazily on the next query).

#### Order of work

1. Metrics/logs and the per-evaluation deadline (**done**), then
   per-session fairness and back-off. These are small and land
   independently. Collect a baseline from the `dns stats` log under real
   traffic before step 2.
2. Pipelining (it replaces the slot pool), with idle handling built into
   the reader task.
3. Sharing duplicate misses, once metrics show how much repeated-miss
   traffic there is.

#### Tests

The existing mock DoT servers in `dns`, `spf` and `mailserv` tests are
the base. Extend them to:

- answer out of order, including replies for several queries in one
  read;
- delay chosen names (already used by
  `slow_lookup_does_not_block_other_lookups`, which must keep passing
  with pipelining);
- send a late reply after the client timed out (it must be discarded,
  and the connection must stay usable);
- close the connection with several queries pending (every waiter fails
  and retries once);
- refuse connections (back-off);
- count queries (duplicate-miss sharing).

Add one test that runs more slow lookups than the in-flight limit and
shows that a fast lookup from a *different* session still finishes
promptly (fairness), and one that checks a dropped query future frees
its in-flight slot.

#### Only without pipelining (recorded, not planned)

If the plan ever changes back to a pool without pipelining, these two
items would also be needed. Pipelining makes both unnecessary.

- **Wait on any free connection (1):** replace the per-slot mutexes with
  a `tokio::sync::Semaphore` (permits = pool size) plus a
  `Mutex<Vec<(DotStream, Instant)>>` stack of idle connections, so a
  waiter gets whichever connection frees first. One exchange per
  connection, drop on failure or timeout, retry once.
- **Configurable pool size (3):** `--dns-connections` sized to load
  (fewer than about `max-connections / 25` queues lookups), capped by
  resolver limits on connections per client.

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
  bodies never are.
- The accept loop survives transient errors (log + backoff) and logs
  every connection task's outcome.

---

## 9. Testing strategy

193 tests, four layers:

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
- DNS: a fixed pool of 8 DoT connections per process (§6.1 covers its
  limits and the plan to move to pipelining), one exchange per
  connection at a time (no pipelining), so a slow lookup occupies one
  slot rather than stalling every session; the resolver address
  is configurable (`--resolver`/config file, default 1.1.1.1) but IPv4-only.
- Per-IP limits are per-address, not per-subnet (IPv6 prefix aggregation
  is future hardening); no RCPT-command rate limiting inside a session.
- No metrics endpoint (the DNS client's counters are logged every 60 s,
  §6.1), no graceful shutdown, no ARC.
- mailparse: `Content-Disposition` is a stub; no RFC 2047 decoding;
  `Received` with comments/IPv6 literals falls back to the raw view.
