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
structurally logs every decision. It does **not** yet deliver mail — the
security pipeline is ahead of the MTA pipeline (see PLAN §Phase 7).

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
4. **Deterministic tests.** The suite (145 tests) runs offline; live
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
- DATA: the terminator is content-`.` with CRLF **or** bare LF;
  dot-unstuffing (RFC 5321 §4.5.2) happens in the protocol layer before
  the policy sees a line. `recv_data` receives the *unstuffed* line with
  its original line ending, as raw bytes (8-bit safe — invalid UTF-8 in
  DATA never drops the session).
- `RSET`/`QUIT` are honored from any state, including mid-DATA.

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
| DKIM | the message (signed headers + body) is unchanged since a holder of the domain's key signed it | logged per signature; feeds DMARC |
| DMARC (From-header domain) | at least one aligned pass exists; else apply `p=` | `550 5.7.1` at end-of-data for `p=reject` |
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
  fail-closed (`451`); refusals are logged as structured events with
  one uniform SMTP reply (no address enumeration). Plus the
  100-recipient cap and MAIL-before-RCPT sequence enforcement.
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
`ptr`): production uses `DotResolver` (DoT, per-query timeout) against the
resolver address chosen at startup (`--resolver` / config-file `resolver`
key, default 1.1.1.1, threaded through `SessionConfig` into
`UserSession`); tests use fixture mocks — the same property that makes
DKIM's fixture corpus openssl-anchored makes the SPF suite deterministic. The RFC 7208 §4.6.4
budget (10 lookups / 2 void, shared across include/redirect/a/mx/ptr/
exists) bounds every evaluation regardless of record hostility.

DMARC reuses `SpfResolver` for its record fetch, which is why the `dmarc`
crate is pure logic with no DNS dependency of its own.

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

174 tests, four layers:

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
- SPF macro expansion is incomplete (transformers, `%{p}`); `exp=`
  explanations are not fetched.
- DNS: no caching/connection reuse (a fresh DoT connection per query);
  the resolver address
  is configurable (`--resolver`/config file, default 1.1.1.1) but IPv4-only.
- Per-IP limits are per-address, not per-subnet (IPv6 prefix aggregation
  is future hardening); no RCPT-command rate limiting inside a session.
- No metrics, no graceful shutdown, no ARC.
- mailparse: `Content-Disposition` is a stub; no RFC 2047 decoding;
  `Received` with comments/IPv6 literals falls back to the raw view.
