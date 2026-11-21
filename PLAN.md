# PLAN.md — Review Findings & Forward Plan

> **Status:** the project has moved from "review findings" to "execution".
> All **19 original critical findings are fixed and regression-tested**
> (Section 1), and the pre-delivery security stack is complete: **STARTTLS,
> AUTH (PLAIN/LOGIN), SPF (with RFC 7208 lookup budget), DKIM verification
> (RSA + Ed25519), DMARC, and closed-relay recipient policy** — every check
> binding, wired into the live pipeline, and validated against real-world
> clients (`openssl s_client -starttls smtp`, spoofed `p=reject` DMARC
> rejection). Workspace state: **143 tests, 0 failures, clippy-clean
> (0 warnings), fmt-clean, stable Rust 1.100.0.**
>
> **The frontier is now delivery**: the server accepts, verifies, and drops
> mail. Queue/spool/delivery is the actual finish line for an MTA
> (Phase 7 below).

---

## 1. Original critical findings — verdict ledger

All 19 findings from the initial review, with the evidence that pins each
fix. Kept as a permanent record; nothing here is open.

| # | Finding | Verdict | Evidence |
|---|---|---|---|
| 1.1 | `cmd[1]` panic on bare HELO/MAIL/RCPT | FIXED | `cmd.get(1)` + `501`; syntax-error tests (smtp) |
| 1.2 | `total_data` never incremented | FIXED | per-message accounting; `552` + Discard; duplex test |
| 1.3 | Unbounded `read_line` — memory DoS | FIXED | 512-octet command / 64 KiB data caps, overflow replies + drain, incl. the silent-client timeout case |
| 1.4 | SPF checked the server's own domain | FIXED | HELO identity (`postmaster@HELO`) + MAIL FROM domain; null-sender fallback; live-verified |
| 1.5 | rcode condition always true | FIXED | `&&` in all lookup helpers |
| 1.6 | `mx` doubly broken | FIXED | lexer fixed; MX exchanges resolved to A records |
| 1.7 | `ip4:`/`ip6:` CIDR parsing broken | FIXED | prefix parsing; CIDR asserted in fixtures |
| 1.8 | `ptr` wrong name, no forward-confirm | FIXED | reversed connecting IP, forward-confirmation, domain match |
| 1.9 | include/redirect recursion unbounded | FIXED | RFC 7208 §4.6.4 budget (10 lookups / 2 void) → PermError; per-query 5s timeout; circular-record tests |
| 1.10 | `exp=` recursion flipped Fail verdicts | FIXED | exp never evaluated for the verdict (RFC 7208 §6.1) |
| 1.11 | DNS responses unvalidated | FIXED | transaction ID + QR + question echo in all transports; UDP off-by-one panic fixed |
| 1.12 | DNS parser panics on hostile input | FIXED | fully bounds-checked parsing; systematic truncation (1452 lengths) + ~5,800 bit-flip tests |
| 1.13 | Multi-string TXT truncated | FIXED | concatenation + roundtrip; live-validated on an 800+ byte key |
| 1.14 | Callback errors → no reply, client hangs | FIXED | every command replies; `SmtpError` deleted; no silent paths |
| 1.15 | Message bodies logged at INFO | FIXED | envelope cleared per transaction; `data` is `#[serde(skip_serializing)]` |
| 1.16 | Session state never reset | FIXED | `clear_envelope()` on end-of-data and RSET |
| 1.17 | DATA: no dot-unstuffing, CRLF-brittle | FIXED | unstuffing + CRLF/LF terminator; raw-byte data path; DKIM-validated end-to-end |
| 1.18 | Reply-code defects | FIXED | CRLF discipline, correct codes, malformed args stay Ready (RCPT/MAIL), RSET anywhere; EHLO capabilities now implemented (see §2) |
| 1.19 | Rejections didn't bind the state machine | FIXED | `Control` verdicts enforced; ignored-550 test proves it |

---

## 2. Feature status ledger

| Feature | Status |
|---|---|
| SMTP core (state machine, framing, DATA transparency) | **DONE** — enforced `Control` verdicts, bounded reads, dot-unstuffing, raw-byte data, 22+ in-process protocol/framing tests |
| STARTTLS (RFC 3207) | **DONE** — `Control::Upgrade` pause/resume, rustls handshake in the driver, protocol reset per §4.2, repeated-STARTTLS `503`, EHLO advertisement, cert/key CLI, 10s handshake timeout; validated against `openssl s_client`. *Open: implicit TLS (465), TLS-required policy, client-side TLS* |
| AUTH (RFC 4954/4616/8310) | **DONE** — PLAIN + LOGIN with challenge continuation (`Control::Challenge`, `SmtpState::Auth(return_to)`, `*` abort); TLS-only accept + advertisement; `--auth-users`; SPF/DMARC exemptions for authenticated senders. *Open: OAUTHBEARER* |
| SPF (RFC 7208) | **DONE** — correct identities, full mechanism set, lookup budget, typed Temp/Perm errors, resolver trait with offline fixtures. *Open: macro expansion completeness, DNS caching* |
| DKIM verify (RFC 6376/8463) | **DONE** — RSA + Ed25519, openssl-anchored fixture corpus, wired into `end_data`. *Open: DKIM signing (Phase 8)* |
| DMARC (RFC 7489) | **DONE** — `dmarc` crate: record parsing, relaxed/strict alignment, org-domain fallback, `p=reject` → `550 5.7.1` at end-of-data; live-verified against facebook.com. *Open: rua/ruf reporting, pct sampling, PSL* |
| Recipient policy | **DONE** — `--local-domains`, closed relay, 100-recipient cap, MAIL-before-RCPT/RCPT-before-DATA sequence enforcement |
| EHLO capabilities | **DONE** — multiline `250-SIZE n / 250-STARTTLS / 250-AUTH PLAIN LOGIN / 250 HELP`, gated by availability and connection state. *Open: 8BITMIME/SMTPUTF8/PIPELINING advertisement (PIPELINING works de-facto), VRFY/EXPN semantics* |
| Recipient validation | **DONE** |

---

## 3. Original parser/hygiene findings — resolved

For the record; all items from the original Sections 3–4 are closed:

- **Parser consolidation**: `tinyparse`, `imfpest`, `mimepest` deleted
  (Phase 0); `mailparse` is the single header parser with a public API
  (`parse_message`/`parse_headers`/`split_message`/`extract_raw_headers`),
  byte-exact raw values, order/duplicate preservation, and the pest
  implicit-whitespace bug class fixed and regression-tested.
- **mail.pest fields ordering, DKIM-Signature folding, `value`/`safe_char`
  bugs, dropped trace/DKIM/resent headers, positional mailbox macro** — all
  fixed during the DKIM work.
- **Dependency hygiene**: per-crate manifests pruned to verified usage;
  `chrono`→`jiff`; `thiserror` consolidated; stable 1.100.0 toolchain;
  workspace clippy-clean.
- **Remaining known parser limitations** (accepted, non-blocking):
  `Received` headers with comments/IPv6 literals fall back to
  `optional_field` in the typed view (raw access unaffected);
  `Content-Disposition` parsing is a stub; no RFC 2047 encoded-word
  decoding (not needed for DKIM; needed for display/UX later).

## 4. Hygiene items — CLOSED

All previously-open hygiene items are done. In addition, **rustdoc is now
enforced**: every library crate carries `#![warn(missing_docs)]` (CI's
`-D warnings` makes it an error), the workspace builds a complete `cargo
doc` with no broken intra-doc links, and DESIGN.md documents the
architecture.

1. ~~**CI**~~ — `.github/workflows/ci.yml`: `cargo fmt --check`, `cargo
   clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
   (offline-deterministic; the live-DNS DKIM test is `#[ignore]`d).
2. ~~**`RUST_LOG`**~~ — `EnvFilter::try_from_default_env()` with an INFO
   default; verified live (`RUST_LOG=error` silences all INFO output).
3. ~~**`sendmail` rename**~~ — now `smtp-client`.
4. ~~**Accept-loop resilience**~~ — accept errors log and back off (100 ms)
   instead of terminating `main`; spawned tasks log their completion
   (handler errors at `error`, duration-limit at `warn`).
5. ~~**Leftover clap doc comment**~~ — replaced with a real description.
6. ~~**Config file**~~ — `--config <file>` (TOML, kebab-case keys mirroring
   the flags, every key optional); precedence CLI > file > built-in
   defaults; missing `domain` anywhere is a hard error; pure
   `resolve_config` unit-tested (parse, precedence, defaults, error),
   live-verified (`--config` + `RUST_LOG=debug` + smtp-client session).
   The binary now also logs its resolved `host`/`port`/`domain` at startup.

---

## 5. Execution plan

### Phases 0–6 (previous plan) — COMPLETE

- Phase 0 (hygiene/consolidation/toolchain): done.
- Phase 1 (protocol correctness): done, including framing + duplex tests.
- Phase 2 (SPF): done, including lookup budget and typed errors.
- Phase 3 (DNS hardening): done (total parsing, response validation,
  multi-string TXT, flag layout). *EDNS0 handling and UDP production
  hardening deliberately deferred to Phase 10.*
- Phase 4 (message handling): recipient validation done; body-logging
  fixed; **delivery still open** → Phase 7.
- Phase 5 (security): STARTTLS/AUTH/DKIM-verify/DMARC/recipient-policy all
  done. *Rate limiting → Phase 10.*
- Phase 6 (modernization): EHLO capabilities + enhanced status codes
  (de-facto) done. *Rest → Phase 9.*

### Phase 7 — Delivery (the headline)

The server verifies mail and drops it. This phase makes it an MTA.

- [ ] **Spool to disk**: on end-of-data acceptance, write the raw message
      plus envelope metadata (session id, peer, HELO, sender, recipients,
      SPF/DKIM/DMARC verdicts) to a durable queue directory; reply `250`
      only after a successful spool; crash-safe enough for a PoC (write +
      rename).
- [ ] **Queue identity**: generate a queue ID; include it in logs and (in
      Phase 8) in the `Received:` header.
- [ ] **Local delivery**: maildir-style delivery for local domains (one
      directory per recipient), with a clear failure→`451` path.
- [ ] **Message fixing on delivery**: prepend `Received:` (from, by, with,
      id, date) and `Return-Path:`.
- [ ] **Queue drain/retry**: minimal retry loop with backoff for spool
      items that failed delivery; dead-letter directory after N attempts.

### Phase 8 — Submission semantics (MSA)

- [ ] **DKIM signing** for authenticated submissions (sign with the
      authenticated domain's key; the `dkim` crate gains a signer).
- [ ] **`From:` validation** for authenticated submissions (user's domain
      or configured aliases; refuse spoofed From headers at MAIL time).
- [ ] OAUTHBEARER (optional).
- [ ] Implicit TLS on 465 (shares the acceptor; separate listener).

### Phase 9 — Protocol modernization

- [ ] Advertise `8BITMIME`, `SMTPUTF8`, `PIPELINING` (PIPELINING works
      de-facto in the line loop; verify with a pipelining test).
- [ ] VRFY → `252` (or `502`), EXPN → `502`; HELP text.
- [ ] `MAIL FROM` parameter parsing (at minimum accept-and-check
      `SIZE=` against the limit; reject oversized before DATA).
- [ ] `NOTIFY`/`RET`/`ORCPT` passthrough tolerance check (accept unknown
      ESMTP parameters gracefully).

### Phase 10 — Operations & hardening

- [x] CI workflow (fmt/clippy/test; tests are offline-deterministic).
- [x] `RUST_LOG` support.
- [x] Accept-loop resilience + task result logging. (Graceful shutdown
      (SIGTERM → stop accepting, drain in-flight) **still open**.)
- [x] Config file (`--config`, TOML, CLI-over-file precedence).
- [ ] DNS result caching + connection reuse in `DotResolver` (currently a
      fresh TLS connection and rustls config **per query** — a per-message
      DoS amplifier).
- [ ] Configurable resolver (not hardcoded 1.1.1.1); IPv6 resolver
      destinations; IPv6 listener validation.
- [ ] Rate limiting / connection caps per source IP.
- [ ] UDP production hardening (retries/timeout) or retire `query_udp`.
- [ ] EDNS0 handling in `dns`.
- [x] `sendmail` → `smtp-client` rename.

### Phase 11 — Later / optional

- [ ] DMARC aggregate reporting (`rua`/`ruf`), `pct` sampling, PSL for
      org-domain discovery.
- [ ] ARC (needed before any forwarding role).
- [ ] CHUNKING/BDAT, Milter interface, OAUTHBEARER.
- [ ] mailparse: RFC 2047 decoding, Content-Disposition (for user-facing
      tooling).

---

## 6. Quick-reference: current priority list

1. **Phase 7 — Delivery** (spool, maildir, `Received:`/`Return-Path`,
   queue ID). The security stack is complete; delivery is the finish line.
2. **Phase 8 — Submission semantics** (DKIM signing, `From:` policy) —
   completes the MSA role started by STARTTLS+AUTH.
3. **Phase 10 — Ops** (DNS caching — the biggest remaining performance/DoS
   item; graceful shutdown; resolver config). CI, `RUST_LOG`, the config
   file, and the accept loop are done.
4. **Phase 9 — Extensions**, then **Phase 11** as needed.

— End of plan.

To resume this session: pi --session 01a1f700-53b6-714d-a210-19c9f103b16f

