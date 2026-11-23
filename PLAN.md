# PLAN.md — Review Findings & Forward Plan

> **Status:** the project has moved from "review findings" to "execution".
> All **19 original critical findings are fixed and regression-tested**
> (Section 1), and the pre-delivery security stack is complete: **STARTTLS,
> AUTH (PLAIN/LOGIN), SPF (with RFC 7208 lookup budget), DKIM verification
> (RSA + Ed25519), DMARC, and closed-relay recipient policy** — every check
> binding, wired into the live pipeline, and validated against real-world
> clients (`openssl s_client -starttls smtp`, spoofed `p=reject` DMARC
> rejection). The DNS resolver is configurable (`--resolver` / config
> file, default 1.1.1.1); accepted messages are **durably spooled and
> delivered to local maildirs**. The external security review
> (REPORT.md) is triaged in §6: all critical and high findings (and the
> round-2 findings N1–N7) are fixed and regression-tested; the medium
> and low findings are tracked there.
> Workspace state: **258 tests, 0 failures,
> clippy-clean (0 warnings), fmt-clean, stable Rust 1.100.0.**
>
> **V1 scope: receive-only.** The product is a hosted receive-only
> email service: users point their domain's MX records at us and
> receive mail at addresses created in the management console.
> Addresses are permanent unless the admin gives them an optional
> expiry (disposable addresses are the flagship use case, not the
> only one). Everything send-side (submission/MSA,
> DKIM signing, relay) is documented but **post-V1, low priority** —
> see Phase 8 and Phase 12. The architecture keeps the sending hooks
> (AUTH, policy profiles, `DeliverySink`) so sending can be added
> later without rework.
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
| AUTH (RFC 4954/4616/8310) | **DONE** — PLAIN + LOGIN with challenge continuation (`Control::Challenge`, `SmtpState::Auth(return_to)`, `*` abort); TLS-only accept + advertisement; `--auth-users`; SPF/DMARC exemptions for authenticated senders. ⚠️ **Unsafe to enable until `From:` validation lands (Phase 8): the exemptions are unconditional, so AUTH is a receive-side spoofing channel.** *Open: OAUTHBEARER* |
| SPF (RFC 7208) | **DONE** — correct identities, full mechanism set, lookup budget, typed Temp/Perm errors, resolver trait with offline fixtures. *Open: macro expansion completeness, DNS caching* |
| DKIM verify (RFC 6376/8463) | **DONE** — RSA + Ed25519, openssl-anchored fixture corpus, wired into `end_data`. *Open: DKIM signing (Phase 8)* |
| DMARC (RFC 7489) | **DONE** — `dmarc` crate: record parsing, relaxed/strict alignment, org-domain fallback, `p=reject` → `550 5.7.1` at end-of-data; live-verified against facebook.com. *Open: rua/ruf reporting, pct sampling, PSL for relaxed alignment; policy discovery is a bounded ancestor walk (F2)* |
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

- [x] **Spool to disk**: on end-of-data acceptance, the raw message plus
      envelope metadata (session id, peer, HELO, sender, recipients,
      SPF/DKIM/DMARC verdicts, TLS state, auth identity) is written to a
      durable queue directory (`--spool-dir` / `spool-dir`, default
      `spool`); the reply `250` is only sent after a successful write — a
      failed write replies `451 4.3.0` so nothing is silently dropped.
      Maildir-style `tmp/`+`new/` layout, fsync before rename, metadata
      renamed last (its presence in `new/` is the commit point). Payload
      is byte-exact raw DATA, ready for Phase 12's user-held encryption
      at this boundary.
- [x] **Queue identity**: maildir-style queue ID (`<hex-seconds>.<uuid>`,
      sortable, unique); logged on spool and stored in the metadata
      (Phase 8 will put it in the `Received:` header).
- [x] **Local delivery**: accepted messages are delivered through a
      `DeliverySink` trait — the first implementation is a maildir sink
      (`--maildir-dir`, default `maildir`), one maildir per recipient
      address (`{root}/{domain}/{local}/new`). The session attempts
      delivery immediately after spooling (fast path); failure leaves the
      message queued with a logged warning — never a bounce, never lost.
      Delivery is **idempotent per (recipient, queue_id)**, so the fast
      path and the drain can race safely. When every recipient copy is
      delivered, the message is dequeued immediately.
- [x] **Message fixing on delivery**: each per-recipient copy gets
      `Return-Path:` (envelope sender, `<>` for null sender) and a
      `Received:` header (from HELO/peer, by server domain, with
      ESMTP/ESMTPS, queue ID, `for <this recipient>` only — other
      envelope recipients are never disclosed, RFC 5321 §4.4) prepended;
      raw bytes follow verbatim.
- [x] **Queue drain/retry**: a drain pass runs at startup and every
      60 s (blocking pool): delivers queued messages, removes fully
      delivered ones, counts failed attempts in an `{id}.attempts`
      sidecar, and dead-letters messages to `spool/dead-letter/` after 5
      failed passes (all files preserved for operator inspection). A
      future `SpoolWriter` S3 backend plugs into the same drain.

### Phase 8 — Submission semantics (MSA) — **post-V1, low priority**

Everything in this phase serves *sending* mail. V1 is a receive-only
hosted-address service (Phase 12): users never send from these
addresses, so none of this blocks V1. It is documented and kept on the
plan because the receive-only design deliberately preserves its hooks
(AUTH exists and is TLS-gated; the policy layer already distinguishes
authenticated senders; DKIM's canonicalization core is shared with the
future signer). Do not invest here until after V1 ships.

> **Update (2026-11-22):** `From:` validation is done (below). AUTH is
> still not internet-ready: plaintext credentials, no failed-attempt
> limit (M16), and no submission-only listener remain.
>
> **Exception — `From:` validation is a security prerequisite, not a
> sending feature.** AUTH is already shipped and usable via
> `--auth-users`, and an authenticated session unconditionally skips SPF
> and is exempt from DMARC rejection (`mailserv/src/main.rs`). The control
> that makes that trust decision safe — constraining the authenticated
> user's `MAIL FROM`/`From:` to domains they own — is the `From:`
> validation item below. Until it lands, **AUTH must not be enabled on any
> deployment** (never advertise it on port 25). If AUTH is to remain
> available in the V1 binary, this item is V1 scope, not post-V1.

- [ ] **DKIM signing** for authenticated submissions (sign with the
      authenticated domain's key; the `dkim` crate gains a signer).
- [x] **`From:` validation** for authenticated submissions (2026-11-22):
      `--auth-senders` maps each login to exact addresses and `@domain`
      grants (`mailserv/src/auth.rs`). `MAIL FROM` must be granted (`553
      5.7.1`; the null sender is refused) and so must every `From:` author
      (`550 5.7.1`), before the SPF skip or DMARC exemption applies. Fails
      closed: no grants means no sending; a grant for an unknown login is a
      startup error. *Follow-ups:* grants from the authority/console instead
      of config (Phase 12), and a submission-only listener (587/465) so
      AUTH is never offered on port 25.
- [ ] **Production-grade credential storage.** `--auth-users` currently
      takes plaintext `user:password` pairs on the CLI or in the config
      file — the credentials land in shell history, `ps` output, and
      world-readable config. This is a deliberate interim design (the
      AUTH mechanism and policy exemptions are the hard parts and are
      done; storage is intentionally minimal until the console
      integration lands) — but it must be replaced before any
      production submission role: a password file holding salted hashes
      (e.g. argon2) or an external auth backend, plus credential reload
      without restart. Until replaced, do not expose `auth-users` on
      internet-facing deployments.

      **Decision (interim file, later backend) — see DESIGN.md §5.** A
      file is an accepted V1 choice, provided it is treated as a secrets
      file: split credentials from sender grants (different owners and
      rotation cadences), store argon2id hashes rather than plaintext,
      `0600` and owned by the service user (refuse to start if
      group/world-readable), and never pass credentials in argv. Add
      SIGHUP reload so a revoked user or grant stops working without a
      restart. Put the file impl behind two seams — `CredentialVerifier`
      and `SenderAuthorizer` — so the backend is a drop-in rather than a
      rewrite. Do **not** build the backend until submission is a real
      product; a receive-only V1 with AUTH disabled has no use for it.
      Constraints when it lands: fail closed for AUTH only (never block
      inbound delivery), cache with a TTL, revoke without restart, and
      bound calls with timeouts and a circuit breaker.
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
- [x] Accept-loop resilience + task result logging.
- [x] Graceful shutdown (D4 in DEPLOYMENT.md): SIGTERM/SIGINT closes the
      listener, idle sessions get `421`, sessions mid-message finish first;
      exit when all sessions end, after `shutdown-grace-ms` (60 s), or on
      a second signal.
- [x] Privilege dropping (D4): root binds port 25, then switches to
      `--user`/`--group` before opening storage or serving; root without
      `--user` is refused. Storage is created `0600`/`0700`, `umask 077`.
- [x] Production defaults (D4): port 25, `/var/lib/mailserv` storage,
      10 MiB messages, 5-minute connection cap, 100 connections.
- [x] Per-domain message size limits (`max-message-bytes` in the
      authority file); mixed-limit recipients split with `452`; every
      size refusal logged. An aborted transfer now clears its transaction.
- [x] Config file (`--config`, TOML, CLI-over-file precedence).
- [x] DNS result caching + connection reuse: `dns::DnsClient` — one
      shared client per process holds pipelined DNS-over-TLS connections
      (DESIGN §6.1: default 2 connections × 64 queries in flight,
      replies matched by transaction ID + question echo, a timed-out
      query abandons its ID without harming the connection, and
      connection-level failures fail every waiter, which retries once on a
      fresh connection) and a TTL-based result cache
      (positive: minimum answer TTL; NXDOMAIN/NODATA: SOA-derived
      negative TTL per RFC 2308; clamped to 1 h; bounded to 4096
      entries). SPF, DKIM, and DMARC all share it — one session went
      from ~4 full TLS handshakes to one connection. Verified against a
      real 1.1.1.1 endpoint and a mock DoT server (reuse, cache-hit,
      transparent reconnect, pipelining). *Still open: resolver back-off,
      duplicate-miss sharing (DESIGN §6.1; the per-source-IP DNS limit is
      done, `--max-dns-per-ip`);
      EDNS0 option negotiation is minimal.*
- [x] Configurable resolver: `--resolver <IP>` / `resolver` config-file
      key (CLI > file > default); default 1.1.1.1; resolved once in
      `resolve_config`, threaded through `SessionConfig` into
      `UserSession`, and logged at startup. IPv6 resolver destinations
      and IPv6 listener validation **still open** (`--resolver` and
      `DotResolver` take `Ipv4Addr`).
- [x] Local resolver support: `--resolver-ca <PEM>` / `resolver-ca` adds CA
      certificates to the public webpki roots for the resolver's DoT
      certificate (D2 in DEPLOYMENT.md), so a local validating resolver
      with a private or self-signed certificate can be used. Additive, so
      public resolvers keep working; scoped to resolver connections; bad
      file = startup error. The certificate must name the resolver IP.
- [x] Rate limiting / connection caps per source IP: per-IP concurrent
      cap and fixed-window connection-rate budget
      (`--max-conn-per-ip` 10, `--max-conn-rate-per-ip` 60/min) plus a
      server-wide semaphore (`--max-connections` 500), all enforced in
      the accept loop before any session work — refusals answer `421`
      and close (with a graceful drain so the client actually reads the
      421; dropping a socket with unread inbound data would RST and
      discard it). *Still open: RCPT-command rate limiting inside a
      session and per-subnet (IPv6 prefix) aggregation.*
- [x] UDP retired: `query_udp` deleted (single unauthenticated datagram
      with no retry/timeout could never be production-safe); production
      queries go over DoT, `dnsq` offers TCP and DoT.
- [x] EDNS0 handling in `dns`: queries advertise a 1232-byte payload
      (DNS flag day 2020; was 4096 — fragmentation territory), responses
      are validated for conformance on every transport (at most one OPT,
      root owner name, version 0; violations fail the query), and the
      parsed EDNS0 fields (payload size, extended RCODE, version, DO
      bit) are exposed for future use.
- [x] `sendmail` → `smtp-client` rename.

### Phase 11 — Later / optional

- [ ] **Multiple MX domains.** The server currently assumes a single
      identity: `--domain` is one required scalar value used for the
      banner, EHLO replies, the implicit local recipient domain, and (in
      Phase 7) `Received:`/`Return-Path:` generation. V1 keeps this
      simple; long-term, the server should accept mail for several
      domains as distinct MX identities. That means: a list of hosted
      domains in the config (each with its own recipient policy at
      minimum), banner/EHLO derived from the per-connection
      `RCPT TO`/HELO context rather than one global domain, per-domain
      delivery paths (maildir roots, aliases), and per-domain DMARC
      alignment assumptions reviewed. The recipient-policy side is
      already close (the local-domain set), so the real work is identity
      selection in the protocol layer and per-domain delivery/queueing in
      Phase 7's output.
- [ ] DMARC aggregate reporting (`rua`/`ruf`), `pct` sampling, PSL for
      org-domain discovery.
- [ ] ARC (needed before any forwarding role).
- [ ] CHUNKING/BDAT, Milter interface, OAUTHBEARER.
- [ ] mailparse: RFC 2047 decoding, Content-Disposition (for user-facing
      tooling).

### Phase 12 — Hosted address service (BYO domain, multi-tenant) — planning only

Long-term product direction: a hosted service where users (provisioned
through a **separate management console**, out of scope for this repo)
bring their own domain, point its MX records at us, and create unlimited
addresses that land in their account. **Addresses are permanent by
default; an admin may optionally give an address an expiry** (the
disposable/temp-address use case is a subset — create-and-expire — not
the default lifecycle). This server becomes the
**MX edge** of a platform; the authoritative knowledge of
"which domains are hosted, which users belong to them, and which
addresses belong to which user" lives in the **external system**, not in
static config. The protocol/policy split (§DESIGN 3) was chosen exactly
so an SMTP session implementation can hook into such an external system.

**V1 is receive-only.** These addresses exist to *receive*; users will
not send from them. Concretely for
V1: no outbound relay, no submission/MSA role (Phase 8 deferred), no
DKIM signing, no bounce/NDR generation — undeliverable mail is refused
at RCPT time by the recipient authority (fail-closed), so senders'
servers generate their own bounces. The design keeps the sending path
open (AUTH, policy profiles, submission semantics, `DeliverySink`), but
V1 priority order is: recipient authority → delivery → multi-domain →
scale hardening.

**What the current design already gets right:** the `SmtpSession` trait
seam is the correct foundation — the state machine is policy-agnostic,
verdict-based, and the driver is generic over streams, so an alternative
session implementation can consult an external authority at every
decision point without touching the `smtp` crate. Per-connection policy
state is cheaply clonable (`SessionConfig`), which fits replacing static
lookups with dynamic ones.

**Gaps and issues in the current code, to close before this feature:**

1. **No recipient authority seam.** ~~`rcpt_to` validates only the
   *domain* against a static `Arc<HashSet<String>>`~~ **SEAM IMPLEMENTED**
   (Phase 12 groundwork): the blocking `RecipientResolver` trait is
   consulted at RCPT time (via `spawn_blocking` under a 5 s timeout);
   its `Resolution` covers NotHosted / Accept(Recipient) / Refuse{mode,
   reason}; accepted resolutions are cached per connection
   (**successes only** — every refusal re-consults the authority),
   failures are fail-closed `451`, and the `Recipient` carries the
   owning user + mailbox + **public key and rotation generation** (the
   gap-3 implementation note is realized). The resolved routing target
   travels in the spool metadata (`SpoolRcpt`) and drives delivery, so
   catch-all mail lands in the designated inbox. Two implementations:
   `FileAuthority` (JSON, hot-reloaded on mtime — the console's first
   publishing contract; strict schema, unknown fields rejected) and
   `StaticAuthority` (the pre-authority fallback for `--local-domains`:
   every local-part accepts, routes to itself). Refusals are logged as
   structured events (peer, mail-from, rcpt, mode, reason) with one
   uniform SMTP reply for every reason (no address enumeration).
   *Still open:* the real console-backed authority (HTTP/gRPC) behind
   the same trait; a shared TTL cache beyond the per-connection one;
   refusal-event aggregation in the console.

   **Per-domain recipient policy** (decided): the authority answers per
   domain with one of three modes —

   | Mode | RCPT behavior |
   |---|---|
   | `reject` (default) | `550` unless the address resolves to a mailbox |
   | `catch-all` | accept any local-part → route to a designated inbox |
   | `grace` | accept for recently-valid addresses for N days, then reject |

   Catch-all is gated by storage quotas/retention and the Phase 10
   rate-limiting/probe caps (catch-all makes every dictionary probe a
   valid recipient). The disposable-address UX is `catch-all` per domain;
   `reject` is the safe default. Note `grace` composes with optional
   address expiry: an expired address accepts for N days, then rejects —
   permanent addresses never age out.

   **Never self-bounce (invariant):** undeliverable mail is refused at
   RCPT time so the *sender's* infrastructure generates its own NDRs —
   this service (receive-only) never emits a bounce itself, in V1 or
   later.

   **Refusal observability** (decided): every refusal emits a structured
   event (timestamp, peer IP, MAIL FROM, refused address, mode, reason:
   no-such-mailbox / expired / lookup-failure). The authority is
   consulted on every miss, so the **console platform is the system of
   record** for refusal stats per domain (the server's bunyan logs are
   the ops-side mirror). This lets admins start on `reject` and graduate
   to `catch-all` based on observed traffic. Metadata is always logged;
   message *bodies* of refused mail are not stored by default (refused
   traffic is mostly spam/probes — a storage and privacy liability); an
   optional per-domain, short-retention sample capture may be offered
   for admins evaluating catch-all.

   **Per-domain admin event stream** (decided): observability is a
   product feature, not just server logs — the platform maintains a
   per-domain event feed surfaced to the domain's admin user in their
   dashboard. Events are generated platform-side from the authority's
   RCPT-consultation results (so the SMTP server stays thin: it emits
   structured data, the console decides what is event-worthy). Likely
   event kinds: refused-mail summaries (per address/sender, with
   volume), delivery activity for a domain's inboxes, catch-all bucket
   traffic, abuse signals (dictionary-attack/refusal spikes, probe
   patterns), quota/retention warnings, and alias-expiry notices. The
   server-side contract is therefore: emit rich structured refusal and
   delivery metadata on every decision; keep event aggregation,
   deduplication, and notification policy (e.g. digests vs. realtime)
   entirely in the console.

   *Known caveat — cache-induced undercounting:* if the server's
   recipient cache answers a refusal from a cached miss, the authority
   is never consulted and the event stream loses that refusal. V1
   decision: **cache successes only, never refusals** — every miss
   consults the authority, giving the invariant *every refusal reaches
   the platform exactly once* (the per-bad-RCPT authority round-trip is
   bounded by the Phase 10 rate-limit/probe caps). If refusal volume
   ever makes this too expensive, evolve to server-side event emission
   to a platform ingest queue (option noted, not planned for V1).
2. **Hosted domains are static config.** BYO domains are provisioned
   live via the console; the server needs a domain catalog that updates
   without restart (reload signal, watcher, or per-connection authority
   query). The `Arc<HashSet>` shape is already swap-friendly.
3. **User-held encryption keys for stored mail** (planned feature).
   Users may register a public key in the console; every message written
   to storage for that user is **encrypted at write time** (in the
   spool/delivery path) to that key. The private key never touches the
   server: the future front-end decrypts inbox contents client-side.
   Design points:

   - **Mechanism — multi-recipient container (decided direction):**
     hybrid encryption, PGP/age-style — a random content key encrypts
     the payload once, and the content key is wrapped once per
     recipient user's public key; any recipient whose key was used can
     decrypt. One stored blob per message (no per-recipient copies).
     Chosen over fan-out (N full ciphertext copies) because storage,
     write cost, and queue consistency all favor a single object, and
     per-recipient lifecycle is handled by an access list in metadata
     ("readable by key ids") rather than duplicated objects — physical
     deletion when no active reader remains. Resolved earlier concern:
     under the per-domain policy model, every accepted message has
     resolvable owner keys at write time (`reject` recipients resolve
     to users; `catch-all` resolves to the designated inbox owner;
     expired `grace` addresses are refused, never stored), so key
     discovery rides the already-planned fail-closed RCPT authority
     lookups. Format candidate: age-style X25519 recipients with
     platform-issued keys (simple, native multi-recipient,
     WASM-decryptable); OpenPGP only if external-tool interop is ever
     required. Trait evolution when the console authority lands:
     `PayloadEncryptor::encrypt` gains the recipient key set; session
     supplies keys from the RCPT-time lookups. Support **key rotation**
     by wrapping with the current key and any still-active previous
     keys.
   - **Integration point — now implemented as the `PayloadEncryptor`
     hook on the spool backend (Phase 7 work):** encryption happens
     *after* SMTP processing (SPF/DKIM/DMARC, `Received:` prepending
     are already done) and *before* the bytes hit storage; the backend
     stores only ciphertext and records the provider id in metadata.
     Queue/routing metadata (recipient identity, verdicts, timestamps)
     stays plaintext — the server must still be able to route and
     expire the message it cannot read. Remaining: real providers
     (user-held keys from the console) and the multi-recipient fan-out
     limitation (one provider seal per message; per-recipient copies
     are future work). The multi-recipient container design above
     supersedes the one-seal-per-message limitation described in
     `spool.rs`; the trait widens to take the recipient key set when
     the authority lands.
   - **Honest guarantee — encrypted at rest, not end-to-end.** The
     server necessarily sees the plaintext during SMTP reception and
     policy evaluation; what this removes is the *server-side ability
     to read stored mail after delivery* (and anyone dumping the disk,
     DB, or backups). Say this plainly in user-facing copy.
   - **Consequences that are features, not bugs**: no server-side
     search (front-end decrypts and searches locally); no post-delivery
     content scanning; lost private key = permanently unreadable stored
     mail (offer no recovery, state it up front).
   - **Lifecycle still works**: retention/expiry is enforced on the
     ciphertext — the server can delete encrypted blobs on schedule
     without ever decrypting them.

4. **Delivery model mismatch (shapes Phase 7).** Planned maildir
   delivery assumes local OS-style recipients; platform mailboxes live
   in the external system. Phase 7 must define the `DeliverySink` seam
   (see Phase 7 note) and the spool metadata must carry the resolved
   tenant/user/address identity from RCPT time, not just the raw
   envelope.
5. **Single-domain identity becomes required multi-domain (promote the
   Phase 11 item).** Banner/EHLO/`Received:` must derive from the
   hosted domain in play, not one global `--domain`; the single-cert
   TLS acceptor needs SNI-based cert selection for BYO domains.
6. **Submission credentials.** The static plaintext `--auth-users` map
   (already flagged in Phase 8) is doubly wrong here: credentials must
   come from the authority (hashed), and submission accounts are created
   in the console, not in server config. Split the two concerns when the
   authority owns them: the credential verifier becomes a backend
   (`CredentialVerifier`), while sender grants (`SenderAuthorizer`) are
   authorization policy and normally remain in the app/console. See the
   Phase 8 credential-storage decision for the seam and fail-closed
   constraints.
7. **MX-scale economics.** The per-query DoT connection was fixed by
   the Phase 10 `DnsClient` (pooled connection + TTL cache); the
   remaining MX-scale item is rate limiting / RCPT-probe caps (Phase
   10): catch-all
   Rate limiting / RCPT-probing caps (Phase 10) likewise: catch-all
   domains make every probe a valid recipient, which is precisely what
   dictionary attackers want.
8. **Verdict semantics are MSA-flavored.** Rejecting `p=reject` DMARC at
   end-of-data and the authenticated-sender exemptions make sense for
   the MSA role; a consumer MX whose users *expect* the mail may want
   configurable per-domain policy (accept-and-tag/quarantine vs.
   reject). Policy profiles should be a parameter, not hard-coded
   behavior.

9. **Spool backend abstraction (object-storage queue).** The trait is
   now in place (Phase 7 work): `SpoolWriter` (blocking
   `write`/`name`, run on the blocking pool) with `DiskSpool` as the
   first implementation, and a `PayloadEncryptor` hook — the backend
   seals the payload *before* its first write and records the provider
   id in the metadata (`encryption`), so no plaintext ever reaches
   storage when a provider is configured. Remaining: an S3-compatible
   backend following the **staged sync** pattern — accept to the
   durable local spool exactly as today (fast, no object-storage
   dependency in the `250` contract), then a backend process uploads
   each message (S3 key = queue ID, so retries are idempotent) and
   deletes the local copy on confirmed upload. Consequences to design
   for: the local disk becomes a *cache with an upload backlog* (needs
   space monitoring and a backlog metric in the admin event stream); the
   read path (drain/retry/dead-letter/admin inspection) must fetch from
   the backend on local miss; an upload manifest/marker makes the
   uploaded-but-not-deleted state recoverable. Never stage in `/tmp`
   (often tmpfs: lost on reboot, defeating durability); the configured
   `--spool-dir` is the staging area.

Sequencing note: Phases 7 (delivery + spool identity), 8 (credential
storage), 10 (DNS caching, rate limiting), and 11 (multi-domain
identity) are all prerequisites for this phase; the Phase 7 design
choices in particular should be made with this consumer in mind so the
work is additive rather than a rewrite.

---

## 6. Security report (REPORT.md, 2026-11-21) — findings ledger

An external security review (commit `6b0a655`) reported **4 critical,
8 high, 17 medium, and 12 low** findings, several verified against the
running binary. A round-2 re-review found gaps in the first fixes
(N1–N7); round 3 closed them along with the remaining highs. Fixed:

| # | Sev | Finding | Verdict |
|---|---|---|---|
| C1 | **Critical** | Path traversal in maildir delivery: any RCPT local-part could write files anywhere the service user could write (`/` and `..` in local-parts; `Path::join` with an absolute path discards the root) | **FIXED** — RCPT-time local-part validation (RFC 5321 dot-atom text minus `/`, no leading dot, no `..`, ≤64 octets, else `553 5.1.3`; round 3 widened the set so `o'brien@` works — N4) plus sink-side component validation as defense in depth; traversal/unusual-local-part regression tests |
| C2 | **Critical** | SMTP smuggling: `RSET` (and any verb) inside DATA ran as commands; bare-LF `.` terminated DATA (CVE-2023-51764/51765/51766 class) — a relay passing such a body would inject a spoofed message from its own trusted IP | **FIXED** — `Data`/`Discard` are pure framing modes: every line is data, the ONLY exit is `<CRLF>.<CRLF>`; a bare-LF `.` is an empty data line. Round 3 (N1): `.<CRLF>` only terminates after a CRLF-terminated line — `<LF>.<CRLF>` is data (read loop tracks the previous ending, incl. over-long lines). Framing regression tests over a duplex; DESIGN §4.1 updated |
| C3 | **Critical** | DKIM verdicts accumulated across messages on one connection, so a replayed genuine signature made a later unsigned spoof pass DMARC | **FIXED** — DMARC consumes only the current message's results; regression test (fake verified facebook.com verdict + unsigned spoof of the same domain must still be rejected). Round 3 (N6): hermetic, served by a local mock DoT resolver |
| C4 | **Critical** | DMARC was skipped whenever the header parser failed (duplicate `From:`, any 8-bit header byte, grammar failure) — an attacker could dodge `p=reject` with one bad byte | **FIXED** — From domain extracted from raw bytes with a tolerant byte-level scan (folding handled, `From:`-in-body ignored); no `From:` / multiple `From:` / unparseable From are hard `550 5.7.1` rejects per RFC 7489 §6.6.1. Round 3 (N2, N3): the value is read as an RFC 5322 mailbox-list — folded lines kept, comments and quoted strings never supply the `@`, `From :` counts, several author domains are `Multiple`; extractor unit tests + integration test |
| H1 | High | SPF `a`/`mx`/`ptr`/`exists` queried type 22 (NSAP-PTR) instead of type 1 (A) — those mechanisms never matched, legitimate senders got `550`, void budgets tripped | **FIXED** — type 1; wire-level regression test runs `DotResolver` against a mock DoT server and asserts the qtype byte. *Open: AAAA for IPv6 senders* |
| H4 | High | Message body lines starting with `QUIT`/`RSET` ended the session mid-DATA (undeliverable mail) | **FIXED** — same framing change as C2 |
| H5 | High | Each refused connection ran inline in the accept loop (up to ~2.5 s), so an attacker holding the connection budgets stalled ALL accepts — the limiter as amplifier | **FIXED** — refusals spawn into a bounded permit pool (32); when saturated, sockets close without the courtesy reply |
| H8 | High | Grace-mode domains refused every *permanent* mailbox (`is_some_and` treated `expires: null` as expired) | **FIXED** — `is_none_or`; `grace-days` capped at 366 (bounded arithmetic); permanent + future-expiry regression tests |
| M15 | Medium | Authority hot-reload: one bad publish made every RCPT `451` until fixed, and re-parsed the broken file per RCPT | **FIXED** — last-good snapshot serves through a bad publish; failed change token memoized (no per-RCPT re-parse); change token is (mtime, size); next good publish applies. Round 3 (N5): a failed reload is logged at `error` (stale policy is never silent) |
| H6 | High | One serialized DNS connection shared process-wide; connect had NO timeout — a black-holed resolver held the mutex ~2 min, and an attacker-chosen slow record stalled every session's lookups | **FIXED** — connect bounded by the per-query timeout; `DnsClient` is now **pipelined** (default 2 connections × 64 queries in flight, `--dns-connections`; replies matched by ID + question echo; a timeout keeps the connection). The round-3 8-slot pool was re-opened in the round-4 review (8 slow lookups from one IP filled it) and is replaced. Regression test: 20 slow lookups in flight don't delay an unrelated one (fails with the in-flight limit set to 1). A per-source-IP limit on concurrent DNS-backed checks (`--max-dns-per-ip`, default 4; tempfails with `451`, never a permanent reject) now bounds what any one client can hold. *Open: resolver back-off, duplicate-miss sharing (DESIGN §6.1)* |
| H2 | High | SPF macro expansion replaced every letter after the first `%` | **FIXED** — RFC 7208 §7 expander (letters, digit/`r` transformers, delimiters, `%%`/`%_`/`%-`, URL-escaping, 253-octet truncation; IPv6 nibble `%{i}`, epoch `%{t}`, `%{p}` = `unknown`); `include:` lexes `%`; RFC §7.4 example tests |
| H3 | High | ESMTP parameters (`SIZE=`, `BODY=`) ended up inside the address: SPF bypass, bounces with `SIZE=` refused | **FIXED** — `<path> [params]` split (RFC 5321 §4.1.2); `SIZE=` over the limit → `552` at MAIL; control characters in paths refused |
| H7 | High | Unlimited DKIM signatures per message (CPU + DNS amplification) | **FIXED** — at most `dkim::MAX_SIGNATURES` (5, topmost) evaluated; offline regression test |
| S1 | **Critical** | (SECURITY.md) Stack-overflow abort of the whole process via deeply nested header comments (recursive pest `comment` rule, reached by DKIM's typed parse) | **FIXED** — DKIM runs on `mailparse::parse_raw_message` (iterative byte scan, no grammar); `parse_headers` refuses nesting > `MAX_COMMENT_DEPTH` (64) via a conservative pre-scan; regression tests on a 2 MiB stack; live 300k-level payload no longer crashes a release build |
| S2 | High | (SECURITY.md) DKIM `h=` selection O(h × headers): one message pins a worker for minutes | **FIXED** — per-name header index (linear, RFC 6376 §5.4.2 semantics kept); `h=` capped at `dkim::MAX_SIGNED_HEADERS` (256) |
| N19 | High (deploy) | IPv4-mapped peers on a `[::]` listener never match SPF `ip4:`/`a`/`mx` | **FIXED** — `canonical_peer()` (`to_canonical()`) at accept and in `handle_connection` |
| M8 | Medium | Trace-header injection via HELO (bare CR copied into `Received:`) | **FIXED** — HELO must be a domain or address literal, else `501 5.5.2` before it is recorded; delivery also neutralises non-printables in stored HELO |
| N11 | Medium | DKIM returned nothing when the typed parser rejected a message (non-UTF-8 headers etc.) | **FIXED** — by the S1 change (raw view only) |
| F1 / M6 | **High** | (SECURITY-AUDIT.md) DMARC failed open on a policy-lookup error (SERVFAIL, query timeout): spoofs of `p=reject` domains delivered | **FIXED** — any lookup error is `451 4.4.3`; `MultipleRecords` means DMARC not applied (RFC 7489 §6.6.3, logged at `warn`); hermetic SERVFAIL test |
| F2 / M3 / M4 | **High** | (SECURITY-AUDIT.md) Org-domain fallback = last two labels: `x.victim.co.uk` asked `_dmarc.co.uk`; `sp=` never applied | **FIXED** — bounded tree walk (`dmarc::policy_candidates`: the From domain then each ancestor down to 2 labels, at most 8 queries); `FoundPolicy` records where the record was found so `sp=` governs inherited policies; fail closed on errors. Live: spoof from `payroll.nonexistent.bbc.co.uk` → `550 5.7.1`. *Open: PSL-based relaxed alignment (M5)* |
| F3 / N8 | **High** | (SECURITY-AUDIT.md) Bare CR in the header block hid a second `From:` from the DMARC scanner | **FIXED** — `550 5.6.0` for any CR not followed by LF in the header block, before any DNS work; live-verified |
| F4 / M1 | Medium | (SECURITY-AUDIT.md) SPF parser weakened hard-fail records (`-ALL`, unknown terms, `mx/24`, `V=SPF1`) and ignored `a`/`mx` CIDR | **FIXED** — term-based parser (RFC 7208 §4.6.1) replaces the logos lexer: case-insensitive names, PermError on any unknown or malformed term, dual-CIDR on `a`/`mx`, duplicate `redirect=`/`exp=` PermError, case-insensitive record detection (`v=spf10` excluded); audit probe table is the regression test |
| F5 / M17 | Medium | (SECURITY-AUDIT.md) DKIM accepted < 1024-bit RSA keys, honoured `l=` (appended content verified), and accepted signatures without `From` in `h=` | **FIXED** — `MIN_RSA_BITS` 1024 (`WeakKey`); a signature whose `l=` doesn't equal the canonical body length never verifies (`PartialBody`); `h=` must include `From` (RFC 6376 §6.1.1). *Open: duplicate tags, `k=` vs `a=` check* |

**Open findings** (see REPORT.md for full detail; roughly priority order):

- **M2**: SPF budget over-counts MX-host and PTR-name A lookups
  (spurious PermError → 550 on large legitimate records).
- **M5**: relaxed alignment is suffix-of, not same-organisational-domain
  — sibling subdomains fail DMARC and get rejected (false negatives, not a
  spoofing vector). Needs the Public Suffix List; policy discovery itself
  no longer does (F2).
- **M6** (remainder): `quarantine` is computed then delivered as normal
  mail — out of V1 scope by decision (2026-11-22).
- **M7**: no `Authentication-Results:` header added; forged inbound ones
  are not stripped (RFC 8601).
- **M9**: catch-all deliveries collapse into one copy (idempotency key
  must include the envelope address — the temp-mail use case depends on
  knowing which address received the mail); lossy `sanitize()`
  collisions; MUA `new/`→`cur/` moves defeat `exists()`.
- **M10**: state-machine sequencing (partially fixed this pass — RSET
  keeps greeting, unknown verbs keep state): MAIL/RCPT/DATA before EHLO
  reply `500` instead of `503`; EHLO does not reset an in-flight
  transaction (RFC 5321 §4.1.4); 512-octet cap truncates long AUTH
  PLAIN initial responses (RFC 4954 allows 12,288).
- **M11**: the 30 s whole-connection cap covers DATA/DNS/fsync and can
  fire between spool-commit and the `250` (client retries → duplicate
  delivery). Per-phase timeouts; never cancel between commit and reply.
- **M12**: limiter sweep is O(n) per close under one mutex; a panicking
  session leaks the per-IP active count (use an RAII guard); IPv6 /64
  bypasses per-IP caps entirely.
- **M13**: `DiskSpool::list()` loads every queued payload per drain
  pass (backlog = RAM). Stream entries; load payloads on demand.
- **M14**: storage hygiene — 0644 files (use 0600/0700), no maildir
  directory fsync after rename, fast-path delivery bypasses the
  encryption boundary, 5-minute dead-letter timer with no alerting,
  `tmp/` debris never cleaned.
- **M16**: AUTH hardening (post-V1 but live when `--auth-users` set): no
  failed-attempt limit, `*`-abort leaves LOGIN state (stale-username
  confusion), case-sensitive mechanism names, non-constant-time
  compare, plaintext credentials (Phase 8).
- **M17** (remainder): duplicate DKIM tags allowed; key `k=` not checked
  against signature `a=`. (Key size, `l=`, From-in-`h=` fixed: F5.)
- **L1–L12**: see REPORT.md §Low — DNS label encoding validation,
  cache eviction policy, resolver privacy/DNSSEC, EHLO-per-connection
  SPF cost, `redirect=` to no-record, per-DATA-line log spans, session
  summary logging fields, ignored write errors, cache-key trimming
  mismatch, TLS reload/SNI, config footguns, dnsq per-call configs.
- **Design observations** (from the report, worth acting on): wrap
  per-message verdict state in a `Transaction` struct created at MAIL
  and dropped at end-of-data/RSET (the structural root of C3); make
  every policy input total — unknown means fail or tempfail, never
  accept; **disable AUTH in V1 builds** (a receive-only service with
  MSA exemptions is an unrestricted spoofing channel for credential
  holders — at minimum never advertise AUTH on port 25); consider
  requiring `--authority` outside development (the StaticAuthority
  fallback accepts every local-part and is C1's reachable path); settle
  idempotency-key and commit/reply ordering before the S3/console
  backends build on them.

**Test-coverage gaps** the report mapped to findings — the regression
tests added in rounds 1–3 close C1–C4, H1–H8, and N1–N6; the others
should be written alongside their fixes.

---

## 7. Quick-reference: current priority list

1. **Security-report open findings** (§6): the critical and high
   tiers are closed; next is the M-tier, highest-value first (M9 idempotency, M11
   commit/reply, M6/M4/M5 DMARC correctness, M12 limiter RAII,
   M14 storage hygiene).
2. **Phase 10 — Ops** (rate limiting/RCPT-probe caps — catch-all
   domains make every probe a valid recipient;
   IPv6 resolver/listener support). DNS caching/reuse (`DnsClient`),
   EDNS0, the accept loop, and resolver configuration are done.
3. **Phase 12 — Hosted address service (receive-only V1)**: authority
   seam is done (file-backed); remaining: console-backed authority,
   multi-domain identity (Phase 11 item), verdict policy profiles.
4. **Phase 9 — Extensions** (the inbound-relevant parts: 8BITMIME/
   SMTPUTF8/PIPELINING advertisement), then **Phase 11** remainders as
   needed.
5. **Phase 8 — Submission semantics (sending)** — **post-V1, low
   priority**. Kept documented so the receive-only design continues to
   preserve its hooks.

— End of plan.
