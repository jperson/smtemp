# PLAN.md — Review Findings & Forward Plan

> **Status:** the project has moved from "review findings" to "execution".
> All **19 original critical findings are fixed and regression-tested**
> (Section 1), and the pre-delivery security stack is complete: **STARTTLS,
> AUTH (PLAIN/LOGIN), SPF (with RFC 7208 lookup budget), DKIM verification
> (RSA + Ed25519), DMARC, and closed-relay recipient policy** — every check
> binding, wired into the live pipeline, and validated against real-world
> clients (`openssl s_client -starttls smtp`, spoofed `p=reject` DMARC
> rejection). The DNS resolver is configurable (`--resolver` / config
> file, default 1.1.1.1). Phase 7 has begun: accepted messages are
> **durably spooled to disk** (the `250` is only sent after the write)
> with a queue ID in the logs; local delivery is the next open item.
> Workspace state: **156 tests, 0 failures,
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
- [x] **Queue identity**: maildir-style queue ID (`<hex-millis>.<uuid>`,
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

- [ ] **DKIM signing** for authenticated submissions (sign with the
      authenticated domain's key; the `dkim` crate gains a signer).
- [ ] **`From:` validation** for authenticated submissions (user's domain
      or configured aliases; refuse spoofed From headers at MAIL time).
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
- [x] Configurable resolver: `--resolver <IP>` / `resolver` config-file
      key (CLI > file > default); default 1.1.1.1; resolved once in
      `resolve_config`, threaded through `SessionConfig` into
      `UserSession`, and logged at startup. IPv6 resolver destinations
      and IPv6 listener validation **still open** (`--resolver` and
      `DotResolver` take `Ipv4Addr`).
- [ ] Rate limiting / connection caps per source IP.
- [ ] UDP production hardening (retries/timeout) or retire `query_udp`.
- [ ] EDNS0 handling in `dns`.
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

1. **No recipient authority seam.** `rcpt_to` validates only the
   *domain* against a static `Arc<HashSet<String>>`; any local-part at a
   local domain is accepted. The product needs an async
   `RecipientResolver` trait ("is this domain hosted? does this address
   map to a mailbox?") consulted at RCPT time, with caching
   (aliases are unlimited — per-RCPT lookups must not hit the authority
   every time), a timeout, and a **fail-closed** outage policy (`451`,
   never accept-then-fail). Failure semantics matter: accepting mail the
   platform cannot route produces backscatter once delivery exists.
   *Implementation note (encryption, gap 3):* design the resolver's
   result to include — or be joinable with — the **user's public key**
   (and key-rotation generation), not just mailbox routing info. The
   multi-recipient container encryption needs the recipient key set at
   end-of-data; retrofitting the key into the lookup result later would
   be a second schema/API migration.

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
   in the console, not in server config.
7. **MX-scale economics.** At real MX volume, the per-query DoT
   connection in `DotResolver` (one fresh TLS connection + rustls config
   per SPF/DKIM/DMARC query) is the dominant cost — the Phase 10 DNS
   caching/reuse item becomes a prerequisite, not an optimization.
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

## 6. Quick-reference: current priority list

1. **Phase 7 — Delivery** (spool, maildir, `Received:`/`Return-Path`,
   queue ID). The security stack is complete; delivery is the finish line.
   *For the receive-only V1 this is the critical path; the `DeliverySink`
   seam should anticipate the Phase 12 hosted backend.*
2. **Phase 10 — Ops** (DNS caching — a prerequisite at MX scale, not an
   optimization; rate limiting/RCPT-probe caps — catch-all domains make
   every probe a valid recipient; graceful shutdown; IPv6
   resolver/listener support). CI, `RUST_LOG`, the config file, the accept
   loop, and resolver configuration are done.
3. **Phase 12 — Hosted address service (receive-only V1)**: recipient
   authority seam, dynamic domain catalog, multi-domain identity (Phase
   11 item), verdict policy profiles.
4. **Phase 9 — Extensions** (the inbound-relevant parts: 8BITMIME/
   SMTPUTF8/PIPELINING advertisement; SIZE parameter enforcement), then
   **Phase 11** remainders as needed.
5. **Phase 8 — Submission semantics (sending)** — **post-V1, low
   priority**. Kept documented so the receive-only design continues to
   preserve its hooks.

— End of plan.
