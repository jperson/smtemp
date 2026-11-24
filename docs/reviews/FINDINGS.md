# FINDINGS.md: Design and Code Assessment

**Date:** 2026-11-22
**Tree:** `8e3a643` plus the uncommitted F7 queue-retry change.
**Scope:** an overall quality assessment of the architecture and code, for
future reference. It complements the security documents rather than
repeating them:

- [SECURITY-AUDIT.md](SECURITY-AUDIT.md): vulnerabilities and their
  remediation;
- [DESIGN.md](DESIGN.md) §13: functional and security gaps;
- [PLAN.md](PLAN.md): remaining work.

**A note on bias.** The assessor also wrote part of the recent code (the
S1/S2/F1–F7 fixes, `auth.rs`, the SPF parser rewrite) and many of the tests
credited below. Discount the scores accordingly, and prefer an independent
review before general availability.

---

## 1. Summary

The **design is good; the code is solid where it matters but uneven.**
The architecture gets the hard decisions right: a protocol/policy seam with
binding verdicts, a durable commit before `250`, idempotent delivery, and
extension points where the product roadmap needs them. The weaknesses are
mostly structural. Too much of the code lives in one file. Per-message
state isn't modelled as a type. There are two header scanners, and a few
patterns have repeatedly produced bugs. None of them blocks the pilot.

| Aspect | Rating | One-line reason |
|---|---|---|
| Architecture | 8/10 | The seam, durability model and extension points are right |
| Security posture (current) | 7/10 | Good for a monitored pilot; N10, F9 and the unaudited dependencies hold it back |
| Code quality | 6.5/10 | Good parts; `main.rs` is too large; blocking work on async threads; loose typing |
| Tests | 8/10 | Broad, layered and externally anchored; no fuzzing; CI depends on live DNS |
| Operability | 6.5/10 | Good logs, graceful shutdown, privilege drop; no metrics endpoint or TLS reload |
| Documentation | 7/10 | Thorough and current; code comments carry too much history |

---

## 2. Design strengths

**D-S1. The protocol/policy seam.** The `smtp` crate owns verbs, states and
framing, and knows nothing about policy. It depends only on `anyhow`,
`tokio` and `base64`. Every decision goes through `SmtpSession`, and the
returned `Control` verdict *binds* the state machine: a rejected command
never advances state. `run()` is generic over the stream, so TCP, TLS and
in-memory duplexes share one loop.
- *Evidence:* STARTTLS, AUTH, DKIM and two SPF rewrites landed without
  reshaping the seam, and a small `TestSession` exercises the full state
  machine with no policy.

**D-S2. The durability contract.**
- The `250` is sent only after a durable write.
- The spool's `.json` metadata, renamed last, is the commit point.
- Delivery is idempotent per (mailbox, queue ID), so the fast path and the
  drain can race safely.
- Undeliverable mail is refused at RCPT, so the server never generates a
  bounce.

This is the established MTA model, implemented carefully.

**D-S3. Fail-closed boundaries** (as of now).
- An unavailable authority gets `451`, and a malformed publish keeps the
  last good snapshot in force.
- DMARC and DNS lookup errors, and an exhausted per-IP DNS share, all give
  temporary failures, never accept-and-skip.

**D-S4. Extension points match the roadmap.** These seams sit where PLAN §4
needs them: `RecipientResolver` (console authority), `DeliverySink` (S3),
`SpfResolver` (DNS abstraction and fixtures), `PayloadEncryptor`
(encryption), and the recipient identity carried through `SpoolRcpt`. Only
two small refactors are needed to keep the planned features additive (PLAN
§2.2).

**D-S5. Crate decomposition.** Crates are small, single-purpose and
independently testable, and dependencies only point downward (DESIGN §2).

---

## 3. Design weaknesses

**D-W1. Per-message state is not a type.**
- *Where:* `UserSession` holds transaction state as loose fields
  (`mail_from`, `rcpt_to`, `data`, `total_data`, `txn_limit`,
  `declared_size`, `spf_result`). It is reset by hand in `clear_envelope()`,
  next to session-level fields (`helo`, `dkim`, `dmarc`, `authenticated`).
- *Consequence:* the C3 bug (DKIM verdicts from one message satisfying
  DMARC for a later one) came directly from this mixing. Every new
  per-message field has to be remembered in `clear_envelope`, and the
  compiler can't help.
- *Recommendation:* a `Transaction` struct, created at an accepted MAIL and
  dropped at end-of-data, RSET or abort. `UserSession` would hold
  `Option<Transaction>`, so per-message state can't outlive its message.

**D-W2. Two header scanners with different rules.**
- *Where:* `mailparse::extract_raw_headers` (`mailparse/src/lib.rs:277`),
  which DKIM uses, and `split_header_lines` (`mailserv/src/main.rs:704`),
  which the From-domain and bare-CR checks use.
- *Consequence:* F3 (a bare CR hiding a second `From:`) was exactly a
  disagreement between readers about line boundaries. Two in-house scanners
  keep that class of bug possible inside the server itself: a header DKIM
  sees but DMARC doesn't, or the reverse.
- *Recommendation:* one raw header scanner, in `mailparse`. The From
  extraction becomes a function over its `RawHeader`s, and the bare-CR
  check is enforced once at the same boundary.

**D-W3. Fail-closed was retrofitted, not structural.**
- *Evidence:* several of the most serious findings were "unknown treated as
  fine":
  - DMARC failed open on DNS errors (F1);
  - the SPF parser dropped unrecognised terms (F4);
  - DKIM was skipped when the typed parse failed (N11);
  - DMARC was skipped on a parse failure (C4).
- *Consequence:* each was found and fixed individually. Nothing in the types
  makes the next one impossible.
- *Recommendation:* make policy inputs total. Lookups return
  `Found | Absent | TempError` (or similar) and are matched exhaustively, so
  a new error path can't fall through to "absent" silently. The DMARC change
  in F1 started this; apply it to SPF and DKIM key lookups too.

**D-W4. The queue's read side is concrete.** `SpoolWriter` abstracts writes,
but the drain takes `&DiskSpool` (list, load, record attempt, remove,
dead-letter). This is tracked as PLAN §2.2; listed here because it is a
design gap, not just missing work.

---

## 4. Code strengths

**C-S1. Hostile-input handling.**
- DNS parsing is total and tested against every truncation length and about
  5,800 bit-flips.
- SMTP framing is strict: `<CRLF>.<CRLF>` is the only DATA terminator, and
  the `<LF>.<CRLF>` variant is handled.
- Line lengths, message sizes, recipient counts, DKIM signature counts,
  `h=` lengths and comment depth are all bounded.

**C-S2. Careful async resource handling in `dns`.** Cancellation-safe drop
guards cover capacity, slot load, pending entries and in-flight gauges, and
each pending entry carries its own token. A dropped query can't leak
resources or remove another query's entry.

**C-S3. Low-level hygiene.**
- `unsafe` is confined to the privilege-drop syscalls, which verify that
  root can't be regained afterwards.
- No remotely reachable panics were found.
- Files are `0600` and directories `0700`, set explicitly.
- Bodies are never logged.

**C-S4. Tests.**
- 261 tests in four layers: unit, protocol, framing and loopback
  integration.
- Conformance anchors are external, never circular: openssl and RFC example
  hashes for DKIM, recorded real records for SPF, a mutated real response for
  DNS.
- Every security finding has a named regression test, often reproducing the
  real attack (a genuinely signed message, then tampered).

---

## 5. Code weaknesses

**C-W1. `mailserv/src/main.rs` is 4,723 lines** (about 2,670 of production
code). One file holds config resolution, the accept loop and shutdown, the
whole `UserSession` policy, the From-header scanner, HELO and path
validation, the TLS setup, and roughly half the crate's tests.
- *Consequence:* the hardest file to review, and the most likely place for
  unrelated changes to collide.
- *Recommendation:* split it into modules: `config.rs`, `server.rs` (accept
  loop, limits, shutdown), `session.rs` (`UserSession`, the `SmtpSession`
  impl), `headers.rs` (From extraction, bare-CR check; see D-W2) and
  `tls.rs`. Each module's tests move with it.

**C-W2. CPU-bound work on async worker threads.**
- *Where:* `end_data` awaits `dkim::verify_dkim` (`main.rs:1729`). Its body
  canonicalisation, SHA-256 and RSA/Ed25519 verification run synchronously
  on a tokio worker. The blocking pool is used for the spool, the authority
  and delivery (`spawn_blocking`, five call sites), but not for the crypto.
- *Consequence:* how S2 could pin a worker for minutes. It's bounded now
  (5 signatures, linear selection, RSA ≤ 4096 bits), but a 10 MiB body
  canonicalised five times is still noticeable worker time per message.
- *Recommendation:* fetch the DNS keys asynchronously, then run
  canonicalisation and verification in one `spawn_blocking`.

**C-W3. Stringly-typed verdicts and coarse errors.**
- *Where:*
  - SPF and DMARC results are stored in the spool metadata via `Debug`
    formatting: `format!("{r:?}")` at `main.rs:1922–1923`,
    `format!("{policy:?}")` and `format!("{action:?}")` at `main.rs:1873,
    1877`;
  - the `dns` and `spf` libraries use `anyhow` for resolver errors.
- *Consequence:*
  - renaming an enum variant silently changes the stored and logged format,
    which downstream consumers (the console, the event stream) will parse;
  - callers can't distinguish error kinds without string matching. DMARC
    only got a precise SERVFAIL/timeout path once a typed `Temp` was mapped
    explicitly.
- *Recommendation:* `serde`-serialised enums with stable names in the
  metadata; typed error enums in `dns` and `spf` (NXDOMAIN, SERVFAIL,
  timeout, malformed).

**C-W4. Duplicated rules.**
- *Where:* the mailbox-safe character set is defined twice:
  `is_mailbox_safe` at `main.rs:557` (RCPT validation) and the `safe`
  closure in `split_recipient` at `delivery.rs:131` (sink re-validation).
  The two header scanners (D-W2) are a second case.
- *Consequence:* the defence-in-depth check can drift from the primary
  check. Widening one (as was done for `o'brien@`, N4) without the other
  turns into delivery failures.
- *Recommendation:* one shared function, used at both sites; keep both call
  sites.

**C-W5. Comments carry history.** Many doc comments retell the bug ("F3
(SECURITY-AUDIT.md): … used to …", "C4 (security report): …").
- *Consequence:* the code's *current intent* is buried in narrative, and
  references go stale when documents are restructured (several did during
  the 2026-11-22 doc rewrite).
- *Recommendation:* comments state the invariant and the reason. Finding
  IDs go in the regression test name and the commit message.

**C-W6. Test-suite gaps.**
- **No fuzzing.** The SMTP framing, the From and bare-CR scanners, the SPF
  parser and macro expander, DMARC record parsing and DNS parsing are all
  good fuzz targets (`cargo fuzz`).
- **CI uses live DNS.** The `mailserv` integration tests resolve
  `spfless-domain-xyz.test` against the real 1.1.1.1. That's
  nondeterministic, and fails offline. The mock DoT resolver used by the
  DMARC tests could serve these too.
- **No dependency audit in CI.** Nothing runs `cargo audit` or `cargo deny`
  against the 232 crates in `Cargo.lock`.

---

## 6. Recommended improvements, by value

| # | Change | Addresses | Effort |
|---|---|---|---|
| 1 | Split `main.rs` into modules; introduce `Transaction` | C-W1, D-W1 | Medium; mechanical apart from `Transaction` |
| 2 | One raw header scanner shared by DKIM, From extraction and the bare-CR check | D-W2, C-W4 | Small–medium |
| 3 | DKIM crypto on the blocking pool | C-W2 | Small |
| 4 | Fuzz targets; hermetic integration tests; `cargo audit` in CI | C-W6 | Small to set up, then ongoing |
| 5 | Total lookup results (`Found / Absent / TempError`) for SPF and DKIM keys | D-W3 | Medium |
| 6 | Typed errors in `dns`/`spf`; `serde` enums in the spool metadata | C-W3 | Small–medium |
| 7 | Extract `SpoolQueue` | D-W4 (PLAN §2.2) | Small |
| 8 | Trim history out of code comments as files are touched | C-W5 | Ongoing |

Items 1–3 most reduce the kind of bug the security reviews have kept
finding: per-message state leaking, parsers disagreeing, and workers
blocked by attacker-controlled input. Do item 4 before general
availability. None of these blocks the monitored pilot.
