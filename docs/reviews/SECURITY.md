# SECURITY.md — Security Review of mailserv

**Scope:** every crate in the workspace (`smtp`, `mailserv`, `dns`, `spf`,
`dkim`, `dmarc`, `mailparse`, plus `dnsq` and `smtp-client`).
**Reviewed revision:** `d014804` ("dns pipelining finished") plus the
uncommitted working-tree changes present at review time.
**Review type:** fresh, independent review. The prior reviews
(`REPORT.md`, `DEPLOYMENT.md`, PLAN.md §6) were read for context, and every
finding claimed open there was re-checked against the current code. The
code was **not modified**.
**Test status:** `cargo test --workspace` → **228 passed, 0 failed, 1
ignored**; `clippy -D warnings` clean. The two new findings below were
reproduced against a locally built server.

---

## 1. Executive summary

The core protocol and policy work is in good shape: the
`SmtpSession`/`Control` seam is sound, the SMTP-smuggling and path-traversal
classes are closed and regression-tested, DNS response parsing is total,
and the transport/recipient policy is fail-closed in the right places.

However, this review found **two denial-of-service defects that the prior
reviews did not identify**, both reachable at end-of-data before any
policy verdict is reached:

| # | Severity | Finding | Status |
|---|---|---|---|
| **S1** | **Critical** | Remote **stack-overflow abort** of the whole process via deeply nested comments in any parsed header (recursive `comment` rule in the pest grammar, reached by DKIM's typed parse). A single ~100 KB message kills the server. | **FIXED** (§2.1) — verified live on a release build |
| **S2** | **High** | DKIM signed-header selection is **O(h=`h:` entries × headers)** and runs synchronously, so one message can pin a worker thread for ~30 minutes. | **FIXED** (§2.1) |

The previously reported **H6 (DNS-pool starvation)** is genuinely fixed by
the pipelining work (2 connections × 64 in flight, plus `--max-dns-per-ip`).
The remaining open items from the prior reviews are catalogued in §4; the
two most important are the **unvalidated HELO** (trace-header injection,
M8 — re-verified) and **IPv4-mapped peers breaking SPF** (N19).

If the service is exposed to the internet today, **S1 must be fixed
first**: it is a one-message, unauthenticated, whole-process crash.

> **Update (2026-11-22):** S1, S2, M8, N19 and N11 are fixed and
> regression-tested; see §2.1. The remaining open items are in §3.

---

## 2. New findings

### S1 — Critical: remote stack overflow via nested header comments

**Class:** unauthenticated remote denial of service (process abort).
**Impact:** the entire server process aborts (`SIGABRT`), dropping every
connection. It is not a recoverable panic — Rust aborts the process on
stack overflow, so the task-level panic handling in the accept loop does
not help.

**Where:**

- `mailparse/grammar/mail.pest:10` —
  `comment = @{ "(" ~ (fws? ~ ccontent)* ~ fws? ~ ")" }`, and
  `ccontent = { ctext | quoted_pair | comment }` (`mail.pest:8`). The
  `comment` rule is directly recursive, with no depth bound.
- `mailparse/src/lib.rs:142` `parse_headers` (the pest parse) and `:125`
  `parse_message`.
- `dkim/src/lib.rs:1395` `verify_dkim` calls `parse_message(raw)` for
  **every** message, before any DKIM signature is examined.
- `mailserv/src/main.rs:1595` calls `verify_dkim` unconditionally at
  end-of-data.

**Trigger:** a message whose header block contains a header parsed through
`cfws`/`comment` — `From:`, `To:`, `Cc:`, `Received:`, `Sender:`,
`Reply-To:`, `Resent-*`, `Message-ID:`, etc. — with a deeply nested
comment. Minimal example (single line, ~2.4 KB):

```
Received: (((((...1200 nested...)))))a@b
Subject: x

body
.
```

The recursion depth is the nesting count; the attacker can go far deeper
by folding the comment across lines (each data line ≤ 64 KiB, message ≤
`--max-data-bytes`, default 10 MiB).

**Why the existing timeouts do not help:** the parse is synchronous. It
runs inside the future wrapped by `timeout_at(END_OF_DATA_DNS_DEADLINE, …)`
(`main.rs:1595`) and inside the whole-connection `timeout_at`
(`main.rs:2143`), but neither can preempt a non-yielding call. The stack
overflow happens before any await point.

**Reproduction (verified):**

- Debug server: 1,000 nested comments (≈2 KB) → `thread
  'tokio-runtime-worker' has overflowed its stack / fatal runtime error:
  stack overflow, aborting`, exit code `-6` (SIGABRT).
- **Release server** (`target/release/mailserv`): 10,000 nested comments on
  one line (≈20 KB), and 50,000–300,000 nested across folded lines, both
  crash the process. The crash occurs at `END_DATA` before DMARC/`From`
  evaluation, so the message does not need a valid `From:`, a valid
  envelope sender, or any DKIM signature.

**Fix directions (not applied):**

1. Bound the nesting depth in the grammar (pest supports explicit stack
   limits via `PUSH`/`POP`/`PEEK`, or add a `depth` counter rule), and
   return a parse error past the limit.
2. Add a cheap pre-scan of the raw header block that rejects pathological
   comment nesting (or an excessive count of `(`/`)`) before invoking pest.
3. Remove the typed pest parse from the untrusted hot path: DKIM only needs
   the byte-level raw view (`split_message` + `extract_raw_headers`), which
   is iterative and safe. This also addresses N11.
4. Add a fuzz/regression test that feeds nested comments and asserts no
   abort. A stack overflow is **not** catchable with `catch_unwind`.

> Note: this affects any caller of `mailparse::parse_message` on untrusted
> bytes, not only mailserv.

---

### S2 — High: DKIM `h=` list gives O(h × headers) CPU amplification

**Class:** unauthenticated remote CPU-exhaustion DoS.
**Impact:** one message can occupy a tokio worker thread for tens of
minutes of CPU; a handful of concurrent messages can starve all workers.
The work is synchronous, so the end-of-data DNS deadline and the
connection-duration cap cannot interrupt it.

**Where:** `dkim/src/lib.rs:515` `signed_header_data`. For every name in
`sig.signed_headers` it scans the **entire** header list from the end
(`dkim/src/lib.rs:523-531`). `find_signatures` (`:267`) imposes no bound on
the length of the `h=` list; `MAX_SIGNATURES` (`:1387`) caps the number of
signatures but not the size of one signature's `h=`.

**Trigger:** a `DKIM-Signature` with a large `h=` list naming headers that
do not exist, plus many other headers, e.g.

```
DKIM-Signature: v=1; a=rsa-sha256; d=attacker.example; s=k;
  bh=AA==; b=AA==; h=z:z:z:...(thousands)...:z
X-F0: v
X-F1: v
...(many headers)...
```

The key lookup at `{s}._domainkey.{d}` must succeed for
`signed_header_data` to be reached (`verify_with_key` is only called when
`fetch_public_key` returns `Ok`), but the attacker controls their own
domain and can publish a syntactically valid (even cryptographically
useless) `v=DKIM1; p=…` record, so this is fully attacker-controlled.

**Verification:** measured directly against the real `dkim` crate in a
standalone release binary:

| `h=` entries | headers | message bytes | `verify_with_key` time |
|---|---|---|---|
| 1,000 | 1,000 | 13 KB | 1.5 ms |
| 4,000 | 4,000 | 55 KB | 24 ms |
| 8,000 | 8,000 | 111 KB | 97 ms |
| 20,000 | 20,000 | 289 KB | 607 ms |

The time scales as h × headers (quadratic when both grow). With the 10 MiB
default limit an attacker can budget roughly 2.5 M `h=` entries and ~500 k
headers, i.e. ~10¹² comparisons ≈ **30+ minutes of one CPU core per
message**, uninterruptible by the async timeouts.

**Fix directions (not applied):**

1. Cap the number of `h=` entries (and/or total signed-header names) per
   signature.
2. Pre-index headers by name once per message (e.g. a
   `HashMap<name, Vec<index>>`) and select from the per-name stack, making
   selection linear.
3. Reject `h=` lists with duplicate names or beyond a small bound, per
   RFC 6376 §3.5.

---

### 2.1 Remediation (2026-11-22)

The proposed fix directions were reviewed. Most were adopted, and one was
rejected (S2 direction 3, below). The fixes for M8, N19 and N11 came from §5's
recommended order and were done in the same pass. `cargo test --workspace`
→ **242 passed, 0 failed, 1 ignored**; clippy `-D warnings` and fmt are clean.

| # | Fix | Regression tests |
|---|---|---|
| **S1** | **Directions 3 + 1/2 + 4.** DKIM no longer runs the typed parse. A new `mailparse::parse_raw_message` returns a `RawMessage { headers, body }` built only by the iterative byte scanner, and every `dkim` API now takes `&RawMessage`, so the type system keeps the grammar off the DKIM path. Nothing else in the server calls the pest parser. For defence in depth, `parse_headers` runs a conservative nesting pre-scan first and returns `MailHeaderError::TooDeeplyNested` above `MAX_COMMENT_DEPTH` (64). The pre-scan never undercounts: it counts parens inside quotes too, a `\` skips one byte to match `quoted_pair` so `\)` can't hide nesting, and depth is never reset at line ends because `ctext` admits CR/LF. A grammar-level `PUSH`/`POP` bound was not used, because pest has no counter primitive. | `mailparse`: `deep_nesting_is_refused_not_overflowed` (depths 65 / 1k / 100k in `Received`/`From`/`To`/`Message-ID`, on a 2 MiB stack), `deep_nesting_across_lines_is_refused`, `escaped_parens_do_not_hide_nesting`, `nesting_at_the_bound_parses`. `dkim`: `verifies_messages_the_typed_parser_rejects`. **Live:** the 300k-level folded payload against `target/release/mailserv` now gets `250 Ok` and is delivered, and the process stays up. |
| **S2** | **Directions 1 + 2.** `signed_header_data` indexes the message's headers by lowercased name once (only names that `h=` lists) and pops from each per-name stack. That keeps RFC 6376 §5.4.2 bottom-up, use-once semantics in O(h + headers). `DkimSignature::parse` refuses an `h=` list over `dkim::MAX_SIGNED_HEADERS` (256) as `InvalidTag("h")`. **Direction 3 was not adopted:** duplicate names in `h=` are legitimate oversigning (RFC 6376 §8.15 recommends it, e.g. `h=From:From`), and RFC 6376 §3.5 sets no such bound, so rejecting duplicates would break real signatures. | `signed_header_selection_order`, `signed_header_list_is_bounded_and_linear` (256 entries × 200k headers). |
| **M8** | `helo()` validates the argument before recording it: a domain (letters, digits, `-`, `_`; 1–63-octet labels; ≤255; optional trailing dot) or an RFC 5321 address literal. Anything else gets `501 5.5.2` and the session stays Idle. The check runs before any SPF lookup. `prepare_for_delivery` also replaces non-printable bytes in a stored HELO with `?`, which covers spool metadata written by older builds. | `helo_validation`, `invalid_helo_is_rejected_and_not_recorded`, `delivery_copy_neutralises_control_characters_in_helo`. **Live:** `EHLO evil.example\rX-Injected: yes` → `501 5.5.2`. |
| **N19** | `canonical_peer()` applies `IpAddr::to_canonical()` at both entry points (accept loop and `handle_connection`). Per-IP limits, SPF, logs and `Received:` therefore all see plain IPv4. | `mapped_peers_are_canonical`. |
| **N11** | Closed by the S1 change: DKIM no longer depends on the typed grammar or on UTF-8 header blocks. | `verifies_messages_the_typed_parser_rejects` (non-UTF-8 `Subject`). |

---

## 3. Re-verified: prior findings still open

These were already tracked in `REPORT.md`/`PLAN.md` §6/`DEPLOYMENT.md`;
they were re-checked against the current tree and are **still present**.
They are listed here so a reader of this document has the current picture.
Severities are the prior reviews'.

| Ref | Sev | Finding | Evidence in current tree |
|---|---|---|---|
| **M8** | Medium | **FIXED (§2.1).** ~~**HELO is not validated; trace-header injection.**~~ A bare CR in the HELO argument is copied verbatim into the delivered `Received:` header. | **Re-verified live:** `EHLO evil.example\rX-Injected: yes` produced `Received: from evil.example\rX-Injected: yes (127.0.0.1)` in the delivered `.eml`. `helo()` (`main.rs:1089`) only does `arg.trim()`; `prepare_for_delivery` (`delivery.rs:215`) interpolates it. |
| **N19** | High (deploy) | **FIXED (§2.1).** ~~**IPv4-mapped peers break SPF.**~~ With `--host [::]`, IPv4 clients appear as `::ffff:a.b.c.d`; `ip4:`/`a`/`mx` never match. | No `to_canonical()` anywhere; `check_ipv4` matches only `IpAddr::V4` (`spf/src/lib.rs:428`). |
| **M6** | Medium | **DMARC fails open on DNS error.** `Ok(Err(e))` from `fetch_policy` is logged and treated as "no record". | `main.rs` end-of-data DMARC match arm. |
| **M4** | Medium | **`sp=` never applied.** `policy_for(&from_domain, &from_domain)` always selects `p=`. | `main.rs` end-of-data. |
| **M3** | Medium | **Org domain = last two labels**, no Public Suffix List (`co.uk`, `com.au` unprotected). | `dmarc/src/lib.rs` `fetch_policy`. |
| **M5** | Medium | **Relaxed alignment is suffix-of, not same-org-domain.** Sibling subdomains fail DMARC. | `dmarc/src/lib.rs` `aligned_relaxed`. |
| **M17** | Medium | **DKIM verifier gaps:** no minimum RSA size (RFC 8301), `l=` honoured, `h=` not required to include `From`, duplicate tags accepted. | `dkim/src/lib.rs` `body_hash`, `verify_signature`. |
| **M9** | Medium | **Catch-all deliveries collapse into one copy.** The idempotency/filename key uses the routing mailbox, not the envelope address, so several catch-all recipients overwrite one file. | `main.rs` fast path `sink.deliver(&rcpt.mailbox, …)`; `delivery.rs` `sanitize(normalized)`. |
| **M10** | Medium | **State-machine sequencing:** MAIL/RCPT/DATA before EHLO reply `500` not `503`; EHLO does not reset an in-flight transaction; the 512-octet command cap truncates long AUTH PLAIN initial responses. | `smtp/src/lib.rs` `handler`. |
| **M11** | Medium | **Whole-connection cap can fire between spool commit and the `250`**, causing duplicate delivery on client retry; silent session drop. | `main.rs` `timeout_at(... max_conn_duration_ms ...)`. |
| **M13** | Medium | **Drain loads every queued payload into memory** each pass. | `spool.rs` `list()`. |
| **M16** | Medium | **AUTH weaknesses:** plaintext credentials, no failed-attempt limit, `*`-abort leaves LOGIN state, case-sensitive mechanism names, non-constant-time comparison. | `main.rs` `auth`/`auth_line`/`verify_credentials`. |
| **N10** | Medium | **No storage quotas.** One message to 100 recipients is stored 100×; the default `StaticAuthority` creates a maildir per invented address. | `main.rs` `rcpt_to`/`end_data`; `authority.rs`. |
| **N9** | Medium | **Display-name spoofing passes DMARC** (`From: ceo@victim <x@attacker>`). | `main.rs` `mailbox_domain`. |
| **N8** | Medium | **Bare CR in the header block hides a header from the `From:` scanner** (parser differential). | `main.rs` `split_header_lines`. |
| **N11** | Medium | **FIXED (§2.1).** ~~**DKIM returns nothing when `mailparse` rejects a message**~~, so legitimate signed mail from `p=reject` domains can be rejected (fail-closed availability bug). | `dkim/src/lib.rs:1395`. |
| **N12** | Low | **SPF macro expander is lenient on malformed input** (brace-count heuristic; `c`/`r`/`t` expanded outside `exp=`). | `spf/src/parser/parser.rs` `expand_macro_string`. |
| **N14** | Low | **Shell metacharacters allowed in maildir directory names** (`|`, `` ` ``, `$`, `?`, `*`). Safe inside mailserv, risky for operator scripts. | `main.rs` `is_mailbox_safe`; `delivery.rs`. |
| **N15** | Low | **Up to ~5 copies of each message in memory at once.** | `main.rs` `end_data`; `spool.rs` `write`. |
| **N16** | Low | **No SPF alignment for the null sender** (bounces), since the HELO identity is ignored. | `main.rs` DMARC SPF alignment. |
| **M1** | Medium | **SPF parser is case-sensitive / stops at unknown terms** (`-ALL` dropped; `v=spf10`). | `spf/src/parser/lexer.rs` (`v=spf1`, `all` lowercase); `spf/src/lib.rs` `query_spf_record` uses `starts_with("v=spf1")`. |
| **M2** | Medium | **SPF budget over-counts MX-host and PTR-name A lookups**, causing spurious PermError on large records. | `spf/src/lib.rs` `check_mx_record`, `check_ptr_record`. |
| **M12** | Medium | **Connection limiter does an O(n) sweep per close and leaks the per-IP active count if a session panics.** | `limit.rs` `release`. |
| **M7** | Medium | **No `Authentication-Results:` header; forged inbound ones are not stripped.** | end-of-data. |
| **L1–L12** | Low | DNS label-length validation in parsed names, cache eviction, no DNSSEC, EHLO-per-connection SPF cost, log spans, ignored write errors, TLS reload/SNI, config footguns, `dnsq` per-call config. | see `REPORT.md` §Low. |

### 3.1 Design-level observations still valid

- **AUTH is enabled in a receive-only V1.** If `--auth-users` is set, any
  credential holder gets SPF/DMARC exemptions and can inject `From:` spoofs
  into hosted mailboxes. The prior reviews recommend disabling AUTH on
  port 25 or removing the exemptions in V1.
- **From-domain validation is a hard prerequisite for AUTH.** The
  `authenticated` trust flag skips SPF (`main.rs:1308`) and exempts the
  session from DMARC rejection (`main.rs:1711`). The control that normally
  makes that safe — constraining an authenticated user's
  `MAIL FROM`/`From:` to domains they own — is **not implemented** (PLAN
  Phase 8). Until it is, AUTH must not be enabled in any deployment: a
  receive-only server has no sending use for AUTH, so the exemptions are
  pure attack surface. Do not set `--auth-users` on an internet-facing
  instance, and never advertise AUTH on port 25.
  **Update (2026-11-22): implemented.** `--auth-senders` maps each login
  to exact addresses and whole domains (`mailserv/src/auth.rs`). An
  authenticated `MAIL FROM` outside the grants, or the null sender, gets
  `553 5.7.1`. Any `From:` author outside them gets `550 5.7.1`, read with
  the same raw scan DMARC uses, so display names and comments can't
  supply it. Both checks run before the SPF skip and the DMARC exemption.
  It fails closed: a login without grants can't send. Tests:
  `auth::tests::*`, `from_validation_tests::*`, and the STARTTLS+AUTH
  integration test `auth_and_relay_policy`. This was the
  prerequisite, but not the only blocker. Keep AUTH off internet-facing
  instances until credentials are hashed (PLAN Phase 8), M16 is fixed
  (attempt limiting, constant-time compare), and AUTH is offered only on
  a submission listener.
- **`StaticAuthority` is the default** and accepts every local-part at the
  configured domain, which is the reachable path for N10 and amplifies S1
  (no valid recipient needed to reach end-of-data). Consider requiring
  `--authority` outside development.
- **No per-message storage quota / free-disk tempfail**, so disk
  exhaustion dead-letters mail that was already accepted.

---

## 4. What is working well (verified this pass)

- **SMTP framing / smuggling:** `Data`/`Discard` are pure framing modes;
  the only exit is `<CRLF>.<CRLF>`; the `<LF>.<CRLF>` differential is
  handled (`smtp/src/lib.rs` `run`/`handler`), with regression tests.
- **Path traversal:** RCPT local-parts are validated at RCPT time and
  again in the sink (`unsafe_local_part`, `split_recipient`); `Path::join`
  with an absolute component cannot escape the maildir root.
- **DKIM cross-message leakage (C3):** DMARC consumes only the current
  message's `dkim_summaries`; the regression test is hermetic (mock DoT).
- **DMARC on bad `From:` (C4/N2/N3):** the tolerant raw-byte scanner is
  used, not the typed parser; missing/multiple/unparseable `From:` are
  hard rejects.
- **DNS hardening:** response parsing is total (bounds-checked,
  depth-limited compression pointers); responses are validated (ID, QR,
  question echo, EDNS0); a per-source-IP DNS limiter bounds one client's
  share; the pipelined client fixes the old pool starvation (H6).
- **Privilege drop / file modes:** root is refused without `--user`;
  `drop_to` verifies it cannot regain root; spool/maildir files are `0600`
  and directories `0700`, with a `umask(0o077)` backstop.
- **Fail-closed authority:** an unreachable/malformed authority yields
  `451`, never accept-then-fail; last-good policy is served through a bad
  publish (M15/N5 fixed) with a loud error log.
- **Secrets in logs:** passwords are never logged; the per-line
  `recv_data` span is `TRACE`, so bodies do not reach the INFO log.

---

## 5. Recommended fix order

1. **S1** — bound pest recursion / remove the typed parse from the
   untrusted hot path. This is a one-message whole-process crash.
2. **S2** — cap or index the DKIM `h=` selection.
3. **M8** — validate HELO (reject control characters; require a
   domain/address-literal syntax) before it reaches `Received:`.
4. **N19** — `peer.ip().to_canonical()` at the peer boundary.
5. **N10 / M9 / M11** — storage quotas, correct catch-all idempotency key,
   and per-phase timeouts that never cancel between commit and reply.
6. **DMARC correctness group (M3/M4/M5/M6/N16)** and **N11** (DKIM on the
   raw view — which also removes a major S1 exposure).
7. The remaining M-tier and L-tier items.

---

## 6. Method and scope notes

- Every crate was read; the SMTP state machine, policy layer, DNS
  client/codec, DKIM/DMARC/SPF logic, spool/delivery, authority,
  privilege-drop, and limiters were reviewed in detail.
- Findings S1 and S2 were reproduced locally: S1 against both
  `target/debug/mailserv` and `target/release/mailserv` (temporary
  directories, loopback only); S2 against the real `dkim` crate in a
  throwaway release binary. No project source was modified.
- M8 was reproduced live against the debug server and the delivered
  message was inspected byte-for-byte.
- `cargo test --workspace` passes (228 tests, 1 ignored live-DNS test).
- Items listed in §3 are prior findings re-confirmed by reading the current
  code; they were not all re-exploited live. See `REPORT.md` and
  `DEPLOYMENT.md` for the original reproductions and full detail.

---

## 7. Round-2 review (post-fix)

**Scope:** the team's fixes on top of the round-1 tree (`HEAD 640b60e` plus
the uncommitted working-tree changes). This review made **no source
changes**; only this document was appended. `cargo test --workspace`:
**249 passed, 0 failed, 1 ignored**. The release server was rebuilt and
probed on loopback.

### 7.1 Fixes verified this pass

| Ref | Round-1 issue | What changed | Evidence |
|---|---|---|---|
| **S1** | Remote stack-overflow abort via nested header comments | `dkim` now reads `mailparse::parse_raw_message`; `parse_headers` gained a pre-scan bounded by `MAX_COMMENT_DEPTH = 64`; DKIM never reaches the pest grammar on untrusted bytes | Live release server survived 300,000 nested comments in `Received:` (no abort); `mailparse` depth tests pass on a 2 MiB stack |
| **S2** | DKIM `h=` selection O(h × headers) | `signed_header_data` indexes headers by name once; `MAX_SIGNED_HEADERS = 256` caps the list | 200k-header/256-`h=` regression test finishes in ~0.02 s (was minutes); no quadratic path |
| **N11** | DKIM gave no verdict when the typed parser rejected a message | DKIM uses the raw view; non-UTF-8 headers no longer suppress verification | Raw-view tests pass; `parse_message` still rejects non-UTF-8 but DKIM no longer calls it |
| **M8** | HELO copied verbatim into `Received:` (bare-CR injection) | `valid_helo` at the SMTP layer; delivery path also neutralises non-printables as defence in depth | Live `EHLO evil.example\rX-Injected: yes` → `501`; valid `EHLO` still works |
| **N19** | IPv4-mapped peers break SPF on `[::]` | `canonical_peer` at accept and in `handle_connection` (`to_canonical()`) | Unit test added; SPF now sees plain IPv4 |
| **AUTH ownership** | `authenticated` was a blanket trust flag | New `mailserv/src/auth.rs`; `--auth-senders` grants; MAIL FROM and every `From:` author checked; null sender denied; SPF/DMARC exemptions are now conditional | Unit tests for grants/HELO; integration tests for authenticated MAIL/From; live server rejects ungranted sends |
| **D4** | No graceful shutdown | Shutdown signal now stops accepting and sends `421 4.3.2` to idle sessions; mid-message sessions finish first (`main.rs:306–310`, `2345`). `421 4.7.0` is the at-capacity refusal (`main.rs:2291`, `limit.rs:54`). | Code read; no regression found |

### 7.2 Remaining open findings (re-confirmed in code)

The team fixed the critical/high items above. The medium/low ledger in
`PLAN.md` §6 is still accurate; the ones I re-checked against the current
tree are:

| Ref | Sev | Still-present evidence |
|---|---|---|
| **M6** | Medium | DMARC fails open on DNS error: `Ok(Err(e)) => … None` in the end-of-data match arm; `quarantine` is also treated as pass. |
| **M4** | Medium | `sp=` still unused: `policy_for(&from_domain, &from_domain)` always selects `p=`. |
| **M3** | Medium | Organisational domain is still last-two-labels (no Public Suffix List); `co.uk`/`com.au` remain unprotected. |
| **M5** | Medium | Relaxed alignment is still suffix-of, not same-organisational-domain. |
| **M1** | Medium | SPF parser remains case-sensitive and truncates on unknown terms: `query_spf_record` uses `starts_with("v=spf1")`; the logos lexer matches lowercase `v=spf1`/`all`. |
| **M2** | Medium | SPF budget still over-counts MX-host and PTR-name A lookups. |
| **M7** | Medium | No `Authentication-Results:` is generated; forged inbound ones are not stripped. |
| **M9** | Medium | Catch-all deliveries still collapse to one copy: the sink is called with `rcpt.mailbox`, so several catch-all recipients share the idempotency key. |
| **M10** | Medium | State-machine sequencing unchanged: MAIL/RCPT/DATA before EHLO still gets `500` not `503`; EHLO does not reset an in-flight envelope; the 512-octet command cap still truncates long AUTH PLAIN initial responses. |
| **M11** | Medium | The whole-connection `timeout_at` still wraps `handle_connection` (`main.rs:2324–2331`), so it can fire between spool commit and the `250`, causing duplicate delivery on client retry. The new graceful-shutdown path does not change this. |
| **M12** | Medium | Connection limiter still does an O(n) sweep per close and releases the per-IP count manually after the session (`drop(permit); limiter.release(ip).await;` at `main.rs:2337–2338`); a panicking handler unwinds past that line and leaks the per-IP count (no RAII guard on the count; `DnsPermit` has `Drop`, the connection count does not). |
| **M13** | Medium | `DiskSpool::list` still loads every queued payload into memory each drain pass. |
| **M14** | Medium | **Partially fixed.** File/dir modes are now private via `fsutil` (`0600`/`0700`), but the maildir `new/` directory is still not fsynced after the rename, and the dead-letter timer/encryption gaps remain. `PLAN.md` still describes M14 as `0644` (stale). |
| **M16** | Medium | AUTH hardening unchanged: plaintext credentials, no failed-attempt limit, non-constant-time comparison (`verify_credentials` uses `==`). |
| **M17** | Medium | DKIM verifier gaps unchanged: no minimum RSA size, `l=` honoured, `h=` not required to include `From`, duplicate tags accepted. |
| **N8** | Medium | Bare CR in the header block still hides headers from the raw scanner (`split_header_lines` unchanged). |
| **N9** | Medium | Display-name spoofing still passes DMARC (`From: ceo@victim <x@attacker>`); the `From:` scanner deliberately reads only the address, not the display name. |
| **N12** | Low | SPF macro expander still lenient on malformed input. |
| **N14** | Low | Shell metacharacters still allowed in maildir directory names. |
| **N15** | Low | Up to ~5 copies of a message still in memory at once. |
| **N16** | Low | No SPF alignment for the null sender. |
| **L1–L12** | Low | DNS label validation, cache eviction, no DNSSEC, ignored write errors, TLS reload/SNI, config footguns, etc. — see `REPORT.md` §Low. |

### 7.3 New issues and regressions introduced by the fixes

1. **AUTH grants constrain only `From:` and `MAIL FROM`.** An authenticated
   sender can still set `Sender:`, `Reply-To:`, `Resent-From:`, or the
   display name of `From:` to an arbitrary address. The address in `From:`
   is checked, but the display name is not — so N9 display-name spoofing
   remains reachable for an authenticated credential holder. Consider
   constraining those headers too, or documenting that only `From:` is
   constrained.
2. **`valid_helo` rejects non-ASCII / IDN HELO domains.** The new validator
   accepts only A-label domains and address-literals, so a sender that
   greets with a raw UTF-8 or U-label domain is now refused (`501`).
   Punycode is unaffected and the RFC form is `Domain`, so this is low
   impact — but it is stricter than the previous verbatim copy and worth
   documenting in the README's `EHLO` description.
3. **Pre-scan over-counts.** `MAX_COMMENT_DEPTH = 64` counts parentheses
   inside quoted strings and display names as well as comments. That
   over-counting is the safety property: the pre-scan must never under-count.
   Do **not** make it quote-aware — a quote-tracking scanner can desync on a
   bare CR (the grammar's `ctext` admits CR/LF) and miss real nesting,
   reopening S1. The only false positive is a header value with >64
   *simultaneously open* `(` across the whole header block. Document the
   bound; leave the scan conservative.
4. **`MAX_SIGNED_HEADERS = 256` may reject legitimate heavily oversigned
   signatures.** 256 is generous, but a sender that signs hundreds of
   headers will now fail verification. Low risk, but document the cap.
5. **`parse_raw_message` still requires a header/body separator.** A signed
   message with no blank line still yields no DKIM verdict. DMARC already
   fails closed there (no DKIM pass ⇒ policy applies), so this is not a
   bypass; the real effect is that legitimate signed mail without a body
   fails to verify. Treat a missing separator as an empty body rather than a
   parse error.
6. **The S1 pre-scan is a library-level mitigation.** The server's real
   protection is that DKIM uses the raw view. If a future caller routes
   untrusted bytes through `parse_message`, the pre-scan is the only guard,
   and it has the false-positive behaviour above. Record the invariant in
   `DESIGN.md` §7: *untrusted mail must be parsed through the raw view*.
7. **`AuthConfig::parse` uses `split_once(':')`**, so a username cannot
   contain `:` (passwords can). Minor; document it in the flag help.
8. **Documentation drift.** `SECURITY.md` §1's table marks S1/S2 FIXED; it
   is the closing sentence above the update note that still says "S1 must be
   fixed first" (stale). `PLAN.md` M14 still says `0644` though `fsutil` now
   writes `0600`/`0700`. The README `--auth-senders` row does document the
   fail-closed behaviour and the startup warning, so that part is fine.

### 7.4 Security-design assessment

- **Ownership is now correct in spirit.** The protocol layer records the
  authenticated identity; the control layer decides what that identity may
  claim; the SPF/DMARC exemptions are conditional on the grant check. This
  matches the round-1 recommendation and removes the blanket-trust flaw.
- **AUTH is still a receive-only oddity.** It remains available behind
  `--auth-users`; the grants make it safe for the `From:` axis, but the
  design would be cleaner with an explicit submission mode (or default-off
  AUTH) rather than a flag on a receive-only binary. The remaining M16
  weaknesses (plaintext, no attempt limit, non-constant-time compare) matter
  if AUTH is ever exposed.
- **The S1/S2 fixes are structural and good.** Keeping the pest parser off
  the untrusted hot path is the right invariant; the pre-scan is a sensible
  backstop for library callers. The S2 index is the correct fix (linear,
  semantics preserved).
- **The biggest remaining policy gap is DMARC correctness** (M3/M4/M5/M6),
  not the DoS work. Those are small, well-scoped changes and should be the
  next security pass.
- **Recommended order:** M6/M4/M3/M5 (DMARC correctness) → M7/N8/M9
  (spoofing/duplicate delivery) → M11/M12/M13 (availability) → M16/M17
  (AUTH/DKIM) → N8/N9 and the remaining L-tier.

### 7.5 Method

- Read the changed files (`mailparse`, `dkim`, `mailserv`, `auth.rs`,
  `smtp`, `delivery`, `spf`) and re-read the unchanged hot paths.
- `cargo test --workspace`: 249 passed, 1 ignored; `cargo build --release -p
  mailserv` succeeded.
- Live probes on loopback against `target/release/mailserv`: S1 payload
  (300k nested comments) → server alive; M8 bare-CR HELO → `501`; valid
  HELO → accepted; valid delivery path → `250`.
- No project source was modified; this section is the only change.
