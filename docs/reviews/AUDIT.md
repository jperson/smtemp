# AUDIT.md — Round-2 Security Audit (post-fix)

**Tree reviewed:** `HEAD 640b60e` ("Security model updates, clean shutdown")
plus the uncommitted working-tree changes (`mailparse`, `dkim`, `mailserv`,
`delivery`, docs, new `mailserv/src/auth.rs`).

**Method:** read the changed files and re-read the unchanged hot paths;
`cargo test --workspace` (**249 passed, 0 failed, 1 ignored**); rebuilt the
release server and probed it on loopback. **No source code was modified by
this audit** — this document is the only artifact.

**Bottom line:** the team closed the critical/high findings from round 1
(S1, S2, N11, M8, N19, AUTH ownership) and added graceful shutdown. The
remaining risk is now concentrated in **DMARC correctness** and a handful
of **availability/robustness** gaps. A few small issues were introduced by
the fixes themselves (see §3).

> **Revision 2 (2026-11-22):** five fix directions in rev 1 would have
> introduced new bugs if implemented as written (M2, §3.3, M6, §3.1, M11),
> and several factual claims were wrong (421 code, SECURITY.md drift, M8→N8
> in the work order, RFC 8301 scope, missing-separator impact). They are
> corrected below and marked **[v2]**. §8 records the open decisions and the
> proposed defaults.

---

## 1. Verified fixed (do not re-open)

| Ref | Round-1 issue | Fix location | Evidence |
|---|---|---|---|
| **S1** | Remote stack-overflow abort via nested header comments | `mailparse/src/lib.rs:79,95` (`MAX_COMMENT_DEPTH`), `dkim/src/lib.rs:38` (raw view) | Live release server survived 300,000 nested comments in `Received:`; depth tests pass on a 2 MiB stack |
| **S2** | DKIM `h=` selection O(h × headers) | `dkim/src/lib.rs:174,1166` (`MAX_SIGNED_HEADERS`) | 200k headers / 256 `h=` entries ≈ 0.02 s; no quadratic path |
| **N11** | DKIM gave no verdict when the typed parser rejected a message | `dkim` uses `parse_raw_message`; non-UTF-8 no longer suppresses verification | Raw-view tests pass |
| **M8** | HELO copied verbatim into `Received:` (bare-CR injection) | `main.rs:527` `valid_helo`; delivery sanitises as defence in depth | Live `EHLO evil.example\rX-Injected: yes` → `501`; valid `EHLO` accepted |
| **N19** | IPv4-mapped peers break SPF on `[::]` | `main.rs:2486` `canonical_peer`; applied at accept and in `handle_connection` | Unit test; SPF sees plain IPv4 |
| **AUTH ownership** | `authenticated` was a blanket trust flag | `mailserv/src/auth.rs`; grants checked at `main.rs:1400` (MAIL FROM) and `main.rs:1765` (every `From:` author) | Unit + integration tests; live server rejects ungranted sends |
| **D4** | No graceful shutdown | `main.rs:306–310,2345` sends `421 4.3.2` to idle sessions; mid-message sessions finish first. (`421 4.7.0` is the at-capacity refusal, `main.rs:2291`/`limit.rs:54`.) | Code read; no regression found |

---

## 2. Remaining open findings

Ordered by recommended priority. Severity is the round-1 rating, unchanged
unless noted.

### 2.1 DMARC correctness (highest priority — this is a spoofing bypass class)

| Ref | Sev | Evidence | Fix direction |
|---|---|---|---|
| **M6** | Medium | DMARC fails **open** on DNS error: `Ok(Err(e)) => … None` at `main.rs:1795–1798`; `Action::Quarantine` is never enforced — only `Reject` is (`main.rs:1844`), so quarantine-policy mail is delivered as if it passed. | **[v2]** A lookup error must be a **temporary failure** (`451`), not a permanent reject and not "no policy" — a permanent reject would bounce legitimate mail on every DNS hiccup. Apply `Quarantine` to a destination (see §8); do not pass it. |
| **M4** | Medium | `sp=` is ignored: `policy_for(&from_domain, &from_domain)` at `main.rs:1820` always selects `p=`, so subdomain senders get the parent policy instead of the subdomain policy. | Pass the record's domain and the From domain separately; use `sp=` when the From domain is a subdomain and no explicit DMARC record of its own exists. |
| **M3** | Medium | Organisational domain is last-two-labels, no Public Suffix List; `co.uk` / `com.au` / `github.io`-style boundaries are wrong. | Add a PSL lookup (or a curated suffix list) for organisational-domain derivation. |
| **M5** | Medium | Relaxed alignment is suffix-of, not same-organisational-domain. | Compare organisational domains, not raw suffixes. |
| **M1** | Medium | SPF parser is case-sensitive and truncates on unknown terms: `query_spf_record` uses `starts_with("v=spf1")` (`spf/src/lib.rs:278`); the lexer matches lowercase `v=spf1`/`all`. | Case-insensitive `v=spf1` detection; `PermError` on any unparseable term instead of truncating. |
| **M2** | Medium | SPF budget over-counts MX-host and PTR-name A lookups against the 10-lookup budget (`spf/src/lib.rs:98,107`). | **[v2]** Do **not** simply remove the charge — today it is the only bound on those lookups (`check_mx_record`, `spf/src/lib.rs:480–490`). First add the RFC 7208 §4.6.4 per-mechanism **address-record cap** (10, `PermError` on exceed), then stop charging each host/name A lookup against the shared 10-query budget. |

### 2.2 Spoofing and duplicate delivery

| Ref | Sev | Evidence | Fix direction |
|---|---|---|---|
| **M7** | Medium | No `Authentication-Results:` is generated; forged inbound ones are not stripped. Only occurrence is a test fixture (`dkim/src/lib.rs:587`). | Generate an `Authentication-Results` header at end-of-data; strip/ignore client-supplied ones before delivery. |
| **M9** | Medium | Catch-all deliveries collapse to one copy: sink is called with `rcpt.mailbox` (`main.rs:1932`), so several catch-all recipients share the idempotency key. | Key idempotency on the actual recipient address, not the catch-all mailbox. |
| **N8** | Medium | Bare CR in the header block still hides headers from the raw scanner (`split_header_lines`, `main.rs:687`). | Reject or normalise bare CR in the header block; keep the raw scanner's view consistent with the delivered bytes. |
| **N9** | Medium | Display-name spoofing passes DMARC (`From: ceo@victim <x@attacker>`); the `From:` scanner reads only the address (`from_authors`, `main.rs:751`). | Detect display-name/address mismatch against the claimed domain, or document that display names are unverified. |

### 2.3 Availability and robustness

| Ref | Sev | Evidence | Fix direction |
|---|---|---|---|
| **M11** | Medium | Whole-connection `timeout_at` wraps `handle_connection` (`main.rs:2324–2331`); it can fire between spool commit and the `250`, causing duplicate delivery on client retry. Graceful shutdown does not change this. | **[v2]** Keep the whole-session deadline — it is the defence against slow-drip clients; do **not** reduce it to per-read idle timeouts. Instead, make the spool commit + `250` atomic with respect to the deadline (e.g. stop the deadline once the commit begins, or finish the transaction and reply before the deadline fires). |
| **M12** | Medium | Limiter releases the per-IP count manually after the session (`drop(permit); limiter.release(ip).await;` at `main.rs:2337–2338`); a panicking handler unwinds past it and leaks the count. `DnsPermit` has `Drop`; the connection count does not. | Wrap the per-IP count in an RAII guard with `Drop`. |
| **M13** | Medium | `DiskSpool::list` loads every queued payload into memory each drain pass (`spool.rs:247,266`). | Return metadata-only entries; load payloads on demand. |
| **M14** | Medium | **Partially fixed.** Modes are now private (`fsutil` `0600`/`0700`; used at `delivery.rs:191`, `spool.rs:471`), but the maildir `new/` directory is **not** fsynced after the rename (`delivery.rs:100`), and the dead-letter timer/encryption gaps remain. `PLAN.md:628` still says `0644` (stale). | fsync the target directory after the rename; keep the dead-letter timer; update `PLAN.md`. |
| **M10** | Medium | State-machine sequencing unchanged: MAIL/RCPT/DATA before EHLO gets `500` not `503`; EHLO does not reset an in-flight envelope; the 512-octet command cap (`smtp/src/lib.rs:347`) truncates long AUTH PLAIN initial responses. | RFC 5321 §4.1.4 sequencing; reset envelope on EHLO; allow the AUTH initial response to exceed the command cap or reject it cleanly. |

### 2.4 AUTH / DKIM hardening

| Ref | Sev | Evidence | Fix direction |
|---|---|---|---|
| **M16** | Medium | Plaintext credentials, no failed-attempt limit, non-constant-time comparison (`verify_credentials` uses `==`, `main.rs:1141–1152`). | Hash credentials at rest; constant-time compare; per-user/IP throttle. |
| **M17** | Medium | DKIM verifier: no minimum RSA key size, `l=` honoured, `h=` not required to include `From`, duplicate tags accepted. | **[v2]** Enforce RFC 8301 (≥1024-bit RSA, drop `rsa-sha1`) — it covers only key size and the hash algorithm. Fix `l=` and `i=` handling separately under RFC 6376. Also require `From` in `h=` and reject duplicate tags. |
| **A1** | Medium | **AUTH is advertised on whatever listener has TLS, not only a submission port.** `main.rs:1247` advertises `AUTH PLAIN LOGIN` whenever `tls_active && auth.is_some()`, so a TLS-enabled port 25 advertises a credential endpoint to the whole internet. DESIGN.md §5 already says submission-listener-only; the code does not enforce it. | Add a listener mode (`Relay` / `Submission`); advertise and accept AUTH only in `Submission`; gate the SPF/DMARC exemptions on the same mode, not on `authenticated` alone. Port 25 stays AUTH-free. |

### 2.5 Low

| Ref | Evidence |
|---|---|
| **N12** | SPF macro expander lenient on malformed input. |
| **N14** | Shell metacharacters allowed in maildir directory names. |
| **N15** | Up to ~5 copies of a message in memory at once. |
| **N16** | No SPF alignment for the null sender. |
| **L1–L12** | DNS label validation, cache eviction, no DNSSEC, ignored write errors, TLS reload/SNI, config footguns — see `REPORT.md` §Low. |

---

## 3. New issues introduced by the fixes

These are regressions or rough edges created by the round-2 changes; each
is small.

1. **AUTH grants constrain only `From:` and `MAIL FROM`.** An authenticated
   sender can still set `Sender:`, `Reply-To:`, `Resent-From:`, or the
   display name of `From:` to an arbitrary address. The address in `From:`
   is checked (`main.rs:1765`), the display name is not — so N9 display-name
   spoofing remains reachable for a credential holder. **[v2]** Constrain
   `Sender:` and `Resent-From:` (they also name a sender), but leave
   `Reply-To:` alone — redirecting replies to a helpdesk or list is normal
   and legitimate. Display names: see the N9 decision in §8.
2. **`valid_helo` rejects non-ASCII / IDN HELO domains** (`main.rs:527`).
   Only A-label domains and address-literals are accepted, so a raw UTF-8
   or U-label greeting is refused (`501`). Punycode is unaffected; low
   impact, but document it in the README's `EHLO` description.
3. **Comment-depth pre-scan over-counts.** `comment_depth_exceeds`
   (`mailparse/src/lib.rs:95`) counts every `(` including those inside
   quoted strings and display names. That over-counting is the **safety
   property** — the pre-scan must never under-count. **[v2]** Do **not**
   make it quote-aware: a quote-tracking scanner can desync on a bare CR
   (the grammar's `ctext` admits CR/LF, so a comment spans lines) and miss
   real nesting, reopening S1. The only false positive is a header value
   with >64 *simultaneously open* `(` across the whole header block, which
   is unusual. **Fix:** document the bound; leave the scan conservative.
4. **`MAX_SIGNED_HEADERS = 256` may reject legitimate heavily oversigned
   signatures.** Low risk, but document the cap.
5. **`parse_raw_message` still requires a header/body separator.** A signed
   message with no blank line yields no DKIM verdict. **[v2]** DMARC already
   fails closed there (no DKIM pass ⇒ policy applies), so this is not a
   bypass; the real effect is that legitimate signed mail without a body
   fails to verify. **Fix:** treat a missing separator as an empty body
   rather than a parse error.
6. **The S1 pre-scan is a library-level mitigation.** The server's real
   protection is that DKIM uses the raw view. If a future caller routes
   untrusted bytes through `parse_message`, the pre-scan is the only guard.
   **Record the invariant in `DESIGN.md` §7:** *untrusted mail must be
   parsed through the raw view.*
7. **`AuthConfig::parse` uses `split_once(':')`** (`auth.rs:40`), so a
   username cannot contain `:` (passwords can). Document it in the flag
   help.
8. **Documentation drift.** **[v2]** `SECURITY.md` §1's table marks S1/S2
   FIXED; it is the closing sentence above the update note that still says
   "S1 must be fixed first" (stale). `PLAN.md:628` still says M14 is `0644`.
   The README should mention the `MAX_SIGNED_HEADERS`/comment-depth caps.

---

## 4. Security-design assessment

- **Ownership is now correct in spirit.** The protocol layer records the
  authenticated identity; the control layer decides what that identity may
  claim; SPF/DMARC exemptions are conditional on the grant check. This
  removes the round-1 blanket-trust flaw.
- **AUTH is still a receive-only oddity.** It remains available behind
  `--auth-users`, and grants make it safe on the `From:` axis, but the
  design would be cleaner with an explicit submission mode (or AUTH
  default-off) rather than a flag on a receive-only binary. The remaining
  M16 weaknesses matter if AUTH is ever exposed.
- **The S1/S2 fixes are structural and good.** Keeping the pest parser off
  the untrusted hot path is the right invariant; the S2 index is the correct
  fix (linear, semantics preserved).
- **The biggest remaining policy gap is DMARC correctness** (M3/M4/M5/M6),
  not DoS. Those are small, well-scoped changes and should be the next
  security pass.

---

## 5. Recommended work order

1. **M6 / M4 / M3 / M5** — DMARC correctness (451 temporary failure on DNS
   error, `sp=`, PSL, organisational alignment). This is the spoofing bypass
   class.
2. **M7 / N8 / M9** — generate/strip `Authentication-Results`, keep the
   bare-CR fix consistent, fix catch-all duplicate delivery.
3. **M11 / M12 / M13** — availability: commit/reply atomicity under the
   deadline (keep the whole-session timeout), RAII limiter guard, streaming
   spool drain.
4. **M16 / M17** — AUTH and DKIM hardening.
5. **N8 / N9** and the remaining L-tier; fix the §3 rough edges and the doc
   drift as they are touched.

---

## 6. Notes for the team

- The working tree is **uncommitted**; `REPORT.md`, `SECURITY.md`, `AUDIT.md`
  and `mailserv/src/auth.rs` are untracked.
- `SECURITY.md` §7 has the same findings in narrative form; this file is the
  task list.
- No source changes were made during this audit.

---

## 7. Decision: credential storage (interim file, later backend)

Recorded in `DESIGN.md` §5 (AUTH) and `PLAN.md` Phase 8. Summary for the
team:

- **A file is an accepted V1 choice.** For a small receive-only server it
  has no network dependency, no new attack surface, and no failure mode
  that can block inbound delivery.
- **It is only acceptable as a secrets file.** Split the two things the
  current spec conflates: AUTH credentials (`user -> password`, argon2id
  hashes, `0600`, never in argv/`ps`) and sender grants (`user ->
  addresses/domains`, authorization policy, reloadable without restart).
- **Add reload before V1.** Today only the authority is hot-reloaded; a
  revoked user or grant stays live until the process restarts. SIGHUP
  reload for the auth file is a security requirement, not an ops nicety.
- **Put the file impl behind two seams** — `CredentialVerifier` and
  `SenderAuthorizer` — so the backend is a drop-in rather than a rewrite.
  Sender authorization normally stays in the app even when authentication
  moves to a backend.
- **Do not build the backend yet.** A receive-only V1 with AUTH disabled
  has no use for it. When submission becomes a product, the backend must
  fail closed for AUTH only (never block inbound delivery), cache with a
  TTL, revoke without restart, and bound calls with timeouts and a
  circuit breaker.

This decision does **not** change the recommended fix order in §5; the
credential-storage work is small and can land alongside the M16 hardening
item.

---

## 8. Open decisions (with proposed defaults)

These are product/policy choices, not document errors. Confirm or change
the defaults before the work starts.

- **M3 — Public Suffix List.** No PSL crate is in the local cargo cache.
  *Default:* vendor a PSL snapshot, with a documented refresh process and a
  test that fails when the snapshot is stale. Alternative: an out-of-tree
  build step that fetches and verifies the list.
- **M6 — quarantine destination.** `Quarantine` needs somewhere to go.
  *Default:* deliver to the recipient's maildir `.Junk` folder rather than
  tagging. Note this requires the sink to accept a folder argument.
- **M16 / §7 — credential file format.** *Default:* argon2id PHC-string
  file, `0600`, owned by the service user, reloaded on SIGHUP; credentials
  split from sender grants (see §7).
- **A1 — listener mode.** *Default:* `--listener-mode relay|submission`,
  default `relay`; AUTH advertised and accepted only in `submission`; the
  SPF/DMARC exemptions gated on the same mode. Port 25 stays AUTH-free.
- **N9 — display names.** *Default:* document display names as unverified
  rather than rejecting them. Rejecting would break legitimate
  `From: "Alice Smith" <alice@…>`; DMARC aligns on the address, not the
  display name.

If these defaults are accepted, the §5 order stands; A1 and N9 land with
the AUTH/DKIM pass.

---
---

# AUDIT.md — Round-3 Security Audit (2026-11-26B)

**Tree reviewed:** `HEAD 9d8fca4` ("security fixes"), the fully refactored
codebase (`mailserv` is now `config`/`server`/`session`/`session/message`,
`address`, `headers`, `auth`, `authority`, `spool`, `delivery`, `limit`,
`quota`, `tls`, `privdrop`, `fsutil`, `hashpw`, `verdict`; no more
`main.rs`).

**Scope:** every workspace crate in full — `smtp`, `mailserv`, `spf`,
`dkim`, `dmarc` (incl. `psl`), `mailparse`, `dns` (codec + DoT client) —
plus the fuzz targets and `DESIGN.md` / `README.md` / `DEPLOYMENT.md` /
`PLAN.md`.

**Method:** read every module end to end; validated each suspicion
empirically (loopback probes and `/proc` measurements) before writing it
up; `cargo test --workspace` (367 passed, 1 ignored) and
`cargo fmt --check` + `cargo clippy --all-targets -- -D warnings` clean.
**No source code was modified by this audit** — the artifact is the
`docs/` document plus six regression tests, one per finding below, that
**fail today** and encode the fixed behaviour.

**Status of prior rounds.** Round 1 (S1/S2/N11/M8/N19/AUTH-ownership) and
Round 2 (M1–M17, N8/N9, R1–R8 in the `AUDIT_20261126` review) are
**addressed in this tree**: the DMARC fail-open (M6), `sp=`/PSL/relaxed
alignment (M3/M4/M5), `Authentication-Results:` generation and forged-
header stripping (M7), bare-CR refusal (N8), display-name warning (N9),
spool-commit/deadline atomicity (M11), RAII limiter guards (M12),
metadata-only drain listing (M13), maildir fsync (M14), 503 sequencing and
AUTH line cap (M10), and the R1–R8 regressions all pass. Round 3 found
**no regression in any of them**; the five findings below are new.

**Bottom line:** the protocol, authentication and storage cores are in
good shape. The one finding that should gate port 25 is **F1**, a
memory-amplification DoS *in the connection-refusal path itself* — the
code the server runs when it is already at capacity. F2–F5 are bounded,
cheap fixes.

---

## R3.1 Findings

| ID | Sev | Where | Finding | Regression test (fails today) |
|----|-----|-------|---------|-------------------------------|
| **F1** | **High** | `mailserv/src/server.rs:714` (`refuse`) | A refused connection drains the peer's flood into an unbounded `Vec` (`read_to_end`), from a pool of 32 tasks, exactly when the server is at capacity. Measured: **208 MB RSS growth from one refused connection in <1 s** (834 MB pushed). | `server::tests::refused_connections_do_not_buffer_the_peer_flood` |
| **F2** | **Medium** | `mailserv/src/limit.rs:144` (`ConnectionLimiter::admit`) | Per-IP tracking state has no hard cap (unlike `FailureLimiter`'s 65 536): one-connection-per-IP churn grows the map with the attacker's chosen addresses, and every new IP runs an O(map) sweep per admit → linear memory, quadratic CPU on the accept path. | `limit::tests::tracked_ips_are_bounded_under_churn` |
| **F3** | **Medium** | `mailserv/src/config.rs` (`FileConfig`) | Unknown TOML keys are silently ignored. A typo'd `authority` key starts the server on the **static accept-every-local-part fallback** on port 25 as a "successful" startup. Same for `min-free-disk-bytes`, `mailbox-quota-bytes`, `submission-port`, `user`, … | `config::tests::unknown_config_keys_are_a_startup_error` |
| **F4** | **Low** | `spf/src/parser/parser.rs:198` (`is_spf_record`) | A valid SPF record whose separator after `v=spf1` is a tab (RFC 7208 §4.5: `sep = LWSP`) is not recognized as a record: the domain reads as "no SPF", so a published `-all` is never enforced — a silent fail-open of the class §4.6.1 forbids. | `record_edge_case_tests::tab_separated_records_are_records` and `…_are_evaluated` |
| **F5** | **Low** | `mailserv/src/config.rs` (`resolve_config`) | `--domain` (banner, EHLO, `Received: by`, `Authentication-Results:` authserv-id) is unvalidated: empty/whitespace silently disables forged-verdict stripping; CR/LF injects lines into the banner and every delivered message. | `config::tests::domain_is_validated_at_startup` |

### F1 (High) — the connection *refusal* path is a memory-amplification DoS

`server::run` hands over-limit connections to `refuse_async`, a bounded
pool of 32 tasks, each running `refuse` (`server.rs:714`). After writing
the `421`, `refuse` does:

```rust
let mut sink = Vec::new();
let _ = tokio::time::timeout(Duration::from_millis(500), async {
    let _ = stream.read_to_end(&mut sink).await;
}).await;
```

The drain's purpose is courtesy (avoid RST so the client can read the
`421`), but `read_to_end` **accumulates** everything the peer sends
during the whole 500 ms window instead of discarding it.

**Attack.** The path runs precisely when capacity is exhausted —
server-wide, per-IP, or per-IP-rate. A botnet (or one fat-pipe host)
opens connections past any limit and floods each one; each of the 32
refusal tasks buffers ~0.5 s × the peer's send rate. Measured with the
new test on loopback: **one refused connection pushed 834 MB and grew
the process 208 MB in under a second** — 32 tasks run concurrently, so
the ceiling is roughly bandwidth × 16 s of heap. Under the
`DEPLOYMENT.md` unit (`MemoryMax=1500M`) the OOM killer takes the whole
service: every accepted message mid-session loses its `250`, systemd
restarts the process, and the attacker repeats — a sustained kill loop
built entirely out of connections the server *thinks it is cheaply
refusing*. It also partially defeats the limits themselves: the refusal
pool becomes the attack's landing zone.

**Fix direction:** read into a fixed-size throwaway buffer (e.g. 8 KiB,
loop until EOF/timeout, drop the bytes), or stop draining and `shutdown`
+ short sleep; either keeps the courtesy property with O(1) memory. (The
kernel's own receive buffer already bounds what a *silent* client leaves
unread — accumulating it is what makes this unbounded.)

**Test:** `mailserv/src/server/tests.rs ::
refused_connections_do_not_buffer_the_peer_flood` — accepts one
connection, runs the real `refuse` against a flooding client, samples
`/proc/self/statm` concurrently, and asserts the RSS peak delta stays
under 16 MiB. Fails today (≈200 MB+).

### F2 (Medium) — `ConnectionLimiter` state is unbounded under IP churn

When the map reaches `sweep_at` (4096) entries, admitting a *new* IP
first runs `entries.retain(…)`, which keeps every IP whose 60 s rate
window has not expired — including IPs with no live connections. There
is no cap on the result.

One short-lived connection per distinct source address (the shape of a
distributed probe, or any IPv6 host, since limits are per-address — a
known §13 gap that multiplies here) inserts one entry that survives a
full window. The map's size is then "distinct IPs seen in 60 s", i.e.
attacker-chosen and bounded only by accept throughput. Two costs:
(1) **memory** grows linearly with churn; (2) **CPU is quadratic**: once
past `sweep_at`, *every* new IP rescans the whole map, an easy way to
burn accept-loop CPU while staying under all connection limits.

The sibling `FailureLimiter` in the same file already demonstrates the
right pattern: a hard `FAILURE_MAX_TRACKED` cap, sweep when full, and
*refuse to track* further new IPs (correctness degrades to per-session
limits; memory does not grow). `ConnectionLimiter` must bound its table
the same way (or bucket/aggregate per /24, per /64 — which also
addresses the §13 IPv6 gap).

**Test:** `mailserv/src/limit.rs ::
tracked_ips_are_bounded_under_churn` — 5000 distinct one-connection IPs
with `sweep_at = 64` and a 60 s window, asserting the tracked map stays
≤ 4096. Fails today: exactly 5000 entries are retained (the test's own
admit loop also shows the O(n)-per-admit sweep cost).

### F3 (Medium) — a TOML typo can silently turn the MX into an accept-all

`FileConfig` is `#[serde(default)]` with unknown keys ignored (the struct
comment says so explicitly). Nothing checks that every key in `--config`
was recognized.

The README and DEPLOYMENT.md both declare `authority` a go-live blocker
— without it the server uses `StaticAuthority`, which **accepts every
local-part at every hosted domain** ("never run an internet-facing
server without `--authority`"). A config containing
`authorith = "/etc/mailserv/authority.json"` starts "successfully": the
strict-schema authority file (itself a deliberate `deny_unknown_fields`
contract) is never read, every address receives mail, quota-exhaustion
and probing surface opens across all hosted domains, and the only signal
is an INFO log line an operator has no reason to diff. The same
silent-default mechanism applies to `min-free-disk-bytes`,
`mailbox-quota-bytes`, `user`, `max-dns-per-ip`, and the
`submission-port` gates. Compare the `auth-users` key handling in
`resolve_config`: the project already agrees this class of silent config
loss is a startup *error* — it just applies that judgment to one removed
key instead of to unknown keys in general.

**Fix:** `#[serde(deny_unknown_fields)]` on `FileConfig` (the key set is
exactly the documented flag names).

**Test:** `mailserv/src/config.rs ::
unknown_config_keys_are_a_startup_error` — `authorith`,
`mailbox-quota-bytez`, `maxconnection` must each fail to parse. Fails
today (all three parse "OK").

### F4 (Low) — tab-separated SPF records are silently ignored (fail-open)

`is_spf_record` (`spf/src/parser/parser.rs:198`) accepts only `"v=spf1"`
followed by a literal space or end-of-string. RFC 7208 §4.5 defines the
separator as `LWSP` (space **or tab** or foldable whitespace), and
§4.6.1 requires: a record that parses → evaluate it; anything unparseable
→ **PermError**. Never "pretend there is no record".

A domain publishing `v=spf1\t-ip4:… -all` (or any tab-separated variant a
zone editor produces) is classified as publishing *nothing*: `check_host`
returns `None`, MAIL FROM is accepted with `spf=none`, and the delivered
`Authentication-Results:` records a noncommittal result for a domain
whose published policy is a hard fail. This is the fail-open direction the
parser rewrite and the "never silently skip a term" rule were written to
eliminate; the detection gate predates and bypasses the parser.
Exploitability is limited (the tab spelling is a victim-side
misconfiguration, not attacker-chosen data), hence Low.

**Fix:** accept LWSP after the version token (`txt[6] == b' ' || txt[6]
== b'\t'`, keeping the `v=spf10`/`v=spf1-all` rejections; `parse()`
already splits on arbitrary ASCII whitespace).

**Tests:** `spf/src/lib.rs :: tab_separated_records_are_records` (unit)
and `tab_separated_records_are_evaluated` (end-to-end against fixture DNS:
unlisted IP → `Fail`, listed → `Pass`). Both fail today (`None`).

### F5 (Low) — `--domain` is not validated at startup

`resolve_config` requires only that `domain` is present. It is then
formatted verbatim into the `220` banner and every EHLO reply
(`server_greet`, `helo`), and into the delivered message —
`Received: … by {server_domain} …` and the `Authentication-Results:`
authserv-id (`with_trace_headers`, `authentication_results`).

A value containing CR/LF therefore injects lines into the banner and into
**every delivered message** (bypassing, from the config side, the exact
"no bare CR in the header block" property enforced on senders); an empty
or whitespace value breaks the forged-verdict stripper —
`is_forged_verdict` compares sender-chosen ids against
`authserv_id.trim_end_matches('.')`, which can never equal `""` or
`" mail.test"` — so senders keep planted `Authentication-Results:`
headers claiming the server's (malformed) id. Operator-supplied, but
every other startup input that reaches the wire is validated (ports,
resolver IPs, listener combinations, credentials file modes), and F3
shows config mistakes are a realistic failure mode.

**Fix:** validate `domain` at startup — non-empty, no whitespace or
control characters, ideally reusing `address::valid_helo`'s domain rules.

**Test:** `mailserv/src/config.rs :: domain_is_validated_at_startup` —
`""`, `"   "`, `"a b"`, `"mx1.example.org\rX-Injected: 1"` must all be
startup errors. Fails today (all four resolve successfully).

---

## R3.2 Informational findings (no test)

1. **DKIM tag values keep embedded folding whitespace.**
   `DkimSignature::parse` trims FWS only at the ends of each tag value,
   so `d=exa\r\n mple.com`-style folds leave CR/LF *inside* `d=`/`s=`.
   Every consumer fails closed (the DNS name never resolves →
   `NoKeyRecord`; alignment compares literal bytes → no match; logs are
   JSON-escaped; the AR copies run through `header_token`), so there is
   no bypass — but calling `strip_fws` on `d=`/`s=` (as `b=`/`bh=`
   already get) would match verifier practice. The `MAX_DNS_NAME_LEN`
   check counts FWS bytes, which is conservative.
2. **DNS cache worst-case footprint.** 4096 entries × up-to-64 KB DoT
   responses ≈ 256 MB is reachable with attacker-chosen names (≤5 DKIM
   `s=`/`d=`, SPF/DMARC names per message): the *count* is capped, not
   the *bytes*. Consider a total byte budget alongside
   `MAX_CACHE_ENTRIES`.
3. **`FileAuthority::current()` `expect`s on lock poisoning**
   (`authority.rs:634/639`), while every other lock recovers via
   `PoisonError::into_inner`. A panic under the write lock (the write
   path runs `serde_json` over operator-published files) would
   permanently convert every RCPT into `451` until restart.
   Poison-recovery would match the rest.
4. **DNS question-echo validation is case-sensitive**
   (`validate_response` compares `Label` strings directly). A conformant
   resolver that lowercases the qname in the echo (seen with some
   forwarders) would tear down the DoT connection on every response.
   Compare case-insensitively.
5. **`AuthConfig::check` waits unboundedly for a check slot**
   (`self.checks.acquire().await`): with the argon2 pool saturated,
   queued AUTH attempts hold their sessions (and connection slots) until
   the session deadline. A `try_acquire`/short timeout mapping to `454`
   would keep refusal replies prompt. (Session/per-IP failure budgets
   bound the *number* of checks; this is only about waiting.)
6. **Authority `catch-all-mailbox` is not syntax-checked at load.** An
   unsafe mailbox string (leading dot, `/`, …) is caught at
   delivery/usage time (`451` → the domain silently cannot receive), not
   at publish time. Validating it in `into_data` would make a broken
   publish a loud reload error.
7. **Known accepted gaps re-confirmed, not re-raised:** `pct<100` and
   `quarantine` handling, the soft quota (+1 message), per-IP (not
   per-/64) limits, PSL snapshot staleness, display-name look-alikes,
   spool bytes ≈ 2× limit per session, and the `452`-reveals-existence
   side channel are all accurately documented in DESIGN §13 /
   DEPLOYMENT §2; the implementations match their descriptions.
8. **Repo hygiene.** `docs/reviews/` was absent from the working tree at
   audit time (git showed the archive files deleted, unstaged — not by
   this review). The README also ends with a stray shell line
   (`claude --resume <uuid>`) that looks accidental. The docs' test count
   ("347") lagged the tree (368 before this audit added its six).

---

## R3.3 What was reviewed and held up

Each of the following was traced through the code and the existing tests
and is correct as implemented:

- **Framing/smuggling:** `<CRLF>.<CRLF>`-only terminator, bare-LF `.`
  and `<LF>.<CRLF>` re-stuffing (incl. across line-overflow boundaries),
  verbs-in-DATA-as-content, over-long command vs AUTH line caps (the
  `may_be_long` gate is precise), the 64 KiB data-line
  abort→discard→reset cycle, and read/deadline handling — no state
  advance on any refusal (`Control` binding verified against every arm
  of `handler`).
- **STARTTLS:** pre-TLS state and authentication discarded, buffered
  plaintext dropped, no second banner, `AUTH` never on MX, `538` on
  plaintext submission, `454` without a cert, RFC 3848 tokens.
- **Envelope → wire:** no control characters can reach `Return-Path:` or
  `Received:` (`clean_path`, `valid_helo`, `valid_reverse_path` — the
  R2 class stays closed; quoted-local edge cases included);
  `with_trace_headers` neutralizes stored HELO bytes.
- **Header pipeline:** one scanner for DKIM / From / bare-CR / strip;
  leading-continuation and verdict-named-continuation stripping
  (R1/R7) effective incl. double-strip idempotence;
  `from_authors`/`mailbox_address` bounds (≤100 authors, ≤253/63 domain,
  empty-label refusal — R4) hold; `MAX_HEADER_FIELDS` counts correctly.
- **SPF:** the §4.6.4 budget (10 terms / 2 voids, mx/ptr address caps),
  redirect-to-no-record → PermError, include→none → PermError, duplicate
  redirect/exp refusal, unknown-mechanism → PermError, macro-expansion
  errors → PermError, the 20 s deadline → TempError, and
  `Lookup` found/absent/temperror separation end-to-end (SERVFAIL is
  never "absent" — the old DKIM fail-open stays fixed). Only the F4
  detection gate was found broken.
- **DKIM:** ≤5 topmost signatures (lazily), mandatory `From` in `h=`,
  duplicate tags fatal, `l=` must equal the whole canonical body, `x=`
  boundary, `i=`/`d=` alignment incl. `t=s`, `k=`/`a=` matching before
  any crypto, SHA-256 only, RSA ≥1024/≤4096, revoked keys, service-type
  check, body streamed into the hash (one-pass), bottom-up single-use
  selection indexed once (linear), and key-lookup type separation with
  the DMARC deferral consuming only the current message's verdicts.
- **DMARC:** ancestor walk (≤8 queries, 7-label skip), nearest-record
  wins, `sp=` via normalized comparison (R4-fixed), lookup errors →
  `451`, multiple records → not-applied per §6.6.3 with loud logging,
  strict/relaxed PSL alignment, unknown-TLD fail-safe, bounce alignment
  through the HELO identity, unresolved-DKIM deferral. PSL
  `normalize`/`organizational_domain` bounded and stable (form-feed
  regression intact).
- **Recipient authority:** strict JSON schema, hot-reload with
  last-good-keeps-serving and per-change retry memoization, uniform
  `550 5.1.1`, expiry/grace (≤366 d)/catch-all semantics,
  successes-only cache cleared per transaction (R3), 5 s fail-closed
  timeout.
- **Limits:** server-wide/per-IP/rate with drop-guard release (incl.
  panic), refusal pool bounded at 32 (the reply write is bounded — but
  see F1 for what it *reads*), refused-recipient budgets per session
  (RSET-proof) and per IP, per-IP DNS permits with cancellation-safe
  drop guards and the 10 s wait → `451`, AUTH 3-per-session +
  10-per-15-min with argon2 cost capped and constant-time unknown-login
  handling.
- **Storage:** maildir commit ordering (payload fsynced, metadata rename
  last), queue-ID charset gate, ctime-based crash sweep, idempotent
  delivery per (envelope, queue-id) with the injective address tag,
  hard-link racing, `new/` fsync, sink-side path re-validation behind
  RCPT's `unsafe_local_part` gate; drain backoff, 5-day dead-letter,
  fast-path cap 64.
- **Quotas:** per-recipient `452`, declared-size reservation per copy
  (R8-fixed), real-size re-check for size liars (the Q3 hole stays
  closed), free-disk floor at MAIL *and* before spooling, unmeasurable
  `usage` → `451`.
- **Privileges/files:** root-without-`--user` refused,
  bind→read-secrets→create-owned-dirs (`O_NOFOLLOW`+`fchown` handle,
  symlink refused)→drop (setgroups/setgid/setuid + "cannot regain
  root" verification)→only then open storage/accept; `umask 077`; files
  0600 / dirs 0700 with startup warnings.
- **Auth material:** argon2id-only credentials file (plaintext is a
  startup error), never echoed, world-readable refused, SIGHUP whole-set
  swap keeping failure counts, revoked logins unable to send even on
  authenticated sessions, grants fail-closed, null sender refused.
- **TLS:** rustls defaults, no client auth, 10 s handshake cap, resolver
  CA *added* to webpki roots, IP-SAN verification for DoT.
- **DNS codec:** total bounds-checked parsing (truncation / bitflip /
  hostile-pointer / rdata-overrun / short-A regressions), EDNS0
  conformance, response validation, pre-send name validation, TTL cache
  semantics (min-TTL, RFC 2308 negative TTLs, SERVFAIL never cached,
  1 h clamp, capacity-bounded).

---

## R3.4 Regression tests added (fail until fixed)

| Test | Finding | Location |
|---|---|---|
| `refused_connections_do_not_buffer_the_peer_flood` | F1 | `mailserv/src/server/tests.rs` |
| `tracked_ips_are_bounded_under_churn` | F2 | `mailserv/src/limit.rs` |
| `unknown_config_keys_are_a_startup_error` | F3 | `mailserv/src/config.rs` |
| `tab_separated_records_are_records` | F4 | `spf/src/lib.rs` |
| `tab_separated_records_are_evaluated` | F4 | `spf/src/lib.rs` |
| `domain_is_validated_at_startup` | F5 | `mailserv/src/config.rs` |

With these: `cargo test --workspace --no-fail-fast` → **367 pass, 6
fail (by design), 1 ignored**; `cargo fmt --all -- --check` and
`cargo clippy --workspace --all-targets -- -D warnings` clean.

---

## R3.5 Recommended work order

1. **F1** before opening port 25 at all — a one-line fix that removes a
   capacity-collapse primitive.
2. **F2, F3** with it (both cheap; both bound failure modes the pilot
   runbook relies on).
3. **F4, F5** next release.
4. The informational items as maintenance.

---

## R3.6 Notes for the team

- The regression tests cite this document by the ID `AUDIT_20261126B` in
  their doc comments; that is this round (§R3).
- No source changes were made during this audit; only test additions and
  this section.
- `docs/reviews/` was restored from `HEAD` so this document exists on
  disk; it is the only file in that directory in the working tree.

---
---

# AUDIT.md — Round-4 Security Audit (2026-11-26C)

**Tree reviewed:** `HEAD 9d8fca4` ("security fixes") **plus the uncommitted
working-tree changes that apply Round 3's F1–F5 fixes** (fixed-size refusal
drain, bounded `ConnectionLimiter` table, `deny_unknown_fields` config,
LWSP-separated SPF records, `--domain` validation) **and their six
regression tests, now passing.** Nothing in this round modifies any of
that.

**Scope:** every workspace crate read end to end against the previous
rounds' findings — `smtp`, `mailserv` (`session`/`session/message`,
`server`, `config`, `limit`, `authority`, `auth`, `spool`, `delivery`,
`headers`, `address`, `verdict`, `quota`, `fsutil`, `privdrop`, `tls`,
`hashpw`), `spf`, `dkim`, `dmarc` (incl. `psl`), `mailparse`, `dns`
(codec + pipelined DoT client) — plus `DESIGN.md` / `README.md` /
`PLAN.md` / `DEPLOYMENT.md`.

**Method:** full code read; `cargo test --workspace` (374 tests: **373
passed, 1 ignored** before this round's test; `cargo fmt --check` and
`cargo clippy --workspace --all-targets -- -D warnings` clean; `cargo
audit --deny warnings` clean); the release-debug server was run locally
(MX on 3525, submission on 3587 with STARTTLS, AUTH, grants) and probed
over loopback (relay attempts, AUTH-on-MX, the refused-recipient budget,
authenticated submissions). **No source code was modified** — the
artifact is this section plus one regression test that **fails today**
and encodes the fixed behaviour. The libFuzzer targets were not re-run
(they need a nightly toolchain not present in this environment); CI runs
them for 30 s each per push.

**Status of prior rounds.** Round 1 (S1, S2, N11, M8, N19, AUTH
ownership), Round 2 (M1–M17, N8/N9, R1–R8) and Round 3 (F1–F5) are
**fixed in this tree and verified**: the Round-3 fixes are applied
exactly as prescribed (O(1) refusal drain at `REFUSE_DRAIN_BUF`;
`CONNECTION_MAX_TRACKED` hard cap with the `FailureLimiter` pattern;
`#[serde(deny_unknown_fields)]` on `FileConfig`; `matches!(txt[6], b' '
| b'\t')` in `is_spf_record`; `validate_domain` via `valid_helo` at
startup), their regression tests pass, and the Q-round header-bounds
work (`MAX_AUTHORS`, `MAX_DOMAIN_LEN`, bounded claims) is in place.
Re-reading the hot paths found **no regression in any prior fix**.

**Bottom line:** the protocol core, the DNS path, the verifier chain
(SPF → DKIM → DMARC), the authority/quota/storage pipeline and the
limiters held up under a fresh adversarial read. One finding is new
(G1) — a gap in the *authenticated-submission* grant model that Round 2
§3.1 recommended closing and that was never implemented. It matters only
if the pilot enables submission (off unless a submission port is set,
PLAN §2.3), but it lets a credential holder claim an identity no grant
covers, under this server's `auth=pass` verdict.

---

## R4.1 Findings

| ID | Sev | Where | Finding | Regression test (fails today) |
|----|-----|-------|---------|-------------------------------|
| **G1** ✅ **FIXED** (see §R7) | **Medium** (submission only) | `mailserv/src/session/message.rs` (`end_of_data`), `mailserv/src/auth.rs` (`SenderGrants`) | An authenticated login's grants are checked against `MAIL FROM` and every `From:` author — but **not** against `Sender:`, `Resent-From:` or `Resent-Sender:`. A login granted only `alice@example.org` can submit a message with `Sender: ceo@victim.example` and it is delivered carrying our `Authentication-Results: … auth=pass smtp.auth=alice`. | `session::tests::authenticated_sender_headers_must_be_granted` |

### G1 (Medium, submission only) — the grant model stops at `From:` — ✅ FIXED (see §R7)

Round 2 (§3.1) already flagged this as a regression introduced by the
grant fixes and prescribed the fix: *"Constrain `Sender:` and
`Resent-From:` (they also name a sender), but leave `Reply-To:` alone."*
It was never implemented, and no later round re-checked it.

**Verified live.** With the server running `--submission-port 3587
--auth-users-file users --auth-senders 'alice=alice@big.example'`, the
session `AUTH PLAIN` → `MAIL FROM:<alice@big.example>` (granted, accepted)
→ message `From: alice@big.example` / `Sender: ceo@victim.example` →
**`250 Ok`**, and the delivered maildir file reads:

```
Authentication-Results: mx.test;
	auth=pass smtp.auth=alice;
	dkim=none;
	dmarc=none
From: alice@big.example
Sender: ceo@victim.example
```

`Resent-From:` and `Resent-Sender:` behave the same.

**Impact.** The grant system is what makes the SPF skip and the
DMARC-rejection exemption for authenticated sessions safe (DESIGN §10:
"being authenticated never means 'may use any From'"). But `Sender:` is
an RFC 5322 assertion of *who actually sent the message*: some
auto-responders, vacation handlers, list software and phishing filters
treat it as the authoritative sender identity, and `Resent-From:` is a
second From-like identity DMARC deliberately never evaluates. A
credential holder (or a stolen credential) can therefore attach an
arbitrary ungranted identity to a message that this server has vouched
for with `auth=pass` — exactly the claim the grant check exists to
prevent on the other two fields. Scope is bounded: only the optional
submission listeners, which V1 leaves off by default.

**Fix direction.** In `end_of_data`, alongside the existing
`from_authors` grant check, extract the `Sender:`/`Resent-Sender:`
mailbox and every `Resent-From:` author from the raw header bytes (the
same scanner: `mailparse::extract_raw_headers` + `headers::mailbox_address`)
and require each to pass `auth.permits(...)` exactly as a `From:` author
does, answering `550 5.7.1` (a reply indistinguishable from the existing
grant refusal). Do **not** constrain `Reply-To:` (Round 2 §8). The
unauthenticated MX path needs no change: for unauthenticated mail the
`Sender:`/`Resent-*:` headers are sender content like any other, and the
verdict headers describe only SPF/DKIM/DMARC.

**Test:** `mailserv/src/session/tests.rs ::
authenticated_sender_headers_must_be_granted` — an authenticated,
granted session sending `Sender:`/`Resent-From:`/`Resent-Sender:` naming
an ungranted address must get `550 5.7.1` and a cleared transaction.
Fails today: the message is accepted (`250 Ok`).

---

## R4.2 Informational findings (no test; all but the last re-confirm
Round 3 §R3.2 items that remain open)

1. **`FileAuthority::current()` `expect`s on lock poisoning**
   (`authority.rs:634/639`). Every other lock in the codebase recovers
   via `PoisonError::into_inner`; a panic under this write lock (the
   reload path runs `serde_json` over operator-published files) would
   turn every RCPT into `451` until restart. Poison-recovery is a
   one-liner and matches the rest of the code.
2. **`AuthConfig::check` waits unboundedly for a check slot**
   (`auth.rs`, `self.checks.acquire().await`): with the argon2 pool
   saturated, queued AUTH attempts hold sessions and connection slots
   until the session deadline. A `try_acquire`/short timeout mapping to
   `454` would keep refusals prompt.
3. **DNS cache worst-case footprint**: the *count* is capped
   (`MAX_CACHE_ENTRIES` 4096) but not the bytes; 4096 × 64 KB DoT
   responses ≈ 256 MB is reachable with attacker-chosen names. A total
   byte budget alongside the count would close it.
4. **DNS question-echo validation is case-sensitive**
   (`dns::validate_response` compares `Label`s directly): a conformant
   resolver that lowercases the qname in the echo would have every
   response tear the connection down. Compare case-insensitively.
5. **Authority `catch-all-mailbox` is not syntax-checked at load**: an
   unsafe mailbox string fails at delivery time (`451`, the domain
   silently cannot receive) instead of loudly at publish time.
   Validating it in `into_data` would make a broken publish a reload
   error.
6. **README hygiene**: the README still ends with a stray shell line
   (`claude --resume <uuid>`) that looks accidental (first raised in
   Round 3 §R3.2.8).

---

## R4.3 What was reviewed and held up

Each of the following was traced through the code and its tests and is
correct as implemented; nothing below re-opens a prior finding.

- **Framing/smuggling:** the `<CRLF>.<CRLF>`-only terminator with the
  bare-LF `.` re-stuffing and its `after_bare_lf` tracking across
  overflow/drain boundaries; verbs-in-DATA-as-content; the `may_be_long`
  gate (only AUTH, exactly); the 64 KiB data-line abort → discard cycle;
  over-long command lines answered without state change.
- **STARTTLS:** pre-TLS state, authentication and envelope discarded; the
  read buffer (pipelined plaintext) dropped; no second banner; AUTH
  refused on MX (`502`) and on plaintext submission (`538`); RFC 3848
  tokens in `Received:`.
- **Envelope → wire:** `clean_path`/`valid_reverse_path`/`valid_helo`
  keep control characters out of `Return-Path:`/`Received:`; trace
  headers are sanitized (`is_ascii_graphic` HELO, validated `--domain`,
  generated queue IDs, `header_token`-reduced sender values).
- **Header pipeline:** one raw scanner for DKIM/From/bare-CR/strip;
  leading-continuation and verdict-named-continuation removal (R1/R7)
  including double-strip idempotence; `MAX_HEADER_FIELDS` counted before
  any parse; the Q-round bounds (`MAX_AUTHORS`, From-domain length,
  bounded claims with the filler-resistant selection and truncation
  marker).
- **SPF:** the §4.6.4 budgets (10 terms, 2 voids, mx/ptr address caps),
  redirect/include semantics, macro expansion (RFC 7489 §7 examples
  pass), the 20 s deadline → TempError, and the F4 LWSP fix. `None`
  accepted, Fail/PermError `550`, TempError `451` — fail-closed.
- **DKIM:** topmost-5 lazy selection; mandatory `From:` in `h=`;
  duplicate tags fatal; `l=` must equal the whole canonical body; `x=`
  boundary; `i=`/`d=`/`t=s` alignment; `k=`/`a=` match before crypto;
  SHA-256 only; RSA ≥ 1024 ≤ 4096; revoked keys and service-type checks;
  streamed body hashing (one pass); linear `h=` selection.
- **DMARC:** fail-closed ancestor walk (≤8 queries, temp error at any
  step → `451`); nearest-record wins; `sp=` via normalized comparison;
  multiple records → not applied (RFC 7489 §6.6.3); strict/relaxed PSL
  alignment with the unknown-TLD fail-safe; bounce alignment via the
  HELO identity; unresolved-DKIM deferral; per-message DKIM verdicts
  only (no cross-message replay).
- **Authority:** strict JSON schema with `deny_unknown_fields`; hot
  reload keeping the last good snapshot and memoizing failed change
  tokens; uniform `550 5.1.1` refusals; successes-only per-transaction
  cache; expiry/grace/catch-all semantics; 5 s fail-closed timeout.
- **Limits:** server-wide/per-IP/rate caps with drop-guard release
  (panic-safe); the F2 hard cap on tracked IPs; refusal pool bounded at
  32 with the F1 fixed-size drain; per-session and per-IP
  refused-recipient budgets (verified live: 20 refusals → `421` + close);
  DNS permits cancellation-safe; AUTH 3-per-session + 10-per-IP/15 min
  with constant-time unknown-login handling.
- **Storage/quotas:** maildir commit ordering with `new/` fsync; queue-ID
  charset gate; ctime debris sweeps; idempotent delivery per (envelope
  address, queue id) with the injective tag (the M9 fix); drain backoff,
  5-day dead-letter; per-recipient `452` with declared-size reservation
  and the real-size re-check; free-disk floor at MAIL and end-of-data.
- **Privileges/files:** bind → read secrets → create-owned-dirs
  (`O_NOFOLLOW` + `fchown`) → verified drop; umask 077; 0600/0700
  everywhere; credentials file refused if other-readable; argon2id-only.
- **Config:** CLI > file > defaults with `deny_unknown_fields` (F3) and
  the F5 `--domain` validation; listener consistency checks; removed-key
  refusal.
- **DNS:** total bounds-checked codec (hostile pointers, rdata overruns,
  short reads all `Err`); EDNS0 conformance; ID/QR/question-echo
  validation; bounded pipelined connections; TTL cache with RFC 2308
  negative TTLs, SERVFAIL never cached, wholesale clear at capacity.

---

## R4.4 Regression test added (fails until fixed)

| Test | Finding | Location |
|---|---|---|
| `authenticated_sender_headers_must_be_granted` | G1 | `mailserv/src/session/tests.rs` |

With it: `cargo test --workspace --no-fail-fast` → **373 pass, 1 fail
(by design), 1 ignored**; `cargo fmt --all -- --check` and
`cargo clippy --workspace --all-targets -- -D warnings` clean.

---

## R4.5 Recommended work order

1. **G1** before any submission listener is enabled (it is off by
   default; keep it that way until the grant check covers the
   `Sender:`-family headers). Small, well-scoped, mirrors the existing
   `From:` check.
2. The informational items as maintenance, cheapest first: the authority
   lock poison-recovery (1), the catch-all-mailbox validation (5), the
   README line (6).

---

## R4.6 Notes for the team

- The regression test cites this document by the ID `AUDIT_20261126C`;
  that is this round (§R4).
- No source changes were made during this audit; only the test above and
  this section.
- This round deliberately re-verified every prior round's fix rather
  than assuming it: all hold. The tree's remaining pre-GA work is
  DEPLOYMENT.md's checklist (Phases A–H), the PSL refresh cadence
  (H7), and the open §13 gaps, all accurately documented.

---

# AUDIT.md — Round-5 Security Audit (2026-11-26D, pre-GA verification)

**Tree reviewed:** `HEAD a6893aa` ("AUDIT"), working tree clean before this
round. Only test code and this document were changed (no `src` behaviour was
touched).

**Method.** A fresh full read of the trust boundaries, then verification
against the *current build* rather than a remembered one:

- `cargo test --workspace` → **293 passed, 1 failed, 1 ignored** (the failure
  is `session::tests::authenticated_sender_headers_must_be_granted`, the
  Round-4 G1 regression test, red by design).
- `cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-targets -- -D warnings` → clean.
- `cargo build -p mailserv`, then ran the **real binary** with a real config
  (`port = 2525`, `submission-port = 2587`, `submissions-port = 2465`,
  argon2id credentials from `mailserv hash-password`, an authority file, a
  spool dir and a maildir root) and drove it over TCP/TLS, reading the
  delivered `.eml` files back off disk.

> **Methodology warning for the next reader.** A server left running from an
> earlier round answered the first probes and produced results that were
> *wrong for this tree* (plaintext AUTH "accepted", a 5000-header message
> "accepted with a truncation marker"). Every live claim below was re-run
> against a binary built from `a6893aa`. Confirm the pid and build time
> before trusting any probe output.

**Bottom line.** G1 is real, reachable end-to-end, and still unfixed; it and
the red `cargo test` it produces are the only go-live blockers found in this
round. Everything else here is Low or informational. The gates that matter —
AUTH/TLS gating, sender grants, closed relay, verdict-header stripping,
header/author/claim bounds, the DNS budgets and fail-closed DMARC/SPF
verdicts, per-IP and per-session limits, credential hot-revocation, spool
permissions — all held up under fresh probing.

## R5.1 Findings

| ID | Sev | Where | Finding | Test |
|----|-----|-------|---------|------|
| **G1** ✅ **FIXED** (see §R7) | **Medium** (submission only) | `session.rs:959-971` (envelope), `session/message.rs:166-183` (`From:` authors) — `SenderGrants::permits` has no other caller | Confirmed real and unfixed: the grant model stops at `MAIL FROM` and the `From:` authors. `Sender:`, `Resent-From:` and `Resent-Sender:` are not read anywhere in `mailserv/src` (outside tests), so an ungranted identity rides through unmodified. | `server::tests::ungranted_sender_headers_reach_the_maildir_under_auth_pass` (passes today; must flip to a refusal when fixed) |
| **A1** | Low | `delivery.rs:465` (`with_trace_headers`), `headers.rs:334` (`strip_forged_verdicts`) | A delivered message carries **two** `Return-Path:` fields: ours on top, the sender's own below. `strip_forged_verdicts` removes only `Authentication-Results:` naming our authserv-id and every `X-Display-Name-Warning:`, and `with_trace_headers` then prepends its own — so the second, sender-chosen one survives into the maildir. RFC 5322 §3.6.3 makes the program that adds `Return-Path:` remove the existing ones first. | `server::tests::a_sender_return_path_survives_alongside_ours` |
| **A2** | Info | `headers.rs:417-426` (`is_forged_verdict`) | The strip is exact-on-authserv-id by design, so a forgery that *almost* names us survives verbatim: `Authentication-Results: "mail.example.org"; auth=pass smtp.auth=root` (quoted-string id) is delivered untouched. RFC 8601 §5 makes a verifier ignore it, and our own header is the topmost one, so this is defense in depth rather than exposure. | `server::tests::foreign_and_quoted_authserv_ids_are_not_stripped` |
| **A3** | Info | `headers.rs` (`display_name_claims`) | Claims are read from RFC 5322 **comments** too: `From: <alice@example.org> (paypal.com ceo@paypal.com)` produces an `X-Display-Name-Warning:` naming `paypal.com`, although no MUA displays a comment. Conservative direction (false positive, never a miss), but it is a disclosure-header vector for a name nobody sees; worth a sentence in DEPLOYMENT.md's log-noise expectations. | covered by the live probe below |
| **A4** | Info | `docs/reviews/AUDIT.md` R4.2 | All six Round-4 informational items are still open in the tree: `.expect("authority lock poisoned")` at `authority.rs:634/639`, the unbounded `self.checks.acquire().await` at `auth.rs:433`, the DNS cache capped by count (4096) not bytes (`dns/src/lib.rs:322,379`), and the stray `claude --resume …` line still at the end of `README.md`. | — |

### G1 — verified live, end to end

Submission listener, `auth-senders = "alice=alice@example.org|@alice.example"`,
`AUTH PLAIN` as `alice`, envelope `MAIL FROM:<alice@example.org>` (`250`),
`RCPT TO:<big@big.example>` (`250`), then:

```
From: alice@example.org
Sender: ceo@victim.example
Resent-From: finance@victim.example
```

`DATA` answered `250 Ok`; the message was spooled and delivered. The copy in
`mail/big.example/big/new/…eml`:

```
Authentication-Results: mx.example.org;
	auth=pass smtp.auth=alice;
	dkim=none;
	dmarc=fail header.from=example.org
From: alice@example.org
Sender: ceo@victim.example
Resent-From: finance@victim.example
```

So this server stamps its own `auth=pass smtp.auth=alice` on a message whose
declared sender is an address no grant covers. Two aggravating details the
Round-4 text did not:

1. **`dmarc=fail` is recorded and still sent.** The authenticated exemption
   turns the failure into a delivery, so the outbound copy advertises a
   DMARC failure of our own hosted domain *together with* `auth=pass`. A
   receiving system that weighs `auth=`/`Authres` over `dmarc=` (some MUAs'
   "verified sender" badges do) reads the wrong one of the two.
2. **`Sender:` outranks `From:` for a lot of downstream automation** —
   bounce/autoreply addressing and some "sender" columns — so the claimed
   identity is not merely cosmetic.

The fix stays exactly as Round 4 prescribed: apply the existing
`authors`-vs-grants check to `Sender:` and `Resent-Sender:` (single-address
headers, same `auth::split_address`), and treat a `Resent-From:` whose
domain is not granted as a `display_name_claims`-style disclosure or a
refusal. `Reply-To:` stays free. Small, and local to `end_of_data`.

### A1 — why it is Low, not Medium

The pilot has no outbound path (DEPLOYMENT.md §1: "No outbound mail"), so the
duplicate field lands only in the local maildir, and the harm requires a
downstream forward/auto-responder on the *reading* side that takes the last
`Return-Path:` rather than the first. One `strip` addition in
`strip_forged_verdicts` (`header.name_eq("return-path")`) closes it; then the
characterization test above must be updated to assert exactly one
`Return-Path:` naming the envelope sender.

## R5.2 Re-verified live (nothing here re-opens a prior finding)

Each row was checked against the running binary, not only by reading.

| Gate | Probe | Result |
|---|---|---|
| AUTH never on the MX port | `EHLO` on 2525, then `AUTH PLAIN <creds>` | not advertised; `502 5.5.1 Authentication not supported` |
| AUTH needs TLS on submission | plaintext `EHLO`/`AUTH` on 2587 | not advertised; `538 5.7.11 Encryption required…`; `MAIL FROM` → `530 5.7.0 Authentication required` |
| Grants bind the envelope | authenticated `MAIL FROM:<ceo@victim.example>` | `553 5.7.1 Sender address not owned by authenticated user` |
| Grants bind the `From:` authors | `From: CEO <ceo@victim.example>` under a granted envelope | `550 5.7.1 From address not owned by authenticated user` (unit-level; the header-only variants above are what G1 misses) |
| Relay closed for everyone | unauthenticated `RCPT TO:<someone@foreign.example>` | `550 5.7.1 Relay access denied` |
| AUTH attempt budgets | 4 bad passwords in one session | 3× `535 5.7.8`, then `454 4.7.0 Too many failed authentication attempts` |
| Credential hot-revocation | rewrite `users`, `kill -HUP` | log `credentials reloaded`; the removed login now gets `535`, the added one `235`; grants left for a removed login are reported inert (and are a startup error), as documented |
| Header-field bound | 5000 header fields | `552 5.3.4 Message header has too many fields` — refused before any DNS work (`MAX_HEADER_FIELDS = 1000`) |
| Claim-list bound | 12 display-name claims in `From:` authors | first 10 listed plus `(truncated: 10 of the 12 addresses at other domains shown)` (`MAX_CLAIMS = 10`) |
| Verdict-header strip | lowercase, mixed-case, trailing-dot authserv-id, folded continuation, forged `X-Display-Name-Warning:` | all removed; only our own `Authentication-Results:` remains; foreign-authserv-id records kept (correct per RFC 8601) |
| Trace headers | delivered copy | `Received:` with `ESMTP`/`ESMTPSA` per RFC 3848, queue id, no CR/LF injection through HELO |
| Spool permissions | `ls -l spool` | `drwx------` for both `new/` and `tmp/`; startup warns when a storage dir is group/world-accessible |

## R5.3 Tests added

All in test files; no source behaviour changed.

| Test | Kind | Pins |
|---|---|---|
| `server::tests::ungranted_sender_headers_reach_the_maildir_under_auth_pass` | characterization (passes today) | G1 reachable through the real submission listener: TLS, AUTH, spool, maildir |
| `server::tests::a_sender_return_path_survives_alongside_ours` | characterization (passes today) | A1 duplicate `Return-Path:` in the delivered copy |
| `server::tests::foreign_and_quoted_authserv_ids_are_not_stripped` | characterization (passes today) | A2 the strip is exact-on-authserv-id |

Each carries a doc comment saying what must change when the underlying
behaviour is fixed, so a fix that forgets the test is still a loud failure.

## R5.4 Go / no-go

**Not yet go-live, for two reasons, both small:**

1. **G1** — fix the grant check before enabling a submission listener. It is
   off by default (no `submission-port`/`submissions-port` without a
   credentials file, `config.rs:554-568`), so the pilot can start **MTA-only**
   today with this risk closed by configuration.
2. **The test suite is red.** `.github/workflows/ci.yml` runs plain
   `cargo test --workspace`, which fails on the G1 test. Either land the G1
   fix (then the suite is green and the new tests must be updated as noted
   above) or, if the fix is to wait, mark that test
   `#[ignore = "AUDIT_20261126C G1: unfixed; submission ports stay off until it lands"]`
   so CI means "green" again and the gap stays named. Leaving a red test with
   no CI marker is the worst of the three: the gate stops being trusted.

Everything else found in this round is Low/informational and appropriate for
the maintenance list alongside Round 4's §R4.2.

---

# AUDIT.md — Round-6 Security Audit (2026-11-26E, pre-GA re-verification)

**Tree reviewed:** `HEAD a6893aa` ("AUDIT") plus the Round-5 test
additions. No `src` behaviour was touched; only tests and this document.

**Method.** Re-read PLAN.md, DESIGN.md and README.md end to end, then
verified the claims against a freshly built binary rather than a memory of
one:

- `cargo test --workspace` → **294 passed, 1 failed, 1 ignored** (the
  failure is G1's `session::tests::authenticated_sender_headers_must_be_granted`,
  red by design);
- `cargo fmt --all -- --check` clean; `cargo clippy --workspace
  --all-targets -- -D warnings` clean;
- all six libFuzzer targets (`headers`, `dkim_tags`, `spf_record`,
  `dmarc_record`, `dns_message`, `smtp_session`) built against this tree
  with ASan + debug assertions and run for 60–120 s each: **no crash, no
  hang, no leak** (≈4.0 M executions total). The DNS codec, SMTP framing,
  header scanner, DKIM/SPF/DMARC parsers held;
- the real binary driven over TCP and TLS with a `submission-port`, an
  argon2id credentials file and `auth-senders = "alice=alice@example.org"`,
  reading the delivered `.eml` back off disk.

**Bottom line.** One Medium finding is open (G1, Round 4) and it is the
only reason the suite is red. Nothing new of Medium or above was found this
round: every trust boundary that Round 5 exercised by hand also held under
ASan fuzzing, and every security-relevant claim in PLAN.md, DESIGN.md and
README.md that was tested matched the code. Three Low/informational items
are added below. The go/no-go is unchanged from Round 5: **do not enable a
submission listener, and do not ship, until G1 is fixed and the suite is
green.**

## R6.1 Findings

| ID | Sev | Where | Finding | Test |
|----|-----|-------|---------|------|
| **G1** ✅ **FIXED** (see §R7) | **Medium** (submission only) | `session.rs:959-971` (envelope), `session/message.rs:166-183` (`From:` authors) | Re-confirmed real and unfixed. The grant check still stops at `MAIL FROM` and the `From:` authors; `Sender:`, `Resent-From:` and `Resent-Sender:` are never checked. Live: a login granted only `alice@example.org` submitted a message carrying all three ungranted identities, delivered with `auth=pass smtp.auth=alice` and `dmarc=fail header.from=example.org`. | `session::tests::authenticated_sender_headers_must_be_granted` (red) |
| **W1** | Low | `server.rs:253` | The accept-everything static fallback (no `--authority`) is logged at **INFO**, not WARN, even on the MX port. The F3 fix made a typo'd `authority` key a startup error, but the two ways to end up with the fallback — forgetting the flag, or a tool that drops it — produce only an `"level":30` line among the startup log. Verified live: a server with no authority logs `"no authority file; static per-address fallback (any local-part accepts)"` at level 30. On an internet-facing MX that is the difference between a closed server and an open relay-of-last-resort; it warrants WARN. | — (log-level observation) |
| **W2** | Info | `fsutil.rs:57` (`create_private_file`) | Staging files are created with `O_CREAT|O_TRUNC` and **no `O_NOFOLLOW`**, so a pre-existing symlink at the target is followed and its target truncated. Not remotely reachable: spool names embed `new_queue_id()`'s UUID and maildir staging names embed a v4 UUID, and both trees are `0700`, so only a process already running as the service user can plant the link. The privilege-drop path is protected (`create_owned_dir_all` uses `O_DIRECTORY|O_NOFOLLOW`); this is the one file-creation site that is not. Defense-in-depth only. | — |
| **W3** | Info | `README.md`, `PLAN.md`, `.github/workflows/ci.yml` | Documentation and CI drift. README and PLAN say "347 tests"; the tree has 296 (294 pass). More important: CI runs plain `cargo test --workspace`, which is red on `HEAD`, so the required checks cannot pass. Round 5 already flagged the red gate; this records that the stated count is also wrong. | — |

### G1 — fresh live reproduction (this round)

Config: `submission-port = 2587`, `auth-users-file` with `alice`,
`auth-senders = "alice=alice@example.org"`, `local-domains = "small.example"`.
STARTTLS → `AUTH PLAIN` → `235`, `MAIL FROM:<alice@example.org>` → `250`,
`RCPT TO:<a@small.example>` → `250`, then:

```
From: alice@example.org
Sender: ceo@victim.example
Resent-From: finance@victim.example
Resent-Sender: cfo@victim.example
Reply-To: free@anywhere.example
```

`DATA` → `250 Ok`; the delivered copy:

```
Authentication-Results: mx.example.org;
	auth=pass smtp.auth=alice;
	dkim=none;
	dmarc=fail header.from=example.org
From: alice@example.org
Sender: ceo@victim.example
Resent-From: finance@victim.example
Resent-Sender: cfo@victim.example
Reply-To: free@anywhere.example
```

`Reply-To:` remaining free is correct and is pinned by the new guard test
below; the three sender-naming headers are the finding. The fix remains the
Round-4 prescription: run the existing `auth.permits` check over `Sender:`
and `Resent-Sender:` (single addr-specs, same `split_address`) and over a
`Resent-From:` whose domain is not granted.

## R6.2 What held under ASan fuzzing and live probing

| Area | Evidence |
|---|---|
| SMTP framing / smuggling | `smtp_session` fuzzer 120 s / 312 k execs, no crash or hang; the `<CRLF>.<CRLF>`-only terminator, bare-LF `.` re-stuffing and Discard cycle are covered by unit tests that pass |
| Header scanner | `headers` fuzzer 60 s / 184 k execs; the shared `extract_raw_headers`/`find_separator` path is the only one the server uses |
| DKIM / SPF / DMARC parsers | 60 s each (541 k / 918 k / 1.54 M execs), no crash |
| DNS codec | 60 s / 454 k execs, no crash (hostile pointers, rdata overruns, short reads) |
| Envelope strictness | `valid_reverse_path` runs on **every** non-null `MAIL FROM` *before* the authenticated branch, so the MSA path is not looser than the MX path (`<<a@b>`, `a b@b`, address literals all `501`) |
| STARTTLS state reset | `tls_established` clears `helo`, `spf_helo`, `authenticated`, `auth_pending`, `auth_login_user` and the envelope |
| AUTH gating | MX port `502`; plaintext submission `538`; unauthenticated `MAIL FROM` `530`; re-AUTH `503`; 3/session then `454` — all in tests and re-checked against the live binary in Round 5 |

## R6.3 Test added

| Test | Kind | Pins |
|---|---|---|
| `session::tests::authenticated_granted_sender_headers_and_reply_to_stay_allowed` | guard (passes today and after a correct fix) | A granted address in `Sender:`/`Resent-Sender:`/`Resent-From:` stays accepted, and `Reply-To:` stays free, so a G1 fix that over-blocks fails loudly instead of passing the refusal-only test |

The existing refusal test already covers `Sender:`, `Resent-From:` **and**
`Resent-Sender:` (Round 5 did not need to extend it).

## R6.4 Go / no-go

Unchanged: **not go-live.**

1. **Fix G1** before enabling `submission-port`/`submissions-port`. The
   pilot can run **MTA-only** today (the ports are off unless configured),
   which closes the finding by configuration.
2. **Make CI mean something.** Right now `cargo test --workspace` fails on
   `HEAD`; either land the G1 fix (and the new guard test keeps the fix
   honest) or mark the red test
   `#[ignore = "AUDIT_20261126C G1: unfixed; submission ports stay off"]`
   so the gate is green and the gap stays named.
3. **W1** at go-live: promote the static-fallback log to WARN (or refuse to
   start on a privileged port without `--authority`). It is the cheapest
   single change that reduces the worst misconfiguration on the real MX
   port.

W2 and W3 are maintenance. Everything else in Round 5 §R5.2 and Round 4
§R4.2 still stands.

---

# R7 — Fix status (2026-11-26)

| ID | Status | Fix |
|----|--------|-----|
| **G1** | ✅ **FIXED** | `headers::sender_identities` reads every `Sender:`, `Resent-Sender:` and `Resent-From:` mailbox with the same raw scanner and mailbox parser as the `From:` authors; `end_of_data` (`session/message.rs`, right after the `From:` author check) requires each to pass `auth.permits(...)` for authenticated sessions and answers `550 5.7.1 From address not owned by authenticated user` otherwise. A field that cannot be parsed fails closed. `Reply-To:` stays free; the unauthenticated MX path is unchanged. |

**Test changes made with the fix:**

- `session::tests::authenticated_sender_headers_must_be_granted` — **test bug
  fixed.** Its fourth case, `Sender: anyone@alice.example`, names an address
  the test login *is* granted (`@alice.example`), so it contradicted both the
  grant model (`authenticated_mail_from_must_be_granted` accepts
  `anything@alice.example`) and the Round-6 guard test (which requires
  `Sender: someone@alice.example` to be accepted). It now uses the ungranted
  near-miss `anyone@sub.alice.example` (subdomains are not granted, as the
  envelope test already pins). Passes.
- `session::tests::authenticated_granted_sender_headers_and_reply_to_stay_allowed`
  — unchanged; passes (the fix does not over-block).
- `server::tests::ungranted_sender_headers_reach_the_maildir_under_auth_pass`
  → renamed `ungranted_sender_headers_are_refused_under_auth` and flipped as
  its doc comment prescribed: DATA now gets `550 5.7.1`, and nothing is
  spooled or delivered.

`cargo test --workspace` is green; `cargo fmt --all -- --check` and
`cargo clippy --workspace --all-targets -- -D warnings` are clean. No High or
Medium finding remains open; the Low/informational items (A1–A4, W1–W3,
R4.2) are unchanged.

---

# AUDIT.md — Round-8 Production-Readiness Review (2026-11-26)

**Question asked:** is this ready to go live on the public internet as a
production MX: real traffic, real customers, real consequences if it fails
or is abused? **Not** the friendly-domains pilot that DEPLOYMENT.md §1 and
Rounds 4–6 judged against.

**Tree reviewed:** `HEAD a6893aa` plus the uncommitted G1 fix (§R7).
**Method:** re-read Rounds 1–7, DEPLOYMENT.md, PLAN.md and DESIGN.md §13,
and checked every open item named below against the current source. No
source code was changed in this round; only this section was added.
`cargo test --workspace`, `cargo fmt --check` and `clippy -D warnings` are
green on the working tree. **Not done in this round:** a live run of the
binary, the fuzzers, or any part of the DEPLOYMENT.md checklist.

## R8.1 Verdict

**No-go for production today.** The code's security core is in good shape:
no High or Medium code finding is open. But the project's own readiness
record (DEPLOYMENT.md §1) rates it *"Not ready for general production. Ready
for a limited pilot"*, and several of the limitations it accepts for a pilot
rely on a few friendly domains, low volume, and an operator reading the logs
every day. Real internet traffic removes all three, so those limitations
become blockers. The production blockers are P1–P8; P9–P14 must be decided
or fixed before GA or soon after.

## R8.2 Production blockers (must be closed before port 25 takes real traffic)

| ID | Sev (prod) | Area | Finding | Required action |
|----|-----------|------|---------|-----------------|
| **P1** | **High** | Release process | The G1 fix (§R7) is uncommitted, so no recorded commit exists with a green suite. DEPLOYMENT.md A1/A3 require the release to be built from a recorded commit with CI green. | Commit G1, confirm `.github/workflows/ci.yml` is green on that commit, and build and hash the release binary from it (A1–A3). |
| **P2** | **High** | Operations | Every row of the DEPLOYMENT.md §4 sign-off table is empty: host sizing (B), config review (C), DNS/TLS (D), the hardened systemd unit (E), external smoke tests (F), alerting (G), and a tested backup restore (H). | Complete Phases A–H and fill in §4 with owner, date and evidence. A production go also needs on-call coverage, which the pilot's "operator watching the logs" does not provide. |
| **P3** | **High** | Assurance | No independent security review has been done (PLAN.md §1, §2.4.6). All six audit rounds were internal. This is a new SMTP stack, DNS-over-TLS client and SPF/DKIM/DMARC implementation, parsing hostile input from the whole internet. | Commission an external review (code plus a black-box test of the deployed host) before GA, and track its findings here. |
| **P4** | **High** | Misconfiguration → open accept-all | **W1 still open** (`mailserv/src/server.rs:253`). Without an `authority` file the server falls back to accepting every local-part at hosted domains, and logs this only at INFO. One missing flag turns the production MX into an accept-everything sink: backscatter, spam storage and disk exhaustion. | On the SMTP (port 25) listener, refuse to start without `--authority`, or at minimum log at WARN or ERROR and alert on it. Startup refusal is preferred for production. |
| **P5** | **High** | Availability | A single host is the only MX. Final storage is local maildir only, which blocks multiple MX hosts (DESIGN.md §13; PLAN §5 "designed, not started"). A host or disk failure means mail is deferred by senders, then bounced after their retry window (typically 4–5 days); a lost disk loses everything not yet backed up. | Decide and document the availability target (RTO/RPO). At minimum: a tested restore (H1), host monitoring with paging, and a recovery runbook proven within the senders' retry window. A secondary MX is only safe if it applies the same authority and spam policy. A naive backup MX is a classic way around policy, so don't add one casually. |
| **P6** | **Medium** | Abuse: disk / quota | Quotas are soft (one message over), don't count queued mail, and there is no per-domain total (PLAN §2.4.1). With open-internet senders, many mailboxes together can fill the disk until the free-disk floor defers **all** mail for **all** customers. | Implement per-domain totals and count queued mail (§2.4.1), or put each customer domain on its own size-limited filesystem. Alert well above the free-disk floor. |
| **P7** | **Medium** | Legitimate mail lost | Some legitimate mail receives a **permanent** `550`, for example from a domain with a malformed SPF record (PermError, as RFC 7208 requires). The pilot contains this with a daily human review of rejections (G2); at production volume that review doesn't scale, and senders see the bounce as a failure of our service. | Decide the policy for PermError and other permanent refusals (refuse, or tag and deliver), make it configurable, and add metrics and alerts on the rate of permanent rejections, broken down by reason. |
| **P8** | **Medium** | IPv6 / limits | SPF `a`/`mx` don't query AAAA, and per-IP limits aren't grouped by IPv6 /64 (PLAN §6). The deployment is therefore IPv4-only (B4). Publishing an AAAA record for the MX would both fail SPF for legitimate IPv6 senders and let one /64 escape every per-IP limit. | Keep the MX IPv4-only, with **no AAAA record for the MX host**, and have this verified by a smoke test, until §6 IPv6 readiness lands. |

## R8.3 Fix before GA or shortly after (each with a production rationale)

| ID | Sev (prod) | Source | Finding (verified in current source) | Action |
|----|-----------|--------|--------------------------------------|--------|
| **P9** | Medium | R4.2 #2 | `AuthConfig::check` waits without a bound for an argon2 slot (`mailserv/src/auth.rs:433`). Only matters if submission is enabled; then a burst of AUTH attempts holds sessions and connection slots until the session deadline. | `try_acquire` or a short timeout mapped to `454`, before submission is ever enabled in production. |
| **P10** | Medium | R4.2 #3 | DNS cache bounded by count (`MAX_CACHE_ENTRIES = 4096`, `dns/src/lib.rs:322`), not by bytes. Up to ~256 MB is reachable with attacker-chosen names, which matters against a `MemoryMax`-limited unit (E1). | Add a total byte budget next to the count, or include 256 MB of headroom explicitly in B2 sizing. |
| **P11** | Medium | R4.2 #1 | `FileAuthority` uses `.expect("authority lock poisoned")` (`mailserv/src/authority.rs:634,639`). A panic under the write lock turns every RCPT into `451` until restart: an outage for every domain. | Recover with `PoisonError::into_inner`, as every other lock in the code does. |
| **P12** | Low | R4.2 #4 | DNS question-echo validation compares labels case-sensitively (`dns/src/lib.rs:143`). A conformant resolver that changes the case of the echoed name (for example 0x20 randomization upstream) would tear down every DoT connection, and with lookups failing, mail would be deferred. | Compare names case-insensitively. Also confirm the chosen resolver's behaviour during Phase F. |
| **P13** | Low | DEPLOYMENT §2 | No TLS certificate reload; renewal needs a restart. In production every renewal is a brief outage, and a missed restart is an expired certificate. | Reload on SIGHUP. Until then, the D3 renewal hook must restart the service and verify the new certificate. Monitor certificate expiry. |
| **P14** | Low | A1, W2, R4.2 #5 | A sender-supplied duplicate `Return-Path:` survives delivery (`headers.rs` strips only verdict headers). Staging files are created without `O_NOFOLLOW` (`fsutil.rs:50`). `catch-all-mailbox` is not validated when the authority file loads. | All are small. Close them in the first maintenance release. |

Housekeeping (no production risk, but it erodes trust in the docs): README
and PLAN.md still say "347 tests" (W3), and `README.md` still ends with the
stray `claude --resume …` line (A4 / R4.2 #6).

## R8.4 Operational requirements a production MX needs that the pilot didn't

These are not code findings, but a production go/no-go should not be signed
without them:

1. **Monitoring and paging** for: process down, port 25 unreachable from an
   external vantage point, queue depth and age, dead-letter count,
   free-disk floor approach, DNS/DoT error rate, the rate of `451`s
   (DNS trouble defers everything), permanent-rejection rate (P7) and
   certificate expiry.
2. **Capacity limits sized for hostile load**, not pilot load:
   `max-connections`, per-IP connection, connection-rate and DNS limits,
   `max-data-bytes` against memory (peak ≈ 2–3× per session, DEPLOYMENT
   §2) and the `MemoryMax` of the systemd unit (E1).
3. **Upstream DNS dependency:** DMARC and SPF fail closed, so a resolver
   outage defers all inbound mail. Have more than one DoT resolver, or a
   documented failover.
4. **PSL refresh cadence (H7)** scheduled and owned, not ad hoc.
5. **Incident runbooks** for: disk full, resolver outage, mail backlog,
   certificate expiry, a compromised credential (if submission is ever
   enabled), and a restore from backup.
6. **Submission stays off** in production until P9 is fixed and a separate
   review of the AUTH path signs it off. G1 is fixed, but that review is
   still the gate.

## R8.5 Go / no-go

**No-go** until P1–P8 are closed and recorded in DEPLOYMENT.md §4, and the
R8.4 operational requirements are in place. P9–P14 should be scheduled
with owners before GA. The code-level work (P1, P4, P9–P14) is small; the
long poles are P2 (the full checklist), P3 (an external review) and P5
(an availability decision).
