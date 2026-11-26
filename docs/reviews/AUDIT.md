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
| **G1** | **Medium** (submission only) | `mailserv/src/session/message.rs` (`end_of_data`), `mailserv/src/auth.rs` (`SenderGrants`) | An authenticated login's grants are checked against `MAIL FROM` and every `From:` author — but **not** against `Sender:`, `Resent-From:` or `Resent-Sender:`. A login granted only `alice@example.org` can submit a message with `Sender: ceo@victim.example` and it is delivered carrying our `Authentication-Results: … auth=pass smtp.auth=alice`. | `session::tests::authenticated_sender_headers_must_be_granted` |

### G1 (Medium, submission only) — the grant model stops at `From:`

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
