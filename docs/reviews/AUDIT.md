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
