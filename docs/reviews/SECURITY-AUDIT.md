# SECURITY-AUDIT.md: Independent Security Audit (V1, receive-only)

**Date:** 2026-11-22
**Tree:** `HEAD 640b60e` plus the uncommitted working tree (S1/S2/M8/N19/N11
fixes, `mailserv/src/auth.rs`).
**Scope:** every production code path in `smtp`, `mailserv`, `spf`, `dmarc`,
`dkim`, `mailparse`, `dns`. Tests and the CLI tools were out of scope.
**V1 assumptions:** receive-only MX; `--auth-users` unset; quarantine is
out of scope, so a DMARC `p=quarantine` result is treated as deliver.
**Method:** I read the code, then confirmed every finding marked
**Confirmed** with a throwaway test against the real crate code. All
probes were removed afterwards, so no source was changed by this audit.
Baseline: `cargo test --workspace` gives 249 passed, 0 failed, 1 ignored.

AUDIT.md was not used as an input.

---

## 1. Summary

V1's purpose is to keep spoofed mail out of hosted mailboxes, and that is
where the serious problems are. Four independent issues let a forged
`From:` pass a domain's published policy. Each is cheap to fix:

| # | Sev | Finding | Status |
|---|---|---|---|
| **F1** | **High** | DMARC fails **open** on any lookup error (SERVFAIL, timeout, duplicate records) | Code-confirmed |
| **F2** | **High** | DMARC org-domain fallback uses the last two labels, so a spoof from `anything.victim.co.uk` finds no policy | Code-confirmed |
| **F3** | **High** | A bare CR in the header block hides a second `From:` from the DMARC scanner | **Confirmed** |
| **F4** | **Medium** | The SPF parser turns hard-fail records into `Neutral`/`None` (`-ALL`, unknown terms, `mx/24`, `V=SPF1`) | **Confirmed** |
| **F5** | **Medium** | The DKIM verifier accepts RSA keys < 1024 bits, honours `l=`, and doesn't require `From` in `h=` | **Confirmed** (all three) |

> **Remediation (2026-11-22): F1–F5 fixed.** `cargo test --workspace`
> gives 258 passed, 0 failed, 1 ignored; clippy and fmt are clean.
>
> | # | Fix | Regression tests |
> |---|---|---|
> | F1 | Any DMARC lookup error now gives `451 4.4.3`. `MultipleRecords` means "DMARC not applied" (RFC 7489 §6.6.3) and is logged at `warn`. | `dmarc_lookup_failure_defers_instead_of_delivering` (mock DoT returning SERVFAIL); `discovery_tests::dns_failure_is_temp_not_no_policy` |
> | F2 | `dmarc::fetch_policy` is now a bounded tree walk: the From domain, then each ancestor down to 2 labels, with at most 8 queries. It returns `FoundPolicy { record, domain }`, so `sp=` governs inherited policies (M4). | `discovery_tests::*`. **Live:** a spoof from `payroll.nonexistent.bbc.co.uk` now gets `550 5.7.1`. |
> | F3 | `550 5.6.0` for any CR not followed by LF in the header block, checked before any DNS work. | `bare_cr_tests::*`. **Live:** the audit's exact payload gets `550 5.6.0`. |
> | F4 | The logos lexer is replaced by a term-based parser (RFC 7208 §4.6.1). Names are case-insensitive; any unknown or malformed term is PermError; `a`/`mx` take a dual CIDR; a duplicate `redirect=` or `exp=` is PermError; record detection is case-insensitive and excludes `v=spf10`. | `f4_tests::hard_fail_records_are_not_weakened` (the probe table above, plus edge cases) |
> | F5 | RSA keys must be at least `MIN_RSA_BITS` (1024). A signature whose `l=` doesn't equal the canonical body length never verifies (`PartialBody`). `h=` must include `From`. | `f5_tests::*`: each gap is reproduced with a genuinely signed message |
>
> **F7 fixed (2026-11-22):** failed deliveries are retried with exponential
> backoff (1 min doubling to 1 h) for `MAX_QUEUE_LIFETIME` (5 days) from the
> first failure, then dead-lettered at `error`. The `.attempts` sidecar
> records `count first_failure last_failure`, and the old count-only format
> still loads. Messages that aren't due are skipped without reading their
> payload, which also fixes the drain half of F8 (M13), since longer
> retention would otherwise mean the whole backlog in memory every pass.
> Tests: `long_outage_is_retried_with_backoff_then_delivered` (a day of
> failure, then delivery), `dead_letters_only_after_the_queue_lifetime`
> (including the DEPLOYMENT.md H2 requeue), `retry_schedule_backs_off_to_the_cap`,
> `attempt_record_formats`. Suite: 261 passed.
>
> Still open from these findings: PSL-based relaxed alignment (a false
> negative, not a spoofing vector), duplicate DKIM tags, `k=`/`a=`
> consistency, and AAAA lookups for `a`/`mx`. F6, F8 (storage quotas),
> F9, F10 and the L-tier are unchanged.

Below those are availability and integrity issues: accepted mail can be
duplicated, or silently dead-lettered after about 5 minutes. There is no
storage bound. Recipients can be enumerated without limit. There are also
AUTH weaknesses, which only matter if AUTH is ever turned on.

---

## 2. Findings

### F1 (High): DMARC fails open on DNS errors

`mailserv/src/main.rs:1795-1798`:

```rust
Ok(Err(e)) => {
    info!(from_domain = %from_domain, error = %e, "dmarc lookup failed");
    None            // treated as "domain publishes no DMARC policy"
}
```

`dmarc::fetch_policy` returns `Err` in three situations, and each one
delivers a spoof of a `p=reject` domain:

- **`Temp`:** the resolver returned SERVFAIL/REFUSED (`spf/src/lib.rs:217`),
  or a query failed or timed out. An attacker can cause this. The resolver
  is shared (2 connections × 64 queries in flight). Load from many source
  IPs, each within its `--max-dns-per-ip` share, makes victim lookups wait
  and time out, and the spoofs that arrive during that window are delivered.
  The victim's own DNS having an outage does the same.
- **`MultipleRecords`:** the domain publishes two DMARC records.
- The inner 5 s per-query timeout fires before the outer 20 s
  end-of-data deadline. Only the outer deadline is handled as `451`.

Only reaching the outer deadline (`Err(_)`, line ~1789) is handled
correctly as a temporary failure.

**Fix:** on `DmarcError::Temp`, answer `451 4.4.3` (RFC 7489 §6.6.3 lets a
receiver defer when it can't get the policy). A `MultipleRecords` result
means "no policy" under RFC 7489 §6.6.3, but log it at `warn`. Add a test
in which a SERVFAIL for the policy produces a tempfail and is never
delivered.

### F2 (High): org-domain fallback is "last two labels"

`dmarc/src/lib.rs:248`: when `_dmarc.<from-domain>` has no record, the
fallback queries `_dmarc.<last two labels>`. For `From: x@anything.victim.co.uk`:

1. `_dmarc.anything.victim.co.uk` returns NXDOMAIN;
2. the fallback queries `_dmarc.co.uk`, **not** `_dmarc.victim.co.uk`. It
   finds nothing, so there is no policy and the message is delivered.

An attacker can therefore spoof **any non-existent subdomain** of every
domain registered under a multi-label public suffix (`co.uk`, `com.au`,
`co.jp`, `com.br`, …), whatever the victim publishes. No preconditions
are needed.

**Fix:** derive the organisational domain from the Public Suffix List
(RFC 7489 §3.2). Vendor a PSL snapshot rather than fetching it at runtime,
and record its date. Until the PSL lands, it is safer to walk the
from-domain's ancestors toward the root, querying `_dmarc.` at each
ancestor below the TLD and stopping at the first record. That costs at
most a few extra cached queries and can't skip the victim's record.

**Related (lower severity):**

- **`sp=` is never applied** (`main.rs:1820` calls `policy_for(&from, &from)`).
  If the record came from the org-domain fallback, `sp=` should govern.
  The effect in practice is that `p=none; sp=reject` subdomains can be
  spoofed, and `p=reject; sp=none` subdomains are over-rejected. `fetch_policy`
  needs to return the domain where it found the record. *(Medium-Low)*
- **Relaxed alignment is a suffix test, not an org-domain comparison**
  (`dmarc/src/lib.rs:145`). Sibling subdomains such as `news.example.com`
  and `mail.example.com` fail alignment. That is not a spoofing vector, but
  it causes false rejections under `p=reject`. Fix it with F2. *(Low)*

### F3 (High): bare CR hides a header from the From scanner

`split_header_lines` (`main.rs:687`) splits only on LF. **Confirmed:**

```
"Subject: x\rFrom: CEO <ceo@victim.example>\r\nFrom: a@evil.example\r\n\r\n"
from_header_domain(...) == Parsed("evil.example")
```

DMARC is evaluated, and passes, for the attacker's own `evil.example`. The
delivered bytes still contain `\rFrom: CEO <ceo@victim.example>`. Any
reader that treats a bare CR as a line break sees a second `From:` from
the victim. Readers that do this include Python's `email` package (it
splits header lines on universal newlines) and many webmail and indexing
pipelines. Which `From` they show varies; some display the first.

**Fix:** refuse (`550 5.6.0`) any message whose **header block** contains a
CR not followed by LF. The check is cheap and runs before DKIM. A bare CR
is never valid in RFC 5322 headers. Bare LF can stay: the scanner and
readers agree on it. Leave the body untouched, for byte fidelity.

### F4 (Medium): SPF parser drops hard-fail policies

**Confirmed** against `spf::check_host` with a mock resolver. The record
authorises `192.0.2.1`; the peer is `198.51.100.9`:

| Record | Result | Correct |
|---|---|---|
| `v=spf1 ip4:192.0.2.1 -all` | Fail | Fail |
| `v=spf1 ip4:192.0.2.1 -ALL` | **Neutral** | Fail |
| `v=spf1 ip4:192.0.2.1 bogus -all` | **Neutral** | PermError |
| `v=spf1 mx/24 -all` | **Neutral** | Fail |
| `V=SPF1 ip4:192.0.2.1 -all` | **None** | Fail |
| `v=spf1 a/24 -all` (peer `192.0.2.77`, in the /24) | **Fail** | Pass |

For a domain whose only protection is SPF `-all` (no DMARC `p=reject`),
SPF Fail is the only thing that rejects a spoof. These records turn
that into Neutral/None, so the spoof is accepted. The last row is the
reverse problem: legitimate mail gets rejected.

The causes:

- the lexer is case-sensitive;
- parsing stops silently at the first term it can't parse instead of
  returning PermError;
- `a`/`mx` dual-CIDR (`/24`, `//64`) is not supported: `parse_a`/`parse_mx`
  (`spf/src/parser/parser.rs:296,311`) drop it, or fold it into the domain;
- `query_spf_record` matches `v=spf1` case-sensitively (`spf/src/lib.rs:278`).

**Fix:** case-insensitive lexing; PermError on any unparseable term
(RFC 7208 §4.6); implement `ip4-cidr-length`/`ip6-cidr-length` on
`a`/`mx`. *(Note for M2 work: MX- and PTR-host address lookups must stay
bounded. RFC 7208 §4.6.4 limits each `mx`/`ptr` mechanism to 10 address
lookups, with PermError beyond that. Don't remove them from the budget
without adding that cap.)* Also: no AAAA lookups, so `a`/`mx` never match
IPv6 senders. That only matters with an IPv6 listener.

### F5 (Medium): DKIM verifier gaps

All three were **confirmed** by signing real messages in a probe:

1. **Weak keys accepted.** A 512-bit RSA key verifies
   (`dkim/src/lib.rs:1414`; rsa 0.9 caps keys at 4096 bits but sets no
   floor). RFC 8301 §3.2: verifiers MUST NOT accept keys < 1024 bits. A
   domain still publishing a 512-bit key can be forged by anyone who
   factors it, which is cheap.
2. **`l=` honoured.** A signature with `l=7` still verifies after the
   attacker appends arbitrary body text. Any genuinely signed `l=` message
   from the victim becomes a template that passes DMARC with attacker
   content. **Fix:** treat a signature whose `l=` is shorter than the
   canonicalised body as failing, or ignore `l=`-limited signatures for
   DMARC.
3. **`From` not required in `h=`.** A signature over `h=Subject` still
   verifies after `From:` is changed to `CEO <ceo@victim.example>`. RFC
   6376 §6.1.1: verifiers MUST ignore signatures that don't sign `From`.
   **Fix:** check this in `DkimSignature::parse` (line ~218).

Minor: the key record's `k=` is used without checking it against the
signature's `a=` key type. This is not exploitable, since the
cryptography still has to verify.

---

### F6 (Medium): accepted mail can be duplicated

The whole-connection `timeout_at` (`main.rs:2324`) can fire after the
spool commit but before the `250` is written. The client then retries and
the message is delivered twice. The window is wide: fast-path delivery,
one fsync per recipient, runs **inside** `end_data`, before the reply
(`main.rs:~1925`).

**Fix:** keep the cap, which is the defence against slow-drip clients.
Make end-of-data immune to it: check the deadline before starting the
commit, then run commit + reply to completion. Move fast-path delivery
after the reply, into a spawned task.

### F7 (Medium): accepted mail is dead-lettered after about 5 minutes

The drain runs every 60 s with `MAX_DELIVERY_ATTEMPTS = 5`
(`delivery.rs:274`). Any delivery outage longer than about 5 minutes moves
mail that was already accepted with a `250` into `spool/dead-letter/`.
Outages include a full disk, a permissions mistake, or a future backend
being down. Nothing alerts or requeues it. For an MX that is silent mail
loss.

**Fix:** retry with exponential backoff for days (as MTAs normally do: 4–5
days), not minutes. Log every dead-letter at `error`, and provide a
requeue path.

### F8 (Medium): no storage bound; drain loads every payload

- No per-message, per-mailbox or free-disk limit (N10). Without
  `--authority`, the default `StaticAuthority` accepts every local-part and
  creates a maildir for each one.
- `DiskSpool::list()` (`spool.rs:247`) loads every queued payload into
  memory each drain pass. Combined with F7's outage scenario, a backlog
  becomes an OOM.

**Fix:**
- Make the drain read metadata only and load payloads one at a time.
- Tempfail (`452 4.3.1`) at DATA/end-of-data when free space is below a
  threshold.
- Require `--authority` when not on a development port, or at least warn
  loudly.

### F9 (Medium): unlimited recipient probing

RCPT is limited to 100 per transaction, but `RSET` resets that, and there
is no session-wide limit on refused RCPTs (`main.rs:1477`). A valid
address gets `250`; an invalid one gets `550 5.1.1`. One connection can
therefore test thousands of addresses in its 5 minutes, and with 60
connections a minute per IP, a few IPs can enumerate a domain's live
disposable addresses. That is a privacy problem for this product.

**Fix:** close the session (`421`) after N refused RCPTs (e.g. 20).
Optionally add a per-IP refused-RCPT budget in `limit.rs`, and a small
delay on each refusal (tarpit).

---

### F10 (Medium if AUTH enabled; inactive in V1): AUTH hardening

These only matter if `--auth-users` is set:

- AUTH is advertised on **any** TLS listener, including port 25
  (`main.rs:1248`). There is no submission-only mode.
- No failed-attempt limit: unlimited guesses per connection, times 60
  connections a minute per IP.
- Password comparison is not constant-time (`main.rs:1151`), and
  passwords are stored in plaintext in argv/config.
- `*` aborting a LOGIN exchange leaves `auth_login_user` set. The next
  `AUTH LOGIN` then takes its username line as the stale user's password.
  This only confuses the client's own session, and it puts a username in
  the session-summary log.

**Recommendation for V1:** refuse to start with `--auth-users` unless an
explicit submission-mode listener is configured, or remove AUTH from the
V1 build. The `From:` grants landed earlier are necessary but not
sufficient.

---

### Low

| # | Finding | Location |
|---|---|---|
| L1 | `create_owned_dir_all` runs as root and `chown`s by path after `mkdir`. If the service account is already compromised, it can swap in a symlink and get root to `chown` an arbitrary file on the next start. Use `fchown` on an `O_DIRECTORY\|O_NOFOLLOW` fd. | `fsutil.rs:74` |
| L2 | `create_private_file` follows symlinks and truncates existing files (no `O_EXCL`/`O_NOFOLLOW`). The parent directories are private, so this is defence in depth. | `fsutil.rs:37` |
| L3 | Catch-all recipients in one transaction share a routing mailbox and queue ID, so they collapse into a single file that records only one envelope address (M9). This is an integrity issue for the temp-mail use case. | `main.rs` fast path, `delivery.rs` filename |
| L4 | Per-IP limits are keyed per address, so an IPv6 /64 escapes them. Only relevant with a `[::]` listener. | `limit.rs` |
| L5 | A panic inside a session skips `limiter.release(ip)` and leaks the per-IP count. I found no remotely reachable panic. Use an RAII guard. | `main.rs:2339` |
| L6 | No `Authentication-Results:` header is added, and forged inbound ones are not stripped. This only matters if a downstream reader trusts A-R. | end-of-data |
| L7 | The per-session RCPT success cache outlives an authority revocation for the rest of the session (at most 5 min). | `rcpt_cache` |
| L8 | No SPF alignment for the null sender (bounces), because the HELO identity isn't used for DMARC. Availability only. | `main.rs` DMARC |
| L9 | EHLO doesn't reset an in-flight envelope; commands before EHLO get `500` instead of `503` (RFC 5321 §4.1.4). | `smtp/src/lib.rs` |

---

## 3. Verified sound

These were checked and need no action:

- **SMTP framing.** The only exit from DATA is `<CRLF>.<CRLF>`, the
  `<LF>.<CRLF>` smuggling variant is handled, and verbs are never parsed
  in Data/Discard.
- **STARTTLS command injection** (CVE-2011-0411 class). Pipelined
  plaintext after `STARTTLS` is dropped with the `BufReader`
  (`into_inner`), and all pre-TLS state, including AUTH, is reset.
- **Path traversal.** RCPT local-parts are validated at RCPT time, and
  again in `MaildirSink::split_recipient` (no `/`, no leading `.`, no `..`).
- **Header-parse DoS (S1/S2).** DKIM uses only the raw view, header
  selection is linear, and the comment-depth bound is conservative.
- **The From author** comes from the address, never from comments or
  quoted display names. Multiple or absent `From:` is a hard reject.
- **Privilege drop.** The order is setgroups, then setgid, then setuid,
  then a check that root can't be regained. It completes before storage
  is opened or any connection is served. Files are created `0600` and
  directories `0700`.
- **DNS.** Parsing is total, responses are validated (ID, QR flag, question
  echo, EDNS0), query names are length-checked, and TXT character-strings
  are concatenated.
- **Logging.** Message bodies are excluded from the session summary.
  Attacker-controlled strings go into JSON fields, never raw log lines.
  HELO and path control characters are refused before they're logged.

---

## 4. Recommended V1 order

1. **F1, F2, F3.** Each is a direct DMARC bypass, and each is small
   (F2's interim ancestor walk avoids taking on the PSL dependency first).
2. **F4, F5.** SPF/DKIM correctness. Each fix has a ready-made regression
   test: the probe cases above.
3. **F6, F7, F8.** Do not lose or duplicate accepted mail.
4. **F9.** Recipient enumeration.
5. **F10:** decide whether V1 ships AUTH at all. Then the L-tier.
