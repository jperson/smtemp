# REPORT.md — Security, Design & Bug Review of mailserv

**Scope:** every crate in the workspace (`smtp`, `mailserv`, `dns`, `spf`,
`dkim`, `dmarc`, `mailparse`, plus a brief look at `dnsq` and `smtp-client`),
checked against DESIGN.md, PLAN.md and README.md.
**Date:** 2026-11-21 · **Commit reviewed:** `6b0a655` (plus the uncommitted `flake.nix` change, which isn't relevant here)
**Rounds 1–2: review only, no source changes. Round 3: fixes applied. Round 4: review only (below).**

---

## Round 4 — security re-evaluation (2026-11-21)

**Reviewed:** commit `5af4540` on `main`, clean working tree.
`cargo test --workspace`: **194 passed, 0 failed, 1 ignored**; clippy
(`-D warnings`) clean. I made no source changes. Method:
- I checked every finding still listed as open against the current code.
- I re-read the code added since round 1 (round-3 fixes, DNS metrics,
  SPF deadline).
- I tested hypotheses two ways: a throwaway crate linking the public
  `dns`/`spf` APIs against a local mock DoT resolver, and live SMTP
  sessions against a freshly built binary on 127.0.0.1. Both ran in temp
  directories, since deleted.

**About commit `5af4540` ("Dns pipelining"):** it contains no pipelining.
Its diff is the DNS metrics, the SPF evaluation deadline, and the
DESIGN §6.1 plan from the previous session. `DnsClient` is still the
fixed 8-slot pool with one exchange per connection, as DESIGN §6.1
correctly says. The commit message shouldn't be read as "pipelining is
done".

### Summary

- **No critical findings are open.** The round-3 fixes for the original
  criticals (path traversal, SMTP smuggling including `<LF>.<CRLF>`, DKIM
  results leaking across messages, DMARC skipped on bad `From:`) still
  hold.
- **One high finding is open: H6, re-opened.** My round-3 status overstated
  the pool fix. Eight slow lookups fill the pool, and a single client IP
  can hold that many within the per-IP limit.
- **There are 11 new findings (N8–N18).** Four are medium, five low, plus
  two note-level process/doc items. Four of them (N12, N13, N14, N17)
  are side effects of changes I made in round 3 or round 4, and N11
  follows from the C4 fix. Each is called out as such.
- **Still open from round 1:** medium M1–M9, M11–M14, M16 and M17 (M10
  partly fixed); all of L1–L12; and the design observations.

### Status changes

> **Follow-up (after round 4): DNS pipelining landed** (uncommitted on top of
> `5af4540`). **H6 is now FIXED**: 2 pipelined connections × 64 queries in
> flight (`--dns-connections`), and a test shows 20 slow lookups in flight
> don't delay an unrelated one. **N13 is FIXED**: a timed-out query
> abandons its transaction ID and the connection survives (test:
> `timeout_keeps_the_connection_and_discards_the_late_reply`). Verified
> live against 1.1.1.1: 5 concurrent sessions, peak 5 in flight, no
> errors. **Per-source-IP DNS limit also landed** (`--max-dns-per-ip`,
> default 4): each DNS-backed check holds one of its IP's permits, and an IP
> at its limit gets a temporary failure after a 10 s wait, never a permanent
> one. Tests cover each stage (HELO, MAIL FROM, end-of-data). A live burst
> of 6 sessions from one IP at a limit of 2 saw 4 short waits and 0 refusals.

| # | Was | Now | Why |
|---|---|---|---|
| H6 | ✅ FIXED (round 3) | ⚠️ **PARTIALLY FIXED — High, open** [verified] | The pool has 8 connections and each slow lookup holds one for up to the 5 s exchange timeout. `--max-conn-per-ip` defaults to 10, so **one client IP** can keep 8 sessions each doing an SPF evaluation against a record whose authoritative servers never answer. That holds every pooled connection continuously: the SPF deadline caps one evaluation at 20 s, but the attacker just starts another. With the mock resolver, an unrelated lookup waited the full 2.8 s delay while 8 slow lookups were in flight. Legitimate sessions then get SPF `TempError` (`451`) or hit the 30 s connection cap, so inbound mail is delayed for as long as the attack runs. The planned fixes cover it: pipelining (many queries per connection), plus a limit on DNS work per client IP (per-session fairness alone doesn't help, because the attacker uses 8 sessions). The round-3 regression test only proves that **one** slow lookup doesn't block others. |
| M8 | open (paths fixed in round 3) | **open** [verified] | Paths are fixed, but HELO still isn't validated. `EHLO evil.example\rX-Injected: yes` was accepted, and the delivered copy's trace header is literally `Received: from evil.example<CR>X-Injected: yes (127.0.0.1)<CR><LF>`. Any client that treats a lone CR as a line break sees an injected header. |
| H2 | ✅ FIXED | ✅ FIXED, follow-up N12 | The main defect is fixed. Minor parser leniency remains (N12). |

### New findings

| # | Severity | Finding | Where |
|---|---|---|---|
| N8 | **Medium** | A bare CR in the header block hides a header from the `From:` scanner (parser differential) **[verified]** | `mailserv/src/main.rs` (`split_header_lines`, `from_header_domain`) |
| N9 | **Medium** | Display-name spoofing: an unquoted address in the display name is accepted, and DMARC passes for the real (attacker) domain **[verified]** | `mailserv/src/main.rs` (`mailbox_domain`) |
| N10 | **Medium** | No storage quotas: one message to 100 recipients is stored 100 times, and the default authority creates a maildir per invented address **[verified]** | `mailserv/src/main.rs` (`rcpt_to`, `end_data`), `authority.rs` (`StaticAuthority`) |
| N11 | **Medium** | DKIM returns no results when `mailparse` rejects a message; since the C4 fix, that means legitimate DKIM-signed mail from `p=reject` domains is rejected | `dkim/src/lib.rs:1395`, `mailserv/src/main.rs` (`end_data`) |
| N12 | Low | The SPF macro expander accepts malformed macro-strings, and the `exp`-only letters (`c`, `r`, `t`) in domain-specs **[verified]** | `spf/src/parser/parser.rs` (`expand_macro_string`) |
| N13 | Low | ✅ *fixed by pipelining* — An SPF deadline hit throws away a warm pooled DoT connection, so an attacker can force repeated TLS handshakes to the resolver **[verified]** | `spf/src/lib.rs` (`check_host_within`), `dns/src/lib.rs` (`query`) |
| N14 | Low | Shell metacharacters are now allowed in maildir directory names **[verified]** | `mailserv/src/main.rs` (`is_mailbox_safe`), `delivery.rs` (`split_recipient`) |
| N15 | Low | `end_data` holds up to five copies of each message at once (~5 MiB per session at the defaults, ~2.5 GiB across 500 sessions) | `mailserv/src/main.rs:1247,1396,1435`, `spool.rs:418` |
| N16 | Low | DMARC never gets SPF alignment for the null sender (bounces), because it ignores the HELO identity | `mailserv/src/main.rs:1315` |
| N17 | Note | The SPF deadline (20 s) and the whole-connection cap (30 s) interact: an EHLO plus a MAIL FROM evaluation can run past the cap | `spf/src/lib.rs`, `mailserv/src/main.rs` |
| N18 | Note | Docs overstate status: PLAN §6 marks H6 FIXED, and the commit named "Dns pipelining" has no pipelining | `PLAN.md` §6, git history |
| N19 | **High** (deployment) | On an IPv6 listener, IPv4 clients appear as IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`), so SPF `ip4:`, `a` and `mx` never match them **[verified]** | `mailserv/src/main.rs` (`handle_connection` peer), `spf/src/lib.rs:416` |

#### N8. A bare CR in the header block hides a header from the `From:` scanner (Medium) [verified]

`split_header_lines` splits only on LF, so a lone CR stays inside a
line. Sent message:

```
Subject: hi<CR>From: ceo@paypal.com<CR><LF>
From: x@attacker-owned.example<CR><LF>
```

The scanner sees one `Subject` header and one `From`, for the attacker's
domain. That domain has no DMARC record, so the message was **accepted
and delivered**. A mail client or downstream parser that treats a lone
CR as a line break sees two `From:` headers, the first being
`ceo@paypal.com`.

RFC 5322 forbids a bare CR in the header section, and major MTAs reject
or rewrite it. This is the same differential class as the SMTP-smuggling
fixes, applied to headers instead of framing. Whether it is exploitable
depends on the reader; it is safest to assume some reader is affected.

**Fix:** in `from_header_domain` (or as a check at end-of-data), treat a
CR not followed by LF anywhere in the header block as `Unparseable` and
reject the message. The From-header rejection path already exists.

#### N9. Display-name spoofing passes DMARC (Medium) [verified]

`From: ceo@paypal.com <x@attacker-owned.example>` was accepted.
`mailbox_domain` correctly takes the angle address
(`attacker-owned.example`), so DMARC is evaluated, and can be made to
pass, for the attacker's domain. But most mail clients show only the
display name, `ceo@paypal.com`.

DMARC itself doesn't cover display names. Still, for a receive-only
service whose users read this mail, this is the most common spoofing
technique left, and the input is **syntactically invalid**: `@` is an RFC
5322 special and can't appear unquoted in a phrase.

**Fix (smallest):** in `mailbox_domain`, look for `@domain` text in the
display-name part (outside quotes and comments; the cleaning pass already
strips those). If that domain doesn't match the actual address's domain,
treat the From as `Unparseable` (reject) or, less strictly, add a
warning header. Plain `john@x.com <john@x.com>`, a common misconfiguration,
stays accepted because the domains match.

#### N10. No storage quotas: 100× amplification per message, and unlimited maildirs (Medium) [verified]

One connection sent one ~50 KB message to 100 distinct invented local
parts (`probe1@` … `probe100@`). The default `StaticAuthority` (used
whenever `--authority` isn't given) accepted all 100. The result was **100
new maildir directories and 5.1 MB on disk**: one 1 MiB message becomes
about 100 MiB, and nothing limits it per sender, per domain or per
mailbox.

At the defaults (60 connections per minute per IP, several messages per
connection), one IP can fill a disk quickly. The last delivery failures
then dead-letter mail that was already accepted (M14). With a real
authority in `reject` mode the attacker needs valid addresses, but the
100× multiplier still applies.

PLAN Phase 12 already says catch-all must be "gated by storage quotas";
none exist. **Fix:** per-domain and per-mailbox quotas checked at RCPT or
end-of-data (`452 4.2.2` when exceeded), a cap on total stored bytes per
message across recipients, and a free-disk check that tempfails (`452
4.3.1`) before the spool fills. Also require `--authority` outside
development (round-1 design observation 5).

#### N11. DKIM silently returns nothing for messages `mailparse` rejects, so legitimate mail is now rejected (Medium)

`verify_dkim` begins with `let Ok(msg) = parse_message(raw) else { return
Vec::new() }` (`dkim/src/lib.rs:1395`). `parse_message` fails if any
header byte isn't UTF-8 (e.g. a Latin-1 subject) or if any header fails
the pest grammar.

Before C4, such a message skipped DMARC entirely, which was the bypass.
Now the tolerant `From:` scanner finds the domain, DMARC runs, sees **no
DKIM results**, and a `p=reject` domain's genuinely signed message gets
`550`.

This fails closed, so it isn't a bypass, but it is an availability
problem caused by the two layers disagreeing about what parses. **Fix:**
make DKIM work from the tolerant raw view. `extract_raw_headers` and
`split_message` already work on bytes; only the typed parse needs UTF-8.
At minimum, log when verification is skipped because of a parse failure,
so these rejections can be diagnosed.

#### N12. The SPF macro expander is lenient on malformed input (Low) [verified]

This is a side effect of my round-3 H2 fix. RFC 7208 §7.1 says a bad
macro is a syntax error, which should give PermError. Two cases slip
through:

- **Unterminated macros:** these are detected by comparing counts of `%{`
  and `}` over the whole string, so a literal `}` earlier in the string
  hides one. `exists:a}%{d` was accepted and expanded to `a}ex.test`.
- **`exp`-only letters:** `c`, `r` and `t` are only valid inside `exp=`
  (§7.3), but are expanded in domain-specs:
  `exists:%{c}.%{t}.%{r}.ex.test` was accepted.

The impact is limited (the record's owner controls both inputs), but
evaluation should follow the RFC. **Fix:** track the closing `}` inside
the `%{` branch, rather than counting braces afterwards, and pass a "this
is `exp`" flag so `c`/`r`/`t` are refused elsewhere.

#### N13. A deadline hit throws away a warm DNS connection (Low) [verified] — ✅ fixed by pipelining

This is a side effect of my SPF-deadline change. When `check_host_within`'s
timeout fires mid-lookup, the in-flight `DnsClient::query` future is
dropped. The pool's cancellation rule then drops the connection it held,
which is correct, since its state is unknown.

Verified: one warm connection (`connects=1`), one SPF evaluation hitting a
500 ms limit mid-exchange, then an ordinary query → `connects=2`. An
attacker who can trigger deadline hits (H6's slow records) makes the
server re-handshake TLS with the resolver over and over. That costs CPU,
and public resolvers rate-limit clients that reconnect excessively, which
could turn into resolver-side throttling of all lookups.

**Fix:** pipelining removes the problem: a timed-out query just abandons
its ID, and the connection survives. Until then, consider letting an
abandoned exchange finish in a detached task that returns the connection
to its slot, under the exchange timeout.

#### N14. Shell metacharacters in maildir directory names (Low) [verified]

This is a side effect of the N4 fix in round 3, which widened the
local-part allow-list to RFC 5321 `atext` minus `/`. `` RCPT TO:<`id`$x|y@mail.test> ``
was accepted and created the directory `` maildir/mail.test/`id`$x|y ``.

That's safe inside mailserv, which never passes paths through a shell.
But any operator script, backup job or delivery agent that interpolates
maildir paths into a shell command unquoted becomes an injection point.
`?` and `*` are also glob characters. **Fix:** the round-1 recommendation
still stands: name storage directories by an opaque mailbox ID (a hash, or
the authority's mailbox ID) rather than the address text. That keeps
address syntax free of filesystem concerns entirely.

#### N15. Several message copies held at once (Low)

During `end_data`, the message exists as:

1. `self.data`;
2. `raw` (`self.data.clone()`, `main.rs:1247`);
3. `write_raw` (`raw.clone()`, `main.rs:1396`);
4. `payload` inside `DiskSpool::write` (`raw.to_vec()`, `spool.rs:418`);
5. one per-recipient delivery copy at a time (`prepare_for_delivery`,
   `main.rs:1435`).

That's up to about 5 × `max-data-bytes` per session, roughly 5 MiB at the
defaults, or about 2.5 GiB across 500 sessions if many finish DATA at
once. **Fix:** move `self.data` out (`std::mem::take`) instead of cloning,
share the buffer as `Arc<[u8]>` with the blocking tasks, and have the
spool take the bytes by value when there's no encryptor.

#### N16. No SPF alignment for bounces (Low)

DMARC alignment uses `self.mail_from`'s domain (`main.rs:1315`). For the
null sender (`MAIL FROM:<>`), that's `None`, so SPF can never align,
although SPF itself was evaluated against the HELO identity. Unsigned
bounces from `p=reject` domains are therefore rejected. RFC 7489 §2.2 and
RFC 7208 §2.4 use the HELO identity when MAIL FROM is null. **Fix:** use
the HELO domain (with `spf_helo`) for DMARC SPF alignment when the sender
is null.

#### N17. The SPF deadline and the connection cap interact (Note)

The HELO evaluation and the MAIL FROM evaluation can each run up to 20 s
(the RFC floor), which together exceeds the default 30 s connection cap.
When the cap fires, the connection is dropped silently: no `421`, and no
session summary log. This is already recorded in DESIGN §6.1 and in M11.
It's listed here because M11 is now the limiting factor for the deadline
work.

#### N18. Documentation and history overstate status (Note)

- PLAN.md §6 lists H6 as **FIXED** (see the status change above).
- PLAN's header says the critical and high tiers are closed, which is no
  longer true with H6 re-opened.
- Commit `5af4540` is titled "Dns pipelining" but contains no pipelining.

None of this is a vulnerability, but the PLAN ledger is what reviewers use
to decide what is safe. Update it whenever the status table here changes.

#### N19. IPv4-mapped peer addresses break SPF on an IPv6 listener (High for deployment) [verified]

Found while preparing the VPS deployment checklist (after round 4).
With `--host "[::]"`, Linux (`net.ipv6.bindv6only=0`, the usual default)
accepts IPv4 connections on the IPv6 socket and reports the peer as an
IPv4-mapped address. Verified: the EHLO reply said
`Hello [::ffff:127.0.0.1]`.

Nothing converts the address back. `check_ipv4` matches only
`IpAddr::V4`, so `ip4:`, `a` and `mx` mechanisms never match, and `%{i}`
expands to IPv6 nibbles. For any sender whose record ends in `-all`, that
is SPF Fail → **`550`** on legitimate mail. The per-IP connection and DNS
limits still work, because they key on the mapped address consistently.

**Fix (one line):** use `peer.ip().to_canonical()` wherever the peer IP
is taken (`handle_connection`, before `UserSession::new` and the
limiters). **Until then:** listen on `0.0.0.0` only and don't publish an
AAAA record for the MX.

### Still open from earlier rounds (re-verified against `5af4540`)

| Tier | Findings |
|---|---|
| High | **H6** (re-opened, above) |
| Medium | M1 SPF parser stops at unknown terms and is case-sensitive · M2 SPF budget over-counts MX/PTR address lookups · M3 DMARC org domain is "last two labels" · M4 `sp=` never applied · M5 relaxed alignment rejects sibling subdomains · M6 DMARC fails open on DNS errors, quarantine does nothing · M7 no `Authentication-Results:`, forged ones kept · M8 HELO not validated (verified above) · M9 catch-all copies collapse · M10 503-vs-500, EHLO doesn't reset the transaction, 512-octet AUTH cap · M11 30 s whole-connection cap, duplicates on timeout · M12 limiter O(n) sweep and leak on panic · M13 drain loads every payload into memory · M14 0644 files, no directory fsync, encryption bypassed by maildir copies · M16 AUTH: no attempt limit, stale LOGIN state, case-sensitive mechanisms · M17 DKIM: no RSA size floor, `l=` honoured, `h=` need not include From |
| Low | L1 DNS label lengths unchecked (now easier to reach, because SPF macros put the attacker-controlled sender local-part into query names) · L2 DNS cache wiped when full · L3 third-party resolver, no DNSSEC · L4 HELO SPF on every EHLO · L5 `redirect=` to a domain with no record · L6 log spans for every DATA line · L7 extra data in the session summary · L8 write errors ignored · L9 cache key vs query name · L10 no TLS reload or SNI · L11 config footguns · L12 dnsq per-call config |
| Design | AUTH still enabled in the receive-only V1 (MSA exemptions let any credential holder spoof `From:` to hosted mailboxes) · `StaticAuthority` is the default · idempotency key and commit-vs-reply ordering unsettled |

### Suggested order

1. **H6:** per-client-IP DNS concurrency limit (small; hold a per-IP
   semaphore around SPF/DKIM/DMARC evaluation in `UserSession`), then the
   pipelining plan in DESIGN §6.1.
2. **N8 and M8:** reject bare CR in the header block and in HELO.
3. **N10:** storage quotas and a free-disk tempfail, and require
   `--authority` in production.
4. **N9, N11:** display-name domain check, and DKIM on the raw view.
5. **M11:** per-phase timeouts. This also resolves N17, and the
   duplicate-delivery risk.
6. The DMARC correctness group (M3, M4, M5, M6, N16), then the rest.

---

## Round 3 — remaining critical/high and round-2 findings fixed

**Base:** commit `a2e96fb` ("Critical security fixes"). The changes are
uncommitted in the working tree, and each is a contained edit inside
the existing function or module, with no restructuring.
`cargo fmt --check` and `cargo clippy --workspace --all-targets -D warnings`
are clean. `cargo test --workspace`: **193 passed, 0 failed, 1 ignored**
(185 before; +8 regression tests). Every fix below was also checked
end to end against a freshly built binary on 127.0.0.1 with the same
attack sessions as round 2, using the real 1.1.1.1 resolver.

| # | Status | Fix | Verified by |
|---|---|---|---|
| N1 (C2) | ✅ **FIXED** | `smtp::run` remembers whether the previous DATA line ended in a bare LF. If so, a following `.<CRLF>` is passed to the handler dot-stuffed, so it is delivered as a literal `.`. Over-long lines track their ending too (`Line::Overflow { last }`, `drain_line` returns CRLF-ness). Bare LF stays legal message data (DESIGN goal 3); only `<CRLF>.<CRLF>` ends DATA. | `lf_dot_crlf_does_not_terminate_data` (duplex). Live: the `first\n.\r\nRSET…MAIL…RCPT…DATA` probe now gets **one** end-of-data reply and no smuggled `250`s. |
| N2 (C4) | ✅ **FIXED** | `from_header_domain` appends continuation lines to the From value it collected (it previously appended them to a copy). | `from_header_scanner` unit test. Live: a folded `From:` now reaches DMARC instead of getting "malformed From". |
| N3 (C4) | ✅ **FIXED** | `from_domain_of` reads an RFC 5322 mailbox-list: comments removed, quoted strings opaque, `<addr-spec>` preferred, obsolete routes handled, group syntax refused, and several author domains count as `Multiple`. The header name match accepts `From<WSP>:`. | `from_header_scanner` (comment, quoted `@`, two domains, `From :`, 8-bit display name, quoted local-part). Live: the comment spoof is judged against `paypal.com` → `550`; two domains and `From :` + `From:` → `550 5.7.1` (bad From). |
| H2 | ✅ **FIXED** | `expand_macro_string` replaced with an RFC 7208 §7 expander: letters, digit/`r` transformers, delimiters, `%%`/`%_`/`%-`, URL-escaping for upper-case letters, and 253-octet left truncation. Malformed macros are errors (PermError). `SpfMacroSubs`: IPv6 `%{i}` as nibbles, `%{t}` in epoch seconds, `%{p}` = `unknown`, empty `%{l}` = `postmaster`. Also the `include:` lexer pattern now accepts `%`; it excluded 0x25, so macro includes were silently dropped. | `macro_expansion_rfc_examples` (RFC 7208 §7.4 examples, including IPv6 and error cases), `include_with_macro_parses`. |
| H3 | ✅ **FIXED** | `clean_path` splits `<path> [ESMTP-params]` (RFC 5321 §4.1.2) and refuses paths with control characters (which also closes the bare-CR path into `Return-Path:` from M8). MAIL FROM enforces `SIZE=` against the advertised limit (`552`). | `clean_path_splits_esmtp_parameters`. Live: `MAIL FROM:<> SIZE=100` → `250`; `SIZE=999999999` → `552`. |
| H6 | ✅ **FIXED** (no pipelining) — *re-opened in round 4: 8 slow lookups from one client IP still fill the pool* | `DnsClient` now holds a fixed pool of 8 connections. A query takes the first idle one (so a quiet server keeps one warm connection) or waits on one chosen round-robin. Each connection still carries one exchange at a time, so the reply-pairing safety argument is unchanged. | `slow_lookup_does_not_block_other_lookups`. A deliberate revert to 1 connection makes it fail ("waited 1.38 s"). The existing connection-reuse test still passes. |
| H7 | ✅ **FIXED** | `verify_dkim` evaluates at most `dkim::MAX_SIGNATURES` (5) signatures, the topmost ones. | `signature_count_is_capped` (50 signatures → 5 results, offline). |
| N4 | ✅ **FIXED** | The RCPT local-part allow-list (and the matching sink check) is now RFC 5321 dot-atom text minus `/`. Recipient syntax refusals reply `553 5.1.3 Bad recipient address syntax` (was the sender code `501 5.1.7`). | `local_part_policy`. Live: `o'brien@` → `250`; `../../x@` → `553`. |
| N5 | ✅ **FIXED** | A failed authority reload is logged at `error` (stale policy in force); a successful reload is logged at `info`. Still logged once per file change, not once per lookup. | Code review; the existing hot-reload test still passes. |
| N6 | ✅ **FIXED** | The C3 regression test uses a local mock DoT resolver (`spawn_mock_dmarc_resolver`, `_dmarc.*` → `p=reject`) instead of facebook.com on 1.1.1.1. | Test passes with no network dependency. |
| N7 | ✅ **FIXED** | DESIGN §1 (delivery exists), §4.1 (the `<LF>.<CRLF>` rule), §5 (From, envelope-parameter and authority-reload behaviour), §6/§10 (DNS pool, SPF macros), test counts in DESIGN/README/PLAN, and the PLAN §6 ledger and priority list were all corrected. | — |

**Still open (deliberately out of scope for this round):** all medium and
low findings except the parts noted above (M8: path control characters
only; M10 and M15 were partly addressed in round 2). DNS pipelining (H6
uses a pool instead), AAAA lookups for IPv6 SPF senders (H1 note),
validating authority mailbox keys when the file loads (N4 follow-up),
and moving DKIM CPU work off the async executor (H7 bounds it instead).

**Design adherence notes:** the protocol/policy seam is unchanged
(`SmtpSession`, `Control` and `SmtpState` are untouched; the N1 fix lives
in the `run` read loop). DESIGN goal 3 (byte fidelity) is kept: bare-LF
lines are still delivered verbatim rather than rejected. The one
deliberate behaviour change beyond the RFCs is the existing server
policy that recipient local-parts may not contain `/` or be quoted.

---

## Re-review (round 2) — fixes for the critical and high findings

**Reviewed:** the uncommitted working tree on top of `6b0a655` (changes to
`smtp`, `mailserv/{main,authority,delivery}.rs`, `spf`, `dns`, `dkim` and
the docs). `cargo test --workspace`: **185 passed, 0 failed, 1 ignored**.
I checked the fixes the same way as round 1: by reading the diff, then
driving a freshly built binary on 127.0.0.1 with crafted sessions. That
server could reach the real 1.1.1.1 resolver, so the DMARC results below
reflect real `p=reject` policies (example.net, paypal.com). No source
changes were made.

| # | Round-1 finding | Status | Notes |
|---|---|---|---|
| C1 | Maildir path traversal | ✅ **FIXED** [verified] | Recipient local-parts are checked at RCPT time and again in the delivery sink. `../../x@` now gets `501`. Side effect: see N4. |
| C2 | SMTP smuggling | ⚠️ **PARTIALLY FIXED** [verified] | `RSET`/`QUIT` and other verbs inside DATA are now message data, and a bare-LF `.` no longer ends DATA. But `<LF>.<CRLF>` still ends DATA, and the lines after it still run as commands. See N1. |
| C3 | DKIM verdicts leak across messages | ✅ **FIXED** | DMARC now uses only `dkim_summaries` (this message's results). The regression test needs live DNS; see N6. |
| C4 | DMARC skipped on parse failure | ⚠️ **PARTIALLY FIXED, plus a regression** [verified] | Missing, duplicate and 8-bit `From:` headers are now rejected. But the new raw scanner takes the **last `@`** in the header, so a comment, a second mailbox or `From :` still bypasses DMARC (N3). It also loses folded `From:` headers, so legitimate mail is now rejected (N2). |
| H1 | SPF A queries used type 22 | ✅ **FIXED** | Now queries type 1, with a wire-level test. IPv6 (AAAA) lookups are still missing, as noted before. |
| H2 | SPF macro expansion broken | ❌ **NOT FIXED** | `spf/src/parser/parser.rs` is unchanged. PLAN §6 lists it as open. |
| H3 | ESMTP parameters inside the address | ❌ **NOT FIXED** [verified] | `clean_path` is unchanged. `MAIL FROM:<> SIZE=100` still gets `501`. PLAN §6 lists it as open. |
| H4 | `QUIT`/`RSET` body lines end the session | ✅ **FIXED** [verified] | A body with `RSET` and `Quit smoking` lines was received in full and reached end-of-data. |
| H5 | Refusals stall the accept loop | ✅ **FIXED** | `refuse_async` runs refusals in spawned tasks (at most 32); beyond that the socket is just closed. |
| H6 | Serialized DNS, no connect timeout | ⚠️ **PARTIALLY FIXED** | Connecting is now time-limited. Every lookup still shares one mutex-guarded connection, so slow records still block all sessions. The worst-case hold is about 4× the timeout (≈20 s with the retry), not the 2× PLAN states. |
| H7 | Unlimited DKIM signatures | ❌ **NOT FIXED** | `verify_dkim` is unchanged (only its doc comment was edited). |
| H8 | Grace mode refuses permanent mailboxes | ✅ **FIXED** | Now uses `is_none_or`, caps grace at 366 days, and has tests for permanent and future-expiry addresses. |
| M10 | State-machine sequencing | ◐ partially fixed | `RSET` keeps the session greeted and unknown verbs keep their state (both verified). The `503`-vs-`500` and EHLO-reset items are still open. |
| M15 | Authority reload behaviour | ◐ fixed, with a new concern | A bad publish now keeps the last good snapshot and the change check also uses file size. But a failed reload is **silent** (N5). |

**Net:** 6 of the 12 critical/high findings are fully fixed (C1, C3, H1,
H4, H5, H8), 3 are partly fixed (C2, C4, H6), and 3 are untouched (H2, H3,
H7). Two critical issues are still exploitable in a new form: N1 is
smuggling, N3 is a DMARC bypass. PLAN.md §6 says "all four critical
findings are fixed and regression-tested", which these results
contradict.

### New findings (round 2)

| # (round-2 status) | Severity | Finding | Where |
|---|---|---|---|
| N1 | **Critical** | `<LF>.<CRLF>` still ends DATA, so smuggling still works **[verified]** | `smtp/src/lib.rs:540` |
| N2 | **High** | The new `From:` scanner drops folded continuation lines, so legitimate mail with a folded `From:` gets `550` **[verified]** | `mailserv/src/main.rs:343-373` |
| N3 | **Critical** | The new `From:` scanner uses the last `@` in the header and only matches exact `From:`, so DMARC can still be bypassed **[verified]** | `mailserv/src/main.rs:399-401,439-460` |
| N4 | Medium | The new RCPT local-part check refuses legitimate addresses, with a sender error code | `mailserv/src/main.rs:299-316,890` |
| N5 | Medium | A failed authority reload is silent and keeps serving stale policy indefinitely | `mailserv/src/authority.rs:465-479` |
| N6 | Low | The C3 regression test needs live DNS (facebook.com through 1.1.1.1) | `mailserv/src/main.rs` (`dkim_verdicts_do_not_leak_across_messages`) |
| N7 | Low | PLAN/DESIGN overstate the fixes, and one round-1 doc issue is still there | `PLAN.md` §6, `DESIGN.md:15` |

#### N1. `<LF>.<CRLF>` still ends DATA (smuggling, Critical) [verified]

The new framing (`smtp/src/lib.rs:540`) treats a line as the terminator
when `content == b"." && ending == b"\r\n"`. That only checks the dot
line's *own* ending. It doesn't check that the **previous** line ended in
CRLF. The sequence `…body\n.\r\n` is split into `body\n` and `.\r\n`, and
the second line ends DATA. That is the `<LF>.<CRLF>` variant of
CVE-2023-51764, the exact sequence used against Postfix.

Reproduced: a DATA body of
`first\n.\r\nRSET\r\nMAIL FROM:<>\r\nRCPT TO:<smuggled2@mail.test>\r\nDATA\r\n…\r\n.\r\n`
gave `550` (DMARC, first message), then `250`, `250`, `250`, `354` for the
smuggled commands, then a second end-of-data. The injected transaction
was only refused because its forged `From:` domain publishes
`p=reject`; with any other domain it would be delivered. An upstream relay
that lets bare LF through (several do) will carry this sequence as body
text, and it arrives from the relay's trusted IP.

**Fix:** remember whether the previous data line ended in CRLF and only
accept `.` as the terminator after one that did. Better, reject bare LF
and bare CR in DATA outright (`550 5.6.0` after the terminator, or
fail the message), as Postfix (`smtpd_forbid_bare_newline`), Exim and
Sendmail now do. Add the `\n.\r\n` case to `smtp_smuggling_is_prevented`.

#### N2. Folded `From:` headers are lost, so legitimate mail is rejected (High) [verified]

`from_header_domain` pushes a **copy** of the first line's value into
`from_values` (`from_values.push(value.to_vec())`). Continuation lines are
then appended to the separate `current` buffer, which is never read
again. Any `From:` folded across lines is judged on its first line only.
A long display name followed by the address on the next line is common
from mailing lists, RFC 2047 encoded names, and MTAs folding at 78
characters. Such a header has no `@` on its first line, so it returns
`Unparseable` and the message gets **550 "missing or malformed From
header"**.

Reproduced:
`From: "A Rather Long Display Name From A Mailing List"\r\n <news@example.net>`
→ `550 5.7.1 Message rejected: missing or malformed From header`.

PLAN.md says the scanner handles folding and has "extractor unit tests".
There are none: the only tests that touch it are the
`message_without_from_is_rejected` integration test and fixtures changed
to include a single-line `From:`. **Fix:** append continuations to the
entry in `from_values` (e.g. keep an index), and add unit tests for
folded, encoded-word, group and comment forms.

#### N3. The `From:` scanner can still be steered past DMARC (Critical) [verified]

`from_domain_of` takes everything after the **last `@` in the whole header
value** (`rposition`), then stops at whitespace and a few delimiters. It
doesn't parse RFC 5322 address syntax, so the domain it picks can differ
from the one mail clients show. All three of these spoofs of
`ceo@paypal.com` (which publishes `p=reject`) were **accepted and
delivered**. A control message with a plain `From: ceo@paypal.com` got
`550` from DMARC.

1. **Comment:** `From: ceo@paypal.com (@attacker-owned.example )`. The
   last `@` is inside the comment, so DMARC is evaluated for
   `attacker-owned.example`. Mail clients show `ceo@paypal.com`.
2. **Two mailboxes:** `From: ceo@paypal.com, x@attacker-owned.example`.
   This is valid RFC 5322 (`mailbox-list`). DMARC sees only the last
   domain; RFC 7489 §6.6.1 wants every author domain checked, or the
   message rejected.
3. **Obsolete spacing:** `From : ceo@paypal.com` plus `From: x@attacker-owned.example`.
   `is_from_header` matches only exactly `From:`, so the `obs-optional`
   form (whitespace before the colon, RFC 5322 §4.5.3, which many clients
   accept) isn't counted. The scanner sees one `From` and the client may
   show the other.

Since the attacker controls `attacker-owned.example`'s SPF, DKIM and DMARC
records, DMARC can be made to *pass* as well as be skipped. This undoes
the point of C4. **Fix:** parse the `From:` field properly. Either make
`mailparse` tolerant (bytes, not UTF-8, one field at a time) or write a
small RFC 5322 address parser that handles comments, quoted strings,
groups and lists. Reject if there are several author mailboxes with
different domains, or if any `From`-like header (including `From<WSP>:`)
appears more than once. Recognise header names with whitespace before the
colon.

#### N4. RCPT local-part allow-list rejects valid addresses with the wrong code (Medium)

`unsafe_local_part` allows only `[A-Za-z0-9._+=-]`. RFC 5321 `atext` also
allows `! # $ % & ' * / = ? ^ ` { | } ~`, and quoted local-parts. Real
addresses such as `o'brien@` and `info&sales@` (verified: `o'brien@` → `501`)
are now refused. The refusal text is the **sender** error
(`501 5.1.7 Bad sender address syntax`) on a RCPT command. A recipient
problem should be `553 5.1.3` (bad destination mailbox syntax), and
`501 5.1.7` misleads senders' bounce messages. The fix is reasonable as a
stopgap. The lasting fix is to map mailboxes to opaque storage IDs (as
round 1 suggested), so path safety doesn't restrict address syntax. The
sink-side check also turns any authority-supplied mailbox outside the set
into a delivery failure, then a dead letter about 5 minutes later, without
refusing it at RCPT. Validate authority mailbox keys when the file loads.

#### N5. A failed authority reload is silent and serves stale policy indefinitely (Medium)

The new `Err(_)` branch in `FileAuthority::current` throws the error away.
There is no log, no metric, and nothing for the console to see. It also
saves the failing file's stamp, so the server keeps using the last good
data until the file's (mtime, size) changes again. The same happens if the
file is **deleted** (stamp `None`). This silently reverses the documented
fail-closed contract. If the console publishes "expire this address" or
"remove this domain" and the write is malformed, the expired address keeps
receiving mail with nothing to show for it. Keeping the last good data is
the right choice, but log the error at `error`, add a staleness
indicator, and consider failing closed after a configurable
maximum staleness.

#### N6. The C3 regression test depends on live DNS (Low)

`dkim_verdicts_do_not_leak_across_messages` builds `DnsClient::new(1.1.1.1)`
and relies on facebook.com publishing `p=reject`. It fails (or wrongly
passes, if `fetch_policy` errors and DMARC is skipped) when there's no
network or facebook.com changes its record. That contradicts the
"hermetic CI" rule in README. Use the mock DoT server now available
through the public `DnsClient::with_config`.

#### N7. Documentation accuracy (Low)

- PLAN.md says "all four critical findings are fixed and
  regression-tested". C2 and C4 are only partly fixed (N1, N3), and C4
  causes a new false-reject problem (N2).
- PLAN.md says the C4 fix has "extractor unit tests". There are none.
- PLAN.md says the H6 mutex is held for at most 2× the timeout. With the
  reconnect-and-retry path it can be connect + exchange + connect +
  exchange, about 4× (≈20 s at the 5 s default).
- DESIGN.md §1 (line 15) still says "It does **not** yet deliver mail",
  which contradicts §10 and the updated README (round-1 doc item, still
  open). The other round-1 doc items (test counts, dns UDP, queue-ID
  format, dkim module header) are fixed.
- `RSET` sent mid-AUTH now returns to the earlier state, but the session
  never clears its AUTH state (`auth_pending`/`auth_login_user`). That
  adds to the stale-LOGIN problem in M16.

---

*The rest of this document is the original round-1 report. Each
critical/high finding now has a **Round-2 status** line.*

## How findings were checked

- `cargo test --workspace`: **181 passed, 0 failed, 1 ignored** (dkim 16+9,
  dmarc 7, dns 21, mailparse 29, mailserv 35, smtp 37, spf 26, doctest 1).
  Every finding below falls outside what the suite tests.
- **Checked by running the real code.** A throwaway crate in the scratchpad
  linked against `mailparse`, `spf`, `dmarc` and `dns` and called their
  public APIs. The real `mailserv` binary was also run on 127.0.0.1:2599,
  with its spool and maildir in a temp directory, and driven with crafted
  SMTP sessions. Address-literal HELO and the null sender kept SPF from
  needing the network. Findings checked this way are marked **[verified]**.
- All other findings come from reading the code, with file and line given.

---

## Summary

| # (round-2 status) | Severity | Finding | Where |
|---|---|---|---|
| C1 ✅ | **Critical** | Path traversal in maildir delivery: any RCPT local-part can write files anywhere the server user can write **[verified]** | `mailserv/src/delivery.rs:76` |
| C2 ⚠️ | **Critical** | SMTP smuggling: `RSET` (or bare-LF `.`) inside DATA ends the message, and the rest of the body runs as new SMTP commands **[verified]** | `smtp/src/lib.rs:536-545` |
| C3 ✅ | **Critical** | DMARC bypass: DKIM results build up across messages on one connection, so a replayed legit signature makes later spoofed messages pass | `mailserv/src/main.rs:842,871` |
| C4 ⚠️ | **Critical** | DMARC bypass: if mailparse fails (two `From:` headers, any non-UTF-8 header byte, grammar failure), DMARC is skipped and the message is accepted **[verified]** | `mailserv/src/main.rs:850-857` |
| H1 ✅ | High | SPF `a`/`mx`/`ptr`/`exists` query record type 22 (NSAP-PTR) instead of A (1), so these mechanisms never match | `spf/src/lib.rs:213` |
| H2 ❌ | High | SPF macro expansion is broken: every letter after the first `%` is replaced **[verified]** | `spf/src/parser/parser.rs:364` |
| H3 ❌ | High | ESMTP parameters (`SIZE=`, `BODY=`) end up inside the address. This bypasses SPF and rejects every null-sender bounce that carries `SIZE=` **[verified]** | `mailserv/src/main.rs:278` |
| H4 ✅ | High | A message body line starting with `QUIT` ends the session and drops the message; such mail can never be delivered **[verified]** | `smtp/src/lib.rs:539` |
| H5 ✅ | High | The accept loop awaits `refuse()` inline, so each refused connection stalls *all* accepts for 0.5–2.5 s | `mailserv/src/main.rs:1226,1238` |
| H6 ⚠️ | High | The process shares one serialized DNS connection with no connect timeout; one hostile record or a dead resolver stalls DNS for every session | `dns/src/lib.rs:322-360` |
| H7 ❌ | High | DKIM verifies an unlimited number of signatures per message, on the async executor (CPU + DNS amplification) | `dkim/src/lib.rs:1368` |
| H8 ✅ | High | Grace-mode domains refuse every *permanent* mailbox | `mailserv/src/authority.rs:249` |
| M1 | Medium | SPF parser stops silently at the first term it doesn't recognise (case-sensitive lexer), so `-ALL` and anything after an unknown term is dropped **[verified]** | `spf/src/parser/parser.rs:166-175` |
| M2 | Medium | SPF budget is over-counted: MX-host and PTR-name A lookups spend the 10-lookup budget, giving spurious PermError → 550 | `spf/src/lib.rs` (`check_mx_record`, `check_ptr_record`) |
| M3 | Medium | DMARC org-domain fallback is "last two labels", so `x.bank.co.uk` looks up `_dmarc.co.uk` and spoofing goes unchecked | `dmarc/src/lib.rs:248` |
| M4 | Medium | DMARC `sp=` is never applied (`policy_for(from, from)`) **[verified]** | `mailserv/src/main.rs:883` |
| M5 | Medium | DMARC relaxed alignment rejects sibling subdomains (`news.example.com` vs `mail.example.com`) **[verified]** | `dmarc/src/lib.rs:148` |
| M6 | Medium | DMARC fails open: a DNS error during the policy fetch counts as "no policy"; `quarantine` is a no-op | `mailserv/src/main.rs:859-866,907` |
| M7 | Medium | No `Authentication-Results:` header is added, and forged inbound ones are not stripped | `mailserv/src/delivery.rs:180-190` |
| M8 | Medium | Trace header injection: HELO/MAIL FROM text (including bare CR) is copied verbatim into `Received:`/`Return-Path:` | `mailserv/src/delivery.rs:182-190` |
| M9 | Medium | Catch-all collapses copies: all recipients routed to the same mailbox share one idempotency file, so the original recipient is lost | `mailserv/src/delivery.rs:84-86` |
| M10 | Medium | `RSET` returns to Idle (500 on the next MAIL), and any unknown verb drops to Idle without clearing the envelope **[verified]** | `smtp/src/lib.rs:537,678` |
| M11 | Medium | 30 s hard cap per connection, covering DATA, DNS and fsync; a timeout after spooling gives duplicate mail on retry | `mailserv/src/main.rs:1257` |
| M12 | Medium | Limiter sweep is O(n) per release under a mutex; the per-IP count leaks if a task panics | `mailserv/src/limit.rs:126-135`, `main.rs:1272` |
| M13 | Medium | `DiskSpool::list()` loads every queued payload into memory on each drain pass | `mailserv/src/spool.rs:247` |
| M14 | Medium | Delivered mail and spool files are 0644 (umask), maildir renames aren't followed by a directory fsync, and encryption-at-rest is bypassed by plaintext maildir copies | `delivery.rs`, `spool.rs` |
| M15 | Medium | Authority hot-reload: one bad publish makes *every* RCPT fail with 451 until fixed, and it re-parses on every RCPT | `mailserv/src/authority.rs:423-439` |
| M16 | Medium | AUTH: no limit on failed attempts, LOGIN state survives a `*` abort, mechanism names are case-sensitive | `mailserv/src/main.rs:543-615` |
| M17 | Medium | DKIM: no minimum RSA key size (RFC 8301), `l=` honoured, `h=` not required to include From, duplicate tags allowed | `dkim/src/lib.rs` |
| L1–L12 | Low | See §Low | various |

---

## Critical

### C1. Path traversal / arbitrary file write through the recipient local-part **[verified]**

> **Round-2 status: ✅ FIXED [verified]. RCPT-time allow-list plus sink-side component check. See N4 for the side effects.**

`MaildirSink::deliver` builds the target directory as
`self.root.join(&domain).join(&local)` (`delivery.rs:76`), using the local-part
from the envelope exactly as the client sent it, apart from lowercasing. Under
the default `StaticAuthority` (used whenever `--authority` isn't given), *every*
local-part at a hosted domain is accepted and routed to itself
(`authority.rs`, `StaticAuthority::resolve`). Nothing anywhere rejects `/`
(which is legal `atext` in RFC 5321) or `..`.

- A relative path (`RCPT TO:<../../x@domain>`) climbs out of the maildir root.
- An absolute path (`RCPT TO:</some/dir@domain>`) **replaces** the whole path,
  because `Path::join` with an absolute component discards the prefix.

Reproduced against the running server: both
`RCPT TO:<$SCRATCH/run/abs_escape@mail.test>` and
`RCPT TO:<../../traversal@mail.test>` got `250` and wrote
`…/abs_escape/new/<id>.eml` and `…/traversal/new/<id>.eml` outside the
maildir root. The attacker picks the directory and controls the file
contents, so files can be dropped into web roots or any directory tree
the service user owns, or injected into other tenants' maildirs.
`create_dir_all` also lets them create arbitrary directory trees.

**Fix:** validate local-parts strictly at RCPT time (reject `/`, `\`, NUL,
leading `.`, `..`). Better, map mailboxes to opaque IDs (a hash or the
authority's mailbox ID) instead of putting user-supplied strings into
paths. As defence in depth, canonicalise the path and assert it is still
under `root`.

### C2. SMTP smuggling / command injection from inside DATA **[verified]**

> **Round-2 status: ⚠️ PARTIALLY FIXED [verified]. Verbs inside DATA are now data and a bare-LF `.` is data, but `<LF>.<CRLF>` still ends DATA. See N1.**

`handler()` checks for `RSET` and `QUIT` **before** the `Data` state arm
(`smtp/src/lib.rs:536-541`), so a message-body line whose first word is
`RSET` (any case) ends the transaction. Every later body line is then
handled as an SMTP command. The DATA terminator also accepts a bare-LF
`.` (`content == b"."` after stripping just `\n`, line 544).

Reproduced: a DATA body containing
`RSET / EHLO / MAIL FROM / RCPT TO:<smuggled@…> / DATA / … / .` dropped
the real message for `bob@` and **delivered a second, attacker-composed
message** to `smuggled@`. A body with `first\n.\nNOOP\r\n` ended the
message at the bare-LF dot and ran `NOOP` as a command.

This is the SMTP-smuggling class (CVE-2023-51764/51765/51766). If a
legitimate relay (e.g. a large provider's outbound MTA) passes such a
body through, the injected message comes from *that relay's IP*, so SPF
for the provider's customer domains passes and spoofed mail is accepted
as authentic. DESIGN §4.1 documents both behaviours as features.

**Fix:** in `Data`/`Discard` state treat every line as data. Only
`<CRLF>.<CRLF>` may end DATA. Reject bare LF (and bare CR) in DATA with
`5xx`, or at least never treat `\n.\n` as the terminator.

### C3. DKIM verdicts accumulate across messages: DMARC bypass

> **Round-2 status: ✅ FIXED. DMARC uses only this message's DKIM results (the regression test needs live DNS, see N6).**

`end_data` appends this message's results to `self.dkim` (`main.rs:842`),
then evaluates DMARC over **all of `self.dkim`** (`main.rs:871-875`).
`clear_envelope()` never clears `self.dkim`, and neither does
`tls_established()`.

Attack: on one connection, first send any genuine DKIM-signed message
from `bank.example` (e.g. a replay of a newsletter the attacker received),
then send a forged `From: security@bank.example` message with no
signature. The second message's DMARC check sees
`("bank.example", verified=true)` left over from the first message, so
`dkim_aligned = true` and `p=reject` doesn't apply. The spool metadata
for message 2 correctly shows *no* DKIM results, which hides the cause.

**Fix:** use only the current message's results (`dkim_summaries`) for
DMARC. Reset per-message verdict state in `clear_envelope()`, keep a
separate session-level list for logging if wanted, and add a
multi-message regression test.

### C4. DMARC is skipped whenever header parsing fails **[verified]**

> **Round-2 status: ⚠️ PARTIALLY FIXED [verified]. Missing, multiple and 8-bit `From:` headers are rejected, but the new scanner can be bypassed (N3) and rejects folded `From:` headers (N2).**

`from_domain = mailparse::parse_message(&raw).ok().and_then(...)`
(`main.rs:850`). Any parse error gives `None`, and then **no DMARC check
runs at all** and the message is accepted. Confirmed with the real crate:

- two `From:` headers → `Err(InvalidMailbox)` (`mailparse/src/lib.rs:711-716`);
- one `0xFF` byte in any header (e.g. `Subject:`) → `Err(InvalidUtf8)`
  (`lib.rs:128`). The header block must be entirely UTF-8, which real
  8-bit mail often isn't;
- any header the pest grammar rejects (`parse_headers` is all-or-nothing).

A message with no `From:` also skips DMARC. So an attacker can make any
spoofed `p=reject` message pass just by adding a duplicate `From:` or one
high byte. RFC 7489 §6.6.1 says messages with multiple From domains (or
no From) should be rejected, not let through.

**Fix:** extract the From domain from the raw header view (which already
tolerates bad bytes), and make "no From", "multiple From" or "unparseable
From" a hard reject (5.7.1) or at least a DMARC fail. Never fail open.

---

## High

### H1. SPF `a`, `mx`, `ptr` and `exists` query the wrong record type

> **Round-2 status: ✅ FIXED. Queries type 1, with a wire-level test. AAAA/IPv6 still open.**

`DotResolver::a` calls `self.query(domain, 0x16)` (`spf/src/lib.rs:213`).
`0x16` is 22 (NSAP-PTR); an A record is type `0x01`. Every `a`, `mx`
(exchange address), `ptr` (forward confirmation) and `exists` lookup gets
no A answers. Consequences:

- `v=spf1 mx -all` / `v=spf1 a -all`: legitimate senders get **Fail → 550**.
- Each empty lookup counts as a void lookup, so records with three or more
  `a`/`mx` lookups hit the 2-void limit: **PermError → 550**.
- `exists:` never matches.

The unit tests use a `MockResolver` that bypasses `DotResolver`, so the
bug is invisible to the suite. There is also no AAAA support, so
`a`/`mx` can never match IPv6 senders (`check_ipv4` only).

**Fix:** use type 1 (and add AAAA, type 28, for IPv6 peers), and add a
test that runs `DotResolver` against the mock DoT server already in
`dns` tests.

### H2. SPF macro expansion corrupts domain-specs **[verified]**

> **Round-2 status: ❌ NOT FIXED. Parser unchanged.**

`expand_macro_string` (`parser.rs:364`) doesn't parse `%{…}` macros. After
the first `%` it replaces *every* character that happens to be a macro
letter (`s l o d i p h c r t v`) anywhere in the rest of the string.
Real-code output for `exists:%{i}._spf.mta.salesforce.com` with sender
`user@sender.example`:

```
192.0.2.1._user@sender.examplepf.m2026-11-22T00:03:29Za.user@sender.exampleausereuser@...
```

Transformers (`%{ir}`, `%{d2}`), delimiters, and the `%%`/`%_`/`%-`
escapes aren't supported. Large senders (Salesforce, Mimecast and others)
rely on macros, so their mail gets the wrong verdict. The expanded name
also contains attacker-controlled text (the sender local-part) at
unexpected positions in DNS queries.

**Fix:** write a real RFC 7208 §7 macro parser. If that's not done yet,
return PermError for records with macros rather than guessing.

### H3. ESMTP parameters on MAIL FROM corrupt the address **[verified]**

> **Round-2 status: ❌ NOT FIXED [verified]. `clean_path` unchanged; `MAIL FROM:<> SIZE=100` still gets `501`.**

`clean_path` (`main.rs:278`) trims `<`/`>` only at the very ends of the
string. With `MAIL FROM:<ceo@bank.example> SIZE=1234`, the address
becomes `ceo@bank.example> SIZE=1234` and the "domain" becomes
`bank.example> SIZE=1234`. The server advertises `SIZE`, so compliant
MTAs (Postfix, Exim, etc.) do send it. Results:

- **SPF bypass:** the bogus domain gets NXDOMAIN, so SPF is `None` and the
  message is accepted. Any sender can dodge an `-all` record by adding a
  parameter.
- **Legitimate mail loses SPF Pass.** DMARC SPF alignment never succeeds
  for parameter-sending MTAs, so domains that rely on SPF alignment get
  rejected under `p=reject`.
- **Every bounce/DSN carrying SIZE= is refused:** `MAIL FROM:<> SIZE=1000` → `501 5.1.7`
  (reproduced).
- The broken string ends up in `Return-Path:` and the spool metadata.

**Fix:** parse `Reverse-path [SP Mail-parameters]` as RFC 5321 §4.1.2
defines it: take the angle-bracketed path, then parse and validate the
parameters (and enforce `SIZE=` against the limit). Do the same for RCPT.

### H4. Message lines starting with `QUIT` (or `RSET`) are protocol commands **[verified]**

> **Round-2 status: ✅ FIXED [verified]. Same framing change as C2.**

Same root cause as C2, but it also breaks ordinary mail. A body line such
as `Quit smoking today!` gives `221 Bye` and closes the connection mid-DATA
(reproduced; nothing was spooled). The sending MTA retries, hits the same
line every time, and finally bounces. Ordinary prose containing that line
is undeliverable to this server. `split_verb` splits on the first space,
so the line only has to *begin* with the word.

### H5. Refused connections stall the whole accept loop

> **Round-2 status: ✅ FIXED. Refusals are spawned into a pool of 32 permits.**

`refuse()` is awaited **inside** the accept loop (`main.rs:1226,1238`).
It can take up to 2 s for the write, and it always waits up to 500 ms
reading toward EOF. An attacker holding `max-conn-per-ip` (10) sockets
open, or filling global capacity, makes each further connection attempt
block `accept()` for at least 0.5 s. Two attempts per second from one IP
starve every legitimate sender: a network-wide MX outage for almost no
traffic. The limiter, meant to protect the server, becomes the
amplifier.

**Fix:** `tokio::spawn` the refusal (with its own small global cap), or
write the 421 without the linger-read.

### H6. One serialized DNS connection shared by the whole process, with no connect timeout

> **Round-2 status: ⚠️ PARTIALLY FIXED. Connecting is time-limited; the single serialized connection (head-of-line blocking) remains.**

`DnsClient::query` holds `self.conn` (an async mutex) across the entire
exchange (`dns/src/lib.rs:322-360`). `connect()` (TCP + TLS) has **no
timeout**, only the exchange does. As a result:

- If the resolver blackholes SYNs, the first query waits for the kernel
  connect timeout (around 2 minutes) while holding the mutex. Every SPF,
  DKIM and DMARC lookup in every session queues behind it.
- An attacker publishes SPF/DKIM records pointing at names whose
  authoritative servers never answer. Each lookup holds the global
  connection for the 5 s timeout, and one MAIL FROM can trigger up to 10
  of them (≈50 s). A few concurrent connections freeze DNS for all
  legitimate mail, and those sessions then hit the 30 s connection cap.
- A timeout returns an error straight away with no retry, so SPF returns
  TempError (451) and DMARC fails open (M6). Slowing DNS therefore also
  *disables* DMARC enforcement.

PLAN acknowledges "contention at very high query rates" but not this
attacker-driven, head-of-line case. **Fix:** a connection pool or DNS
pipelining (DoT supports out-of-order replies by ID), a connect timeout,
per-session lookup deadlines, and concurrent dispatch.

### H7. Unlimited DKIM signatures: CPU and DNS amplification

> **Round-2 status: ❌ NOT FIXED. `verify_dkim` unchanged.**

`verify_dkim` loops over every `DKIM-Signature` header
(`dkim/src/lib.rs:1368`). For each one it does a key lookup (serialized
DNS, see H6), a full body canonicalisation and hash (up to 1 MiB each),
and an RSA/Ed25519 verify. All of this runs inside `end_data` **on the
async executor thread**, not in `spawn_blocking`. A 1 MiB message can
hold more than 10,000 signature headers, which means more than 10 GB of
hashing plus 10,000 DNS queries, all from one message.

**Fix:** cap the number of signatures evaluated (e.g. 5–10), dedupe
body-hash work by `(c=, l=)`, and run verification on the blocking pool
under a deadline.

### H8. Grace-mode domains refuse all permanent mailboxes

> **Round-2 status: ✅ FIXED. `is_none_or` plus a 366-day cap and tests.**

In `DomainPolicy::Grace` (`authority.rs:249-251`):

```rust
let in_grace = mb.expires.is_some_and(|exp| now < exp + days*86400);
```

A mailbox with `expires: null` (permanent, which the docs call the
default) gives `in_grace = false` and **Refuse(Expired)**. Addresses with
a future or recent expiry date are handled correctly; only permanent ones
are refused. The docs ("Permanent addresses never age out") say the
opposite. The grace test only covers
expired addresses. Every permanent user on a grace domain silently loses
mail with `550 5.1.1`. A large `grace-days` value (`u64 as i64`, then
`* 86400`) can also overflow.

**Fix:** `mb.expires.is_none_or(|exp| now < exp + grace)`, use checked
arithmetic, and add tests for a permanent mailbox and an unexpired one.

---

## Medium

**M1. SPF parsing stops silently at the first term it doesn't recognise [verified].**
`parse()` breaks out of the loop when a term is neither a directive nor a
modifier (`parser.rs:166-175`) and returns the terms so far. The logos
lexer is case-sensitive, but RFC 7208 mechanism names are
case-insensitive. Real-code results: `v=spf1 ip4:192.0.2.0/24 -ALL` loses
`-ALL`, so senders outside the range get Neutral (accepted) instead of
Fail. `v=spf1 foo:bar -all` gives zero terms, so Neutral instead of
PermError. A bad `ip4:` value has the same effect. CIDR suffixes on
`a`/`mx` (`a/24`, `mx/24`) are ignored or fail to lex. `v=spf10`
matches `starts_with("v=spf1")`. Fix: return PermError on any
unparseable term and lex case-insensitively.

**M2. SPF lookup budget is over-counted.** `check_mx_record` spends budget
for every MX exchange, and `check_ptr_record` for every PTR name. RFC 7208
§4.6.4 counts only the `mx`/`ptr` term itself; the per-host address
lookups have their own limit of 10. Large legitimate records (several
includes plus multiple MX hosts) therefore hit PermError → **550**.

**M3. DMARC organisational domain is wrong for multi-label public suffixes.**
`fetch_policy` falls back to the last two labels (`dmarc/src/lib.rs:248`).
For `From: x@alerts.bank.co.uk`, it fetches `_dmarc.co.uk` instead of
`_dmarc.bank.co.uk`. The bank's policy is never found and spoofed
subdomain mail is accepted. This affects every ccTLD second-level
registry (`co.uk`, `com.au`, `co.jp`, …). Use the Public Suffix List.

**M4. `sp=` is never applied [verified].** `main.rs:883` calls
`record.policy_for(&from_domain, &from_domain)`, so `is_subdomain` is
always false. A domain with `p=none; sp=reject` gets **no** protection for
its subdomains; `p=reject; sp=none` rejects subdomain mail the owner
wanted only monitored. `fetch_policy` needs to return the domain the
record was found at.

**M5. Relaxed alignment is "one is a suffix of the other", not "same
organisational domain" [verified].** `aligned_relaxed("news.example.com",
"mail.example.com")` returns `false`. RFC 7489 §3.1 treats those as
aligned. Legitimate mail where the DKIM `d=`/MAIL FROM domain is a
sibling subdomain of the From domain fails DMARC and is **rejected**
under `p=reject`.

**M6. DMARC fails open; quarantine does nothing.** A DNS error from
`fetch_policy` is logged and treated as "no record" (`main.rs:859-866`).
Combined with H6, anyone who can slow DNS disables `p=reject`. Consider
451 on TempError for domains known to publish `p=reject`, or at least
mark the message. `Action::Quarantine` is computed and then ignored: the
message is delivered normally with no header, flag, or separate folder.

**M7. No `Authentication-Results:` header; forged ones pass through.** As
the final MTA, the server should prepend an RFC 8601
`Authentication-Results:` header (SPF/DKIM/DMARC verdicts). It should
also remove or rename inbound `Authentication-Results` headers claiming
its own authserv-id (RFC 8601 §5). As it stands, attacker-supplied
`Authentication-Results: …; dmarc=pass` headers reach users' mailboxes
and MUAs/filters may trust them. The verdicts exist only in the spool
JSON, which is deleted after delivery.

**M8. Trace-header injection.** `prepare_for_delivery`
(`delivery.rs:182-190`) copies `helo`, `mail_from` and the recipient into
`Return-Path:`/`Received:` without validation. The command reader strips
only the *trailing* `\r\n`, so an embedded bare CR (`EHLO x\rX-Spam: no`)
survives `from_utf8` and is written into the header. Some MUAs and parsers
treat a lone CR as a line break, which allows header injection. Free text
in HELO (`EHLO trusted.example (10.0.0.1) by internal`) also forges
plausible trace data. Validate HELO as a domain or address literal and
MAIL/RCPT as RFC 5321 paths, and reject control characters.

**M9. Catch-all deliveries collapse into one copy.** The idempotency
filename is `{queue_id}.{sanitize(mailbox)}.eml` (`delivery.rs:84-86`),
where `mailbox` is the *routed* mailbox. Under catch-all, `a@`, `b@` and
`c@` in one transaction all route to `admin@`, so the second and third
copies "already exist" and are skipped. Only the first copy's
`Received: … for <a@…>` survives. The disposable-address flagship use
case depends on knowing which address received the mail (often hidden by
BCC). Include the envelope address in the idempotency key. Separately,
sanitisation is lossy (`a+b@x` and `a_b@x` collide), and MUAs moving
files from `new/` to `cur/` defeat the `exists()` check, so re-delivery
duplicates.

**M10. State-machine sequencing bugs [verified].** *(Round 2: partially fixed. RSET keeps the session greeted and unknown verbs keep their state; the 503/EHLO-reset/AUTH-length items are still open.)*
- `RSET` sets the state to `Idle` (`smtp/src/lib.rs:537`). RFC 5321 §4.1.1.5
  keeps the session greeted. Reproduced: `EHLO, MAIL, RCPT, RSET, MAIL` →
  `500 Unknown`. Clients that RSET between transactions (common with
  connection reuse) break.
- The fallback arm `_ => (UNKNOWN, Idle)` (line 678) drops to Idle on any
  unknown or out-of-state verb *without* calling `reset()`. Reproduced:
  after `BOGUS`, a re-EHLO and then `MAIL` returned
  `503 Multiple MAIL FROM` because the old envelope was still set. EHLO
  also doesn't reset the transaction (RFC 5321 §4.1.4).
- `MAIL`/`RCPT`/`DATA` sent before EHLO get `500 Unknown` rather than
  `503`. `VRFY`/`EXPN` reply `250 Ok` (PLAN Phase 9 tracks this). The
  512-octet command cap also truncates long `AUTH PLAIN` initial
  responses (RFC 4954 allows 12,288).

**M11. 30 s whole-connection cap.** `timeout_at(max_conn_duration_ms)`
(`main.rs:1257`) covers the TLS handshake, DATA transfer, DNS (up to
roughly 50 s alone under H6), DKIM, spool fsync and fast-path delivery.
RFC 5321 §4.5.3.2 recommends a DATA timeout of 10 minutes. Large or slow
legitimate transfers get cut off. Worse, if the cap fires after the spool
write succeeds but before `250` is sent, the future is dropped. The client
sees no reply, retries, and the message is **delivered twice**. The
connection also closes without a 421, and the session summary log is
skipped. Prefer per-phase timeouts, and never cancel between commit and
reply.

**M12. Limiter scalability and leaks.** `release()` runs `entries.retain`
over the entire map on every connection close (`limit.rs:132`), all under
one mutex. An IPv6 attacker rotating source addresses (one /64 holds 2⁶⁴)
grows the map to rate × 60 s and makes every release O(n). The
per-address design also means a /64 bypasses the per-IP caps entirely
(acknowledged in PLAN). `limiter.release(ip)` (`main.rs:1272`) runs only
if the spawned task finishes normally. A panic in the session (pest,
deku, rsa, `expect`s on poisoned locks) leaks the active count, and after
10 such panics that IP is locked out permanently. Use an RAII guard.

**M13. Drain loads the whole queue into memory.** `DiskSpool::list()`
reads every payload into a `Vec` each pass (`spool.rs:247-290`). A backlog
(sink outage, disk-full on the maildir volume) of N × 1 MiB messages
needs N MiB of RAM every 60 s, so roughly 10k queued messages risks OOM.
Stream the entries and load each payload only when needed.

**M14. Storage hygiene.**
- Files are created with the process umask. Verified: delivered `.eml` is
  `0644` and directories are `0755`, so mail is world-readable to other
  local users. Use `0600`/`0700` explicitly.
- `MaildirSink::deliver` fsyncs the file but not the `new/` directory
  after the rename. Once the fast path removes the spool entry, a power
  loss can lose a message that already got `250`. The spool only does a
  best-effort fsync of `new/`, never of `tmp/`.
- Encryption at rest (Phase 12) only applies to the spool. The fast-path
  delivery writes the **plaintext** `raw` to the maildir. If an encryptor
  were set, the drain would also prepend plaintext headers onto
  ciphertext. The sink needs to be in the encryption boundary before the
  feature means anything.
- Only 5 drain passes at 60 s intervals (about 5 minutes) before
  dead-lettering. Accepted mail stuck behind a short disk incident ends up
  in `dead-letter/` with no alerting. Crash debris in `tmp/` is never
  cleaned up.

**M15. Authority reload behaviour.** *(Round 2: fixed. The last good snapshot is kept and the change check uses (mtime, size); but see N5, the failure is now silent.)* In `FileAuthority::current()`
(`authority.rs:423-439`), the doc comment says a failed reload keeps the
"running policy". In fact it returns `Err`, so every RCPT for **every
hosted domain** gets 451 until the file is fixed. The mtime isn't
updated on failure, so every RCPT re-reads and re-parses the whole file
under the write lock. A console writing the file non-atomically causes
451 bursts. If two writes happen within one mtime tick, the second is
missed (e.g. an address expiry that never takes effect). Keep serving the
last good snapshot (log loudly), require atomic rename publishes, and
compare a content hash or size as well as mtime.

**M16. AUTH weaknesses** (post-V1, but the code is live whenever
`--auth-users` is set):
- There is no failed-attempt limit, delay or lockout. With 60
  connections per minute per IP and unlimited attempts per connection
  within 30 s, online guessing is fast. Comparison is a plain `==`, which
  is not constant-time.
- The protocol layer handles `*` aborts but never tells the policy, so
  `auth_login_user` and `auth_pending` survive. `AUTH LOGIN dXNlcg==` → `*`
  → `AUTH LOGIN` → the next line, intended as a *username*, is checked as
  the *password* for the stale user. `AUTH LOGIN <bad-base64>` also leaves
  `auth_pending = LOGIN` set.
- `"PLAIN"`/`"LOGIN"` are matched case-sensitively; SASL names are
  case-insensitive (`auth plain` → 504).
- Credentials are plaintext, as already documented.

**M17. DKIM verifier gaps.**
- No minimum RSA modulus. RFC 8301 says keys under 1024 bits MUST NOT be
  considered valid, so a 512-bit key (factorable) is accepted as an
  aligned pass.
- `l=` is honoured (`dkim/src/lib.rs:476`). Content appended after the
  signed length still verifies, so a replayed legitimate signature can
  carry attacker text into a DMARC-passing message. Either ignore
  signatures with `l=` or flag unsigned trailing content.
- RFC 6376 §5.4 says signatures whose `h=` omits `From` MUST fail. This
  isn't checked.
- Duplicate tags are allowed (later value wins) instead of PERMFAIL.
- The algorithm is chosen from the key's `k=`, not checked against the
  signature's `a=`.
- Bottom-up header selection is correct, but combined with C4 (duplicate
  From → parse error) the "extra unsigned From" attack is just accepted.

---

## Low

- **L1. DNS label encoding doesn't validate lengths** [verified]
  (`dns/src/proto/mod.rs:481`). `part.len() as u8` with a 200-byte label
  writes `0xC8`, which a resolver reads as a *compression pointer*. Labels
  of 256 bytes or more wrap around. Empty labels (`a..b`, a trailing dot)
  emit a 0 terminator mid-name. The question-echo check blocks spoofing,
  but the query is malformed and the domains involved can be
  attacker-supplied (SPF and DKIM `d=`/`s=`). Enforce ≤63 octets per label
  and ≤255 per name.
- **L2. DNS cache wipes everything when full** (`dns/src/lib.rs:201`). The
  4,096-entry cache does `clear()` on overflow, so an attacker generating
  unique names (SPF macros, random DKIM selectors) keeps it permanently
  cold and amplifies H6.
- **L3. Third-party resolver trust and privacy.** Every sender domain,
  DKIM selector and client IP (via `%{i}`/PTR) goes to Cloudflare 1.1.1.1
  by default. There's no DNSSEC/AD-bit use and the resolver is IPv4 only.
  Document this, and default to a local validating resolver.
- **L4. HELO SPF is evaluated on every EHLO**, including after STARTTLS. A
  client can send many EHLOs per connection, each costing up to 10 DNS
  lookups. `self.helo` is also set before a HELO rejection.
- **L5. `redirect=` to a domain with no record** returns `None` (accept)
  instead of PermError (RFC 7208 §6.1). Recipients are also never
  de-duplicated: `RCPT TO:<a@x>` 100 times counts toward the 100-recipient
  cap.
- **L6. Logs grow with every data line.** `#[instrument]` on `recv_data`
  emits START/END span events at INFO for **every line of DATA**
  (observed in the test log: 14 lines gave 28 events). A 1 MiB message of
  one-byte lines produces about a million log records, a cheap way to
  fill the disk. Skip instrumenting `recv_data`, or lower its level.
- **L7. The session summary logs extra data.** `serde_json::to_string(&session)`
  includes `auth_login_user` and, if the connection drops mid-transaction,
  `rcpt_to` with users' public keys. It also includes the unbounded
  accumulated `dkim` list.
- **L8. `run()` ignores write errors.** Write failures (`let _ =
  stream.write_all`) are discarded. The loop continues until the next read
  fails, and `end_data` can spool and deliver mail to a peer that has
  already gone.
- **L9. `DnsClient::query` cache key vs query name.** The cache key uses
  `domain.trim().to_ascii_lowercase()` but the query sends the untrimmed
  name, so `" x"` and `"x"` share a cache entry but produce different
  wire queries.
- **L10. TLS operations.** There's no certificate reload (a restart is
  needed on renewal) and no SNI, so multi-tenant use needs one cert for
  all domains (already in PLAN). STARTTLS buffer flushing *is* handled
  correctly (`into_inner()` drops the buffered plaintext, so there's no
  CVE-2011-0411-style injection).
- **L11. Config footguns.** `--auth-users` can't hold passwords containing
  `,`. A missing `--tls-key` with `--tls-cert` is caught, but
  `--auth-users` without TLS gives a server that advertises nothing and
  says nothing at startup. The README says the default `--port` is 2525
  while production examples use 25. That's fine, but nothing warns about
  running as root to bind port 25.
- **L12. `query_tls`/`query_tcp` (dnsq paths).** These build a new rustls
  config and root store on every call and `unwrap()` `ServerName`. They're
  CLI-only, so low impact.

---

## Design observations

1. **The protocol/policy seam has the wrong boundary for DATA.** C2 and H4
   both come from the protocol layer treating commands as valid in every
   state. The seam would be stronger if `Data`/`Discard` were a separate
   framing mode with exactly one exit (`CRLF.CRLF`).
2. **Verdict state has no lifecycle.** Per-message fields (`dkim`, `dmarc`,
   `spf_result`) and per-session fields (`helo`, `spf_helo`,
   `authenticated`) live together in `UserSession`, cleared by hand in
   several places. C3 is the result. Split them into a `Transaction`
   struct that is created at MAIL and dropped at end-of-data or RSET.
3. **Fail-open paths in a "binding policy" design.** DESIGN §1 says policy
   verdicts bind, yet DMARC is skipped on a parse error (C4), on a DNS
   error (M6), with ESMTP parameters (H3), or with a lowercase `-all`
   (M1). Make every policy input total: unknown means fail or tempfail,
   never accept.
4. **Receive-only V1 still ships MSA exemptions.** Authenticated users skip
   SPF and DMARC rejection and can set any `From:`. For a receive-only
   product, `--auth-users` gives anyone holding a credential an
   unrestricted spoofing channel into every hosted mailbox. Disable AUTH
   in V1 builds, or at least don't advertise it on port 25.
5. **The StaticAuthority fallback is the default and the riskiest path.**
   It accepts every local-part, which makes C1 reachable and makes the
   server a catch-all for dictionary attacks with unbounded per-address
   directory creation (each probe address creates a maildir). Consider
   requiring `--authority` outside of development.
6. **Idempotency key design** (M9) and **commit vs reply ordering** (M11)
   both need explicit treatment before the S3 and console backends are
   built on top of them.
7. **The SMTP 512-byte cap applies before AUTH framing**, and the 64 KiB
   data line cap is larger than RFC 5321's 1000, which helps smuggling-style
   parser differentials with downstream systems. Consider 998+CRLF, with a
   configurable escape hatch.

---

## Documentation inconsistencies

- DESIGN.md §1 says "It does **not** yet deliver mail", and README's note
  says "not yet delivered to mailboxes". Both contradict DESIGN §10, README's
  `--maildir-dir` row and PLAN Phase 7, which describe local maildir
  delivery as implemented.
- Test counts: DESIGN §1 and README say **145** tests; DESIGN §9 and PLAN
  say **181**. 181 is correct.
- The README workspace table says `dns` has "DNS-over-TLS/TCP/UDP
  transports", but UDP was retired (DESIGN §6).
- PLAN Phase 7 says the queue ID is `<hex-millis>.<uuid>`; the code uses
  hex **seconds** (`spool.rs`, `as_second()`).
- PLAN gap 7 still says the "per-query DoT connection … one fresh TLS
  connection per query is the dominant cost", which Phase 10's
  `DnsClient` already changed.
- `dkim/src/lib.rs` has two module headers; the second says
  "cryptographic verification … not yet implemented" and that TXT records
  are truncated. Both are out of date.
- DESIGN §4.1 describes bare-LF termination and RSET/QUIT handling
  mid-DATA as features; see C2 and H4.
- `FileAuthority::current` docs say a failed reload doesn't disturb
  running policy; see M15.
- The README says the suite is "offline-deterministic except" the
  mailserv integration tests. CI runs those tests too, so CI depends on
  live 1.1.1.1 reachability.

---

## Test-coverage gaps worth closing (each maps to a finding)

1. Two messages on one connection: DKIM from message 1 must not count for message 2 (C3).
2. RCPT local-parts containing `/` and `..` are refused (C1).
3. DATA bodies containing `RSET`/`QUIT` lines and `\n.\n` (C2, H4).
4. `MAIL FROM:<a@b> SIZE=10` and `MAIL FROM:<> SIZE=10` (H3).
5. `DotResolver` against the mock DoT server, to check the query type (H1).
6. SPF records with macros, upper-case mechanisms, and unknown terms (H2, M1).
7. Duplicate-From and 8-bit-header messages under `p=reject` (C4).
8. Grace domain with a permanent mailbox (H8).
9. `sp=` and sibling-subdomain alignment (M4, M5).
10. `RSET` followed by `MAIL` without re-EHLO (M10).
