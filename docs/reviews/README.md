# Security and design reviews (archive)

These are the review reports written during November 2026, kept **as
written**. Each is a snapshot of the tree it names: its line numbers, test
counts and "open" lists describe that tree, not the current code. Don't
work from them directly. Open work lives in [PLAN.md](../../PLAN.md) (by
description, without finding IDs), and the current design and its gaps in
[DESIGN.md](../../DESIGN.md).

| Report | Date | Tree reviewed | Finding IDs |
|---|---|---|---|
| [REPORT.md](REPORT.md) | 2026-11-21 | `6b0a655`, then rounds up to `5af4540` | C1–C4, H1–H8, M1–M17, L1–L12, N1–N19 |
| [SECURITY.md](SECURITY.md) | 2026-11-22 | `d014804` | S1–S2 (and re-checks of REPORT's IDs) |
| [SECURITY-AUDIT.md](SECURITY-AUDIT.md) | 2026-11-22 | `640b60e` + working tree | F1–F10, and its own L1–L9 |
| [AUDIT.md](AUDIT.md) | 2026-11-22 | `640b60e` + working tree | Re-checks of REPORT's and SECURITY.md's IDs |
| [FINDINGS.md](FINDINGS.md) | 2026-11-22 | `8e3a643` | Design and code quality (D-W, C-W); carried into PLAN.md §4 |

The deployment review's D1–D7 lived in DEPLOYMENT.md until it was rewritten
as a pure checklist; read them with `git show b6bfaf9:DEPLOYMENT.md`.

Note that `L1`–`L9` mean different things in REPORT.md and
SECURITY-AUDIT.md; the tables below keep them apart.

## Where each finding stands (2026-11-23)

**Fixed** means fixed in code with a test. **Open** items are in PLAN.md at
the section given.

### REPORT.md

| ID | Finding | Status |
|---|---|---|
| C1 | Path traversal through the recipient local-part | Fixed |
| C2 | SMTP smuggling from inside DATA | Fixed |
| C3 | DKIM verdicts carried across messages into DMARC | Fixed |
| C4 | DMARC skipped when header parsing failed | Fixed |
| H1 | SPF `a`/`mx`/`ptr`/`exists` queried the wrong record type | Fixed. (SPF still doesn't query AAAA: PLAN §6) |
| H2 | SPF macro expansion corrupted domain-specs | Fixed |
| H3 | ESMTP parameters on MAIL FROM corrupted the address | Fixed |
| H4 | `QUIT`/`RSET` lines inside DATA acted as commands | Fixed |
| H5 | Refused connections stalled the accept loop | Fixed |
| H6 | One serialized DNS connection for the whole process | Fixed (pipelined client, per-IP DNS limit) |
| H7 | Unlimited DKIM signatures per message | Fixed (at most 5) |
| H8 | Grace-mode domains refused permanent mailboxes | Fixed |
| M1 | SPF parser stopped at the first unknown term | Fixed |
| M2 | SPF budget over-counts `mx`/`ptr` address lookups | Open (§2.4.3) |
| M3 | DMARC organisational domain was "last two labels" | Fixed (parent-domain walk) |
| M4 | DMARC `sp=` never applied | Fixed |
| M5 | Relaxed alignment is a suffix test | Open (§2.4.3) |
| M6 | DMARC failed open on DNS errors; `quarantine` a no-op | Fixed; `quarantine` delivered normally by decision |
| M7 | No `Authentication-Results:` | Open (§2.4.4) |
| M8 | HELO/MAIL FROM text copied into trace headers | Fixed |
| M9 | Catch-all copies collapse | Fixed (2026-11-23): one file per envelope address |
| M10 | State-machine sequencing | Partly fixed; pre-EHLO `503`, EHLO reset, long AUTH PLAIN open (§2.4.5) |
| M11 | Connection cap can fire after the spool commit (duplicates) | Fixed (2026-11-23): the deadline is enforced between reads, and the fast path runs after the reply |
| M12 | Per-IP connection count released by hand | Open (§2.4.5) |
| M13 | Drain loaded every queued payload each pass | Fixed |
| M14 | File modes; maildir directory fsync; maildir bypasses encryption | Modes fixed; fsync and `tmp/` sweep open (§2.4.5); encryption ordering fixed (trace headers are inside the stored payload, delivered verbatim) |
| M15 | A bad authority publish failed every RCPT | Fixed (last good snapshot kept) |
| M16 | AUTH weaknesses | Fixed (2026-11-23): argon2id-hashed credentials file, per-session and per-IP attempt limits, case-insensitive mechanisms, LOGIN state reset, AUTH only on submission ports (587/465). Credentials reload on SIGHUP added (2026-11-23) |
| M17 | DKIM: RSA floor, `l=`, From in `h=`, duplicate tags | Fixed except duplicate tags and `k=`/`a=` (§2.4.5) |
| L1 | DNS label lengths not validated | Fixed |
| L2 | DNS cache cleared wholesale when full | Open, accepted (bounded memory) |
| L3 | Third-party resolver privacy; no DNSSEC | Mitigated by `--resolver-ca` (local resolver possible); DNSSEC is the resolver's job |
| L4 | HELO SPF evaluated on every EHLO | Open, accepted (per-IP DNS limit bounds it) |
| L5 | `redirect=` to a domain with no SPF record returns `None` | Fixed (2026-11-23): PermError |
| L6 | Every DATA line logged | Fixed (span at `trace`) |
| L7 | Session summary logs extra fields | Open, low |
| L8 | `run()` ignores write errors | Open, low (the next read ends the session) |
| L9 | DNS cache key differed from the query name | Fixed |
| L10 | No TLS certificate reload | Open (§6); restart hook in DEPLOYMENT.md |
| L11 | Config footguns (`--auth-users` in argv, commas in passwords) | Fixed by the credentials file (2026-11-23) |
| L12 | `dnsq` one-shot queries: per-call TLS config, no timeout | Timeout added (2026-11-23); per-call config kept (CLI only) |
| N1 | `<LF>.<CRLF>` ended DATA | Fixed |
| N2 | Folded `From:` headers lost | Fixed |
| N3 | `From:` scanner steered by comments and quotes | Fixed |
| N4 | Local-part allow-list rejected valid addresses | Fixed |
| N5 | Failed authority reload was silent | Fixed (logged at `error`) |
| N6 | A DMARC test used live DNS | Fixed (mock DoT resolver; since 2026-11-23 no test uses live DNS except one `#[ignore]`d DKIM test) |
| N7 | Documentation accuracy | Fixed |
| N8 | Bare CR hid a header from the `From:` scanner | Fixed (`550 5.6.0`) |
| N9 | Display-name spoofing | Open (§2.4.4) |
| N10 | No storage quotas | Open (§2.4.1) |
| N11 | DKIM gave no result when `mailparse` rejected the message | Fixed (raw view) |
| N12 | SPF macro expander lenient on malformed input | Fixed (malformed macros are PermError) |
| N13 | A deadline threw away a warm DNS connection | Fixed (pipelining) |
| N14 | Shell metacharacters allowed in maildir directory names | Open, operational: never pass maildir paths through a shell |
| N15 | Several message copies held at once | Open (§2.4.5) |
| N16 | No SPF alignment for bounces | Open (§2.4.3) |
| N17 | SPF deadline and connection cap interact | Fixed: the cap no longer interrupts processing (see M11) |
| N18 | Documentation overstated status | Fixed |
| N19 | IPv4-mapped peers broke SPF on an IPv6 listener | Fixed |

### SECURITY.md

| ID | Finding | Status |
|---|---|---|
| S1 | Stack overflow from nested header comments | Fixed |
| S2 | DKIM `h=` selection O(h × headers) | Fixed |

### SECURITY-AUDIT.md

| ID | Finding | Status |
|---|---|---|
| F1 | DMARC failed open on lookup errors | Fixed (`451 4.4.3`) |
| F2 | DMARC policy discovery used the last two labels | Fixed |
| F3 | Bare CR hid a second `From:` | Fixed |
| F4 | SPF parser weakened hard-fail records | Fixed |
| F5 | DKIM: short RSA keys, `l=`, From not required in `h=` | Fixed |
| F6 | Duplicates when the cap fires after commit | Fixed (= M11) |
| F7 | Accepted mail dead-lettered after ~5 minutes | Fixed (5-day retry with backoff) |
| F8 | No storage bound; drain loaded every payload | Payload loading fixed; quotas open (§2.4.1) |
| F9 | Unlimited recipient probing | Open (§2.4.2) |
| F10 | AUTH hardening | Fixed; see M16 |
| L1 | `create_owned_dir_all` `chown`s by path | Open (§2.4.5) |
| L2 | `create_private_file` follows symlinks | Open, low (parent directories are private) |
| L3 | Catch-all copies collapse | Fixed (= M9) |
| L4 | Per-IP limits not aggregated per IPv6 /64 | Open (§6, IPv6 readiness) |
| L5 | Per-IP count leaks on panic | Open (= M12) |
| L6 | No `Authentication-Results:` | Open (= M7) |
| L7 | RCPT success cache outlives a revocation for the session | Accepted (bounded by the 5-minute cap) |
| L8 | No SPF alignment for the null sender | Open (= N16) |
| L9 | EHLO doesn't reset the envelope; pre-EHLO `500` | Open (= M10) |

### DEPLOYMENT.md (D1–D7, in git history)

| ID | Finding | Status |
|---|---|---|
| D1 | Every DATA line logged twice | Fixed |
| D2 | Only public DoT resolvers usable | Fixed (`--resolver-ca`); IPv6 resolver addresses open (§6) |
| D3 | Malformed query names cost a full timeout; no end-of-data DNS deadline | Fixed |
| D4 | Unsafe defaults, no privilege drop or graceful shutdown | Fixed |
| D5 | Peak memory per session | Sizing guidance in DEPLOYMENT.md B2; fewer copies open (§2.4.5) |
| D6 | Postmaster must be routable | Configuration (DEPLOYMENT.md C2) |
| D7 | Documentation status gaps | Fixed |
