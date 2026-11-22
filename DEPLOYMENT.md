# DEPLOYMENT.md — VPS Readiness Assessment and Deployment Checklist

**Assessed:** commit `d014804` ("dns pipelining finished") on `main`, 2026-11-22.
**Target:** a receive-only public MX on a single Linux VPS (systemd), V1 scope
per DESIGN.md §1. No outbound mail, no submission.
**Baseline:** `cargo fmt --check` clean, `cargo clippy --workspace
--all-targets -D warnings` clean, `cargo test --workspace` **207 passed, 0
failed, 1 ignored**.

This document is the go/no-go record. It covers:
1. the readiness verdict;
2. new findings from this review (D1–D7);
3. every open finding, classified for go-live;
4. the deployment steps, each with a check;
5. runbooks and the sign-off list.

Finding IDs (C/H/M/L/N) refer to REPORT.md. Items marked **[verified]**
were reproduced on the current code. The rest are from reading the code.

---

## 1. Readiness verdict

**Not ready for general production. Ready for a limited pilot** (a few
friendly domains, low volume, an operator watching the logs) once the two
code fixes in Phase A are merged and Phases B–H are complete.

| Area | State |
|---|---|
| Protocol safety (smuggling, framing, path traversal, header spoofing that skips DMARC) | ✅ Good. All round-1 criticals are fixed and regression-tested. |
| DNS robustness (pipelining, per-IP DNS limit, SPF deadline) | ✅ Good. The round-4 H6 re-open is resolved in `d014804`. |
| Durability (spool before `250`, idempotent delivery, retry and dead-letter) | ✅ Adequate for a pilot. See M11 and M14 for the edge cases. |
| **Operability** (logging, sizing, shutdown, privilege, paths) | ⚠️ **Configuration needed.** Log amplification (D1) is fixed; the rest is handled by configuration in Phases B, C and E. |
| **Abuse resistance** (disk exhaustion) | ⚠️ **Pilot only.** N10 has no quotas. Configuration narrows it; only code closes it. |
| **Mail-loss risk** (legitimate mail wrongly rejected) | ⚠️ **Pilot only.** M2, M5, N11 and N16 can permanently reject real mail. Acceptable while the logs are watched; fix before general availability. |
| Spoofing that reaches users (display names, bare-CR headers, no `Authentication-Results:`) | ⚠️ **Pilot only.** N8, N9, M7 and M8. |

**Go-live blockers** (all must be ✅ before port 25 is opened):
- ~~**D1:** per-DATA-line log spans.~~ ✅ **Fixed** (see D1 status).
- **N19:** IPv4-mapped peers break SPF. Fix in code (one line), or the
  configuration workaround in B4 (IPv4-only listener, no AAAA record).
- **Run with `--authority` in `reject` mode**, never the `StaticAuthority`
  fallback. Configuration (C1).
- **AUTH not configured.** Configuration (C1).
- **Storage on a dedicated filesystem, with disk alerts** (N10
  mitigation). Host and monitoring (B3, G1).

---

## 2. New findings from this review (D1–D7)

### D1. Every DATA line is logged twice, so logs are ~7× the mail volume (High for deployment) [verified]

> **Status: ✅ FIXED (2026-11-22).** `recv_data`'s span is now
> `level = "trace"` (`mailserv/src/main.rs`, above `fn recv_data`).
> Verified on the real binary at `RUST_LOG=info`: two 50-line messages
> now produce 41 log lines in total and **0** `RECV_DATA` records (one
> message produced 130 lines before). `RUST_LOG=trace` brings the span
> back for debugging. The findings below are kept as the record.

`#[instrument]` on `UserSession::recv_data` makes the bunyan layer write a
`[RECV_DATA - START]` and a `[RECV_DATA - END]` record (~280 bytes each)
for **every line of message data**, at INFO.

Measured: one 50-line message produced 130 log lines, 106 of them these
span records. A 1 MiB message of ordinary 76-character lines is about
13,800 lines, which comes to about 27,600 records and **~7.7 MB of logs
per 1 MiB of mail**. With `max-data-bytes` raised for real mail (see C1),
one 10 MiB message produces about 77 MB of logs.

- No `RUST_LOG` value suppresses them while keeping the INFO-level
  decision events. I tried `info,mailserv[recv_data]=off`,
  `info,[recv_data]=warn` and `warn,mailserv=info`; all still emitted
  106 span lines. `RUST_LOG=warn` would drop them, but also drops
  refusals, deliveries and DMARC verdicts.
- Consequences: an attacker can fill the disk through the logs. journald's
  default rate limit (10,000 messages / 30 s per unit) then **drops
  security events**. The `tracing_appender::non_blocking` writer is lossy
  by default, so lines are also dropped when its buffer fills.

**Remediation (Phase A1):** change the attribute on `recv_data`
(`mailserv/src/main.rs`) to `#[instrument(level = "trace", skip(self,
line), …)]`, or remove it. Then confirm with the log-volume smoke test
(F10).

### D2. The resolver must be a public DoT service (Medium, operational)

> **Status: ✅ RESOLVED (2026-11-22)** by `--resolver-ca <PEM>` /
> `resolver-ca`: its CA certificates are **added to** the public roots
> (`dns::DnsClient::with_extra_roots`), so a local resolver with a
> private or self-signed certificate can be used and public resolvers
> still work with the option set (verified live: DMARC lookups through
> 1.1.1.1 with a CA configured). The resolver's certificate must carry
> its IP as a subject alternative name. A missing, empty or invalid file
> stops startup before the port is bound (verified). See B6 for setup.
> **Still open:** IPv6 resolver addresses (`--resolver` is IPv4 only).

`dns::default_client_config` trusts only the `webpki_roots` public CA set,
and dials `--resolver` (IPv4 only) on port 853, validating the certificate
against the IP address.

- A local validating resolver (unbound or knot-resolver on 127.0.0.1, with
  a self-signed or private-CA certificate) **cannot be used**. Only public
  DoT services with publicly issued IP-address certificates work, such as
  `1.1.1.1`, `8.8.8.8` and `9.9.9.9`.
- Every sender domain, DKIM selector and (through SPF macros such as
  `%{i}`) client IP is therefore disclosed to that third party (L3). No
  DNSSEC validation status is used.

**Remediation:** for the pilot, choose the provider deliberately and
record it in the privacy notice (B6). Post-pilot, add a `--resolver-ca
<PEM>` option, so a local resolver with a private CA can be trusted, and
IPv6 resolver addresses.

### D3. Malformed query names cost a full timeout each (Low) [verified]

> **Status: ✅ FIXED (2026-11-22).** Both parts of the remediation are in:
> - **Names are checked before sending** (`dns::proto::check_name` /
>   `normalize_name`). An empty label, a label over 63 octets, or a name
>   over 253 is refused with `InvalidName` before capacity, connection or
>   network are touched, and the wire encoder refuses them too, which
>   closes **L1**. SPF treats such a name as nonexistent (RFC 7208 §4.3:
>   SPF `None`, a void lookup inside a record), and DKIM reports the key
>   lookup as failed at once. Names are normalized once, so the cache key
>   and the name sent match, which closes **L9**.
> - **End-of-data DNS deadline:** DKIM key lookups and the DMARC fetch
>   share one 20 s deadline (`END_OF_DATA_DNS_DEADLINE`). Running out gives
>   `451 4.4.3 Message checks timed out waiting for DNS`, never a
>   rejection, logged at `warn` with the stage.
>
> Verified live against 1.1.1.1: a message with five 70-octet DKIM
> selectors now gets its end-of-data reply in **0.17 s** (about 25 s
> before), and a MAIL FROM domain with a 64-octet label gets SPF `None` at
> once. Tests cover the name limits, the encoder, no network use for
> invalid names, trailing-dot cache sharing, SPF's empty answers, and the
> deadline firing at each stage against a resolver that never answers.

L1 is still open: label lengths aren't checked when encoding. Tested live
against 1.1.1.1 over the pipelined client:
- 70-byte and 200-byte labels are **silently dropped** by the resolver,
  so each query waits the full 5 s timeout;
- the connection survived (`connects=1`, `exchange_errors=0`), and ten
  concurrent unrelated queries all succeeded.

So there is no collateral damage with Cloudflare. But a sender controls
these names: each of up to 5 DKIM `s=`/`d=` values in its own message
costs 5 s at end-of-data. **End-of-data DNS (DKIM + DMARC) has no overall
deadline**, unlike SPF (20 s). Five 5 s timeouts plus the DMARC fetch
exceed the 30 s connection cap, and the session is then dropped with no
reply (M11/N17).

The harm falls on the attacker's own session and its per-IP DNS share,
so this is Low. Resolvers that answer FORMERR without echoing the
question would instead fail validation and tear down the shared
connection; that wasn't observed with 1.1.1.1. **Remediation:** reject
labels over 63 octets and names over 253 before querying (L1), and wrap
end-of-data DNS in a deadline like `spf::EVALUATION_DEADLINE`.

### D4. Defaults that are unsafe on a VPS (Medium, configuration)

> **Status: ✅ FIXED (2026-11-22)** in code, not just configuration:
> - **Defaults:** port 25; storage under `/var/lib/mailserv` (absolute;
>   a relative path is warned about at startup); 10 MiB messages; a
>   5-minute connection cap; 100 connections.
> - **Per-domain size limits:** `max-message-bytes` in the authority file
>   (can only lower `max-data-bytes`). Mixed-limit recipients are split
>   with `452`, and every size refusal is logged (`message refused: size
>   limit`). An aborted transfer now clears its transaction; it used to
>   leave the next MAIL failing with `503`.
> - **Permissions:** files `0600`, directories `0700` explicitly, plus
>   `umask 077`; a startup warning if a storage directory is open to others.
> - **Privilege dropping:** `--user`/`--group`. Root binds, reads the TLS
>   key, creates storage owned by the user, drops and verifies before
>   serving; root without `--user` is refused. *The real root drop is not
>   yet tested on a host: do it in E1.*
> - **Graceful shutdown:** SIGTERM/SIGINT refuses new connections, sends
>   idle sessions `421`, lets messages in progress finish, and exits when
>   all sessions end or after `shutdown-grace-ms` (60 s). Verified live.
>
> The table below is the original finding, kept as the record.

| Default | Problem | Remediation |
|---|---|---|
| `spool-dir = "spool"`, `maildir-dir = "maildir"` (relative) | Resolved against the working directory. Under systemd that is `/` unless `WorkingDirectory=` is set. | Absolute paths (C1) |
| `port = 2525`, `host = 0.0.0.0` | Not the MX port; IPv4 only, which is what B4 wants anyway. | `port = 25`, `host = "0.0.0.0"` (C1) |
| `max-data-bytes = 1048576` (1 MiB) | Real mail with attachments is routinely 5–25 MiB, so legitimate mail gets `552`. | Raise, within the memory budget (B2) |
| `max-conn-duration-ms = 30000` | Covers transfer, DNS and fsync together (M11). A large message on a slow link, or HELO SPF + MAIL SPF (N17), exceeds it, and the session is dropped silently. | `300000` (C1); per-phase timeouts later |
| `max-connections = 500` | With D4/N15 memory use, can exceed small-VPS RAM. | Size from B2 |
| Process umask | Mail is written `0644` / dirs `0755`, so it's readable by every local user (M14). | `UMask=0077` (or `0027` plus a group, if a reader process needs access) (E1) |
| No privilege dropping | Binding port 25 needs `CAP_NET_BIND_SERVICE`; there is no setuid/drop code. | Dedicated user with an ambient capability (E1) |
| No graceful shutdown | SIGTERM ends in-flight sessions mid-command; the senders retry. If a session had already spooled but not sent `250`, that message is **delivered twice** (M11). | Restart only in quiet periods (H4) |

### D5. Peak memory per session is ~2× `max-data-bytes` during DATA and up to ~6× at end-of-data (Medium, sizing)

During DATA, `self.data` is a growing `Vec`, whose capacity can reach 2×
its length. At end-of-data, N15's copies add up to four more (`raw`,
`write_raw`, the spool `payload`, one delivery copy).

**Estimate** (not measured under load): peak RSS ≈ baseline +
`max-connections` × 2 × `max-data-bytes` + (sessions finishing DATA at
once) × 4 × `max-data-bytes`.

| VPS RAM | Suggested `max-data-bytes` | Suggested `max-connections` | Worst case DATA-phase buffers |
|---|---|---|---|
| 2 GiB | 10 MiB | 40 | ~800 MiB |
| 4 GiB | 25 MiB | 50 | ~2.5 GiB |

With the new defaults (10 MiB × 100 connections), the worst-case
DATA-phase buffers are about 2 GiB, so on a 2 GiB VPS lower
`max-connections` to about 40 as in the table.

Set `MemoryMax=` (E1) so a spike kills and restarts only mailserv.
**Remediation (post-pilot):** fix N15 (`std::mem::take`, `Arc<[u8]>`).

### D6. Postmaster must be routable (Medium, configuration)

RFC 5321 §4.5.1 requires `postmaster@` to be accepted for every domain
the server accepts mail for. With `--authority`, only the mailboxes listed
in the file are accepted (in `reject` mode). Neither `--domain` nor
postmaster is added implicitly.

**Remediation:** add `postmaster@<domain>` (and preferably `abuse@`)
mailboxes for every hosted domain, and for the MX host's own domain if it
is listed (C2).

### D7. Documentation status gaps (Note)

- PLAN.md doesn't track round-4 findings N8–N19 at all. Its header says
  "all critical and high findings … are fixed", but N19 is High for
  deployment and open.
- REPORT.md's round-4 "Summary" still says H6 is open. Only the
  "Follow-up" note below it records the fix in `d014804`.
- README's "typical production-ish invocation" passes `--auth-users`.
  PLAN Phase 8 says "do not expose `auth-users` on internet-facing
  deployments", and AUTH has no role in a receive-only V1.

**Remediation:** add N8–N19 and D1–D7 to the PLAN §6 ledger and correct
its header. Fix the REPORT round-4 summary line. Replace the README
example with the config from C1.

---

## 3. Open findings, classified for go-live

**Legend:**
- **BLOCK**: must be resolved before opening port 25.
- **CONFIG**: mitigated by configuration in this checklist.
- **PILOT**: acceptable for a monitored pilot; fix before general
  availability.
- **LATER**: post-launch backlog.

| ID | Summary | Class | Mitigation in this checklist |
|---|---|---|---|
| D1 | Per-DATA-line log spans | ✅ FIXED | A1 (done) |
| N19 | IPv4-mapped peers break SPF on an IPv6 listener | **BLOCK** → CONFIG | A2 (code) or B4 (IPv4 only) |
| — | `StaticAuthority` fallback accepts every local-part | **BLOCK** → CONFIG | C1/C2: always `--authority`, `reject` mode |
| Design | AUTH enabled → spoofing channel for credential holders | **BLOCK** → CONFIG | C1: never set `auth-users` |
| N10 | No storage quotas (100× per message, unlimited maildirs) | **BLOCK** → CONFIG for the pilot | B3 dedicated filesystem, G1 alerts, C2 `reject` mode, avoid `catch-all` |
| D4 | Unsafe defaults (paths, size, duration cap, umask, privileges, shutdown) | ✅ FIXED | C1 (sizing only), E1 |
| D5 / N15 | Memory per session | CONFIG | B2 sizing, E1 `MemoryMax` |
| D6 | Postmaster not routable | CONFIG | C2 |
| D2 / L3 | Third-party DoT resolver only | ✅ RESOLVED (choice is now CONFIG) | B6: public provider, or a local resolver with `resolver-ca` |
| M14 | 0644 files, no directory fsync, maildir bypasses encryption | CONFIG (perms) / PILOT (fsync) | E1 `UMask=0077`; durability risk accepted |
| M11 / N17 | Whole-connection cap; duplicates on timeout | CONFIG / PILOT | C1 `max-conn-duration-ms = 300000` |
| L10 | No TLS reload | CONFIG | D3 restart hook |
| M2 | SPF budget over-counts MX/PTR lookups, giving spurious PermError → **550** | PILOT | G2: watch `SPF policy error` rejections |
| M5 | Relaxed alignment rejects sibling subdomains → **550** under `p=reject` | PILOT | G2: watch DMARC rejections |
| N11 | DKIM gives no results for non-UTF-8 headers → legitimate mail rejected | PILOT | G2 |
| N16 | Null-sender SPF never aligns → unsigned bounces from `p=reject` domains rejected | PILOT | G2 |
| M1 | SPF parser stops at unknown terms / case-sensitive (weaker, not stricter) | PILOT | — |
| M3 / M4 | DMARC org-domain heuristic; `sp=` ignored (missed spoofing) | PILOT | — |
| M6 | DMARC fails open on DNS errors; `quarantine` ignored | PILOT | G1: `dns stats` connect failures |
| M7 | No `Authentication-Results:`; forged ones kept | PILOT | Pilot users are told verdicts aren't shown |
| N8 / N9 / M8 | Bare-CR header hiding, display-name spoofing, HELO not validated | PILOT | — |
| M9 | Catch-all copies collapse | PILOT | C2: don't use `catch-all` in the pilot |
| M12 | Limiter sweep O(n); per-IP count leaks on panic | PILOT | E1 `Restart=always` clears leaks |
| M13 | Drain loads all queued payloads each pass | PILOT | G1 queue-depth alert |
| M16 | AUTH weaknesses | n/a while AUTH is unset | C1 |
| M17 | DKIM: no RSA floor, `l=` honoured, `h=` need not include From | PILOT | — |
| D3 / L1 | Malformed query names; no end-of-data DNS deadline | ✅ FIXED | — (L9 fixed with it) |
| N12, N14, L2, L4–L8, L11, L12 | Low items | LATER | N14: never pass maildir paths through a shell in ops scripts |
| D7 / N18 | Doc status gaps | LATER (before GA) | — |

---

## 4. Deployment checklist

Work top to bottom. Every step has a **Check** that must pass. Record who
did each one and when in §6.

### Phase A — Code fixes (before building the release)

- [x] **A1. Fix D1 (log spans).** Done: `recv_data`'s `#[instrument(...)]`
  is now `level = "trace"`. **Check:** F10 shows no `RECV_DATA` lines at
  `RUST_LOG=info` (already verified on a dev build; repeat on the VPS).
- [ ] **A2. Fix N19 (recommended even with B4).** Canonicalise the peer
  address once, in `handle_connection`, and the accept loop's
  `let ip = peer.ip()`. Use `peer.ip().to_canonical()` (keep the port),
  before `UserSession::new` and both limiters. Add a test that a
  `::ffff:192.0.2.1` peer matches `ip4:192.0.2.0/24`.
  **Check:** with `host = "[::]"`, EHLO answers `Hello [127.0.0.1]`, not
  `[::ffff:127.0.0.1]`.
- [ ] **A3. Run the CI gate:** `cargo fmt --all -- --check && cargo clippy
  --workspace --all-targets -- -D warnings && cargo test --workspace`.
  **Check:** all green. The `mailserv` integration tests need outbound
  DoT to 1.1.1.1 (README "Network caveat").
- [ ] **A4. Build and record the release:** `cargo build --release`,
  then record the commit hash and `sha256sum target/release/mailserv`.
  **Check:** the hash is in §6.

### Phase B — Host and capacity

- [ ] **B1. Provision the VPS.** Use a current, supported Linux with
  systemd. Enable time sync (`timedatectl` shows `System clock
  synchronized: yes`): DKIM `x=`, authority expiries and logs depend on
  it. Apply OS updates.
- [ ] **B2. Size memory (D5).** Choose `max-data-bytes` and
  `max-connections` from the D5 table for the VPS's RAM. Record them in C1.
  **Check:** at the end of F11, measured peak RSS (`systemctl status
  mailserv`) is under 60% of `MemoryMax`.
- [ ] **B3. Dedicated storage (N10).** Mount a separate filesystem (or LV)
  at `/var/lib/mailserv`, so a full mail store can't fill `/` or the
  journal. Size it to at least 10× the expected daily volume.
  **Check:** `findmnt /var/lib/mailserv` shows its own device.
- [ ] **B4. IPv4-only MX (N19 and missing SPF AAAA).** Unless A2 is merged
  *and* tested, listen on `0.0.0.0` only and **publish no AAAA record**
  for the MX host. Even with A2, SPF `a`/`mx` mechanisms don't resolve
  AAAA (H1 note), so IPv6 senders using them get SPF Fail. Stay
  IPv4-only for the pilot.
  **Check:** `dig AAAA mx1.<domain>` returns nothing.
- [ ] **B5. Firewall.**
  - Inbound: allow `25/tcp` from anywhere, and `22/tcp` from admin
    addresses only. Allow `80/tcp` only if certbot uses HTTP-01
    (otherwise use DNS-01).
  - Outbound: allow `853/tcp` to the chosen public resolver (or, with a
    local resolver, whatever *it* needs upstream, typically `53` or `853`),
    and `80`/`443` for updates and ACME.
  - Deny everything else, including `2525`.

  **Check:** from an outside host, `nc -vz mx1.<domain> 25` succeeds and
  `nc -vz mx1.<domain> 2525` fails.
- [ ] **B6. Choose the resolver (D2).** Either:
  - **Public DoT** (`1.1.1.1`, `9.9.9.9` or `8.8.8.8`): no `resolver-ca`
    needed. Record the choice and its privacy implications (sender domains
    and client IPs are disclosed to the provider) in the service's privacy
    notice. **Check:** `openssl s_client -connect <resolver>:853
    </dev/null` completes the handshake from the VPS.
  - **Local validating resolver** (recommended for privacy and DNSSEC):
    run unbound or knot-resolver listening for DoT on `127.0.0.1:853`.
    Give it a certificate whose subject alternative names include
    **`IP:127.0.0.1`** (mailserv verifies the IP, not a hostname), issued
    by a private CA or self-signed. Install the CA (or the self-signed
    certificate) as `/etc/mailserv/resolver-ca.pem` (`root:mailserv`,
    `0640`), and set `resolver = "127.0.0.1"` and `resolver-ca` in C1.
    For unbound, that is `interface: 127.0.0.1@853` with
    `tls-service-key` / `tls-service-pem`.
    **Check:** `openssl s_client -connect 127.0.0.1:853 -CAfile
    /etc/mailserv/resolver-ca.pem -verify_ip 127.0.0.1
    -verify_return_error </dev/null` verifies. The startup log shows
    `resolver CA loaded (trusted in addition to the public roots)`, and
    the first `dns stats` line shows `connect_failures=0`.
- [ ] **B7. Service account and directories.**
  ```sh
  useradd --system --home /var/lib/mailserv --shell /usr/sbin/nologin mailserv
  install -d -o mailserv -g mailserv -m 0700 /var/lib/mailserv /var/lib/mailserv/spool /var/lib/mailserv/maildir
  install -d -o root -g mailserv -m 0750 /etc/mailserv /etc/mailserv/tls
  install -o root -g root -m 0755 target/release/mailserv /usr/local/bin/mailserv
  ```

### Phase C — Configuration

- [ ] **C1. Write `/etc/mailserv/mailserv.toml`** (`root:mailserv`, `0640`):
  ```toml
  host = "0.0.0.0"                 # B4: IPv4 only for the pilot
  port = 25
  domain = "mx1.example.org"       # MX FQDN: banner, EHLO, Received: "by"
  max-data-bytes = 10485760        # 10 MiB, from B2
  max-connections = 40             # from B2
  max-conn-duration-ms = 300000    # D4/M11: 5 min, was 30 s
  max-read-duration-ms = 15000
  max-conn-per-ip = 10
  max-conn-rate-per-ip = 60
  max-dns-per-ip = 4
  dns-connections = 2
  resolver = "9.9.9.9"             # B6
  # resolver-ca = "/etc/mailserv/resolver-ca.pem"  # B6, local resolver only
  tls-cert = "/etc/mailserv/tls/fullchain.pem"
  tls-key  = "/etc/mailserv/tls/privkey.pem"
  spool-dir   = "/var/lib/mailserv/spool"     # D4: absolute
  maildir-dir = "/var/lib/mailserv/maildir"   # D4: absolute
  authority   = "/etc/mailserv/authority.json"  # never run without it
  # auth-users: DO NOT SET (receive-only V1; see REPORT design observations)
  ```
  **Check:** the startup log has `recipient authority ready` with
  `backend":"file"`, `STARTTLS available`, and **no** `AUTH PLAIN/LOGIN
  available` line.
- [ ] **C2. Write `/etc/mailserv/authority.json`.**
  - Use `reject` mode for every domain: **no `catch-all`** in the pilot
    (M9, N10).
  - Include `postmaster@` and `abuse@` for every domain (D6).
  - Keys are lowercase.
  - Publish atomically: write a temporary file in the same directory,
    then `mv` it over the original (the reload watches mtime and size).

  **Check:** `python3 -m json.tool` (or `jq .`) parses it, and the
  service starts. After any later edit, the log shows `recipient
  authority reloaded`, not `authority reload failed`.
- [ ] **C3. Environment:** `RUST_LOG=info` (set in the unit file). Don't
  use `debug` in production (volume).

### Phase D — DNS records and TLS

- [ ] **D1. Records for the MX host:** an `A` record for `mx1.example.org`
  pointing at the VPS IPv4, **no AAAA** (B4), and a PTR for the VPS IP
  set to `mx1.example.org` (hygiene; not required to receive).
- [ ] **D2. Certificate** for `mx1.example.org` (Let's Encrypt via
  `certbot certonly --standalone` with port 80 open temporarily, or
  DNS-01). Install the **full chain**: `rustls_pemfile` loads every
  certificate in `tls-cert`.
- [ ] **D3. Renewal hook (L10: no hot reload).**
  `/etc/letsencrypt/renewal-hooks/deploy/mailserv`:
  ```sh
  #!/bin/sh
  install -o root -g mailserv -m 0640 "$RENEWED_LINEAGE/fullchain.pem" /etc/mailserv/tls/fullchain.pem
  install -o root -g mailserv -m 0640 "$RENEWED_LINEAGE/privkey.pem"   /etc/mailserv/tls/privkey.pem
  systemctl restart mailserv
  ```
  **Check:** `certbot renew --dry-run` runs the hook, and F2 passes
  afterwards.
- [ ] **D4. Point each hosted domain's MX** at `mx1.example.org` **last**,
  after Phase F passes when connecting to the host directly by name or
  IP (F11, the real-sender test, comes after this switch). Use a low TTL
  (300 s) for the pilot so you can roll back quickly.

### Phase E — systemd unit

- [ ] **E1. `/etc/systemd/system/mailserv.service`:**
  ```ini
  [Unit]
  Description=mailserv receive-only MX
  After=network-online.target
  Wants=network-online.target

  [Service]
  User=mailserv
  Group=mailserv
  ExecStart=/usr/local/bin/mailserv --config /etc/mailserv/mailserv.toml
  WorkingDirectory=/var/lib/mailserv
  Environment=RUST_LOG=info
  # Port 25 without root (D4: no privilege-drop code)
  AmbientCapabilities=CAP_NET_BIND_SERVICE
  CapabilityBoundingSet=CAP_NET_BIND_SERVICE
  NoNewPrivileges=yes
  # M14: mail readable by the service user only
  UMask=0077
  ProtectSystem=strict
  ReadWritePaths=/var/lib/mailserv
  ProtectHome=yes
  PrivateTmp=yes
  PrivateDevices=yes
  ProtectKernelTunables=yes
  ProtectKernelModules=yes
  ProtectControlGroups=yes
  RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
  RestrictNamespaces=yes
  LockPersonality=yes
  # D5 sizing: set to the VPS budget for mailserv
  MemoryMax=1500M
  LimitNOFILE=8192
  # Clears M12 limiter leaks after a crash
  Restart=always
  RestartSec=2

  [Install]
  WantedBy=multi-user.target
  ```
  Then run `systemctl daemon-reload && systemctl enable --now mailserv`.
  **Check:** `systemd-analyze security mailserv` rates the unit "OK" or
  better. `ss -ltnp | grep :25` shows mailserv. `ps -o user= -C mailserv`
  shows `mailserv`, not `root`.

  **Alternative (built-in privilege drop):** start as root and let
  mailserv drop privileges itself. Remove `User=`, `Group=`,
  `AmbientCapabilities=` and `CapabilityBoundingSet=`, and set `user =
  "mailserv"` in C1 (or pass `--user mailserv`). mailserv then binds port
  25, reads the TLS key (which can stay `root:root 0600`), creates any
  missing storage directories owned by `mailserv`, and drops before
  serving. **This path has not been tested on a real host yet:** check
  that the log shows `privileges dropped after binding the port` and that
  `grep -E '^(Uid|Gid|Groups)' /proc/$(pgrep -x mailserv)/status` shows
  only mailserv's uid and gid, with no other groups. Starting as root
  without `user` is refused by design.
- [ ] **E2. Files are private.** After F5, `stat -c '%a' <delivered
  .eml>` shows `600`, and the maildir directories show `700`.

### Phase F — Smoke tests (from an external host; replace names)

Use `openssl s_client -starttls smtp -connect mx1.example.org:25 -crlf
-quiet` for TLS sessions, or `nc mx1.example.org 25` for plaintext ones.
Run the authority-dependent tests against a test domain listed in
`authority.json`.

- [ ] **F1. Banner and EHLO:** the banner is `220 mx1.example.org SMTP
  service ready`. EHLO lists `SIZE <max-data-bytes>` and `STARTTLS`, and
  **does not list `AUTH`**. The reply shows `Hello [<your IPv4>]`, not a
  `::ffff:` address (N19).
- [ ] **F2. TLS:**
  `openssl s_client -starttls smtp -connect mx1.example.org:25 -servername mx1.example.org -verify_return_error </dev/null`
  verifies the chain. Re-run it after D3.
- [ ] **F3. Closed relay:** `RCPT TO:<x@not-hosted.example>` → `550 5.7.1 Relay access denied`.
- [ ] **F4. Unknown recipient:** `RCPT TO:<nobody@<test-domain>>` → `550 5.1.1 No such mailbox`.
- [ ] **F5. Delivery:** send a message to a listed mailbox with a
  `From:` whose domain has no DMARC record → `250 Ok`. A file appears
  under `/var/lib/mailserv/maildir/<domain>/<local>/new/`, with
  `Return-Path:` and `Received:` headers.
- [ ] **F6. DMARC enforcement:** an unsigned message with `From:
  ceo@paypal.com` → `550 5.7.1 … DMARC policy`.
- [ ] **F7. From-header policy:** a message with no `From:`, or two
  `From:` headers → `550 5.7.1 Message rejected: missing or malformed From header`.
- [ ] **F8. Size:** `MAIL FROM:<> SIZE=<max+1>` → `552 5.3.4`, and `MAIL FROM:<> SIZE=100` → `250`.
- [ ] **F9. Protocol safety:**
  - `RCPT TO:<../../x@<test-domain>>` → `553 5.1.3`;
  - a DATA body containing `x\n.\r\nRSET\r\n…` produces exactly **one**
    reply, at the real `\r\n.\r\n`.
- [ ] **F10. Log volume (D1):** after one ~1,000-line message,
  `journalctl -u mailserv --since "-5 min" | grep -c RECV_DATA` is `0`,
  and the total log lines for the session are under about 50.
- [ ] **F11. Real senders:** send from at least Gmail, Outlook.com and one
  other provider to a pilot mailbox.
  **Check:** each is delivered, and the log's `dmarc evaluation` shows
  `dmarc_pass: true`. If any legitimate message is rejected, record its
  `spf_result`/`dkim`/`dmarc` lines and match them to M2, M5, N11 or N16
  before go-live.
- [ ] **F12. Restart recovery:** send a message, then immediately run
  `systemctl restart mailserv`.
  **Check:** the message is either delivered or still in
  `spool/new/`, and is delivered within 60 s of the restart (startup
  drain). Nothing goes to `dead-letter/`.

### Phase G — Monitoring and alerting

- [ ] **G1. Alerts** (any log shipper or a cron'd `journalctl` grep is
  enough for the pilot):

  | Signal | Source | Alert when |
  |---|---|---|
  | Disk usage of `/var/lib/mailserv` (bytes **and** inodes) | `df -h`, `df -i` | > 70% warn, > 85% page (N10) |
  | Dead letters | `ls /var/lib/mailserv/spool/dead-letter/*.json` | any file (accepted mail at risk) |
  | Queue depth | `ls /var/lib/mailserv/spool/new/*.json \| wc -l` | > 100 for 10 min (M13) |
  | `spool write failed; refusing with a temporary error` | log | any |
  | `authority reload failed; serving the last good policy (stale)` | log | any |
  | `delivery attempts exhausted; message dead-lettered` | log | any |
  | `fast-path delivery failed; queued for retry` / `delivery failed; message stays queued` | log | > 5 in 10 min |
  | `dns stats` with `connect_failures` rising or `timeouts` > 5% of queries | log, every 60 s | sustained 5 min (M6: DMARC fails open on DNS errors) |
  | `per-IP DNS limit: no permit within the wait; temporary failure` | log | > 20 in 10 min (attack, or `max-dns-per-ip` too low) |
  | `message refused: size limit` | log | daily review; a spike for one domain means its `max-message-bytes` may be too low |
  | `shutdown grace period over; closing the remaining sessions` | log | any (sessions were cut; raise `shutdown-grace-ms`) |
  | `end-of-data DNS checks exceeded their time limit; temporary failure` (and `spf evaluation exceeded its time limit; temperror`) | log | > 5 in 10 min (slow resolver or hostile records) |
  | `connection refused: server at capacity` | log | any sustained (capacity or attack) |
  | `connection exceeded the duration limit` | log | > 1% of sessions (M11) |
  | `connection handler failed` / `drain task panicked` / `spool task panicked` | log | any |
  | Service liveness | `systemctl is-active mailserv`, external TCP check on 25 | down for 1 min |
  | Certificate expiry | `openssl s_client … \| openssl x509 -noout -enddate` | < 14 days |
  | journald suppression | `journalctl -u systemd-journald \| grep Suppressed` | any line mentioning mailserv |

- [ ] **G2. Mail-loss review (pilot):** check the day's permanent
  rejections every day:
  ```sh
  journalctl -u mailserv --since today | grep -E '"(dmarc_action":"Reject|spf_result":"(PermError|Fail))'
  ```
  For each rejection, decide whether it was legitimate mail hit by M2,
  M5, N11 or N16, and keep a tally. Any legitimate rejection is a reason
  to prioritise that fix.

### Phase H — Backups and runbooks

- [ ] **H1. Backups:** nightly `restic`/`rsync` of
  `/var/lib/mailserv/maildir`, `/etc/mailserv/authority.json` and
  `/etc/mailserv/mailserv.toml`. The spool is transient, but include
  `spool/dead-letter/`. Keep the binary and its hash from A4 for
  rollback.
  **Check:** a test restore of one mailbox to a scratch directory
  succeeds.
- [ ] **H2. Runbook: re-queue a dead-lettered message** (after fixing the
  cause, e.g. a full disk):
  ```sh
  cd /var/lib/mailserv/spool
  id=<queue-id>
  mv dead-letter/$id.eml new/          # payload first
  mv dead-letter/$id.json new/         # metadata last: this is the commit point
  rm -f dead-letter/$id.attempts       # reset the 5-attempt budget
  ```
  The next drain pass (≤ 60 s) delivers it. Delivery is idempotent per
  recipient, so re-queuing an already-delivered message doesn't
  duplicate it, unless the user has since moved it from `new/` to `cur/`
  (M9).
- [ ] **H3. Runbook: disk full.** Spool writes fail, so senders get `451`
  and retry; nothing that was already accepted is lost. Delivery
  failures dead-letter after about 5 minutes. To recover:
  1. free space;
  2. re-queue dead letters (H2);
  3. find the cause: per-recipient or per-sender volume in `message
     spooled` / `recipient refused` logs (N10). Block an abusive source
     at the firewall if needed.
- [ ] **H4. Runbook: restart and upgrade.** `systemctl restart` sends
  SIGTERM, which shuts down gracefully (D4): idle sessions get `421`,
  messages in progress finish, up to `shutdown-grace-ms` (60 s, under
  systemd's 90 s `TimeoutStopSec`). Low-traffic restarts still minimise
  the M11 window.
  1. Install the new binary next to the old one.
  2. Run `systemctl restart mailserv`.
  3. Repeat F1–F3.
  4. To roll back, restore the A4 binary and restart.

  A restart can duplicate any message that was spooled but hadn't yet
  received its `250` (M11).
- [ ] **H5. Runbook: resolver outage.** If `dns stats` shows sustained
  connect failures, SPF returns TempError (`451`, so senders retry) and
  DMARC **fails open** (M6). Switch `resolver` in C1 to another DoT
  provider from B6, then `systemctl restart mailserv`.
- [ ] **H6. Runbook: authority publish.** Write to a temporary file, `jq .`
  it, then `mv` it into place, and confirm `recipient authority
  reloaded` in the log. If the log shows `authority reload failed`,
  **the previous policy is still in force**, including any address you
  meant to expire. Fix the file immediately.

---

## 5. Recommended fix order after the pilot starts

1. **Mail-loss group:** M2 (SPF budget), M5 (relaxed alignment by
   organisational domain), N11 (DKIM from the raw view), N16 (HELO
   alignment for bounces).
2. **N10:** per-domain and per-mailbox quotas, a cap on stored bytes per
   message, and a free-space tempfail (`452 4.3.1`). Then `catch-all`
   can be enabled.
3. **M11 / N17:** per-phase timeouts (the end-of-data DNS deadline from
   D3 is in). This removes the duplicates on timeout and allows the
   default connection cap to drop again.
4. **Spoofing presentation:** M7 (add and strip
   `Authentication-Results:`), N9 (display-name domain check), N8 and M8
   (bare CR in headers and HELO).
5. **N15:** memory copies. This allows larger `max-data-bytes` on the
   same RAM.
6. **Operability:** graceful shutdown (stop accepting, finish in-flight
   sessions), TLS hot reload (L10), IPv6 resolver addresses (D2 follow-up), and a metrics
   endpoint instead of log-only `dns stats`.
7. The remaining M- and L-tier items, and the documentation updates (D7).

---

## 6. Go/no-go sign-off

| Item | Owner | Date | Result / evidence |
|---|---|---|---|
| A1 log-span fix merged (commit) | | 2026-11-22 | Done in working tree; record commit hash |
| A2 IPv4-mapped fix merged, **or** B4 IPv4-only confirmed | | | |
| A3 CI gate green | | | |
| A4 release hash | | | |
| B1–B7 host ready | | | |
| C1–C3 configuration reviewed (no `auth-users`, `authority` set, absolute paths) | | | |
| D1–D3 DNS and TLS in place; D4 MX switched | | | |
| E1–E2 unit hardened, files `0600` | | | |
| F1–F12 smoke tests passed | | | |
| G1 alerts firing in a test (e.g. touch a fake dead-letter `.json`) | | | |
| H1 backup restore tested | | | |
| Pilot risk acceptance for the PILOT-class items in §3 | | | |

**Go** requires every row above to be filled in, and no BLOCK item in §3
left unresolved.
