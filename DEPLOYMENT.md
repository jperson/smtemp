# DEPLOYMENT.md — Go-live checklist

**Target:** a receive-only public MX on a single Linux VPS (systemd), V1
scope per [DESIGN.md](DESIGN.md) §1. No outbound mail. Submission (587/465)
exists but stays off for the pilot; [Enabling submission](#enabling-submission)
says what changes if you turn it on.

This document is the go/no-go record:
1. the readiness verdict;
2. the known limitations accepted for a pilot, and how this checklist
   contains them;
3. the deployment steps, each with a check;
4. the sign-off list.

What's left to fix in code is in [PLAN.md](PLAN.md); past security reviews
are archived in [docs/reviews/](docs/reviews/README.md).

---

## 1. Readiness verdict

**Not ready for general production. Ready for a limited pilot** (a few
friendly domains, low volume, an operator watching the logs) once the
release is built from a recorded commit (Phase A) and Phases B–H are
complete.

| Area | State |
|---|---|
| Protocol safety (smuggling, framing, path traversal, header-parser crashes) | ✅ Good. Covered by tests that reproduce each attack. |
| Spoofing that bypasses policy (SPF/DKIM/DMARC) | ✅ Good for a pilot. DMARC fails closed on lookup errors and finds policies at parent domains; bare-CR headers are refused; the SPF parser never weakens a `-all` record; DKIM enforces RFC 8301 key sizes, whole-body `l=` and `From` in `h=`. |
| DNS robustness | ✅ Good. Pipelined DoT connections, per-IP DNS limit, deadlines for SPF and end-of-data checks. |
| Durability (spool before `250`, idempotent delivery, retry, dead-letter) | ✅ Adequate for a pilot. Failed deliveries are retried for 5 days; crash debris is swept. Duplicates on a timeout remain possible (§2). |
| Operability (logging, sizing, shutdown, privileges, paths) | ⚠️ **Configuration needed** in Phases B, C and E. |
| Abuse resistance (disk exhaustion, recipient probing) | ⚠️ **Pilot only.** No quotas; unlimited address probing per session. Configuration and monitoring narrow both; only code closes them. |
| Legitimate mail wrongly rejected | ⚠️ **Pilot only.** Some legitimate mail can get a permanent `550` (§2). Acceptable while the logs are reviewed daily (G2). |
| Spoofing that reaches users (display names, no `Authentication-Results:`) | ⚠️ **Pilot only.** |

**Go-live blockers** (all must be done before port 25 is opened):
- the release is built from a recorded commit (A1–A3);
- mailserv runs with `authority` in `reject` mode, never the static
  fallback (C1, C2);
- submission is off: no `submission-port`, `submissions-port` or
  `auth-users-file` (C1);
- storage is on a dedicated filesystem, with disk alerts (B3, G1).

---

## 2. Known limitations accepted for the pilot

Each is contained by a step below and fixed in code later (PLAN.md).

| Limitation | Risk | Contained by | Fix |
|---|---|---|---|
| The static authority (no `authority` file) accepts every local-part | Any address at a hosted domain receives mail | C1, C2: always set `authority`, `reject` mode | Configuration |
| No storage quotas or free-disk check | A sender can fill the disk | B3 dedicated filesystem, G1 alerts, C2 `reject` mode, no `catch-all` | PLAN §2.4.1 |
| Unlimited refused RCPTs per session | Probing which addresses exist | G1 `recipient refused` alert; firewall abusive sources | PLAN §2.4.2 |
| The connection cap can fire after the spool commit, before the `250` | The sender retries and the message is delivered twice | C1 `max-conn-duration-ms = 300000`; G1 duration alert; restart in quiet periods (H4) | PLAN §2.4.3 |
| SPF budget over-counts `mx`/`ptr` lookups; relaxed DMARC alignment is a suffix test; no SPF alignment for bounces; malformed SPF records are PermError, as RFC 7208 requires | Legitimate mail gets a permanent `550` | G2 daily review of permanent rejections | PLAN §2.4.4 |
| No `Authentication-Results:`; display names unchecked | Users can be misled by forged headers or names | Tell pilot users that verdicts aren't shown | PLAN §2.4.5 |
| Maildir directory not fsynced after the rename | A power cut can lose a just-delivered file that was already dequeued | Accepted for the pilot | PLAN §2.4.6 |
| Per-IP connection count released by hand | A panicking session leaks one slot of its IP's budget | E1 `Restart=always` | PLAN §2.4.6 |
| Peak memory is about 2× `max-data-bytes` per session during DATA, up to 6× at end of data | Memory exhaustion | B2 sizing, E1 `MemoryMax` | PLAN §2.4.6 |
| SPF `a`/`mx` don't query AAAA; per-IP limits are per address | IPv6 senders can fail SPF or escape limits | B4: IPv4-only MX | PLAN §6 |
| No TLS certificate reload | A restart is needed to pick up a renewed certificate | D3 renewal hook | PLAN §6 |
| Local-parts may contain shell metacharacters (`$`, `` ` ``, `|`, `&` are valid in addresses) | Operator scripts could misbehave on maildir paths | Never pass maildir paths through a shell unquoted | — |

---

## 3. Deployment checklist

Work top to bottom. Every step has a **Check** that must pass. Record who
did each one and when in §4.

### Phase A — Release

- [ ] **A1. Run the CI gate:** `cargo fmt --all -- --check && cargo clippy
  --workspace --all-targets -- -D warnings && cargo test --workspace`.
  **Check:** all green. The `mailserv` integration tests need outbound
  DoT to 1.1.1.1 (README "Network caveat").
- [ ] **A2. Audit dependencies:** `cargo install cargo-audit && cargo
  audit --deny warnings` on the release commit (CI also runs it on every
  push and weekly). **Check:** clean. Accepted advisories are listed with
  their reasons in `.cargo/audit.toml`; copy any new one into §4.
- [ ] **A3. Build and record the release:** `cargo build --release`, then
  record the commit hash and `sha256sum target/release/mailserv`.
  **Check:** the hash is in §4.

### Phase B — Host and capacity

- [ ] **B1. Provision the VPS.** Use a current, supported Linux with
  systemd. Enable time sync (`timedatectl` shows `System clock
  synchronized: yes`): DKIM `x=`, authority expiries, the spool's debris
  sweep and logs depend on it. Apply OS updates.
- [ ] **B2. Size memory.** During DATA a session's buffer can reach about
  2× its message size, and at end of data up to four more copies exist
  briefly (spool write, delivery). Estimate peak RSS as baseline +
  `max-connections` × 2 × `max-data-bytes` + (sessions finishing DATA at
  once) × 4 × `max-data-bytes`:

  | VPS RAM | Suggested `max-data-bytes` | Suggested `max-connections` | Worst-case DATA-phase buffers |
  |---|---|---|---|
  | 2 GiB | 10 MiB | 40 | ~800 MiB |
  | 4 GiB | 25 MiB | 50 | ~2.5 GiB |

  The defaults (10 MiB × 100 connections) allow about 2 GiB of buffers, so
  on a 2 GiB VPS lower `max-connections` to about 40. Record the values in
  C1. **Check:** at the end of F11, measured peak RSS (`systemctl status
  mailserv`) is under 60% of `MemoryMax`.
- [ ] **B3. Dedicated storage.** Mount a separate filesystem (or LV) at
  `/var/lib/mailserv`, so a full mail store can't fill `/` or the journal.
  Size it to at least 10× the expected daily volume.
  **Check:** `findmnt /var/lib/mailserv` shows its own device.
- [ ] **B4. IPv4-only MX.** Listen on `0.0.0.0` only and **publish no
  AAAA record** for the MX host: SPF `a`/`mx` mechanisms don't resolve
  AAAA, so IPv6 senders authorised only through them would get SPF Fail,
  and per-IP limits don't aggregate IPv6 /64s.
  **Check:** `dig AAAA mx1.<domain>` returns nothing.
- [ ] **B5. Firewall.**
  - Inbound: allow `25/tcp` from anywhere, and `22/tcp` from admin
    addresses only. Allow `80/tcp` only if certbot uses HTTP-01
    (otherwise use DNS-01).
  - Outbound: allow `853/tcp` to the chosen public resolver (or, with a
    local resolver, whatever *it* needs upstream, typically `53` or `853`),
    and `80`/`443` for updates and ACME.
  - Deny everything else, including `2525`, and `587`/`465` unless
    submission is enabled.

  **Check:** from an outside host, `nc -vz mx1.<domain> 25` succeeds and
  `nc -vz mx1.<domain> 2525` fails.
- [ ] **B6. Choose the resolver.** mailserv speaks DNS-over-TLS only, to an
  IPv4 resolver, and verifies its certificate against the IP. Either:
  - **Public DoT** (`1.1.1.1`, `9.9.9.9` or `8.8.8.8`): no `resolver-ca`
    needed. Every sender domain, DKIM selector and (through SPF macros)
    client IP is disclosed to the provider: record the choice in the
    service's privacy notice. **Check:** `openssl s_client -connect
    <resolver>:853 </dev/null` completes the handshake from the VPS.
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
  max-conn-duration-ms = 300000    # 5 min
  max-read-duration-ms = 15000
  max-conn-per-ip = 10
  max-conn-rate-per-ip = 60
  max-dns-per-ip = 4
  dns-connections = 2
  resolver = "9.9.9.9"             # B6
  # resolver-ca = "/etc/mailserv/resolver-ca.pem"  # B6, local resolver only
  tls-cert = "/etc/mailserv/tls/fullchain.pem"
  tls-key  = "/etc/mailserv/tls/privkey.pem"
  spool-dir   = "/var/lib/mailserv/spool"
  maildir-dir = "/var/lib/mailserv/maildir"
  authority   = "/etc/mailserv/authority.json"  # never run without it
  # submission-port / submissions-port / auth-users-file / auth-senders:
  # not for the pilot (receive-only V1)
  ```
  **Check:** the startup log has `recipient authority ready` with
  `backend":"file"`, `STARTTLS available`, and **no** `AUTH PLAIN/LOGIN
  available` line.
- [ ] **C2. Write `/etc/mailserv/authority.json`.**
  - Use `reject` mode for every domain: **no `catch-all`** in the pilot
    (there are no storage quotas yet).
  - Include `postmaster@` (RFC 5321 §4.5.1 requires it for every domain
    the server accepts mail for) and `abuse@` for every hosted domain, and
    for the MX host's own domain if it is listed. Neither is added
    implicitly.
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
  DNS-01). Install the **full chain**: every certificate in `tls-cert` is
  loaded.
- [ ] **D3. Renewal hook** (there is no hot reload).
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
  # Port 25 without root. (mailserv can also drop privileges itself:
  # see the alternative below.)
  AmbientCapabilities=CAP_NET_BIND_SERVICE
  CapabilityBoundingSet=CAP_NET_BIND_SERVICE
  NoNewPrivileges=yes
  # Backstop: mailserv already creates files 0600 and directories 0700
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
  # B2 sizing: set to the VPS budget for mailserv
  MemoryMax=1500M
  LimitNOFILE=8192
  # Also clears a per-IP connection count leaked by a panicking session
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
  `::ffff:` address.
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
- [ ] **F6b. DMARC policy discovery:** an unsigned message with
  `From: ceo@payroll.nonexistent.bbc.co.uk` (a non-existent subdomain of a
  `p=reject` domain under a two-label suffix) → `550 5.7.1 … DMARC policy`.
  The log's `dmarc evaluation` shows `from_domain` as the subdomain and
  `dmarc_action":"Reject"`.
- [ ] **F7. Header policy:** a message with no `From:`, or two `From:`
  headers → `550 5.7.1 Message rejected: missing or malformed From
  header`. A header block containing a bare CR (`Subject: x\rFrom:
  ceo@paypal.com`, then a normal `From:` line) → `550 5.6.0 Message
  header contains a bare CR`. Also: `EHLO evil.example\rX: y` →
  `501 5.5.2`.
- [ ] **F8. Size:** `MAIL FROM:<> SIZE=<max+1>` → `552 5.3.4`, and `MAIL FROM:<> SIZE=100` → `250`.
- [ ] **F9. Protocol safety:**
  - `RCPT TO:<../../x@<test-domain>>` → `553 5.1.3`;
  - a DATA body containing `x\n.\r\nRSET\r\n…` produces exactly **one**
    reply, at the real `\r\n.\r\n`.
- [ ] **F10. Log volume:** after one ~1,000-line message,
  `journalctl -u mailserv --since "-5 min" | grep -c RECV_DATA` is `0`,
  and the total log lines for the session are under about 50.
- [ ] **F11. Real senders:** send from at least Gmail, Outlook.com and one
  other provider to a pilot mailbox.
  **Check:** each is delivered, and the log's `dmarc evaluation` shows
  `dmarc_pass: true`. If any legitimate message is rejected, record its
  `spf_result`/`dkim`/`dmarc` lines and match them to the §2 rejection
  causes before go-live.
- [ ] **F12. Restart recovery:** send a message, then immediately run
  `systemctl restart mailserv`.
  **Check:** the message is either delivered or still in
  `spool/new/`, and is delivered within 60 s of the restart (startup
  drain). Nothing goes to `dead-letter/`.
- [ ] **F13. Delivery outage:** make the maildir unwritable for a few
  minutes (`chmod 000 /var/lib/mailserv/maildir/<domain>/<local>/new`),
  send a message (it gets `250` and is spooled), then restore the mode.
  **Check:** the log shows `delivery deferred` with a growing
  `next_attempt_in_secs` (60, 120, 240 …), the message is delivered at the
  first retry after the restore (within ~10 minutes for a short outage),
  and nothing goes to `dead-letter/`. Run this on the test domain only.

### Phase G — Monitoring and alerting

- [ ] **G1. Alerts** (any log shipper or a cron'd `journalctl` grep is
  enough for the pilot):

  | Signal | Source | Alert when |
  |---|---|---|
  | Disk usage of `/var/lib/mailserv` (bytes **and** inodes) | `df -h`, `df -i` | > 70% warn, > 85% page (no quotas) |
  | Dead letters | `ls /var/lib/mailserv/spool/dead-letter/*.json` | any file (accepted mail at risk) |
  | Queue depth | `drain pass` log line (every 60 s while the queue is non-empty): `queued` field; or `ls /var/lib/mailserv/spool/new/*.json \| wc -l` | > 100 for 10 min, or any `queued` > 0 for 1 h (a delivery outage: mail is safe for 5 days, but find the cause) |
  | `removed uncommitted spool file (crash debris)` | log (`warn`) | any (a write was interrupted: look for a crash or a full disk around the file's time) |
  | `spool debris sweep failed` | log | any |
  | `spool write failed; refusing with a temporary error` | log | any |
  | `authority reload failed; serving the last good policy (stale)` | log | any |
  | `accepted message undeliverable for the queue lifetime; dead-lettered` (level `error`) | log | any (accepted mail left the queue undelivered: requeue with H2 after fixing the cause) |
  | `delivery deferred` | log | > 20 in 10 min (the delivery backend is failing) |
  | `fast-path delivery failed; queued for retry` / `delivery failed; message stays queued` | log | > 5 in 10 min |
  | `dns stats` with `connect_failures` rising or `timeouts` > 5% of queries | log, every 60 s | sustained 5 min (all mail is being deferred with `451`) |
  | `dmarc policy lookup failed; temporary failure` | log | > 5 in 10 min (resolver trouble: inbound mail is deferring) |
  | `multiple DMARC records; DMARC not applied` | log | daily review (a sender domain's misconfiguration) |
  | `message refused: bare CR in the header block` | log | daily review; a spike means a spoofing campaign |
  | `recipient refused` | log | > 50 in 10 min from one `peer` (address probing): block the source at the firewall |
  | `per-IP DNS limit: no permit within the wait; temporary failure` | log | > 20 in 10 min (attack, or `max-dns-per-ip` too low) |
  | `message refused: size limit` | log | daily review; a spike for one domain means its `max-message-bytes` may be too low |
  | `shutdown grace period over; closing the remaining sessions` | log | any (sessions were cut; raise `shutdown-grace-ms`) |
  | `end-of-data DNS checks exceeded their time limit; temporary failure` (and `spf evaluation exceeded its time limit; temperror`) | log | > 5 in 10 min (slow resolver or hostile records) |
  | `connection refused: server at capacity` | log | any sustained (capacity or attack) |
  | `connection exceeded the duration limit` | log | > 1% of sessions (each can mean a duplicate delivery) |
  | `connection handler failed` / `drain task panicked` / `spool task panicked` | log | any |
  | Service liveness | `systemctl is-active mailserv`, external TCP check on 25 | down for 1 min |
  | Certificate expiry | `openssl s_client … \| openssl x509 -noout -enddate` | < 14 days |
  | journald suppression | `journalctl -u systemd-journald \| grep Suppressed` | any line mentioning mailserv |

- [ ] **G2. Mail-loss review (pilot):** check the day's permanent
  rejections every day:
  ```sh
  journalctl -u mailserv --since today | grep -E '"(dmarc_action":"Reject|spf_result":"(PermError|Fail))'
  ```
  For each rejection, decide whether it was legitimate mail hit by one of
  the §2 rejection causes (the SPF budget, suffix-based alignment, bounce
  alignment, or a sender's malformed SPF record), and keep a tally. Any
  legitimate rejection is a reason to prioritise that fix (PLAN §2.4.4).

### Phase H — Backups and runbooks

- [ ] **H1. Backups:** nightly `restic`/`rsync` of
  `/var/lib/mailserv/maildir`, `/etc/mailserv/authority.json` and
  `/etc/mailserv/mailserv.toml`. The spool is transient, but include
  `spool/dead-letter/`. Keep the binary and its hash from A3 for
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
  rm -f dead-letter/$id.attempts       # reset the backoff and the 5-day lifetime
  ```
  With no `.attempts` record the message is due immediately, so the next
  drain pass (≤ 60 s) delivers it. Keeping the `.attempts` file would
  dead-letter it again at the next failure, because its lifetime clock
  would still be running from the first failure. (This exact sequence is
  the `dead_letters_only_after_the_queue_lifetime` test.) The debris sweep
  won't touch the `.eml` while it waits for its `.json`: the move resets
  its change time, and the sweep only removes files untouched for an hour.
  Delivery is idempotent per recipient, so re-queuing an already-delivered
  message doesn't duplicate it, unless the user has since moved it from
  `new/` to `cur/`.
- [ ] **H3. Runbook: disk full.** Spool writes fail, so senders get `451`
  and retry; nothing that was already accepted is lost. Deliveries of
  accepted mail fail, and are retried with backoff (1 min doubling to
  1 h) for 5 days, so nothing is dead-lettered unless the outage lasts
  that long. To recover:
  1. free space (queued mail is then delivered at each message's next
     retry, within an hour);
  2. re-queue anything that was dead-lettered (H2);
  3. find the cause: per-recipient or per-sender volume in `message
     spooled` / `recipient refused` logs. Block an abusive source at the
     firewall if needed.
- [ ] **H4. Runbook: restart and upgrade.** `systemctl restart` sends
  SIGTERM, which shuts down gracefully: idle sessions get `421`, messages
  in progress finish, up to `shutdown-grace-ms` (60 s, under systemd's
  90 s `TimeoutStopSec`). A session still mid-message when the grace
  period ends may already be spooled without its `250`, and its sender
  then delivers it again, so restart in quiet periods.
  1. Install the new binary next to the old one.
  2. Run `systemctl restart mailserv`.
  3. Repeat F1–F3.
  4. To roll back, restore the A3 binary and restart.
- [ ] **H5. Runbook: resolver outage.** If `dns stats` shows sustained
  connect failures, SPF returns TempError and the DMARC lookup fails, so
  inbound mail is deferred with `451` and senders retry. Nothing is
  accepted unchecked, but nothing is received either. Switch `resolver` in
  C1 to another DoT provider from B6, then `systemctl restart mailserv`.
- [ ] **H6. Runbook: authority publish.** Write to a temporary file, `jq .`
  it, then `mv` it into place, and confirm `recipient authority
  reloaded` in the log. If the log shows `authority reload failed`,
  **the previous policy is still in force**, including any address you
  meant to expire. Fix the file immediately.

### Enabling submission

Not part of the pilot. When it is wanted:
- Make the credentials file: `mailserv hash-password` per login, one
  `user:hash` line each, `root:root 0600`. Set `auth-users-file` and
  `auth-senders` (a login without grants can't send).
- Set `submission-port = 587` and/or `submissions-port = 465`. Both need
  `tls-cert`/`tls-key`; the startup check refuses them otherwise. AUTH is
  never offered on port 25.
- Open `587/tcp` and/or `465/tcp` in B5. The systemd unit's
  `CAP_NET_BIND_SERVICE` already covers them.
- Revoking a login means editing the file and restarting (no reload yet:
  PLAN §2.3).
- **Check:** `openssl s_client -connect mx1.<domain>:465 -quiet` then
  `EHLO x` lists `AUTH PLAIN LOGIN`; on port 25 after STARTTLS it
  doesn't, and `AUTH PLAIN` gets `502`; on 587, `MAIL FROM` before AUTH
  gets `530`.

---

## 4. Go/no-go sign-off

| Item | Owner | Date | Result / evidence |
|---|---|---|---|
| A1 CI gate green | | | |
| A2 dependency audit clean (or exceptions recorded) | | | |
| A3 release commit and binary hash | | | |
| B1–B7 host ready (incl. B4 IPv4-only) | | | |
| C1–C3 configuration reviewed (no submission ports or `auth-users-file`, `authority` set, absolute paths) | | | |
| D1–D3 DNS and TLS in place; D4 MX switched | | | |
| E1–E2 unit hardened, files `0600` | | | |
| F1–F13 smoke tests passed (incl. F6b) | | | |
| G1 alerts firing in a test (e.g. touch a fake dead-letter `.json`) | | | |
| H1 backup restore tested | | | |
| Pilot risk acceptance for the §2 limitations | | | |

**Go** requires every row above to be filled in, and every go-live
blocker in §1 to be done.
