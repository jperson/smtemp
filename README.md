# mailserv

A small inbound SMTP server (MX) written in Rust. It accepts mail over
plaintext or STARTTLS SMTP, checks **SPF**, **DKIM** and **DMARC** on every
message, accepts only recipients its **recipient authority** hosts, durably
spools what it accepts, and delivers it to local maildirs. Every decision is
logged as structured JSON (bunyan format); message bodies never are.

**V1 is receive-only.** Point a domain's MX records at mailserv and receive
mail at addresses defined in the authority file (permanent, or with an
optional expiry; disposable addresses are the flagship use case). It never
relays, sends, or generates bounces: undeliverable mail is refused at RCPT
time, so the sender's server bounces it. Optional submission ports (587,
465) take authenticated mail from mail clients for hosted recipients.

| Document | What it covers |
|---|---|
| [DESIGN.md](DESIGN.md) | How the system works today, and its known gaps |
| [PLAN.md](PLAN.md) | Everything left to do: open gaps, code quality, features |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Readiness verdict, accepted pilot limitations, and the go-live checklist |
| [docs/reviews/](docs/reviews/README.md) | Archived security and design reviews, with the current status of every finding |

**Status:** ready for a limited, monitored pilot (see DEPLOYMENT.md §1),
not yet for general production.

## Building

Stable Rust **1.100.0**, pinned in `rust-toolchain.toml` (`rustup` picks it
up automatically; Nix users can run `nix develop`, which also provides
`rust-analyzer` and `jq`).

```sh
cargo build --release        # → target/release/mailserv
```

## Running

`--domain` is the only required setting. Everything else has a production
default: port **25**, storage under **`/var/lib/mailserv`**.

**Local testing** (unprivileged, local directories):

```sh
cargo run -p mailserv -- --domain mail.test --port 2525 \
  --spool-dir ./spool --maildir-dir ./maildir
```

Without `--authority`, every local-part at `--domain` (and any
`--local-domains`) is accepted. That's convenient for testing, but **never
run an internet-facing server without `--authority`**.

**Production** (receive-only: no `--auth-users-file`):

```sh
sudo mailserv \
  --domain mx1.example.org \
  --user mailserv \
  --tls-cert /etc/mailserv/fullchain.pem \
  --tls-key /etc/mailserv/privkey.pem \
  --authority /etc/mailserv/authority.json \
  --resolver 9.9.9.9
```

Started as root, mailserv binds the port, reads the TLS key, then drops to
`--user` before opening storage or accepting connections. Running as root
without `--user` is refused. It can also run unprivileged with
`CAP_NET_BIND_SERVICE`. DEPLOYMENT.md has a hardened systemd unit for
either way.

**Shutdown.** SIGTERM or SIGINT shuts down gracefully:
- new connections are refused;
- idle sessions get `421` at once;
- a session in the middle of a message finishes it, gets its reply, then
  gets `421`;
- the process exits when every session has ended, or after
  `--shutdown-grace-ms`. A second signal exits immediately.

## Configuration

Settings come from three sources; the first one that sets a value wins:

1. command-line flags;
2. a TOML file given with `--config <file>`, whose keys are the flag names
   without the leading `--`;
3. built-in defaults.

### Options

**Listener and identity**

| Flag / config key | Default | Description |
|---|---|---|
| `--host` / `host` | `0.0.0.0` | Address to listen on. |
| `--port` / `port` | `25` | Port to listen on. Use `2525` for unprivileged testing. |
| `--submission-port` / `submission-port` | *(none)* | Also listen for message submission (normally `587`): plaintext, then STARTTLS. AUTH is offered only on submission ports, over TLS, and required before `MAIL FROM` (`530`). Needs `--tls-cert`, `--tls-key` and `--auth-users-file`. |
| `--submissions-port` / `submissions-port` | *(none)* | Also listen for submission over implicit TLS (normally `465`, RFC 8314). Same rules and requirements as `submission-port`. |
| `--domain` / `domain` | *(required)* | The server's own name: used in the `220` banner, EHLO replies and `Received: by`. Also a hosted domain when there's no `--authority`. |

**Recipients**

| Flag / config key | Default | Description |
|---|---|---|
| `--authority` / `authority` | *(none)* | Recipient authority file (JSON; see [schema](#authority-file)). Hosted domains, per-domain policy, mailboxes. Hot-reloaded on change. **Use it in production.** |
| `--local-domains` / `local-domains` | `--domain` | Comma-separated hosted domains for the no-authority fallback, which accepts every local-part. Ignored when `--authority` is set. |

**Limits**

| Flag / config key | Default | Description |
|---|---|---|
| `--max-data-bytes` / `max-data-bytes` | `10485760` (10 MiB) | Message size limit. It is advertised as `SIZE`, and larger messages get `552`. A hosted domain can set a lower limit in the authority file. |
| `--mailbox-quota-bytes` / `mailbox-quota-bytes` | `10485760` (10 MiB) | Default storage quota per mailbox (`0`: no default), for mailboxes whose authority entry and domain set no `quota-bytes` (see [Recipient authority](#recipient-authority)). A recipient whose mailbox is at its quota, or can't fit a declared `SIZE=`, gets `452 4.2.2 Mailbox full` at RCPT; the sender retries later, and the transaction's other recipients are unaffected. Soft: an undeclared message can take a mailbox one message over. |
| `--min-free-disk-bytes` / `min-free-disk-bytes` | `1073741824` (1 GiB) | Free space the spool and maildir filesystems must keep (`0`: no check). Below it, MAIL FROM and end of data get `452 4.3.1 Insufficient system storage`, so mail already accepted can still be delivered. |
| `--max-conn-duration-ms` / `max-conn-duration-ms` | `300000` (5 min) | Wall-clock cap per connection, including TLS and AUTH. |
| `--max-read-duration-ms` / `max-read-duration-ms` | `15000` | Per-read timeout; a silent client is dropped. |
| `--max-connections` / `max-connections` | `100` | Server-wide simultaneous connections. Over the limit: `421`. |
| `--max-conn-per-ip` / `max-conn-per-ip` | `10` | Simultaneous connections per source IP. |
| `--max-conn-rate-per-ip` / `max-conn-rate-per-ip` | `60` | New connections per 60 s per source IP. |
| `--max-dns-per-ip` / `max-dns-per-ip` | `4` | Concurrent DNS-backed checks (SPF, DKIM + DMARC) per source IP. A check over the limit waits up to 10 s, then gets `451 4.7.0` (never a permanent reject). `0` is a startup error. |

**TLS**

| Flag / config key | Default | Description |
|---|---|---|
| `--tls-cert` / `tls-cert` | *(none)* | PEM certificate chain for STARTTLS (needs `--tls-key`). Without it, STARTTLS is neither advertised nor accepted (`454`). |
| `--tls-key` / `tls-key` | *(none)* | PEM private key for STARTTLS. |

**DNS**

| Flag / config key | Default | Description |
|---|---|---|
| `--resolver` / `resolver` | `1.1.1.1` | Resolver for SPF, DKIM and DMARC, over **DNS-over-TLS (port 853)**. IPv4 only. Its certificate must name this IP; public DoT services (1.1.1.1, 9.9.9.9, 8.8.8.8) work as they are. |
| `--resolver-ca` / `resolver-ca` | *(none)* | PEM file of extra CA certificates for a local resolver with a private or self-signed certificate. They're added to the public roots, not substituted. A missing or invalid file is a startup error. |
| `--dns-connections` / `dns-connections` | `2` | Pipelined DoT connections (1–16), each carrying up to 64 queries in flight. Size it from the `dns stats` log line. |

**Storage**

| Flag / config key | Default | Description |
|---|---|---|
| `--spool-dir` / `spool-dir` | `/var/lib/mailserv/spool` | The queue. The `250` is sent only after a durable write there; a failed write gets `451`. |
| `--maildir-dir` / `maildir-dir` | `/var/lib/mailserv/maildir` | Delivery root: one maildir per mailbox, `{root}/{domain}/{local}/new`, one file per envelope address (`{queue-id}.{address}.eml`), so catch-all copies stay apart. |

**Privileges and shutdown**

| Flag / config key | Default | Description |
|---|---|---|
| `--user` / `user` | *(none)* | Account to switch to after binding when started as root (required then). Name or uid. |
| `--group` / `group` | user's primary group | Group for `--user` (needs `--user`). |
| `--shutdown-grace-ms` / `shutdown-grace-ms` | `60000` | How long in-progress sessions may take after SIGTERM/SIGINT. |

**AUTH (not for V1)**

| Flag / config key | Default | Description |
|---|---|---|
| `--auth-users-file` / `auth-users-file` | *(none)* | Credentials for AUTH PLAIN/LOGIN, offered only on the submission ports over TLS: a file with one `user:hash` per line, where `hash` is an argon2id string from `mailserv hash-password` (`#` comments and blank lines allowed; a plaintext password is a startup error). Read at startup, before privileges are dropped, and again on `SIGHUP` (`systemctl reload mailserv`) as the service user, so for reloads make it owner root, group the service group, mode `0640` (startup warns when the service user can't read it). A file other users can access is a startup error. A reload that fails keeps the current logins; a login removed by a reload can no longer authenticate or send. Failed attempts are limited to 3 per session and 10 per source IP per 15 minutes (then `454`). Port 25 never offers AUTH (`502`); without a submission port the logins can't be used, which is warned about. The old inline `auth-users` key is a startup error. |
| `--auth-senders` / `auth-senders` | *(none)* | What each AUTH login may send as: `user=grant\|grant,…`, each grant an address (`alice@example.org`) or a whole domain (`@example.net`). An authenticated `MAIL FROM` outside the grants gets `553 5.7.1` (the null sender always does), and a `From:` author outside them gets `550 5.7.1`. A login with no grants can't send. Grants for an unknown login, or this flag without `--auth-users-file`, are startup errors. |

| Flag | Description |
|---|---|
| `--config <FILE>` | TOML configuration file. |

To create a credentials file (the password is read without echo, twice;
it can also be piped in):

```sh
install -m 0600 /dev/null /etc/mailserv/auth-users
printf 'alice:%s\n' "$(mailserv hash-password)" >> /etc/mailserv/auth-users
```

### Config file example

```toml
# /etc/mailserv/mailserv.toml: every key is optional except domain.
host = "0.0.0.0"
port = 25
domain = "mx1.example.org"
user = "mailserv"                  # when started as root

authority = "/etc/mailserv/authority.json"
tls-cert = "/etc/mailserv/fullchain.pem"
tls-key = "/etc/mailserv/privkey.pem"

resolver = "9.9.9.9"
# resolver-ca = "/etc/mailserv/resolver-ca.pem"   # only for a local resolver
dns-connections = 2

spool-dir = "/var/lib/mailserv/spool"
maildir-dir = "/var/lib/mailserv/maildir"

max-data-bytes = 10485760
mailbox-quota-bytes = 10485760
min-free-disk-bytes = 1073741824
max-connections = 100
max-conn-per-ip = 10
max-conn-rate-per-ip = 60
max-dns-per-ip = 4
max-conn-duration-ms = 300000
max-read-duration-ms = 15000
shutdown-grace-ms = 60000

# auth-users-file / auth-senders: leave unset (receive-only V1).
```

### Environment

| Variable | Description |
|---|---|
| `RUST_LOG` | Log filter (`tracing` `EnvFilter` syntax). Default `info`. For example `RUST_LOG=debug`, or `RUST_LOG=mailserv=trace`. |

## Authority file

`--authority` points at a JSON document that the management console
publishes. It is reloaded when its modification time or size changes. A
malformed update is refused: the last good version stays in force, and the
failure is logged at `error`. Publish atomically: write a temporary file in
the same directory, then `mv` it into place.

```json
{
  "version": 1,
  "domains": {
    "example.org": { "mode": "reject", "quota-bytes": 1073741824 },
    "lists.example.org": { "mode": "catch-all", "catch-all-mailbox": "admin@example.org" },
    "legacy.example.net": { "mode": "grace", "grace-days": 7, "max-message-bytes": 5242880 }
  },
  "mailboxes": {
    "alice@example.org": {
      "user": "alice",
      "expires": null,
      "public-key": null,
      "key-generation": 2,
      "quota-bytes": 5368709120
    }
  }
}
```

- **`domains.*.mode`:**
  - `reject`: only listed, unexpired mailboxes accept mail;
  - `catch-all`: unknown addresses go to `catch-all-mailbox` (expired
    ones are still refused);
  - `grace`: an expired address keeps accepting for `grace-days` (up to
    366), then refuses.
- **`domains.*.max-message-bytes`** (optional, at least 1024): lowers the
  server limit for that domain. Recipients with different limits can't share
  a transaction: the later one gets `452 4.5.3`, so its sender delivers it
  separately.
- **`quota-bytes`** (optional, on a domain or a mailbox; `0` or at least
  1024): the storage quota. A mailbox's own value wins, then its domain's,
  then the server's `mailbox-quota-bytes`; `0` means no quota. Under
  catch-all, the catch-all inbox's quota applies to everything routed to
  it.
- **`mailboxes.*.expires`:** an RFC 3339 timestamp, or `null` for a
  permanent address.
- **`public-key` / `key-generation`:** reserved for per-user encryption at
  rest (PLAN.md). They are carried into the spool metadata but not used yet.
- Every refusal gets the same reply, `550 5.1.1`, so senders can't tell
  which addresses exist. The reason goes to the log.
- The schema is strict: unknown fields are rejected (extend it by bumping
  `version`).

## What the server enforces

| Stage | Check | Result on failure |
|---|---|---|
| Connect | Server-wide, per-IP and per-IP-rate connection limits | `421 4.7.0` |
| HELO/EHLO | Argument is a domain or address literal (no control characters) | `501 5.5.2` |
| MAIL FROM | Path syntax and `SIZE=`; SPF for the sender (HELO identity for `<>`) | `501`/`552`; SPF Fail or PermError `550`, TempError `451` |
| RCPT TO | Safe local-part; hosted by the authority; per-domain size limit; at most 100 | `553 5.1.3`; `550 5.7.1` (relay), `550 5.1.1` (no mailbox); `552`/`452`; `452` |
| DATA | Size limit; 64 KiB line limit; `<CRLF>.<CRLF>` is the only terminator | `552` |
| End of data | No bare CR in the headers | `550 5.6.0` |
| | Exactly one `From:` with one author domain | `550 5.7.1` |
| | DKIM verified (at most 5 signatures; RSA ≥ 1024 bits; must sign `From`; `l=` must cover the body) | feeds DMARC |
| | DMARC: policy found at the From domain or its nearest parent, `sp=` for subdomains | `p=reject` fail: `550 5.7.1`. Lookup failure: `451 4.4.3` |
| | Durable spool write | `451 4.3.0` |

Also:
- **STARTTLS** (RFC 3207): pre-TLS state is discarded, and pipelined
  plaintext is dropped.
- **Closed relay:** mail for domains the authority doesn't host is always
  refused, even for authenticated sessions.
- **Delivery:** accepted mail is delivered at once. Failures are retried
  with backoff (1 minute, doubling to 1 hour) for **5 days**, then moved to
  `spool/dead-letter/` and logged at `error`. DEPLOYMENT.md H2 has the
  requeue procedure. Files left behind by an interrupted write (they never
  got a `250`) are removed from the spool once they're an hour old.

## Logging

bunyan-format JSON on stdout. Logs include:
- one summary per connection: envelope, SPF/DKIM/DMARC verdicts, TLS
  state, message count;
- one line per refusal, with its reason;
- a `dns stats` line every 60 s while DNS is in use;
- a `drain pass` line every 60 s while the queue isn't empty.

Message bodies are never logged.

```sh
RUST_LOG=info mailserv --config /etc/mailserv/mailserv.toml | jq   # or | bunyan
```

## Testing

### Automated tests

```sh
cargo test --workspace          # 297 tests, 1 ignored
cargo test -p dkim -- --ignored # the ignored one: fetches a real DKIM key over DoT
cargo test -p spf               # one crate: smtp, spf, dkim, dmarc, mailparse, dns, mailserv
```

The suite has four layers (DESIGN.md §12):
1. **unit**, per crate;
2. **protocol**, driving the SMTP state machine in-process;
3. **framing**, running full sessions over in-memory streams;
4. **integration**, with a real rustls client against the real connection
   driver over loopback.

Every fixed security finding has a test that reproduces its attack.

**Network.** The tests need nothing beyond loopback: every DNS-backed test
runs against a local mock DNS-over-TLS resolver. The one exception is the
`#[ignore]`d DKIM test, which fetches a live key.

### Lints (enforced by CI)

`.github/workflows/ci.yml` runs these on every push and pull request (Rust
1.100.0). Run them before pushing:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit --deny warnings     # also weekly; accepted advisories: .cargo/audit.toml
```

Warnings are errors, including `missing_docs`: every library crate has
`#![warn(missing_docs)]`, so new public API needs doc comments.

### Trying a local server by hand

Start a server on port 2525 (see [Running](#running)), then talk to it:

```sh
# Plain SMTP
printf 'EHLO test\r\nQUIT\r\n' | nc 127.0.0.1 2525

# STARTTLS, with a throwaway self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 1 -nodes -subj '/CN=localhost'
cargo run -p mailserv -- --domain mail.test --port 2525 \
  --spool-dir ./spool --maildir-dir ./maildir --tls-cert cert.pem --tls-key key.pem
openssl s_client -starttls smtp -connect 127.0.0.1:2525 -crlf -quiet
```

The workspace has two small tools:

- **`smtp-client`** replays one fixed demo transaction (sender
  `foo@foo.com`, recipients at `foo.com`) and prints each reply. Run the
  server with `--domain foo.com` to see it accepted:
  ```sh
  cargo run -p smtp-client -- --host 127.0.0.1 --port 2525
  ```
- **`dnsq`** queries DNS over TCP (the default) or DNS-over-TLS
  (`--tls`), giving up after `--timeout-ms` (default 5000). Use it to
  inspect a sender's records the way the server sees them:
  ```sh
  cargo run -p dnsq -- --domain _dmarc.example.com -q txt --tls --server 1.1.1.1
  ```

For a fuller external test plan (TLS, relay, DMARC, size, smuggling, outage
drill), see DEPLOYMENT.md Phase F.

## Workspace layout

| Crate | Purpose |
|---|---|
| `mailserv` | The binary: policy (`UserSession`), authority, spool, delivery, limits, privilege drop |
| `smtp` | Wire protocol: state machine, framing, DATA transparency |
| `spf` | RFC 7208 evaluation over an abstract resolver |
| `dmarc` | RFC 7489 records, policy discovery, alignment |
| `dkim` | RFC 6376/8463 verification (RSA, Ed25519) |
| `mailparse` | RFC 5322/2045 headers: raw byte view and typed view |
| `dns` | DNS wire codec and pipelined DNS-over-TLS client |
| `dnsq` | DNS query CLI |
| `smtp-client` | Demo SMTP client |

claude --resume a3e8080d-b50c-435b-b268-bf8e28005f2d

