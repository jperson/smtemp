# mailserv

A small SMTP server written in Rust: it accepts mail over plaintext or
STARTTLS SMTP, evaluates **SPF**, **DKIM**, and **DMARC** on every message,
enforces a closed-relay recipient policy, and optionally authenticates
submitters (AUTH PLAIN/LOGIN over TLS). Every decision is logged as
structured JSON (bunyan format) — never message bodies.

Status and architecture are documented in
[PLAN.md](PLAN.md) (work backlog) and
[DESIGN.md](DESIGN.md) (architecture).

> **Note:** accepted mail is verified, **durably spooled** (the `250`
> is only sent after the write), and **delivered to local maildirs**
> (retried from the queue until it succeeds); hosted per-user mailboxes
> arrive with the platform (PLAN.md, Phase 12).
>
> **V1 scope: receive-only.** mailserv is being built as a hosted
> receive-only email service: point a domain's MX records at it and
> receive mail at addresses created in the management console —
> addresses are permanent unless given an optional expiry (disposable
> addresses are the flagship use case). It does not
> relay or send. Send-side features (submission/AUTH, DKIM signing) are
> implemented or planned but are post-V1, low priority; the design keeps
> their hooks (see PLAN.md, Phases 8 and 12).

## Building

Stable Rust (see `rust-toolchain.toml`; currently 1.100.0):

```sh
cargo build --release
```

The binary is `target/release/mailserv`.

## Running

A domain is the only required setting; everything else has a
production default. By default mailserv listens on **port 25** and stores
mail under `/var/lib/mailserv`. Started as root it must be given `--user`,
and it drops to that user right after binding the port. Running as root
without `--user` is refused.

```sh
sudo mailserv --domain mx1.example.org --user mailserv
```

To test as an ordinary user, use port 2525 and local directories:

```sh
mailserv --domain mail.test --port 2525 --spool-dir ./spool --maildir-dir ./maildir
```

A typical production invocation (receive-only: no `--auth-users`):

```sh
mailserv \
  --domain mx1.example.org \
  --user mailserv \
  --tls-cert /etc/mailserv/fullchain.pem \
  --tls-key /etc/mailserv/privkey.pem \
  --authority /etc/mailserv/authority.json \
  --resolver 9.9.9.9
```

SIGTERM or SIGINT starts a **graceful shutdown**:
- new connections are refused;
- idle sessions get `421` straight away;
- a session in the middle of a message finishes it, gets its reply, then
  gets `421`;
- the process exits when every session has ended, or after
  `--shutdown-grace-ms`. A second signal exits at once.

Or via a config file (see below):

```sh
mailserv --config /etc/mailserv/mailserv.toml
```

### Quick test with the bundled client

The `smtp-client` crate in this workspace is a small CLI test client:

```sh
cargo run -p mailserv -- --domain example.org &
cargo run -p smtp-client -- --help
```

## Configuration

Configuration comes from three sources, in order of precedence:

1. **CLI flags** (highest)
2. **`--config <file>`** — a TOML file whose keys mirror the flags in
   kebab-case
3. **Built-in defaults** (lowest)

The one exception: `domain` must be provided by the CLI or the config
file — there is no default, and its absence is a hard error at startup.

### CLI flags / config keys

| CLI flag | Config key | Default | Description |
|---|---|---|---|
| `--host <ADDR>` | `host` | `"0.0.0.0"` | Address to listen on. |
| `--port <PORT>` | `port` | `25` | TCP port to listen on. Binding 25 needs root (then `--user` is required) or `CAP_NET_BIND_SERVICE`; use `2525` for unprivileged testing. |
| `--domain <DOMAIN>` | `domain` | *(required)* | The server's own domain: used in the `220` banner, `EHLO` replies, and as a local recipient domain when `--local-domains` is not given. |
| `--max-data-bytes <N>` | `max-data-bytes` | `10485760` (10 MiB) | Server-wide limit; a hosted domain can set a **lower** one with `max-message-bytes` in the authority file. Enforced across the whole DATA phase, advertised as `SIZE` in EHLO, overruns get `552`. Every size refusal is logged (`message refused: size limit`). |
| `--max-conn-duration-ms <MS>` | `max-conn-duration-ms` | `300000` (5 min) | Hard wall-clock cap per connection, including STARTTLS and AUTH. |
| `--max-read-duration-ms <MS>` | `max-read-duration-ms` | `15000` (15 s) | Per-read timeout; a silent client is dropped. |
| `--max-connections <N>` | `max-connections` | `100` | Server-wide cap on simultaneous connections; over-capacity connections are answered `421` and closed. |
| `--max-conn-per-ip <N>` | `max-conn-per-ip` | `10` | Maximum simultaneous connections from a single source IP. |
| `--max-conn-rate-per-ip <N>` | `max-conn-rate-per-ip` | `60` | Maximum new connections per 60-second window from a single source IP (flood/churn budget). Both per-IP refusals answer `421 4.7.0` and close. |
| `--max-dns-per-ip <N>` | `max-dns-per-ip` | `4` | Maximum concurrent DNS-backed checks (SPF for HELO and MAIL FROM, DKIM + DMARC at end-of-data) from a single source IP, so one client can't fill the shared resolver capacity with slow lookups. A check over the limit waits up to 10 s, then gets a temporary failure (`451 4.7.0`; HELO just records SPF `TempError`). Never a permanent rejection. 0 is a startup error. |
| `--tls-cert <FILE>` | `tls-cert` | *(none)* | PEM certificate enabling STARTTLS (RFC 3207). Must be given together with `--tls-key`. When absent, STARTTLS is refused with `454` and never advertised. |
| `--tls-key <FILE>` | `tls-key` | *(none)* | PEM private key for STARTTLS. |
| `--auth-users <SPEC>` | `auth-users` | *(none)* | SASL credentials for AUTH PLAIN/LOGIN, as comma-separated `user:password` pairs (e.g. `alice:secret,bob:hunter2`). When set, `AUTH PLAIN LOGIN` is advertised **only over TLS** (RFC 8310); AUTH on a plaintext session is refused with `538`. ⚠️ Credentials are stored **in plaintext** in the process arguments/config file (shell history, `ps` output) — acceptable for testing only, not for production (see PLAN.md, Phase 8). |
| `--resolver <IP>` | `resolver` | `1.1.1.1` | DNS resolver address used for SPF, DKIM key, and DMARC lookups, over **DNS-over-TLS (port 853)**. Logged at startup. IPv4 addresses only. | The resolver's certificate is verified against this IP address using the public web PKI roots, so public DoT services (`1.1.1.1`, `9.9.9.9`, `8.8.8.8`) work as-is; a local resolver needs `--resolver-ca`. |
| `--resolver-ca <FILE>` | `resolver-ca` | *(none)* | PEM file of extra CA certificates (one or more; a self-signed resolver certificate also works) to trust for the resolver's DNS-over-TLS certificate, so a **local resolver** (unbound, knot-resolver, ...) with a private certificate can be used. The certificates are **added to** the public roots, never substituted, so public resolvers keep working with it set; they are trusted only for resolver connections. The resolver's certificate must carry the `--resolver` address as an IP subject alternative name (e.g. `IP:127.0.0.1`). A missing, empty or invalid file is a startup error. |
| `--dns-connections <N>` | `dns-connections` | `2` | Pipelined DNS-over-TLS connections to the resolver (1–16; out of range is a startup error). Each carries up to 64 queries in flight, so slow lookups for one domain don't stall others. Size it from the periodic `dns stats` log line: sustained `waits` mean every connection is at its in-flight limit. |
| `--spool-dir <DIR>` | `spool-dir` | `/var/lib/mailserv/spool` | Queue directory where accepted messages are written before delivery. Spooling is part of the acceptance contract: the `250` reply is only sent after a durable write (a failed write replies `451 4.3.0`, inviting the client to retry). Layout is maildir-style (`tmp/` + `new/`); each message is a byte-exact `.eml` payload plus a `.json` metadata sidecar (queue ID, envelope, SPF/DKIM/DMARC verdicts). The queue sits behind a `SpoolWriter` trait with an optional `PayloadEncryptor` hook (payloads can be sealed before they reach storage — see PLAN.md, Phase 12), so alternate backends (e.g. S3-compatible) can be added without touching the SMTP path. Messages past the delivery retry budget land in `spool/dead-letter/`. |
| `--maildir-dir <DIR>` | `maildir-dir` | `/var/lib/mailserv/maildir` | Local delivery root: one maildir per recipient address (`{root}/{domain}/{local}/new`), written via the `DeliverySink` trait. Delivery happens immediately after acceptance and is retried from the queue until it succeeds; each delivered copy carries `Return-Path:` and a per-recipient `Received:` trace header. |
| `--local-domains <SPEC>` | `local-domains` | *(the `--domain` value)* | Comma-separated list of recipient domains we accept mail for. The value of `--domain` is always added implicitly. Relay access is closed regardless of authentication — mail for any other recipient domain is refused with `550 5.7.1`. Superseded by `--authority` when given. |
| `--authority <FILE>` | `authority` | *(none)* | Recipient authority file (JSON): the hosted-domain list, per-domain policy modes, and the address→mailbox mapping. Hot-reloaded on change; supersedes `--local-domains`. See [the authority schema](#authority-file-schema). Without it, the pre-authority fallback applies: every local-part at a `--local-domains` domain is accepted and delivered to its own maildir. |
| `--user <USER>` | `user` | *(none)* | Unprivileged user to switch to right after binding, when started as root (required then). Files are created `0600`, directories `0700`. |
| `--group <GROUP>` | `group` | *(user's primary group)* | Group for `--user`. |
| `--shutdown-grace-ms <MS>` | `shutdown-grace-ms` | `60000` | How long sessions may take to finish after SIGTERM/SIGINT. |
| `--config <FILE>` | — | *(none)* | Path to a TOML config file (see below). |

### Config file example

```toml
# /etc/mailserv/mailserv.toml
# Keys are the CLI flags in kebab-case; every key is optional.
# CLI flags override values set here.

host = "0.0.0.0"
port = 25
domain = "example.org"

max-data-bytes = 10485760
max-conn-duration-ms = 300000
max-read-duration-ms = 15000
max-connections = 100
max-conn-per-ip = 10
max-conn-rate-per-ip = 60
max-dns-per-ip = 4

tls-cert = "/etc/mailserv/cert.pem"
tls-key = "/etc/mailserv/key.pem"
# auth-users: leave unset (receive-only V1; AUTH exempts senders from SPF/DMARC)

resolver = "1.1.1.1"
# resolver-ca = "/etc/mailserv/resolver-ca.pem"   # only for a local resolver (e.g. resolver = "127.0.0.1")
dns-connections = 2
spool-dir = "/var/lib/mailserv/spool"
maildir-dir = "/var/lib/mailserv/maildir"
local-domains = "example.org,example.net"
authority = "/etc/mailserv/authority.json"
user = "mailserv"                 # required when started as root
# group = "mailserv"
shutdown-grace-ms = 60000
```

### Environment variables

| Variable | Description |
|---|---|
| `RUST_LOG` | Log verbosity (`tracing` `EnvFilter` syntax). Defaults to `INFO`; e.g. `RUST_LOG=debug` or `RUST_LOG=mailserv=trace`. Logs are bunyan-format JSON on stdout. |

## Behavior summary

- **Closed relay, authority-owned policy.** Only recipients on hosted
  domains are accepted, authenticated or not. With `--authority`, the
  authority decides per domain (`reject` / `catch-all` / `grace`) and
  per address; without it, every local-part at a `--local-domains`
  domain is accepted. An authority that cannot be consulted fails
  closed: `451`, the client retries — mail is never accepted without a
  resolvable destination.

- **SPF** (RFC 7208) is evaluated for the MAIL FROM identity at MAIL time
  (HELO identity for the null sender): `Fail`/`PermError` → `550`,
  `TempError` → `451`. DNS lookups go over DNS-over-TLS to the configured
  `--resolver`, with a lookup budget and per-query timeout.
- **DKIM** (RFC 6376/8463, RSA + Ed25519) signatures are verified at
  end-of-data; results are logged and feed DMARC.
- **DMARC** (RFC 7489): a published `p=reject` policy that the message
  fails → `550 5.7.1` at end-of-data. Authenticated submitters are exempt
  (and skip SPF) — they already passed local authentication.
- **STARTTLS** is advertised on plaintext only; a second STARTTLS on a
  TLS session gets `503`. Session state is reset on upgrade (RFC 3207
  §4.2).
- **AUTH** is offered only over TLS; supported mechanisms are PLAIN and
  LOGIN with challenge continuation; `*` aborts. *(Submission is a
  sending feature — post-V1, low priority for the receive-only service,
  but the implementation and its policy exemptions are kept.)*
- **Framing limits:** commands capped at 512 octets, data lines at 64 KiB,
  dot-unstuffing per RFC 5321 §4.5.2, up to 100 recipients (RFC 5321
  §4.5.3.1.8).
- **Connection caps:** server-wide concurrency, per-IP concurrency, and
  a per-IP connection-rate window (all configurable, see the table);
  over-budget connections are answered `421 4.7.0` and closed before
  any session starts. DNS resolution goes over DNS-over-TLS with EDNS0
  (1232-byte payload, RFC 6891 conformance validated on every
  response).
- **Durable spool + local delivery:** accepted messages are written to
  the spool directory before the `250` is sent — accepted mail is never
  silently dropped. Delivery to per-recipient maildirs happens
  immediately (fast path) and is retried by the queue drain until it
  succeeds; exhausted messages are dead-lettered for inspection.
  Rejected mail (e.g. DMARC `p=reject`) is not spooled or delivered.

## Authority file schema

`--authority` points at a JSON document (hot-reloaded on change) that
the management console publishes:

```json
{
  "version": 1,
    "legacy.example.net": { "mode": "grace", "grace-days": 7, "max-message-bytes": 5242880 }
    "example.org": { "mode": "reject" },
    "lists.example.org": { "mode": "catch-all", "catch-all-mailbox": "admin@example.org" },
    "legacy.example.net": { "mode": "grace", "grace-days": 7 }
  },
  "mailboxes": {
    "alice@example.org": {
      "user": "alice",
      "expires": null,
      "public-key": "...",
      "key-generation": 2
    }
  }
}
```

- **`domains[].mode`** — `reject`: only listed, unexpired mailboxes
  accept; `catch-all`: unknown addresses route to
  `catch-all-mailbox` (expired addresses still refuse); `grace`:
  expired addresses keep accepting for `grace-days` days, then refuse.
- **`domains[].max-message-bytes`** (optional) — the domain's own message
  size limit in bytes, at least 1024. It can only lower the server's
  `max-data-bytes`. A recipient whose domain limit differs from the
  recipients already accepted in a transaction gets `452 4.5.3`, which
  tells the sending server to deliver it separately, so one domain's limit
  never causes another domain's mail to be refused. A declared `SIZE=`
  over the limit gets `552` at RCPT; data over it gets `552` at DATA.
  Every refusal is logged as `message refused: size limit`.
- **`mailboxes[].expires`** — RFC 3339 timestamp or `null`
  (permanent). **`public-key`/`key-generation`** — reserved for the
  user-held payload encryption (PLAN.md, Phase 12); carried through to
  the spool metadata already.
- Refused mail gets one uniform SMTP reply (`550 5.1.1`) regardless of
  reason, so senders cannot probe which addresses exist; the refusal
  *reason* (with peer, sender, mode) is written to the structured log
  for the domain admin's event stream.
- The schema is strict: unknown fields are rejected at load (extend by
  bumping `version`).

## Logging

Logs are bunyan-format JSON on stdout. Each connection logs a summary
(envelope verdicts, SPF/DKIM/DMARC results, message count, TLS state).
Message bodies are never logged.

```sh
RUST_LOG=info mailserv --domain example.org | bunyan   # or jq
```

## Local development & testing

### Prerequisites

- Stable Rust **1.100.0** (pinned in `rust-toolchain.toml`; `rustup` will
  pick it up automatically).
- Nix users: `nix develop` provides the toolchain, `rust-analyzer`, and
  `jq` via `flake.nix`.

Useful `cargo` commands:

```sh
cargo build                    # debug build
cargo build --release          # optimized build
cargo doc --workspace --no-deps  # rustdoc (missing_docs is warn-by-default)
```

### Running the test suites

```sh
cargo test --workspace
```

This runs ~229 tests across the workspace in four layers (see DESIGN.md
§9 for the rationale):

1. **Unit** — pure logic per crate (DKIM canonicalization, DMARC
   alignment, SPF parsing, config resolution, SASL decoding).
2. **Protocol** — the SMTP state machine driven by an in-process test
   session: every verb, rejection path, and sequence rule.
3. **Framing** — full sessions over in-memory duplexes: line-cap
   overflows, STARTTLS pause/resume, timeouts, EOF.
4. **Integration** — a real rustls client against the real connection
   driver over loopback TCP: STARTTLS upgrade, AUTH flows, relay policy.

**Network caveat:** the suite is offline-deterministic *except* for the
`mailserv` integration tests, which exercise the real resolver path and
rely on `spfless-domain-xyz.test` being NXDOMAIN (they use the default
resolver, 1.1.1.1), and one `#[ignore]`d live-DNS DKIM test:

```sh
cargo test -p dkim -- --ignored   # fetches a real DKIM key over DoT
```

To run a single crate's tests: `cargo test -p smtp` (or `spf`, `dkim`,
`dmarc`, `mailparse`, `dns`, `mailserv`).

### Lints and formatting

CI enforces all three of these; run them locally before pushing:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Clippy warnings are **errors** in CI, as is `missing_docs` (every library
crate carries `#![warn(missing_docs)]`), so new public API needs doc
comments.

### Exercising a local server by hand

Start a server on an ephemeral port with a throwaway domain:

```sh
cargo run -p mailserv -- --domain mail.test --port 2525
```

Talk to it with the bundled test client (`smtp-client`) or raw `nc`:

```sh
printf 'EHLO test\r
QUIT\r
' | nc 127.0.0.1 2525
```

For STARTTLS/AUTH testing without real certificates, generate a
self-signed pair and point the flags at it:

```sh
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 1 -nodes -subj '/CN=localhost'
cargo run -p mailserv -- --domain mail.test --tls-cert cert.pem --tls-key key.pem
```

Then drive the full STARTTLS dance with `openssl s_client`:

```sh
openssl s_client -starttls smtp -connect 127.0.0.1:2525 -quiet
```

Logs are bunyan JSON, so piping through `jq` or `bunyan` makes sessions
readable:

```sh
RUST_LOG=debug cargo run -p mailserv -- --domain mail.test 2>&1 | jq
```

### Continuous integration

`.github/workflows/ci.yml` runs the three checks above on every push and
pull request (Rust 1.100.0, warnings denied). The suite is kept fast and
hermetic enough to run in CI — keep it that way when adding tests: use
in-memory duplexes or loopback TCP, fixture mocks for DNS, and `#[ignore]`
anything that needs the live internet.

## Workspace layout

| Crate | Purpose |
|---|---|
| `mailserv` | The binary: policy (`UserSession`), TLS acceptor, connection driver |
| `smtp` | Wire protocol: state machine, framing, DATA transparency |
| `spf` | RFC 7208 evaluation over an abstract DNS resolver |
| `dmarc` | RFC 7489 record parsing, alignment, policy application |
| `dkim` | RFC 6376/8463 verification |
| `mailparse` | RFC 5322/2045 header parsing (raw + typed views) |
| `dns` | DNS wire codec + DNS-over-TLS/TCP transports, shared pooled client |
| `dnsq` | CLI DNS query tool (uses the `dns` crate) |
| `smtp-client` | CLI test client |


claude --resume 17773ca4-9b93-48ce-ae74-1003d060ce37
pi --session 01a1ff3a-6548-7504-98a3-a0e1f5d36b8e
