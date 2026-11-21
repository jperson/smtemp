# mailserv

A small SMTP server written in Rust: it accepts mail over plaintext or
STARTTLS SMTP, evaluates **SPF**, **DKIM**, and **DMARC** on every message,
enforces a closed-relay recipient policy, and optionally authenticates
submitters (AUTH PLAIN/LOGIN over TLS). Every decision is logged as
structured JSON (bunyan format) — never message bodies.

Status and architecture are documented in
[PLAN.md](PLAN.md) (work backlog) and
[DESIGN.md](DESIGN.md) (architecture).

> **Note:** accepted mail is verified, logged, and **durably spooled to
> disk** (the `250` is only sent after the write), but not yet delivered
> to mailboxes — local delivery is the next phase (see PLAN.md,
> Phase 7).
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

A domain is the only required setting — everything else has a default:

```sh
mailserv --domain example.org
```

A typical production-ish invocation with STARTTLS and AUTH:

```sh
mailserv \
  --domain example.org \
  --host 0.0.0.0 \
  --port 25 \
  --local-domains example.org,example.net \
  --tls-cert /etc/mailserv/cert.pem \
  --tls-key /etc/mailserv/key.pem \
  --auth-users alice:secret,bob:hunter2 \
  --resolver 1.1.1.1
```

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
| `--port <PORT>` | `port` | `2525` | TCP port to listen on. |
| `--domain <DOMAIN>` | `domain` | *(required)* | The server's own domain: used in the `220` banner, `EHLO` replies, and as a local recipient domain when `--local-domains` is not given. |
| `--max-data-bytes <N>` | `max-data-bytes` | `1048576` (1 MiB) | Per-message size limit; enforced across the whole DATA phase, advertised as `SIZE` in EHLO, overruns get `552`. |
| `--max-conn-duration-ms <MS>` | `max-conn-duration-ms` | `30000` (30 s) | Hard wall-clock cap per connection, including STARTTLS and AUTH. |
| `--max-read-duration-ms <MS>` | `max-read-duration-ms` | `15000` (15 s) | Per-read timeout; a silent client is dropped. |
| `--tls-cert <FILE>` | `tls-cert` | *(none)* | PEM certificate enabling STARTTLS (RFC 3207). Must be given together with `--tls-key`. When absent, STARTTLS is refused with `454` and never advertised. |
| `--tls-key <FILE>` | `tls-key` | *(none)* | PEM private key for STARTTLS. |
| `--auth-users <SPEC>` | `auth-users` | *(none)* | SASL credentials for AUTH PLAIN/LOGIN, as comma-separated `user:password` pairs (e.g. `alice:secret,bob:hunter2`). When set, `AUTH PLAIN LOGIN` is advertised **only over TLS** (RFC 8310); AUTH on a plaintext session is refused with `538`. ⚠️ Credentials are stored **in plaintext** in the process arguments/config file (shell history, `ps` output) — acceptable for testing only, not for production (see PLAN.md, Phase 8). |
| `--resolver <IP>` | `resolver` | `1.1.1.1` | DNS resolver address used for SPF, DKIM key, and DMARC lookups, over **DNS-over-TLS (port 853)**. Logged at startup. IPv4 addresses only. |
| `--spool-dir <DIR>` | `spool-dir` | `spool` | Queue directory where accepted messages are written before delivery. Spooling is part of the acceptance contract: the `250` reply is only sent after a durable write (a failed write replies `451 4.3.0`, inviting the client to retry). Layout is maildir-style (`tmp/` + `new/`); each message is a byte-exact `.eml` payload plus a `.json` metadata sidecar (queue ID, envelope, SPF/DKIM/DMARC verdicts). |
| `--local-domains <SPEC>` | `local-domains` | *(the `--domain` value)* | Comma-separated list of recipient domains we accept mail for. The value of `--domain` is always added implicitly. Relay access is closed regardless of authentication — mail for any other recipient domain is refused with `550 5.7.1`. |
| `--config <FILE>` | — | *(none)* | Path to a TOML config file (see below). |

### Config file example

```toml
# /etc/mailserv/mailserv.toml
# Keys are the CLI flags in kebab-case; every key is optional.
# CLI flags override values set here.

host = "0.0.0.0"
port = 25
domain = "example.org"

max-data-bytes = 1048576
max-conn-duration-ms = 30000
max-read-duration-ms = 15000

tls-cert = "/etc/mailserv/cert.pem"
tls-key = "/etc/mailserv/key.pem"
auth-users = "alice:secret,bob:hunter2"

resolver = "1.1.1.1"
spool-dir = "spool"
local-domains = "example.org,example.net"
```

### Environment variables

| Variable | Description |
|---|---|
| `RUST_LOG` | Log verbosity (`tracing` `EnvFilter` syntax). Defaults to `INFO`; e.g. `RUST_LOG=debug` or `RUST_LOG=mailserv=trace`. Logs are bunyan-format JSON on stdout. |

## Behavior summary

- **Closed relay.** Only recipients in `--local-domains` (plus
  `--domain`) are accepted, authenticated or not.
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
- **Durable spool:** accepted messages are written to the spool directory
  before the `250` is sent — accepted mail is never silently dropped.
  Rejected mail (e.g. DMARC `p=reject`) is not spooled. Local delivery
  from the queue is the next open item (PLAN.md, Phase 7).

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

This runs ~145 tests across the workspace in four layers (see DESIGN.md
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
| `dns` | DNS wire codec + DNS-over-TLS/TCP/UDP transports |
| `dnsq` | CLI DNS query tool (uses the `dns` crate) |
| `smtp-client` | CLI test client |
