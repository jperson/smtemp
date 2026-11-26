# REFACTOR.md — Cleanup and Refactoring Review

**Date:** 2026-11-26 · **Commit reviewed:** `53be105` (main, clean tree)
**Scope:** code structure, duplication, API shape, workspace/build hygiene,
CI, docs and repository hygiene. This is **not** a security review: it
doesn't re-open AUDIT.md findings, except where a cleanup item touches one.

**Baseline:** `cargo clippy --workspace --all-targets -D warnings` is clean.
`cargo test --workspace` passes 382 tests with 1 ignored.

**Context:** V1 is a receive-only MX. A later version may add outbound
(TX) delivery. Items marked **[TX]** are the ones that make that later work
additive instead of a rewrite.

---

## 0. Summary

The codebase is in better shape than a week of security fixes usually
leaves code. The crate boundaries (protocol in `smtp`, policy in
`mailserv`, verifiers in their own crates) are sound. Errors from DNS are
typed and matched exhaustively. Blocking work is consistently sent to the
blocking pool. Every production `expect` guards a real invariant. The main
costs of fast growth are:

1. **Duplication** in test infrastructure and small utilities: five mock
   DNS-over-TLS servers, two identical `write_durable`, five copies of the
   lock-poison helper, and 23 hand-written `SessionConfig` literals.
2. **A few oversized units:** `server::run` is about 490 lines,
   `dns/src/lib.rs` holds five subsystems, and `dkim/src/lib.rs` puts
   production code after its test module.
3. **Types that allow states production never uses.** A session without a
   spool answers `250` and drops the message. `Control::Reject` and
   `Control::Tempfail` are never told apart.
4. **Abstractions that will block TX:** the resolver trait lives in `spf`,
   DKIM takes a concrete `DnsClient`, the SMTP state machine is written as
   default methods on the policy trait, and the authority trait is
   synchronous.
5. **Repo hygiene drift:** links to deleted docs, stale test counts, a
   stray `claude --resume` line that four audit rounds have flagged, and
   commit messages that don't describe their changes.

### Top 10 by value for effort

| # | Item | Effort | Why now |
|---|---|---|---|
| 1 | H1–H3: fix broken doc links, the stray README line, and stale test counts | XS | Visible to anyone opening the repo; flagged 4× already |
| 2 | A1: make `spool` (and `sink`) non-optional in `SessionConfig` | S | Removes a type-permitted fail-open path (accept + drop) |
| 3 | D1: one shared mock DoT resolver (`dns` `test-util` feature) | S | Five copies across three crates |
| 4 | D7: a `SessionConfig` test builder | S | Every new session field currently means editing 25 places |
| 5 | B1: move the resolver trait into `dns`; make DKIM generic over it | M | Decouples `dmarc` from `spf`, makes DKIM mockable **[TX]** |
| 6 | S1: split `server::run` into phases | M | The highest-churn function in the repo |
| 7 | D2–D4: put `write_durable`, `lock`/poison and "now" helpers in one place | XS | Mechanical, zero-risk |
| 8 | W1: centralise dependency versions and lints in the workspace | S | Prevents version skew as crates are added |
| 9 | A2: a typed `Reply`, so the `Control` kind derives from the code | M | Fixes the mismatch class and deduplicates reply text |
| 10 | S5: feature-gate (or decide on) `mailparse`'s typed pest parser | S | About 1,250 lines and 3 dependencies unused in production |

Effort: XS < 1 h, S ≈ half a day, M ≈ 1–2 days, L > 2 days.

---

## 1. Correctness-adjacent refactors (types that allow wrong states)

### A1. `SessionConfig::spool: Option<…>` lets a session accept mail and drop it — S

`mailserv/src/session/message.rs:326`: `if let Some(spool) = self.spool.clone() { … }`
is followed at `:406` by an unconditional `Control::accept(UserSession::OK)`.
When `spool` is `None`, end of data answers **250 and discards the message**.
Production always passes `Some` (`server.rs:518-519`). The `Option` exists
so tests can skip spooling: 23 test configs set `spool: None, sink: None`.

**Recommendation:** make `spool: Arc<dyn SpoolWriter>` and
`sink: Arc<dyn DeliverySink>` required. Add an in-memory `MemorySpool` and a
`NullSink` under `#[cfg(test)]` (or in `testutil`). Tests that check
"accepted" then also check "spooled", which is the property that matters.

### A2. `Control::Reject` and `Control::Tempfail` are never told apart; one is mislabelled — M

- No production code branches on `Reject` vs `Tempfail`. `smtp/src/lib.rs:86-99`
  only extracts the reply, and both variants leave the state unchanged.
- `mailserv/src/session.rs:803` sends `454 4.7.0 TLS not available…` through
  `Control::reject`, and so does the test session at `smtp/src/lib.rs:1032`.
  The mismatch is harmless today only because nothing reads the variant.
- Reply text lives in 4 modules (`session.rs:55-139`, `quota.rs`,
  `limit.rs`, the `SmtpSession` associated consts) plus about 15 inline
  literals. Some repeat verbatim: `"451 4.3.0 Mailbox check failed, try
  again later\r\n"` appears 4 times (`session.rs:574,580,641,647`).

**Recommendation:** add a small `smtp::Reply { code: u16, enhanced:
&'static str, text: Cow<'static, str> }` with `const` constructors that
write the CRLF. `Control::refuse(reply)` then picks `Reject` or `Tempfail`
from `code / 100`. Alternatively, drop the distinction and keep a single
`Refuse`. Move mailserv's reply constants into one `mailserv/src/replies.rs`.
This also helps TX: an SMTP client must *parse* replies, and can share
the same type.

### A3. Inconsistent lock-poison policy — XS

`authority.rs:634,639` panics on a poisoned lock
(`.expect("authority lock poisoned")`). `auth.rs:352,396`, `delivery.rs:221,273,283`,
`limit.rs:180,375,533` and `dns/src/lib.rs:507` all recover with
`PoisonError::into_inner`. The writer in `authority.rs` only swaps an `Arc`,
exactly like `auth.rs`, so recovering is safe there too. This was also
raised as AUDIT R4.2 and is still open. Fix it as part of D3.

---

## 2. Architecture: seams to fix before they harden

### B1. The DNS resolver abstraction lives in the wrong crate **[TX]** — M

- `spf::SpfResolver` (`spf/src/lib.rs:185`) is the only resolver trait.
  `dmarc` depends on `spf` just to use it (`dmarc/src/lib.rs:18`), so the
  DESIGN.md §2 arrow `dmarc → spf` exists only because of this trait.
- `dkim` takes a concrete `&DnsClient` (`dkim/src/lib.rs:1508,1803,1821`).
  That is why its tests need a real resolver (the one `#[ignore]`d live
  test) instead of a mock like SPF and DMARC use.
- Record types are passed as raw `u16` values: `0x10`, `0x01`, `0x0F`, `0x0C`
  (`spf/src/lib.rs:281-311`, `dkim/src/lib.rs:1513`).

**Recommendation:** move the trait to `dns` as `dns::Resolver` with
`txt`/`a`/`aaaa`/`mx`/`ptr`, and implement it for `DnsClient` in `dns`.
This deletes spf's `DotResolver` newtype (`spf/src/lib.rs:275`). Make
`spf`, `dmarc` and `dkim` generic over it, and add a
`dns::RecordType` enum (or consts) for the qtypes. TX needs MX and AAAA
lookups for next-hop selection, so the trait gets its second consumer
straight away. The AAAA gap in DESIGN §13 also lands here.

### B2. The SMTP state machine is written as default methods on the policy trait **[TX]** — M

`SmtpSession::run` (`smtp/src/lib.rs:549`) and `SmtpSession::handler`
(`:720`, about 220 lines) are *provided* trait methods. Problems:

- Any implementor can override `run`/`handler`, which defeats the
  "protocol binds policy" guarantee the crate docs promise.
- `run` takes `_peer: &SocketAddr` and `_domain: &str`, which it never
  reads, and `max_read_duration_ms: &u64`, which should be a `Duration`
  passed by value.
- Test sessions must re-delegate every method. `SmallSession`
  (`smtp/src/lib.rs:1237-1293`) is 50 lines of forwarding just to change
  three consts.

**Recommendation:** add `pub struct Server<S> { session: S, limits: Limits }`
(or a free `pub async fn serve<S: SmtpSession, R>(…)`) that owns the loop.
Make the line caps a `Limits` value instead of associated consts, so tests
only change data. Rename the crate's server side to `smtp::server` now, so
`smtp::client` (TX) and shared `smtp::reply` / `smtp::codec` modules can
sit beside it. Today `smtp-client` is a 140-line demo binary with no shared
code.

### B3. `RecipientResolver` (and friends) are synchronous **[TX]** — M

`RecipientResolver`, `SpoolWriter`, `SpoolQueue` and `DeliverySink` are sync
traits wrapped in `spawn_blocking` at every call site (`session.rs:551,623,1102`,
`message.rs:362,439,458`). That suits files, but PLAN §5's next step is a
**console-backed authority** (network I/O), and TX adds an SMTP-client
`DeliverySink`. Both are naturally async.

**Recommendation:** make `RecipientResolver` async now, while it has only
two implementations (`FileAuthority`, `StaticAuthority`), and move the
`spawn_blocking` inside `FileAuthority`. Do the same for `DeliverySink`
before an outbound sink exists. Leave the spool traits sync: they really
are local disk.

### B4. Three different reload models — S (design decision first)

- The authority stats its file on **every lookup** and reloads when the
  mtime or length changes (`authority.rs:631`). A same-size edit within
  the mtime granularity is missed.
- Credentials reload on **SIGHUP** (`auth.rs:374`, `server.rs:650`).
- Sender grants are read **only at startup** (PLAN §3).

`auth.rs` and `authority.rs` each implement their own `RwLock<Arc<T>>`
snapshot swap. **Recommendation:** add one `Reloadable<T>` helper
(`current()`, `replace()`; or the `arc-swap` crate) used by both. Pick one
trigger policy (SIGHUP for all, with optional polling) and write it down
in DESIGN §12.

### B5. Binary/library split is inverted — S

`mailserv/src/lib.rs` exports only `address` and `headers` (for fuzzing).
The other 15 modules are declared `mod` in `main.rs:21-35`. Effects:

- No integration tests (`mailserv/tests/`) are possible. All 1,400 lines
  of `server/tests.rs` must live inside the binary crate.
- The fuzz crate can't reach `session` or `spool` without more carve-outs.
- `main.rs:39` has to re-import `use mailserv::{address, headers}` to make
  `crate::address` resolve. That's a confusing path alias.

**Recommendation:** move every module into the library and expose
`mailserv::run(Config)`. `main.rs` keeps only argument parsing and
logging setup. Use `pub(crate)` to keep the API surface small.

### B6. Configuration is defined three times (four with the README) — M

There are 32 `Args` fields (`config.rs:16`), 31 `FileConfig` fields
(`:216`) and 30 `Config` fields (`:267`). They are merged by about 130
lines of `cli.x.or(file.x).unwrap_or(DEFAULT)` (`:434-567`), and the
README options table is a fourth copy. Adding one option touches four
places.

**Recommendation:** derive both layers from one struct of `Option` fields
(`#[derive(clap::Args, serde::Deserialize)]`) and merge with a single
`fn or(self, other)` (a small macro or `merge` crate). Before TX
adds outbound settings, also consider sections (`[listen]`, `[submission]`,
`[dns]`, `[storage]`, `[limits]`) with `#[serde(alias)]` for today's flat
keys, so existing pilot configs keep loading. `deny_unknown_fields`
(AUDIT F3) must stay.

---

## 3. Duplication

| ID | What | Where | Fix | Effort |
|---|---|---|---|---|
| D1 | Mock DNS-over-TLS server (self-signed cert, `TlsAcceptor`, frame loop), 5 copies | `dns/src/lib.rs:1452,1842,1987`; `spf/src/lib.rs:1493`; `mailserv/src/testutil.rs:54` | `dns::testing::MockDot` behind a `test-util` feature; spf/mailserv enable it in `[dev-dependencies]`. This also drops `tokio-rustls`/`rcgen`/`rustls-pki-types` from spf's dev-deps | S |
| D2 | `write_durable`, byte-identical | `delivery.rs:394`, `spool.rs:664` | Move it to `fsutil` | XS |
| D3 | Recover-from-poison `lock()` helper, 5 copies | `dns/src/lib.rs:507`; `limit.rs:180,375,533`; inline in `auth.rs`, `delivery.rs` | One `fn lock<T>(&Mutex<T>)` / `read`/`write` in a small `sync` module per crate (or `parking_lot`, which doesn't poison) | XS |
| D4 | "Now as Unix seconds", 3 styles | `delivery.rs:636` (`SystemTime`), `spool.rs:43,945` and `message.rs:87` (`jiff`, with differing `max(0)`/casts), `fsutil.rs:170` | One `fn unix_now() -> u64`; inject a clock where tests need one | XS |
| D5 | Hot-reload snapshot | `auth.rs:349-396`, `authority.rs:631-668` | See B4 | S |
| D6 | Reply strings | see A2 | `replies.rs` | S |
| D7 | 23 hand-written ~20-line `SessionConfig` literals | `session/tests.rs` (and `testutil.rs:172`, `session/tests.rs:409`) | `SessionConfig::test_default(dir)` plus `with_*` setters, or struct-update syntax from one base | S |
| D8 | std reimplementations | `smtp/src/lib.rs:310` (`eq_ignore_ascii_case`), `:366` (`trim_ascii_end`) | `<[u8]>::eq_ignore_ascii_case` and `<[u8]>::trim_ascii_end` (stable since 1.80) | XS |
| D9 | Two `From:` address parsers | `mailserv/src/headers.rs:191-368` (raw, used) and `mailparse` pest grammar (typed, unused in production) | See S5. Keep one, or have the fuzzer assert the two agree | — |

---

## 4. Structure and module size

### S1. `server::run` is about 490 lines — M

`mailserv/src/server.rs:102-593` does TLS setup, the DNS client,
credentials, privilege planning, binding, the privilege drop, the
authority, spool, sink, path warnings, the drain task, limiters, the PSL,
storage checks, the signal loop, the accept loop, and graceful shutdown,
all in one function. Comments already split it into phases.

**Recommendation:** turn each phase into a function. Group the shared
`Arc`s into one `Services` struct (it replaces the 14-field
`SessionConfig` clone per connection too):

```rust
let pre   = prepare_privileged(&config).await?;  // TLS, DNS, creds, bind
privdrop::apply(pre.drop_to)?;
let svc   = Services::build(&config, pre)?;     // authority, spool, sink, limits
spawn_drain(&svc);
let sig   = accept_loop(&config, &svc, pre.listeners).await;
graceful_shutdown(&config, &svc, sig).await
```

### S2. `UserSession` clones every `Arc` from a config it already borrows — S

`UserSession<'session>` holds `domain: &'session str` from `cfg`, but
`new()` (`session.rs:407-450`) also clones 10 `Arc`s out of the same
`&'session SessionConfig`. Holding `cfg: &'session SessionConfig` (or an
`Arc<Services>`) removes about 25 lines and the field-for-field mirror.
Group the four loose auth fields (`authenticated`, `auth_failures`,
`auth_login_user`, `auth_pending`) into an `AuthState` struct. Pass `mode`
to `new()` instead of setting it afterwards (`server.rs:812`). The
`#[derive(Serialize)]` with 15 `skip_serializing` attributes mixes the
log snapshot with the runtime state; a separate `SessionLog` view would
be cleaner.

`mail_from` (about 136 lines, `session.rs:908`) and `rcpt_to` (about 186
lines, `:1044`) are long but read linearly. Extract the quota/authority
sub-steps only when they are next touched.

### S3. `dns/src/lib.rs` (2,315 lines) mixes five subsystems — M

It holds the one-shot queries (`:163-310`), the cache (`:317-425`), stats
(`:427-505`), the pipeline (`:526-818`), the pooled client (`:820-1256`)
and 1,050 lines of tests. **Split into** `oneshot.rs`, `cache.rs`,
`stats.rs`, `pipeline.rs`, `client.rs`, plus `tests/`, with
`lib.rs` re-exporting. Also in this crate:

- **`deku` is used only for the 12-byte header** (`proto/mod.rs:306`).
  Everything else is hand-written `from_bytes`/`to_bytes`. Replacing it
  with about 30 lines of shifts removes a proc-macro dependency (and
  `bitvec`) from the most security-critical parser.
- **`QType` is record *data*, not a query type** (`proto/mod.rs:676`).
  Meanwhile `record_type`/`qtype` are bare `u16`. Rename it to `RData` and
  add a `RecordType` (see B1).
- `#[allow(dead_code)]` on `pub` structs (`proto/mod.rs:56,352,404`)
  has no effect. Delete it.
- `let _ = data.write_all(…)` on a `Vec` (about 20 sites) hides an
  infallible call behind an ignored `Result`. Use `extend_from_slice`.
- `as u16` on section counts and rdata length (`proto/mod.rs:148,277-280,471`)
  should be `u16::try_from(..)?`, so an oversized message fails to encode
  instead of producing a corrupt one. They can't overflow today, because
  the client builds the messages, but the encoder is `pub`.

### S4. `dkim/src/lib.rs` puts production code after tests — S

The `mod tests` block spans `:723-1385`. Then `DkimKeyRecord`, key fetch,
`verify_signature`, `verify_with_key`, `verify_dkim`, `fetch_keys`, and
`verify_with_keys` follow (`:1396-1870`, 20 items), then two more test
modules (`:1876`, `:2009`). **Split into** `signature.rs` (tag parsing),
`canon.rs`, `key.rs`, `verify.rs`, plus `tests/` modules.

### S5. `mailparse`'s typed (pest) layer is unused in production — S (decision)

Production calls only `find_separator`, `extract_raw_headers` and
`parse_raw_message`, which are pure byte scanning. `parse_message`,
`parse_headers`, `MailHeaders`, and the `mail.pest` grammar (lines
`33-1778` of `lib.rs`, plus 350 grammar lines) are reached only from tests,
fuzz, and one `dkim` test assertion (`dkim/src/lib.rs:1303`). They pull in
`pest`, `pest_derive` and `jiff`.

**Recommendation:** decide. Either put it behind a `typed` cargo feature
(default off), moved to `mailparse/src/typed/`, or delete it until a
feature needs it (for example a console that shows parsed headers). Keeping
a second, unused RFC 5322 parser around invites someone to wire it in
later and create a parser differential with the raw scanner that DESIGN
§11 deliberately standardised on. `mailparse` is also the only edition-2024
crate (see W2).

### S6. `spf::parser::parser` — XS

`spf/src/parser/mod.rs:3-7` allows `module_inception` "rather than
restructured". Fix it now, while there is only one external path
(`fuzz/fuzz_targets/spf_record.rs:5`): move `parser/parser.rs` into
`parser/mod.rs` (or `spf/src/record.rs`) and re-export `parse` and
`SpfMacroSubs` at `spf::`.

### S7. Test layout is inconsistent — S

`mailserv` uses sibling `session/tests.rs` and `server/tests.rs`. `smtp`
(2,050 test lines in a 3,016-line `lib.rs`), `dns` (1,050), `spf` (1,050)
and `mailparse` (790) keep large inline `mod tests`. Use one convention:
move any test module over ~300 lines into `<module>/tests.rs`. After B5,
put black-box SMTP-conversation tests in `mailserv/tests/`.

---

## 5. Small code-level cleanups

Each is XS. Batch them into one "tidy" PR.

- **Tests that assert nothing:** `spf/src/parser/parser.rs:781-787`
  (`test_ipv4net` only `println!`s) and `dns/src/proto/mod.rs:1074-1078`
  (`test_txt_response` only prints). Add assertions or delete them.
- **Truncating casts in production:** `dmarc/src/psl.rs:239`,
  `mailserv/src/auth.rs:417,847` (`usize as u32`), `spool.rs:945` and
  `message.rs:87` (`i64 as u64`). Use `try_from` or `cast_unsigned()`
  with intent comments.
- **`use super::*`** in `session/message.rs:9` pulls in about 30 names.
  List them, so it's clear what end of data depends on.
- **Unused `async`** on `server.rs:691` (`refuse_async`, which never
  awaits; it only spawns), and on the test `delivery.rs:1232`.
- **TODOs** without owners: `spf/src/lib.rs:466`, `mailparse/src/lib.rs:1236`.
  Link them to PLAN items or remove them.
- **`clippy::pedantic` surfaces about 300 warnings.** Most are style
  noise. Worth enabling selectively in `[workspace.lints]`:
  `cast_possible_truncation`, `cast_sign_loss`, `match_same_arms`,
  `unused_async`, `wildcard_imports`, `redundant_closure_for_method_calls`.

---

## 6. Workspace and build hygiene

### W1. Centralise dependency versions — S

`[workspace.dependencies]` covers 4 crates. Meanwhile `tokio` is declared
in 6 manifests, `anyhow` in 6, `serde` in 4 with three different minimum
versions (`1.0.207`, `1.0.210`, `1.0.218`), and `clap`, `base64`, `sha2`,
`ipnet`, `rcgen`, `tokio-rustls`, `serde_json` in 2–3 each. Move all
shared dependencies to the workspace and use `x = { workspace = true }`.

### W2. Add `[workspace.package]` and `[workspace.lints]` — S

- Edition: 8 crates use `2021`, `mailparse` uses `2024`. Pick one
  (2024, with the 1.100 toolchain) and inherit it.
- Add `rust-version = "1.100"`, `publish = false` (only `fuzz` has it),
  and a `license` once one is chosen. **There is no LICENSE file.**
- Lints: `#![warn(missing_docs)]` is repeated in 7 crate roots, and
  `dnsq` has its own `[lints.clippy]`. Move them to `[workspace.lints]`
  and use `lints.workspace = true`.

### W3. Unused and misplaced dependencies — XS

- `dmarc` declares `anyhow` and never uses it (`dmarc/Cargo.toml`).
- `dns` enables `tokio = { features = ["full"] }`. As a library, it needs
  only `net`, `io-util`, `time`, `sync`, `rt`. Leave `full` to the binaries.
  The same applies to `smtp`.
- After D1, spf's TLS dev-dependencies go away.

### W4. Redundant per-crate `.gitignore` files — XS

`dkim/`, `dns/`, `dnsq/`, `mailparse/`, `mailserv/`, `smtp/`, `smtp-client/`,
`spf/` each contain `/target`. The root `.gitignore` already ignores
`target/`, and workspace members build into the root `target/`. Delete
them (keep `fuzz/.gitignore`, a separate workspace).

### W5. `mailparse/test/` vs `tests/` — XS

The fixture `mailparse/test/trace` sits in a directory named like Cargo's
`tests/` but isn't one. Move it to `mailparse/tests/fixtures/trace` to
match `dkim/tests/fixtures/`.

---

## 7. CI and tooling

- **Action versions disagree:** `fmt` uses `actions/checkout@v6`; the other
  jobs use `@v4` (`.github/workflows/ci.yml`). Use one, and pin by SHA
  for a security-sensitive project.
- **The toolchain is stated twice:** each job passes `toolchain: "1.100.0"`
  even though `rust-toolchain.toml` already pins it. Use
  `dtolnay/rust-toolchain@master` with no input (or plain `rustup show`),
  so bumping means editing one file.
- **No rustdoc job**, although PLAN.md claims "rustdoc … clean". Add
  `RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps`.
- **No dependency policy check:** consider `cargo deny` (licenses,
  duplicate versions, banned crates) next to `cargo audit`.
- **`flake.nix`:** the description says "Rust v1.100.0", but it installs
  `rust-bin.stable.latest.default`. Use
  `rust-bin.fromRustupToolchainFile ./rust-toolchain.toml`. `devShell`
  is deprecated (use `devShells.default`). The shell also ships personal
  tools (`claude-code`, `pi-coding-agent`, `allowUnfree`, an env var).
  Move those to a personal overlay or `.envrc`, so the project flake
  holds only what building and fuzzing need.

---

## 8. Documentation and repository hygiene

### H1. Broken links to deleted review docs — XS

Commit `5ff3812` ("security fixes, regression tests") deleted
`docs/reviews/README.md`, `FINDINGS.md`, `REPORT.md`, `SECURITY-AUDIT.md`
and `SECURITY.md`. Several files still link to them:

- `README.md:21`, `PLAN.md:9` and `DEPLOYMENT.md:16` link `docs/reviews/README.md`.
- `PLAN.md:129` links `docs/reviews/FINDINGS.md`.

Either restore the index (it promised "maps their finding IDs to where
each item stands now") or update the links.

### H2. Stray `claude --resume <uuid>` at `README.md:400` — XS

Reported in AUDIT R3.2, R4.2, A4 and R9.3, and still present. It also
publishes a local session ID. Delete it. The fact that an XS item
survived four rounds is itself a finding: informational audit items have
no tracked owner (see H5).

### H3. Hard-coded test counts are stale — XS

`README.md:313`, `DESIGN.md:746` and `PLAN.md:3` say 347 tests, but the
suite runs 382. Drop the numbers ("the full suite, hermetic, one
`#[ignore]`d live test") or have CI print them.

### H4. Architecture docs drift — XS

- DESIGN §2's dependency graph leaves out `mailserv → dns, mailparse` and
  `dkim → dns`. The README's "Workspace layout" is a second copy of the
  same table. Keep one (DESIGN) and link to it.
- `PLAN.md` §4 says "Nothing is open in this section". Link this
  REFACTOR.md from there, so the code-quality backlog has a home.

### H5. `AUDIT.md` is a 1,628-line append log — S

`AUDIT.md` holds nine rounds and two fix-status addenda, each with its own
H1. Round labels mix dates and letters ("2026-11-26B" … "F"). Finding
status sits in each round's prose, so the current state of any one ID
means reading the whole file. **Recommendation:**

- Split it into `docs/reviews/2026-11-26-round-NN.md`, each immutable once
  written.
- Restore `docs/reviews/README.md` as the **single status table**: ID,
  severity, round, status, fix commit or PR, owner. Informational items
  get rows too.
- Store this file there as the code-quality counterpart.

### H6. Commit hygiene — ongoing

There are 38 commits. Recent messages include `AUDIT`, `audit round 9.`,
`security round 8`, and "security fixes" five times. Some commits mix
unrelated changes (`ee7c91c`: credential reload, grants, file permissions,
a duplicate-delivery fix, tests, and the `main.rs` split). One labelled
as code fixes deleted five docs (`5ff3812`). For a security-sensitive
codebase heading to production, `git log` and `git bisect` are part of
the audit trail. Going forward:

- Make one logical change per commit. Keep doc-only and refactor-only
  commits separate from behaviour changes.
- Write an imperative subject naming the area: `session: make spool
  non-optional`, `dns: replace deku header codec`.
- Reference the finding ID in the body: `Fixes AUDIT H1`.
- Work on short-lived branches with PRs into `main` (CI runs on
  `pull_request` already). Even solo, this gives each fix a reviewable
  unit and a CI record.
- Optionally use a commit-msg convention (Conventional Commits) and a
  `CHANGELOG.md` from the first tagged release.

---

## 9. Already in good shape (keep doing this)

- The protocol/policy split, and verdicts that bind state (`smtp::Control`).
- `dns::Lookup` (found / absent / temporary) matched exhaustively
  everywhere. This is the pattern to copy for B1.
- Every production `expect` guards a real invariant
  (`dns/src/lib.rs:1065,1134,1200`, `config.rs:510`, `authority.rs:370`),
  apart from A3.
- Blocking I/O and argon2 consistently run on the blocking pool.
- The spool/drain separation (`SpoolWriter` / `SpoolQueue`) and the
  `PayloadEncryptor` seam already fit an outbound queue **[TX]**.
- Hermetic tests, CI fuzz smoke runs with committed regression seeds, and
  a `cargo audit` ignore list with written reasons.
- Doc comments are thorough and explain *why*, not just *what*.

---

## 10. Suggested order

**Phase 0 — before pilot go-live (about 1 hour, docs/config only):**
H1, H2, H3, W3 (`dmarc` anyhow), W4, CI action versions.

**Phase 1 — mechanical, no behaviour change (1–2 days):**
D2, D3+A3, D4, D8, the §5 batch, S6, W1, W2, D1, D7. Each is a separate
commit. The suite should stay at 382 passing throughout.

**Phase 2 — type tightening (1–2 days):**
A1 (with `MemorySpool`), A2 (`Reply`), S2.

**Phase 3 — structure (3–5 days):**
B5 (lib/bin), S1 (`server::run`), S3 (dns split + deku), S4 (dkim split),
S5 (decide on mailparse typed), S7.

**Phase 4 — TX readiness (when outbound work is scheduled):**
B1 (`dns::Resolver`, AAAA), B2 (`smtp::server`, then `smtp::client`), B3
(async authority/sink), B4 (reload model), B6 (config sections).

Phases 1–3 don't change wire behaviour. Rerun the fuzz smoke targets after
S3 (DNS codec) and B2 (state machine), and diff the session transcripts in
`server/tests.rs` before and after.
