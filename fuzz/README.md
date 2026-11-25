# Fuzz targets

libFuzzer targets for the code that parses attacker-controlled bytes. Each
checks invariants as well as looking for crashes and hangs.

| Target | What it feeds | Invariants checked |
|---|---|---|
| `smtp_session` | a whole client byte stream to the SMTP state machine (`smtp::SmtpSession::run`) | the session ends after EOF |
| `headers` | a raw message to the shared header scanner (`mailparse`) and the end-of-data checks (`mailserv::headers`) | field spans are ordered, disjoint and inside the header block; stripping only removes bytes and is idempotent |
| `dkim_tags` | a key record and a message to DKIM tag parsing, header selection, canonicalisation and verification | no panic |
| `spf_record` | TXT text to the SPF parser and macro expansion | no panic |
| `dmarc_record` | text to the DMARC parser and the Public Suffix List | an organisational domain is its own organisational domain |
| `dns_message` | reply bytes to the DNS wire decoder | no panic or loop |

## Running

With [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (`cargo install
cargo-fuzz`), from this directory:

```sh
cargo +nightly fuzz run headers corpus/headers seeds/headers
```

`seeds/` holds the hand-written starting inputs and the inputs of past
findings (kept as regression cases); `corpus/`, `target/` and any `crash-*`
files are generated and not committed.

Without cargo-fuzz (on stable; no AddressSanitizer, which needs nightly),
build with the same coverage instrumentation and run the binary directly:

```sh
export RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cdebug-assertions -Coverflow_checks"
cargo build --release --target x86_64-unknown-linux-gnu
mkdir -p corpus/headers
./target/x86_64-unknown-linux-gnu/release/headers -max_total_time=600 corpus/headers seeds/headers
```

A crash writes `crash-<hash>` here; replay it by passing that file to the
binary. Once fixed, copy the input into `seeds/<target>/` so it stays a
regression case.

## Findings

- 2026-11-24, `dmarc_record`: a name with form feeds had an
  "organisational domain" that wasn't stable (looking it up again gave
  none). Fixed: names with characters no hostname has get no
  organisational domain, so they align only with themselves
  (`seeds/dmarc_record/regression-form-feed`).
