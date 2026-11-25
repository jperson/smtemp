//! SPF record parsing and macro expansion over arbitrary TXT text.
#![no_main]

use libfuzzer_sys::fuzz_target;
use spf::parser::parser::{parse, SpfMacroSubs};

fuzz_target!(|text: &str| {
    let subs = SpfMacroSubs {
        s: Some("sender@example.com".into()),
        l: Some("sender".into()),
        o: Some("example.com".into()),
        d: Some("example.com".into()),
        i: Some("192.0.2.1".into()),
        h: Some("mx.example.com".into()),
        ..SpfMacroSubs::default()
    };
    let _ = parse(&subs, text);
});
