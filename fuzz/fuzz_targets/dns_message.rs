//! The DNS wire decoder: any reply bytes (compression pointers, counts,
//! rdlengths) must decode or be refused, never panic or loop.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok((_, message)) = dns::proto::DnsMessage::from_bytes(bytes) {
        let _ = message.to_vec();
    }
});
