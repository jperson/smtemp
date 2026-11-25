//! DKIM: signature and key-record tag lists, header selection and
//! canonicalization over arbitrary messages and keys.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    // The first line is a key record; the rest is the message.
    let split = input
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(input.len());
    let (key_part, message) = (&input[..split], input.get(split + 1..).unwrap_or_default());

    if let Ok(text) = std::str::from_utf8(input) {
        let _ = dkim::DkimSignature::parse(text);
    }
    let key = std::str::from_utf8(key_part)
        .ok()
        .and_then(|k| dkim::DkimKeyRecord::parse(k).ok());

    // Verification with that key, and with a failed lookup, for every
    // signature found: canonicalization, the body hash, the signed header
    // data and the crypto must all survive hostile input.
    let lookups: Vec<_> = (0..dkim::MAX_SIGNATURES)
        .map(|i| match (&key, i % 2) {
            (Some(key), 0) => Ok(key.clone()),
            _ => Err(dkim::DkimError::KeyLookupFailed("fuzz".into())),
        })
        .collect();
    let _ = dkim::verify_with_keys(message, &lookups, 0);
});
