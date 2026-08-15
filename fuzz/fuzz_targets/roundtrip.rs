#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use quantus_ur::test_helpers::MAX_FRAGMENT_LENGTH;

#[derive(Arbitrary, Debug)]
struct Input {
    payload: Vec<u8>,
    fragment_length: u16,
}

// Encoding arbitrary payloads must never panic, and anything the encoder
// accepts must round-trip byte-for-byte through the decoder and is_complete.
fuzz_target!(|input: Input| {
    let mut payload = input.payload;
    payload.truncate(64 * 1024);
    // Map into the encoder's accepted range; out-of-range lengths would reject
    // almost every input before it reaches the round-trip.
    let fragment_length = input.fragment_length as usize % MAX_FRAGMENT_LENGTH + 1;

    if let Ok(parts) = quantus_ur::encode_bytes_with_options(&payload, fragment_length) {
        let decoded = quantus_ur::decode_bytes(&parts).expect("roundtrip decode");
        assert_eq!(decoded, payload, "roundtrip mismatch");
        assert!(quantus_ur::is_complete(&parts), "encoded parts must be complete");
        let decoded_hex = quantus_ur::decode_hex(&parts).expect("roundtrip decode_hex");
        assert_eq!(decoded_hex, hex::encode(&payload), "hex/bytes decode mismatch");
    }
});
