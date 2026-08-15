#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

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
    let fragment_length = input.fragment_length as usize;

    if let Ok(parts) = quantus_ur::encode_bytes_with_options(&payload, fragment_length) {
        let decoded = quantus_ur::decode_bytes(&parts).expect("roundtrip decode");
        assert_eq!(decoded, payload, "roundtrip mismatch");
        assert!(quantus_ur::is_complete(&parts), "encoded parts must be complete");
        let decoded_hex = quantus_ur::decode_hex(&parts).expect("roundtrip decode_hex");
        assert_eq!(decoded_hex, hex::encode(&payload), "hex/bytes decode mismatch");
    }
});
