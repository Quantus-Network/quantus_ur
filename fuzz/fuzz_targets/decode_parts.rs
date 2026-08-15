#![no_main]

use libfuzzer_sys::fuzz_target;

// The raw attack surface: any set of arbitrary strings presented as scanned
// QR frames must produce errors, never panics.
fuzz_target!(|parts: Vec<String>| {
    let _ = quantus_ur::decode_bytes(&parts);
    let _ = quantus_ur::decode_hex(&parts);
    let _ = quantus_ur::is_complete(&parts);
});
