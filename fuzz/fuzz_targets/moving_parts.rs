#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const UR_TYPE: &str = "quantus-sign-request";

#[derive(Arbitrary, Debug)]
enum ForeignType {
    CryptoPsbt,
    Bytes,
    Empty,
    Uppercase,
}

impl ForeignType {
    fn name(&self) -> &'static str {
        match self {
            ForeignType::CryptoPsbt => "crypto-psbt",
            ForeignType::Bytes => "bytes",
            ForeignType::Empty => "",
            ForeignType::Uppercase => "QUANTUS-SIGN-REQUEST",
        }
    }
}

/// One mutation an attacker can apply to an animated (multi-frame) QR scan:
/// corrupted frames, dropped/duplicated/reordered frames, frames re-labeled
/// with a foreign UR type, and frames with fully attacker-chosen fountain
/// metadata mixed into an otherwise legitimate sequence.
#[derive(Arbitrary, Debug)]
enum Op {
    FlipChar { part: u8, pos: u16, ch: u8 },
    Truncate { part: u8, len: u16 },
    Extend { part: u8, extra: String },
    Duplicate { part: u8 },
    Drop { part: u8 },
    Swap { a: u8, b: u8 },
    Reverse,
    ChangeType { part: u8, ty: ForeignType },
    InjectPart { seq: u32, count: u32, msg_len: u32, checksum: u32, data: Vec<u8> },
    InjectRaw(String),
}

#[derive(Arbitrary, Debug)]
struct Scenario {
    payload: Vec<u8>,
    fragment_length: u16,
    ops: Vec<Op>,
}

/// Mirrors the test helper in src/lib.rs: builds a multipart fragment carrying
/// arbitrary fountain metadata, bypassing the encoder's bounds.
fn craft_multipart_part(seq: u32, count: u32, msg_len: u32, checksum: u32, data: &[u8]) -> String {
    let mut cbor = Vec::new();
    minicbor::Encoder::new(&mut cbor)
        .array(5)
        .unwrap()
        .u32(seq)
        .unwrap()
        .u32(count)
        .unwrap()
        .u32(msg_len)
        .unwrap()
        .u32(checksum)
        .unwrap()
        .bytes(data)
        .unwrap();
    let body = ur::bytewords::encode(&cbor, ur::bytewords::Style::Minimal);
    format!("ur:{}/{}-{}/{}", UR_TYPE, seq, count, body)
}

fn apply(parts: &mut Vec<String>, op: &Op) {
    match op {
        Op::FlipChar { part, pos, ch } => {
            if let Some(p) = parts.get_mut(*part as usize) {
                let len = p.len();
                if len > 0 {
                    let i = *pos as usize % len;
                    // Keep the result valid UTF-8 by replacing whole chars.
                    if let Some((start, _)) = p.char_indices().nth(i % p.chars().count()) {
                        let end = start + p[start..].chars().next().unwrap().len_utf8();
                        let replacement = char::from_u32(0x20 + (*ch as u32 % 0x5F)).unwrap();
                        p.replace_range(start..end, &replacement.to_string());
                    }
                }
            }
        }
        Op::Truncate { part, len } => {
            if let Some(p) = parts.get_mut(*part as usize) {
                let mut n = (*len as usize).min(p.len());
                while !p.is_char_boundary(n) {
                    n -= 1;
                }
                p.truncate(n);
            }
        }
        Op::Extend { part, extra } => {
            if let Some(p) = parts.get_mut(*part as usize) {
                p.push_str(&extra.chars().take(512).collect::<String>());
            }
        }
        Op::Duplicate { part } => {
            if let Some(p) = parts.get(*part as usize) {
                parts.push(p.clone());
            }
        }
        Op::Drop { part } => {
            if !parts.is_empty() {
                parts.remove(*part as usize % parts.len());
            }
        }
        Op::Swap { a, b } => {
            if !parts.is_empty() {
                let i = *a as usize % parts.len();
                let j = *b as usize % parts.len();
                parts.swap(i, j);
            }
        }
        Op::Reverse => parts.reverse(),
        Op::ChangeType { part, ty } => {
            if let Some(p) = parts.get_mut(*part as usize) {
                let lower = p.to_lowercase();
                let prefix = format!("ur:{}/", UR_TYPE);
                if let Some(body) = lower.strip_prefix(&prefix) {
                    *p = format!("ur:{}/{}", ty.name(), body);
                }
            }
        }
        Op::InjectPart { seq, count, msg_len, checksum, data } => {
            let data: Vec<u8> = data.iter().take(8192).copied().collect();
            parts.push(craft_multipart_part(*seq, *count, *msg_len, *checksum, &data));
        }
        Op::InjectRaw(s) => parts.push(s.chars().take(16 * 1024).collect()),
    }
}

fuzz_target!(|scenario: Scenario| {
    let mut payload = scenario.payload;
    payload.truncate(32 * 1024);

    // Encode legitimately when the options allow; an invalid fragment length
    // just starts the scenario from an empty frame list.
    let mut parts = quantus_ur::encode_bytes_with_options(
        &payload,
        scenario.fragment_length as usize,
    )
    .unwrap_or_default();

    for op in scenario.ops.iter().take(64) {
        apply(&mut parts, op);
    }

    // None of this may panic; errors are the only acceptable outcome.
    let _ = quantus_ur::decode_bytes(&parts);
    let _ = quantus_ur::decode_hex(&parts);
    let _ = quantus_ur::is_complete(&parts);
});
