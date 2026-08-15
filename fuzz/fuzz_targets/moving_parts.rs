#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use quantus_ur::test_helpers::{craft_multipart_part, rewrite_ur_type, MAX_FRAGMENT_LENGTH};

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
            // Case-insensitive prefix match: this one must still be accepted.
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

/// Every op addresses frames the same way, so an arbitrary `u8` always lands on
/// a real frame instead of no-oping past the end of a short scan.
fn frame(parts: &[String], part: u8) -> Option<usize> {
    if parts.is_empty() {
        None
    } else {
        Some(part as usize % parts.len())
    }
}

fn apply(parts: &mut Vec<String>, op: &Op) {
    match op {
        Op::FlipChar { part, pos, ch } => {
            let Some(i) = frame(parts, *part) else { return };
            let p = &mut parts[i];
            if p.is_empty() {
                return;
            }
            // Keep the result valid UTF-8 by replacing whole chars.
            let n = p.chars().count();
            let (start, c) = p.char_indices().nth(*pos as usize % n).unwrap();
            let end = start + c.len_utf8();
            let replacement = char::from_u32(0x20 + (*ch as u32 % 0x5F)).unwrap();
            let mut buf = [0u8; 4];
            p.replace_range(start..end, replacement.encode_utf8(&mut buf));
        }
        Op::Truncate { part, len } => {
            let Some(i) = frame(parts, *part) else { return };
            let p = &mut parts[i];
            let mut n = (*len as usize).min(p.len());
            while !p.is_char_boundary(n) {
                n -= 1;
            }
            p.truncate(n);
        }
        Op::Extend { part, extra } => {
            let Some(i) = frame(parts, *part) else { return };
            parts[i].push_str(&extra.chars().take(512).collect::<String>());
        }
        Op::Duplicate { part } => {
            let Some(i) = frame(parts, *part) else { return };
            let clone = parts[i].clone();
            parts.push(clone);
        }
        Op::Drop { part } => {
            let Some(i) = frame(parts, *part) else { return };
            parts.remove(i);
        }
        Op::Swap { a, b } => {
            if let (Some(i), Some(j)) = (frame(parts, *a), frame(parts, *b)) {
                parts.swap(i, j);
            }
        }
        Op::Reverse => parts.reverse(),
        Op::ChangeType { part, ty } => {
            let Some(i) = frame(parts, *part) else { return };
            if let Some(relabeled) = rewrite_ur_type(&parts[i], ty.name()) {
                parts[i] = relabeled;
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

    // Map into the encoder's accepted range so scenarios start from a real
    // multi-frame scan rather than an empty frame list. Fragment counts beyond
    // the decoder's envelope are still rejected, leaving an empty list.
    let fragment_length = scenario.fragment_length as usize % MAX_FRAGMENT_LENGTH + 1;
    let mut parts =
        quantus_ur::encode_bytes_with_options(&payload, fragment_length).unwrap_or_default();

    for op in scenario.ops.iter().take(64) {
        apply(&mut parts, op);
    }

    // None of this may panic; errors are the only acceptable outcome.
    let _ = quantus_ur::decode_bytes(&parts);
    let _ = quantus_ur::decode_hex(&parts);
    let _ = quantus_ur::is_complete(&parts);
});
