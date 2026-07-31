#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use hex;
use minicbor::{bytes::ByteVec, Decoder};
use ur_parse_lib::keystone_ur_encoder::probe_encode;

const UR_TYPE: &str = "quantus-sign-request";
/// Default bytes per QR fragment when the caller doesn't specify one.
const DEFAULT_FRAGMENT_LENGTH: usize = 200;
/// Largest fragment the decoder accepts. Screens can show much denser QR codes
/// than the conservative default, so encoding may go up to this bound.
const MAX_FRAGMENT_LENGTH: usize = 4096;
/// Maximum number of fountain fragments a message may be split into. Mirrors the
/// encoding envelope so inbound fragments can't claim an arbitrary fragment count.
const MAX_FRAGMENT_COUNT: usize = 1024;
/// Maximum size of a reconstructed CBOR message.
const MAX_MESSAGE_LENGTH: usize = 200 * 1024;

fn ur_error(e: impl core::fmt::Display) -> QuantusUrError {
    QuantusUrError::UrError(e.to_string())
}

/// Returns true if `part` (already lowercased) is a `ur:quantus-sign-request/...` URI.
fn has_expected_ur_type(part: &str) -> bool {
    let Some(rest) = part.strip_prefix("ur:") else {
        return false;
    };
    let Some((ur_type, _)) = rest.split_once('/') else {
        return false;
    };
    ur_type == UR_TYPE
}

#[derive(Debug)]
pub enum QuantusUrError {
    HexError(hex::FromHexError),
    UrError(String),
    CborError(String),
    Incomplete,
}

impl core::fmt::Display for QuantusUrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            QuantusUrError::HexError(e) => write!(f, "Hex decoding error: {}", e),
            QuantusUrError::UrError(msg) => write!(f, "UR error: {}", msg),
            QuantusUrError::CborError(msg) => write!(f, "CBOR error: {}", msg),
            QuantusUrError::Incomplete => write!(f, "Decoding incomplete"),
        }
    }
}

fn encode_internal(
    payload: &[u8],
    max_fragment_length: usize,
) -> Result<Vec<String>, QuantusUrError> {
    if max_fragment_length == 0 || max_fragment_length > MAX_FRAGMENT_LENGTH {
        return Err(QuantusUrError::UrError(
            "max_fragment_length out of range".to_string(),
        ));
    }

    let cbor = minicbor::to_vec(ByteVec::from(payload.to_vec()))
        .map_err(|e| QuantusUrError::CborError(e.to_string()))?;

    // Stay inside the envelope the decoder accepts, rather than emitting a
    // fragment set that `decode_internal` would reject.
    if cbor.len() > MAX_MESSAGE_LENGTH {
        return Err(QuantusUrError::UrError("Payload too large".to_string()));
    }

    let result = probe_encode(&cbor, max_fragment_length, UR_TYPE.to_string())
        .map_err(|e| QuantusUrError::UrError(e.to_string()))?;

    if !result.is_multi_part {
        return Ok(vec![result.data.to_uppercase()]);
    }

    let mut encoder = result
        .encoder
        .ok_or_else(|| QuantusUrError::UrError("Multi-part but no encoder returned".to_string()))?;

    let count = encoder.fragment_count();
    let mut parts = Vec::with_capacity(count);
    parts.push(result.data.to_uppercase());

    while parts.len() < count {
        let part = encoder
            .next_part()
            .map_err(|e| QuantusUrError::UrError(e.to_string()))?;
        parts.push(part.to_uppercase());
    }

    Ok(parts)
}

pub fn encode_hex(hex_payload: &str) -> Result<Vec<String>, QuantusUrError> {
    encode_hex_with_options(hex_payload, DEFAULT_FRAGMENT_LENGTH)
}

pub fn encode_hex_with_options(
    hex_payload: &str,
    max_fragment_length: usize,
) -> Result<Vec<String>, QuantusUrError> {
    let payload = hex::decode(hex_payload).map_err(QuantusUrError::HexError)?;
    encode_internal(&payload, max_fragment_length)
}

pub fn encode_bytes(payload: &[u8]) -> Result<Vec<String>, QuantusUrError> {
    encode_bytes_with_options(payload, DEFAULT_FRAGMENT_LENGTH)
}

pub fn encode_bytes_with_options(
    payload: &[u8],
    max_fragment_length: usize,
) -> Result<Vec<String>, QuantusUrError> {
    encode_internal(payload, max_fragment_length)
}

/// Unwraps the CBOR bytestring produced by `encode_internal`, rejecting anything
/// left over: the wrapper contains exactly one item, so trailing bytes or extra
/// CBOR items mean the input is non-canonical and must not be accepted.
fn decode_cbor_payload(cbor: &[u8]) -> Result<Vec<u8>, QuantusUrError> {
    let mut decoder = Decoder::new(cbor);
    let bytes = decoder
        .bytes()
        .map_err(|e| QuantusUrError::CborError(e.to_string()))?;

    if decoder.position() != cbor.len() {
        return Err(QuantusUrError::CborError(
            "Trailing CBOR data after payload bytestring".to_string(),
        ));
    }

    Ok(bytes.to_vec())
}

/// Validates every inbound multipart fragment before it reaches `ur::ur::Decoder`.
///
/// The fountain decoder sizes its work from metadata carried inside the fragment,
/// so a tiny fragment claiming a huge sequence count would otherwise drive large
/// allocations. Enforce the UR type, the encoder's fragment envelope, and that all
/// fragments describe the same message.
fn validate_multipart_parts(ur_parts: &[String]) -> Result<(), QuantusUrError> {
    if ur_parts.len() > MAX_FRAGMENT_COUNT {
        return Err(QuantusUrError::UrError(
            "Too many UR parts provided".to_string(),
        ));
    }

    // (sequence_count, message_length, checksum, data_length) shared by all fragments.
    let mut expected: Option<(usize, usize, u32, usize)> = None;

    for part in ur_parts {
        let normalized = part.to_lowercase();
        if !has_expected_ur_type(&normalized) {
            return Err(QuantusUrError::UrError("Unexpected UR type".to_string()));
        }

        let (kind, decoded) =
            ur::ur::decode(&normalized).map_err(|e| QuantusUrError::UrError(e.to_string()))?;
        if kind != ur::ur::Kind::MultiPart {
            return Err(QuantusUrError::UrError("Mixed UR part kinds".to_string()));
        }

        let mut part_decoder = Decoder::new(&decoded);
        if !matches!(part_decoder.array(), Ok(Some(5))) {
            return Err(QuantusUrError::UrError(
                "Invalid multipart fountain part".to_string(),
            ));
        }

        let sequence = part_decoder.u32().map_err(ur_error)? as usize;
        let sequence_count = part_decoder.u32().map_err(ur_error)? as usize;
        let message_length = part_decoder.u32().map_err(ur_error)? as usize;
        let checksum = part_decoder.u32().map_err(ur_error)?;
        let data_length = part_decoder.bytes().map_err(ur_error)?.len();

        // `sequence > sequence_count` would be a mixed fountain part; this crate's
        // encoder only ever emits the simple parts 1..=sequence_count, so reject
        // them and keep the decoder's memory bounded by the message length.
        if sequence == 0
            || sequence_count == 0
            || sequence > sequence_count
            || sequence_count > MAX_FRAGMENT_COUNT
            || data_length == 0
            || data_length > MAX_FRAGMENT_LENGTH
            || message_length == 0
            || message_length > MAX_MESSAGE_LENGTH
        {
            return Err(QuantusUrError::UrError(
                "Multipart UR exceeds supported bounds".to_string(),
            ));
        }

        // All fragments are equally sized, so the message must fill the last one
        // at least partially and cannot overflow the fragment set.
        let min_message_length = (sequence_count - 1) * data_length + 1;
        let max_message_length = sequence_count * data_length;
        if message_length < min_message_length || message_length > max_message_length {
            return Err(QuantusUrError::UrError(
                "Multipart UR metadata is inconsistent".to_string(),
            ));
        }

        let metadata = (sequence_count, message_length, checksum, data_length);
        match expected {
            None => expected = Some(metadata),
            Some(seen) if seen == metadata => {}
            Some(_) => {
                return Err(QuantusUrError::UrError(
                    "Multipart UR metadata is inconsistent".to_string(),
                ))
            }
        }
    }

    Ok(())
}

fn decode_internal(ur_parts: &[String]) -> Result<Vec<u8>, QuantusUrError> {
    if ur_parts.is_empty() {
        return Err(QuantusUrError::UrError("No UR parts provided".to_string()));
    }

    let first = ur_parts[0].to_lowercase();
    if !has_expected_ur_type(&first) {
        return Err(QuantusUrError::UrError("Unexpected UR type".to_string()));
    }
    let (kind, decoded) =
        ur::ur::decode(&first).map_err(|e| QuantusUrError::UrError(e.to_string()))?;

    match kind {
        ur::ur::Kind::SinglePart => {
            if ur_parts.len() != 1 {
                return Err(QuantusUrError::UrError(
                    "Single-part UR must be the only provided part".to_string(),
                ));
            }
            decode_cbor_payload(&decoded)
        }
        ur::ur::Kind::MultiPart => {
            validate_multipart_parts(ur_parts)?;
            let mut d = ur::ur::Decoder::default();
            for part in ur_parts {
                d.receive(&part.to_lowercase())
                    .map_err(|e| QuantusUrError::UrError(e.to_string()))?;
            }
            if !d.complete() {
                return Err(QuantusUrError::Incomplete);
            }
            let message = d
                .message()
                .map_err(|e| QuantusUrError::UrError(e.to_string()))?
                .ok_or_else(|| QuantusUrError::UrError("No message".to_string()))?;
            decode_cbor_payload(&message)
        }
    }
}

pub fn decode_hex(ur_parts: &[String]) -> Result<String, QuantusUrError> {
    let bytes = decode_internal(ur_parts)?;
    Ok(hex::encode(bytes))
}

pub fn decode_bytes(ur_parts: &[String]) -> Result<Vec<u8>, QuantusUrError> {
    decode_internal(ur_parts)
}

pub fn is_complete(ur_parts: &[String]) -> bool {
    if ur_parts.is_empty() {
        return false;
    }

    let first = ur_parts[0].to_lowercase();
    if !has_expected_ur_type(&first) {
        return false;
    }
    let (kind, _) = match ur::ur::decode(&first) {
        Ok(result) => result,
        Err(_) => return false,
    };

    match kind {
        // A single-part UR is only complete when it is the whole input; extra
        // fragments alongside it mean the collection is inconsistent.
        ur::ur::Kind::SinglePart => ur_parts.len() == 1,
        ur::ur::Kind::MultiPart => {
            if validate_multipart_parts(ur_parts).is_err() {
                return false;
            }
            let mut d = ur::ur::Decoder::default();
            for part in ur_parts {
                if d.receive(&part.to_lowercase()).is_err() {
                    return false;
                }
            }
            d.complete()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn test_single_part_roundtrip() {
        // Small payload that fits in 200 bytes
        let hex_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000";

        let encoded_parts = encode_hex(hex_payload).expect("Encoding failed");
        assert_eq!(encoded_parts.len(), 1, "Should be single part");

        let decoded_hex = decode_hex(&encoded_parts).expect("Decoding failed");
        assert_eq!(decoded_hex.to_lowercase(), hex_payload.to_lowercase());
    }

    #[test]
    fn test_multi_part_roundtrip() {
        // Create a large payload (> 200 bytes)
        // 250 bytes of data
        let mut large_payload = String::with_capacity(500);
        for i in 0..250 {
            large_payload.push_str(&format!("{:02x}", i));
        }

        let encoded_parts = encode_hex(&large_payload).expect("Encoding failed");
        assert!(encoded_parts.len() > 1, "Should be multi-part");

        // Print parts for debug
        // for (i, part) in encoded_parts.iter().enumerate() {
        //     println!("Part {}: {}", i, part);
        // }

        let decoded_hex = decode_hex(&encoded_parts).expect("Decoding failed");
        assert_eq!(decoded_hex.to_lowercase(), large_payload.to_lowercase());
    }

    #[test]
    fn test_is_complete_empty() {
        assert!(!is_complete(&[]), "Empty parts should be incomplete");
    }

    #[test]
    fn test_is_complete_single_part() {
        let hex_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000";
        let encoded_parts = encode_hex(hex_payload).expect("Encoding failed");
        assert_eq!(encoded_parts.len(), 1, "Should be single part");
        assert!(is_complete(&encoded_parts), "Single part should be complete");
    }

    #[test]
    fn test_is_complete_multi_part_complete() {
        let mut large_payload = String::with_capacity(500);
        for i in 0..250 {
            large_payload.push_str(&format!("{:02x}", i));
        }
        let encoded_parts = encode_hex(&large_payload).expect("Encoding failed");
        assert!(encoded_parts.len() > 1, "Should be multi-part");
        assert!(is_complete(&encoded_parts), "Complete multi-part should return true");
    }

    #[test]
    fn test_is_complete_multi_part_incomplete() {
        let mut large_payload = String::with_capacity(500);
        for i in 0..250 {
            large_payload.push_str(&format!("{:02x}", i));
        }
        let encoded_parts = encode_hex(&large_payload).expect("Encoding failed");
        assert!(encoded_parts.len() > 1, "Should be multi-part");
        
        let incomplete_parts = &encoded_parts[..encoded_parts.len() - 1];
        assert!(!is_complete(incomplete_parts), "Incomplete multi-part should return false");
    }

    #[test]
    fn test_is_complete_invalid_ur() {
        let invalid_parts = vec!["not-a-valid-ur".to_string()];
        assert!(!is_complete(&invalid_parts), "Invalid UR should return false");
    }

    #[test]
    fn test_is_complete_multi_part_partial() {
        let mut large_payload = String::with_capacity(500);
        for i in 0..250 {
            large_payload.push_str(&format!("{:02x}", i));
        }
        let encoded_parts = encode_hex(&large_payload).expect("Encoding failed");
        assert!(encoded_parts.len() > 1, "Should be multi-part");
        
        let partial_parts = &encoded_parts[..1];
        assert!(!is_complete(partial_parts), "Single part of multi-part should return false");
    }

    #[test]
    fn test_encode_bytes_roundtrip() {
        let binary_payload = b"Hello, Quantus!";
        let encoded_parts = encode_bytes(binary_payload).expect("Encoding failed");
        let decoded_bytes = decode_bytes(&encoded_parts).expect("Decoding failed");
        assert_eq!(decoded_bytes, binary_payload);
    }

    #[test]
    fn test_encode_bytes_multi_part() {
        let mut large_payload = Vec::with_capacity(250);
        for i in 0..250 {
            large_payload.push(i as u8);
        }
        let encoded_parts = encode_bytes(&large_payload).expect("Encoding failed");
        assert!(encoded_parts.len() > 1, "Should be multi-part");
        let decoded_bytes = decode_bytes(&encoded_parts).expect("Decoding failed");
        assert_eq!(decoded_bytes, large_payload);
    }

    #[test]
    fn test_encode_with_options_fragment_count_scales_with_fragment_length() {
        // ML-DSA-87 signature + public key, the app's largest real payload.
        let payload: Vec<u8> = (0..7219u32).map(|i| (i % 251) as u8).collect();

        let parts_700 = encode_bytes_with_options(&payload, 700).expect("Encoding failed");
        assert_eq!(parts_700.len(), 11, "7219 bytes at 700 per fragment");
        let parts_1500 = encode_bytes_with_options(&payload, 1500).expect("Encoding failed");
        assert_eq!(parts_1500.len(), 5, "7219 bytes at 1500 per fragment");

        assert_eq!(
            decode_bytes(&parts_700).expect("Decoding failed"),
            payload
        );
        assert_eq!(
            decode_bytes(&parts_1500).expect("Decoding failed"),
            payload
        );
        assert!(is_complete(&parts_1500));
    }

    #[test]
    fn test_encode_with_options_rejects_out_of_range_fragment_length() {
        let payload = b"Hello, Quantus!";
        for bad in [0, MAX_FRAGMENT_LENGTH + 1] {
            assert!(
                matches!(
                    encode_bytes_with_options(payload, bad),
                    Err(QuantusUrError::UrError(_))
                ),
                "fragment length {bad} should be rejected"
            );
        }
        assert!(
            encode_bytes_with_options(payload, MAX_FRAGMENT_LENGTH).is_ok(),
            "the decode bound itself should be encodable"
        );
    }

    /// Re-labels an encoded fragment with a different UR type, as an attacker
    /// substituting a foreign UR into a scan would.
    fn rewrite_ur_type(part: &str, new_type: &str) -> String {
        let lower = part.to_lowercase();
        let prefix = format!("ur:{}/", UR_TYPE);
        let body = lower
            .strip_prefix(&prefix)
            .expect("encoded part must use the quantus UR type");
        format!("ur:{}/{}", new_type, body)
    }

    /// Builds a multipart fragment with arbitrary fountain metadata, bypassing the
    /// encoder's bounds.
    fn craft_multipart_part(
        sequence: u32,
        sequence_count: u32,
        message_length: u32,
        checksum: u32,
        data: &[u8],
    ) -> String {
        let mut cbor = Vec::new();
        minicbor::Encoder::new(&mut cbor)
            .array(5)
            .unwrap()
            .u32(sequence)
            .unwrap()
            .u32(sequence_count)
            .unwrap()
            .u32(message_length)
            .unwrap()
            .u32(checksum)
            .unwrap()
            .bytes(data)
            .unwrap();

        let body = ur::bytewords::encode(&cbor, ur::bytewords::Style::Minimal);
        format!("ur:{}/{}-{}/{}", UR_TYPE, sequence, sequence_count, body)
    }

    fn multi_part_payload() -> Vec<u8> {
        (0..250).map(|i| i as u8).collect()
    }

    #[test]
    fn test_decode_rejects_foreign_ur_type() {
        let encoded_parts = encode_bytes(b"Hello, Quantus!").expect("Encoding failed");
        let foreign = vec![rewrite_ur_type(&encoded_parts[0], "crypto-psbt")];

        assert!(
            matches!(decode_bytes(&foreign), Err(QuantusUrError::UrError(_))),
            "Foreign UR type should be rejected"
        );
        assert!(!is_complete(&foreign), "Foreign UR type should not be complete");
    }

    #[test]
    fn test_single_part_must_be_alone() {
        let attacker_parts = encode_bytes(b"attacker controlled payload").expect("Encoding failed");
        assert_eq!(attacker_parts.len(), 1, "Should be single part");

        let legitimate_parts = encode_bytes(&multi_part_payload()).expect("Encoding failed");
        assert!(legitimate_parts.len() > 1, "Should be multi-part");

        let mut mixed_parts = vec![attacker_parts[0].clone()];
        mixed_parts.extend(legitimate_parts);

        assert!(
            matches!(decode_bytes(&mixed_parts), Err(QuantusUrError::UrError(_))),
            "A prepended single-part UR must not short-circuit multipart fragments"
        );
        assert!(
            !is_complete(&mixed_parts),
            "A prepended single-part UR must not mark a mixed set complete"
        );
    }

    #[test]
    fn test_multi_part_rejects_foreign_fragment() {
        let legitimate_parts = encode_bytes(&multi_part_payload()).expect("Encoding failed");
        assert!(legitimate_parts.len() > 1, "Should be multi-part");

        let mut mixed_parts = legitimate_parts.clone();
        let last = mixed_parts.len() - 1;
        mixed_parts[last] = rewrite_ur_type(&legitimate_parts[last], "crypto-psbt");

        assert!(
            matches!(decode_bytes(&mixed_parts), Err(QuantusUrError::UrError(_))),
            "A foreign-type fragment must be rejected"
        );
        assert!(!is_complete(&mixed_parts), "A foreign-type fragment must not be accepted");
    }

    #[test]
    fn test_multi_part_rejects_out_of_bounds_metadata() {
        // Tiny fragment claiming an enormous fragment count: the decoder must reject
        // it instead of sizing its work from attacker-supplied metadata.
        let malicious = vec![craft_multipart_part(30_001, 30_000, 1, 0xdead_beef, &[0x41])];

        assert!(
            matches!(decode_bytes(&malicious), Err(QuantusUrError::UrError(_))),
            "Out-of-bounds fragment metadata should be rejected before decoding"
        );
        assert!(!is_complete(&malicious), "Out-of-bounds fragment should not be complete");
    }

    #[test]
    fn test_multi_part_rejects_oversized_fragment_data() {
        let data = vec![0x41; MAX_FRAGMENT_LENGTH + 1];
        let message_length = data.len() as u32 * 2;
        let malicious = vec![craft_multipart_part(1, 2, message_length, 0xdead_beef, &data)];

        assert!(
            matches!(decode_bytes(&malicious), Err(QuantusUrError::UrError(_))),
            "Fragments larger than the encoding envelope should be rejected"
        );
        assert!(!is_complete(&malicious), "Oversized fragment should not be complete");
    }

    #[test]
    fn test_multi_part_rejects_inconsistent_metadata() {
        let first = craft_multipart_part(1, 2, 300, 0xdead_beef, &[0x41; 200]);
        let second = craft_multipart_part(2, 2, 300, 0xfeed_face, &[0x42; 200]);

        let parts = vec![first, second];
        assert!(
            matches!(decode_bytes(&parts), Err(QuantusUrError::UrError(_))),
            "Fragments describing different messages should be rejected"
        );
        assert!(!is_complete(&parts), "Inconsistent fragments should not be complete");
    }

    /// UR-encodes raw CBOR, mirroring `encode_internal` but without the canonical
    /// bytestring wrapper, so tests can craft non-canonical payloads.
    fn encode_cbor_as_ur(cbor: &[u8]) -> Vec<String> {
        let result = probe_encode(cbor, DEFAULT_FRAGMENT_LENGTH, UR_TYPE.to_string())
            .expect("Encoding failed");

        if !result.is_multi_part {
            return vec![result.data.to_uppercase()];
        }

        let mut encoder = result.encoder.expect("Multi-part but no encoder returned");
        let count = encoder.fragment_count();
        let mut parts = Vec::with_capacity(count);
        parts.push(result.data.to_uppercase());
        while parts.len() < count {
            parts.push(encoder.next_part().expect("Encoding failed").to_uppercase());
        }
        parts
    }

    fn wrap_payload_with_trailing_cbor(payload: &[u8]) -> Vec<u8> {
        let mut cbor = minicbor::to_vec(ByteVec::from(payload.to_vec())).expect("Encoding failed");
        let trailing =
            minicbor::to_vec(ByteVec::from(b"attacker trailer".to_vec())).expect("Encoding failed");
        cbor.extend_from_slice(&trailing);
        cbor
    }

    #[test]
    fn test_encode_rejects_payload_beyond_decode_envelope() {
        let oversized = vec![0u8; MAX_MESSAGE_LENGTH + 1];
        assert!(
            matches!(encode_bytes(&oversized), Err(QuantusUrError::UrError(_))),
            "Payloads the decoder can't accept should be rejected at encode time"
        );

        let largest = vec![0u8; MAX_MESSAGE_LENGTH - 8];
        let parts = encode_bytes(&largest).expect("Encoding failed");
        assert!(parts.len() <= MAX_FRAGMENT_COUNT, "Should stay within the fragment bound");
        assert_eq!(decode_bytes(&parts).expect("Decoding failed"), largest);
    }

    #[test]
    fn test_single_part_rejects_trailing_cbor() {
        let smuggled = encode_cbor_as_ur(&wrap_payload_with_trailing_cbor(b"approved payload"));
        assert_eq!(smuggled.len(), 1, "Should be single part");

        assert!(
            matches!(decode_bytes(&smuggled), Err(QuantusUrError::CborError(_))),
            "CBOR with trailing data should be rejected"
        );
    }

    #[test]
    fn test_multi_part_rejects_trailing_cbor() {
        let smuggled = encode_cbor_as_ur(&wrap_payload_with_trailing_cbor(&multi_part_payload()));
        assert!(smuggled.len() > 1, "Should be multi-part");

        assert!(
            matches!(decode_bytes(&smuggled), Err(QuantusUrError::CborError(_))),
            "Multipart CBOR with trailing data should be rejected"
        );
    }

    #[test]
    fn test_decode_bytes_hex_equivalence() {
        let hex_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000";
        let encoded_parts = encode_hex(hex_payload).expect("Encoding failed");
        
        let decoded_hex = decode_hex(&encoded_parts).expect("Decoding failed");
        let decoded_bytes = decode_bytes(&encoded_parts).expect("Decoding failed");
        
        assert_eq!(decoded_hex.to_lowercase(), hex_payload.to_lowercase());
        assert_eq!(hex::encode(&decoded_bytes), decoded_hex);
    }
}
