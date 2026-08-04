#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use hex;
use minicbor::{bytes::ByteVec, Decoder};
use ur_parse_lib::keystone_ur_encoder::probe_encode;

const UR_TYPE: &str = "quantus-sign-request";
/// Full prefix every inbound fragment must carry, including the trailing slash.
const UR_PREFIX: &str = "ur:quantus-sign-request/";
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

/// The 256 minimal bytewords (first + last letter of each BCR-2020-005 word),
/// two letters per byte value.
const MINIMAL_WORDS: &[u8; 512] = b"aeadaoaxaaahamatayasbkbdbnbtbabsbebybgbwbbbzcmchcscfcycwcecackctcxclcpcndkdadsdidedtdrdndwdpdmdldyeheyeoeeecenemetesftfrfnfsfmfhfzfpfwfxfyfefgflfdgagegrgsgtglgwgdgygmgughgohfhghdhkhthphhhlhyhehnhsidiaieihiyioisinimjejzjnjtjljojsjpjkjykpkoktkskkknkgkekikblblalylflslrlplnltloldlelulklgmnmymhmemomumwmdmtmsmknlnyndnsntnnnenboyoeotoxonolospdptpkpypspmplpepfpaprqdqzrerprlrorhrdrkrfryrnrsrtsesasrssskswstspsosgsbsfsntotktitttdtetytltbtstptatnuyuoutueurvtvyvovlvevwvavdvswlwdwmwpwewywswtwnwzwfwkykynylyaytzszoztzczezm";

/// Sentinel for "not a byteword" in the decode table; u16 so the legitimate
/// byte value 0xFF cannot collide with it.
const INVALID_WORD: u16 = 0xFFFF;

/// (first letter, last letter) -> byte value, `INVALID_WORD` for non-words.
const MINIMAL_DECODE_TABLE: [u16; 676] = build_minimal_decode_table();

const fn build_minimal_decode_table() -> [u16; 676] {
    let mut table = [INVALID_WORD; 676];
    let mut i = 0;
    while i < 256 {
        let c1 = MINIMAL_WORDS[i * 2] - b'a';
        let c2 = MINIMAL_WORDS[i * 2 + 1] - b'a';
        table[c1 as usize * 26 + c2 as usize] = i as u16;
        i += 1;
    }
    table
}

const CRC32_TABLE: [u32; 256] = build_crc32_table();

/// CRC-32 ISO-HDLC (reflected, poly 0xEDB88320), matching the bytewords checksum.
const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c = CRC32_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// Decodes minimal-style bytewords, verifying and stripping the trailing CRC-32
/// checksum. Accepts upper- and lowercase, so scanned fragments need no
/// normalization pass. Table lookups replace the dependency's per-word phf hash.
fn decode_minimal_bytewords(encoded: &str) -> Result<Vec<u8>, QuantusUrError> {
    let bytes = encoded.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(QuantusUrError::UrError(
            "Invalid bytewords length".to_string(),
        ));
    }

    let mut data = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let c1 = pair[0].to_ascii_lowercase().wrapping_sub(b'a');
        let c2 = pair[1].to_ascii_lowercase().wrapping_sub(b'a');
        let value = if c1 < 26 && c2 < 26 {
            MINIMAL_DECODE_TABLE[c1 as usize * 26 + c2 as usize]
        } else {
            INVALID_WORD
        };
        if value == INVALID_WORD {
            return Err(QuantusUrError::UrError("Invalid byteword".to_string()));
        }
        data.push(value as u8);
    }

    if data.len() < 4 {
        return Err(QuantusUrError::UrError(
            "Invalid bytewords checksum".to_string(),
        ));
    }
    let payload_len = data.len() - 4;
    let (payload, checksum) = data.split_at(payload_len);
    if crc32(payload).to_be_bytes() != checksum {
        return Err(QuantusUrError::UrError(
            "Invalid bytewords checksum".to_string(),
        ));
    }
    data.truncate(payload_len);
    Ok(data)
}

/// Decodes one `ur:quantus-sign-request/...` fragment into its kind and CBOR
/// payload, equivalent to `ur::ur::decode` but without lowercasing the input or
/// hashing every byteword.
fn decode_ur_part(part: &str) -> Result<(ur::ur::Kind, Vec<u8>), QuantusUrError> {
    let head = part.get(..UR_PREFIX.len()).unwrap_or("");
    if !head.eq_ignore_ascii_case(UR_PREFIX) {
        return Err(QuantusUrError::UrError("Unexpected UR type".to_string()));
    }
    let body = &part[UR_PREFIX.len()..];

    match body.rsplit_once('/') {
        None => Ok((
            ur::ur::Kind::SinglePart,
            decode_minimal_bytewords(body)?,
        )),
        Some((indices, payload)) => {
            let Some((index, index_total)) = indices.split_once('-') else {
                return Err(QuantusUrError::UrError("Invalid indices".to_string()));
            };
            if index.parse::<u16>().is_err() || index_total.parse::<u16>().is_err() {
                return Err(QuantusUrError::UrError("Invalid indices".to_string()));
            }
            Ok((
                ur::ur::Kind::MultiPart,
                decode_minimal_bytewords(payload)?,
            ))
        }
    }
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

    // Reject before materializing parts: the decoder caps fragment sets at
    // MAX_FRAGMENT_COUNT, so a larger count here could never round-trip.
    let count = encoder.fragment_count();
    if count > MAX_FRAGMENT_COUNT {
        return Err(QuantusUrError::UrError(
            "Fragment count exceeds supported maximum".to_string(),
        ));
    }
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

/// Validates every inbound multipart fragment before it reaches the fountain decoder.
///
/// The fountain decoder sizes its work from metadata carried inside the fragment,
/// so a tiny fragment claiming a huge sequence count would otherwise drive large
/// allocations. Enforce the encoder's fragment envelope and that all fragments
/// describe the same message.
fn validate_multipart_parts(decoded_parts: &[Vec<u8>]) -> Result<(), QuantusUrError> {
    // (sequence_count, message_length, checksum, data_length) shared by all fragments.
    let mut expected: Option<(usize, usize, u32, usize)> = None;

    for decoded in decoded_parts {
        let mut part_decoder = Decoder::new(decoded);
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

/// Fragments normalized, UR-decoded, and validated, ready for final assembly.
enum PreparedParts {
    Single(Vec<u8>),
    Multi(Vec<Vec<u8>>),
}

/// UR-decodes every fragment exactly once and, for multipart input, validates
/// all fountain metadata before anything reaches the fountain decoder.
fn prepare_parts(ur_parts: &[String]) -> Result<PreparedParts, QuantusUrError> {
    if ur_parts.is_empty() {
        return Err(QuantusUrError::UrError("No UR parts provided".to_string()));
    }

    let (kind, decoded) = decode_ur_part(&ur_parts[0])?;

    match kind {
        ur::ur::Kind::SinglePart => {
            if ur_parts.len() != 1 {
                return Err(QuantusUrError::UrError(
                    "Single-part UR must be the only provided part".to_string(),
                ));
            }
            Ok(PreparedParts::Single(decoded))
        }
        ur::ur::Kind::MultiPart => {
            if ur_parts.len() > MAX_FRAGMENT_COUNT {
                return Err(QuantusUrError::UrError(
                    "Too many UR parts provided".to_string(),
                ));
            }

            let mut decoded_parts = Vec::with_capacity(ur_parts.len());
            decoded_parts.push(decoded);
            for part in &ur_parts[1..] {
                let (kind, decoded) = decode_ur_part(part)?;
                if kind != ur::ur::Kind::MultiPart {
                    return Err(QuantusUrError::UrError("Mixed UR part kinds".to_string()));
                }
                decoded_parts.push(decoded);
            }

            validate_multipart_parts(&decoded_parts)?;
            Ok(PreparedParts::Multi(decoded_parts))
        }
    }
}

/// Feeds validated fountain-part CBOR into the fountain decoder, one part at a
/// time. `ur::ur::Decoder::receive` would re-decode each fragment from its
/// string form, so go through the public `fountain::Decoder` + `minicbor`
/// `Decode` impl of `Part` instead.
fn assemble_message(decoded_parts: &[Vec<u8>]) -> Result<ur::fountain::Decoder, QuantusUrError> {
    let mut d = ur::fountain::Decoder::default();
    for decoded in decoded_parts {
        let part: ur::fountain::Part = minicbor::decode(decoded).map_err(ur_error)?;
        d.receive(part).map_err(ur_error)?;
    }
    Ok(d)
}

fn decode_internal(ur_parts: &[String]) -> Result<Vec<u8>, QuantusUrError> {
    match prepare_parts(ur_parts)? {
        PreparedParts::Single(decoded) => decode_cbor_payload(&decoded),
        PreparedParts::Multi(decoded_parts) => {
            let d = assemble_message(&decoded_parts)?;
            if !d.complete() {
                return Err(QuantusUrError::Incomplete);
            }
            let message = d
                .message()
                .map_err(ur_error)?
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
    match prepare_parts(ur_parts) {
        // A single-part UR is only complete when it is the whole input, which
        // `prepare_parts` already enforced.
        Ok(PreparedParts::Single(_)) => true,
        Ok(PreparedParts::Multi(decoded_parts)) => match assemble_message(&decoded_parts) {
            Ok(d) => d.complete(),
            Err(_) => false,
        },
        Err(_) => false,
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
    fn test_crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_minimal_bytewords_all_words() {
        for i in 0..256usize {
            // Route byte `i` through the dependency's encoder so the checksum
            // is real, then decode with the fast table.
            let encoded = ur::bytewords::encode(&[i as u8], ur::bytewords::Style::Minimal);
            let decoded = decode_minimal_bytewords(&encoded).expect("decode");
            assert_eq!(decoded, vec![i as u8], "word index {i}");
            // Case-insensitivity: same result from uppercase input.
            let decoded_upper = decode_minimal_bytewords(&encoded.to_ascii_uppercase()).expect("decode");
            assert_eq!(decoded_upper, vec![i as u8], "word index {i} uppercase");
        }
    }

    #[test]
    fn test_decode_ur_part_matches_dependency() {
        // Single- and multi-part, upper- and lowercase: identical results.
        let payloads: Vec<Vec<u8>> = vec![
            b"Hello, Quantus!".to_vec(),
            multi_part_payload(),
            (0..7219u32).map(|i| (i % 251) as u8).collect(),
        ];
        for payload in payloads {
            for parts in [
                encode_bytes(&payload).expect("encode"),
                encode_bytes_with_options(&payload, 700).expect("encode"),
            ] {
            for part in &parts {
                let lower = part.to_ascii_lowercase();
                let expected = ur::ur::decode(&lower).expect("dependency decode");
                let actual = decode_ur_part(&lower).expect("fast decode");
                assert_eq!(expected.0, actual.0);
                assert_eq!(expected.1, actual.1);
                // The dependency requires lowercase; ours must accept the
                // uppercase scan equally.
                let actual_upper = decode_ur_part(part).expect("fast decode uppercase");
                assert_eq!(expected.0, actual_upper.0);
                assert_eq!(expected.1, actual_upper.1);
            }
            }
        }
    }

    #[test]
    fn test_decode_ur_part_rejects_bad_checksum_and_indices() {
        let parts = encode_bytes(b"Hello, Quantus!").expect("encode");
        let part = parts[0].to_ascii_lowercase();

        // Flip a character in the bytewords body: checksum must catch it.
        let mut corrupted = part.clone();
        let last = corrupted.len() - 1;
        let flipped = if corrupted.as_bytes()[last] == b'a' { b'e' } else { b'a' };
        corrupted.replace_range(last.., core::str::from_utf8(&[flipped]).unwrap());
        assert!(decode_ur_part(&corrupted).is_err());

        // Malformed sequence indices.
        assert!(decode_ur_part("ur:quantus-sign-request/1-1a/aeae").is_err());
        assert!(decode_ur_part("ur:quantus-sign-request/aeae").is_err());
        assert!(decode_ur_part("ur:crypto-psbt/aeaeaeae").is_err());
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

    #[test]
    fn test_encode_with_options_rejects_fragment_count_beyond_decoder_bound() {
        // 1,025 bytes at 1 byte per fragment would need 1,028 parts, beyond the
        // decoder's MAX_FRAGMENT_COUNT envelope.
        let payload = vec![0x42; 1_025];
        assert!(
            matches!(
                encode_bytes_with_options(&payload, 1),
                Err(QuantusUrError::UrError(_))
            ),
            "Fragment counts beyond the decoder's bound must be rejected at encode time"
        );

        // A small fragment length that stays within the bound still round-trips.
        let payload = multi_part_payload();
        let parts = encode_bytes_with_options(&payload, 50).expect("Encoding failed");
        assert!(parts.len() <= MAX_FRAGMENT_COUNT);
        assert_eq!(decode_bytes(&parts).expect("Decoding failed"), payload);
        assert!(is_complete(&parts));
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
