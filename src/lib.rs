use hex;
use minicbor::{bytes::ByteVec, Decoder};
use ur::ur::Kind;
use ur_parse_lib::keystone_ur_encoder::probe_encode;

const UR_TYPE: &str = "quantus-sign-request";
const MAX_FRAGMENT_LENGTH: usize = 200;

#[derive(Debug)]
pub enum QuantusUrError {
    HexError(hex::FromHexError),
    UrError(String),
    CborError(String),
    Incomplete,
}

impl std::fmt::Display for QuantusUrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuantusUrError::HexError(e) => write!(f, "Hex decoding error: {}", e),
            QuantusUrError::UrError(msg) => write!(f, "UR error: {}", msg),
            QuantusUrError::CborError(msg) => write!(f, "CBOR error: {}", msg),
            QuantusUrError::Incomplete => write!(f, "Decoding incomplete"),
        }
    }
}

impl std::error::Error for QuantusUrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            QuantusUrError::HexError(e) => Some(e),
            _ => None,
        }
    }
}

fn encode_internal(payload: &[u8]) -> Result<Vec<String>, QuantusUrError> {
    let cbor = minicbor::to_vec(ByteVec::from(payload.to_vec()))
        .map_err(|e| QuantusUrError::CborError(e.to_string()))?;

    let result = probe_encode(&cbor, MAX_FRAGMENT_LENGTH, UR_TYPE.to_string())
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
    let payload = hex::decode(hex_payload).map_err(QuantusUrError::HexError)?;
    encode_internal(&payload)
}

pub fn encode_bytes(payload: &[u8]) -> Result<Vec<String>, QuantusUrError> {
    encode_internal(payload)
}

fn decode_internal(ur_parts: &[String]) -> Result<Vec<u8>, QuantusUrError> {
    if ur_parts.is_empty() {
        return Err(QuantusUrError::UrError("No UR parts provided".to_string()));
    }

    let first = ur_parts[0].to_lowercase();
    let (kind, decoded) =
        ur::ur::decode(&first).map_err(|e| QuantusUrError::UrError(e.to_string()))?;

    match kind {
        Kind::SinglePart => {
            let mut d = Decoder::new(&decoded);
            let bytes = d
                .bytes()
                .map_err(|e| QuantusUrError::CborError(e.to_string()))?;
            Ok(bytes.to_vec())
        }
        Kind::MultiPart => {
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
            let mut dec = Decoder::new(&message);
            let bytes = dec
                .bytes()
                .map_err(|e| QuantusUrError::CborError(e.to_string()))?;
            Ok(bytes.to_vec())
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
    let (kind, _) = match ur::ur::decode(&first) {
        Ok(result) => result,
        Err(_) => return false,
    };

    match kind {
        Kind::SinglePart => true,
        Kind::MultiPart => {
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
    fn test_decode_bytes_hex_equivalence() {
        let hex_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000";
        let encoded_parts = encode_hex(hex_payload).expect("Encoding failed");
        
        let decoded_hex = decode_hex(&encoded_parts).expect("Decoding failed");
        let decoded_bytes = decode_bytes(&encoded_parts).expect("Decoding failed");
        
        assert_eq!(decoded_hex.to_lowercase(), hex_payload.to_lowercase());
        assert_eq!(hex::encode(&decoded_bytes), decoded_hex);
    }
}
