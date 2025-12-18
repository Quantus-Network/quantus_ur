use hex;
use minicbor::{bytes::ByteVec, Decoder};
use thiserror::Error;
use ur::ur::Kind;
use ur_parse_lib::keystone_ur_encoder::probe_encode;

const UR_TYPE: &str = "quantus-sign-request";
const MAX_FRAGMENT_LENGTH: usize = 200;

#[derive(Error, Debug)]
pub enum QuantusUrError {
    #[error("Hex decoding error: {0}")]
    HexError(hex::FromHexError),
    #[error("UR error: {0}")]
    UrError(String),
    #[error("CBOR error: {0}")]
    CborError(String),
    #[error("Decoding incomplete")]
    Incomplete,
}

pub fn encode(hex_payload: &str) -> Result<Vec<String>, QuantusUrError> {
    let payload = hex::decode(hex_payload).map_err(QuantusUrError::HexError)?;
    let cbor = minicbor::to_vec(ByteVec::from(payload))
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

pub fn decode(ur_parts: &[String]) -> Result<String, QuantusUrError> {
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
            Ok(hex::encode(bytes))
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
            Ok(hex::encode(bytes))
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

        let encoded_parts = encode(hex_payload).expect("Encoding failed");
        assert_eq!(encoded_parts.len(), 1, "Should be single part");

        let decoded_hex = decode(&encoded_parts).expect("Decoding failed");
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

        let encoded_parts = encode(&large_payload).expect("Encoding failed");
        assert!(encoded_parts.len() > 1, "Should be multi-part");

        // Print parts for debug
        // for (i, part) in encoded_parts.iter().enumerate() {
        //     println!("Part {}: {}", i, part);
        // }

        let decoded_hex = decode(&encoded_parts).expect("Decoding failed");
        assert_eq!(decoded_hex.to_lowercase(), large_payload.to_lowercase());
    }
}
