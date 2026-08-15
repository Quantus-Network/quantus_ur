//! Attack-simulation helpers shared by this crate's tests and the `fuzz/` targets.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Largest fragment the encoder accepts, so fuzz targets can stay in range.
pub const MAX_FRAGMENT_LENGTH: usize = crate::MAX_FRAGMENT_LENGTH;

/// Re-labels an encoded fragment with a different UR type, as an attacker
/// substituting a foreign UR into a scan would. `None` when `part` does not
/// carry this crate's UR prefix.
pub fn rewrite_ur_type(part: &str, new_type: &str) -> Option<String> {
    let lower = part.to_lowercase();
    let body = lower.strip_prefix(crate::UR_PREFIX)?;
    Some(format!("ur:{}/{}", new_type, body))
}

/// Builds a multipart fragment with arbitrary fountain metadata, bypassing the
/// encoder's bounds.
pub fn craft_multipart_part(
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
    format!(
        "ur:{}/{}-{}/{}",
        crate::UR_TYPE,
        sequence,
        sequence_count,
        body
    )
}
