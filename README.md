# quantus_ur

A Rust library for encoding and decoding Quantus sign requests using the [UR (Uniform Resources)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md) standard for QR code transmission.

## Overview

`quantus_ur` provides a simple interface for converting hex-encoded payloads into UR-encoded QR code strings and decoding them back. It implements the UR standard (BCR-2020-005) with support for both single-part and multi-part message encoding, making it suitable for transmitting cryptocurrency signing requests via QR codes.

## UR Standard

This library implements the [Uniform Resources (UR)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md) specification (BCR-2020-005), which provides a standard way to encode binary data into QR codes with support for:

- **Single-part encoding**: Small payloads encoded in a single QR code
- **Multi-part encoding**: Large payloads split across multiple QR codes with error correction
- **CBOR encoding**: Payloads are encoded using [CBOR (Concise Binary Object Representation)](https://cbor.io/) for efficient binary serialization

The UR type used by this library is `quantus-sign-request`, which wraps the payload in a CBOR bytestring.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
quantus_ur = { git = "https://github.com/Quantus-Network/quantus_ur.git", tag = "1.0.0" }
```

## Requirements

This crate works with **stable Rust** (1.70+). No nightly toolchain is required.

## Usage

### Encoding

Convert a hex string or binary data into UR-encoded QR code strings:

```rust
use quantus_ur::{encode, encode_bytes};

// Encode from hex string
let hex_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000";
let ur_parts = encode(hex_payload)?;

// Encode from binary bytes
let binary_payload = b"Hello, Quantus!";
let ur_parts = encode_bytes(binary_payload)?;

// ur_parts is a Vec<String> containing one or more UR-encoded strings
// For small payloads: single QR code
// For large payloads: multiple QR codes for multi-part transmission
```

### Decoding

Decode UR-encoded QR code strings back to hex or binary:

```rust
use quantus_ur::{decode, decode_bytes};

// Decode to hex string
let decoded_hex = decode(&ur_parts)?;

// Decode to binary bytes
let decoded_bytes = decode_bytes(&ur_parts)?;
```

### Complete Example

```rust
use quantus_ur::{encode, decode, encode_bytes, decode_bytes, QuantusUrError};

fn main() -> Result<(), QuantusUrError> {
    // Example 1: Hex encoding/decoding
    let hex_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000";
    
    let ur_parts = encode(hex_payload)?;
    println!("Encoded into {} QR code(s):", ur_parts.len());
    for (i, part) in ur_parts.iter().enumerate() {
        println!("  Part {}: {}", i + 1, part);
    }
    
    let decoded_hex = decode(&ur_parts)?;
    assert_eq!(decoded_hex.to_lowercase(), hex_payload.to_lowercase());
    println!("Decoded successfully: {}", decoded_hex);
    
    // Example 2: Binary encoding/decoding
    let binary_payload = b"Hello, Quantus!";
    let ur_parts = encode_bytes(binary_payload)?;
    let decoded_bytes = decode_bytes(&ur_parts)?;
    assert_eq!(decoded_bytes, binary_payload);
    println!("Binary roundtrip successful");
    
    Ok(())
}
```

## Implementation Details

- **UR Type**: `quantus-sign-request`
- **Max Fragment Length**: 200 bytes (configurable via `MAX_FRAGMENT_LENGTH`)
- **Encoding Format**: Payloads are wrapped in CBOR bytestrings before UR encoding
- **Multi-part Support**: Automatically splits large payloads across multiple QR codes

## References

- [UR Specification (BCR-2020-005)](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)
- [CBOR Specification (RFC 8949)](https://www.rfc-editor.org/rfc/rfc8949.html)
- [UR Registry](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-ur-types.md)
- [Blockchain Commons UR Documentation](https://github.com/BlockchainCommons/Research)

## License

See [LICENSE](LICENSE) file for details.
