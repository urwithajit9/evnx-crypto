// src/encoding.rs

//! Wire-format encoding helpers shared by every module.
//!
//! The evnx API transmits all binary values as text inside JSON:
//!
//! | Value | Encoding | Wire length |
//! |-------|----------|-------------|
//! | Argon2 salt, SRP salt | base64 (padded) | 44 chars (32 bytes) |
//! | Ed25519 / X25519 public key | base64 (padded) | 44 chars (32 bytes) |
//! | `EncryptedPrivateKey` | base64 (padded) of `nonce \|\| ciphertext` | 96 chars |
//! | `WrappedVaultKey` fields | base64 (padded) | variable |
//! | SRP verifier | lowercase hex | 256–1024 chars |
//!
//! Base64 is standard alphabet **with** padding — the server validates exact
//! character counts (e.g. `length(equal = 44)`), so unpadded base64 would be
//! rejected. Do not switch to `Base64Unpadded`.

use base64ct::{Base64, Encoding};

use crate::errors::CryptoError;

/// Encode bytes as standard padded base64.
pub fn b64_encode(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

/// Decode standard padded base64 into bytes.
///
/// `what` names the value being decoded and appears in the error message —
/// it must never contain the value itself.
pub fn b64_decode(s: &str, what: &str) -> Result<Vec<u8>, CryptoError> {
    Base64::decode_vec(s).map_err(|_| CryptoError::InvalidInput(format!("{what}: invalid base64")))
}

/// Decode standard padded base64 into a fixed-size array.
///
/// Returns [`CryptoError::InvalidInput`] if the decoded length is not exactly `N`.
pub fn b64_decode_array<const N: usize>(s: &str, what: &str) -> Result<[u8; N], CryptoError> {
    let bytes = b64_decode(s, what)?;
    if bytes.len() != N {
        return Err(CryptoError::InvalidInput(format!(
            "{what}: expected {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
