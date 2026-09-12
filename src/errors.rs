//! The single error type returned by every fallible operation in this crate.

use thiserror::Error;

/// Everything that can go wrong in evnx-crypto.
///
/// Variants are deliberately coarse where an attacker might be watching. In
/// particular [`CryptoError::Decryption`] does not distinguish "wrong key" from
/// "tampered ciphertext" from "wrong associated data" — telling them apart would
/// hand an attacker a decryption oracle.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Argon2id or HKDF derivation failed. Carries the underlying description,
    /// which never contains key material.
    #[error("Key derivation failed: {0}")]
    Kdf(String),

    /// Authenticated encryption failed. In practice this only happens on
    /// pathological input sizes; a correct caller will not see it.
    #[error("Encryption failed")]
    Encryption,

    /// Authenticated decryption failed.
    ///
    /// The key is wrong, the ciphertext or nonce was modified, or the associated
    /// data does not match what the blob was sealed with. Which one is not
    /// reported, on purpose.
    #[error("Decryption failed — wrong key or tampered data")]
    Decryption,

    /// A content hash did not match the expected value.
    #[error("Integrity check failed — ciphertext hash mismatch")]
    IntegrityCheck,

    /// Wrapping a key under another key failed.
    #[error("Key wrap failed")]
    KeyWrap,

    /// Unwrapping a key failed — wrong wrapping key, or the wrapped blob was
    /// modified.
    #[error("Key unwrap failed — wrong key or tampered wrapped key")]
    KeyUnwrap,

    /// A value was malformed: wrong length, invalid base64, or otherwise not
    /// the shape this function requires. The message names the field, never its
    /// contents.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// An X25519 public key produced a non-contributory (all-zero) shared secret.
    ///
    /// The peer supplied a low-order point, so the shared secret is independent of
    /// our private key and therefore predictable by anyone. Treat this as a
    /// key-substitution attempt, not a transient failure.
    #[error("Invalid public key — non-contributory ECDH, possible key-substitution attack")]
    InvalidPublicKey,

    /// The SRP-6a exchange failed or the peer sent an invalid protocol value.
    #[error("SRP error: {0}")]
    Srp(String),
}
