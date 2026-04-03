use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Key derivation failed: {0}")]
    Kdf(String),
    #[error("Encryption failed")]
    Encryption,
    #[error("Decryption failed — wrong key or tampered data")]
    Decryption,
    #[error("Integrity check failed — ciphertext hash mismatch")]
    IntegrityCheck,
    #[error("Key wrap failed")]
    KeyWrap,
    #[error("Key unwrap failed — wrong key or tampered wrapped key")]
    KeyUnwrap,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("SRP error: {0}")]
    Srp(String),
}