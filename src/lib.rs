// src/lib.rs

//! # evnx-crypto
//!
//! Zero-knowledge encryption primitives for evnx cloud sync.
//!
//! ## Module Overview
//!
//! | Module | Purpose | Week |
//! |--------|---------|------|
//! | `kdf`     | Argon2id key derivation (master key + SRP password) | 1 |
//! | `vault`   | AES-256-GCM vault encryption + XChaCha20 key wrapping | 1 |
//! | `keypair` | Ed25519 + X25519 keypairs, private key encryption, ECDH vault sharing | 2 |
//! | `srp`     | SRP-6a client — verifier, ephemeral, proof, verification | 2 |
//! | `zeroize` | Secure memory types for heap-allocated secrets | 2 |
//! | `errors`  | `CryptoError` enum | 1 |
//! | `encoding` | base64 / hex wire-format helpers shared by the modules above | 1 |

pub mod encoding;
pub mod errors;
pub mod kdf;
pub mod keypair;
pub mod srp;
pub mod vault;
pub mod zeroize;

// Re-export the most commonly used types at crate root
pub use encoding::{b64_decode, b64_decode_array, b64_encode};
pub use errors::CryptoError;
pub use kdf::{
    derive_master_key, derive_srp_password, generate_salt, salt_from_base64, salt_to_base64,
    MasterKey,
};
pub use keypair::{
    decrypt_private_key, encrypt_private_key, generate_keypair, unwrap_vault_key,
    wrap_vault_key_for_user, Ed25519PublicKey, EncryptedPrivateKey, UserKeypair, WrappedVaultKey,
    X25519PublicKeyBytes,
};
pub use srp::{
    compute_client_proof, compute_verifier, generate_client_ephemeral, verify_server_proof,
    SrpClientEphemeral, SrpClientProof, SrpVerifier,
};
pub use vault::{
    decrypt_vault, encrypt_vault, unwrap_vault_key_with_master_key, wrap_vault_key_with_master_key,
    EncryptedBlob, VaultKey,
};
pub use zeroize::{zeroize_slice, SecretArray, SecretBytes, SecretString};
