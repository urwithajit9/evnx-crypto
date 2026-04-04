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

pub mod errors;
pub mod kdf;
pub mod keypair;
pub mod srp;
pub mod vault;
pub mod zeroize;

// Re-export the most commonly used types at crate root
pub use errors::CryptoError;
pub use kdf::{MasterKey, derive_master_key, derive_srp_password, generate_salt};
pub use vault::{VaultKey, EncryptedBlob, encrypt_vault, decrypt_vault,
    wrap_vault_key_with_master_key, unwrap_vault_key_with_master_key};
pub use keypair::{
    UserKeypair, EncryptedPrivateKey, WrappedVaultKey,
    Ed25519PublicKey, X25519PublicKeyBytes,
    generate_keypair, encrypt_private_key, decrypt_private_key,
    wrap_vault_key_for_user, unwrap_vault_key,
};
pub use srp::{
    SrpVerifier, SrpClientEphemeral, SrpClientProof,
    compute_verifier, generate_client_ephemeral,
    compute_client_proof, verify_server_proof,
};
pub use zeroize::{SecretBytes, SecretString, SecretArray, zeroize_slice};