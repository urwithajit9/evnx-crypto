// src/lib.rs

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

//! Zero-knowledge encryption primitives for evnx cloud sync.
//!
//! Everything secret happens here, on the client. The evnx server stores
//! ciphertext, wrapped keys and public keys; it never holds a password, a master
//! key, a vault key, or a plaintext `.env`. This crate is what makes that true,
//! so its threat model is worth stating plainly.
//!
//! # Threat model
//!
//! **The server is untrusted.** It may be breached, compelled, or hostile. It can
//! return any bytes it likes — old ciphertext, keys it generated itself,
//! public keys chosen to be degenerate. Callers must assume every value that
//! arrives from the network is attacker-controlled, and this crate is written to
//! stay safe when it is.
//!
//! Concretely, that means:
//!
//! - ECDH rejects non-contributory (low-order) public keys, so a server cannot
//!   force a predictable shared secret and substitute a vault key it knows.
//! - Vault blobs are bound to their identity with AEAD associated data, so a
//!   server cannot replay an old version as the current one. See [`vault_aad`].
//! - The two password derivations are domain-separated, so reusing one salt
//!   cannot make the SRP input equal the master key.
//! - Every symmetric key is an HKDF subkey with its own domain tag; no key is
//!   ever the live cipher key for two purposes.
//!
//! **Out of scope:** a compromised client. If an attacker runs code on the
//! user's machine while they are logged in, they can read the plaintext. This
//! crate protects data at rest and in transit, not a hostile local process.
//!
//! # Key hierarchy
//!
//! ```text
//! password
//!   └─ Argon2id(m=64MB, t=3, p=4) ─┬─ MasterKey          (never leaves the device)
//!                                  └─ SRP password input (proves identity, reveals nothing)
//!
//! MasterKey ─ HKDF ─┬─ encrypts the Ed25519 private key seed
//!                   └─ wraps VaultKeys for solo vaults
//!
//! Ed25519 seed ─ HKDF ─ X25519 private key   (one encrypted seed restores both;
//!                                             the Ed25519 half is not yet used to sign)
//!
//! VaultKey ─ AES-256-GCM ─ the .env ciphertext
//!          └─ X25519-ECDH ─ HKDF ─ XChaCha20-Poly1305 ─ wrapped for a teammate
//! ```
//!
//! # Module overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`kdf`] | Argon2id derivation of the master key and the SRP password input |
//! | [`vault`] | AES-256-GCM vault encryption and master-key wrapping |
//! | [`keypair`] | Ed25519 + X25519 keypairs, private-key encryption, ECDH sharing |
//! | [`srp`] | SRP-6a client — verifier, ephemeral, proof, server verification |
//! | [`zeroize`] | Secret-holding types that clear themselves on drop |
//! | [`encoding`] | base64 / hex wire formats the server validates |
//! | [`errors`] | [`CryptoError`] |
//!
//! # Example — encrypt a vault and wrap its key for a teammate
//!
//! ```rust
//! use evnx_crypto::*;
//!
//! # fn main() -> Result<(), CryptoError> {
//! let vault_key = VaultKey::generate();
//!
//! // Bind the ciphertext to this vault and version so an old blob cannot be
//! // replayed in its place.
//! let aad = vault_aad("8b1f…-vault-id", 7);
//! let blob = encrypt_vault(b"API_KEY=s3cret\n", &vault_key, &aad)?;
//!
//! // Share it: wrap the vault key to the recipient's X25519 public key.
//! let teammate = generate_keypair();
//! let wrapped = wrap_vault_key_for_user(&vault_key, &teammate.x25519_public)?;
//!
//! // The teammate unwraps and decrypts.
//! let their_key = unwrap_vault_key(&wrapped, teammate.x25519_private_bytes())?;
//! let plaintext = decrypt_vault(&blob, &their_key, &aad)?;
//! assert_eq!(plaintext, b"API_KEY=s3cret\n");
//! # Ok(())
//! # }
//! ```
//!
//! # Cryptographic choices
//!
//! | Purpose | Algorithm | Why |
//! |---------|-----------|-----|
//! | Password KDF | Argon2id, 64 MB / t=3 / p=4 | OWASP 2024 minimum; memory-hard against GPU attack |
//! | Vault encryption | AES-256-GCM | Hardware-accelerated; 96-bit random nonce, see [`encrypt_vault`] for the budget |
//! | Key wrapping | XChaCha20-Poly1305 | 192-bit nonce — random nonces never collide in practice |
//! | Key agreement | X25519 | Small, fast, misuse-resistant; contributory behaviour checked |
//! | Identity keypair | Ed25519 | Seed is the single encrypted secret; the X25519 key is derived from it. **No signatures are produced yet** — the public key is registered for future use |
//! | Subkey derivation | HKDF-SHA256 | Domain separation per purpose |
//! | Authentication | SRP-6a (2048-bit, SHA-256) | The server verifies a password it never learns |

pub mod encoding;
pub mod errors;
pub mod kdf;
pub mod keypair;
pub mod srp;
pub mod vault;
pub mod zeroize;

#[cfg(feature = "wasm")]
pub mod wasm;

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
    blob_hash, decrypt_vault, encrypt_vault, unwrap_vault_key_with_master_key, vault_aad,
    wrap_vault_key_with_master_key, EncryptedBlob, VaultKey,
};
pub use zeroize::{zeroize_slice, SecretArray, SecretBytes, SecretString};
