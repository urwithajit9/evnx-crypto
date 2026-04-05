// src/keypair.rs

//! Ed25519 + X25519 keypair management and ECDH vault key wrapping.
//!
//! ## Key types and their roles
//!
//! - **Ed25519**: Signing keypair. Public key is registered with the server
//!   and used to verify vault access grants. Private key is encrypted with
//!   the user's MasterKey and stored (encrypted) on the server.
//!
//! - **X25519**: Key agreement keypair. Used exclusively for ECDH when
//!   sharing a vault with another user. Never used for signing.
//!
//! ## Vault sharing flow (ECDH)
//!
//! ```text
//! Owner:
//!   1. Fetch recipient's X25519 public key from server
//!   2. Generate ephemeral X25519 keypair
//!   3. shared_secret = X25519(eph_private, recipient_public)
//!   4. wrap_key = HKDF-SHA256(shared_secret, "evnx-vault-key-wrap-v1")
//!   5. encrypted_vault_key = XChaCha20Poly1305(vault_key, wrap_key, random_nonce)
//!   6. Send { encrypted_vault_key, eph_public_key } to server
//!   7. Zeroize eph_private, shared_secret, wrap_key
//!
//! Recipient:
//!   1. Fetch { encrypted_vault_key, eph_public_key } from server
//!   2. shared_secret = X25519(my_x25519_private, eph_public_key)
//!   3. wrap_key = HKDF-SHA256(shared_secret, "evnx-vault-key-wrap-v1")
//!   4. vault_key = XChaCha20Poly1305_decrypt(encrypted_vault_key, wrap_key)
//!   5. Zeroize shared_secret, wrap_key
//! ```

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::errors::CryptoError;
use crate::kdf::MasterKey;
use crate::vault::VaultKey;
use crate::zeroize::SecretArray;

// ─── Constants ────────────────────────────────────────────────────────────────

/// XChaCha20-Poly1305 nonce length: 192-bit.
/// Larger than AES-GCM's 96-bit — safe for random nonce generation.
const XCHACHA_NONCE_LEN: usize = 24;

/// Ed25519 signing private key length.
const ED25519_PRIVATE_LEN: usize = 32;

/// X25519 static private key length.
const X25519_PRIVATE_LEN: usize = 32;

/// X25519 public key length.
const X25519_PUBLIC_LEN: usize = 32;

/// HKDF info string for vault key wrapping.
/// Including a version suffix allows future algorithm migration.
const HKDF_INFO_VAULT_KEY_WRAP: &[u8] = b"evnx-vault-key-wrap-v1";

/// HKDF info string for private key encryption (different domain from vault wrap).
const HKDF_INFO_PRIVATE_KEY_ENC: &[u8] = b"evnx-private-key-enc-v1";

/// XChaCha20-Poly1305 key length.
const XCHACHA_KEY_LEN: usize = 32;

// ─── Public Key Types ─────────────────────────────────────────────────────────

/// Ed25519 public key — 32 bytes, safe to share publicly.
/// Registered with the server for vault access verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ed25519PublicKey(pub [u8; 32]);

/// X25519 public key — 32 bytes, safe to share publicly.
/// Used by vault owners to wrap vault keys for this user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct X25519PublicKeyBytes(pub [u8; X25519_PUBLIC_LEN]);

// ─── Keypair Types ─────────────────────────────────────────────────────────────

/// A complete user keypair: Ed25519 (signing) + X25519 (key agreement).
///
/// The private keys are `ZeroizeOnDrop`. Do not clone or copy this struct.
/// After use, allow it to drop or explicitly call `drop()`.
#[derive(ZeroizeOnDrop)]
pub struct UserKeypair {
    /// Ed25519 signing private key seed (32 bytes).
    /// The full 64-byte expanded private key is derived from this seed.
    ed25519_private_seed: [u8; ED25519_PRIVATE_LEN],

    /// Ed25519 public key (32 bytes). Safe to transmit.
    #[zeroize(skip)]
    pub ed25519_public: Ed25519PublicKey,

    /// X25519 static private key (32 bytes).
    x25519_private: [u8; X25519_PRIVATE_LEN],

    /// X25519 public key (32 bytes). Safe to transmit.
    #[zeroize(skip)]
    pub x25519_public: X25519PublicKeyBytes,
}

/// Encrypted form of the Ed25519 private key seed.
/// Stored (server-side) in the `users.encrypted_private_key` column.
///
/// Format: `[24-byte XChaCha20 nonce || ciphertext || 16-byte poly1305 tag]`
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedPrivateKey {
    pub nonce: [u8; XCHACHA_NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// An X25519 public key + ECDH-wrapped vault key for a specific recipient.
/// One row per member in `vault_members` table.
///
/// Format of `encrypted_vault_key`: `[24-byte XChaCha20 nonce || ciphertext || tag]`
#[derive(Clone, Serialize, Deserialize)]
pub struct WrappedVaultKey {
    /// Ephemeral X25519 public key used by the sender during ECDH.
    pub eph_pub_key: [u8; X25519_PUBLIC_LEN],
    /// VaultKey encrypted with the HKDF-derived wrap key.
    pub encrypted_vault_key: Vec<u8>,
}

// ─── Keypair Generation ────────────────────────────────────────────────────────

/// Generate a fresh `UserKeypair` using the OS CSPRNG.
///
/// Call this once at registration. The resulting public keys
/// are sent to the server. The private keys are encrypted with
/// the user's `MasterKey` before transmission.
pub fn generate_keypair() -> UserKeypair {
    // Ed25519: generate from random seed
    let ed25519_signing_key = SigningKey::generate(&mut OsRng);
    let ed25519_public = Ed25519PublicKey(ed25519_signing_key.verifying_key().to_bytes());
    let ed25519_private_seed = ed25519_signing_key.to_bytes();

    // // X25519: generate static keypair (for vault sharing)
    // let x25519_private_bytes: [u8; 32] = {
    //     let mut buf = [0u8; 32];
    //     OsRng.fill_bytes(&mut buf);
    //     buf
    // };
    // X25519: DERIVE from Ed25519 seed (not random!) for deterministic reconstruction
    let x25519_private_bytes = derive_x25519_from_ed25519_seed(&ed25519_private_seed)
        .expect("HKDF derivation should never fail with valid inputs");

    let x25519_static = StaticSecret::from(x25519_private_bytes);
    let x25519_public = X25519PublicKeyBytes(X25519PublicKey::from(&x25519_static).to_bytes());

    // Store the raw bytes (StaticSecret doesn't implement ZeroizeOnDrop directly)
    let x25519_private = x25519_static.to_bytes();

    UserKeypair {
        ed25519_private_seed,
        ed25519_public,
        x25519_private,
        x25519_public,
    }
}

// ─── Private Key Encryption ────────────────────────────────────────────────────

/// Encrypt the Ed25519 private key seed with the user's `MasterKey`.
///
/// Uses XChaCha20-Poly1305 for authenticated encryption.
/// The MasterKey itself is derived from the user's password client-side
/// and never sent to the server.
///
/// # Returns
/// `EncryptedPrivateKey` — safe to store on the server.
pub fn encrypt_private_key(
    keypair: &UserKeypair,
    master_key: &MasterKey,
) -> Result<EncryptedPrivateKey, CryptoError> {
    let (cipher, nonce_bytes, nonce) =
        new_xchacha_cipher(&master_key.0, HKDF_INFO_PRIVATE_KEY_ENC)?;

    let ciphertext = cipher
        .encrypt(&nonce, keypair.ed25519_private_seed.as_ref())
        .map_err(|_| CryptoError::KeyWrap)?;

    Ok(EncryptedPrivateKey {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt the Ed25519 private key seed stored on the server.
///
/// Called client-side at login after re-deriving the `MasterKey`
/// from the user's password.
///
/// # Errors
/// Returns `Err(KeyUnwrap)` if the MasterKey is wrong or the ciphertext
/// has been tampered with. Never panics.
pub fn decrypt_private_key(
    enc: &EncryptedPrivateKey,
    master_key: &MasterKey,
) -> Result<UserKeypair, CryptoError> {
    let (cipher, _, nonce) =
        new_xchacha_cipher_from_nonce(&master_key.0, &enc.nonce, HKDF_INFO_PRIVATE_KEY_ENC)?;

    let seed_bytes = cipher
        .decrypt(&nonce, enc.ciphertext.as_ref())
        .map_err(|_| CryptoError::KeyUnwrap)?;

    if seed_bytes.len() != ED25519_PRIVATE_LEN {
        return Err(CryptoError::InvalidInput(format!(
            "expected {} byte seed, got {}",
            ED25519_PRIVATE_LEN,
            seed_bytes.len()
        )));
    }

    let mut seed = [0u8; ED25519_PRIVATE_LEN];
    seed.copy_from_slice(&seed_bytes);

    // Reconstruct the signing key from seed to regenerate the public key
    let signing_key = SigningKey::from_bytes(&seed);
    let ed25519_public = Ed25519PublicKey(signing_key.verifying_key().to_bytes());

    // We also need to reconstruct the X25519 keypair.
    // NOTE: Since we only encrypted the Ed25519 seed, the X25519 private key
    // must also be stored (encrypted) separately, OR derived from the same seed.
    // DESIGN DECISION: Derive X25519 private from Ed25519 seed via HKDF.
    // This means one EncryptedPrivateKey covers both keypairs.
    let x25519_private = derive_x25519_from_ed25519_seed(&seed)?;
    let x25519_static = StaticSecret::from(x25519_private);
    let x25519_public = X25519PublicKeyBytes(X25519PublicKey::from(&x25519_static).to_bytes());

    Ok(UserKeypair {
        ed25519_private_seed: seed,
        ed25519_public,
        x25519_private: x25519_static.to_bytes(),
        x25519_public,
    })
}

/// Derive X25519 private key from Ed25519 seed using HKDF.
///
/// This lets us store one encrypted seed and reconstruct both keypairs.
/// The derivation uses a domain-separated HKDF so the derived X25519
/// key is cryptographically independent of the Ed25519 seed.
fn derive_x25519_from_ed25519_seed(
    ed25519_seed: &[u8; ED25519_PRIVATE_LEN],
) -> Result<[u8; X25519_PRIVATE_LEN], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, ed25519_seed);
    let mut x25519_private = SecretArray::<X25519_PRIVATE_LEN>::zeroed();
    hkdf.expand(b"evnx-x25519-from-ed25519-v1", &mut x25519_private.0)
        .map_err(|_| CryptoError::Kdf("HKDF expand failed for X25519 derivation".into()))?;
    Ok(x25519_private.0)
}

// ─── ECDH Vault Key Wrapping ───────────────────────────────────────────────────

/// Wrap a `VaultKey` for a specific recipient using X25519 ECDH.
///
/// The sender generates a fresh ephemeral X25519 keypair for each wrap
/// operation. The ephemeral private key is zeroized immediately after use.
///
/// # Arguments
/// * `vault_key`      — The vault encryption key to wrap
/// * `recipient_pub`  — Recipient's X25519 public key (from server)
///
/// # Returns
/// `WrappedVaultKey` — contains `eph_pub_key` and `encrypted_vault_key`.
/// Both fields are safe to store on the server.
pub fn wrap_vault_key_for_user(
    vault_key: &VaultKey,
    recipient_pub: &X25519PublicKeyBytes,
) -> Result<WrappedVaultKey, CryptoError> {
    // Generate ephemeral keypair — EphemeralSecret zeroizes on drop
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = X25519PublicKey::from(&eph_secret);

    // ECDH: compute shared secret
    let recipient_pubkey = X25519PublicKey::from(recipient_pub.0);
    let shared_secret = eph_secret.diffie_hellman(&recipient_pubkey);

    // HKDF: derive 32-byte wrap key from shared secret
    // Domain separation ensures the wrap key is distinct from any
    // other key derived from the same shared secret.
    let wrap_key = hkdf_derive_wrap_key(shared_secret.as_bytes(), HKDF_INFO_VAULT_KEY_WRAP)?;

    // Encrypt vault_key with wrap_key
    let (cipher, nonce_bytes, nonce) = new_xchacha_cipher(&wrap_key.0, &[])?;
    let ciphertext = cipher
        .encrypt(&nonce, vault_key.0.as_ref())
        .map_err(|_| CryptoError::KeyWrap)?;

    // Prepend nonce to match WrappedVaultKey format spec
    let mut encrypted_vault_key = Vec::with_capacity(XCHACHA_NONCE_LEN + ciphertext.len());
    encrypted_vault_key.extend_from_slice(&nonce_bytes);
    encrypted_vault_key.extend_from_slice(&ciphertext);

    Ok(WrappedVaultKey {
        eph_pub_key: eph_pub.to_bytes(),
        encrypted_vault_key,
    })
}

/// Unwrap a `VaultKey` using the recipient's X25519 private key.
///
/// Called client-side when pulling a vault that you're a member of.
///
/// # Arguments
/// * `wrapped`          — The `WrappedVaultKey` from the server
/// * `my_x25519_private` — Your X25519 private key bytes
pub fn unwrap_vault_key(
    wrapped: &WrappedVaultKey,
    my_x25519_private: &[u8; X25519_PRIVATE_LEN],
) -> Result<VaultKey, CryptoError> {
    // Reconstruct static secret from bytes
    let my_static = StaticSecret::from(*my_x25519_private);
    let eph_pub = X25519PublicKey::from(wrapped.eph_pub_key);

    // ECDH: same shared secret as sender computed
    let shared_secret = my_static.diffie_hellman(&eph_pub);

    // HKDF: derive the same wrap key
    let wrap_key = hkdf_derive_wrap_key(shared_secret.as_bytes(), HKDF_INFO_VAULT_KEY_WRAP)?;

    // Decrypt: extract nonce from first 24 bytes if prepended,
    // OR use a fixed nonce stored in WrappedVaultKey.
    // DESIGN: nonce is embedded in encrypted_vault_key (first 24 bytes).
    if wrapped.encrypted_vault_key.len() < XCHACHA_NONCE_LEN {
        return Err(CryptoError::InvalidInput(
            "wrapped vault key too short".into(),
        ));
    }

    let nonce_bytes: [u8; XCHACHA_NONCE_LEN] = wrapped.encrypted_vault_key[..XCHACHA_NONCE_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidInput("nonce extraction failed".into()))?;
    let ciphertext = &wrapped.encrypted_vault_key[XCHACHA_NONCE_LEN..];

    let (cipher, _, nonce) = new_xchacha_cipher_from_nonce(&wrap_key.0, &nonce_bytes, &[])?;
    let vault_key_bytes = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::KeyUnwrap)?;

    if vault_key_bytes.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "decrypted vault key wrong length".into(),
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&vault_key_bytes);
    Ok(VaultKey(key))
}

// ─── Internal Helpers ──────────────────────────────────────────────────────────

/// Derive a 32-byte XChaCha20-Poly1305 key via HKDF-SHA256.
fn hkdf_derive_wrap_key(
    input_key_material: &[u8],
    info: &[u8],
) -> Result<SecretArray<XCHACHA_KEY_LEN>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, input_key_material);
    let mut key = SecretArray::<XCHACHA_KEY_LEN>::zeroed();
    hkdf.expand(info, &mut key.0)
        .map_err(|_| CryptoError::Kdf("HKDF expand failed for wrap key".into()))?;
    Ok(key)
}

/// Create a new XChaCha20-Poly1305 cipher with a freshly derived key.
///
/// The key passed in is the raw MasterKey or HKDF-derived key.
/// The `info` parameter provides domain separation via HKDF
/// when the raw key is reused across multiple operations.
/// Pass `info = &[]` when the key is already purpose-specific (e.g., ECDH-derived).
fn new_xchacha_cipher(
    raw_key: &[u8; 32],
    info: &[u8],
) -> Result<(XChaCha20Poly1305, [u8; XCHACHA_NONCE_LEN], XNonce), CryptoError> {
    // If info is provided, derive a purpose-specific key via HKDF.
    // If info is empty, use raw_key directly.
    let key_bytes: SecretArray<XCHACHA_KEY_LEN> = if info.is_empty() {
        SecretArray::new(*raw_key)
    } else {
        let hkdf = Hkdf::<Sha256>::new(None, raw_key);
        let mut derived = SecretArray::<XCHACHA_KEY_LEN>::zeroed();
        hkdf.expand(info, &mut derived.0)
            .map_err(|_| CryptoError::Kdf("HKDF expand failed".into()))?;
        derived
    };

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key_bytes.0).map_err(|_| CryptoError::KeyWrap)?;

    let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_ref = XNonce::from_slice(&nonce_bytes);
    let nonce = *nonce_ref;

    Ok((cipher, nonce_bytes, nonce))
}

fn new_xchacha_cipher_from_nonce(
    raw_key: &[u8; 32],
    nonce_bytes: &[u8; XCHACHA_NONCE_LEN],
    info: &[u8],
) -> Result<(XChaCha20Poly1305, [u8; XCHACHA_NONCE_LEN], XNonce), CryptoError> {
    let key_bytes: SecretArray<XCHACHA_KEY_LEN> = if info.is_empty() {
        SecretArray::new(*raw_key)
    } else {
        let hkdf = Hkdf::<Sha256>::new(None, raw_key);
        let mut derived = SecretArray::<XCHACHA_KEY_LEN>::zeroed();
        hkdf.expand(info, &mut derived.0)
            .map_err(|_| CryptoError::Kdf("HKDF expand failed".into()))?;
        derived
    };

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key_bytes.0).map_err(|_| CryptoError::KeyUnwrap)?;

    let nonce = *XNonce::from_slice(nonce_bytes);
    Ok((cipher, *nonce_bytes, nonce))
}

// ─── Accessor methods for tests ───────────────────────────────────────────────

// impl UserKeypair {
//     /// Access the X25519 private key bytes for ECDH unwrapping.
//     /// Only expose to the crypto layer — never serialize or transmit.
//     #[cfg(any(test, feature = "test-utils"))]
//     #[allow(dead_code)]
//     pub fn x25519_private_bytes(&self) -> &[u8; X25519_PRIVATE_LEN] {
//         &self.x25519_private
//     }

//     /// Access the Ed25519 seed for signing operations.
//     #[cfg(any(test, feature = "test-utils"))]
//     #[allow(dead_code)]
//     pub fn ed25519_seed(&self) -> &[u8; ED25519_PRIVATE_LEN] {
//         &self.ed25519_private_seed
//     }
// }

impl UserKeypair {
    /// Access the X25519 private key bytes for ECDH unwrapping.
    /// Only expose to the crypto layer — never serialize or transmit.
    #[allow(dead_code)]
    pub fn x25519_private_bytes(&self) -> &[u8; X25519_PRIVATE_LEN] {
        &self.x25519_private
    }

    /// Access the Ed25519 seed for signing operations.
    #[allow(dead_code)]
    pub fn ed25519_seed(&self) -> &[u8; ED25519_PRIVATE_LEN] {
        &self.ed25519_private_seed
    }
}
