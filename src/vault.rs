use crate::errors::CryptoError;
use crate::kdf::MasterKey;
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
// use chacha20poly1305::{aead::Aead as XAead, KeyInit as XKeyInit, XChaCha20Poly1305, XNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::ZeroizeOnDrop;

pub const VAULT_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12; // 96-bit for AES-GCM
pub const XCHACHA_NONCE_LEN: usize = 24; // 192-bit for XChaCha20

#[derive(ZeroizeOnDrop)]
pub struct VaultKey(pub [u8; VAULT_KEY_LEN]);

impl VaultKey {
    pub fn generate() -> Self {
        let mut key = [0u8; VAULT_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut key);
        VaultKey(key)
    }
}

/// The encrypted form of a .env file.
/// Nonce is stored alongside ciphertext for decryption.
/// AES-256-GCM embeds a 128-bit auth tag in the ciphertext —
/// do NOT add a separate integrity hash here (redundant + confusing).
pub struct EncryptedBlob {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>, // includes GCM auth tag (last 16 bytes)
}

/// Encrypt a .env plaintext with a VaultKey using AES-256-GCM.
/// A fresh random nonce is generated for every call.
/// The GCM auth tag provides authentication — any tampering
/// causes Err(Decryption) on decrypt.
pub fn encrypt_vault(plaintext: &[u8], vault_key: &VaultKey) -> Result<EncryptedBlob, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(&vault_key.0);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Encryption)?;
    Ok(EncryptedBlob {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt an EncryptedBlob. Returns Err(Decryption) if:
/// - vault_key is wrong
/// - ciphertext has been tampered with
/// - nonce is wrong
///
/// Does NOT panic — always returns Result.
pub fn decrypt_vault(blob: &EncryptedBlob, vault_key: &VaultKey) -> Result<Vec<u8>, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(&vault_key.0);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&blob.nonce);
    cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|_| CryptoError::Decryption)
}

/// Wrap VaultKey with the user's MasterKey using XChaCha20-Poly1305.
/// Used for SOLO vaults (owner wraps their own vault key for storage
/// in vault_members row).
///
/// Returns: [24-byte nonce || ciphertext]
pub fn wrap_vault_key_with_master_key(
    vault_key: &VaultKey,
    master_key: &MasterKey,
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(&master_key.0).map_err(|_| CryptoError::KeyWrap)?;
    let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let mut ciphertext = cipher
        .encrypt(nonce, vault_key.0.as_ref())
        .map_err(|_| CryptoError::KeyWrap)?;
    let mut wrapped = nonce_bytes.to_vec();
    wrapped.append(&mut ciphertext);
    Ok(wrapped)
}

pub fn unwrap_vault_key_with_master_key(
    wrapped: &[u8],
    master_key: &MasterKey,
) -> Result<VaultKey, CryptoError> {
    if wrapped.len() < XCHACHA_NONCE_LEN + VAULT_KEY_LEN {
        return Err(CryptoError::InvalidInput("wrapped key too short".into()));
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(&master_key.0).map_err(|_| CryptoError::KeyUnwrap)?;
    let nonce = XNonce::from_slice(&wrapped[..XCHACHA_NONCE_LEN]);
    let plaintext = cipher
        .decrypt(nonce, &wrapped[XCHACHA_NONCE_LEN..])
        .map_err(|_| CryptoError::KeyUnwrap)?;
    if plaintext.len() != VAULT_KEY_LEN {
        return Err(CryptoError::InvalidInput(
            "decrypted key wrong length".into(),
        ));
    }
    let mut key = [0u8; VAULT_KEY_LEN];
    key.copy_from_slice(&plaintext);
    Ok(VaultKey(key))
}
