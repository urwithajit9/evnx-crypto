//! Vault encryption and key wrapping.
//!
//! A [`VaultKey`] encrypts one vault's `.env` contents with AES-256-GCM, bound to
//! the vault's identity through associated data. The key itself travels only
//! wrapped — under the owner's master key here, or under an ECDH shared secret in
//! [`crate::keypair`].

use crate::errors::CryptoError;
use crate::kdf::MasterKey;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, Key, KeyInit, Nonce,
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::ZeroizeOnDrop;

/// Length of a [`VaultKey`], in bytes.
pub const VAULT_KEY_LEN: usize = 32;
/// AES-GCM nonce length: 96 bits, the size NIST specifies for GCM.
pub const NONCE_LEN: usize = 12;
/// XChaCha20 nonce length: 192 bits, large enough that random nonces never
/// collide in practice.
pub const XCHACHA_NONCE_LEN: usize = 24;

/// HKDF domain tag for wrapping a vault key under the owner's master key.
///
/// The master key is never used directly as a cipher key: it also protects the
/// user's private key, and two purposes sharing one live key invites
/// cross-protocol confusion. Each purpose gets its own derived subkey.
const HKDF_INFO_VAULT_KEY_WRAP_MK: &[u8] = b"evnx-vault-key-wrap-mk-v1";

/// A 256-bit symmetric key that encrypts one vault's contents.
///
/// Generated client-side, never transmitted in the clear: it travels only wrapped,
/// either under the owner's [`MasterKey`] or under an ECDH secret shared with a
/// recipient. The inner bytes are private and readable only via
/// [`VaultKey::expose`].
///
/// Zeroized on drop, and deliberately neither `Clone` nor `Copy`.
#[derive(ZeroizeOnDrop)]
pub struct VaultKey([u8; VAULT_KEY_LEN]);

impl VaultKey {
    /// Generate a fresh vault key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut key = [0u8; VAULT_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut key);
        VaultKey(key)
    }

    /// Borrow the raw key bytes. Named `expose` so call sites read as a
    /// deliberate act; never log, serialize, or transmit the result.
    pub fn expose(&self) -> &[u8; VAULT_KEY_LEN] {
        &self.0
    }

    /// Build a key from raw bytes recovered by unwrapping.
    ///
    /// Crate-internal on purpose: outside this crate a `VaultKey` can only come
    /// from [`VaultKey::generate`] or an authenticated unwrap, so it can never be
    /// conjured from attacker-supplied bytes.
    pub(crate) fn from_bytes(bytes: [u8; VAULT_KEY_LEN]) -> Self {
        VaultKey(bytes)
    }
}

#[cfg(feature = "test-utils")]
impl VaultKey {
    /// Construct a key from raw bytes. **Test support only** — see
    /// [`crate::kdf::MasterKey::from_bytes_for_test`].
    pub fn from_bytes_for_test(bytes: [u8; VAULT_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

/// The encrypted form of a .env file.
/// Nonce is stored alongside ciphertext for decryption.
/// AES-256-GCM embeds a 128-bit auth tag in the ciphertext —
/// do NOT add a separate integrity hash here (redundant + confusing).
pub struct EncryptedBlob {
    /// Random 96-bit nonce, fresh for every encryption.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the 128-bit GCM tag appended.
    pub ciphertext: Vec<u8>,
}

/// The transport hash a push declares for its ciphertext: BLAKE3, lowercase hex.
///
/// # Why this lives here rather than in each caller
///
/// It was written out three times — in the CLI's push, in the server's push
/// validation, and again in the server's download check — and the three agreed
/// only by everyone independently choosing "BLAKE3 of the ciphertext, hex". The
/// server **rejects** a push whose declared hash does not match what it computes,
/// so any divergence is not a subtle bug but a hard failure at the worst moment.
/// One definition, in the crate both ends already depend on, removes that.
///
/// # What it is and is not for
///
/// Transport integrity and storage-corruption detection. It is **not** the
/// authenticity check: AES-256-GCM's tag already authenticates the ciphertext and
/// its associated data under the vault key, which is strictly stronger because it
/// is keyed — anyone can recompute a BLAKE3 hash over bytes they have modified.
///
/// So this exists to tell "the bytes changed in flight or at rest" apart from
/// "the key or the version is wrong", and to give the server something to verify
/// without ever holding a key. Do not add it to [`EncryptedBlob`]: the note there
/// about not embedding an integrity hash still stands.
///
/// Hash the **ciphertext alone** — not the `nonce || ciphertext` blob as stored.
pub fn blob_hash(ciphertext: &[u8]) -> String {
    blake3::hash(ciphertext).to_hex().to_string()
}

/// Build the canonical associated data binding a blob to its identity.
///
/// Pass the result to [`encrypt_vault`] and [`decrypt_vault`]. The encoding is
/// unambiguous — a length-prefixed vault id followed by the version — so no pair
/// of distinct inputs can produce the same bytes.
///
/// Changing this format invalidates every stored blob, because decryption of an
/// existing version would no longer see the associated data it was sealed with.
pub fn vault_aad(vault_id: &str, version: u32) -> Vec<u8> {
    let id = vault_id.as_bytes();
    let mut aad = Vec::with_capacity(4 + 2 + id.len() + 4);
    aad.extend_from_slice(b"evnx");
    aad.extend_from_slice(&(id.len() as u16).to_be_bytes());
    aad.extend_from_slice(id);
    aad.extend_from_slice(&version.to_be_bytes());
    aad
}

/// Encrypt a `.env` plaintext with a `VaultKey` using AES-256-GCM.
///
/// A fresh random nonce is generated for every call, and the GCM tag authenticates
/// both the ciphertext and `aad` — tampering with either yields
/// [`CryptoError::Decryption`].
///
/// # The `aad` argument is a security control, not a formality
///
/// AES-GCM proves a ciphertext was produced by someone holding the key. It does
/// **not** say *which* blob it is. Without associated data, a malicious server can
/// serve an old version's ciphertext as the current one: the client's key is
/// correct, decryption succeeds, and the user silently receives stale secrets —
/// a revoked credential returns to service.
///
/// Pass [`vault_aad`]`(vault_id, version)` so a blob sealed as one (vault, version)
/// cannot be opened as another. `&[]` disables the binding and reopens that hole;
/// only use it for data with no identity to bind to.
///
/// # Nonce budget
///
/// Nonces are 96 bits and random, so distinct messages under one key collide with
/// probability ~2⁻³² after 2³² encryptions (NIST SP 800-38D). One encryption is one
/// `evnx cloud push`, so the bound is unreachable in practice — but rotate the vault
/// key rather than approaching it.
pub fn encrypt_vault(
    plaintext: &[u8],
    vault_key: &VaultKey,
    aad: &[u8],
) -> Result<EncryptedBlob, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(vault_key.expose());
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;
    Ok(EncryptedBlob {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt an [`EncryptedBlob`].
///
/// `aad` must be byte-identical to the value passed to [`encrypt_vault`], so a
/// caller that sealed with [`vault_aad`] must reopen with the same vault id and
/// version. A mismatch is indistinguishable from tampering, by design.
///
/// Returns [`CryptoError::Decryption`] if the key is wrong, the ciphertext or
/// nonce was modified, or the associated data does not match. Never panics, and
/// the error deliberately does not say which of those it was.
pub fn decrypt_vault(
    blob: &EncryptedBlob,
    vault_key: &VaultKey,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = Key::<Aes256Gcm>::from_slice(vault_key.expose());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&blob.nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: blob.ciphertext.as_ref(),
                aad,
            },
        )
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
    let subkey = crate::kdf::hkdf_subkey(master_key.expose(), HKDF_INFO_VAULT_KEY_WRAP_MK)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(subkey.expose()).map_err(|_| CryptoError::KeyWrap)?;
    let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let mut ciphertext = cipher
        .encrypt(nonce, vault_key.expose().as_ref())
        .map_err(|_| CryptoError::KeyWrap)?;
    let mut wrapped = nonce_bytes.to_vec();
    wrapped.append(&mut ciphertext);
    Ok(wrapped)
}

/// Recover a [`VaultKey`] wrapped by [`wrap_vault_key_with_master_key`].
///
/// # Errors
/// [`CryptoError::KeyUnwrap`] if the master key is wrong or the wrapped blob was
/// modified; [`CryptoError::InvalidInput`] if it is too short to be well-formed.
pub fn unwrap_vault_key_with_master_key(
    wrapped: &[u8],
    master_key: &MasterKey,
) -> Result<VaultKey, CryptoError> {
    if wrapped.len() < XCHACHA_NONCE_LEN + VAULT_KEY_LEN {
        return Err(CryptoError::InvalidInput("wrapped key too short".into()));
    }
    let subkey = crate::kdf::hkdf_subkey(master_key.expose(), HKDF_INFO_VAULT_KEY_WRAP_MK)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(subkey.expose()).map_err(|_| CryptoError::KeyUnwrap)?;
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
    Ok(VaultKey::from_bytes(key))
}
