//! Password-based key derivation.
//!
//! Argon2id turns the user's password into two independent secrets: the
//! [`MasterKey`], which never leaves the device, and the SRP password input,
//! which proves identity to the server without revealing anything it could use.
//! The two are domain-separated so that reusing a salt cannot make them equal.

use crate::errors::CryptoError;
use crate::zeroize::SecretArray;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroizing;

/// Length of a [`MasterKey`], in bytes.
pub const MASTER_KEY_LEN: usize = 32;
/// Length of an Argon2 or SRP salt, in bytes.
pub const SALT_LEN: usize = 32;

/// Length of the SRP password input, in bytes.
pub const SRP_PASSWORD_LEN: usize = 32;

/// Argon2id parameters — OWASP 2024 minimums.
/// These should be benchmarked on target hardware.
/// Target: 300–500 ms derivation time. Raise `m_cost` first if there is headroom.
const ARGON2_M_COST: u32 = 65536; // 64 MB memory
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 parallel lanes

/// Domain-separation tags, passed as Argon2's optional secret (the `K` parameter).
///
/// These are **not** secret. They exist so the two derivations below produce
/// different output even when handed the same password and the same salt. Without
/// them, identical Argon2 parameters mean `derive_master_key(pw, s)` and
/// `derive_srp_password(pw, s)` return identical bytes — so a caller who reused one
/// salt would make the SRP password input equal to the master key, and any leak of
/// the former would expose the latter. Separate salts are still required; this
/// makes a slip non-catastrophic instead of merely discouraged.
///
/// Changing either tag invalidates every existing account, because the verifier
/// stored on the server and the key that decrypts the private key both change.
const KDF_DOMAIN_MASTER_KEY: &[u8] = b"evnx-master-key-v1";
const KDF_DOMAIN_SRP_PASSWORD: &[u8] = b"evnx-srp-password-v1";

/// A 256-bit key derived from the user's password. **Never leaves the device.**
///
/// The inner bytes are private: a `MasterKey` can only come from
/// [`derive_master_key`], so it cannot be forged from arbitrary input, and reading
/// the bytes requires the deliberately-named [`MasterKey::expose`].
///
/// Zeroized on drop. Deliberately not `Clone` or `Copy` — every copy is another
/// place the key can leak from, and another that must be zeroized.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct MasterKey([u8; MASTER_KEY_LEN]);

#[cfg(feature = "test-utils")]
impl MasterKey {
    /// Construct a key from raw bytes, bypassing the KDF.
    ///
    /// **Test support only.** Gated behind the `test-utils` feature so it cannot
    /// appear in a dependent's build by accident: outside tests a `MasterKey` must
    /// come from [`derive_master_key`], or the Argon2id work factor protecting the
    /// user's password can be sidestepped.
    pub fn from_bytes_for_test(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl MasterKey {
    /// Borrow the raw key bytes.
    ///
    /// Named `expose` so that every call site reads as a deliberate act. Never
    /// log, serialize, or transmit the result.
    pub fn expose(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }
}

/// No `Debug` is derived anywhere a key lives, so a key cannot reach a log through
/// a `{:?}` on some enclosing struct. This impl makes that explicit rather than
/// accidental, and keeps `MasterKey` usable inside types that do derive `Debug`.
impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// Generate a cryptographically random 32-byte salt.
/// Call separately for argon2_salt and srp_salt — never reuse.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive the master key from a password and Argon2id salt.
/// Used CLIENT-SIDE ONLY to:
///   1. Encrypt the Ed25519 private key at registration
///   2. Decrypt the Ed25519 private key at login
///
/// NEVER send master_key or password to the server.
///
/// # Arguments
/// * `password` — raw password bytes (UTF-8 encoded)
/// * `salt`     — argon2_salt (stored on server, fetched at login)
pub fn derive_master_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<MasterKey, CryptoError> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(MASTER_KEY_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new_with_secret(
        KDF_DOMAIN_MASTER_KEY,
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(MasterKey(*key))
}

/// Derive the SRP password input from a password and SRP-specific salt.
/// Used CLIENT-SIDE ONLY to generate the SRP verifier at registration,
/// and to compute the SRP proof at login.
///
/// CRITICAL: srp_salt MUST be different from argon2_salt.
/// Using separate salts ensures compromise of the SRP verifier
/// does NOT allow derivation of the master key.
pub fn derive_srp_password(
    password: &[u8],
    srp_salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let params = Params::new(
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(SRP_PASSWORD_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let argon2 = Argon2::new_with_secret(
        KDF_DOMAIN_SRP_PASSWORD,
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let mut output = Zeroizing::new(vec![0u8; SRP_PASSWORD_LEN]);
    argon2
        .hash_password_into(password, srp_salt, output.as_mut())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(output)
}

// ─── Wire Encoding ─────────────────────────────────────────────────────────────

/// Encode a raw 32-byte salt as base64 for transmission to the server.
///
/// Produces exactly 44 characters — the length the server validates.
pub fn salt_to_base64(salt: &[u8; SALT_LEN]) -> String {
    crate::encoding::b64_encode(salt)
}

/// Decode a base64 salt received from the server.
///
/// # Errors
/// [`CryptoError::InvalidInput`] if the string is not valid base64 or does not
/// decode to exactly [`SALT_LEN`] bytes.
pub fn salt_from_base64(s: &str) -> Result<[u8; SALT_LEN], CryptoError> {
    crate::encoding::b64_decode_array::<SALT_LEN>(s, "salt")
}

// ─── Internal: subkey derivation ───────────────────────────────────────────────

/// Derive a 256-bit subkey from existing key material via HKDF-SHA256.
///
/// Every symmetric key in this crate is derived through here rather than used
/// raw, so each purpose gets an independent key and the same input can never be
/// the live cipher key in two different contexts. `info` is the domain tag and
/// must be unique per purpose.
pub(crate) fn hkdf_subkey(ikm: &[u8], info: &[u8]) -> Result<SecretArray<32>, CryptoError> {
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, ikm);
    let mut key = SecretArray::<32>::zeroed();
    hkdf.expand(info, key.expose_mut())
        .map_err(|_| CryptoError::Kdf("HKDF expand failed".into()))?;
    Ok(key)
}
