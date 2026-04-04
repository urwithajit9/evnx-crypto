use crate::errors::CryptoError;
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroizing;

pub const MASTER_KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 32;

/// Argon2id parameters — OWASP 2024 minimums.
/// These should be benchmarked on target server hardware.
/// Target: 300–500ms derivation time.
/// Adjust m_cost up if server hardware allows.
const ARGON2_M_COST: u32 = 65536; // 64 MB memory
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 parallel lanes

/// ZeroizeOnDrop ensures key material is overwritten when dropped.
/// Do NOT derive Copy or Clone — keys must not be duplicated.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct MasterKey(pub [u8; MASTER_KEY_LEN]);

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
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
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
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new(vec![0u8; 32]);
    argon2
        .hash_password_into(password, srp_salt, output.as_mut())
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(output)
}
