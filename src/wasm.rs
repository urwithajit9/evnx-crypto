//! WebAssembly bindings for the browser dashboard (`app.evnx.dev`).
//!
//! Gated behind the `wasm` feature, so the CLI and the server compile exactly as
//! before and never pull in `wasm-bindgen`.
//!
//! # Why every key is a handle, never a byte array
//!
//! No function here returns key material to JavaScript. Keys live in this
//! module's linear memory and JS holds only an opaque handle.
//!
//! Once key bytes cross into JS they sit in a garbage-collected heap that cannot
//! be deterministically overwritten: there is no `ZeroizeOnDrop` equivalent, the
//! engine may copy the buffer while compacting, and nothing says when the
//! original is released. Handles keep the guarantee the CLI already makes — and
//! make "keys in memory only" *checkable* rather than aspirational, because there
//! is no API that yields raw key bytes for front-end code to mislay in
//! `localStorage`.
//!
//! A `VaultKey` is obtainable only two ways, exactly as in the crate proper:
//! [`createVaultKey`] for a new vault, or [`unwrapVaultKey`] with the master key.
//! Never from caller-supplied bytes.

use wasm_bindgen::prelude::*;

use crate::kdf::{self, MasterKey, SALT_LEN};
use crate::vault::{self, EncryptedBlob, VaultKey};

fn js<E: core::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

fn salt_from_b64(s: &str) -> Result<[u8; SALT_LEN], JsError> {
    kdf::salt_from_base64(s).map_err(js)
}

/// An Argon2id-derived master key. Bytes never leave wasm memory.
#[wasm_bindgen]
pub struct MasterKeyHandle {
    inner: MasterKey,
}

/// A vault key, either freshly generated or recovered by an authenticated unwrap.
#[wasm_bindgen]
pub struct VaultKeyHandle {
    inner: VaultKey,
}

#[wasm_bindgen]
impl MasterKeyHandle {
    /// Drop the key now rather than waiting for JS to release the handle.
    /// `MasterKey` is `ZeroizeOnDrop`, so the bytes are overwritten here.
    pub fn destroy(self) {}
}

#[wasm_bindgen]
impl VaultKeyHandle {
    /// Drop the key now rather than waiting for JS to release the handle.
    pub fn destroy(self) {}
}

// ─── Key derivation ────────────────────────────────────────────────────────────

/// Derive the master key from the password.
///
/// **Call this from a Web Worker.** It is memory-hard by design (64 MiB, t=3) and
/// blocks its thread for hundreds of milliseconds; on the main thread that is a
/// frozen UI.
#[wasm_bindgen(js_name = deriveMasterKey)]
pub fn derive_master_key(password: &str, argon2_salt_b64: &str) -> Result<MasterKeyHandle, JsError> {
    let salt = salt_from_b64(argon2_salt_b64)?;
    Ok(MasterKeyHandle {
        inner: kdf::derive_master_key(password.as_bytes(), &salt).map_err(js)?,
    })
}

/// Derive the SRP password input, base64-encoded.
///
/// This one legitimately crosses into JS — it is an input to the SRP exchange,
/// not a stored key. It is still password-equivalent: use it for the proof and
/// drop the reference immediately.
#[wasm_bindgen(js_name = deriveSrpPassword)]
pub fn derive_srp_password(password: &str, srp_salt_b64: &str) -> Result<String, JsError> {
    let salt = salt_from_b64(srp_salt_b64)?;
    let out = kdf::derive_srp_password(password.as_bytes(), &salt).map_err(js)?;
    Ok(crate::encoding::b64_encode(&out))
}

/// Fresh random Argon2id salt, base64-encoded.
#[wasm_bindgen(js_name = generateSalt)]
pub fn generate_salt() -> String {
    kdf::salt_to_base64(&kdf::generate_salt())
}

// ─── Vault keys ────────────────────────────────────────────────────────────────

/// Generate a vault key for a NEW vault.
#[wasm_bindgen(js_name = createVaultKey)]
pub fn create_vault_key() -> VaultKeyHandle {
    VaultKeyHandle {
        inner: VaultKey::generate(),
    }
}

/// Wrap a vault key under the master key for storage in `vault_members`.
///
/// This is the **creator's own copy** — symmetric XChaCha20 under an HKDF subkey,
/// so it is post-quantum safe and `eph_pub_key` stays NULL. Do not route it
/// through X25519 ECDH; that is only for sharing with another member.
#[wasm_bindgen(js_name = wrapVaultKey)]
pub fn wrap_vault_key(vk: &VaultKeyHandle, mk: &MasterKeyHandle) -> Result<Vec<u8>, JsError> {
    vault::wrap_vault_key_with_master_key(&vk.inner, &mk.inner).map_err(js)
}

/// Recover a vault key from the server's `encrypted_vault_key`.
#[wasm_bindgen(js_name = unwrapVaultKey)]
pub fn unwrap_vault_key(wrapped: &[u8], mk: &MasterKeyHandle) -> Result<VaultKeyHandle, JsError> {
    Ok(VaultKeyHandle {
        inner: vault::unwrap_vault_key_with_master_key(wrapped, &mk.inner).map_err(js)?,
    })
}

// ─── Blob encryption ───────────────────────────────────────────────────────────

/// Encrypt, sealed to `(vault_id, version)`. Returns `nonce || ciphertext`.
///
/// `version` must be the version the server will assign — `base_version + 1` on a
/// push. Getting it wrong produces a blob nothing can open.
#[wasm_bindgen(js_name = encryptVault)]
pub fn encrypt_vault(
    plaintext: &[u8],
    vk: &VaultKeyHandle,
    vault_id: &str,
    version: u32,
) -> Result<Vec<u8>, JsError> {
    let aad = vault::vault_aad(vault_id, version);
    let blob = vault::encrypt_vault(plaintext, &vk.inner, &aad).map_err(js)?;
    let mut out = Vec::with_capacity(blob.nonce.len() + blob.ciphertext.len());
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&blob.ciphertext);
    Ok(out)
}

/// Decrypt a `nonce || ciphertext` blob sealed at `(vault_id, version)`.
///
/// Failure is deliberately indistinguishable between a wrong key, a tampered
/// blob, and a mismatched version.
#[wasm_bindgen(js_name = decryptVault)]
pub fn decrypt_vault(
    blob: &[u8],
    vk: &VaultKeyHandle,
    vault_id: &str,
    version: u32,
) -> Result<Vec<u8>, JsError> {
    if blob.len() < vault::NONCE_LEN {
        return Err(JsError::new("blob shorter than a nonce"));
    }
    let (n, c) = blob.split_at(vault::NONCE_LEN);
    let mut nonce = [0u8; vault::NONCE_LEN];
    nonce.copy_from_slice(n);
    let eb = EncryptedBlob {
        nonce,
        ciphertext: c.to_vec(),
    };
    let aad = vault::vault_aad(vault_id, version);
    vault::decrypt_vault(&eb, &vk.inner, &aad).map_err(js)
}

// ─── Self-test ─────────────────────────────────────────────────────────────────

/// Proves the associated-data contract holds in the browser exactly as in the
/// CLI: a blob sealed at `(vault_id, version)` opens at that pair and **fails**
/// at any other. Returns true only if both halves behave.
///
/// This is the property the Phase 2 spec omitted entirely — a browser client
/// passing empty AAD would silently produce blobs the CLI cannot open.
#[wasm_bindgen(js_name = aadSelfTest)]
pub fn aad_self_test(vault_id: &str, version: u32) -> Result<bool, JsError> {
    let key = VaultKey::generate();
    let plaintext = b"API_KEY=sk-live-example\nDATABASE_URL=postgres://localhost/db\n";

    let aad = vault::vault_aad(vault_id, version);
    let blob = vault::encrypt_vault(plaintext, &key, &aad).map_err(js)?;

    if vault::decrypt_vault(&blob, &key, &aad).map_err(js)? != plaintext {
        return Ok(false);
    }

    // A different version MUST fail, or a malicious server could replay an old
    // version as current.
    let wrong = vault::vault_aad(vault_id, version.wrapping_add(1));
    Ok(vault::decrypt_vault(&blob, &key, &wrong).is_err())
}
