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
//! [`create_vault_key`] (`createVaultKey` in JS) for a new vault, or
//! [`unwrap_vault_key`] (`unwrapVaultKey`) with the master key. Never from
//! caller-supplied bytes.

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
pub fn derive_master_key(
    password: &str,
    argon2_salt_b64: &str,
) -> Result<MasterKeyHandle, JsError> {
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

/// The `blob_hash` a push must declare: BLAKE3 of the **ciphertext**, hex.
///
/// The server recomputes this and refuses a push that disagrees, so the browser
/// cannot skip it. Pass the ciphertext alone — `encryptVault` returns
/// `nonce || ciphertext`, so slice off the first 12 bytes first.
///
/// This is transport integrity, not authenticity: GCM's tag already covers that,
/// keyed. See [`crate::vault::blob_hash`].
#[wasm_bindgen(js_name = blobHash)]
pub fn blob_hash(ciphertext: &[u8]) -> String {
    vault::blob_hash(ciphertext)
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

// ─── Registration and login ──────────────────────────────────────────────────
//
// Added in 0.1.1 for the browser dashboard. Everything below mirrors the wire
// format the CLI already uses, because both clients talk to the same server and
// a mismatch would only surface as an unexplained authentication failure:
//
//   srp_verifier          hex          client_public (A)   hex
//   srp_salt              base64       client_proof (M1)   hex
//   ed25519_public_key    base64       server_proof (M2)   hex
//   x25519_public_key     base64
//   encrypted_private_key base64
//
// SRP state and keypairs stay in wasm memory as handles for the same reason vault
// keys do: `SrpClientEphemeral`, `SrpClientProof` and `UserKeypair` all hold
// private material under `ZeroizeOnDrop`, and handing any of it to JavaScript
// would put it somewhere that cannot be reliably erased.

use crate::keypair::{self, EncryptedPrivateKey, UserKeypair};
use crate::srp::{self, SrpClientEphemeral, SrpClientProof};

/// A user's Ed25519 + X25519 keypair. Private halves never leave wasm.
#[wasm_bindgen]
pub struct KeypairHandle {
    inner: UserKeypair,
}

#[wasm_bindgen]
impl KeypairHandle {
    /// Base64 Ed25519 public key, for `ed25519_public_key` at registration.
    #[wasm_bindgen(js_name = ed25519PublicKey)]
    pub fn ed25519_public_key(&self) -> String {
        self.inner.ed25519_public_base64()
    }

    /// Base64 X25519 public key, for `x25519_public_key` at registration.
    #[wasm_bindgen(js_name = x25519PublicKey)]
    pub fn x25519_public_key(&self) -> String {
        self.inner.x25519_public_base64()
    }

    /// Drop the private halves now rather than waiting for JS to release this.
    pub fn destroy(self) {}
}

/// One login's SRP ephemeral. Single-use: a second login needs a fresh one.
#[wasm_bindgen]
pub struct SrpEphemeralHandle {
    inner: SrpClientEphemeral,
}

#[wasm_bindgen]
impl SrpEphemeralHandle {
    /// Hex public `A`, sent as `client_public` to `/auth/srp/init`.
    #[wasm_bindgen(js_name = publicA)]
    pub fn public_a(&self) -> String {
        hex::encode(&self.inner.public_a)
    }

    /// Drop this now rather than waiting for JS to release the handle.
    pub fn destroy(self) {}
}

/// The client's SRP proof, and the verifier state needed to check the server's.
///
/// Keep this alive between `/auth/srp/verify` and checking `server_proof` —
/// dropping it early makes the server's proof uncheckable, which would silently
/// give up the guarantee that the server holds your verifier.
#[wasm_bindgen]
pub struct SrpProofHandle {
    inner: SrpClientProof,
}

#[wasm_bindgen]
impl SrpProofHandle {
    /// Hex `M1`, sent as `client_proof`.
    #[wasm_bindgen(js_name = clientProof)]
    pub fn client_proof(&self) -> String {
        hex::encode(&self.inner.client_proof)
    }

    /// Drop this now rather than waiting for JS to release the handle.
    pub fn destroy(self) {}
}

/// What registration sends for the SRP half.
#[wasm_bindgen]
pub struct VerifierBundle {
    verifier_hex: String,
    srp_salt_b64: String,
}

#[wasm_bindgen]
impl VerifierBundle {
    /// Hex verifier, for `srp_verifier`.
    #[wasm_bindgen(getter, js_name = verifier)]
    pub fn verifier(&self) -> String {
        self.verifier_hex.clone()
    }

    /// Base64 salt, for `srp_salt`.
    #[wasm_bindgen(getter, js_name = srpSalt)]
    pub fn srp_salt(&self) -> String {
        self.srp_salt_b64.clone()
    }
}

/// Compute the SRP verifier for registration.
///
/// **The email is the SRP identity**, mixed into the verifier — so it must be
/// normalised identically here and at login. The server lowercases it, so send a
/// lowercased, trimmed address or the verifier will not match at login and the
/// failure will look like a wrong password.
#[wasm_bindgen(js_name = computeVerifier)]
pub fn compute_verifier(
    email: &str,
    srp_password_b64: &str,
    srp_salt_b64: &str,
) -> Result<VerifierBundle, JsError> {
    let pw = crate::encoding::b64_decode(srp_password_b64, "srp_password").map_err(js)?;
    let salt = salt_from_b64(srp_salt_b64)?;
    let v = srp::compute_verifier(email, zeroize::Zeroizing::new(pw), salt).map_err(js)?;
    Ok(VerifierBundle {
        verifier_hex: v.verifier_hex(),
        srp_salt_b64: v.srp_salt_base64(),
    })
}

/// Generate a fresh SRP ephemeral for one login attempt.
#[wasm_bindgen(js_name = generateClientEphemeral)]
pub fn generate_client_ephemeral() -> Result<SrpEphemeralHandle, JsError> {
    Ok(SrpEphemeralHandle {
        inner: srp::generate_client_ephemeral().map_err(js)?,
    })
}

/// Compute `M1` from the server's `B`.
///
/// Rejects `B = 0` outright — a server sending it is either broken or trying to
/// force a predictable session key.
#[wasm_bindgen(js_name = computeClientProof)]
pub fn compute_client_proof(
    email: &str,
    srp_password_b64: &str,
    srp_salt_b64: &str,
    server_public_b_hex: &str,
    ephemeral: &SrpEphemeralHandle,
) -> Result<SrpProofHandle, JsError> {
    let pw = crate::encoding::b64_decode(srp_password_b64, "srp_password").map_err(js)?;
    let salt = salt_from_b64(srp_salt_b64)?;
    let b = hex::decode(server_public_b_hex)
        .map_err(|_| JsError::new("server_public_b is not valid hex"))?;
    Ok(SrpProofHandle {
        inner: srp::compute_client_proof(
            email,
            zeroize::Zeroizing::new(pw),
            &salt,
            &b,
            &ephemeral.inner,
        )
        .map_err(js)?,
    })
}

/// Verify the server's `M2`.
///
/// **Do not skip this.** It is the half of SRP that proves the *server* holds
/// your verifier. Without it a replaced server, or a proxy in front of one, gets
/// a session out of you and you never learn.
#[wasm_bindgen(js_name = verifyServerProof)]
pub fn verify_server_proof(server_proof_hex: &str, proof: &SrpProofHandle) -> Result<(), JsError> {
    let m2 =
        hex::decode(server_proof_hex).map_err(|_| JsError::new("server_proof is not valid hex"))?;
    srp::verify_server_proof(&m2, &proof.inner).map_err(js)
}

// ─── Keypairs ────────────────────────────────────────────────────────────────

/// Generate the user's Ed25519 + X25519 keypair at registration.
#[wasm_bindgen(js_name = generateKeypair)]
pub fn generate_keypair() -> KeypairHandle {
    KeypairHandle {
        inner: keypair::generate_keypair(),
    }
}

/// Seal the private key under the master key, base64, for `encrypted_private_key`.
#[wasm_bindgen(js_name = encryptPrivateKey)]
pub fn encrypt_private_key(kp: &KeypairHandle, mk: &MasterKeyHandle) -> Result<String, JsError> {
    Ok(keypair::encrypt_private_key(&kp.inner, &mk.inner)
        .map_err(js)?
        .to_base64())
}

/// Recover the keypair at login from `GET /auth/me`'s `encrypted_private_key`.
///
/// Failure here means the master key is wrong — in practice, the wrong password.
#[wasm_bindgen(js_name = decryptPrivateKey)]
pub fn decrypt_private_key(
    encrypted_b64: &str,
    mk: &MasterKeyHandle,
) -> Result<KeypairHandle, JsError> {
    let enc = EncryptedPrivateKey::from_base64(encrypted_b64).map_err(js)?;
    Ok(KeypairHandle {
        inner: keypair::decrypt_private_key(&enc, &mk.inner).map_err(js)?,
    })
}
