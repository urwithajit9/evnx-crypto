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
use ml_kem::kem::{Decapsulate as _, KeyExport as _};
use ml_kem::{DecapsulationKey768, EncapsulationKey768, Key, Seed};
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

/// HKDF info string for the hybrid vault key wrap.
///
/// ⚠️ **Bumped v1 → v2 when the wrap became hybrid.** v1 derived the wrap key
/// from the X25519 shared secret alone. Keeping that string would mean a v1 and
/// a v2 wrap could derive the same key from the same ECDH secret, so a
/// downgrade — strip the ML-KEM ciphertext, present it as v1 — would produce a
/// *working* wrap key rather than a failure. The version is what makes the
/// hybrid non-optional.
const HKDF_INFO_VAULT_KEY_WRAP: &[u8] = b"evnx-vault-key-wrap-v2";

/// HKDF info string for private key encryption (different domain from vault wrap).
const HKDF_INFO_PRIVATE_KEY_ENC: &[u8] = b"evnx-private-key-enc-v1";

/// HKDF info string for deriving the ML-KEM-768 seed from the Ed25519 seed.
///
/// ⚠️ **This string can never change.** It is not a label — it is part of the
/// key derivation. Changing it derives a different decapsulation key for every
/// existing user, and every vault key already wrapped to the old public key
/// becomes permanently unopenable. There is no migration that recovers from it,
/// because the server holds only ciphertext.
///
/// A future parameter set gets a new string (`evnx/mlkem1024/v1`) alongside this
/// one, never in place of it.
const HKDF_INFO_MLKEM_DERIVE: &[u8] = b"evnx/mlkem768/v1";

/// ML-KEM-768 seed length.
///
/// FIPS 203 key generation takes `d ‖ z` — 32 bytes of key-generation randomness
/// and 32 bytes of implicit-rejection secret. The `ml-kem` crate takes both as
/// one 64-byte `Seed`.
const MLKEM_SEED_LEN: usize = 64;

/// ML-KEM-768 encapsulation (public) key length, in bytes.
///
/// Measured against the crate rather than taken from the spec, and asserted in
/// the test suite so a parameter-set mix-up cannot pass silently.
pub const MLKEM768_PUBLIC_LEN: usize = 1184;

/// ML-KEM-768 ciphertext length, in bytes.
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

/// ML-KEM shared-secret length, in bytes.
pub const MLKEM_SHARED_SECRET_LEN: usize = 32;

/// Compile-time proof that ml-kem's **non-default** `zeroize` feature is on.
///
/// Without it `DecapsulationKey` has no `Drop` impl, and ~2.4 KB of expanded
/// ML-KEM private key would be left in freed memory — silently, with everything
/// still compiling and every test still passing. A dependency edit that dropped
/// the feature is exactly the change nobody would notice, so it fails the build
/// here instead.
const _: () = {
    const fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<DecapsulationKey768>();
};

/// XChaCha20-Poly1305 key length.
const XCHACHA_KEY_LEN: usize = 32;

/// Poly1305 authentication tag length appended to every XChaCha20-Poly1305 ciphertext.
const POLY1305_TAG_LEN: usize = 16;

// ─── Public Key Types ─────────────────────────────────────────────────────────

/// Ed25519 public key — 32 bytes, safe to share publicly.
/// Registered with the server for vault access verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ed25519PublicKey(pub [u8; 32]);

/// X25519 public key — 32 bytes, safe to share publicly.
/// Used by vault owners to wrap vault keys for this user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct X25519PublicKeyBytes(pub [u8; X25519_PUBLIC_LEN]);

/// ML-KEM-768 encapsulation key — 1184 bytes, safe to share publicly.
///
/// The post-quantum half of the hybrid vault-key wrap. Published alongside the
/// X25519 public key; a sender encapsulates to both and mixes the two shared
/// secrets, so the wrap holds if *either* primitive survives.
///
/// Deliberately **not** `Serialize`/`Deserialize`: serde has no impl for arrays
/// longer than 32, and adding `serde-big-array` to carry a value that only ever
/// crosses the wire as base64 (see the `encoding` module) would be a dependency
/// bought for nothing. Use [`MlKem768PublicKey::as_bytes`] and
/// [`MlKem768PublicKey::from_bytes`].
#[derive(Clone)]
pub struct MlKem768PublicKey(pub [u8; MLKEM768_PUBLIC_LEN]);

impl MlKem768PublicKey {
    /// Borrow the raw encoding — 1184 bytes, safe to publish.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MLKEM768_PUBLIC_LEN] {
        &self.0
    }

    /// Parse a raw encoding received from the server.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if `bytes` is not exactly
    /// [`MLKEM768_PUBLIC_LEN`] long. The bytes are **not** otherwise validated
    /// here; a malformed key is caught at encapsulation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; MLKEM768_PUBLIC_LEN] = bytes.try_into().map_err(|_| {
            CryptoError::InvalidInput(format!(
                "ML-KEM-768 public key must be {} bytes, got {}",
                MLKEM768_PUBLIC_LEN,
                bytes.len()
            ))
        })?;
        Ok(Self(arr))
    }
}

/// Hand-written because `[u8; 1184]` has no `Debug`, and because printing 1184
/// bytes into a log line helps nobody even though the value is public.
impl core::fmt::Debug for MlKem768PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MlKem768PublicKey({} bytes)", MLKEM768_PUBLIC_LEN)
    }
}

impl PartialEq for MlKem768PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for MlKem768PublicKey {}

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

    /// ML-KEM-768 decapsulation key, derived from `ed25519_private_seed`.
    ///
    /// Derived **eagerly**, at the same moment the X25519 key is, so that a
    /// `UserKeypair` is always complete. The alternative — deriving on first
    /// share — would move a ~1 ms key expansion off the unlock path and onto an
    /// interactive one, and would put an `Option` in a struct whose whole
    /// contract is that it holds a usable identity.
    ///
    /// `ZeroizeOnDrop` here comes from ml-kem's non-default `zeroize` feature,
    /// which `Cargo.toml` asks for by name. The expanded form is ~2.4 KB.
    mlkem_decap: DecapsulationKey768,

    /// ML-KEM-768 encapsulation key (1184 bytes). Safe to transmit.
    #[zeroize(skip)]
    pub mlkem_public: MlKem768PublicKey,
}

/// Encrypted form of the Ed25519 private key seed.
/// Stored (server-side) in the `users.encrypted_private_key` column.
///
/// Format: `[24-byte XChaCha20 nonce || ciphertext || 16-byte poly1305 tag]`
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedPrivateKey {
    /// Random 192-bit XChaCha20 nonce, fresh for every encryption.
    pub nonce: [u8; XCHACHA_NONCE_LEN],
    /// Ciphertext with the Poly1305 tag appended.
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

    /// ML-KEM-768 ciphertext — 1088 bytes — encapsulating the post-quantum half
    /// of the wrap key to the recipient's ML-KEM public key.
    ///
    /// Not optional. A `WrappedVaultKey` without one cannot be unwrapped, which
    /// is the point: there is no code path that degrades to X25519 alone.
    pub mlkem_ciphertext: Vec<u8>,

    /// VaultKey encrypted with the HKDF-derived wrap key.
    pub encrypted_vault_key: Vec<u8>,
}

/// Everything a sender needs to wrap a vault key for one recipient.
///
/// Both halves are required. Bundling them is not sugar — it is what stops a
/// caller from supplying a stale ML-KEM key beside a fresh X25519 one, or from
/// silently skipping the post-quantum half because the parameter happened to be
/// an `Option`. One value, fetched together from
/// `GET /api/v1/users/{email}/public-key`, used together.
#[derive(Clone, Debug)]
pub struct UserPublicKeys {
    /// For the classical ECDH half.
    pub x25519: X25519PublicKeyBytes,
    /// For the post-quantum KEM half.
    pub mlkem: MlKem768PublicKey,
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

    // ML-KEM-768: DERIVE from the same Ed25519 seed, for the same reason X25519
    // is derived — one encrypted seed reconstructs the whole identity, so adding
    // a post-quantum key needs no second sealed blob, no schema change, and no
    // re-prompt for the master password of an existing user.
    let (mlkem_decap, mlkem_public) = derive_mlkem_from_ed25519_seed(&ed25519_private_seed)
        .expect("HKDF derivation should never fail with valid inputs");

    UserKeypair {
        ed25519_private_seed,
        ed25519_public,
        x25519_private,
        x25519_public,
        mlkem_decap,
        mlkem_public,
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
        new_xchacha_cipher(master_key.expose(), HKDF_INFO_PRIVATE_KEY_ENC)?;

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
        new_xchacha_cipher_from_nonce(master_key.expose(), &enc.nonce, HKDF_INFO_PRIVATE_KEY_ENC)?;

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

    // Same derivation as `generate_keypair`, which is what makes the ML-KEM key
    // recoverable at all: nothing about it is stored, so unlocking an account on
    // a new machine reproduces it byte for byte or not at all.
    let (mlkem_decap, mlkem_public) = derive_mlkem_from_ed25519_seed(&seed)?;

    Ok(UserKeypair {
        ed25519_private_seed: seed,
        ed25519_public,
        x25519_private: x25519_static.to_bytes(),
        x25519_public,
        mlkem_decap,
        mlkem_public,
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
    hkdf.expand(b"evnx-x25519-from-ed25519-v1", x25519_private.expose_mut())
        .map_err(|_| CryptoError::Kdf("HKDF expand failed for X25519 derivation".into()))?;
    Ok(x25519_private.into_inner())
}

/// Derive the ML-KEM-768 keypair from the Ed25519 seed using HKDF.
///
/// Same construction as [`derive_x25519_from_ed25519_seed`], under a **different
/// info string**, so the two derived keys are independent: learning one tells an
/// attacker nothing about the other, and neither reveals the Ed25519 seed.
///
/// ## Why derive rather than generate
///
/// The alternative is a second random keypair sealed in a second blob. That
/// needs a new column, a migration, and — for every existing user — a moment
/// where they type their master password so the new private key can be sealed
/// under it. Deriving needs none of that: `users.encrypted_private_key` stays a
/// sealed 32-byte Ed25519 seed, exactly as it is today, and the ML-KEM key
/// simply appears the next time that seed is unsealed.
///
/// ## The derivation is load-bearing forever
///
/// It is deterministic by requirement, not by convenience. A vault key wrapped
/// to a user's ML-KEM public key can only be opened by re-deriving the identical
/// decapsulation key from the identical seed. Any change to the info string, the
/// hash, or the seed length is a silent, unrecoverable data loss for every
/// shared vault. The test suite pins the derivation to a known answer for
/// exactly this reason.
fn derive_mlkem_from_ed25519_seed(
    ed25519_seed: &[u8; ED25519_PRIVATE_LEN],
) -> Result<(DecapsulationKey768, MlKem768PublicKey), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, ed25519_seed);
    let mut mlkem_seed = SecretArray::<MLKEM_SEED_LEN>::zeroed();
    hkdf.expand(HKDF_INFO_MLKEM_DERIVE, mlkem_seed.expose_mut())
        .map_err(|_| CryptoError::Kdf("HKDF expand failed for ML-KEM derivation".into()))?;

    // FIPS 203 keygen takes d ‖ z. `ml-kem` wants them as one 64-byte Seed.
    let seed = Seed::from(*mlkem_seed.expose());
    let decap = DecapsulationKey768::from_seed(seed);
    let public = MlKem768PublicKey::from_bytes(decap.encapsulation_key().to_bytes().as_slice())?;

    Ok((decap, public))
}

// ─── ML-KEM Decapsulation ──────────────────────────────────────────────────────

impl UserKeypair {
    /// Recover the shared secret from a ciphertext encapsulated to our ML-KEM key.
    ///
    /// ⚠️ **ML-KEM never reports a wrong key.** FIPS 203 specifies *implicit
    /// rejection*: a ciphertext that does not decapsulate correctly yields a
    /// pseudo-random secret derived from the key's own `z` value, not an error.
    /// That is deliberate — it denies an attacker the decryption oracle a plain
    /// failure would hand them — but it means this function returning `Ok` says
    /// nothing about whether the ciphertext was genuine.
    ///
    /// Authentication comes from the AEAD that consumes the derived wrap key: a
    /// wrong secret produces a wrong key, and the Poly1305 tag fails. Never treat
    /// a successful decapsulation as proof of anything on its own.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if `ciphertext` is not exactly
    /// [`MLKEM768_CIPHERTEXT_LEN`] bytes.
    pub fn mlkem_decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<[u8; MLKEM_SHARED_SECRET_LEN], CryptoError> {
        // `decapsulate` itself is INFALLIBLE — see the implicit-rejection note
        // above — so the only error here is a length mismatch.
        let shared = self
            .mlkem_decap
            .decapsulate_slice(ciphertext)
            .map_err(|_| {
                CryptoError::InvalidInput(format!(
                    "ML-KEM-768 ciphertext must be {} bytes, got {}",
                    MLKEM768_CIPHERTEXT_LEN,
                    ciphertext.len()
                ))
            })?;

        let mut secret = [0u8; MLKEM_SHARED_SECRET_LEN];
        secret.copy_from_slice(shared.as_slice());
        Ok(secret)
    }
}

// ─── ML-KEM Encapsulation ──────────────────────────────────────────────────────

/// Encapsulate a fresh shared secret to a recipient's ML-KEM-768 public key.
///
/// Returns `(ciphertext, shared_secret)`. The sender keeps the shared secret and
/// publishes the ciphertext; the recipient recovers the same secret with
/// [`UserKeypair::mlkem_decapsulate`].
///
/// ⚠️ **Not a vault-key wrap on its own, and must not be used as one.** The
/// point of the hybrid is that neither primitive is trusted alone: ML-KEM is a
/// young lattice scheme with no decades of cryptanalysis behind it, and X25519
/// is broken by a sufficiently large quantum computer. A wrap key must come from
/// an HKDF over *both* shared secrets so it holds if either survives. Using this
/// function's output directly would trade one single point of failure for a
/// different one.
///
/// # Errors
/// [`CryptoError::InvalidPublicKey`] if the recipient's key is not a well-formed
/// ML-KEM-768 encapsulation key.
pub fn mlkem_encapsulate(
    recipient_pub: &MlKem768PublicKey,
) -> Result<(Vec<u8>, [u8; MLKEM_SHARED_SECRET_LEN]), CryptoError> {
    let encoded = Key::<EncapsulationKey768>::try_from(recipient_pub.as_bytes().as_slice())
        .map_err(|_| CryptoError::InvalidPublicKey)?;

    let ek = EncapsulationKey768::new(&encoded).map_err(|_| CryptoError::InvalidPublicKey)?;

    // OsRng from `rand 0.8` — the same source already used for nonces and vault
    // keys. ml-kem's own RNG traits are on the rand_core 0.10 line, which is why
    // this path supplies the randomness itself rather than handing over an Rng.
    let mut m = [0u8; 32];
    OsRng.fill_bytes(&mut m);
    let m = ml_kem::B32::from(m);

    let (ciphertext, shared) = ek.encapsulate_deterministic(&m);

    let mut secret = [0u8; MLKEM_SHARED_SECRET_LEN];
    secret.copy_from_slice(shared.as_slice());
    Ok((ciphertext.as_slice().to_vec(), secret))
}

// ─── ECDH Vault Key Wrapping ───────────────────────────────────────────────────

/// The hybrid combiner: one wrap key from two independent shared secrets.
///
/// ```text
/// ikm       = ss_mlkem ‖ ss_x25519 ‖ mlkem_ct ‖ eph_pub ‖ recipient_x25519_pub
/// wrap_key  = HKDF-SHA256(ikm, "evnx-vault-key-wrap-v2")
/// ```
///
/// ## Why both secrets, and why the transcript too
///
/// **Both secrets** is the entire point of F1: X25519 falls to Shor, and ML-KEM
/// is a young lattice scheme with far less cryptanalysis behind it than the
/// curve. Feeding both into one HKDF means the wrap key holds as long as
/// *either* primitive does. Neither is trusted alone.
///
/// **The transcript** — the ML-KEM ciphertext, the ephemeral public key and the
/// recipient's static public key — is included because a shared secret alone
/// does not bind the message that produced it. X25519 in particular is not
/// ciphertext-collision-resistant: distinct ephemeral keys can yield the same
/// secret against a chosen static key, so without the transcript an attacker who
/// can substitute one half could steer two different wraps onto one key. ML-KEM
/// already binds its own ciphertext and public key through the FO transform, but
/// including them costs nothing and keeps the combiner robust by construction
/// rather than by appeal to one primitive's internals. This is the shape X-Wing
/// and the TLS hybrid drafts settled on, for the same reason.
///
/// Order is fixed: ML-KEM's secret first. Arbitrary, but it has to be *some*
/// fixed order and both sides must agree.
fn hybrid_wrap_key(
    ss_mlkem: &[u8; MLKEM_SHARED_SECRET_LEN],
    ss_x25519: &[u8; 32],
    mlkem_ciphertext: &[u8],
    eph_pub: &[u8; X25519_PUBLIC_LEN],
    recipient_x25519_pub: &[u8; X25519_PUBLIC_LEN],
) -> Result<SecretArray<32>, CryptoError> {
    let mut ikm = Vec::with_capacity(
        MLKEM_SHARED_SECRET_LEN + 32 + mlkem_ciphertext.len() + X25519_PUBLIC_LEN * 2,
    );
    ikm.extend_from_slice(ss_mlkem);
    ikm.extend_from_slice(ss_x25519);
    ikm.extend_from_slice(mlkem_ciphertext);
    ikm.extend_from_slice(eph_pub);
    ikm.extend_from_slice(recipient_x25519_pub);

    let key = crate::kdf::hkdf_subkey(&ikm, HKDF_INFO_VAULT_KEY_WRAP);

    // The concatenation held two shared secrets in plaintext. Nothing else wipes
    // it — `Vec<u8>` has no Drop that does.
    crate::zeroize::zeroize_slice(&mut ikm);
    key
}

/// Wrap a `VaultKey` for a specific recipient — **hybrid X25519 + ML-KEM-768**.
///
/// The sender generates a fresh ephemeral X25519 keypair and a fresh ML-KEM
/// encapsulation for every wrap. Both ephemeral secrets are zeroized after use.
///
/// # Arguments
/// * `vault_key` — the vault encryption key to wrap
/// * `recipient` — both of the recipient's public keys, from
///   `GET /api/v1/users/{email}/public-key`
///
/// # Returns
/// [`WrappedVaultKey`] — `eph_pub_key`, `mlkem_ciphertext` and
/// `encrypted_vault_key`. All three are safe to store on the server, and all
/// three are required to unwrap.
///
/// # Errors
/// [`CryptoError::InvalidPublicKey`] if the recipient's X25519 key is low-order
/// (see below) or their ML-KEM key is malformed.
pub fn wrap_vault_key_for_user(
    vault_key: &VaultKey,
    recipient: &UserPublicKeys,
) -> Result<WrappedVaultKey, CryptoError> {
    // ─── Classical half ──────────────────────────────────────────────────────
    // Generate ephemeral keypair — EphemeralSecret zeroizes on drop
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = X25519PublicKey::from(&eph_secret);

    let recipient_pubkey = X25519PublicKey::from(recipient.x25519.0);
    let shared_secret = eph_secret.diffie_hellman(&recipient_pubkey);

    // Reject low-order recipient keys. Curve25519 has eight points of small order;
    // multiplying any of them by our scalar yields the identity, so the shared
    // secret would be all-zero and independent of both private keys. Wrapping a
    // vault key under such a secret would publish it to anyone who noticed.
    //
    // Still checked even though ML-KEM now also contributes: a wrap that is
    // secretly single-primitive is exactly the silent downgrade F1 exists to
    // prevent, and it must fail loudly rather than lean on the other half.
    if !shared_secret.was_contributory() {
        return Err(CryptoError::InvalidPublicKey);
    }

    // ─── Post-quantum half ───────────────────────────────────────────────────
    let (mlkem_ciphertext, ss_mlkem) = mlkem_encapsulate(&recipient.mlkem)?;

    // ─── Combine ─────────────────────────────────────────────────────────────
    let wrap_key = hybrid_wrap_key(
        &ss_mlkem,
        shared_secret.as_bytes(),
        &mlkem_ciphertext,
        &eph_pub.to_bytes(),
        &recipient.x25519.0,
    )?;

    // Encrypt vault_key with wrap_key
    let (cipher, nonce_bytes, nonce) = new_xchacha_cipher(wrap_key.expose(), &[])?;
    let ciphertext = cipher
        .encrypt(&nonce, vault_key.expose().as_ref())
        .map_err(|_| CryptoError::KeyWrap)?;

    // Prepend nonce to match WrappedVaultKey format spec
    let mut encrypted_vault_key = Vec::with_capacity(XCHACHA_NONCE_LEN + ciphertext.len());
    encrypted_vault_key.extend_from_slice(&nonce_bytes);
    encrypted_vault_key.extend_from_slice(&ciphertext);

    Ok(WrappedVaultKey {
        eph_pub_key: eph_pub.to_bytes(),
        mlkem_ciphertext,
        encrypted_vault_key,
    })
}

/// Unwrap a vault key that was wrapped for us — **hybrid X25519 + ML-KEM-768**.
///
/// Takes the whole [`UserKeypair`] rather than raw private key bytes, because
/// both halves are needed and because handing out private key material to pass
/// it back in was never a shape worth keeping.
///
/// # Errors
/// * [`CryptoError::InvalidPublicKey`] — the ephemeral key is low-order, i.e. a
///   key-substitution attempt by whoever served this blob.
/// * [`CryptoError::InvalidInput`] — malformed lengths.
/// * [`CryptoError::KeyUnwrap`] — the AEAD tag failed. **This is the check that
///   catches a wrong ML-KEM ciphertext**, because ML-KEM's implicit rejection
///   reports nothing itself; see [`UserKeypair::mlkem_decapsulate`].
pub fn unwrap_vault_key(
    wrapped: &WrappedVaultKey,
    keypair: &UserKeypair,
) -> Result<VaultKey, CryptoError> {
    // ─── Classical half ──────────────────────────────────────────────────────
    let my_static = StaticSecret::from(keypair.x25519_private);
    let eph_pub = X25519PublicKey::from(wrapped.eph_pub_key);

    let shared_secret = my_static.diffie_hellman(&eph_pub);

    // The critical check. A malicious server can put a low-order point in
    // `eph_pub_key`, which forces the shared secret to all-zero regardless of our
    // private key. The attacker can then derive the same wrap key and hand us a
    // vault key of their choosing — we would encrypt the user's .env under a key
    // they already know. Refuse before deriving anything.
    if !shared_secret.was_contributory() {
        return Err(CryptoError::InvalidPublicKey);
    }

    // ─── Post-quantum half ───────────────────────────────────────────────────
    // Succeeds even on a forged ciphertext — FIPS 203 implicit rejection returns
    // a pseudo-random secret rather than an error. The AEAD below is what fails.
    let ss_mlkem = keypair.mlkem_decapsulate(&wrapped.mlkem_ciphertext)?;

    // ─── Combine ─────────────────────────────────────────────────────────────
    let wrap_key = hybrid_wrap_key(
        &ss_mlkem,
        shared_secret.as_bytes(),
        &wrapped.mlkem_ciphertext,
        &wrapped.eph_pub_key,
        &keypair.x25519_public.0,
    )?;

    // Decrypt: the nonce is the first 24 bytes of `encrypted_vault_key`.
    if wrapped.encrypted_vault_key.len() < XCHACHA_NONCE_LEN {
        return Err(CryptoError::InvalidInput(
            "wrapped vault key too short".into(),
        ));
    }

    let nonce_bytes: [u8; XCHACHA_NONCE_LEN] = wrapped.encrypted_vault_key[..XCHACHA_NONCE_LEN]
        .try_into()
        .map_err(|_| CryptoError::InvalidInput("nonce extraction failed".into()))?;
    let ciphertext = &wrapped.encrypted_vault_key[XCHACHA_NONCE_LEN..];

    let (cipher, _, nonce) = new_xchacha_cipher_from_nonce(wrap_key.expose(), &nonce_bytes, &[])?;
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
    Ok(VaultKey::from_bytes(key))
}

// ─── Internal Helpers ──────────────────────────────────────────────────────────

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
        hkdf.expand(info, derived.expose_mut())
            .map_err(|_| CryptoError::Kdf("HKDF expand failed".into()))?;
        derived
    };

    let cipher =
        XChaCha20Poly1305::new_from_slice(key_bytes.expose()).map_err(|_| CryptoError::KeyWrap)?;

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
        hkdf.expand(info, derived.expose_mut())
            .map_err(|_| CryptoError::Kdf("HKDF expand failed".into()))?;
        derived
    };

    let cipher = XChaCha20Poly1305::new_from_slice(key_bytes.expose())
        .map_err(|_| CryptoError::KeyUnwrap)?;

    let nonce = *XNonce::from_slice(nonce_bytes);
    Ok((cipher, *nonce_bytes, nonce))
}

// ─── Test support ─────────────────────────────────────────────────────────────

#[cfg(feature = "test-utils")]
impl UserKeypair {
    /// Reconstruct a keypair from a fixed Ed25519 seed, bypassing the CSPRNG.
    ///
    /// **Test support only.** Gated behind `test-utils` so it cannot appear in a
    /// dependent's build by accident: outside tests a keypair must come from
    /// [`generate_keypair`] or [`decrypt_private_key`], or an identity can be
    /// created from a low-entropy seed the caller chose.
    ///
    /// This exists so the ML-KEM derivation can be pinned to a known answer. A
    /// KAT is the only test that catches a *silent* change to the derivation —
    /// round-trip tests all pass happily against a wrong-but-consistent key,
    /// while every already-shared vault becomes unopenable.
    ///
    /// # Panics
    /// If HKDF expansion fails, which cannot happen for these output lengths.
    #[must_use]
    pub fn from_ed25519_seed_for_test(seed: [u8; ED25519_PRIVATE_LEN]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let ed25519_public = Ed25519PublicKey(signing_key.verifying_key().to_bytes());

        let x25519_private =
            derive_x25519_from_ed25519_seed(&seed).expect("HKDF cannot fail on a 32-byte output");
        let x25519_static = StaticSecret::from(x25519_private);
        let x25519_public = X25519PublicKeyBytes(X25519PublicKey::from(&x25519_static).to_bytes());

        let (mlkem_decap, mlkem_public) =
            derive_mlkem_from_ed25519_seed(&seed).expect("HKDF cannot fail on a 64-byte output");

        Self {
            ed25519_private_seed: seed,
            ed25519_public,
            x25519_private: x25519_static.to_bytes(),
            x25519_public,
            mlkem_decap,
            mlkem_public,
        }
    }

    /// The X25519 private key, for asserting that the two derivations are
    /// independent. **Test support only.**
    #[must_use]
    pub fn x25519_private_for_test(&self) -> [u8; X25519_PRIVATE_LEN] {
        self.x25519_private
    }
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

// ─── Wire Encoding ─────────────────────────────────────────────────────────────
//
// Every type below crosses the network as text inside JSON. The server stores
// these values verbatim and never decodes them — it cannot, since it has no key.

impl Ed25519PublicKey {
    /// Encode as base64 for the `ed25519_public_key` registration field.
    /// Produces exactly 44 characters.
    pub fn to_base64(&self) -> String {
        crate::encoding::b64_encode(&self.0)
    }

    /// Decode from the base64 form returned by the server.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if not valid base64 or not 32 bytes.
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        Ok(Self(crate::encoding::b64_decode_array::<32>(
            s,
            "ed25519_public_key",
        )?))
    }
}

impl X25519PublicKeyBytes {
    /// Encode as base64 for the `x25519_public_key` registration field.
    /// Produces exactly 44 characters.
    pub fn to_base64(&self) -> String {
        crate::encoding::b64_encode(&self.0)
    }

    /// Decode a recipient's public key from `GET /api/v1/users/{email}/public-key`.
    ///
    /// This is the entry point for vault sharing: the returned key is passed to
    /// [`wrap_vault_key_for_user`].
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if not valid base64 or not 32 bytes.
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        Ok(Self(
            crate::encoding::b64_decode_array::<X25519_PUBLIC_LEN>(s, "x25519_public_key")?,
        ))
    }
}

impl MlKem768PublicKey {
    /// Encode as base64 for the `mlkem_public_key` registration field.
    /// 1184 bytes in, exactly 1580 characters out.
    pub fn to_base64(&self) -> String {
        crate::encoding::b64_encode(&self.0)
    }

    /// Decode a recipient's ML-KEM key from
    /// `GET /api/v1/users/{email}/public-key`.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if not valid base64 or not 1184 bytes.
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        Ok(Self(crate::encoding::b64_decode_array::<
            MLKEM768_PUBLIC_LEN,
        >(s, "mlkem_public_key")?))
    }
}

impl UserPublicKeys {
    /// Build from the two base64 fields the public-key endpoint returns.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if either field is malformed. **A recipient
    /// with no ML-KEM key on file cannot be shared with** — that is the intended
    /// outcome, not a gap. Callers should present it as "this user must sign in
    /// once with an updated client", never wrap under X25519 alone.
    pub fn from_base64(x25519_b64: &str, mlkem_b64: &str) -> Result<Self, CryptoError> {
        Ok(Self {
            x25519: X25519PublicKeyBytes::from_base64(x25519_b64)?,
            mlkem: MlKem768PublicKey::from_base64(mlkem_b64)?,
        })
    }
}

impl UserKeypair {
    /// Both of our own public keys, as a sender would need them.
    ///
    /// Useful for wrapping to oneself in tests, and for the round-trip check a
    /// client can run after registering.
    pub fn public_keys(&self) -> UserPublicKeys {
        UserPublicKeys {
            x25519: self.x25519_public.clone(),
            mlkem: self.mlkem_public.clone(),
        }
    }

    /// Ed25519 public key as base64 — for the registration payload.
    pub fn ed25519_public_base64(&self) -> String {
        self.ed25519_public.to_base64()
    }

    /// ML-KEM-768 public key as base64 — for the registration payload.
    ///
    /// The server stores this in `users.mlkem_public_key` so other users can
    /// wrap vault keys for this account with the post-quantum half.
    pub fn mlkem_public_base64(&self) -> String {
        self.mlkem_public.to_base64()
    }

    /// X25519 public key as base64 — for the registration payload.
    ///
    /// The server stores this in `users.x25519_public_key` so other users can
    /// wrap vault keys for this account.
    pub fn x25519_public_base64(&self) -> String {
        self.x25519_public.to_base64()
    }
}

impl EncryptedPrivateKey {
    /// Serialize to a single base64 string: `base64(nonce || ciphertext)`.
    ///
    /// This is the exact format stored in `users.encrypted_private_key` and sent
    /// as the `encrypted_private_key` registration field.
    pub fn to_base64(&self) -> String {
        let mut combined = Vec::with_capacity(self.nonce.len() + self.ciphertext.len());
        combined.extend_from_slice(&self.nonce);
        combined.extend_from_slice(&self.ciphertext);
        crate::encoding::b64_encode(&combined)
    }

    /// Reconstruct from the base64 string returned by `GET /api/v1/auth/me`.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if the string is not valid base64, or is too
    /// short to contain a nonce plus a Poly1305 tag.
    pub fn from_base64(s: &str) -> Result<Self, CryptoError> {
        let bytes = crate::encoding::b64_decode(s, "encrypted_private_key")?;

        // Must hold at least the nonce and the 16-byte Poly1305 tag.
        const MIN_LEN: usize = XCHACHA_NONCE_LEN + POLY1305_TAG_LEN;
        if bytes.len() < MIN_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "encrypted_private_key: expected at least {MIN_LEN} bytes, got {}",
                bytes.len()
            )));
        }

        let mut nonce = [0u8; XCHACHA_NONCE_LEN];
        nonce.copy_from_slice(&bytes[..XCHACHA_NONCE_LEN]);

        Ok(Self {
            nonce,
            ciphertext: bytes[XCHACHA_NONCE_LEN..].to_vec(),
        })
    }
}

impl WrappedVaultKey {
    /// The ECDH-wrapped vault key as base64 — the `encrypted_vault_key` API field.
    pub fn encrypted_vault_key_base64(&self) -> String {
        crate::encoding::b64_encode(&self.encrypted_vault_key)
    }

    /// The sender's ephemeral X25519 public key as base64 — the `eph_pub_key` API field.
    pub fn eph_pub_key_base64(&self) -> String {
        crate::encoding::b64_encode(&self.eph_pub_key)
    }

    /// The ML-KEM-768 ciphertext as base64 — the `mlkem_ciphertext` API field.
    /// 1088 bytes in, 1452 characters out.
    pub fn mlkem_ciphertext_base64(&self) -> String {
        crate::encoding::b64_encode(&self.mlkem_ciphertext)
    }

    /// Rebuild from the three base64 fields the server returns
    /// (`GET /api/v1/vaults/{id}/my-key`).
    ///
    /// ⚠️ **Takes three arguments since 0.2.0.** `mlkem_ciphertext_b64` is not
    /// optional: a wrap without it cannot be unwrapped, and accepting `None` here
    /// would only move the failure later while implying a degraded mode exists.
    ///
    /// # Errors
    /// [`CryptoError::InvalidInput`] if any string is not valid base64, if
    /// `eph_pub_key_b64` is not exactly 32 bytes, or if `mlkem_ciphertext_b64`
    /// is not exactly 1088.
    pub fn from_base64(
        encrypted_vault_key_b64: &str,
        eph_pub_key_b64: &str,
        mlkem_ciphertext_b64: &str,
    ) -> Result<Self, CryptoError> {
        let mlkem_ciphertext =
            crate::encoding::b64_decode(mlkem_ciphertext_b64, "mlkem_ciphertext")?;
        if mlkem_ciphertext.len() != MLKEM768_CIPHERTEXT_LEN {
            return Err(CryptoError::InvalidInput(format!(
                "mlkem_ciphertext must be {} bytes, got {}",
                MLKEM768_CIPHERTEXT_LEN,
                mlkem_ciphertext.len()
            )));
        }
        Ok(Self {
            eph_pub_key: crate::encoding::b64_decode_array::<X25519_PUBLIC_LEN>(
                eph_pub_key_b64,
                "eph_pub_key",
            )?,
            mlkem_ciphertext,
            encrypted_vault_key: crate::encoding::b64_decode(
                encrypted_vault_key_b64,
                "encrypted_vault_key",
            )?,
        })
    }
}
