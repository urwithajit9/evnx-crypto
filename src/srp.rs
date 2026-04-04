// src/srp.rs

//! SRP-6a (Secure Remote Password) client implementation.
//!
//! This module wraps the `srp` crate to provide a clean, safe interface
//! for the two client-side operations:
//!
//! 1. **Registration**: `compute_verifier()` — derives the SRP verifier
//!    from the SRP password bytes (NOT the raw password — use `derive_srp_password`
//!    from `kdf.rs` first) and a random SRP salt.
//!
//! 2. **Login**: Three-step protocol —
//!    a. `generate_client_ephemeral()` → `(A, a)` — sent A to server
//!    b. `compute_client_proof()` → `(M1, K)` — send M1 to server
//!    c. `verify_server_proof()` → validates M2 from server
//!
//! ## SRP-6a Protocol Overview
//!
//! ```text
//! Registration:
//!   client: x = H(srp_salt || srp_password_bytes)
//!   client: v = g^x mod N              ← verifier, sent to server
//!   server: stores (email, v, srp_salt)
//!
//! Login:
//!   client → server: A = g^a mod N     ← client ephemeral public
//!   server → client: B, srp_salt       ← server ephemeral public + salt
//!   client:  u = H(A || B)
//!   client:  x = H(srp_salt || srp_password_bytes)
//!   client:  S = (B - k*g^x)^(a+u*x) mod N   ← shared secret
//!   client:  K = H(S)                          ← session key
//!   client:  M1 = H(H(N) XOR H(g), H(email), srp_salt, A, B, K)
//!   client → server: M1
//!   server:  verifies M1; computes M2 = H(A, M1, K)
//!   server → client: M2
//!   client:  verifies M2                        ← mutual auth
//! ```
//!
//! ## Security Notes
//!
//! - SRP group: RFC 5054 2048-bit group (G_2048). Never use smaller groups.
//! - Hash: SHA-256. The `srp` crate supports multiple hash algorithms.
//! - Client MUST validate A != 0 mod N before sending (prevent abort attack).
//! - Server MUST validate B != 0 mod N.
//! - Both proofs use constant-time comparison via the `srp` crate.
//! - SRP alone provides no forward secrecy — combine with TLS for transport.

use rand::rngs::OsRng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use srp::client::{SrpClient, SrpClientVerifier};
use srp::groups::G_2048;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::errors::CryptoError;

// ─── Types ─────────────────────────────────────────────────────────────────────

/// SRP verifier — a large number stored by the server.
/// Generated once at registration from the SRP password bytes.
/// The server uses this to verify login without seeing the password.
#[derive(Clone, Serialize, Deserialize)]
pub struct SrpVerifier {
    /// Verifier bytes (v = g^x mod N).
    pub verifier: Vec<u8>,
    /// The SRP-specific salt used to derive x (NOT the argon2_salt).
    pub srp_salt: [u8; 32],
}

/// Client-side ephemeral state for the SRP login protocol.
/// Holds `a` (private ephemeral scalar) — must be zeroized after use.
#[derive(ZeroizeOnDrop)]
pub struct SrpClientEphemeral {
    /// a: private ephemeral scalar as bytes (large random number)
    private_a: Vec<u8>,
    /// A: g^a mod N — sent to server in SRP init
    pub public_a: Vec<u8>,
}

/// The output of `compute_client_proof()`.
/// `client_proof` (M1) is sent to the server.
/// `session_key` (K) is the shared session key used to verify M2.
#[derive(ZeroizeOnDrop)]
pub struct SrpClientProof {
    /// M1: client proof — send to server
    pub client_proof: Vec<u8>,
    /// Verifier holding session key and proof verification logic.
    #[zeroize(skip)]
    verifier: SrpClientVerifier<Sha256>,
}

// Manual Debug implementation that skips the opaque verifier field
impl std::fmt::Debug for SrpClientProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrpClientProof")
            .field(
                "client_proof",
                &format!("<{} bytes>", self.client_proof.len()),
            )
            .field(
                "session_key",
                &format!("<{} bytes>", self.verifier.key().len()),
            )
            .finish()
    }
}

impl SrpClientProof {
    /// Returns the derived session key K for encrypting subsequent traffic.
    pub fn session_key(&self) -> &[u8] {
        self.verifier.key()
    }
}

// ─── Registration ──────────────────────────────────────────────────────────────

/// Compute the SRP verifier from the SRP password bytes and a random salt.
///
/// **Call `derive_srp_password()` from `kdf.rs` BEFORE this function.**
/// Do not pass the raw user password here.
///
/// # Arguments
/// * `email`              — User's email address (identity for SRP)
/// * `srp_password_bytes` — Output of `derive_srp_password(password, srp_salt)`.
///   This is a 32-byte Argon2id-derived value, NOT the password itself.
/// * `srp_salt`           — A fresh 32-byte random salt (from `generate_salt()`).
///   Must be the SAME salt used in `derive_srp_password()`.
///
/// # Returns
/// `SrpVerifier { verifier, srp_salt }` — both fields are sent to the server at registration.
///
/// # Security
/// - `srp_password_bytes` is consumed and zeroized after use.
/// - The raw password is never an argument to this function.
pub fn compute_verifier(
    email: &str,
    srp_password_bytes: Zeroizing<Vec<u8>>,
    srp_salt: [u8; 32],
) -> Result<SrpVerifier, CryptoError> {
    let client = SrpClient::<Sha256>::new(&G_2048);

    // SRP: compute x = H(salt || password_bytes), then v = g^x mod N
    // API: compute_verifier(username, password, salt)
    let verifier = client.compute_verifier(
        email.as_bytes(),    // username/identity
        &srp_password_bytes, // derived password bytes
        &srp_salt,           // salt
    );

    // Explicitly drop to trigger zeroize on sensitive data
    drop(srp_password_bytes);

    Ok(SrpVerifier { verifier, srp_salt })
}

// ─── Login: Step 1 ─────────────────────────────────────────────────────────────

/// Generate client ephemeral values for SRP login Step 1.
///
/// Returns `(A, a)` where:
/// - `A` = g^a mod N — the client public ephemeral (send to server)
/// - `a` = private ephemeral scalar (keep locally, zeroize after Step 3)
///
/// # Critical Validation
/// The generated `A` value MUST NOT be 0 mod N.
/// This is an SRP-6a requirement. We validate explicitly as a defense-in-depth measure.
pub fn generate_client_ephemeral() -> Result<SrpClientEphemeral, CryptoError> {
    let client = SrpClient::<Sha256>::new(&G_2048);

    // Generate private ephemeral 'a' as random bytes
    // 64 bytes = 512 bits, sufficient for 2048-bit SRP group
    let mut private_a = vec![0u8; 64];
    OsRng.fill_bytes(&mut private_a);

    // Compute public ephemeral A = g^a mod N
    // compute_public_ephemeral returns Vec<u8> directly
    let public_a = client.compute_public_ephemeral(&private_a);

    // Validate A != 0 mod N (SRP-6a protocol requirement)
    if public_a.iter().all(|&b| b == 0) {
        return Err(CryptoError::Srp(
            "Generated A = 0 mod N — this should be computationally impossible.".into(),
        ));
    }

    Ok(SrpClientEphemeral {
        private_a,
        public_a,
    })
}

// ─── Login: Step 2 ─────────────────────────────────────────────────────────────

/// Compute the client proof (M1) and session key (K) for SRP login Step 2.
///
/// Call this after receiving `{ srp_salt, server_public (B) }` from the server.
///
/// # Arguments
/// * `email`              — User's email address (identity, not hashed before passing here)
/// * `srp_password_bytes` — Output of `derive_srp_password(password, srp_salt)` — NOT raw password
/// * `srp_salt`           — SRP salt received from the server in Step 1 response
/// * `server_public_b`    — B value received from the server in Step 1 response (as bytes)
/// * `ephemeral`          — The `SrpClientEphemeral` from `generate_client_ephemeral()`
///
/// # Returns
/// `SrpClientProof { client_proof (M1), session_key (K) }`.
/// Send `client_proof` to server. Keep `session_key` to verify M2.
pub fn compute_client_proof(
    email: &str,
    srp_password_bytes: Zeroizing<Vec<u8>>,
    srp_salt: &[u8],
    server_public_b: &[u8],
    ephemeral: &SrpClientEphemeral,
) -> Result<SrpClientProof, CryptoError> {
    let client = SrpClient::<Sha256>::new(&G_2048);

    // Validate B != 0 (defend against malicious server sending invalid B)
    if server_public_b.iter().all(|&b| b == 0) {
        return Err(CryptoError::Srp(
            "Server sent B = 0 — possible attack or server bug".into(),
        ));
    }

    // Process server reply to compute shared secret, client proof (M1), and session key (K)
    // API: process_reply(private_a: &[u8], username, password, salt, server_public: &[u8])
    let verifier = client
        .process_reply(
            &ephemeral.private_a, // private ephemeral 'a' as bytes
            email.as_bytes(),     // username/identity
            &srp_password_bytes, // derived password bytes (dereference Zeroizing)
            srp_salt,             // salt
            server_public_b,      // server's public ephemeral B (as bytes)
        )
        .map_err(|e| CryptoError::Srp(format!("SRP process_reply failed: {e:?}")))?;

    Ok(SrpClientProof {
        client_proof: verifier.proof().to_vec(),
        verifier, // Store for M2 verification
    })
}

// ─── Login: Step 3 ─────────────────────────────────────────────────────────────

/// Verify the server's proof (M2) to complete mutual authentication.
///
/// Called after the server responds to M1. This step proves that the
/// server also derived the same session key — i.e., the server also
/// "knows" the password (via the verifier). Without this check,
/// the client cannot distinguish a legitimate server from a man-in-the-middle.
///
/// # Arguments
/// * `server_proof` — M2 received from server
/// * `srp_proof`    — The `SrpClientProof` from `compute_client_proof()`
///
/// # Returns
/// `Ok(())` if M2 is valid. `Err(Srp(...))` if verification fails.
///
/// # Action on failure
/// If this returns `Err`, abort the login and display an error.
/// Do NOT proceed with the session — the server cannot be trusted.
pub fn verify_server_proof(
    server_proof: &[u8],
    srp_proof: &SrpClientProof,
) -> Result<(), CryptoError> {
    // Use the stored verifier to check server's proof M2
    // API: verify_server(server_proof: &[u8]) -> Result<(), SrpError>
    srp_proof.verifier.verify_server(server_proof).map_err(|_| {
        CryptoError::Srp("Server proof verification failed — possible MITM or server error".into())
    })
}
