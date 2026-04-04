// tests/srp.rs

//! Tests for SRP-6a client: verifier, ephemeral, proof, server verification.
//!
//! These tests simulate a complete SRP exchange by performing
//! both client and server steps locally (using the `srp` crate's
//! server types directly in tests). Production code only uses the
//! client functions — the server runs in evnx-server.

use evnx_crypto::{
    kdf::{generate_salt, derive_srp_password},
    srp::{
        compute_verifier, generate_client_ephemeral,
        compute_client_proof, verify_server_proof,
    },
};
use srp::{
    server::{SrpServer, UserRecord},
    groups::G_2048,
};
use sha2::Sha256;
use zeroize::Zeroizing;
use proptest::prelude::*;

// ─── Test helper: simulate full SRP exchange in one test ──────────────────────

struct SrpTestSession {
    email: String,
    password: Vec<u8>,
    srp_salt: [u8; 32],
    verifier: Vec<u8>,
}

impl SrpTestSession {
    fn new(email: &str, password: &str) -> Self {
        let srp_salt = generate_salt();
        let srp_pw = derive_srp_password(password.as_bytes(), &srp_salt).unwrap();
        let verifier_struct = compute_verifier(srp_pw, srp_salt).unwrap();

        Self {
            email: email.to_string(),
            password: password.as_bytes().to_vec(),
            srp_salt: verifier_struct.srp_salt,
            verifier: verifier_struct.verifier,
        }
    }
}

// ─── Verifier Tests ────────────────────────────────────────────────────────────

#[test]
fn test_compute_verifier_produces_non_empty_output() {
    let srp_salt = generate_salt();
    let srp_pw = derive_srp_password(b"password123", &srp_salt).unwrap();
    let verifier = compute_verifier(srp_pw, srp_salt).unwrap();

    assert!(!verifier.verifier.is_empty(), "Verifier must not be empty");
    assert_eq!(verifier.srp_salt, srp_salt, "Salt must be preserved");
}

#[test]
fn test_same_password_same_salt_produces_same_verifier() {
    let srp_salt = generate_salt();
    let pw = b"same-password";

    let srp_pw1 = derive_srp_password(pw, &srp_salt).unwrap();
    let v1 = compute_verifier(srp_pw1, srp_salt).unwrap();

    let srp_pw2 = derive_srp_password(pw, &srp_salt).unwrap();
    let v2 = compute_verifier(srp_pw2, srp_salt).unwrap();

    assert_eq!(v1.verifier, v2.verifier,
        "Same password + salt must produce same verifier (determinism)");
}

#[test]
fn test_different_passwords_produce_different_verifiers() {
    let srp_salt = generate_salt();

    let srp_pw1 = derive_srp_password(b"password-a", &srp_salt).unwrap();
    let v1 = compute_verifier(srp_pw1, srp_salt).unwrap();

    let srp_pw2 = derive_srp_password(b"password-b", &srp_salt).unwrap();
    let v2 = compute_verifier(srp_pw2, srp_salt).unwrap();

    assert_ne!(v1.verifier, v2.verifier,
        "Different passwords must produce different verifiers");
}

#[test]
fn test_different_salts_produce_different_verifiers() {
    let salt1 = generate_salt();
    let salt2 = generate_salt();
    let pw = b"same-password";

    let srp_pw1 = derive_srp_password(pw, &salt1).unwrap();
    let v1 = compute_verifier(srp_pw1, salt1).unwrap();

    let srp_pw2 = derive_srp_password(pw, &salt2).unwrap();
    let v2 = compute_verifier(srp_pw2, salt2).unwrap();

    assert_ne!(v1.verifier, v2.verifier,
        "Different salts must produce different verifiers");
}

// ─── Ephemeral Generation ──────────────────────────────────────────────────────

#[test]
fn test_client_ephemeral_public_key_is_not_all_zeros() {
    let eph = generate_client_ephemeral().unwrap();
    assert!(!eph.public_a.iter().all(|&b| b == 0),
        "A must not be 0 mod N");
}

#[test]
fn test_client_ephemeral_is_unique_per_call() {
    let eph1 = generate_client_ephemeral().unwrap();
    let eph2 = generate_client_ephemeral().unwrap();

    assert_ne!(eph1.public_a, eph2.public_a,
        "Each ephemeral generation must produce unique A");
}

// ─── Full Protocol Tests ───────────────────────────────────────────────────────

/// Complete SRP-6a exchange simulation.
/// Client-side functions from evnx-crypto; server-side uses srp crate directly.
#[test]
fn test_full_srp_exchange_correct_password() {
    let session = SrpTestSession::new("user@example.com", "correct-password");

    // Step 1: Client generates ephemeral
    let eph = generate_client_ephemeral().unwrap();

    // Step 2: Server processes init (simulated here using srp crate server)
    let server = SrpServer::<Sha256>::new(&G_2048);
    let record = UserRecord {
        username: session.email.as_bytes(),
        salt: &session.srp_salt,
        verifier: &session.verifier,
    };
    let (server_state, server_b) = server.process_registration(record).unwrap();

    // Step 3: Client computes proof
    let srp_pw = derive_srp_password(&session.password, &session.srp_salt).unwrap();
    let proof = compute_client_proof(
        &session.email,
        srp_pw,
        &session.srp_salt,
        &server_b,
        &eph,
    ).unwrap();

    // Step 4: Server verifies client proof, generates M2
    let server_m2 = server_state.verify_client(&proof.client_proof)
        .expect("Server must accept correct M1");

    // Step 5: Client verifies server proof
    verify_server_proof(&server_m2, &proof)
        .expect("Client must accept correct M2");
}

#[test]
fn test_srp_exchange_wrong_password_fails_at_server() {
    let session = SrpTestSession::new("user@example.com", "correct-password");

    let eph = generate_client_ephemeral().unwrap();

    let server = SrpServer::<Sha256>::new(&G_2048);
    let record = UserRecord {
        username: session.email.as_bytes(),
        salt: &session.srp_salt,
        verifier: &session.verifier,
    };
    let (server_state, server_b) = server.process_registration(record).unwrap();

    // Client uses WRONG password
    let wrong_srp_pw = derive_srp_password(b"wrong-password", &session.srp_salt).unwrap();
    let proof = compute_client_proof(
        &session.email,
        wrong_srp_pw,
        &session.srp_salt,
        &server_b,
        &eph,
    ).unwrap();

    // Server must reject M1 from wrong password
    let result = server_state.verify_client(&proof.client_proof);
    assert!(result.is_err(),
        "Server must reject M1 computed with wrong password");
}

#[test]
fn test_verify_server_proof_rejects_tampered_m2() {
    let session = SrpTestSession::new("user@example.com", "password");
    let eph = generate_client_ephemeral().unwrap();

    let server = SrpServer::<Sha256>::new(&G_2048);
    let record = UserRecord {
        username: session.email.as_bytes(),
        salt: &session.srp_salt,
        verifier: &session.verifier,
    };
    let (server_state, server_b) = server.process_registration(record).unwrap();

    let srp_pw = derive_srp_password(&session.password, &session.srp_salt).unwrap();
    let proof = compute_client_proof(
        &session.email,
        srp_pw,
        &session.srp_salt,
        &server_b,
        &eph,
    ).unwrap();

    let mut server_m2 = server_state.verify_client(&proof.client_proof).unwrap();

    // Tamper with M2
    server_m2[0] ^= 0x01;

    let result = verify_server_proof(&server_m2, &proof);
    assert!(result.is_err(), "Tampered M2 must fail server proof verification");
}

// ─── Property-Based Tests ──────────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_verifier_deterministic_for_any_password(
        password in "[a-zA-Z0-9!@#$%]{8,32}"
    ) {
        let salt = generate_salt();
        let pw1 = derive_srp_password(password.as_bytes(), &salt).unwrap();
        let pw2 = derive_srp_password(password.as_bytes(), &salt).unwrap();

        let v1 = compute_verifier(pw1, salt).unwrap();
        let v2 = compute_verifier(pw2, salt).unwrap();

        prop_assert_eq!(v1.verifier, v2.verifier);
    }

    #[test]
    fn prop_different_passwords_always_different_verifiers(
        pw_a in "[a-z]{8,16}",
        pw_b in "[A-Z]{8,16}",  // Different character class ensures pw_a != pw_b
    ) {
        let salt = generate_salt();
        let srp_pw_a = derive_srp_password(pw_a.as_bytes(), &salt).unwrap();
        let srp_pw_b = derive_srp_password(pw_b.as_bytes(), &salt).unwrap();

        let v_a = compute_verifier(srp_pw_a, salt).unwrap();
        let v_b = compute_verifier(srp_pw_b, salt).unwrap();

        prop_assert_ne!(v_a.verifier, v_b.verifier);
    }
}