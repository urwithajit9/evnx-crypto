// tests/srp.rs

//! Tests for SRP-6a client implementation.
//!
//! These tests validate client-side SRP operations only.
//! Full protocol integration tests belong in evnx-server.

use evnx_crypto::{
    kdf::{derive_srp_password, generate_salt},
    srp::{compute_client_proof, compute_verifier, generate_client_ephemeral},
};

// ─── Verifier Tests ────────────────────────────────────────────────────────────

#[test]
fn test_compute_verifier_produces_non_empty_output() {
    let email = "test@example.com";
    let srp_salt = generate_salt();
    let srp_pw = derive_srp_password(b"password123", &srp_salt).unwrap();
    let verifier = compute_verifier(email, srp_pw, srp_salt).unwrap();

    assert!(!verifier.verifier.is_empty(), "Verifier must not be empty");
    assert_eq!(verifier.srp_salt, srp_salt, "Salt must be preserved");
}

#[test]
fn test_same_password_same_salt_produces_same_verifier() {
    let email = "test@example.com";
    let srp_salt = generate_salt();
    let pw = b"same-password";

    let srp_pw1 = derive_srp_password(pw, &srp_salt).unwrap();
    let v1 = compute_verifier(email, srp_pw1, srp_salt).unwrap();

    let srp_pw2 = derive_srp_password(pw, &srp_salt).unwrap();
    let v2 = compute_verifier(email, srp_pw2, srp_salt).unwrap();

    assert_eq!(
        v1.verifier, v2.verifier,
        "Same password + salt must produce same verifier (determinism)"
    );
}

#[test]
fn test_different_passwords_produce_different_verifiers() {
    let email = "test@example.com";
    let srp_salt = generate_salt();

    let srp_pw1 = derive_srp_password(b"password-a", &srp_salt).unwrap();
    let v1 = compute_verifier(email, srp_pw1, srp_salt).unwrap();

    let srp_pw2 = derive_srp_password(b"password-b", &srp_salt).unwrap();
    let v2 = compute_verifier(email, srp_pw2, srp_salt).unwrap();

    assert_ne!(
        v1.verifier, v2.verifier,
        "Different passwords must produce different verifiers"
    );
}

#[test]
fn test_different_salts_produce_different_verifiers() {
    let email = "test@example.com";
    let salt1 = generate_salt();
    let salt2 = generate_salt();
    let pw = b"same-password";

    let srp_pw1 = derive_srp_password(pw, &salt1).unwrap();
    let v1 = compute_verifier(email, srp_pw1, salt1).unwrap();

    let srp_pw2 = derive_srp_password(pw, &salt2).unwrap();
    let v2 = compute_verifier(email, srp_pw2, salt2).unwrap();

    assert_ne!(
        v1.verifier, v2.verifier,
        "Different salts must produce different verifiers"
    );
}

#[test]
fn test_different_emails_produce_different_verifiers() {
    let srp_salt = generate_salt();
    let pw = b"same-password";

    let srp_pw = derive_srp_password(pw, &srp_salt).unwrap();
    let v1 = compute_verifier("alice@example.com", srp_pw, srp_salt).unwrap();
    
    let srp_pw2 = derive_srp_password(pw, &srp_salt).unwrap();
    let v2 = compute_verifier("bob@example.com", srp_pw2, srp_salt).unwrap();

    assert_ne!(
        v1.verifier, v2.verifier,
        "Different emails must produce different verifiers"
    );
}

// ─── Ephemeral Generation Tests ───────────────────────────────────────────────

#[test]
fn test_client_ephemeral_public_key_is_not_all_zeros() {
    let eph = generate_client_ephemeral().unwrap();
    assert!(
        !eph.public_a.iter().all(|&b| b == 0),
        "A must not be 0 mod N"
    );
}

#[test]
fn test_client_ephemeral_is_unique_per_call() {
    let eph1 = generate_client_ephemeral().unwrap();
    let eph2 = generate_client_ephemeral().unwrap();

    assert_ne!(
        &eph1.public_a, &eph2.public_a,
        "Each ephemeral generation must produce unique A"
    );
}

#[test]
fn test_client_ephemeral_public_key_has_expected_size() {
    let eph = generate_client_ephemeral().unwrap();
    // RFC 5054 2048-bit group: public values should be ~256 bytes
    assert!(
        eph.public_a.len() >= 250 && eph.public_a.len() <= 256,
        "Public A should be ~256 bytes for 2048-bit group, got {}",
        eph.public_a.len()
    );
}

// ─── Client Proof Computation Tests ───────────────────────────────────────────

#[test]
fn test_compute_client_proof_rejects_zero_b() {
    let email = "test@example.com";
    let srp_salt = generate_salt();
    let srp_pw = derive_srp_password(b"password", &srp_salt).unwrap();
    let eph = generate_client_ephemeral().unwrap();
    
    // Server sends B = 0 (malicious or buggy)
    let zero_b = vec![0u8; 256];
    
    let result = compute_client_proof(
        email,
        srp_pw,
        &srp_salt,
        &zero_b,
        &eph,
    );
    
    assert!(
        result.is_err(),
        "Client must reject B = 0 from server"
    );
    
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(
            err_msg.contains("B = 0"),
            "Error message should mention B = 0, got: {}",
            err_msg
        );
    }
}

#[test]
fn test_compute_client_proof_different_salts_different_proofs() {
    let email = "test@example.com";
    let salt1 = generate_salt();
    let salt2 = generate_salt();
    
    let srp_pw1 = derive_srp_password(b"password", &salt1).unwrap();
    let eph1 = generate_client_ephemeral().unwrap();
    let fake_server_b = vec![1u8; 256];  // placeholder
    
    let proof1 = compute_client_proof(
        email,
        srp_pw1,
        &salt1,
        &fake_server_b,
        &eph1,
    ).unwrap();
    
    let srp_pw2 = derive_srp_password(b"password", &salt2).unwrap();
    let eph2 = generate_client_ephemeral().unwrap();
    let proof2 = compute_client_proof(
        email,
        srp_pw2,
        &salt2,
        &fake_server_b,
        &eph2,
    ).unwrap();
    
    assert_ne!(
        proof1.client_proof, proof2.client_proof,
        "Different salts must produce different client proofs"
    );
}

// ─── Property-Based Tests (Simplified, No proptest macro) ─────────────────────

#[test]
fn prop_verifier_deterministic_multiple_runs() {
    let email = "test@example.com";
    let password = b"random-password-123";
    let salt = generate_salt();
    
    // Run multiple times to verify determinism
    for _ in 0..5 {
        let pw1 = derive_srp_password(password, &salt).unwrap();
        let pw2 = derive_srp_password(password, &salt).unwrap();
        
        let v1 = compute_verifier(email, pw1, salt).unwrap();
        let v2 = compute_verifier(email, pw2, salt).unwrap();
        
        assert_eq!(v1.verifier, v2.verifier, "Verifier must be deterministic");
    }
}

#[test]
fn prop_different_passwords_different_verifiers_multiple() {
    let email = "test@example.com";
    let salt = generate_salt();
    
    let passwords: &[&[u8]] = &[b"pass-A", b"pass-B", b"pass-C", b"pass-D"];
    let mut verifiers = Vec::new();
    
    for pw in passwords {
        let srp_pw = derive_srp_password(*pw, &salt).unwrap();  // *pw dereferences &&[u8] to &[u8]
        let v = compute_verifier(email, srp_pw, salt).unwrap();
        verifiers.push(v.verifier);
    }
    
    // All verifiers should be unique
    for i in 0..verifiers.len() {
        for j in (i+1)..verifiers.len() {
            assert_ne!(
                verifiers[i], verifiers[j],
                "Different passwords must produce different verifiers"
            );
        }
    }
}

#[test]
fn prop_ephemeral_unique_multiple_generations() {
    // Generate many ephemerals and verify uniqueness
    let mut public_as = Vec::new();
    
    for _ in 0..20 {
        let eph = generate_client_ephemeral().unwrap();
        // Check not already seen, and clone to avoid move
        for existing in &public_as {
            assert_ne!(&eph.public_a, existing, "Ephemeral A must be unique");
        }
        public_as.push(eph.public_a.clone());  // ← Clone to avoid move error
    }
}

// ─── Security Property Tests ──────────────────────────────────────────────────

#[test]
fn test_verifier_does_not_leak_password() {
    let email = "test@example.com";
    let password = b"super-secret-password-123!";
    let salt = generate_salt();
    
    let srp_pw = derive_srp_password(password, &salt).unwrap();
    let verifier = compute_verifier(email, srp_pw, salt).unwrap();
    
    // Basic check: verifier shouldn't contain password bytes directly
    let password_str = String::from_utf8_lossy(password).to_lowercase();
    let verifier_hex = format!("{:x?}", &verifier.verifier);
    
    assert!(
        !verifier_hex.to_lowercase().contains(&password_str),
        "Verifier should not contain password in plaintext"
    );
}

#[test]
fn test_salt_is_preserved_in_verifier_output() {
    let email = "test@example.com";
    let salt = generate_salt();
    let srp_pw = derive_srp_password(b"password", &salt).unwrap();
    
    let result = compute_verifier(email, srp_pw, salt).unwrap();
    
    assert_eq!(
        result.srp_salt, salt,
        "Output SrpVerifier must preserve the input salt"
    );
}