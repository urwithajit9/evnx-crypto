// tests/kdf.rs
// Integration tests for the KDF module

use evnx_crypto::kdf::{
    derive_master_key,
    derive_srp_password,
    generate_salt,
    // MasterKey,
    MASTER_KEY_LEN,
    SALT_LEN,
};
// use zeroize::Zeroizing;

/// Test 1: KDF determinism — same password + same salt → identical output
/// Critical for: being able to re-derive the same master key at login
#[test]
fn test_derive_master_key_deterministic() {
    let password = b"correct horse battery staple";
    let salt = [0x42u8; SALT_LEN]; // Fixed, known salt for reproducibility

    let key1 = derive_master_key(password, &salt)
        .expect("derive_master_key should succeed with valid inputs");
    let key2 = derive_master_key(password, &salt)
        .expect("derive_master_key should succeed with valid inputs");

    assert_eq!(
        key1.0, key2.0,
        "Same password and salt must produce identical master keys (determinism required)"
    );
}

/// Test 2: Salt sensitivity — same password + different salt → different keys
/// Critical for: ensuring salt uniqueness prevents precomputation attacks
#[test]
fn test_derive_master_key_different_salts_produce_different_keys() {
    let password = b"correct horse battery staple";
    let salt_a = [0x11u8; SALT_LEN];
    let mut salt_b = [0x22u8; SALT_LEN];
    salt_b[0] = 0xFF; // Ensure salts differ

    let key_a = derive_master_key(password, &salt_a).expect("derive_master_key should succeed");
    let key_b = derive_master_key(password, &salt_b).expect("derive_master_key should succeed");

    assert_ne!(
        key_a.0, key_b.0,
        "Different salts must produce different master keys (avalanche effect)"
    );
}

/// Test 3: Independent derivation paths — argon2_salt ≠ srp_salt
/// Critical for: compartmentalization; compromise of SRP verifier
/// must not enable derivation of the Ed25519-encrypting master key
#[test]
fn test_argon2_salt_and_srp_salt_produce_independent_outputs() {
    let password = b"correct horse battery staple";
    let argon2_salt = [0xAAu8; SALT_LEN]; // Salt for master key derivation
    let srp_salt = [0xBBu8; SALT_LEN]; // Salt for SRP password derivation

    // Derive using their intended, separate salts
    let master_key =
        derive_master_key(password, &argon2_salt).expect("derive_master_key should succeed");
    let srp_password =
        derive_srp_password(password, &srp_salt).expect("derive_srp_password should succeed");

    // Outputs must differ (different salts + different intended purposes)
    assert_ne!(
        master_key.0.as_slice(),
        srp_password.as_slice(),
        "Master key and SRP password must be cryptographically independent"
    );

    // Cross-derivation with wrong salt must NOT reproduce the correct output
    let master_key_wrong_salt = derive_master_key(password, &srp_salt)
        .expect("derive_master_key should succeed with any salt");
    let srp_password_wrong_salt = derive_srp_password(password, &argon2_salt)
        .expect("derive_srp_password should succeed with any salt");

    assert_ne!(
        master_key.0, master_key_wrong_salt.0,
        "Using SRP salt for master key derivation must produce different output"
    );
    assert_ne!(
        srp_password.as_slice(),
        srp_password_wrong_salt.as_slice(),
        "Using argon2 salt for SRP derivation must produce different output"
    );
}

// ============================================================================
// Additional robustness tests (recommended for production)
// ============================================================================

#[test]
fn test_generate_salt_uniqueness_and_length() {
    let salt1 = generate_salt();
    let salt2 = generate_salt();

    assert_eq!(
        salt1.len(),
        SALT_LEN,
        "Generated salt must be {} bytes",
        SALT_LEN
    );
    assert_eq!(
        salt2.len(),
        SALT_LEN,
        "Generated salt must be {} bytes",
        SALT_LEN
    );
    assert_ne!(
        salt1, salt2,
        "Generated salts must be unique (cryptographic randomness)"
    );
}

#[test]
fn test_derive_master_key_output_length() {
    let password = b"test";
    let salt = generate_salt();

    let master_key = derive_master_key(password, &salt).expect("derive_master_key should succeed");

    assert_eq!(
        master_key.0.len(),
        MASTER_KEY_LEN,
        "Master key must be exactly {} bytes",
        MASTER_KEY_LEN
    );
}

#[test]
fn test_derive_srp_password_output_length() {
    let password = b"test";
    let salt = generate_salt();

    let srp_output =
        derive_srp_password(password, &salt).expect("derive_srp_password should succeed");

    assert_eq!(
        srp_output.len(),
        32,
        "SRP password output must be exactly 32 bytes"
    );
}

#[test]
fn test_empty_password_does_not_panic() {
    // Argon2 should handle empty passwords gracefully
    let password = b"";
    let salt = [0u8; SALT_LEN];

    assert!(
        derive_master_key(password, &salt).is_ok(),
        "Empty password should not cause panic in derive_master_key"
    );
    assert!(
        derive_srp_password(password, &salt).is_ok(),
        "Empty password should not cause panic in derive_srp_password"
    );
}

#[test]
fn test_unicode_password_determinism() {
    // Ensure UTF-8 byte sequences are handled consistently
    let password = "pāsswörd🔐🚀".as_bytes();
    let salt = [0x99u8; SALT_LEN];

    let key1 = derive_master_key(password, &salt).expect("should succeed");
    let key2 = derive_master_key(password, &salt).expect("should succeed");

    assert_eq!(
        key1.0, key2.0,
        "Unicode passwords must derive deterministically when bytes match"
    );
}

#[test]
fn test_long_password_handling() {
    // Argon2 should handle arbitrarily long passwords
    let password = vec![0xCDu8; 4096];
    let salt = generate_salt();

    assert!(
        derive_master_key(&password, &salt).is_ok(),
        "Long passwords should be handled without error"
    );
    assert!(
        derive_srp_password(&password, &salt).is_ok(),
        "Long passwords should be handled without error (SRP path)"
    );
}

/// Benchmark helper (run with `cargo test -- --ignored` to execute)
/// Use this to tune ARGON2_* constants for your target hardware.
/// Target: 300–500ms per derivation on production server.
#[test]
#[ignore]
fn benchmark_derive_master_key() {
    use std::time::Instant;

    let password = b"benchmark_password_for_timing";
    let salt = generate_salt();

    let start = Instant::now();
    let _key = derive_master_key(password, &salt).expect("derivation should succeed");
    let elapsed = start.elapsed();

    println!("derive_master_key took: {:?}", elapsed);

    // Optional: fail test if too slow/fast during CI tuning
    // assert!(
    //     elapsed.as_millis() >= 300 && elapsed.as_millis() <= 500,
    //     "Derivation time {:?} outside target range 300-500ms",
    //     elapsed
    // );
}
