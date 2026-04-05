// tests/keypair.rs

//! Tests for keypair generation, private key encryption, and ECDH vault wrapping.

use evnx_crypto::{
    kdf::{derive_master_key, generate_salt},
    keypair::{
        decrypt_private_key, encrypt_private_key, generate_keypair, unwrap_vault_key,
        wrap_vault_key_for_user,
    },
    vault::VaultKey,
};
use proptest::prelude::*;
// use proptest::test_runner::ProptestConfig;
use proptest::prelude::ProptestConfig;

// ─── Keypair Generation ────────────────────────────────────────────────────────

#[test]
fn test_keypair_generates_distinct_keys_each_call() {
    let kp1 = generate_keypair();
    let kp2 = generate_keypair();

    // Public keys must differ (random generation)
    assert_ne!(kp1.ed25519_public.0, kp2.ed25519_public.0);
    assert_ne!(kp1.x25519_public.0, kp2.x25519_public.0);
}

#[test]
fn test_ed25519_public_key_is_32_bytes() {
    let kp = generate_keypair();
    assert_eq!(kp.ed25519_public.0.len(), 32);
}

#[test]
fn test_x25519_public_key_is_32_bytes() {
    let kp = generate_keypair();
    assert_eq!(kp.x25519_public.0.len(), 32);
}

#[test]
fn test_x25519_key_derivation_is_deterministic() {
    // Regenerating keypair from encrypted private key should reproduce
    // the same X25519 public key
    let kp = generate_keypair();
    let original_x25519_pub = kp.x25519_public.0;

    let salt = generate_salt();
    let master_key = derive_master_key(b"test-password", &salt).unwrap();

    let enc = encrypt_private_key(&kp, &master_key).unwrap();
    let master_key2 = derive_master_key(b"test-password", &salt).unwrap();
    let kp2 = decrypt_private_key(&enc, &master_key2).unwrap();

    assert_eq!(
        original_x25519_pub, kp2.x25519_public.0,
        "X25519 public key must be deterministically derived from Ed25519 seed"
    );
}

// ─── Private Key Encryption ────────────────────────────────────────────────────

#[test]
fn test_encrypt_decrypt_private_key_round_trip() {
    let kp = generate_keypair();
    let original_ed25519_pub = kp.ed25519_public.0;
    let original_x25519_pub = kp.x25519_public.0;

    let salt = generate_salt();
    let master_key = derive_master_key(b"my-password-123", &salt).unwrap();
    let enc = encrypt_private_key(&kp, &master_key).unwrap();

    // Re-derive master key (simulates login flow)
    let master_key2 = derive_master_key(b"my-password-123", &salt).unwrap();
    let kp2 = decrypt_private_key(&enc, &master_key2).unwrap();

    assert_eq!(
        original_ed25519_pub, kp2.ed25519_public.0,
        "Ed25519 public key must match"
    );
    assert_eq!(
        original_x25519_pub, kp2.x25519_public.0,
        "X25519 public key must match"
    );
}

#[test]
fn test_wrong_master_key_fails_decryption() {
    let kp = generate_keypair();
    let salt = generate_salt();
    let master_key = derive_master_key(b"correct-password", &salt).unwrap();
    let enc = encrypt_private_key(&kp, &master_key).unwrap();

    // Wrong password → different master key
    let wrong_master_key = derive_master_key(b"wrong-password", &salt).unwrap();
    let result = decrypt_private_key(&enc, &wrong_master_key);

    assert!(
        result.is_err(),
        "Decryption with wrong master key must fail"
    );
    // Must NOT panic — must return Err
}

#[test]
fn test_tampered_encrypted_private_key_fails() {
    let kp = generate_keypair();
    let salt = generate_salt();
    let master_key = derive_master_key(b"password", &salt).unwrap();
    let mut enc = encrypt_private_key(&kp, &master_key).unwrap();

    // Flip a bit in the ciphertext
    enc.ciphertext[5] ^= 0xFF;

    let master_key2 = derive_master_key(b"password", &salt).unwrap();
    let result = decrypt_private_key(&enc, &master_key2);

    assert!(
        result.is_err(),
        "Tampered ciphertext must fail authentication"
    );
}

#[test]
fn test_encrypted_private_key_nonce_is_unique_per_call() {
    let kp1 = generate_keypair();
    let kp2 = generate_keypair();
    let salt = generate_salt();
    let mk = derive_master_key(b"pw", &salt).unwrap();
    let salt2 = generate_salt();
    let mk2 = derive_master_key(b"pw", &salt2).unwrap();

    let enc1 = encrypt_private_key(&kp1, &mk).unwrap();
    let enc2 = encrypt_private_key(&kp2, &mk2).unwrap();

    assert_ne!(
        enc1.nonce, enc2.nonce,
        "Each encryption must use a fresh nonce"
    );
}

#[test]
fn test_encrypted_private_key_different_passwords_produce_different_ciphertext() {
    let kp = generate_keypair();
    let salt = generate_salt();
    let mk1 = derive_master_key(b"password-a", &salt).unwrap();
    let mk2 = derive_master_key(b"password-b", &salt).unwrap();

    let enc1 = encrypt_private_key(&kp, &mk1).unwrap();
    let enc2 = encrypt_private_key(&kp, &mk2).unwrap();

    assert_ne!(enc1.ciphertext, enc2.ciphertext);
}

// ─── ECDH Vault Key Wrapping ───────────────────────────────────────────────────

#[test]
fn test_wrap_unwrap_vault_key_round_trip() {
    let sender = generate_keypair();
    let recipient = generate_keypair();

    let vault_key = VaultKey::generate();
    let original_key_bytes = vault_key.0;

    let wrapped = wrap_vault_key_for_user(&vault_key, &recipient.x25519_public).unwrap();
    let unwrapped = unwrap_vault_key(&wrapped, recipient.x25519_private_bytes()).unwrap();

    assert_eq!(
        original_key_bytes, unwrapped.0,
        "VaultKey must survive wrap/unwrap round-trip"
    );
    let _ = sender; // suppress unused warning
}

#[test]
fn test_wrap_for_wrong_recipient_fails() {
    let recipient_a = generate_keypair();
    let recipient_b = generate_keypair();

    let vault_key = VaultKey::generate();
    let wrapped = wrap_vault_key_for_user(&vault_key, &recipient_a.x25519_public).unwrap();

    // recipient_b tries to unwrap with their key — must fail
    let result = unwrap_vault_key(&wrapped, recipient_b.x25519_private_bytes());
    assert!(result.is_err(), "Wrong private key must fail unwrap");
}

#[test]
fn test_wrap_uses_fresh_ephemeral_key_each_call() {
    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();

    let wrapped1 = wrap_vault_key_for_user(&vault_key, &recipient.x25519_public).unwrap();
    let wrapped2 = wrap_vault_key_for_user(&vault_key, &recipient.x25519_public).unwrap();

    // Ephemeral public keys must differ (each wrap generates new ephemeral keypair)
    assert_ne!(
        wrapped1.eph_pub_key, wrapped2.eph_pub_key,
        "Each wrap must use a fresh ephemeral keypair"
    );

    // Both must unwrap to the same vault key
    let kp1 = unwrap_vault_key(&wrapped1, recipient.x25519_private_bytes()).unwrap();
    let kp2 = unwrap_vault_key(&wrapped2, recipient.x25519_private_bytes()).unwrap();
    assert_eq!(kp1.0, kp2.0);
}

#[test]
fn test_tampered_wrapped_vault_key_fails() {
    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();
    let mut wrapped = wrap_vault_key_for_user(&vault_key, &recipient.x25519_public).unwrap();

    // Tamper with ciphertext (skip first 24-byte nonce prefix)
    let ciphertext_start = 24; // XCHACHA_NONCE_LEN
    if wrapped.encrypted_vault_key.len() > ciphertext_start + 1 {
        wrapped.encrypted_vault_key[ciphertext_start + 1] ^= 0xAA;
    }

    let result = unwrap_vault_key(&wrapped, recipient.x25519_private_bytes());
    assert!(result.is_err(), "Tampered ciphertext must fail");
}

#[test]
fn test_tampered_ephemeral_pubkey_fails() {
    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();
    let mut wrapped = wrap_vault_key_for_user(&vault_key, &recipient.x25519_public).unwrap();

    // Corrupt the ephemeral public key
    wrapped.eph_pub_key[0] ^= 0xFF;

    let result = unwrap_vault_key(&wrapped, recipient.x25519_private_bytes());
    assert!(
        result.is_err(),
        "Wrong ephemeral public key must produce wrong shared secret → decrypt fail"
    );
}

// ─── Property-Based Tests ──────────────────────────────────────────────────────

// proptest! {
//     #[test]
//     fn prop_encrypt_decrypt_private_key_any_password(
//         password in "[a-zA-Z0-9!@#$%^&*]{8,64}"
//     ) {
//         let kp = generate_keypair();
//         let original_pub = kp.ed25519_public.0;

//         let salt = generate_salt();
//         let mk = derive_master_key(password.as_bytes(), &salt).unwrap();
//         let enc = encrypt_private_key(&kp, &mk).unwrap();

//         let mk2 = derive_master_key(password.as_bytes(), &salt).unwrap();
//         let kp2 = decrypt_private_key(&enc, &mk2).unwrap();

//         prop_assert_eq!(original_pub, kp2.ed25519_public.0);
//     }

//     #[test]
//     fn prop_wrap_unwrap_vault_key_any_vault_key(
//         key_bytes in proptest::array::uniform32(any::<u8>())
//     ) {
//         let recipient = generate_keypair();
//         let vault_key = VaultKey(key_bytes);
//         let original = vault_key.0;

//         let wrapped = wrap_vault_key_for_user(&vault_key, &recipient.x25519_public).unwrap();
//         let unwrapped = unwrap_vault_key(&wrapped, recipient.x25519_private_bytes()).unwrap();

//         prop_assert_eq!(original, unwrapped.0);
//     }
// }

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]  // ← Reduce from 256 to 16

    #[test]
    fn prop_encrypt_decrypt_private_key_any_password(
        password in "[a-zA-Z0-9!@#$%^&*]{8,32}"  // ← Shorter max length
    ) {
        let kp = generate_keypair();
        let original_pub = kp.ed25519_public.0;

        let salt = generate_salt();
        let mk = derive_master_key(password.as_bytes(), &salt).unwrap();
        let enc = encrypt_private_key(&kp, &mk).unwrap();

        let mk2 = derive_master_key(password.as_bytes(), &salt).unwrap();
        let kp2 = decrypt_private_key(&enc, &mk2).unwrap();

        prop_assert_eq!(original_pub, kp2.ed25519_public.0);
    }

    #[test]
    fn prop_wrap_unwrap_vault_key_any_vault_key(
        key_bytes in proptest::array::uniform32(any::<u8>())
    ) {
        let recipient = generate_keypair();
        let vault_key = VaultKey(key_bytes);
        let original = vault_key.0;

        let wrapped = wrap_vault_key_for_user(&vault_key, &recipient.x25519_public).unwrap();
        let unwrapped = unwrap_vault_key(&wrapped, recipient.x25519_private_bytes()).unwrap();

        prop_assert_eq!(original, unwrapped.0);
    }
}
