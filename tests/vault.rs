// tests/vault.rs
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, KeyInit as XKeyInit};
use aes_gcm::aead::Aead;
use chacha20poly1305::aead::Aead as XAead;
use rand::RngCore;
use proptest::prelude::*;

use evnx_crypto::vault::{
    encrypt_vault, decrypt_vault, wrap_vault_key_with_master_key, 
    unwrap_vault_key_with_master_key, VaultKey, EncryptedBlob,
    VAULT_KEY_LEN, NONCE_LEN, XCHACHA_NONCE_LEN,
};
use evnx_crypto::errors::CryptoError;
use evnx_crypto::kdf::MasterKey;



// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a random MasterKey for testing
fn generate_test_master_key() -> MasterKey {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    MasterKey(key)
}

/// Generate a random VaultKey for testing
fn generate_test_vault_key() -> VaultKey {
    VaultKey::generate()
}

// ============================================================================
// Basic Round-Trip Tests
// ============================================================================

#[test]
fn test_encrypt_decrypt_round_trip_empty() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"";
    
    let blob = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key).expect("decryption failed");
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_encrypt_decrypt_round_trip_small() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"KEY=value\nSECRET=topsecret\n";
    
    let blob = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key).expect("decryption failed");
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_encrypt_decrypt_round_trip_large() {
    let vault_key = generate_test_vault_key();
    let mut plaintext = vec![0u8; 1024 * 1024];
    rand::rngs::OsRng.fill_bytes(&mut plaintext);
    
    let blob = encrypt_vault(&plaintext, &vault_key).expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key).expect("decryption failed");
    
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_encrypt_decrypt_round_trip_binary_data() {
    let vault_key = generate_test_vault_key();
    let plaintext: Vec<u8> = (0..256).map(|i| i as u8).cycle().take(500).collect();
    
    let blob = encrypt_vault(&plaintext, &vault_key).expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key).expect("decryption failed");
    
    assert_eq!(plaintext, decrypted);
}

// ============================================================================
// Property-Based Testing with Proptest
// ============================================================================

proptest! {
    #[test]
    fn proptest_encrypt_decrypt_round_trip(plaintext in prop::collection::vec(any::<u8>(), 0..65536)) {
        let vault_key = generate_test_vault_key();
        
        let blob = encrypt_vault(&plaintext, &vault_key)
            .expect("encryption should succeed");
        let decrypted = decrypt_vault(&blob, &vault_key)
            .expect("decryption should succeed with correct key");
        
        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn proptest_different_keys_fail_decryption(plaintext in prop::collection::vec(any::<u8>(), 0..1024)) {
        let vault_key1 = generate_test_vault_key();
        let vault_key2 = generate_test_vault_key();
        
        let blob = encrypt_vault(&plaintext, &vault_key1)
            .expect("encryption should succeed");
        
        let result = decrypt_vault(&blob, &vault_key2);
        prop_assert!(matches!(result, Err(CryptoError::Decryption)));
    }
}

// ============================================================================
// Nonce Uniqueness Tests
// ============================================================================

#[test]
fn test_encrypt_generates_unique_nonces() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"test data";
    
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..100 {
        let blob = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
        assert!(nonces.insert(blob.nonce), "Duplicate nonce generated!");
    }
}

#[test]
fn test_same_plaintext_different_ciphertexts() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"identical plaintext";
    
    let blob1 = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    let blob2 = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    
    assert_ne!(blob1.nonce, blob2.nonce);
    assert_ne!(blob1.ciphertext, blob2.ciphertext);
    
    let dec1 = decrypt_vault(&blob1, &vault_key).expect("decryption 1 failed");
    let dec2 = decrypt_vault(&blob2, &vault_key).expect("decryption 2 failed");
    assert_eq!(dec1, dec2);
    assert_eq!(plaintext, &dec1[..]);
}

// ============================================================================
// Error Handling: Wrong Key Tests
// ============================================================================

#[test]
fn test_wrong_key_returns_decryption_error_not_panic() {
    let vault_key = generate_test_vault_key();
    let wrong_key = generate_test_vault_key();
    let plaintext = b"secret data";
    
    let blob = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    let result = decrypt_vault(&blob, &wrong_key);
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

#[test]
fn test_corrupted_key_returns_decryption_error() {
    let mut vault_key = generate_test_vault_key();
    let plaintext = b"secret data";
    
    let blob = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    vault_key.0[0] ^= 0xFF;
    
    let result = decrypt_vault(&blob, &vault_key);
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

// ============================================================================
// Error Handling: Tampering Tests
// ============================================================================

#[test]
fn test_single_byte_tamper_in_ciphertext_returns_error() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"do not tamper";
    
    let mut blob = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    
    if !blob.ciphertext.is_empty() {
        blob.ciphertext[0] ^= 0x01;
    }
    
    let result = decrypt_vault(&blob, &vault_key);
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

#[test]
fn test_single_byte_tamper_in_nonce_returns_error() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"nonce tamper test";
    
    let mut blob = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    blob.nonce[0] ^= 0x01;
    
    let result = decrypt_vault(&blob, &vault_key);
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

#[test]
fn test_truncated_ciphertext_returns_error() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"truncation test";
    
    let mut blob = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    blob.ciphertext.pop();
    
    let result = decrypt_vault(&blob, &vault_key);
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

#[test]
fn test_appended_data_to_ciphertext_returns_error() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"append test";
    
    let mut blob = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    blob.ciphertext.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    
    let result = decrypt_vault(&blob, &vault_key);
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

// ============================================================================
// Key Wrapping/Unwrapping Tests
// ============================================================================

#[test]
fn test_wrap_unwrap_vault_key_round_trip() {
    let master_key = generate_test_master_key();
    let original_vault_key = generate_test_vault_key();
    
    let wrapped = wrap_vault_key_with_master_key(&original_vault_key, &master_key)
        .expect("wrapping failed");
    
    assert_eq!(wrapped.len(), XCHACHA_NONCE_LEN + VAULT_KEY_LEN + 16);
    
    let unwrapped = unwrap_vault_key_with_master_key(&wrapped, &master_key)
        .expect("unwrapping failed");
    
    assert_eq!(original_vault_key.0, unwrapped.0);
}

#[test]
fn test_wrap_unwrap_with_different_master_key_fails() {
    let master_key1 = generate_test_master_key();
    let master_key2 = generate_test_master_key();
    let vault_key = generate_test_vault_key();
    
    let wrapped = wrap_vault_key_with_master_key(&vault_key, &master_key1)
        .expect("wrapping failed");
    
    let result = unwrap_vault_key_with_master_key(&wrapped, &master_key2);
    assert!(matches!(result, Err(CryptoError::KeyUnwrap)));
}

#[test]
fn test_unwrap_too_short_input_returns_error() {
    let master_key = generate_test_master_key();
    let too_short = vec![0u8; XCHACHA_NONCE_LEN + VAULT_KEY_LEN - 1];
    
    let result = unwrap_vault_key_with_master_key(&too_short, &master_key);
    assert!(matches!(result, Err(CryptoError::InvalidInput(_))));
}

#[test]
fn test_unwrap_wrong_length_decrypted_key_returns_error() {
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    
    let master_key = generate_test_master_key();
    
    let cipher = XChaCha20Poly1305::new_from_slice(&master_key.0).unwrap();
    let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    // FIX: Use slice &short_key[..] instead of &[u8; 16]
    let short_key: [u8; 16] = [0u8; 16];
    let ciphertext = cipher.encrypt(nonce, &short_key[..]).unwrap();
    
    let mut wrapped = nonce_bytes.to_vec();
    wrapped.extend(ciphertext);
    
    let result = unwrap_vault_key_with_master_key(&wrapped, &master_key);
    assert!(matches!(result, Err(CryptoError::InvalidInput(_))));
}

#[test]
fn test_wrap_generates_unique_nonces() {
    let master_key = generate_test_master_key();
    let vault_key = generate_test_vault_key();
    
    let mut nonces = std::collections::HashSet::new();
    for _ in 0..50 {
        let wrapped = wrap_vault_key_with_master_key(&vault_key, &master_key)
            .expect("wrapping failed");
        let nonce: [u8; XCHACHA_NONCE_LEN] = wrapped[..XCHACHA_NONCE_LEN]
            .try_into()
            .expect("nonce extraction failed");
        assert!(nonces.insert(nonce), "Duplicate nonce in key wrapping!");
    }
}

// ============================================================================
// VaultKey Generation Tests
// ============================================================================

#[test]
fn test_vault_key_generate_produces_unique_keys() {
    let mut keys = std::collections::HashSet::new();
    for _ in 0..100 {
        let key = VaultKey::generate();
        assert!(keys.insert(key.0), "Duplicate VaultKey generated!");
    }
}

#[test]
fn test_vault_key_has_correct_length() {
    let key = VaultKey::generate();
    assert_eq!(key.0.len(), VAULT_KEY_LEN);
}

// ============================================================================
// EncryptedBlob Structure Tests
// ============================================================================

#[test]
fn test_encrypted_blob_contains_auth_tag() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"test";
    
    let blob = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    assert!(blob.ciphertext.len() >= plaintext.len() + 16);
}

#[test]
fn test_nonce_has_correct_length() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"test";
    
    let blob = encrypt_vault(plaintext, &vault_key).expect("encryption failed");
    assert_eq!(blob.nonce.len(), NONCE_LEN);
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[test]
fn test_encrypt_decrypt_with_all_zero_plaintext() {
    let vault_key = generate_test_vault_key();
    let plaintext = vec![0u8; 100];
    
    let blob = encrypt_vault(&plaintext, &vault_key).expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key).expect("decryption failed");
    
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_encrypt_decrypt_with_all_ones_plaintext() {
    let vault_key = generate_test_vault_key();
    let plaintext = vec![0xFFu8; 100];
    
    let blob = encrypt_vault(&plaintext, &vault_key).expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key).expect("decryption failed");
    
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_decrypt_with_empty_ciphertext_returns_error() {
    let vault_key = generate_test_vault_key();
    let blob = EncryptedBlob {
        nonce: [0u8; NONCE_LEN],
        ciphertext: vec![],
    };
    
    let result = decrypt_vault(&blob, &vault_key);
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

// ============================================================================
// Integration: Full Vault Workflow
// ============================================================================

#[test]
fn test_full_workflow_encrypt_wrap_unwrap_decrypt() {
    let master_key = generate_test_master_key();
    let vault_key = generate_test_vault_key();
    let plaintext = b"WORKFLOW_TEST=success\n";
    
    let blob = encrypt_vault(plaintext, &vault_key).expect("encrypt failed");
    let wrapped = wrap_vault_key_with_master_key(&vault_key, &master_key)
        .expect("wrap failed");
    let unwrapped = unwrap_vault_key_with_master_key(&wrapped, &master_key)
        .expect("unwrap failed");
    let decrypted = decrypt_vault(&blob, &unwrapped).expect("decrypt failed");
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_workflow_wrong_master_key_fails_unwrap() {
    let master_key1 = generate_test_master_key();
    let master_key2 = generate_test_master_key();
    let vault_key = generate_test_vault_key();
    
    let wrapped = wrap_vault_key_with_master_key(&vault_key, &master_key1)
        .expect("wrap failed");
    
    let result = unwrap_vault_key_with_master_key(&wrapped, &master_key2);
    assert!(matches!(result, Err(CryptoError::KeyUnwrap)));
}

// ============================================================================
// ZeroizeOnDrop Verification
// ============================================================================

#[test]
fn test_vault_key_implements_zeroize_on_drop() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_x: T) {}
    let key = VaultKey::generate();
    assert_zeroize_on_drop(key);
}