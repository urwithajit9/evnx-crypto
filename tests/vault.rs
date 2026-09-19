// tests/vault.rs
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use proptest::prelude::*;
use rand::RngCore;

use evnx_crypto::errors::CryptoError;
use evnx_crypto::kdf::MasterKey;
use evnx_crypto::vault::{
    blob_hash, decrypt_vault, encrypt_vault, reencrypt_vault, unwrap_vault_key_with_master_key,
    vault_aad, wrap_vault_key_with_master_key, EncryptedBlob, VaultKey, NONCE_LEN, VAULT_KEY_LEN,
    XCHACHA_NONCE_LEN,
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a random MasterKey for testing
fn generate_test_master_key() -> MasterKey {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    MasterKey::from_bytes_for_test(key)
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

    let blob = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key, b"").expect("decryption failed");

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_encrypt_decrypt_round_trip_small() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"KEY=value\nSECRET=topsecret\n";

    let blob = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key, b"").expect("decryption failed");

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_encrypt_decrypt_round_trip_large() {
    let vault_key = generate_test_vault_key();
    let mut plaintext = vec![0u8; 1024 * 1024];
    rand::rngs::OsRng.fill_bytes(&mut plaintext);

    let blob = encrypt_vault(&plaintext, &vault_key, b"").expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key, b"").expect("decryption failed");

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_encrypt_decrypt_round_trip_binary_data() {
    let vault_key = generate_test_vault_key();
    let plaintext: Vec<u8> = (0..256).map(|i| i as u8).cycle().take(500).collect();

    let blob = encrypt_vault(&plaintext, &vault_key, b"").expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key, b"").expect("decryption failed");

    assert_eq!(plaintext, decrypted);
}

// ============================================================================
// Property-Based Testing with Proptest
// ============================================================================

proptest! {
    #[test]
    fn proptest_encrypt_decrypt_round_trip(plaintext in prop::collection::vec(any::<u8>(), 0..65536)) {
        let vault_key = generate_test_vault_key();

        let blob = encrypt_vault(&plaintext, &vault_key, b"")
            .expect("encryption should succeed");
        let decrypted = decrypt_vault(&blob, &vault_key, b"")
            .expect("decryption should succeed with correct key");

        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn proptest_different_keys_fail_decryption(plaintext in prop::collection::vec(any::<u8>(), 0..1024)) {
        let vault_key1 = generate_test_vault_key();
        let vault_key2 = generate_test_vault_key();

        let blob = encrypt_vault(&plaintext, &vault_key1, b"")
            .expect("encryption should succeed");

        let result = decrypt_vault(&blob, &vault_key2, b"");
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
        let blob = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");
        assert!(nonces.insert(blob.nonce), "Duplicate nonce generated!");
    }
}

#[test]
fn test_same_plaintext_different_ciphertexts() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"identical plaintext";

    let blob1 = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");
    let blob2 = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");

    assert_ne!(blob1.nonce, blob2.nonce);
    assert_ne!(blob1.ciphertext, blob2.ciphertext);

    let dec1 = decrypt_vault(&blob1, &vault_key, b"").expect("decryption 1 failed");
    let dec2 = decrypt_vault(&blob2, &vault_key, b"").expect("decryption 2 failed");
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

    let blob = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");
    let result = decrypt_vault(&blob, &wrong_key, b"");
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

#[test]
fn test_corrupted_key_returns_decryption_error() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"secret data";

    let blob = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");

    // A key can no longer be mutated in place — it is built corrupted instead,
    // which is closer to the real threat anyway: a wrong key, not a damaged one.
    let mut corrupted_bytes = *vault_key.expose();
    corrupted_bytes[0] ^= 0xFF;
    let corrupted_key = VaultKey::from_bytes_for_test(corrupted_bytes);

    let result = decrypt_vault(&blob, &corrupted_key, b"");
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

// ============================================================================
// Error Handling: Tampering Tests
// ============================================================================

#[test]
fn test_single_byte_tamper_in_ciphertext_returns_error() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"do not tamper";

    let mut blob = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");

    if !blob.ciphertext.is_empty() {
        blob.ciphertext[0] ^= 0x01;
    }

    let result = decrypt_vault(&blob, &vault_key, b"");
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

#[test]
fn test_single_byte_tamper_in_nonce_returns_error() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"nonce tamper test";

    let mut blob = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");
    blob.nonce[0] ^= 0x01;

    let result = decrypt_vault(&blob, &vault_key, b"");
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

#[test]
fn test_truncated_ciphertext_returns_error() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"truncation test";

    let mut blob = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");
    blob.ciphertext.pop();

    let result = decrypt_vault(&blob, &vault_key, b"");
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

#[test]
fn test_appended_data_to_ciphertext_returns_error() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"append test";

    let mut blob = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");
    blob.ciphertext.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let result = decrypt_vault(&blob, &vault_key, b"");
    assert!(matches!(result, Err(CryptoError::Decryption)));
}

// ============================================================================
// Key Wrapping/Unwrapping Tests
// ============================================================================

#[test]
fn test_wrap_unwrap_vault_key_round_trip() {
    let master_key = generate_test_master_key();
    let original_vault_key = generate_test_vault_key();

    let wrapped =
        wrap_vault_key_with_master_key(&original_vault_key, &master_key).expect("wrapping failed");

    assert_eq!(wrapped.len(), XCHACHA_NONCE_LEN + VAULT_KEY_LEN + 16);

    let unwrapped =
        unwrap_vault_key_with_master_key(&wrapped, &master_key).expect("unwrapping failed");

    assert_eq!(original_vault_key.expose(), unwrapped.expose());
}

#[test]
fn test_wrap_unwrap_with_different_master_key_fails() {
    let master_key1 = generate_test_master_key();
    let master_key2 = generate_test_master_key();
    let vault_key = generate_test_vault_key();

    let wrapped =
        wrap_vault_key_with_master_key(&vault_key, &master_key1).expect("wrapping failed");

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

    // White-box: mirrors the implementation's key derivation so the test can forge
    // a blob that authenticates but carries a wrong-length payload. The domain tag
    // must stay in step with HKDF_INFO_VAULT_KEY_WRAP_MK in src/vault.rs.
    //
    // Note this is only reachable by someone who already holds the master key — the
    // length check below is defence against our own bugs, not against an attacker.
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, master_key.expose());
    let mut subkey = [0u8; 32];
    hk.expand(b"evnx-vault-key-wrap-mk-v1", &mut subkey)
        .unwrap();

    let cipher = XChaCha20Poly1305::new_from_slice(&subkey).unwrap();
    let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

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
        let wrapped =
            wrap_vault_key_with_master_key(&vault_key, &master_key).expect("wrapping failed");
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
        assert!(keys.insert(*key.expose()), "Duplicate VaultKey generated!");
    }
}

#[test]
fn test_vault_key_has_correct_length() {
    let key = VaultKey::generate();
    assert_eq!(key.expose().len(), VAULT_KEY_LEN);
}

// ============================================================================
// EncryptedBlob Structure Tests
// ============================================================================

#[test]
fn test_encrypted_blob_contains_auth_tag() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"test";

    let blob = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");
    assert!(blob.ciphertext.len() >= plaintext.len() + 16);
}

#[test]
fn test_nonce_has_correct_length() {
    let vault_key = generate_test_vault_key();
    let plaintext = b"test";

    let blob = encrypt_vault(plaintext, &vault_key, b"").expect("encryption failed");
    assert_eq!(blob.nonce.len(), NONCE_LEN);
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

#[test]
fn test_encrypt_decrypt_with_all_zero_plaintext() {
    let vault_key = generate_test_vault_key();
    let plaintext = vec![0u8; 100];

    let blob = encrypt_vault(&plaintext, &vault_key, b"").expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key, b"").expect("decryption failed");

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_encrypt_decrypt_with_all_ones_plaintext() {
    let vault_key = generate_test_vault_key();
    let plaintext = vec![0xFFu8; 100];

    let blob = encrypt_vault(&plaintext, &vault_key, b"").expect("encryption failed");
    let decrypted = decrypt_vault(&blob, &vault_key, b"").expect("decryption failed");

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_decrypt_with_empty_ciphertext_returns_error() {
    let vault_key = generate_test_vault_key();
    let blob = EncryptedBlob {
        nonce: [0u8; NONCE_LEN],
        ciphertext: vec![],
    };

    let result = decrypt_vault(&blob, &vault_key, b"");
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

    let blob = encrypt_vault(plaintext, &vault_key, b"").expect("encrypt failed");
    let wrapped = wrap_vault_key_with_master_key(&vault_key, &master_key).expect("wrap failed");
    let unwrapped = unwrap_vault_key_with_master_key(&wrapped, &master_key).expect("unwrap failed");
    let decrypted = decrypt_vault(&blob, &unwrapped, b"").expect("decrypt failed");

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_workflow_wrong_master_key_fails_unwrap() {
    let master_key1 = generate_test_master_key();
    let master_key2 = generate_test_master_key();
    let vault_key = generate_test_vault_key();

    let wrapped = wrap_vault_key_with_master_key(&vault_key, &master_key1).expect("wrap failed");

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

// ============================================================================
// blob_hash — the transport hash a push declares
// ============================================================================

/// Pins the wire format against an independently computed value.
///
/// The server recomputes this hash and **rejects** a push that disagrees, so a
/// change here does not degrade gracefully — it breaks every push at once.
#[test]
fn test_blob_hash_is_blake3_hex_of_the_ciphertext() {
    let h = blob_hash(b"some ciphertext");

    assert_eq!(h, blake3::hash(b"some ciphertext").to_hex().to_string());
    assert_eq!(h.len(), 64, "hex of a 256-bit digest");
    assert!(
        h.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "lowercase hex, which is what the server compares against"
    );
}

/// Guards against a stub returning a constant — which every assertion above
/// would happily accept.
#[test]
fn test_blob_hash_distinguishes_inputs() {
    assert_ne!(blob_hash(b"a"), blob_hash(b"b"));
    assert_eq!(blob_hash(b"a"), blob_hash(b"a"));
    // Empty input is legal and must not panic.
    assert_eq!(blob_hash(b"").len(), 64);
}

/// The hash covers the **ciphertext alone**, never the stored `nonce || ciphertext`.
///
/// Getting this wrong is the likeliest mistake a new client makes: `encrypt_vault`
/// hands back both halves, and hashing the concatenation produces a value the
/// server refuses with a message about the hash rather than about the nonce.
#[test]
fn test_blob_hash_excludes_the_nonce() {
    let vault_key = generate_test_vault_key();
    let blob = encrypt_vault(b"KEY=value", &vault_key, b"aad").expect("encrypt failed");

    let mut with_nonce = blob.nonce.to_vec();
    with_nonce.extend_from_slice(&blob.ciphertext);

    assert_eq!(blob_hash(&blob.ciphertext).len(), 64);
    assert_ne!(
        blob_hash(&blob.ciphertext),
        blob_hash(&with_nonce),
        "hashing nonce || ciphertext must not accidentally agree"
    );
}

// ─── Re-keying (Phase 3 step 4) ────────────────────────────────────────────────

/// The core property: after re-encryption the new key opens it and the old one
/// does not.
#[test]
fn reencrypt_moves_a_blob_to_a_new_key() {
    let old_key = VaultKey::generate();
    let new_key = VaultKey::generate();
    let aad = vault_aad("3f2504e0-4f89-11d3-9a0c-0305e82c3301", 7);
    let plaintext = b"DATABASE_URL=postgres://localhost/app\nAPI_KEY=s3cret\n";

    let original = encrypt_vault(plaintext, &old_key, &aad).unwrap();
    let rekeyed = reencrypt_vault(&original, &old_key, &new_key, &aad).unwrap();

    assert_eq!(
        decrypt_vault(&rekeyed, &new_key, &aad).unwrap(),
        plaintext,
        "the new key must open the re-encrypted blob"
    );
    assert!(
        decrypt_vault(&rekeyed, &old_key, &aad).is_err(),
        "the OLD key must not open it — otherwise re-keying achieves nothing"
    );
}

/// ⚠️ The AAD binds a blob to `(vault_id, version)`. Re-encryption must preserve
/// it: a re-keyed version 7 that only opens under version 8's AAD would be
/// unreadable through the normal pull path, and a caller passing `b""` would
/// silently strip the replay protection the blob had before.
#[test]
fn reencrypt_preserves_the_associated_data() {
    let old_key = VaultKey::generate();
    let new_key = VaultKey::generate();
    let vault = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
    let aad_v7 = vault_aad(vault, 7);

    let original = encrypt_vault(b"X=1\n", &old_key, &aad_v7).unwrap();
    let rekeyed = reencrypt_vault(&original, &old_key, &new_key, &aad_v7).unwrap();

    assert!(decrypt_vault(&rekeyed, &new_key, &aad_v7).is_ok());

    // A different version's AAD must not open it.
    assert!(decrypt_vault(&rekeyed, &new_key, &vault_aad(vault, 8)).is_err());
    // Nor a different vault's.
    assert!(decrypt_vault(
        &rekeyed,
        &new_key,
        &vault_aad("00000000-0000-0000-0000-000000000000", 7)
    )
    .is_err());
    // Nor an absent one.
    assert!(decrypt_vault(&rekeyed, &new_key, b"").is_err());
}

/// A wrong old key must fail cleanly — the caller has re-keyed nothing, rather
/// than writing a blob encrypted under a new key from plaintext it never
/// recovered.
#[test]
fn reencrypt_refuses_a_wrong_old_key() {
    let old_key = VaultKey::generate();
    let wrong = VaultKey::generate();
    let new_key = VaultKey::generate();
    let aad = vault_aad("3f2504e0-4f89-11d3-9a0c-0305e82c3301", 1);

    let original = encrypt_vault(b"X=1\n", &old_key, &aad).unwrap();
    assert!(reencrypt_vault(&original, &wrong, &new_key, &aad).is_err());
}

/// A mismatched AAD fails too, for the same reason.
#[test]
fn reencrypt_refuses_a_mismatched_aad() {
    let old_key = VaultKey::generate();
    let new_key = VaultKey::generate();
    let vault = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

    let original = encrypt_vault(b"X=1\n", &old_key, &vault_aad(vault, 1)).unwrap();
    assert!(reencrypt_vault(&original, &old_key, &new_key, &vault_aad(vault, 2)).is_err());
}

/// Re-encryption uses a fresh nonce, so two runs over the same input differ.
/// Reusing the old nonce under a different key would be harmless in AES-GCM
/// terms, but it is not a habit worth having near this code.
#[test]
fn reencrypt_uses_a_fresh_nonce() {
    let old_key = VaultKey::generate();
    let new_key = VaultKey::generate();
    let aad = vault_aad("3f2504e0-4f89-11d3-9a0c-0305e82c3301", 1);

    let original = encrypt_vault(b"X=1\n", &old_key, &aad).unwrap();
    let a = reencrypt_vault(&original, &old_key, &new_key, &aad).unwrap();
    let b = reencrypt_vault(&original, &old_key, &new_key, &aad).unwrap();

    assert_ne!(a.nonce, original.nonce);
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);

    // Both still open to the same plaintext.
    assert_eq!(
        decrypt_vault(&a, &new_key, &aad).unwrap(),
        decrypt_vault(&b, &new_key, &aad).unwrap()
    );
}

/// A whole vault's history re-keyed in one pass — the shape `POST /rekey` drives.
/// Every version must move, each under its own AAD.
#[test]
fn a_whole_history_rekeys_version_by_version() {
    let old_key = VaultKey::generate();
    let new_key = VaultKey::generate();
    let vault = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

    let history: Vec<(u32, Vec<u8>)> = (1..=12)
        .map(|v| (v, format!("VERSION={v}\nSECRET=value-{v}\n").into_bytes()))
        .collect();

    let originals: Vec<_> = history
        .iter()
        .map(|(v, pt)| encrypt_vault(pt, &old_key, &vault_aad(vault, *v)).unwrap())
        .collect();

    let rekeyed: Vec<_> = originals
        .iter()
        .zip(&history)
        .map(|(blob, (v, _))| {
            reencrypt_vault(blob, &old_key, &new_key, &vault_aad(vault, *v)).unwrap()
        })
        .collect();

    for (blob, (v, expected)) in rekeyed.iter().zip(&history) {
        assert_eq!(
            &decrypt_vault(blob, &new_key, &vault_aad(vault, *v)).unwrap(),
            expected,
            "version {v} did not survive the re-key"
        );
        assert!(
            decrypt_vault(blob, &old_key, &vault_aad(vault, *v)).is_err(),
            "version {v} is still readable with the old key"
        );
    }
}
