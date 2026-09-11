//! Wire-format encoding round-trips.
//!
//! Every helper here sits on the boundary between the client and the server.
//! A silent encoding change would break login for existing users, so these
//! tests pin both the round-trip property *and* the exact wire lengths the
//! server validates (`length(equal = 44)` and friends in `RegisterRequest`).

use evnx_crypto::{
    derive_master_key, encrypt_private_key, generate_keypair, generate_salt, salt_from_base64,
    salt_to_base64, wrap_vault_key_for_user, Ed25519PublicKey, EncryptedPrivateKey, VaultKey,
    WrappedVaultKey, X25519PublicKeyBytes,
};
use proptest::prelude::*;

/// The server validates salts and public keys as exactly 44 base64 characters.
const WIRE_B64_32_LEN: usize = 44;

// ─── Salts ─────────────────────────────────────────────────────────────────────

#[test]
fn salt_base64_round_trips_and_is_44_chars() {
    let salt = generate_salt();
    let encoded = salt_to_base64(&salt);

    assert_eq!(
        encoded.len(),
        WIRE_B64_32_LEN,
        "server validates srp_salt/argon2_salt as exactly 44 chars"
    );
    assert_eq!(salt_from_base64(&encoded).unwrap(), salt);
}

#[test]
fn salt_from_base64_rejects_wrong_length() {
    // 31 bytes instead of 32 — valid base64, wrong size.
    let short = evnx_crypto::b64_encode(&[7u8; 31]);
    assert!(salt_from_base64(&short).is_err());
}

#[test]
fn salt_from_base64_rejects_malformed_input() {
    assert!(salt_from_base64("this is not base64!!").is_err());
    assert!(salt_from_base64("").is_err());
}

// ─── Public keys ───────────────────────────────────────────────────────────────

#[test]
fn public_keys_round_trip_at_wire_length() {
    let kp = generate_keypair();

    let ed_b64 = kp.ed25519_public_base64();
    let x_b64 = kp.x25519_public_base64();

    assert_eq!(ed_b64.len(), WIRE_B64_32_LEN);
    assert_eq!(x_b64.len(), WIRE_B64_32_LEN);

    assert_eq!(
        Ed25519PublicKey::from_base64(&ed_b64).unwrap().0,
        kp.ed25519_public.0
    );
    assert_eq!(
        X25519PublicKeyBytes::from_base64(&x_b64).unwrap().0,
        kp.x25519_public.0
    );
}

#[test]
fn public_key_accessors_agree_with_the_underlying_types() {
    let kp = generate_keypair();
    assert_eq!(kp.ed25519_public_base64(), kp.ed25519_public.to_base64());
    assert_eq!(kp.x25519_public_base64(), kp.x25519_public.to_base64());
}

#[test]
fn public_key_from_base64_rejects_wrong_length() {
    let too_long = evnx_crypto::b64_encode(&[1u8; 33]);
    assert!(X25519PublicKeyBytes::from_base64(&too_long).is_err());
    assert!(Ed25519PublicKey::from_base64(&too_long).is_err());
}

// ─── EncryptedPrivateKey ───────────────────────────────────────────────────────

fn sample_encrypted_private_key() -> EncryptedPrivateKey {
    let kp = generate_keypair();
    let salt = generate_salt();
    let mk = derive_master_key(b"correct horse battery staple", &salt).unwrap();
    encrypt_private_key(&kp, &mk).unwrap()
}

#[test]
fn encrypted_private_key_round_trips() {
    let epk = sample_encrypted_private_key();
    let encoded = epk.to_base64();
    let decoded = EncryptedPrivateKey::from_base64(&encoded).unwrap();

    assert_eq!(decoded.nonce, epk.nonce);
    assert_eq!(decoded.ciphertext, epk.ciphertext);
}

#[test]
fn encrypted_private_key_fits_the_servers_length_window() {
    // RegisterRequest validates: length(min = 60, max = 300)
    let encoded = sample_encrypted_private_key().to_base64();
    assert!(
        (60..=300).contains(&encoded.len()),
        "encrypted_private_key was {} chars, outside the server's 60..=300 window",
        encoded.len()
    );
}

#[test]
fn encrypted_private_key_rejects_truncated_input() {
    // Nonce (24) + tag (16) = 40 bytes minimum; 39 must fail.
    let too_short = evnx_crypto::b64_encode(&[0u8; 39]);
    assert!(EncryptedPrivateKey::from_base64(&too_short).is_err());

    // Exactly at the boundary must succeed.
    let boundary = evnx_crypto::b64_encode(&[0u8; 40]);
    assert!(EncryptedPrivateKey::from_base64(&boundary).is_ok());
}

// ─── WrappedVaultKey ───────────────────────────────────────────────────────────

#[test]
fn wrapped_vault_key_round_trips() {
    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();
    let wrapped = wrap_vault_key_for_user(&vault_key, &recipient.x25519_public).unwrap();

    let rebuilt = WrappedVaultKey::from_base64(
        &wrapped.encrypted_vault_key_base64(),
        &wrapped.eph_pub_key_base64(),
    )
    .unwrap();

    assert_eq!(rebuilt.eph_pub_key, wrapped.eph_pub_key);
    assert_eq!(rebuilt.encrypted_vault_key, wrapped.encrypted_vault_key);
}

#[test]
fn wrapped_vault_key_rejects_bad_ephemeral_key() {
    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();
    let wrapped = wrap_vault_key_for_user(&vault_key, &recipient.x25519_public).unwrap();

    // eph_pub_key must be exactly 32 bytes.
    let bad_eph = evnx_crypto::b64_encode(&[9u8; 31]);
    assert!(WrappedVaultKey::from_base64(&wrapped.encrypted_vault_key_base64(), &bad_eph).is_err());
}

/// The arguments are easy to transpose at the call site; confirm the order is
/// (encrypted_vault_key, eph_pub_key) and not the reverse.
#[test]
fn wrapped_vault_key_argument_order_is_not_reversible() {
    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();
    let wrapped = wrap_vault_key_for_user(&vault_key, &recipient.x25519_public).unwrap();

    let swapped = WrappedVaultKey::from_base64(
        &wrapped.eph_pub_key_base64(),
        &wrapped.encrypted_vault_key_base64(),
    );

    // encrypted_vault_key is longer than 32 bytes, so it fails the eph length check.
    assert!(swapped.is_err(), "swapped arguments should be rejected");
}

// ─── SRP verifier ──────────────────────────────────────────────────────────────

#[test]
fn srp_verifier_encodes_as_hex_and_salt_as_base64() {
    use evnx_crypto::{compute_verifier, derive_srp_password};

    let srp_salt = generate_salt();
    let srp_password = derive_srp_password(b"correct horse battery staple", &srp_salt).unwrap();
    let verifier = compute_verifier("user@example.com", srp_password, srp_salt).unwrap();

    let hex_str = verifier.verifier_hex();
    assert!(
        hex_str.chars().all(|c| c.is_ascii_hexdigit()),
        "srp_verifier must be hex — the server calls hex::decode on it"
    );
    assert!(
        hex_str
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .all(|c| c.is_lowercase()),
        "hex must be lowercase"
    );
    assert_eq!(hex::decode(&hex_str).unwrap(), verifier.verifier);

    // RegisterRequest validates: length(min = 256, max = 1024)
    assert!(
        (256..=1024).contains(&hex_str.len()),
        "srp_verifier was {} chars, outside the server's 256..=1024 window",
        hex_str.len()
    );

    let salt_b64 = verifier.srp_salt_base64();
    assert_eq!(salt_b64.len(), WIRE_B64_32_LEN);
    assert_eq!(salt_from_base64(&salt_b64).unwrap(), srp_salt);
}

// ─── Properties ────────────────────────────────────────────────────────────────

proptest! {
    /// base64 round-trips for any byte string.
    #[test]
    fn b64_round_trips_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let encoded = evnx_crypto::b64_encode(&bytes);
        prop_assert_eq!(evnx_crypto::b64_decode(&encoded, "test").unwrap(), bytes);
    }

    /// Fixed-size decoding accepts exactly N bytes and rejects every other length.
    #[test]
    fn b64_decode_array_enforces_length(len in 0usize..80) {
        let encoded = evnx_crypto::b64_encode(&vec![0u8; len]);
        let decoded = evnx_crypto::b64_decode_array::<32>(&encoded, "test");
        prop_assert_eq!(decoded.is_ok(), len == 32);
    }

    /// Any 32-byte salt survives the encode/decode round-trip at 44 chars.
    #[test]
    fn salt_round_trips_for_any_value(raw in prop::array::uniform32(any::<u8>())) {
        let encoded = salt_to_base64(&raw);
        prop_assert_eq!(encoded.len(), WIRE_B64_32_LEN);
        prop_assert_eq!(salt_from_base64(&encoded).unwrap(), raw);
    }

    /// Any nonce + ciphertext pair survives the EncryptedPrivateKey round-trip.
    #[test]
    fn encrypted_private_key_round_trips_for_any_payload(
        nonce in prop::array::uniform24(any::<u8>()),
        ciphertext in prop::collection::vec(any::<u8>(), 16..256),
    ) {
        let epk = EncryptedPrivateKey { nonce, ciphertext: ciphertext.clone() };
        let decoded = EncryptedPrivateKey::from_base64(&epk.to_base64()).unwrap();
        prop_assert_eq!(decoded.nonce, nonce);
        prop_assert_eq!(decoded.ciphertext, ciphertext);
    }
}
