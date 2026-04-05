// tests/integration.rs

//! End-to-end client-side ZKE integration test.
//!
//! Tests the complete local crypto flow WITHOUT simulating the server.
//! SRP client-side operations are tested separately in tests/srp.rs.
//! This test focuses on the ZKE guarantee: keypair reconstruction,
//! vault key wrapping/unwrapping, and .env encrypt/decrypt round-trips.

use evnx_crypto::{
    kdf::{derive_master_key, derive_srp_password, generate_salt},
    keypair::{
        decrypt_private_key, encrypt_private_key, generate_keypair, unwrap_vault_key,
        wrap_vault_key_for_user,
    },
    srp::{compute_verifier, generate_client_ephemeral},
    vault::{
        decrypt_vault, encrypt_vault, unwrap_vault_key_with_master_key,
        wrap_vault_key_with_master_key, VaultKey,
    },
};

const TEST_EMAIL: &str = "integration-test@example.com";
const TEST_PASSWORD: &str = "TestP@ssw0rd-Integration!";
const TEST_ENV: &[u8] =
    b"DATABASE_URL=postgres://user:secret@localhost/db\nAPI_KEY=sk-live-abc123\nDEBUG=false\nPORT=8080\n";

// ─── Test 1: Registration ──────────────────────────────────────────────────────

#[test]
fn test_full_registration_flow() {
    let argon2_salt = generate_salt();
    let srp_salt = generate_salt();
    assert_ne!(argon2_salt, srp_salt, "Salts must be independent");

    let master_key = derive_master_key(TEST_PASSWORD.as_bytes(), &argon2_salt).unwrap();
    let keypair = generate_keypair();

    let ed25519_pub = keypair.ed25519_public.0;
    let x25519_pub = keypair.x25519_public.0;

    let enc_private_key = encrypt_private_key(&keypair, &master_key).unwrap();
    drop(keypair); // ZeroizeOnDrop

    // compute_verifier takes (email, srp_password_bytes, srp_salt)
    let srp_pw = derive_srp_password(TEST_PASSWORD.as_bytes(), &srp_salt).unwrap();
    let verifier = compute_verifier(TEST_EMAIL, srp_pw, srp_salt).unwrap();

    // Verify what the server would receive — no secrets
    assert!(!verifier.verifier.is_empty());
    assert!(!enc_private_key.ciphertext.is_empty());
    assert_eq!(ed25519_pub.len(), 32);
    assert_eq!(x25519_pub.len(), 32);

    println!(
        "✓ Registration: {} bytes verifier, {} bytes enc_key",
        verifier.verifier.len(),
        enc_private_key.ciphertext.len()
    );
}

// ─── Test 2: Login + Vault Push/Pull ──────────────────────────────────────────

#[test]
fn test_full_login_and_vault_push_pull_flow() {
    // ── Registration ──────────────────────────────────────────────────────
    let argon2_salt = generate_salt();
    let srp_salt = generate_salt();

    let master_key_reg = derive_master_key(TEST_PASSWORD.as_bytes(), &argon2_salt).unwrap();
    let keypair_reg = generate_keypair();
    let x25519_pub = keypair_reg.x25519_public.clone();
    let enc_private_key = encrypt_private_key(&keypair_reg, &master_key_reg).unwrap();

    drop(keypair_reg);
    drop(master_key_reg);

    // ── Vault creation (server-side: generates VaultKey, wraps for owner) ─
    let vault_key_original = VaultKey::generate();
    let original_key_bytes = vault_key_original.0;
    let wrapped_for_owner = wrap_vault_key_for_user(&vault_key_original, &x25519_pub).unwrap();

    // ── Login: re-derive master key, reconstruct keypair ─────────────────
    // (No SRP server simulation needed — srp.rs tests cover SRP round-trips)
    let master_key_login = derive_master_key(TEST_PASSWORD.as_bytes(), &argon2_salt).unwrap();
    let keypair_login = decrypt_private_key(&enc_private_key, &master_key_login).unwrap();
    drop(master_key_login);

    // Verify keypair public keys are consistent after reconstruction
    assert_eq!(
        keypair_login.x25519_public.0, x25519_pub.0,
        "Reconstructed X25519 public key must match original"
    );

    // Verify SRP ephemeral generation works (server call not simulated here)
    let eph = generate_client_ephemeral().unwrap();
    assert!(!eph.public_a.is_empty());
    println!(
        "✓ Login: keypair reconstructed, SRP A = {} bytes",
        eph.public_a.len()
    );

    // ── Vault Push: unwrap key, encrypt .env ─────────────────────────────
    let vault_key_push =
        unwrap_vault_key(&wrapped_for_owner, keypair_login.x25519_private_bytes()).unwrap();
    assert_eq!(
        vault_key_push.0, original_key_bytes,
        "Unwrapped key must match original"
    );

    let encrypted_blob = encrypt_vault(TEST_ENV, &vault_key_push).unwrap();
    println!(
        "✓ Push: encrypted {} bytes",
        encrypted_blob.ciphertext.len()
    );

    // ── Vault Pull: unwrap key again, decrypt .env ────────────────────────
    let vault_key_pull =
        unwrap_vault_key(&wrapped_for_owner, keypair_login.x25519_private_bytes()).unwrap();
    let decrypted = decrypt_vault(&encrypted_blob, &vault_key_pull).unwrap();
    assert_eq!(
        decrypted, TEST_ENV,
        "Decrypted content must be byte-identical to original"
    );
    println!("✓ Pull: {} bytes, content matches", decrypted.len());
}

// ─── Test 3: Vault Sharing ────────────────────────────────────────────────────

#[test]
fn test_vault_sharing_flow() {
    let owner_keypair = generate_keypair();
    let collab_keypair = generate_keypair();

    let vault_key = VaultKey::generate();
    let original = vault_key.0;

    // Owner wraps vault key for themselves
    let wrapped_for_owner =
        wrap_vault_key_for_user(&vault_key, &owner_keypair.x25519_public).unwrap();

    // Owner unwraps their copy, re-wraps for collaborator
    let vault_key_owner =
        unwrap_vault_key(&wrapped_for_owner, owner_keypair.x25519_private_bytes()).unwrap();

    let wrapped_for_collab =
        wrap_vault_key_for_user(&vault_key_owner, &collab_keypair.x25519_public).unwrap();

    // Collaborator unwraps their copy
    let vault_key_collab =
        unwrap_vault_key(&wrapped_for_collab, collab_keypair.x25519_private_bytes()).unwrap();

    assert_eq!(
        vault_key_collab.0, original,
        "Collaborator must get same vault key"
    );

    // Owner encrypts, collaborator decrypts
    let blob = encrypt_vault(TEST_ENV, &vault_key_owner).unwrap();
    let decrypted = decrypt_vault(&blob, &vault_key_collab).unwrap();
    assert_eq!(decrypted, TEST_ENV);

    println!("✓ Vault sharing: owner wrapped for collab, collab decrypted");
}

// ─── Test 4: Solo Vault (MasterKey wrap) ──────────────────────────────────────

#[test]
fn test_solo_vault_master_key_wrap_flow() {
    let argon2_salt = generate_salt();
    let master_key = derive_master_key(b"solo-user-password", &argon2_salt).unwrap();
    let vault_key = VaultKey::generate();
    let original = vault_key.0;

    let wrapped = wrap_vault_key_with_master_key(&vault_key, &master_key).unwrap();
    let master_key2 = derive_master_key(b"solo-user-password", &argon2_salt).unwrap();
    let unwrapped = unwrap_vault_key_with_master_key(&wrapped, &master_key2).unwrap();
    assert_eq!(unwrapped.0, original);

    let blob = encrypt_vault(TEST_ENV, &unwrapped).unwrap();
    let master_key3 = derive_master_key(b"solo-user-password", &argon2_salt).unwrap();
    let vk3 = unwrap_vault_key_with_master_key(&wrapped, &master_key3).unwrap();
    let decrypted = decrypt_vault(&blob, &vk3).unwrap();
    assert_eq!(decrypted, TEST_ENV);

    println!("✓ Solo vault MasterKey wrap/unwrap + encrypt/decrypt");
}
