// tests/integration.rs

//! End-to-end client-side ZKE integration test.
//!
//! Simulates the complete flow that the CLI performs locally,
//! without any network or server involvement:
//!
//! 1. Registration: generate salts, derive keys, encrypt private key, compute SRP verifier
//! 2. Login: re-derive master key, decrypt private key, perform SRP auth
//! 3. Vault push: unwrap vault key, encrypt .env
//! 4. Vault pull: decrypt .env, verify it matches original
//! 5. Vault sharing: wrap vault key for a second user, unwrap and decrypt

use evnx_crypto::{
    kdf::{generate_salt, derive_master_key, derive_srp_password},
    vault::{VaultKey, encrypt_vault, decrypt_vault, wrap_vault_key_with_master_key, unwrap_vault_key_with_master_key},
    keypair::{generate_keypair, encrypt_private_key, decrypt_private_key, wrap_vault_key_for_user, unwrap_vault_key},
    srp::{compute_verifier, generate_client_ephemeral, compute_client_proof, verify_server_proof},
};
use srp::{server::{SrpServer, UserRecord}, groups::G_2048};
use sha2::Sha256;

const TEST_EMAIL: &str = "integration-test@example.com";
const TEST_PASSWORD: &str = "TestP@ssw0rd-Integration!";
const TEST_ENV: &[u8] = b"DATABASE_URL=postgres://user:secret@localhost/db\nAPI_KEY=sk-live-abc123\nDEBUG=false\nPORT=8080\n";

#[test]
fn test_full_registration_flow() {
    // CLIENT: Generate two independent salts
    let argon2_salt = generate_salt();
    let srp_salt = generate_salt();
    assert_ne!(argon2_salt, srp_salt, "Salts must be independent");

    // CLIENT: Derive master key (stays local, never transmitted)
    let master_key = derive_master_key(TEST_PASSWORD.as_bytes(), &argon2_salt).unwrap();

    // CLIENT: Generate keypair
    let keypair = generate_keypair();
    let ed25519_pub_bytes = keypair.ed25519_public.0;
    let x25519_pub_bytes = keypair.x25519_public.0;

    // CLIENT: Encrypt private key with master key
    let enc_private_key = encrypt_private_key(&keypair, &master_key).unwrap();
    drop(keypair); // simulates ZeroizeOnDrop

    // CLIENT: Derive SRP password and compute verifier (goes to server)
    let srp_pw = derive_srp_password(TEST_PASSWORD.as_bytes(), &srp_salt).unwrap();
    let verifier = compute_verifier(srp_pw, srp_salt).unwrap();

    // SERVER would store: { email, srp_verifier, srp_salt, argon2_salt, ed25519_pub, enc_private_key }
    // CLIENT would store nothing — all secrets derived fresh each session

    // Verify what the server receives:
    assert!(!verifier.verifier.is_empty());
    assert!(!enc_private_key.ciphertext.is_empty());
    assert_eq!(ed25519_pub_bytes.len(), 32);
    assert_eq!(x25519_pub_bytes.len(), 32);

    println!("✓ Registration flow complete");
    println!("  SRP verifier: {} bytes", verifier.verifier.len());
    println!("  Encrypted private key: {} bytes", enc_private_key.ciphertext.len());
}

#[test]
fn test_full_login_and_vault_push_pull_flow() {
    // ─── REGISTRATION ──────────────────────────────────────────────
    let argon2_salt = generate_salt();
    let srp_salt = generate_salt();
    let master_key_reg = derive_master_key(TEST_PASSWORD.as_bytes(), &argon2_salt).unwrap();
    let keypair_reg = generate_keypair();
    let x25519_pub = keypair_reg.x25519_public.clone();
    let enc_private_key = encrypt_private_key(&keypair_reg, &master_key_reg).unwrap();
    let srp_pw_reg = derive_srp_password(TEST_PASSWORD.as_bytes(), &srp_salt).unwrap();
    let verifier = compute_verifier(srp_pw_reg, srp_salt).unwrap();
    drop(keypair_reg);
    drop(master_key_reg);

    // ─── VAULT CREATION (server-side simulation) ───────────────────
    // When user creates a vault, a random VaultKey is generated.
    // It's wrapped with the user's X25519 public key for storage.
    let vault_key_original = VaultKey::generate();
    let original_key_bytes = vault_key_original.0;
    let wrapped_for_owner = wrap_vault_key_for_user(&vault_key_original, &x25519_pub).unwrap();

    // ─── LOGIN ─────────────────────────────────────────────────────
    // Client re-derives master key
    let master_key_login = derive_master_key(TEST_PASSWORD.as_bytes(), &argon2_salt).unwrap();

    // Client decrypts private key from server
    let keypair_login = decrypt_private_key(&enc_private_key, &master_key_login).unwrap();
    drop(master_key_login);

    // SRP authentication (abbreviated — full test in srp.rs)
    let eph = generate_client_ephemeral().unwrap();
    let server = SrpServer::<Sha256>::new(&G_2048);
    let record = UserRecord {
        username: TEST_EMAIL.as_bytes(),
        salt: &verifier.srp_salt,
        verifier: &verifier.verifier,
    };
    let (server_state, server_b) = server.process_registration(record).unwrap();
    let srp_pw_login = derive_srp_password(TEST_PASSWORD.as_bytes(), &verifier.srp_salt).unwrap();
    let proof = compute_client_proof(TEST_EMAIL, srp_pw_login, &verifier.srp_salt, &server_b, &eph).unwrap();
    let server_m2 = server_state.verify_client(&proof.client_proof).unwrap();
    verify_server_proof(&server_m2, &proof).unwrap();
    println!("✓ SRP login verified");

    // ─── VAULT PUSH ────────────────────────────────────────────────
    // Unwrap vault key using user's X25519 private key
    let vault_key_push = unwrap_vault_key(&wrapped_for_owner, keypair_login.x25519_private_bytes()).unwrap();
    assert_eq!(vault_key_push.0, original_key_bytes, "Unwrapped key must match original");

    // Encrypt .env file
    let encrypted_blob = encrypt_vault(TEST_ENV, &vault_key_push).unwrap();
    println!("✓ .env encrypted: {} bytes ciphertext", encrypted_blob.ciphertext.len());

    // ─── VAULT PULL ────────────────────────────────────────────────
    // Unwrap vault key again (simulates fetching from server)
    let vault_key_pull = unwrap_vault_key(&wrapped_for_owner, keypair_login.x25519_private_bytes()).unwrap();

    // Decrypt .env file
    let decrypted = decrypt_vault(&encrypted_blob, &vault_key_pull).unwrap();
    assert_eq!(decrypted, TEST_ENV, "Decrypted content must match original");
    println!("✓ .env decrypted: {} bytes, content matches", decrypted.len());
}

#[test]
fn test_vault_sharing_flow() {
    // Owner setup
    let owner_argon2_salt = generate_salt();
    let owner_mk = derive_master_key(b"owner-password", &owner_argon2_salt).unwrap();
    let owner_keypair = generate_keypair();
    let owner_x25519_pub = owner_keypair.x25519_public.clone();

    // Collaborator setup
    let collab_keypair = generate_keypair();
    let collab_x25519_pub = collab_keypair.x25519_public.clone();

    // Owner creates vault key
    let vault_key = VaultKey::generate();
    let original = vault_key.0;

    // Owner wraps vault key for themselves
    let wrapped_for_owner = wrap_vault_key_for_user(&vault_key, &owner_x25519_pub).unwrap();

    // Owner shares vault: wraps vault key for collaborator
    // (Owner must first unwrap their copy, then re-wrap for collaborator)
    let vault_key_owner = unwrap_vault_key(&wrapped_for_owner, owner_keypair.x25519_private_bytes()).unwrap();
    let wrapped_for_collab = wrap_vault_key_for_user(&vault_key_owner, &collab_x25519_pub).unwrap();

    // Collaborator can now decrypt the vault
    let vault_key_collab = unwrap_vault_key(&wrapped_for_collab, collab_keypair.x25519_private_bytes()).unwrap();
    assert_eq!(vault_key_collab.0, original, "Collaborator must get same vault key");

    // Encrypt with owner's key, decrypt with collab's unwrapped key
    let blob = encrypt_vault(TEST_ENV, &vault_key_owner).unwrap();
    let decrypted = decrypt_vault(&blob, &vault_key_collab).unwrap();
    assert_eq!(decrypted, TEST_ENV);

    println!("✓ Vault sharing: owner wrapped for collab, collab decrypted successfully");
    drop(owner_mk); // suppress unused
}

#[test]
fn test_solo_vault_master_key_wrap_flow() {
    // Alternative flow: solo vault where vault key is wrapped with MasterKey
    // (used in early versions before ECDH sharing is set up)
    let argon2_salt = generate_salt();
    let master_key = derive_master_key(b"solo-user-password", &argon2_salt).unwrap();
    let vault_key = VaultKey::generate();
    let original = vault_key.0;

    let wrapped = wrap_vault_key_with_master_key(&vault_key, &master_key).unwrap();

    let master_key2 = derive_master_key(b"solo-user-password", &argon2_salt).unwrap();
    let unwrapped = unwrap_vault_key_with_master_key(&wrapped, &master_key2).unwrap();
    assert_eq!(unwrapped.0, original);

    // Encrypt and decrypt
    let blob = encrypt_vault(TEST_ENV, &unwrapped).unwrap();
    let master_key3 = derive_master_key(b"solo-user-password", &argon2_salt).unwrap();
    let vk3 = unwrap_vault_key_with_master_key(&wrapped, &master_key3).unwrap();
    let decrypted = decrypt_vault(&blob, &vk3).unwrap();
    assert_eq!(decrypted, TEST_ENV);

    println!("✓ Solo vault MasterKey wrap/unwrap + encrypt/decrypt round-trip");
}