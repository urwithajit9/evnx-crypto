//! The README's Quick Start flows, as compiled and executed code.
//!
//! The README is the first thing anyone evaluating this crate reads. If its
//! examples do not compile, every other claim in it becomes suspect — so they are
//! not prose here, they are tests. Change an API and this file breaks, which is
//! the signal that the README needs updating.
//!
//! Keep these in step with the corresponding README sections.

use evnx_crypto::{
    compute_client_proof, compute_verifier, decrypt_private_key, decrypt_vault, derive_master_key,
    derive_srp_password, encrypt_private_key, encrypt_vault, generate_client_ephemeral,
    generate_keypair, generate_salt, unwrap_vault_key, vault_aad, verify_server_proof,
    wrap_vault_key_for_user, CryptoError, EncryptedPrivateKey, VaultKey, X25519PublicKeyBytes,
};

const PASSWORD: &[u8] = b"correct horse battery staple";
const EMAIL: &str = "user@example.test";

/// README — "Registration (client-side)"
#[test]
fn readme_registration_flow() -> Result<(), CryptoError> {
    // 1. Two independent salts — never shared, never reused.
    let argon2_salt = generate_salt();
    let srp_salt = generate_salt();

    // 2. Master key: local only, never transmitted.
    let master_key = derive_master_key(PASSWORD, &argon2_salt)?;

    // 3. Asymmetric keypair.
    let keypair = generate_keypair();

    // 4. Private key encrypted under the master key — safe to store server-side.
    let enc_private_key = encrypt_private_key(&keypair, &master_key)?;

    // 5. SRP verifier. Note the email: identity is bound into the verifier, so
    //    the same password under a different address yields a different one.
    let srp_password = derive_srp_password(PASSWORD, &srp_salt)?;
    let verifier = compute_verifier(EMAIL, srp_password, srp_salt)?;

    // 6. What actually goes to the server — all of it useless without the password.
    let _registration_payload = (
        EMAIL,
        verifier.verifier_hex(),
        verifier.srp_salt_base64(),
        evnx_crypto::salt_to_base64(&argon2_salt),
        keypair.ed25519_public_base64(),
        keypair.x25519_public_base64(),
        enc_private_key.to_base64(),
    );
    Ok(())
}

/// README — "Login (client-side)", including the M2 check most clients skip.
#[test]
fn readme_login_flow() -> Result<(), CryptoError> {
    // Registration, so there is something to log in against.
    let argon2_salt = generate_salt();
    let srp_salt = generate_salt();
    let master_key = derive_master_key(PASSWORD, &argon2_salt)?;
    let keypair = generate_keypair();
    let enc_private_key = encrypt_private_key(&keypair, &master_key)?;
    let verifier = compute_verifier(EMAIL, derive_srp_password(PASSWORD, &srp_salt)?, srp_salt)?;

    // The client stores nothing: everything below is re-derived from the password
    // plus what the server hands back.
    let enc_private_key =
        EncryptedPrivateKey::from_base64(&enc_private_key.to_base64()).expect("round trip");

    // 1. Re-derive the master key and recover the keypair.
    let master_key = derive_master_key(PASSWORD, &argon2_salt)?;
    let keypair_again = decrypt_private_key(&enc_private_key, &master_key)?;
    assert_eq!(
        keypair_again.x25519_public.0, keypair.x25519_public.0,
        "the same keypair must come back on a new machine"
    );

    // 2. SRP step 1 — client ephemeral.
    let eph = generate_client_ephemeral()?;

    // The server half, stood up locally so the flow completes end to end.
    let server = ::srp::server::SrpServer::<sha2::Sha256>::new(&::srp::groups::G_2048);
    let b = [3u8; 32];
    let server_b = server.compute_public_ephemeral(&b, &verifier.verifier);

    // 3. SRP step 2 — proof.
    let srp_password = derive_srp_password(PASSWORD, &srp_salt)?;
    let proof = compute_client_proof(EMAIL, srp_password, &srp_salt, &server_b, &eph)?;

    let server_verifier = server
        .process_reply(&b, &verifier.verifier, &eph.public_a)
        .expect("server processes A");
    server_verifier
        .verify_client(&proof.client_proof)
        .expect("server accepts M1");

    // 4. SRP step 3 — verify M2. Skipping this makes SRP one-way and lets an
    //    impostor server through; it is not optional.
    verify_server_proof(server_verifier.proof(), &proof)?;
    Ok(())
}

/// README — "Push (encrypt .env)" and "Pull (decrypt .env)".
#[test]
fn readme_push_and_pull_flow() -> Result<(), CryptoError> {
    let keypair = generate_keypair();
    let vault_id = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

    // A vault key, wrapped to the owner's own public key, as vault creation does.
    let vault_key = VaultKey::generate();
    let wrapped = wrap_vault_key_for_user(&vault_key, &keypair.x25519_public)?;

    // ── push ──────────────────────────────────────────────────────────────────
    let env_file_bytes = b"DATABASE_URL=postgres://user:pass@localhost/db\nAPI_KEY=s3cret\n";
    let base_version = 6;

    let key_for_push = unwrap_vault_key(&wrapped, keypair.x25519_private_bytes())?;
    let aad = vault_aad(vault_id, base_version + 1);
    let blob = encrypt_vault(env_file_bytes, &key_for_push, &aad)?;

    // ── pull ──────────────────────────────────────────────────────────────────
    let version_num = base_version + 1;
    let key_for_pull = unwrap_vault_key(&wrapped, keypair.x25519_private_bytes())?;
    let aad = vault_aad(vault_id, version_num);
    let plaintext = decrypt_vault(&blob, &key_for_pull, &aad)?;

    assert_eq!(
        plaintext, env_file_bytes,
        "push/pull must round-trip exactly"
    );
    Ok(())
}

/// README — "Share vault with a collaborator".
#[test]
fn readme_share_flow() -> Result<(), CryptoError> {
    let me = generate_keypair();
    let collaborator = generate_keypair();
    let vault_id = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";

    let vault_key = VaultKey::generate();
    let my_wrapped = wrap_vault_key_for_user(&vault_key, &me.x25519_public)?;

    let blob = encrypt_vault(b"SHARED=yes\n", &vault_key, &vault_aad(vault_id, 1))?;

    // Fetch the collaborator's public key from the server and re-wrap for them.
    // The server learns nothing: it only ever sees ciphertext and public keys.
    let collab_pub = X25519PublicKeyBytes::from_base64(&collaborator.x25519_public_base64())?;
    let my_vault_key = unwrap_vault_key(&my_wrapped, me.x25519_private_bytes())?;
    let wrapped_for_them = wrap_vault_key_for_user(&my_vault_key, &collab_pub)?;

    // The collaborator pulls and reads the same plaintext.
    let their_key = unwrap_vault_key(&wrapped_for_them, collaborator.x25519_private_bytes())?;
    let plaintext = decrypt_vault(&blob, &their_key, &vault_aad(vault_id, 1))?;

    assert_eq!(plaintext, b"SHARED=yes\n");
    Ok(())
}
