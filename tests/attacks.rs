//! Adversarial tests.
//!
//! Every test here plays an attacker against a documented threat-model boundary.
//! The server is untrusted: it stores ciphertext and can return anything it likes,
//! including values crafted to break the client.

use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use evnx_crypto::*;
use hkdf::Hkdf;
use sha2::Sha256;

/// Curve25519 u-coordinate 0. Multiplying any scalar by this point yields the
/// identity, so the X25519 shared secret is all-zero **whatever** the victim's
/// private key is — the attacker does not need to know it.
const LOW_ORDER_POINT: [u8; 32] = [0u8; 32];

/// Reproduce the key derivation `wrap_vault_key_for_user` performs internally,
/// which an attacker can do too once the shared secret is predictable.
fn attacker_derive_wrap_key(shared_secret: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(b"evnx-vault-key-wrap-v1", &mut key).unwrap();
    key
}

#[test]
fn rejects_non_contributory_ecdh_key_substitution() {
    // THREAT: a malicious server (or anyone who can write vault_members) replaces
    // eph_pub_key with a low-order point and encrypted_vault_key with a key of
    // their own choosing. If the client accepts it, the victim encrypts their
    // .env under a key the attacker knows — zero-knowledge is gone.
    let victim = generate_keypair();

    // The attacker knows the shared secret will be all-zero, so they can derive
    // the wrap key without any of the victim's secrets.
    let wrap_key = attacker_derive_wrap_key(&[0u8; 32]);
    let attacker_chosen_vault_key = [0x42u8; 32];

    let cipher = XChaCha20Poly1305::new_from_slice(&wrap_key).unwrap();
    let nonce_bytes = [7u8; 24];
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            &attacker_chosen_vault_key[..],
        )
        .unwrap();

    let mut encrypted_vault_key = nonce_bytes.to_vec();
    encrypted_vault_key.extend_from_slice(&ciphertext);

    let forged = WrappedVaultKey {
        eph_pub_key: LOW_ORDER_POINT,
        // A real encapsulation to the victim, so the ML-KEM half is genuinely
        // valid. The attack has to be refused on the X25519 half alone — this is
        // not a test that passes because the forgery was lazy.
        mlkem_ciphertext: mlkem_encapsulate(&victim.mlkem_public).unwrap().0,
        encrypted_vault_key,
    };

    let result = unwrap_vault_key(&forged, &victim);

    assert!(
        result.is_err(),
        "client accepted a vault key chosen by the attacker — \
         non-contributory ECDH must be rejected"
    );
}

#[test]
fn master_key_and_srp_password_differ_even_under_a_reused_salt() {
    // THREAT: the two KDFs are documented as requiring distinct salts, but nothing
    // enforces it. If a caller ever passes the same salt to both — a plausible
    // slip, since both are 32 random bytes generated the same way — identical
    // Argon2 parameters would make the SRP password input byte-identical to the
    // master key. Anything that leaked the SRP input would then leak the key that
    // decrypts the user's private key.
    //
    // Domain separation must make that impossible rather than merely discouraged.
    let password = b"correct horse battery staple";
    let shared_salt = generate_salt();

    let master = derive_master_key(password, &shared_salt).unwrap();
    let srp = derive_srp_password(password, &shared_salt).unwrap();

    assert_ne!(
        &master.expose()[..],
        &srp[..],
        "master key and SRP password collide when the same salt is reused"
    );
}

#[test]
fn vault_blob_is_bound_to_its_vault_and_version() {
    // THREAT: a malicious server serves an OLD version's blob in place of the
    // latest. The client holds the right vault key, so an unbound ciphertext
    // decrypts perfectly and the user silently gets stale secrets — a revoked API
    // key comes back to life, a rotated credential reverts.
    //
    // The server's stored BLAKE3 hash does not help: the server is untrusted in
    // this model and can serve the old blob together with its matching hash.
    //
    // The fix is to bind each ciphertext to its identity with AEAD associated
    // data, so a blob encrypted as (vault, v3) cannot be decrypted as (vault, v7).
    let vault_key = VaultKey::generate();
    let vault_id = "11111111-2222-3333-4444-555555555555";

    let v3 = encrypt_vault(
        b"API_KEY=old-and-revoked\n",
        &vault_key,
        &vault_aad(vault_id, 3),
    )
    .unwrap();

    // The attacker replays v3's bytes while the client believes it asked for v7.
    let replayed = decrypt_vault(&v3, &vault_key, &vault_aad(vault_id, 7));

    assert!(
        replayed.is_err(),
        "a version-3 blob decrypted as version 7 — rollback attack succeeds"
    );

    // And a blob cannot be moved between vaults, even for the same key holder.
    let other_vault = decrypt_vault(
        &v3,
        &vault_key,
        &vault_aad("99999999-8888-7777-6666-555555555555", 3),
    );
    assert!(
        other_vault.is_err(),
        "blob accepted under a different vault id"
    );

    // The honest path still works.
    let ok = decrypt_vault(&v3, &vault_key, &vault_aad(vault_id, 3)).unwrap();
    assert_eq!(ok, b"API_KEY=old-and-revoked\n");
}

/// Every Curve25519 point of small order. A clamped X25519 scalar is a multiple
/// of 8, so each of these is sent to the identity and yields an all-zero shared
/// secret whatever the peer's private key is.
const LOW_ORDER_POINTS: [[u8; 32]; 7] = [
    [0u8; 32],
    {
        let mut p = [0u8; 32];
        p[0] = 1;
        p
    },
    hex_literal(*b"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    hex_literal(*b"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    hex_literal(*b"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex_literal(*b"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex_literal(*b"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
];

/// Decode a 64-character hex literal at compile time.
const fn hex_literal(src: [u8; 64]) -> [u8; 32] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => 0,
        }
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(src[i * 2]) << 4) | nib(src[i * 2 + 1]);
        i += 1;
    }
    out
}

#[test]
fn every_low_order_point_is_rejected_when_unwrapping() {
    let victim = generate_keypair();

    for (i, point) in LOW_ORDER_POINTS.iter().enumerate() {
        let wrap_key = attacker_derive_wrap_key(&[0u8; 32]);
        let cipher = XChaCha20Poly1305::new_from_slice(&wrap_key).unwrap();
        let nonce = [9u8; 24];
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), &[0xAAu8; 32][..])
            .unwrap();

        let mut encrypted_vault_key = nonce.to_vec();
        encrypted_vault_key.extend_from_slice(&ct);

        let forged = WrappedVaultKey {
            eph_pub_key: *point,
            mlkem_ciphertext: mlkem_encapsulate(&victim.mlkem_public).unwrap().0,
            encrypted_vault_key,
        };

        assert!(
            unwrap_vault_key(&forged, &victim).is_err(),
            "low-order point #{i} was accepted"
        );
    }
}

#[test]
fn low_order_recipient_key_is_rejected_when_wrapping() {
    // The same defect in the other direction: sharing a vault *to* a low-order
    // public key would wrap the vault key under a secret anyone can compute.
    let vault_key = VaultKey::generate();

    // A real, valid ML-KEM key beside the poisoned X25519 one, so the refusal
    // has to come from the curve check rather than from a malformed bundle.
    let honest = generate_keypair();

    for (i, point) in LOW_ORDER_POINTS.iter().enumerate() {
        let recipient = UserPublicKeys {
            x25519: X25519PublicKeyBytes(*point),
            mlkem: honest.mlkem_public.clone(),
        };
        assert!(
            wrap_vault_key_for_user(&vault_key, &recipient).is_err(),
            "wrapped a vault key for low-order recipient #{i}"
        );
    }
}

#[test]
fn ephemeral_public_keys_cannot_be_swapped_between_wraps() {
    // THREAT: a server that holds two legitimate wraps splices the ephemeral key
    // of one onto the ciphertext of the other. Both halves are individually
    // authentic, so anything that authenticates them separately would accept it.
    let recipient = generate_keypair();
    let key_a = VaultKey::generate();
    let key_b = VaultKey::generate();

    let wrap_a = wrap_vault_key_for_user(&key_a, &recipient.public_keys()).unwrap();
    let wrap_b = wrap_vault_key_for_user(&key_b, &recipient.public_keys()).unwrap();

    let spliced = WrappedVaultKey {
        eph_pub_key: wrap_a.eph_pub_key,
        mlkem_ciphertext: wrap_a.mlkem_ciphertext.clone(),
        encrypted_vault_key: wrap_b.encrypted_vault_key.clone(),
    };

    assert!(
        unwrap_vault_key(&spliced, &recipient).is_err(),
        "spliced ephemeral key and ciphertext were accepted"
    );

    // And the post-quantum half splices no better: A's ephemeral X25519 key with
    // B's ML-KEM ciphertext derives a wrap key matching neither wrap.
    let crossed = WrappedVaultKey {
        eph_pub_key: wrap_a.eph_pub_key,
        mlkem_ciphertext: wrap_b.mlkem_ciphertext.clone(),
        encrypted_vault_key: wrap_a.encrypted_vault_key.clone(),
    };

    assert!(
        unwrap_vault_key(&crossed, &recipient).is_err(),
        "a wrap with one half from each of two legitimate wraps was accepted"
    );
}

#[test]
fn stripping_the_gcm_tag_is_rejected() {
    // THREAT: truncate the 128-bit authentication tag and hope the AEAD only
    // checks what remains.
    let key = VaultKey::generate();
    let blob = encrypt_vault(b"DATABASE_URL=postgres://secret", &key, b"").unwrap();

    let mut stripped = blob.ciphertext.clone();
    stripped.truncate(stripped.len() - 16);

    let tampered = EncryptedBlob {
        nonce: blob.nonce,
        ciphertext: stripped,
    };
    assert!(decrypt_vault(&tampered, &key, b"").is_err());
}

#[test]
fn a_vault_key_wrapped_for_one_user_is_useless_to_another() {
    let alice = generate_keypair();
    let mallory = generate_keypair();
    let vault_key = VaultKey::generate();

    let for_alice = wrap_vault_key_for_user(&vault_key, &alice.public_keys()).unwrap();

    assert!(
        unwrap_vault_key(&for_alice, &mallory).is_err(),
        "a non-recipient unwrapped the vault key"
    );
    // Alice still can.
    let recovered = unwrap_vault_key(&for_alice, &alice).unwrap();
    assert_eq!(recovered.expose(), vault_key.expose());
}

#[test]
fn a_tampered_server_proof_is_rejected() {
    // THREAT: an active MITM completes SRP with the client but cannot produce a
    // valid M2, because it never learned the verifier. If the client skipped or
    // mis-implemented this check, SRP's mutual authentication would be one-way and
    // the client would trust an impostor server.
    let email = "user@example.test";
    let password = b"correct horse battery staple";
    let srp_salt = generate_salt();

    let srp_pw = derive_srp_password(password, &srp_salt).unwrap();
    let verifier = compute_verifier(email, srp_pw, srp_salt).unwrap();

    // Stand in for the server just enough to produce a well-formed B.
    let ephemeral = generate_client_ephemeral().unwrap();
    let server = ::srp::server::SrpServer::<sha2::Sha256>::new(&::srp::groups::G_2048);
    let b = [7u8; 32];
    let server_public = server.compute_public_ephemeral(&b, &verifier.verifier);

    let srp_pw2 = derive_srp_password(password, &srp_salt).unwrap();
    let proof =
        compute_client_proof(email, srp_pw2, &srp_salt, &server_public, &ephemeral).unwrap();

    let genuine = server
        .process_reply(&b, &verifier.verifier, &ephemeral.public_a)
        .unwrap();
    genuine.verify_client(&proof.client_proof).unwrap();
    let real_m2 = genuine.proof().to_vec();

    // The honest proof verifies.
    verify_server_proof(&real_m2, &proof).expect("genuine M2 must verify");

    // Every single-bit corruption of it must not.
    for bit in 0..8 {
        let mut forged = real_m2.clone();
        forged[0] ^= 1 << bit;
        assert!(
            verify_server_proof(&forged, &proof).is_err(),
            "a server proof with bit {bit} flipped was accepted"
        );
    }
    assert!(
        verify_server_proof(&[], &proof).is_err(),
        "empty M2 accepted"
    );
    assert!(
        verify_server_proof(&[0u8; 32], &proof).is_err(),
        "all-zero M2 accepted"
    );
}

#[test]
fn key_types_do_not_leak_through_debug() {
    // A key reaching a log through a `{:?}` on some enclosing struct is a silent,
    // total compromise. Redaction is asserted, not assumed.
    let salt = generate_salt();
    let master = derive_master_key(b"hunter2", &salt).unwrap();
    let vault = VaultKey::generate();

    let master_dbg = format!("{master:?}");
    let vault_dbg = format!("{vault:?}");

    assert!(master_dbg.contains("redacted"), "{master_dbg}");
    assert!(vault_dbg.contains("redacted"), "{vault_dbg}");

    // And the actual bytes must not appear.
    let master_hex = hex::encode(master.expose());
    let vault_hex = hex::encode(vault.expose());
    assert!(!master_dbg.contains(&master_hex));
    assert!(!vault_dbg.contains(&vault_hex));
    for byte_str in [
        format!("{}", master.expose()[0]),
        format!("{}", vault.expose()[0]),
    ] {
        assert!(
            !master_dbg.contains(&format!("[{byte_str}")),
            "{master_dbg}"
        );
    }
}

#[test]
fn wrong_master_key_cannot_open_a_wrapped_vault_key() {
    let salt_a = generate_salt();
    let salt_b = generate_salt();
    let mk_a = derive_master_key(b"password-a", &salt_a).unwrap();
    let mk_b = derive_master_key(b"password-b", &salt_b).unwrap();

    let vault_key = VaultKey::generate();
    let wrapped = wrap_vault_key_with_master_key(&vault_key, &mk_a).unwrap();

    assert!(unwrap_vault_key_with_master_key(&wrapped, &mk_b).is_err());
    let ok = unwrap_vault_key_with_master_key(&wrapped, &mk_a).unwrap();
    assert_eq!(ok.expose(), vault_key.expose());
}
