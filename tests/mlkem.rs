// tests/mlkem.rs

//! ML-KEM-768 derivation, encapsulation and decapsulation.
//!
//! These cover the post-quantum half of the hybrid vault-key wrap. The wrap
//! itself does not exist yet — this step only makes the keypair exist and proves
//! it is derived stably.
//!
//! ## What is actually at stake here
//!
//! The ML-KEM keypair is **derived**, not stored. Nothing about it lives in the
//! database: `users.encrypted_private_key` holds the same sealed 32-byte Ed25519
//! seed it always has, and the decapsulation key is recomputed from that seed on
//! every unlock. So the derivation is not an implementation detail that can be
//! tuned later — it is a permanent commitment. Change the info string, the hash,
//! or the seed length, and every vault key already wrapped to a user's ML-KEM
//! public key becomes unopenable, by them and by everyone. The server holds only
//! ciphertext; there is no migration that recovers from it.
//!
//! `test_mlkem_derivation_known_answer` is the test that catches that. Every
//! other test here passes happily against a wrong-but-self-consistent
//! derivation.

use evnx_crypto::{
    kdf::{derive_master_key, generate_salt},
    keypair::{
        decrypt_private_key, encrypt_private_key, generate_keypair, mlkem_encapsulate,
        MlKem768PublicKey, UserKeypair, MLKEM768_CIPHERTEXT_LEN, MLKEM768_PUBLIC_LEN,
        MLKEM_SHARED_SECRET_LEN,
    },
};
use hkdf::Hkdf;
use sha2::Sha256;

/// A fixed, arbitrary Ed25519 seed. Its only property is that it never changes.
const KAT_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─── The derivation is a permanent commitment ─────────────────────────────────

/// ⚠️ **If this test fails, do not update the expected value.**
///
/// A failure means the ML-KEM derivation changed, and that is a breaking change
/// for every user who has ever shared a vault — their wrapped vault keys were
/// encapsulated to the *old* public key and nothing can open them under the new
/// one. Find what changed (the HKDF info string, the hash, the seed length, the
/// ml-kem version's keygen) and revert it. Only a deliberate, versioned migration
/// with a new info string alongside the old one may change this number.
///
/// ## What this pins, and what it does not
///
/// It pins **our derivation**: seed → HKDF → ML-KEM keygen → public key. The
/// expected value was produced by this implementation, so it proves stability,
/// not conformance to FIPS 203. Conformance is `ml-kem`'s own KAT suite's job,
/// and this test will catch it if a future version of that crate changes keygen
/// output — which is the failure mode that would otherwise be silent.
#[test]
fn test_mlkem_derivation_known_answer() {
    let kp = UserKeypair::from_ed25519_seed_for_test(KAT_SEED);
    let pk = kp.mlkem_public.as_bytes();

    // Hashed rather than inlined: 1184 bytes of literal would be unreadable, and
    // BLAKE3 over the whole key catches a change anywhere in it.
    assert_eq!(
        blake3::hash(pk).to_hex().as_str(),
        "98595908e6d4ecb14dbd5f79af8bdd48151e4a2bab44c361e7e1b84ae669599b",
        "ML-KEM-768 derivation changed — see this test's doc comment before touching it"
    );

    // Endpoints too, so a failure message says *where* rather than only *that*.
    assert_eq!(
        hex(&pk[..32]),
        "6d8ca95fb5c0d006166535383a18191e9030927315f0822445aa5332486981f5"
    );
    assert_eq!(
        hex(&pk[MLKEM768_PUBLIC_LEN - 32..]),
        "3c87200bd1b8c54f557283c1c8a11f79b74314db9c7ca1748262bde850576cb9"
    );
}

/// The X25519 derivation must not have moved either — it predates ML-KEM and has
/// live users, so it is the more dangerous of the two to disturb. Adding a second
/// HKDF over the same seed is exactly the kind of change that could.
#[test]
fn test_x25519_derivation_unchanged_by_mlkem() {
    let kp = UserKeypair::from_ed25519_seed_for_test(KAT_SEED);
    assert_eq!(
        hex(&kp.x25519_public.0),
        "32c36f41accd5d7779648d0826838bd990f5663f25fb01e7fd6ff5158c01f437",
        "the X25519 derivation changed — existing shared vaults would break"
    );
}

// ─── Parameter set ────────────────────────────────────────────────────────────

/// Guards against a parameter-set mix-up. ML-KEM-512 and -1024 differ only by
/// these sizes at the type level, and picking the wrong one would compile.
#[test]
fn test_mlkem_sizes_are_the_768_parameter_set() {
    let kp = generate_keypair();
    assert_eq!(kp.mlkem_public.as_bytes().len(), 1184);
    assert_eq!(MLKEM768_PUBLIC_LEN, 1184);

    let (ct, ss) = mlkem_encapsulate(&kp.mlkem_public).expect("own key must encapsulate");
    assert_eq!(ct.len(), 1088);
    assert_eq!(MLKEM768_CIPHERTEXT_LEN, 1088);
    assert_eq!(ss.len(), 32);
    assert_eq!(MLKEM_SHARED_SECRET_LEN, 32);
}

// ─── Determinism ──────────────────────────────────────────────────────────────

#[test]
fn test_mlkem_derivation_is_deterministic() {
    let a = UserKeypair::from_ed25519_seed_for_test(KAT_SEED);
    let b = UserKeypair::from_ed25519_seed_for_test(KAT_SEED);
    assert_eq!(a.mlkem_public, b.mlkem_public);
}

#[test]
fn test_mlkem_distinct_seeds_give_distinct_keys() {
    let a = UserKeypair::from_ed25519_seed_for_test(KAT_SEED);
    let mut other = KAT_SEED;
    other[31] ^= 0x01; // one bit
    let b = UserKeypair::from_ed25519_seed_for_test(other);
    assert_ne!(a.mlkem_public, b.mlkem_public);
}

/// The property that makes the whole "derive, don't store" design work: unlocking
/// the account on a different machine must reproduce the identical ML-KEM key.
///
/// This goes through the real path — seal the seed under a master key, unseal it,
/// re-derive — rather than the test constructor.
#[test]
fn test_mlkem_key_survives_seal_and_unseal() {
    let original = generate_keypair();
    let salt = generate_salt();
    let mk = derive_master_key(b"correct horse battery staple", &salt).expect("kdf");

    let sealed = encrypt_private_key(&original, &mk).expect("seal");
    let restored = decrypt_private_key(&sealed, &mk).expect("unseal");

    assert_eq!(
        original.mlkem_public, restored.mlkem_public,
        "the ML-KEM key is not stored — if it does not re-derive, it is gone"
    );

    // And the restored key genuinely decapsulates what was sent to the original.
    let (ct, sent) = mlkem_encapsulate(&original.mlkem_public).expect("encapsulate");
    let received = restored.mlkem_decapsulate(&ct).expect("decapsulate");
    assert_eq!(sent, received);
}

// ─── Domain separation ────────────────────────────────────────────────────────

/// Both keys come from one Ed25519 seed, so the only thing keeping them
/// independent is the HKDF info string. Recomputed here against the documented
/// construction: if the two strings ever collided, the ML-KEM seed's first 32
/// bytes would be the X25519 private key.
#[test]
fn test_mlkem_seed_is_domain_separated_from_x25519() {
    let kp = UserKeypair::from_ed25519_seed_for_test(KAT_SEED);

    let hkdf = Hkdf::<Sha256>::new(None, &KAT_SEED);

    let mut mlkem_seed = [0u8; 64];
    hkdf.expand(b"evnx/mlkem768/v1", &mut mlkem_seed)
        .expect("expand");

    let mut x25519_seed = [0u8; 32];
    hkdf.expand(b"evnx-x25519-from-ed25519-v1", &mut x25519_seed)
        .expect("expand");

    assert_ne!(&mlkem_seed[..32], &x25519_seed[..]);
    assert_ne!(&mlkem_seed[32..], &x25519_seed[..]);
    assert_eq!(
        x25519_seed,
        kp.x25519_private_for_test(),
        "the recomputation must match what the crate actually derives, or this \
         test is checking a construction nobody uses"
    );
    // Nor may the Ed25519 seed itself survive into either derived key.
    assert_ne!(&mlkem_seed[..32], &KAT_SEED[..]);
    assert_ne!(x25519_seed, KAT_SEED);
}

// ─── Encapsulation round trip ─────────────────────────────────────────────────

#[test]
fn test_mlkem_encapsulate_decapsulate_round_trip() {
    let kp = generate_keypair();
    let (ct, sender_secret) = mlkem_encapsulate(&kp.mlkem_public).expect("encapsulate");
    let receiver_secret = kp.mlkem_decapsulate(&ct).expect("decapsulate");
    assert_eq!(sender_secret, receiver_secret);
    assert_ne!(sender_secret, [0u8; MLKEM_SHARED_SECRET_LEN]);
}

/// Encapsulation must be randomised. Two calls against the same public key that
/// produced the same ciphertext would mean the shared secret is a function of the
/// recipient alone — every vault shared with someone would use the same key.
#[test]
fn test_mlkem_encapsulation_is_randomised() {
    let kp = generate_keypair();
    let (ct1, ss1) = mlkem_encapsulate(&kp.mlkem_public).expect("encapsulate");
    let (ct2, ss2) = mlkem_encapsulate(&kp.mlkem_public).expect("encapsulate");
    assert_ne!(ct1, ct2);
    assert_ne!(ss1, ss2);
}

/// ⚠️ FIPS 203 specifies **implicit rejection**: decapsulating a ciphertext meant
/// for someone else does not fail. It returns a pseudo-random secret derived from
/// this key's own `z` value.
///
/// That is deliberate — an error would hand an attacker a decryption oracle — but
/// it means a successful `mlkem_decapsulate` proves nothing on its own.
/// Authentication has to come from the AEAD that consumes the derived key.
#[test]
fn test_mlkem_wrong_key_yields_wrong_secret_not_an_error() {
    let alice = generate_keypair();
    let mallory = generate_keypair();

    let (ct, sent) = mlkem_encapsulate(&alice.mlkem_public).expect("encapsulate");

    let wrong = mallory
        .mlkem_decapsulate(&ct)
        .expect("implicit rejection means this SUCCEEDS — it does not error");

    assert_ne!(
        sent, wrong,
        "implicit rejection must not return the real secret"
    );
    assert_ne!(wrong, [0u8; MLKEM_SHARED_SECRET_LEN]);
}

/// A tampered ciphertext is likewise accepted and yields a different secret.
#[test]
fn test_mlkem_tampered_ciphertext_yields_wrong_secret() {
    let kp = generate_keypair();
    let (mut ct, sent) = mlkem_encapsulate(&kp.mlkem_public).expect("encapsulate");
    ct[0] ^= 0x01;
    let got = kp
        .mlkem_decapsulate(&ct)
        .expect("implicit rejection: no error");
    assert_ne!(sent, got);
}

// ─── Malformed input ──────────────────────────────────────────────────────────

#[test]
fn test_mlkem_decapsulate_rejects_wrong_length_ciphertext() {
    let kp = generate_keypair();
    for len in [
        0usize,
        1,
        MLKEM768_CIPHERTEXT_LEN - 1,
        MLKEM768_CIPHERTEXT_LEN + 1,
    ] {
        assert!(
            kp.mlkem_decapsulate(&vec![0u8; len]).is_err(),
            "{len}-byte ciphertext must be refused"
        );
    }
}

#[test]
fn test_mlkem_public_key_rejects_wrong_length() {
    for len in [0usize, 31, MLKEM768_PUBLIC_LEN - 1, MLKEM768_PUBLIC_LEN + 1] {
        assert!(
            MlKem768PublicKey::from_bytes(&vec![0u8; len]).is_err(),
            "{len}-byte public key must be refused"
        );
    }
    assert!(MlKem768PublicKey::from_bytes(&vec![0u8; MLKEM768_PUBLIC_LEN]).is_ok());
}

/// An all-zero buffer is the right length but not a valid encapsulation key.
/// It must be refused at encapsulation rather than silently producing a secret
/// nobody can decapsulate.
#[test]
fn test_mlkem_encapsulate_rejects_malformed_public_key() {
    let junk = MlKem768PublicKey::from_bytes(&vec![0xff; MLKEM768_PUBLIC_LEN]).expect("length ok");
    assert!(mlkem_encapsulate(&junk).is_err());
}

// ─── The public key is public ─────────────────────────────────────────────────

/// Two freshly generated users must not share an ML-KEM key. Trivially true, and
/// the test that would have caught a constant seed.
#[test]
fn test_mlkem_public_keys_differ_between_users() {
    let a = generate_keypair();
    let b = generate_keypair();
    assert_ne!(a.mlkem_public, b.mlkem_public);
}

/// Smoke test against catastrophic miswiring: the private X25519 key must not
/// appear inside the published ML-KEM public key.
#[test]
fn test_mlkem_public_key_does_not_contain_private_material() {
    let kp = UserKeypair::from_ed25519_seed_for_test(KAT_SEED);
    let pk = kp.mlkem_public.as_bytes();
    let x_priv = kp.x25519_private_for_test();

    assert!(
        !pk.windows(32).any(|w| w == x_priv),
        "X25519 private key found inside the published ML-KEM public key"
    );
    assert!(
        !pk.windows(32).any(|w| w == KAT_SEED),
        "Ed25519 seed found inside the published ML-KEM public key"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// The hybrid wrap (F1 step 3)
// ═══════════════════════════════════════════════════════════════════════════════

use evnx_crypto::{unwrap_vault_key, wrap_vault_key_for_user, UserPublicKeys, VaultKey};

#[test]
fn test_hybrid_wrap_round_trip() {
    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();

    let wrapped = wrap_vault_key_for_user(&vault_key, &recipient.public_keys()).expect("wrap");
    let unwrapped = unwrap_vault_key(&wrapped, &recipient).expect("unwrap");

    assert_eq!(vault_key.expose(), unwrapped.expose());
    assert_eq!(wrapped.mlkem_ciphertext.len(), MLKEM768_CIPHERTEXT_LEN);
}

/// ⚠️ **The test that proves the wrap is actually hybrid.**
///
/// Corrupting the ML-KEM ciphertext must break the unwrap. If it did not, the
/// post-quantum half would be decorative — present on the wire, absent from the
/// key — and F1 would have shipped a lie.
///
/// Note what makes this work: ML-KEM's implicit rejection means the corrupted
/// ciphertext *decapsulates successfully* to a different secret. Nothing in the
/// KEM reports a problem. The failure surfaces only at the AEAD tag.
#[test]
fn test_hybrid_wrap_breaks_if_mlkem_ciphertext_is_tampered() {
    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();
    let mut wrapped = wrap_vault_key_for_user(&vault_key, &recipient.public_keys()).expect("wrap");

    wrapped.mlkem_ciphertext[0] ^= 0x01;

    assert!(
        unwrap_vault_key(&wrapped, &recipient).is_err(),
        "the ML-KEM half does not contribute to the wrap key — the hybrid is fake"
    );
}

/// The mirror image: the classical half must matter too. A hybrid that silently
/// ignored X25519 would be a pure lattice scheme with extra bytes.
#[test]
fn test_hybrid_wrap_breaks_if_ephemeral_key_is_tampered() {
    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();
    let mut wrapped = wrap_vault_key_for_user(&vault_key, &recipient.public_keys()).expect("wrap");

    wrapped.eph_pub_key[0] ^= 0x01;

    assert!(
        unwrap_vault_key(&wrapped, &recipient).is_err(),
        "the X25519 half does not contribute to the wrap key"
    );
}

/// Truncating the ML-KEM ciphertext must be refused outright rather than
/// producing some shorter-but-workable path.
#[test]
fn test_hybrid_wrap_rejects_truncated_mlkem_ciphertext() {
    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();
    let mut wrapped = wrap_vault_key_for_user(&vault_key, &recipient.public_keys()).expect("wrap");

    wrapped
        .mlkem_ciphertext
        .truncate(MLKEM768_CIPHERTEXT_LEN - 1);
    assert!(unwrap_vault_key(&wrapped, &recipient).is_err());

    wrapped.mlkem_ciphertext.clear();
    assert!(
        unwrap_vault_key(&wrapped, &recipient).is_err(),
        "an empty ML-KEM ciphertext must not degrade to an X25519-only unwrap"
    );
}

#[test]
fn test_hybrid_wrap_is_not_openable_by_the_wrong_recipient() {
    let alice = generate_keypair();
    let mallory = generate_keypair();
    let vault_key = VaultKey::generate();

    let wrapped = wrap_vault_key_for_user(&vault_key, &alice.public_keys()).expect("wrap");
    assert!(unwrap_vault_key(&wrapped, &mallory).is_err());
    assert_eq!(
        unwrap_vault_key(&wrapped, &alice).expect("alice").expose(),
        vault_key.expose()
    );
}

/// Every wrap is freshly randomised on both halves, so the same vault key wrapped
/// twice for the same person shares no bytes.
#[test]
fn test_hybrid_wrap_is_randomised_on_both_halves() {
    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();

    let a = wrap_vault_key_for_user(&vault_key, &recipient.public_keys()).expect("wrap");
    let b = wrap_vault_key_for_user(&vault_key, &recipient.public_keys()).expect("wrap");

    assert_ne!(a.eph_pub_key, b.eph_pub_key);
    assert_ne!(a.mlkem_ciphertext, b.mlkem_ciphertext);
    assert_ne!(a.encrypted_vault_key, b.encrypted_vault_key);

    // Both still open to the same vault key.
    assert_eq!(
        unwrap_vault_key(&a, &recipient).unwrap().expose(),
        unwrap_vault_key(&b, &recipient).unwrap().expose()
    );
}

/// Mixing a key bundle — Alice's X25519 beside Bob's ML-KEM — must produce
/// something neither of them can open. It is the shape of a server that serves
/// one honest key and one substituted one.
#[test]
fn test_hybrid_wrap_to_a_mixed_key_bundle_opens_for_nobody() {
    let alice = generate_keypair();
    let bob = generate_keypair();
    let vault_key = VaultKey::generate();

    let franken = UserPublicKeys {
        x25519: alice.x25519_public.clone(),
        mlkem: bob.mlkem_public.clone(),
    };

    let wrapped = wrap_vault_key_for_user(&vault_key, &franken).expect("wrap");
    assert!(unwrap_vault_key(&wrapped, &alice).is_err());
    assert!(unwrap_vault_key(&wrapped, &bob).is_err());
}

/// ⚠️ **Isolates the ML-KEM secret's contribution** rather than inferring it from
/// a tampering test.
///
/// Corrupting a ciphertext changes the derived secret *and* the transcript at
/// once, so a passing tamper test is also consistent with a combiner that only
/// hashes the transcript. This reproduces the documented combiner exactly, and
/// shows that substituting the ML-KEM secret alone — every other input held
/// identical — yields a different wrap key.
///
/// It also serves as the executable spec of the construction:
/// `HKDF-SHA256(ss_mlkem ‖ ss_x25519 ‖ ct_mlkem ‖ eph_pub ‖ recipient_x25519_pub,
/// "evnx-vault-key-wrap-v2")`.
#[test]
fn test_hybrid_combiner_depends_on_the_mlkem_secret_itself() {
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};

    let recipient = generate_keypair();
    let vault_key = VaultKey::generate();
    let wrapped = wrap_vault_key_for_user(&vault_key, &recipient.public_keys()).expect("wrap");

    let ss_mlkem = recipient
        .mlkem_decapsulate(&wrapped.mlkem_ciphertext)
        .expect("decapsulate");

    // The X25519 half, computed the way the crate does.
    let ss_x25519 = {
        use x25519_dalek::{PublicKey, StaticSecret};
        let mine = StaticSecret::from(recipient.x25519_private_for_test());
        let eph = PublicKey::from(wrapped.eph_pub_key);
        *mine.diffie_hellman(&eph).as_bytes()
    };

    let combine = |ss_m: &[u8; 32]| -> [u8; 32] {
        let mut ikm = Vec::new();
        ikm.extend_from_slice(ss_m);
        ikm.extend_from_slice(&ss_x25519);
        ikm.extend_from_slice(&wrapped.mlkem_ciphertext);
        ikm.extend_from_slice(&wrapped.eph_pub_key);
        ikm.extend_from_slice(&recipient.x25519_public.0);
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(b"evnx-vault-key-wrap-v2", &mut out)
            .expect("expand");
        out
    };

    let open = |key: [u8; 32]| -> bool {
        let nonce = &wrapped.encrypted_vault_key[..24];
        let ct = &wrapped.encrypted_vault_key[24..];
        XChaCha20Poly1305::new_from_slice(&key)
            .expect("key")
            .decrypt(XNonce::from_slice(nonce), ct)
            .is_ok()
    };

    // The real secret reproduces the wrap key — so the construction above IS the
    // one the crate uses, and this test is checking the real thing.
    assert!(
        open(combine(&ss_mlkem)),
        "the documented combiner does not reproduce the wrap key — the doc is wrong"
    );

    // Change ONLY the ML-KEM secret. Transcript, X25519 secret, info string all
    // identical. If the wrap key survived that, the PQ half would be inert.
    let mut wrong = ss_mlkem;
    wrong[0] ^= 0x01;
    assert!(
        !open(combine(&wrong)),
        "the wrap key does not depend on the ML-KEM shared secret"
    );
}
