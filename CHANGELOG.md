# Changelog

All notable changes to evnx-crypto are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-09-13

First published release. Zero-knowledge encryption primitives for evnx cloud sync:
Argon2id key derivation, AES-256-GCM vault encryption, XChaCha20-Poly1305 key
wrapping, X25519 ECDH sharing, Ed25519 keypairs and an SRP-6a client.

### Security

Findings from the pre-publication review, all fixed here. None had shipped — the
crate had not been released — but each would have been exploitable in the deployed
system.

- **Non-contributory ECDH is now rejected.** `wrap_vault_key_for_user` and
  `unwrap_vault_key` verify the X25519 shared secret is contributory. Without this,
  a malicious server could supply a low-order `eph_pub_key`, forcing an all-zero
  shared secret **independent of the victim's private key** — then hand over a vault
  key it chose. The victim would encrypt their `.env` under a key the attacker
  already knew. A working exploit is preserved as a regression test.
- **Vault blobs are bound to their identity.** `encrypt_vault` and `decrypt_vault`
  take AEAD associated data; [`vault_aad`] builds the canonical form. Previously a
  ciphertext was not tied to its vault or version, so an untrusted server could
  replay an old version as the current one and silently restore revoked secrets.
- **The two password derivations are domain-separated.** `derive_master_key` and
  `derive_srp_password` pass distinct tags as Argon2's secret parameter. They
  previously differed only by salt, so a caller who reused one salt would have made
  the SRP password input byte-identical to the master key.
- **No key is used raw as a cipher key.** `wrap_vault_key_with_master_key` used the
  master key directly while the private-key path used an HKDF subkey. All symmetric
  keys now come from `hkdf_subkey` with a per-purpose domain tag.

### Added

- `vault_aad(vault_id, version)` — canonical, unambiguous associated data.
- `CryptoError::InvalidPublicKey` for the contributory-ECDH failure, so callers can
  distinguish an attack from a malformed input.
- `MasterKey::expose`, `VaultKey::expose`, `SecretArray::expose` / `expose_mut` /
  `into_inner`.
- Redacting `Debug` for `MasterKey` and `VaultKey`, asserted by test.
- `tests/attacks.rs` — 11 adversarial tests: all seven low-order points in both
  directions, ephemeral/ciphertext splicing, GCM tag stripping, version rollback,
  cross-vault replay, non-recipient unwrap, tampered SRP server proof, and Debug
  leakage.

### Changed

- **Breaking:** `encrypt_vault` and `decrypt_vault` take an `aad` argument.
- **Breaking:** `MasterKey`, `VaultKey` and `SecretArray` no longer expose their
  inner field; use `expose()`. A key can no longer be built from arbitrary bytes
  outside the crate, or mutated in place.
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]` at the crate root.
- The `test-utils` feature now does something: it gates `from_bytes_for_test`
  constructors. It previously existed but had no effect.
- `hex` moved from dev-dependencies to dependencies (`src/srp.rs` uses it).

### Removed

- `zeroize::read_raw_memory` — an unused `unsafe` helper. Its removal lets the
  crate forbid unsafe code outright.
- `criterion` dev-dependency; both `[[bench]]` targets had been commented out.

### Documentation

- Crate-level threat model: what the untrusted server can do, and what is out of
  scope.
- Key-hierarchy diagram and a rationale table for every algorithm choice.
- `encrypt_vault` documents the 96-bit random-nonce budget (NIST SP 800-38D).
