# Changelog

All notable changes to evnx-crypto are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-09-18

**Shared vaults are now post-quantum safe.** The vault-key wrap is hybrid
X25519 + ML-KEM-768 (FIPS 203). This is a breaking change to both the API and the
wire format, and it lands deliberately **before** `evnx vault share` ships — a key
wrapped under X25519 alone stays wrapped that way for as long as the row exists,
so there was no version of this that could be safely retrofitted.

### Breaking

- **`wrap_vault_key_for_user`** takes `&UserPublicKeys` (both the X25519 and
  ML-KEM public keys) instead of `&X25519PublicKeyBytes`. Bundling them is not
  sugar: it stops a caller supplying a stale ML-KEM key beside a fresh X25519
  one, and stops the post-quantum half being silently skipped.
- **`unwrap_vault_key`** takes `&UserKeypair` instead of raw X25519 private key
  bytes. Both halves are needed, and handing out private key material so it could
  be passed straight back in was never a shape worth keeping.
- **`UserKeypair::x25519_private_bytes()` removed.** It existed only to serve the
  old `unwrap` signature; a public accessor returning a raw private key is pure
  attack surface once nothing needs it.
- **`WrappedVaultKey` gains `mlkem_ciphertext: Vec<u8>`** — 1088 bytes. Not
  optional. There is no code path that degrades to X25519 alone.
- **`WrappedVaultKey::from_base64` takes three arguments**, the third being the
  ML-KEM ciphertext. Rejects anything that is not exactly 1088 bytes at parse
  time rather than at unwrap.
- **HKDF info string `evnx-vault-key-wrap-v1` → `v2`.** Reusing v1 would let a
  v1 and a v2 wrap derive the same key from the same ECDH secret, so stripping
  the ML-KEM ciphertext and presenting the blob as v1 would produce a *working*
  key instead of a failure. The version is what makes the hybrid non-optional.

### Added

- **ML-KEM-768 keypair, derived from the existing Ed25519 seed** via HKDF under
  `evnx/mlkem768/v1`. `users.encrypted_private_key` is unchanged — still a sealed
  32-byte seed — so there is no new column for private material, no migration of
  sealed data, and no existing user is ever asked to re-enter their master
  password. Derived eagerly, so a `UserKeypair` is always complete.
- `MlKem768PublicKey`, `UserPublicKeys`, `mlkem_encapsulate`,
  `UserKeypair::mlkem_decapsulate`, `UserKeypair::public_keys`,
  `UserKeypair::mlkem_public_base64`.
- `MLKEM768_PUBLIC_LEN` (1184), `MLKEM768_CIPHERTEXT_LEN` (1088),
  `MLKEM_SHARED_SECRET_LEN` (32).
- wasm bindings: `wrapVaultKeyForUser`, `KeypairHandle.unwrapSharedVaultKey`,
  `KeypairHandle.mlkemPublicKey`, and a `WrappedKeyBundle` carrying the three
  base64 fields.

### Security

- **The combiner binds the transcript, not just the two secrets.** The HKDF input
  is `ss_mlkem ‖ ss_x25519 ‖ ct_mlkem ‖ eph_pub ‖ recipient_x25519_pub`. A shared
  secret does not bind the message that produced it, and X25519 is not
  ciphertext-collision-resistant — without the transcript an attacker able to
  substitute one half could steer two different wraps onto one key. Same shape as
  X-Wing and the TLS hybrid drafts.
- **ml-kem's `zeroize` feature is enabled explicitly.** It is not default, and
  without it `DecapsulationKey` has no `Drop` impl at all — ~2.4 KB of expanded
  private key would be left in freed memory. Two guards now fail the build if it
  is ever removed, and both were verified to fire.
- **A known-answer test pins the ML-KEM derivation.** The key is derived, never
  stored, so a changed derivation is not a bug that surfaces — it is every
  already-shared vault becoming permanently unopenable. The KAT was verified
  non-vacuous: changing the info string makes it the *only* failing test, while
  the full round trip still passes.
- **FIPS 203 implicit rejection is asserted, not assumed.** Decapsulating a
  ciphertext meant for someone else *succeeds*, returning a pseudo-random secret.
  Callers must never read a successful decapsulation as authentication — that
  comes from the AEAD consuming the derived key.

### Size

Browser bundle 285,655 → 308,265 bytes raw; 126,150 → 134,549 gzipped
(+8,399 bytes, +6.66 %).

---

## [0.1.2] - 2026-09-17

Not previously recorded here. Added `blob_hash` — BLAKE3 over the ciphertext,
defined once in this crate and exported to wasm, replacing three copies that had
been maintained separately in the CLI and the server.

---

## [0.1.1] - 2026-09-16

Not previously recorded here. Added the optional `wasm` feature: browser bindings
for the KDF, vault encryption, SRP-6a and keypair handling, published to npm as
`@evnx/crypto-wasm`. Private key material stays inside wasm behind opaque
handles; nothing reaches JavaScript.

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
- `tests/readme_flows.rs` — the README's Quick Start flows as compiled, executed
  code. Writing it immediately caught a README example calling `compute_verifier`
  with two arguments instead of three. Documentation that cannot drift silently.
- `docs/security-model.md` — threat model, what a server breach actually yields,
  an attack-by-attack walkthrough, post-quantum posture, and a limitations section.
- `SECURITY.md` — private reporting process and scope.

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
- `docs/kdf.md` and `docs/vault.md`. Both predated this release: roughly half their
  code no longer compiled against the encapsulated key types and the AAD API, and
  nothing linked to either. `docs/vault.md` was worse than stale — it documented
  `POST /vault/encrypt` and `POST /vault/decrypt` server handlers, i.e. a server
  that decrypts vaults, which is the opposite of this library's entire premise.
  Shipping it would have taught readers to build the insecure thing. The accurate
  material now lives in one place each: README for usage, rustdoc for the API,
  `docs/security-model.md` for the threat model. Both files remain in git history.

### Documentation

- Crate-level threat model: what the untrusted server can do, and what is out of
  scope.
- Key-hierarchy diagram and a rationale table for every algorithm choice.
- `encrypt_vault` documents the 96-bit random-nonce budget (NIST SP 800-38D).
