# evnx-crypto

> Zero-knowledge encryption primitives for [evnx](https://github.com/urwithajit9/evnx) cloud sync.

[![Crates.io](https://img.shields.io/crates/v/evnx-crypto)](https://crates.io/crates/evnx-crypto)
[![CI](https://github.com/urwithajit9/evnx-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/urwithajit9/evnx-crypto/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

A pure-Rust cryptographic library implementing the ZKE (Zero-Knowledge Encryption) protocol for evnx. The server **never** sees your password, master key, or plaintext `.env` contents — all sensitive operations run locally in this library.

---

## Capabilities

| Area | What you get |
|------|--------------|
| **Password derivation** | Argon2id at OWASP 2024 parameters — 64 MiB, t=3, p=4. Two domain-separated outputs: a master key that never leaves the device, and an SRP input that proves identity without revealing the password. |
| **Vault encryption** | AES-256-GCM, fresh random nonce per message, and AEAD associated data binding each blob to its vault and version — so an untrusted server cannot replay an old version as the current one. |
| **Key wrapping** | XChaCha20-Poly1305 with 192-bit nonces, so random nonces never collide in practice. Every key is an HKDF-SHA256 subkey with its own domain tag; no key is ever the live cipher key for two purposes. |
| **Team sharing** | X25519 ECDH to a recipient's public key, with a **contributory-behaviour check** that rejects low-order points — the defence against a server substituting a vault key it knows. |
| **Authentication** | SRP-6a (2048-bit group, SHA-256). The password is never transmitted, and the client verifies the server's proof, so a rogue TLS certificate is not enough to impersonate the server. |
| **One secret, two keypairs** | The X25519 key is HKDF-derived from the Ed25519 seed, so a single encrypted blob restores both on a new machine. |
| **Memory hygiene** | Key material is `ZeroizeOnDrop`. Key types keep their bytes private, cannot be built from arbitrary input outside the crate, and redact themselves in `Debug` output. |
| **No unsafe** | `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]` at the crate root. |

### Design properties worth knowing

- **The server is treated as hostile**, not merely curious. Every value arriving
  from the network is attacker-controlled, and the library is written to stay safe
  when it is.
- **Errors do not leak.** `Decryption` does not distinguish a wrong key from
  tampered ciphertext from mismatched associated data — telling them apart would
  offer a decryption oracle.
- **118 tests**, including [`tests/attacks.rs`](tests/attacks.rs): every low-order
  Curve25519 point in both directions, ephemeral/ciphertext splicing, GCM tag
  stripping, version rollback, cross-vault replay, non-recipient unwrap, tampered
  SRP server proof, KDF collision under a reused salt, and `Debug` leakage. Each is
  written against a stated threat, and several began life as working exploits.

### Limits, stated plainly

- **A weak password defeats all of it.** Argon2id raises the cost of a guess; it
  does not make a bad password good.
- **Variable *names* are stored in the clear** by evnx-server; values are encrypted.
- **Shared vaults are not post-quantum safe** — the X25519 wrapping is vulnerable to
  harvest-now-decrypt-later. Solo vaults are safe.
- **Not externally audited.** Carefully reviewed, not certified.

See **[docs/security-model.md](docs/security-model.md)** for the full threat model,
what a server breach actually yields, and the post-quantum analysis.

---

## What This Library Does

```
User Password
    │
    ├─[Argon2id + argon2_salt]──→  Master Key (local only, never transmitted)
    │                                   └──→  encrypt Ed25519 private key
    │                                   └──→  wrap VaultKey (solo vaults)
    │
    └─[Argon2id + srp_salt]────→  SRP Password Input
                                       └──→  SRP Verifier (sent to server)
                                       └──→  SRP Login Proof (sent to server)

Server stores:   argon2_salt, srp_salt, SRP verifier, encrypted private key
Server NEVER sees: password, master key, VaultKey, .env plaintext
```

---

## Modules

| Module | Purpose | Status |
|--------|---------|--------|
| [`kdf`](#kdf) | Argon2id key derivation — master key + SRP password | ✅ v0.1.0 |
| [`vault`](#vault) | AES-256-GCM vault encryption + XChaCha20 key wrapping | ✅ v0.1.0 |
| [`keypair`](#keypair) | Ed25519 + X25519 keypairs, private key encryption, ECDH vault sharing | ✅ v0.1.0 |
| [`srp`](#srp) | SRP-6a client — verifier, ephemeral, proof, verification | ✅ v0.1.0 |
| [`zeroize`](#zeroize) | Secure memory types for heap-allocated secrets | ✅ v0.1.0 |
| [`encoding`](#encoding) | base64 / hex wire formats the server validates | ✅ v0.1.0 |
| [`errors`](#errors) | `CryptoError` — all failure variants | ✅ v0.1.0 |

---

## Installation

```toml
[dependencies]
evnx-crypto = "0.1"
```

Requires Rust 1.85 or later.

Developing against a local checkout alongside evnx-server or the evnx CLI — the
`version` is what makes `cargo publish` work for the dependent, the `path` is what
makes local iteration fast:

```toml
[dependencies]
evnx-crypto = { version = "0.1", path = "../evnx-crypto" }
```

Running this crate's own test suite needs the `test-utils` feature, which exposes
constructors that bypass the KDF:

```bash
cargo test --all-features
```

---

## Quick Start

> Every flow below is compiled and executed by
> [`tests/readme_flows.rs`](tests/readme_flows.rs). If an API changes, that test
> breaks and this section gets fixed — these are not untested snippets.

### Registration (client-side)

```rust
use evnx_crypto::{
    kdf::{generate_salt, derive_master_key, derive_srp_password},
    keypair::{generate_keypair, encrypt_private_key},
    srp::compute_verifier,
};

// 1. Generate two independent salts — NEVER share or reuse
let argon2_salt = generate_salt();  // for master key derivation
let srp_salt    = generate_salt();  // for SRP authentication

// 2. Derive master key — LOCAL ONLY, never transmitted
let master_key = derive_master_key(password.as_bytes(), &argon2_salt)?;

// 3. Generate asymmetric keypair
let keypair = generate_keypair();

// 4. Encrypt private key with master key (safe to store on server)
let enc_private_key = encrypt_private_key(&keypair, &master_key)?;

// 5. Derive SRP verifier (password-equivalent stored on server)
let srp_password = derive_srp_password(password.as_bytes(), &srp_salt)?;
// The email is bound into the verifier — the same password under a different
// address produces a different one.
let verifier     = compute_verifier(&email, srp_password, srp_salt)?;

// 6. Send to server (master_key and private key NEVER leave the client):
//    { email, verifier, srp_salt, argon2_salt,
//      keypair.ed25519_public, keypair.x25519_public, enc_private_key }
```

### Login (client-side)

```rust
use evnx_crypto::{
    kdf::{derive_master_key, derive_srp_password},
    keypair::decrypt_private_key,
    srp::{generate_client_ephemeral, compute_client_proof, verify_server_proof},
};

// After server returns { argon2_salt, srp_salt, enc_private_key }:

// 1. Re-derive master key and decrypt private key
let master_key = derive_master_key(password.as_bytes(), &argon2_salt)?;
let keypair    = decrypt_private_key(&enc_private_key, &master_key)?;

// 2. SRP Step 1 — generate ephemeral, send A to server
let eph = generate_client_ephemeral()?;
// POST /auth/srp/init { email, client_public: eph.public_a }
// server responds with { server_public: B, srp_salt, session_id }

// 3. SRP Step 2 — compute proof, send M1 to server
let srp_password = derive_srp_password(password.as_bytes(), &srp_salt)?;
let proof = compute_client_proof(&email, srp_password, &srp_salt, &server_b, &eph)?;
// POST /auth/srp/verify { session_id, client_proof: proof.client_proof }
// server responds with { server_proof: M2 }

// 4. SRP Step 3 — verify M2 (mutual authentication)
verify_server_proof(&server_m2, &proof)?;
// If Ok(()), the server is legitimate. Proceed with session.
```

### Push (encrypt .env)

```rust
use evnx_crypto::{
    vault::{encrypt_vault},
    keypair::unwrap_vault_key,
};

// After fetching { encrypted_vault_key, eph_pub_key } from server:
let vault_key = unwrap_vault_key(&wrapped, keypair.x25519_private_bytes())?;
// Bind the blob to its vault and version so an old one cannot be replayed.
let aad       = vault_aad(vault_id, base_version + 1);
let blob      = encrypt_vault(env_file_bytes, &vault_key, &aad)?;

// Send { nonce: blob.nonce, ciphertext: blob.ciphertext } to server for S3 upload
```

### Pull (decrypt .env)

```rust
use evnx_crypto::{
    vault::decrypt_vault,
    keypair::unwrap_vault_key,
};

// After fetching { nonce, ciphertext } from server:
let vault_key = unwrap_vault_key(&wrapped, keypair.x25519_private_bytes())?;
let aad       = vault_aad(vault_id, version_num);    // same values used to encrypt
let plaintext = decrypt_vault(&blob, &vault_key, &aad)?;
// Write plaintext to .env
```

### Share vault with a collaborator

```rust
use evnx_crypto::keypair::{unwrap_vault_key, wrap_vault_key_for_user};

// After fetching collaborator's x25519_public from server:
let my_vault_key     = unwrap_vault_key(&my_wrapped, keypair.x25519_private_bytes())?;
let wrapped_for_them = wrap_vault_key_for_user(&my_vault_key, &collab_x25519_pub)?;
// POST /vaults/{id}/members { encrypted_vault_key, eph_pub_key }
```

---

## Module Reference

### `kdf` {#kdf}

Argon2id-based key derivation. All derivations happen client-side.

```rust
// Generate a random 32-byte salt (call separately for argon2 and SRP salts)
pub fn generate_salt() -> [u8; 32];

// Derive 256-bit master key from password + salt
// Returns MasterKey (ZeroizeOnDrop)
pub fn derive_master_key(password: &[u8], salt: &[u8; 32]) -> Result<MasterKey, CryptoError>;

// Derive SRP password input (different Argon2id call, different salt)
// Returns Zeroizing<Vec<u8>>
pub fn derive_srp_password(password: &[u8], srp_salt: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
```

**Parameters (OWASP 2024 defaults):** m=64MB, t=3 iterations, p=4 lanes. Tune in `src/kdf.rs` for your hardware. Target: 300–500ms.

---

### `vault` {#vault}

AES-256-GCM for .env encryption. XChaCha20-Poly1305 for key wrapping.

```rust
// Generate a fresh random 256-bit vault key
pub fn VaultKey::generate() -> VaultKey;

// Encrypt plaintext → EncryptedBlob { nonce, ciphertext }
// Fresh random nonce per call. GCM auth tag embedded in ciphertext.
pub fn encrypt_vault(plaintext: &[u8], key: &VaultKey, aad: &[u8]) -> Result<EncryptedBlob, CryptoError>;

// Decrypt EncryptedBlob → plaintext
// Returns Err(Decryption) on wrong key or tampered ciphertext. Never panics.
pub fn decrypt_vault(blob: &EncryptedBlob, key: &VaultKey, aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

// Wrap VaultKey with user's MasterKey (solo vaults / backup)
pub fn wrap_vault_key_with_master_key(vk: &VaultKey, mk: &MasterKey) -> Result<Vec<u8>, CryptoError>;
pub fn unwrap_vault_key_with_master_key(wrapped: &[u8], mk: &MasterKey) -> Result<VaultKey, CryptoError>;
```

---

### `keypair` {#keypair}

Ed25519 (signing) + X25519 (key agreement) keypair management.

```rust
// Generate a fresh Ed25519 + X25519 keypair
// X25519 private key is deterministically derived from Ed25519 seed via HKDF.
// One EncryptedPrivateKey covers both.
pub fn generate_keypair() -> UserKeypair;

// Encrypt Ed25519 seed with MasterKey (XChaCha20-Poly1305)
pub fn encrypt_private_key(keypair: &UserKeypair, mk: &MasterKey) -> Result<EncryptedPrivateKey, CryptoError>;

// Decrypt and reconstruct full keypair from EncryptedPrivateKey
pub fn decrypt_private_key(enc: &EncryptedPrivateKey, mk: &MasterKey) -> Result<UserKeypair, CryptoError>;

// ECDH wrap: encrypt VaultKey for a specific recipient
// Uses ephemeral X25519 + HKDF-SHA256 + XChaCha20-Poly1305
// Ephemeral private key is zeroized immediately after ECDH.
pub fn wrap_vault_key_for_user(vk: &VaultKey, recipient_pub: &X25519PublicKeyBytes) -> Result<WrappedVaultKey, CryptoError>;

// ECDH unwrap: decrypt VaultKey using your X25519 private key
pub fn unwrap_vault_key(wrapped: &WrappedVaultKey, my_x25519_private: &[u8; 32]) -> Result<VaultKey, CryptoError>;
```

---

### `srp` {#srp}

SRP-6a client — RFC 5054 with 2048-bit group and SHA-256.

```rust
// Registration: compute SRP verifier from Argon2id-derived SRP password
// srp_password_bytes = output of derive_srp_password(), NOT raw password
pub fn compute_verifier(srp_password: Zeroizing<Vec<u8>>, srp_salt: [u8; 32]) -> Result<SrpVerifier, CryptoError>;

// Login Step 1: generate ephemeral A (send public_a to server)
pub fn generate_client_ephemeral() -> Result<SrpClientEphemeral, CryptoError>;

// Login Step 2: compute client proof M1 (send client_proof to server)
// Keep session_key to verify M2 in Step 3.
pub fn compute_client_proof(
    email: &str,
    srp_password: Zeroizing<Vec<u8>>,
    srp_salt: &[u8],
    server_public_b: &[u8],
    ephemeral: &SrpClientEphemeral,
) -> Result<SrpClientProof, CryptoError>;

// Login Step 3: verify server proof M2 (mutual authentication)
// Returns Err if server cannot prove it knows the verifier.
pub fn verify_server_proof(server_m2: &[u8], proof: &SrpClientProof) -> Result<(), CryptoError>;
```

---

### `zeroize` {#zeroize}

Secure memory wrappers for heap-allocated secrets.

```rust
// Variable-length heap secret
pub struct SecretBytes(Zeroizing<Vec<u8>>);

// Password input before conversion to bytes
pub struct SecretString(Zeroizing<String>);

// Fixed-size stack secret with ZeroizeOnDrop
pub struct SecretArray<const N: usize>([u8; N]);

// Explicit zeroize of a mutable byte slice
pub fn zeroize_slice(buf: &mut [u8]);
```

All types implement `Debug` and `Display` as `[REDACTED]` — safe to log.

---

### `errors` {#errors}

```rust
pub enum CryptoError {
    Kdf(String),           // Argon2 derivation failure
    Encryption,            // AES-GCM encrypt failed
    Decryption,            // AES-GCM decrypt failed (wrong key or tampered)
    KeyWrap,               // XChaCha20 wrap failed
    KeyUnwrap,             // XChaCha20 unwrap failed (wrong key or tampered)
    InvalidInput(String),  // Malformed input (e.g., slice too short)
    Srp(String),           // SRP protocol error
}
```

All library functions return `Result<T, CryptoError>`. No panics in library code.

---

## Security Properties

| Guarantee | How |
|-----------|-----|
| Password never transmitted | All derivation happens client-side before any network call |
| Master key never stored | Derived fresh from password each session, ZeroizeOnDrop |
| SRP verifier compromise ≠ vault access | Separate salts **and** distinct Argon2 domain tags, so the two derivations differ even if a caller reuses one salt |
| AES-GCM nonce never reused | Fresh OsRng nonce per `encrypt_vault()` call; 96-bit random, budget 2³² messages per key |
| Blob bound to its identity | AEAD associated data via `vault_aad(vault_id, version)` blocks version rollback |
| ECDH key substitution blocked | Non-contributory (low-order) public keys rejected |
| Tampering detected | AES-GCM and XChaCha20-Poly1305 auth tags; `Err(Decryption)` on failure |
| ECDH ephemeral key erasure | `EphemeralSecret` (x25519-dalek) zeroizes on drop automatically |
| Key material erased from heap | `ZeroizeOnDrop` on `MasterKey`, `VaultKey`, `UserKeypair`, proof types |
| No key reuse across domains | HKDF subkey with a distinct `info` tag per purpose; no key is ever the live cipher key for two things |
| Confidentiality | AES-256-GCM and XChaCha20-Poly1305 (IND-CCA2) |
| Key isolation | `MasterKey` and `VaultKey` are distinct types with private bytes; compromise of one is not compromise of the other |
| Keys cannot be forged | `MasterKey` and `VaultKey` can only come from a KDF, generation, or an authenticated unwrap — never from arbitrary bytes |
| Keys cannot leak via logs | Redacting `Debug` on `MasterKey` and `VaultKey`, asserted by test |

---

## Running Tests

```bash
# All tests
cargo test

# Specific module
cargo test --test kdf
cargo test --test vault
cargo test --test keypair
cargo test --test srp
cargo test --test zeroize
cargo test --test integration

# Verbose output (see timing, println! output)
cargo test --test integration -- --nocapture

# More proptest iterations (slow but thorough)
PROPTEST_CASES=1000 cargo test

# KDF timing benchmark
cargo test --test kdf benchmark_derive_master_key -- --ignored --nocapture

# Security audit
cargo audit

# Lint
cargo clippy -- -D warnings
```

---

## Cryptographic Choices

| Decision | Choice | Rationale |
|----------|--------|-----------|
| KDF | Argon2id | PHC winner; memory-hard; `id` variant resists both side-channel and GPU attacks |
| Vault encryption | AES-256-GCM | FIPS 140-2; hardware acceleration on x86/ARM; AEAD |
| Key wrapping | XChaCha20-Poly1305 | 192-bit nonce safe for random generation at scale; no hardware requirement |
| Asymmetric signing | Ed25519 | Fast, small keys/sigs, constant-time, no parameter choices to get wrong |
| Key agreement | X25519 | RFC 7748; constant-time; pairs naturally with Ed25519 (same curve family) |
| KDF for ECDH | HKDF-SHA256 | Standard; domain-separated via `info` parameter |
| SRP group | RFC 5054 G_2048 | 2048-bit DH group; balance of security and performance |
| SRP hash | SHA-256 | Collision-resistant; standard |

---

## What This Library Does NOT Do

- **Network I/O** — No HTTP, no TLS, no socket operations
- **File I/O** — Does not read or write `.env` files
- **Server-side SRP** — Only the client side; `evnx-server` implements the server
- **Key storage** — Does not manage OS keychains or config files
- **Token generation** — JWT and API token logic lives in `evnx-server`

---

## Using This Library Safely

```rust
// ❌ NEVER reuse a nonce with the same key      — encrypt_vault generates one per call
// ❌ NEVER store a VaultKey or MasterKey unwrapped
// ❌ NEVER log ciphertext, keys, passwords, or raw IPs
// ❌ NEVER pass the same salt to derive_master_key and derive_srp_password
// ❌ NEVER pass an empty `aad` when the blob has an identity to bind to

// ✅ ALWAYS generate a fresh VaultKey per vault
// ✅ ALWAYS wrap a VaultKey before it leaves the device
// ✅ ALWAYS pass vault_aad(vault_id, version) to encrypt_vault and decrypt_vault
// ✅ ALWAYS call verify_server_proof — skipping it makes SRP one-way
// ✅ ALWAYS treat Err(Decryption) as hostile, not as a retry
```

Several of these are enforced rather than merely advised: salts are domain-separated
so reuse is not catastrophic, low-order ECDH keys are rejected, and key types cannot
be constructed from arbitrary bytes. The ones that remain your responsibility are
the `aad` argument and the `verify_server_proof` call.

---

## License

Licensed under the [MIT License](LICENSE), the same terms as the evnx CLI.

---

## Related Repositories

| Repo | Role |
|------|------|
| [`evnx`](https://github.com/urwithajit9/evnx) | CLI — consumes this library for local crypto |
| [`evnx-server`](https://github.com/urwithajit9/evnx-server) | Backend — consumes this library for KDF params and error types |
