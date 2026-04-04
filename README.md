# evnx-crypto

> Zero-knowledge encryption primitives for [evnx](https://github.com/urwithajit9/evnx) cloud sync.

[![Crates.io](https://img.shields.io/crates/v/evnx-crypto)](https://crates.io/crates/evnx-crypto)
[![CI](https://github.com/urwithajit9/evnx-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/urwithajit9/evnx-crypto/actions)
[![Security Audit](https://github.com/urwithajit9/evnx-crypto/actions/workflows/audit.yml/badge.svg)](https://github.com/urwithajit9/evnx-crypto/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE)

A pure-Rust cryptographic library implementing the ZKE (Zero-Knowledge Encryption) protocol for evnx. The server **never** sees your password, master key, or plaintext `.env` contents — all sensitive operations run locally in this library.

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
| [`errors`](#errors) | `CryptoError` — all failure variants | ✅ v0.1.0 |

---

## Installation

This crate is an internal library for the evnx project. Add as a Git dependency:

```toml
[dependencies]
evnx-crypto = { git = "https://github.com/urwithajit9/evnx-crypto", tag = "v0.1.0" }
```

For local development alongside evnx-server or evnx CLI:

```toml
[dependencies]
evnx-crypto = { path = "../evnx-crypto" }
```

---

## Quick Start

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
let verifier     = compute_verifier(srp_password, srp_salt)?;

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
let blob      = encrypt_vault(env_file_bytes, &vault_key)?;

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
let plaintext = decrypt_vault(&blob, &vault_key)?;
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
pub fn encrypt_vault(plaintext: &[u8], key: &VaultKey) -> Result<EncryptedBlob, CryptoError>;

// Decrypt EncryptedBlob → plaintext
// Returns Err(Decryption) on wrong key or tampered ciphertext. Never panics.
pub fn decrypt_vault(blob: &EncryptedBlob, key: &VaultKey) -> Result<Vec<u8>, CryptoError>;

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
| SRP verifier compromise ≠ vault access | argon2_salt and srp_salt are independent; different Argon2id calls |
| AES-GCM nonce never reused | Fresh OsRng nonce per `encrypt_vault()` call |
| Tampering detected | AES-GCM and XChaCha20-Poly1305 auth tags; `Err(Decryption)` on failure |
| ECDH ephemeral key erasure | `EphemeralSecret` (x25519-dalek) zeroizes on drop automatically |
| Key material erased from heap | `ZeroizeOnDrop` on `MasterKey`, `VaultKey`, `UserKeypair`, proof types |
| No key reuse across domains | HKDF with distinct `info` strings per operation |

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

## License

Licensed under MIT OR Apache-2.0 at your option.

---

## Related Repositories

| Repo | Role |
|------|------|
| [`evnx`](https://github.com/urwithajit9/evnx) | CLI — consumes this library for local crypto |
| [`evnx-server`](https://github.com/urwithajit9/evnx-server) | Backend — consumes this library for KDF params and error types |

## 🔐 Key Derivation Function (KDF)

The KDF module provides secure, Argon2id-based key derivation for password-to-key transformation, implementing industry best practices for zero-knowledge encryption.

### Overview

Our KDF implementation uses **Argon2id** (winner of the Password Hashing Competition) with parameters aligned to **OWASP 2024 recommendations**. It serves two critical, isolated purposes:

1. **Master Key Derivation**: Derives a 32-byte encryption key for protecting Ed25519 private keys
2. **SRP Password Derivation**: Generates a separate input for Secure Remote Password (SRP) authentication

### 🔑 Security Architecture

```mermaid
graph TB
    subgraph Client["🔒 Client-Side (Never Transmitted)"]
        P[User Password]
        AS[Argon2 Salt<br/>32 bytes]
        SS[SRP Salt<br/>32 bytes]
        
        subgraph KDF["Key Derivation Functions"]
            MDK[derive_master_key<br/>Argon2id]
            DSP[derive_srp_password<br/>Argon2id]
        end
        
        MK[Master Key<br/>32 bytes]
        SP[SRP Password<br/>32 bytes]
        
        subgraph Crypto["Cryptographic Operations"]
            ENC[Encrypt Ed25519<br/>Private Key]
            SRP[Generate SRP<br/>Verifier/Proof]
        end
    end
    
    subgraph Server["🖥️ Server Storage"]
        AS_STORE[Argon2 Salt<br/>Stored]
        SS_STORE[SRP Salt<br/>Stored]
        V[SRP Verifier<br/>Stored]
        ENC_KEY[Encrypted<br/>Ed25519 Key]
    end
    
    P --> MDK
    P --> DSP
    AS --> MDK
    SS --> DSP
    
    MDK --> MK
    DSP --> SP
    
    MK --> ENC
    SP --> SRP
    
    AS -.-> AS_STORE
    SS -.-> SS_STORE
    
    ENC --> ENC_KEY
    SRP --> V
    
    ENC_KEY -.-> Server
    V -.-> Server
    AS_STORE -.-> Client
    SS_STORE -.-> Client
    
    style MK fill:#f96,stroke:#333,stroke-width:3px
    style SP fill:#f96,stroke:#333,stroke-width:2px
    style P fill:#bbf,stroke:#333,stroke-width:2px
    style KDF fill:#ffebcd,stroke:#333,stroke-width:2px
```

### 🔒 Security Guarantees

| Feature | Implementation | Benefit |
|---------|----------------|---------|
| **Algorithm** | Argon2id v0x13 | Memory-hard, resistant to GPU/ASIC attacks |
| **Memory Cost** | 64 MB (configurable) | Prevents parallel brute-force attacks |
| **Time Cost** | 3 iterations | Increases computational cost per guess |
| **Parallelism** | 4 lanes | Optimized for modern CPUs |
| **Output Length** | 32 bytes (256 bits) | Sufficient for symmetric encryption |
| **Salt Uniqueness** | 32-byte random per user | Prevents rainbow table attacks |
| **Key Separation** | Independent salts for master/SRP | Compartmentalization of secrets |
| **Zeroization** | Automatic memory clearing | Prevents key material leakage |

### 🛡️ Threat Model Protection

```mermaid
graph LR
    subgraph Threats["🎯 Attack Vectors"]
        T1[Dictionary Attack]
        T2[Rainbow Tables]
        T3[GPU/ASIC Cracking]
        T4[Side-Channel]
        T5[Memory Dump]
        T6[Verifier Compromise]
    end
    
    subgraph Defenses["🛡️ Mitigations"]
        D1[High iteration count<br/>3 rounds]
        D2[Unique random salts<br/>32 bytes each]
        D3[Memory-hard function<br/>64 MB RAM]
        D4[Constant-time ops<br/>Argon2 library]
        D5[ZeroizeOnDrop<br/>Secure memory]
        D6[Separate derivation<br/>paths]
    end
    
    T1 --> D1
    T2 --> D2
    T3 --> D3
    T4 --> D4
    T5 --> D5
    T6 --> D6
    
    style Defenses fill:#d4edda,stroke:#28a745,stroke-width:2px
    style Threats fill:#f8d7da,stroke:#dc3545,stroke-width:2px
```

### 📊 Performance Characteristics

**Target Hardware:** Modern server (Intel Xeon / AMD EPYC)  
**Target Derivation Time:** 300–500ms

| Parameter | Value | Impact |
|-----------|-------|--------|
| Memory (m_cost) | 64 MB | RAM requirement per derivation |
| Iterations (t_cost) | 3 | CPU time multiplier |
| Parallelism (p_cost) | 4 | Thread utilization |
| **Actual Time** (Mac Mini M1) | ~1175ms | ⚠️ May need tuning |

> **⚠️ Tuning Required:** Benchmark on your target deployment hardware and adjust `ARGON2_*_COST` constants in `src/kdf.rs`.

### 🔄 Key Derivation Flow

#### Registration Flow

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client App
    participant S as Server
    
    U->>C: Enter password
    C->>C: Generate argon2_salt (random)
    C->>C: Generate srp_salt (random)
    
    C->>C: derive_master_key(password, argon2_salt)
    C->>C: Generate Ed25519 keypair
    C->>C: Encrypt private key with master_key
    
    C->>C: derive_srp_password(password, srp_salt)
    C->>C: Generate SRP verifier
    
    C->>S: Register(argon2_salt, srp_salt, verifier, encrypted_key)
    S->>S: Store salts + verifier
    S-->>C: Registration successful
    
    Note over C: Password & master_key<br/>NEVER leave client
    Note over U: Only encrypted data<br/>sent to server
```

#### Login Flow

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client App
    participant S as Server
    
    U->>C: Enter password
    C->>S: Request login (username)
    S->>S: Lookup user
    S-->>C: Return argon2_salt, srp_salt
    
    C->>C: derive_master_key(password, argon2_salt)
    C->>C: Fetch encrypted private key
    C->>C: Decrypt with master_key
    
    C->>C: derive_srp_password(password, srp_salt)
    C->>C: Generate SRP proof
    
    C->>S: SRP proof
    S->>S: Verify proof
    S-->>C: Authenticated!
    
    Note over C: Master key derived<br/>locally each time
    Note over U: Password never<br/>transmitted
```

### 🔧 Configuration

Edit `src/kdf.rs` to tune parameters:

```rust
// OWASP 2024 minimums - ADJUST FOR YOUR HARDWARE
const ARGON2_M_COST: u32 = 65536;  // Memory: 64 MB
const ARGON2_T_COST: u32 = 3;      // Iterations: 3
const ARGON2_P_COST: u32 = 4;      // Parallelism: 4 lanes

// Target: 300-500ms derivation time on production server
```

**Tuning Guide:**
- **Increase `M_COST`** if server has excess RAM (more secure)
- **Increase `T_COST`** if CPU is fast but RAM is limited
- **Decrease both** if derivation is too slow for UX (less secure)
- **Run benchmark:** `cargo test --test kdf benchmark_derive_master_key -- --ignored`

### 🧪 Testing

```bash
# Run all KDF tests
cargo test --test kdf

# Run with timing output
cargo test --test kdf -- --nocapture

# Run benchmark (ignored by default)
cargo test --test kdf benchmark_derive_master_key -- --ignored --nocapture

# Test all modules
cargo test
```

### 📦 Dependencies

```toml
[dependencies]
argon2 = "0.5"                    # Argon2 implementation
rand = "0.8"                      # Cryptographic RNG
zeroize = { version = "1.7", features = ["derive"] }  # Secure memory
```

### 🔍 Security Audit Checklist

- ✅ Argon2id (not Argon2i or Argon2d)
- ✅ Unique salts per user per purpose
- ✅ No password transmission to server
- ✅ Master key never leaves client
- ✅ Zeroization of sensitive memory
- ✅ Constant-time comparison (via Argon2 library)
- ✅ Cryptographically secure RNG (OsRng)
- ✅ No Copy/Clone on MasterKey struct

---


# 🔐 Vault Cryptography Module

> Secure encryption and key wrapping for `.env` files and vault keys using AES-256-GCM and XChaCha20-Poly1305.

## Overview

The `vault` module provides authenticated encryption for sensitive configuration data. It is designed for:

- ✅ Encrypting `.env` files before storage or transmission
- ✅ Wrapping vault keys with user master keys for secure key management
- ✅ Ensuring integrity via AEAD (Authenticated Encryption with Associated Data)
- ✅ Zeroizing sensitive keys from memory on drop

## Cryptographic Primitives

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| **Data Encryption** | AES-256-GCM | Encrypt `.env` plaintext with auth tag |
| **Key Wrapping** | XChaCha20-Poly1305 | Wrap `VaultKey` with user `MasterKey` |
| **KDF** | Argon2id (via `kdf` module) | Derive `MasterKey` from user password |
| **Randomness** | `rand::OsRng` | Cryptographically secure nonce/key generation |
| **Memory Safety** | `zeroize::ZeroizeOnDrop` | Securely erase keys when dropped |

## Constants

```rust
pub const VAULT_KEY_LEN: usize = 32;        // 256-bit key
pub const NONCE_LEN: usize = 12;            // 96-bit nonce for AES-GCM
pub const XCHACHA_NONCE_LEN: usize = 24;    // 192-bit nonce for XChaCha20
```

## Core Types

### `VaultKey`

```rust
#[derive(ZeroizeOnDrop)]
pub struct VaultKey(pub [u8; VAULT_KEY_LEN]);
```

A 32-byte symmetric key for encrypting vault data. Automatically zeroized on drop.

#### Methods

```rust
impl VaultKey {
    /// Generate a new cryptographically random vault key
    pub fn generate() -> Self;
}
```

### `EncryptedBlob`

```rust
pub struct EncryptedBlob {
    pub nonce: [u8; NONCE_LEN],           // 12-byte nonce for AES-GCM
    pub ciphertext: Vec<u8>,              // Ciphertext + 16-byte GCM auth tag
}
```

Represents an encrypted `.env` file. The nonce is stored in plaintext; the auth tag is appended to the ciphertext.

## Public API

### Encrypt/Decrypt `.env` Data

```rust
/// Encrypt plaintext with VaultKey using AES-256-GCM
pub fn encrypt_vault(
    plaintext: &[u8], 
    vault_key: &VaultKey
) -> Result<EncryptedBlob, CryptoError>;

/// Decrypt EncryptedBlob with VaultKey
pub fn decrypt_vault(
    blob: &EncryptedBlob, 
    vault_key: &VaultKey
) -> Result<Vec<u8>, CryptoError>;
```

#### Example

```rust
use evnx_crypto::vault::{VaultKey, encrypt_vault, decrypt_vault};

let vault_key = VaultKey::generate();
let env_content = b"DATABASE_URL=postgres://user:pass@localhost/db\n";

// Encrypt
let blob = encrypt_vault(env_content, &vault_key)?;

// Store blob.nonce and blob.ciphertext securely...

// Later, decrypt
let decrypted = decrypt_vault(&blob, &vault_key)?;
assert_eq!(env_content, &decrypted[..]);
```

### Wrap/Unwrap Vault Keys

```rust
/// Wrap VaultKey with user's MasterKey using XChaCha20-Poly1305
/// Returns: [24-byte nonce || ciphertext]
pub fn wrap_vault_key_with_master_key(
    vault_key: &VaultKey, 
    master_key: &MasterKey
) -> Result<Vec<u8>, CryptoError>;

/// Unwrap VaultKey from wrapped blob
pub fn unwrap_vault_key_with_master_key(
    wrapped: &[u8], 
    master_key: &MasterKey
) -> Result<VaultKey, CryptoError>;
```

#### Example

```rust
use evnx_crypto::vault::{VaultKey, wrap_vault_key_with_master_key, unwrap_vault_key_with_master_key};
use evnx_crypto::kdf::MasterKey;

let master_key = MasterKey::derive_from_password("user_password", b"salt123")?;
let vault_key = VaultKey::generate();

// Wrap for storage
let wrapped = wrap_vault_key_with_master_key(&vault_key, &master_key)?;
// Store `wrapped` in database (e.g., vault_members row)

// Later, unwrap
let unwrapped = unwrap_vault_key_with_master_key(&wrapped, &master_key)?;
assert_eq!(vault_key.0, unwrapped.0);
```

## Error Handling

All functions return `Result<T, CryptoError>`:

```rust
pub enum CryptoError {
    Encryption,           // AES-GCM encryption failure
    Decryption,           // Auth tag mismatch, wrong key, or tampering
    KeyWrap,              // XChaCha20-Poly1305 wrap failure
    KeyUnwrap,            // Auth failure or invalid input during unwrap
    InvalidInput(String), // Malformed input (e.g., too short)
    KdfError(String),     // Argon2id derivation failure
}
```

✅ **Never panic** — all errors are handled gracefully.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Confidentiality** | AES-256-GCM / XChaCha20-Poly1305 provide IND-CCA2 security |
| **Integrity** | AEAD auth tags detect any tampering (1-bit change → decryption fails) |
| **Nonce Safety** | Fresh random nonce generated per encryption call (OsRng) |
| **Key Isolation** | `VaultKey` and `MasterKey` are separate; compromise of one ≠ compromise of other |
| **Memory Safety** | `ZeroizeOnDrop` ensures keys are erased from heap/stack on drop |
| **No Key Reuse** | Each `encrypt_vault()` call uses unique nonce; never reuse (key, nonce) pairs |

## ⚠️ Critical Warnings

```rust
// ❌ NEVER reuse a nonce with the same key
// ❌ NEVER store VaultKey in plaintext
// ❌ NEVER log ciphertext, keys, or passwords
// ❌ NEVER use static/test keys in production

// ✅ ALWAYS generate fresh VaultKey per vault
// ✅ ALWAYS wrap VaultKey with user's MasterKey before storage
// ✅ ALWAYS verify decryption errors before proceeding
// ✅ ALWAYS use constant-time comparison for passwords (handled by Argon2)
```

## Testing

Run the test suite:

```bash
# All vault tests
cargo test --test vault

# With verbose output
cargo test --test vault -- --nocapture

# Property-based tests only
cargo test --test vault proptest

# Increase proptest iterations for CI
PROPTEST_CASES=1000 cargo test --test vault
```

### Test Coverage

- ✅ Round-trip encrypt/decrypt (empty, small, large, binary data)
- ✅ Nonce uniqueness (100+ encryptions → all nonces distinct)
- ✅ Wrong key → `Err(Decryption)`, not panic
- ✅ Tampering (ciphertext, nonce, truncation, append) → auth failure
- ✅ Key wrapping round-trip + cross-key failure
- ✅ Edge cases: all-zeros, all-ones, empty ciphertext
- ✅ Full workflow: encrypt → wrap → unwrap → decrypt

## Dependencies

```toml
# Cargo.toml
[dependencies]
aes-gcm = "0.10"
chacha20poly1305 = "0.10"
rand = "0.8"
zeroize = { version = "1.7", features = ["derive"] }

[dev-dependencies]
proptest = "1.4"
```

## See Also

- [`src/kdf.rs`](../kdf.rs) — Argon2id key derivation for `MasterKey`
- [`src/errors.rs`](../errors.rs) — `CryptoError` definitions
- [`tests/vault.rs`](../../tests/vault.rs) — Comprehensive test suite
