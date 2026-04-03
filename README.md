# evnx-crypto

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
