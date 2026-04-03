# KDF Module - Developer Guide

This guide provides comprehensive documentation for integrating and using the Key Derivation Function (KDF) module in the evnx-crypto project.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [API Reference](#api-reference)
- [Usage Examples](#usage-examples)
- [Integration Guide](#integration-guide)
- [Configuration](#configuration)
- [Testing](#testing)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [Performance Tuning](#performance-tuning)

---

## Overview

The KDF module provides secure password-based key derivation using **Argon2id**, the recommended algorithm for password hashing and key derivation. It's designed for:

1. **Client-side encryption**: Deriving keys to encrypt/decrypt Ed25519 private keys
2. **SRP authentication**: Generating secure inputs for SRP protocol
3. **Zero-knowledge architecture**: Ensuring passwords never leave the client

### Key Concepts

- **Master Key**: 32-byte key derived from password + argon2_salt, used for encryption
- **SRP Password**: 32-byte derived value used for SRP authentication
- **Salt**: 32-byte random value that ensures unique derivations per user
- **Deterministic**: Same password + salt always produces same output

---

## Installation

The KDF module is part of the `evnx-crypto` crate. Ensure your `Cargo.toml` includes:

```toml
[dependencies]
evnx-crypto = { path = "../evnx-crypto" }  # Or your version
argon2 = "0.5"
rand = "0.8"
zeroize = { version = "1.7", features = ["derive"] }
```

---

## API Reference

### Constants

```rust
pub const MASTER_KEY_LEN: usize = 32;  // Master key output length
pub const SALT_LEN: usize = 32;        // Salt length
```

### Structs

#### `MasterKey`

```rust
pub struct MasterKey(pub [u8; MASTER_KEY_LEN]);
```

**Properties:**
- Wraps a 32-byte array
- Implements `ZeroizeOnDrop` (automatically clears memory when dropped)
- Does NOT implement `Copy` or `Clone` (prevents accidental duplication)

**Usage:**
```rust
let master_key: MasterKey = derive_master_key(password, &salt)?;
// Use master_key.0 to access the byte array
let key_bytes: &[u8; 32] = &master_key.0;
```

### Functions

#### `generate_salt()`

Generates a cryptographically secure random salt.

**Signature:**
```rust
pub fn generate_salt() -> [u8; SALT_LEN]
```

**Returns:** 32-byte array filled with random data from `OsRng`

**Example:**
```rust
use evnx_crypto::generate_salt;

let salt = generate_salt();
println!("Generated salt: {:02x?}", &salt[..8]); // Print first 8 bytes
```

**Security Note:** Call this separately for `argon2_salt` and `srp_salt` - **never reuse salts**.

---

#### `derive_master_key()`

Derives the master encryption key from a password and Argon2 salt.

**Signature:**
```rust
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8; SALT_LEN]
) -> Result<MasterKey, CryptoError>
```

**Parameters:**
- `password`: Raw password bytes (UTF-8 encoded)
- `salt`: Argon2 salt (stored on server, fetched at login)

**Returns:**
- `Ok(MasterKey)`: 32-byte key for encryption/decryption
- `Err(CryptoError::Kdf)`: If Argon2 derivation fails

**Example:**
```rust
use evnx_crypto::{derive_master_key, generate_salt};

let password = b"my_secure_password";
let salt = generate_salt(); // Store this on server!

match derive_master_key(password, &salt) {
    Ok(master_key) => {
        println!("Master key derived successfully");
        // Use master_key.0 for encryption
    }
    Err(e) => {
        eprintln!("Key derivation failed: {}", e);
    }
}
```

**Use Cases:**
1. **Registration**: Derive key to encrypt newly generated Ed25519 private key
2. **Login**: Derive key to decrypt stored Ed25519 private key

---

#### `derive_srp_password()`

Derives the SRP password input from a password and SRP-specific salt.

**Signature:**
```rust
pub fn derive_srp_password(
    password: &[u8],
    srp_salt: &[u8; SALT_LEN]
) -> Result<Zeroizing<Vec<u8>>, CryptoError>
```

**Parameters:**
- `password`: Raw password bytes (UTF-8 encoded)
- `srp_salt`: SRP-specific salt (MUST differ from argon2_salt)

**Returns:**
- `Ok(Zeroizing<Vec<u8>>)`: 32-byte vector for SRP operations
- `Err(CryptoError::Kdf)`: If Argon2 derivation fails

**Example:**
```rust
use evnx_crypto::{derive_srp_password, generate_salt};

let password = b"my_secure_password";
let srp_salt = generate_salt(); // Different from argon2_salt!

match derive_srp_password(password, &srp_salt) {
    Ok(srp_password) => {
        println!("SRP password derived: {} bytes", srp_password.len());
        // Use srp_password.as_slice() for SRP operations
    }
    Err(e) => {
        eprintln!("SRP derivation failed: {}", e);
    }
}
```

**Critical:** `srp_salt` MUST be different from `argon2_salt` to ensure compromise of SRP verifier doesn't enable master key derivation.

---

## Usage Examples

### Example 1: User Registration Flow

```rust
use evnx_crypto::{derive_master_key, derive_srp_password, generate_salt};
use ed25519_dalek::{SigningKey, SecretKey};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

async fn register_user(username: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Generate unique salts
    let argon2_salt = generate_salt();
    let srp_salt = generate_salt();
    
    // Step 2: Derive master key for encryption
    let master_key = derive_master_key(password.as_bytes(), &argon2_salt)?;
    
    // Step 3: Generate Ed25519 keypair
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let secret_key_bytes = signing_key.to_bytes();
    
    // Step 4: Encrypt private key with master key
    let cipher = ChaCha20Poly1305::new_from_slice(&master_key.0)?;
    // ... encryption logic (use nonce, etc.)
    
    // Step 5: Derive SRP password and generate verifier
    let srp_password = derive_srp_password(password.as_bytes(), &srp_salt)?;
    // ... SRP verifier generation
    
    // Step 6: Send to server (NEVER send password or master_key!)
    send_to_server(username, argon2_salt, srp_salt, encrypted_key, srp_verifier).await?;
    
    // master_key is automatically zeroized when dropped
    Ok(())
}
```

### Example 2: User Login Flow

```rust
use evnx_crypto::{derive_master_key, derive_srp_password};

async fn login_user(username: &str, password: &str) -> Result<SigningKey, Box<dyn std::error::Error>> {
    // Step 1: Fetch salts from server
    let (argon2_salt, srp_salt, encrypted_private_key) = fetch_user_data(username).await?;
    
    // Step 2: Derive master key to decrypt private key
    let master_key = derive_master_key(password.as_bytes(), &argon2_salt)?;
    
    // Step 3: Decrypt Ed25519 private key
    let cipher = ChaCha20Poly1305::new_from_slice(&master_key.0)?;
    // ... decryption logic
    let secret_key_bytes = decrypt(&cipher, &encrypted_private_key)?;
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    
    // Step 4: Derive SRP password for authentication
    let srp_password = derive_srp_password(password.as_bytes(), &srp_salt)?;
    
    // Step 5: Perform SRP authentication
    perform_srp_auth(username, srp_password.as_slice()).await?;
    
    Ok(signing_key)
}
```

### Example 3: Password Change

```rust
use evnx_crypto::{derive_master_key, generate_salt};

async fn change_password(
    username: &str,
    old_password: &str,
    new_password: &str
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Fetch current data
    let (old_argon2_salt, encrypted_key) = fetch_user_data(username).await?;
    
    // Step 2: Derive old master key to decrypt
    let old_master_key = derive_master_key(old_password.as_bytes(), &old_argon2_salt)?;
    let private_key = decrypt(&old_master_key.0, &encrypted_key)?;
    
    // Step 3: Generate new salt
    let new_argon2_salt = generate_salt();
    
    // Step 4: Derive new master key
    let new_master_key = derive_master_key(new_password.as_bytes(), &new_argon2_salt)?;
    
    // Step 5: Re-encrypt with new key
    let new_encrypted_key = encrypt(&new_master_key.0, &private_key)?;
    
    // Step 6: Update server
    update_user_salt_and_key(username, new_argon2_salt, new_encrypted_key).await?;
    
    Ok(())
}
```

---

## Integration Guide

### Step 1: Import the Module

```rust
use evnx_crypto::{
    derive_master_key,
    derive_srp_password,
    generate_salt,
    MasterKey,
    MASTER_KEY_LEN,
    SALT_LEN,
};
```

### Step 2: Handle Errors

The KDF functions return `Result<T, CryptoError>`. Define error handling:

```rust
use evnx_crypto::errors::CryptoError;

fn my_function() -> Result<(), MyError> {
    let salt = generate_salt();
    let key = derive_master_key(b"password", &salt)
        .map_err(|e| MyError::KeyDerivationFailed(e.to_string()))?;
    
    Ok(())
}

enum MyError {
    KeyDerivationFailed(String),
    // ... other errors
}
```

### Step 3: Secure Memory Handling

The module uses `zeroize` for automatic memory clearing:

```rust
use zeroize::Zeroizing;

// MasterKey automatically zeroizes on drop
let master_key = derive_master_key(password, &salt)?;
// Use master_key...
// When master_key goes out of scope, memory is cleared

// For custom buffers:
let mut sensitive_data = Zeroizing::new(vec![0u8; 64]);
// Use sensitive_data...
// Automatically cleared when dropped
```

### Step 4: Salt Storage

**On Server:**
```rust
struct UserRecord {
    username: String,
    argon2_salt: [u8; SALT_LEN],  // Store this
    srp_salt: [u8; SALT_LEN],     // Store this
    srp_verifier: Vec<u8>,        // Store this
    encrypted_private_key: Vec<u8>, // Store this
}
```

**Important:**
- Store both salts with the user record
- Never store passwords or master keys
- Salts are NOT secret (can be stored in plaintext)

---

## Configuration

### Tuning Argon2 Parameters

Edit `src/kdf.rs`:

```rust
// Current settings (OWASP 2024 minimums)
const ARGON2_M_COST: u32 = 65536;  // 64 MB memory
const ARGON2_T_COST: u32 = 3;      // 3 iterations
const ARGON2_P_COST: u32 = 4;      // 4 parallel lanes
```

**Tuning Guide:**

| Scenario | M_COST | T_COST | P_COST | Expected Time |
|----------|--------|--------|--------|---------------|
| Low-end server | 32768 | 2 | 4 | ~200-300ms |
| **Default (recommended)** | **65536** | **3** | **4** | **~300-500ms** |
| High-security | 131072 | 4 | 4 | ~800-1200ms |
| Mobile client | 16384 | 2 | 2 | ~100-200ms |

**Benchmark Command:**
```bash
cargo test --test kdf benchmark_derive_master_key -- --ignored --nocapture
```

**Adjustment Strategy:**
1. Deploy to target hardware
2. Run benchmark
3. If too slow (>500ms): Decrease `M_COST` or `T_COST`
4. If too fast (<300ms): Increase `M_COST` (preferred) or `T_COST`
5. Re-test until in target range

---

## Testing

### Unit Tests

```bash
# Run all KDF tests
cargo test --test kdf

# Run specific test
cargo test --test kdf test_derive_master_key_deterministic

# Run with output
cargo test --test kdf -- --nocapture
```

### Test Coverage

The test suite covers:

| Test | Purpose |
|------|---------|
| `test_derive_master_key_deterministic` | Same inputs → same output |
| `test_derive_master_key_different_salts_produce_different_keys` | Salt sensitivity |
| `test_argon2_salt_and_srp_salt_produce_independent_outputs` | Key separation |
| `test_generate_salt_uniqueness_and_length` | Salt quality |
| `test_empty_password_does_not_panic` | Edge case handling |
| `test_unicode_password_determinism` | UTF-8 support |
| `test_long_password_handling` | Arbitrary length support |

### Writing Custom Tests

```rust
#[cfg(test)]
mod tests {
    use evnx_crypto::{derive_master_key, generate_salt};
    
    #[test]
    fn test_my_custom_scenario() {
        let password = b"test_password";
        let salt = generate_salt();
        
        let key = derive_master_key(password, &salt)
            .expect("Should derive key");
        
        assert_eq!(key.0.len(), 32);
    }
}
```

---

## Security Best Practices

### ✅ DO

1. **Always use fresh salts**
   ```rust
   let argon2_salt = generate_salt();
   let srp_salt = generate_salt(); // Separate call!
   ```

2. **Handle errors properly**
   ```rust
   match derive_master_key(password, &salt) {
       Ok(key) => { /* use key */ }
       Err(e) => {
           log::error!("KDF failed: {}", e);
           return Err(AuthError::InvalidCredentials);
       }
   }
   ```

3. **Zeroize sensitive data**
   ```rust
   use zeroize::Zeroize;
   
   let mut password_vec = password.to_vec();
   // Use password...
   password_vec.zeroize(); // Explicit clear if needed
   ```

4. **Use constant-time comparison**
   ```rust
   use subtle::ConstantTimeEq;
   
   if key1.0.ct_eq(&key2.0).into() {
       // Keys match
   }
   ```

### ❌ DON'T

1. **Never transmit passwords or master keys**
   ```rust
   // ❌ WRONG
   send_to_server(password);
   
   // ✅ CORRECT
   let salt = fetch_salt_from_server();
   let key = derive_master_key(password, &salt);
   // Only send encrypted data
   ```

2. **Never reuse salts**
   ```rust
   // ❌ WRONG
   let salt = generate_salt();
   let master_key = derive_master_key(password, &salt);
   let srp_password = derive_srp_password(password, &salt); // Same salt!
   
   // ✅ CORRECT
   let argon2_salt = generate_salt();
   let srp_salt = generate_salt();
   ```

3. **Don't log sensitive data**
   ```rust
   // ❌ WRONG
   println!("Master key: {:?}", master_key.0);
   
   // ✅ CORRECT
   println!("Key derived successfully");
   ```

4. **Don't derive Copy/Clone on MasterKey**
   ```rust
   // The struct is intentionally NOT Copy/Clone
   // If you need to pass it around, use references
   fn encrypt_data(key: &MasterKey, data: &[u8]) { ... }
   ```

---

## Troubleshooting

### Common Errors

#### `CryptoError::Kdf("...")`

**Cause:** Argon2 derivation failed

**Solutions:**
- Check that salt is exactly 32 bytes
- Verify password is not null
- Ensure Argon2 parameters are valid

```rust
// Debug example
let salt = [0u8; 32]; // Correct: 32 bytes
let key = derive_master_key(password, &salt);
```

#### Derivation Too Slow

**Symptom:** Login takes >2 seconds

**Solution:** Reduce Argon2 parameters
```rust
// In src/kdf.rs
const ARGON2_M_COST: u32 = 32768; // Reduced from 65536
const ARGON2_T_COST: u32 = 2;     // Reduced from 3
```

#### Derivation Too Fast

**Symptom:** Benchmark shows <100ms

**Solution:** Increase parameters for security
```rust
const ARGON2_M_COST: u32 = 131072; // Increased
const ARGON2_T_COST: u32 = 4;      // Increased
```

#### Compilation Errors

**Error:** `cannot find function 'derive_master_key'`

**Solution:** Ensure module is public in `lib.rs`
```rust
// src/lib.rs
pub mod kdf; // Must be pub, not private
```

---

## Performance Tuning

### Benchmarking

```bash
# Run benchmark
cargo test --test kdf benchmark_derive_master_key -- --ignored --nocapture

# Expected output:
# derive_master_key took: 1.175068417s
```

### Optimization Strategies

**1. Memory vs Time Tradeoff**

```rust
// Memory-optimized (less secure)
const ARGON2_M_COST: u32 = 16384;  // 16 MB
const ARGON2_T_COST: u32 = 4;      // More iterations

// Balanced (recommended)
const ARGON2_M_COST: u32 = 65536;  // 64 MB
const ARGON2_T_COST: u32 = 3;      // 3 iterations

// Time-optimized (more secure if RAM available)
const ARGON2_M_COST: u32 = 131072; // 128 MB
const ARGON2_T_COST: u32 = 2;      // Fewer iterations
```

**2. Parallelism Tuning**

```rust
// For single-core systems
const ARGON2_P_COST: u32 = 1;

// For multi-core (recommended)
const ARGON2_P_COST: u32 = 4;

// For many cores
const ARGON2_P_COST: u32 = 8;
```

**3. Platform-Specific Tuning**

Create environment-specific configs:

```rust
#[cfg(debug_assertions)]
// Development: faster for testing
const ARGON2_M_COST: u32 = 4096;
const ARGON2_T_COST: u32 = 1;

#[cfg(not(debug_assertions))]
// Production: secure settings
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
```

### Monitoring

Add timing metrics in production:

```rust
use std::time::Instant;

fn derive_with_timing(password: &[u8], salt: &[u8; 32]) -> Result<MasterKey, CryptoError> {
    let start = Instant::now();
    let key = derive_master_key(password, salt)?;
    let duration = start.elapsed();
    
    metrics::histogram!("kdf_derivation_time", duration);
    
    Ok(key)
}
```

---

## Additional Resources

- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- [OWASP Password Storage Cheatatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [zeroize crate documentation](https://docs.rs/zeroize)
- [SRP Protocol](https://srp.stanford.edu/)

## Support

For issues or questions:
- 📧 Email: security@evnx.io
- 🐛 Issues: [GitHub Issues](https://github.com/evnx/evnx-crypto/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/evnx/evnx-crypto/discussions)

---

**Last Updated:** April 2026  
**Version:** 0.1.0


---

