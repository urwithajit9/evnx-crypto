// src/zeroize.rs

//! Secure memory wrappers for ephemeral secret material.
//!
//! All types in this module guarantee that their contents are
//! overwritten with zeros when dropped. Use these for any secret
//! that lives on the heap (Vec, String) during computation.
//!
//! ## When to use each type
//!
//! | Type | Use for |
//! |------|---------|
//! | `SecretBytes` | Variable-length binary secrets (ECDH shared secret, derived keys) |
//! | `SecretString` | Password input before converting to bytes |
//! | `ZeroizeVec<T>` | Temporary buffers holding multiple secret values |

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// A heap-allocated byte buffer that is zeroized on drop.
///
/// Backed by `zeroize::Zeroizing<Vec<u8>>` — a thin wrapper that
/// ensures `Vec::zeroize()` is called before `Vec::drop()`.
///
/// # Example
/// ```rust
/// # use evnx_crypto::zeroize::SecretBytes;
/// let secret = SecretBytes::from(vec![1u8, 2, 3, 4]);
/// // ... use secret.as_ref() ...
/// // Automatically zeroed when `secret` goes out of scope.
/// ```
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Create from a raw byte vector.
    /// Ownership is transferred — the caller should not keep a copy.
    /// Take ownership of bytes that must be cleared on drop.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Wrap an existing `Zeroizing<Vec<u8>>` (from argon2 / hkdf output).
    /// Wrap an existing `Zeroizing` buffer.
    pub fn from_zeroizing(z: Zeroizing<Vec<u8>>) -> Self {
        Self(z)
    }

    /// Number of bytes held.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if nothing is held.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(s: &[u8]) -> Self {
        Self::new(s.to_vec())
    }
}

/// Never print secret bytes — this would leak them to logs.
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED {} bytes])", self.0.len())
    }
}

/// Never display secret bytes.
impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// A heap-allocated password string that is zeroized on drop.
///
/// Accepts user password input before it is converted to bytes
/// for Argon2 derivation. Once converted, use `SecretBytes`.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Take ownership of a string that must be cleared on drop.
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    /// Borrow the string's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Borrow the string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True if nothing is held.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([REDACTED])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// A fixed-size array that is zeroized on drop.
///
/// Prefer this over `[u8; N]` for ephemeral keys that are
/// stack-allocated but must be zeroized (e.g., intermediate
/// HKDF outputs, nonce buffers used for a single operation).
#[derive(Clone)]
pub struct SecretArray<const N: usize>([u8; N]);

impl<const N: usize> SecretArray<N> {
    /// Take ownership of an array that must be cleared on drop.
    pub fn new(arr: [u8; N]) -> Self {
        Self(arr)
    }

    /// An all-zero buffer, ready to be filled by a KDF.
    pub fn zeroed() -> Self {
        Self([0u8; N])
    }

    /// Borrow the bytes. Named `expose` so call sites read as a deliberate act.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// Mutable access, for writing a derived key into the buffer.
    ///
    /// The only intended caller is a KDF expand step. Anything that overwrites
    /// this buffer with non-secret data defeats the point of the type.
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// Consume the wrapper and return the bytes.
    ///
    /// The returned array is **not** zeroized on drop — the caller takes over that
    /// responsibility. Prefer [`SecretArray::expose`] unless ownership is required.
    pub fn into_inner(mut self) -> [u8; N] {
        let out = self.0;
        self.0.zeroize();
        out
    }
}

impl<const N: usize> AsRef<[u8]> for SecretArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Drop for SecretArray<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> fmt::Debug for SecretArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretArray<{}>([REDACTED])", N)
    }
}

/// Explicitly zeroize a mutable byte slice.
///
/// Use this when you need to clear a buffer that isn't wrapped in
/// a Zeroizing type (e.g., a stack array passed by mutable reference).
///
/// # Example
/// ```rust
/// # use evnx_crypto::zeroize::zeroize_slice;
/// let mut key_bytes = [0u8; 32];
/// // ... fill and use key_bytes ...
/// zeroize_slice(&mut key_bytes);
/// assert!(key_bytes.iter().all(|&b| b == 0));
/// ```
pub fn zeroize_slice(buf: &mut [u8]) {
    buf.zeroize();
}
