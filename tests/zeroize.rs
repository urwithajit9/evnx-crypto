// tests/zeroize.rs

//! Tests for secure memory types and zeroization guarantees.

use evnx_crypto::zeroize::{SecretBytes, SecretString, SecretArray, zeroize_slice};

#[test]
fn test_secret_bytes_as_ref() {
    let data = vec![1u8, 2, 3, 4, 5];
    let secret = SecretBytes::new(data.clone());
    assert_eq!(secret.as_ref(), &data[..]);
}

#[test]
fn test_secret_bytes_len() {
    let secret = SecretBytes::new(vec![0u8; 64]);
    assert_eq!(secret.len(), 64);
}

#[test]
fn test_secret_bytes_debug_does_not_leak() {
    let secret = SecretBytes::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let debug_str = format!("{:?}", secret);
    assert!(!debug_str.contains("DE"), "Debug must not expose secret bytes");
    assert!(debug_str.contains("REDACTED"), "Debug must say REDACTED");
}

#[test]
fn test_secret_string_as_bytes() {
    let secret = SecretString::new("my-secret-password".to_string());
    assert_eq!(secret.as_bytes(), b"my-secret-password");
}

#[test]
fn test_secret_string_debug_does_not_leak() {
    let secret = SecretString::from("super-secret");
    let debug_str = format!("{:?}", secret);
    assert!(!debug_str.contains("super-secret"), "Debug must not expose content");
}

#[test]
fn test_secret_array_as_ref() {
    let arr: [u8; 32] = [42u8; 32];
    let secret = SecretArray::new(arr);
    assert_eq!(secret.as_ref(), &[42u8; 32][..]);
}

#[test]
fn test_zeroize_slice_clears_memory() {
    let mut buf = [0xABu8; 64];
    assert!(buf.iter().all(|&b| b == 0xAB));
    zeroize_slice(&mut buf);
    assert!(buf.iter().all(|&b| b == 0),
        "zeroize_slice must overwrite all bytes with zero");
}

/// Verify that SecretArray is zeroed on drop using raw pointer inspection.
///
/// # Safety note
/// This test reads memory after the value has been dropped.
/// This is technically undefined behavior in Rust, but is acceptable
/// in test code specifically designed to verify zeroization.
/// The stack frame is kept alive by the surrounding function scope.
#[test]
fn test_secret_array_zeroed_on_drop() {
    let arr_bytes: [u8; 32] = [0xFFu8; 32];
    let ptr: *const u8;
    {
        let secret = SecretArray::new(arr_bytes);
        ptr = secret.0.as_ptr();
        // Verify it's non-zero while alive
        assert!(unsafe { *ptr } == 0xFF);
        // Drop happens here
    }
    // After drop, memory should be zeroed
    // Note: This test may be unreliable on some platforms due to
    // compiler optimizations. Run with: RUSTFLAGS="-C opt-level=0"
    let after_drop = unsafe { *ptr };
    assert_eq!(after_drop, 0,
        "SecretArray memory must be zeroed after drop. \
         If this fails, run with RUSTFLAGS='-C opt-level=0'");
}

#[test]
fn test_from_vec_into_secret_bytes() {
    let v = vec![1u8, 2, 3];
    let s: SecretBytes = v.into();
    assert_eq!(s.as_ref(), &[1u8, 2, 3]);
}

#[test]
fn test_from_str_into_secret_string() {
    let s: SecretString = "hello".into();
    assert_eq!(s.as_str(), "hello");
    assert!(!s.is_empty());
}