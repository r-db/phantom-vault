//! # Phantom Hardware
//!
//! Hardware security module abstraction for enhanced key protection.
//!
//! Supports:
//! - macOS Secure Enclave
//! - Linux TPM 2.0
//! - FIDO2/YubiKey
//! - Software fallback (Argon2id)

pub mod fallback;
pub mod fido2;
pub mod secure_enclave;
pub mod tpm;

use phantom_core::memory::SecretBuffer;
use thiserror::Error;

/// Errors that can occur during HSM operations.
#[derive(Debug, Error)]
pub enum HsmError {
    /// Hardware not available.
    #[error("hardware not available: {0}")]
    NotAvailable(String),

    /// Key operation failed.
    #[error("key operation failed: {0}")]
    KeyOperation(String),

    /// Authentication failed.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// User cancelled operation.
    #[error("user cancelled")]
    Cancelled,

    /// Platform not supported.
    #[error("platform not supported")]
    PlatformNotSupported,
}

/// Result type for HSM operations.
pub type HsmResult<T> = Result<T, HsmError>;

/// Available HSM backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmBackend {
    /// macOS Secure Enclave.
    SecureEnclave,
    /// Linux TPM 2.0.
    Tpm,
    /// FIDO2/WebAuthn device.
    Fido2,
    /// Software-only fallback.
    Software,
}

/// Trait for HSM implementations.
pub trait Hsm: Send + Sync {
    /// Get the backend type.
    fn backend(&self) -> HsmBackend;

    /// Check if the HSM is available.
    fn is_available(&self) -> bool;

    /// Generate a new key pair.
    fn generate_key(&self, key_id: &str) -> HsmResult<()>;

    /// Delete a key.
    fn delete_key(&self, key_id: &str) -> HsmResult<()>;

    /// Sign data with a key.
    fn sign(&self, key_id: &str, data: &[u8]) -> HsmResult<Vec<u8>>;

    /// Verify a signature.
    fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> HsmResult<bool>;

    /// Encrypt data with a key.
    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> HsmResult<Vec<u8>>;

    /// Decrypt data with a key.
    fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> HsmResult<SecretBuffer>;

    /// Derive a key from a password using hardware-backed KDF.
    fn derive_key(&self, password: &SecretBuffer, salt: &[u8]) -> HsmResult<SecretBuffer>;
}

/// Detect and return the best available HSM.
pub fn detect_hsm() -> Box<dyn Hsm> {
    todo!("detect_hsm")
}

/// Get a specific HSM backend.
pub fn get_hsm(_backend: HsmBackend) -> HsmResult<Box<dyn Hsm>> {
    todo!("get_hsm")
}
