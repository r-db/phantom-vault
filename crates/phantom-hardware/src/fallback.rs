//! Software-only fallback implementation.
//!
//! Uses Argon2id for key derivation when no hardware
//! security module is available.

use crate::{Hsm, HsmBackend, HsmResult};
use phantom_core::memory::SecretBuffer;

/// Software fallback HSM implementation.
pub struct SoftwareHsm {
    _initialized: bool,
}

impl SoftwareHsm {
    /// Create a new software HSM.
    pub fn new() -> HsmResult<Self> {
        todo!("SoftwareHsm::new")
    }

    /// Software HSM is always available.
    pub fn is_supported() -> bool {
        true
    }
}

impl Hsm for SoftwareHsm {
    fn backend(&self) -> HsmBackend {
        HsmBackend::Software
    }

    fn is_available(&self) -> bool {
        true
    }

    fn generate_key(&self, _key_id: &str) -> HsmResult<()> {
        todo!("SoftwareHsm::generate_key")
    }

    fn delete_key(&self, _key_id: &str) -> HsmResult<()> {
        todo!("SoftwareHsm::delete_key")
    }

    fn sign(&self, _key_id: &str, _data: &[u8]) -> HsmResult<Vec<u8>> {
        todo!("SoftwareHsm::sign")
    }

    fn verify(&self, _key_id: &str, _data: &[u8], _signature: &[u8]) -> HsmResult<bool> {
        todo!("SoftwareHsm::verify")
    }

    fn encrypt(&self, _key_id: &str, _plaintext: &[u8]) -> HsmResult<Vec<u8>> {
        todo!("SoftwareHsm::encrypt")
    }

    fn decrypt(&self, _key_id: &str, _ciphertext: &[u8]) -> HsmResult<SecretBuffer> {
        todo!("SoftwareHsm::decrypt")
    }

    fn derive_key(&self, _password: &SecretBuffer, _salt: &[u8]) -> HsmResult<SecretBuffer> {
        todo!("SoftwareHsm::derive_key")
    }
}

impl Default for SoftwareHsm {
    fn default() -> Self {
        Self::new().expect("Software HSM initialization failed")
    }
}

/// Argon2id parameters for software key derivation.
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost (iterations).
    pub iterations: u32,
    /// Parallelism factor.
    pub parallelism: u32,
    /// Output length in bytes.
    pub output_len: usize,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 65536,  // 64 MiB
            iterations: 3,
            parallelism: 4,
            output_len: 32,
        }
    }
}

/// Derive a key using Argon2id.
pub fn derive_argon2id(
    _password: &SecretBuffer,
    _salt: &[u8],
    _params: &Argon2Params,
) -> HsmResult<SecretBuffer> {
    todo!("derive_argon2id")
}
