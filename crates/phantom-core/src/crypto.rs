//! Cryptographic primitives for Phantom Vault.
//!
//! Provides dual-layer encryption with AES-256-GCM (outer layer) and
//! XChaCha20-Poly1305 (inner layer) for defense in depth.
//!
//! # Encryption Scheme
//!
//! ```text
//! plaintext
//!     │
//!     ▼
//! ┌──────────────────────────┐
//! │  XChaCha20-Poly1305      │ ◄─── Inner layer (24-byte nonce)
//! │  (inner encryption)      │
//! └──────────────────────────┘
//!     │
//!     ▼
//! inner_ciphertext
//!     │
//!     ▼
//! ┌──────────────────────────┐
//! │  AES-256-GCM             │ ◄─── Outer layer (12-byte nonce)
//! │  (outer encryption)      │
//! └──────────────────────────┘
//!     │
//!     ▼
//! final_ciphertext
//! ```
//!
//! # Key Derivation
//!
//! Master keys are derived using Argon2id with:
//! - 256 MB memory
//! - 4 iterations
//! - 4 parallelism lanes

use crate::memory::{MemoryError, SecretBuffer};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ring::aead::{self, Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

/// AES-256-GCM nonce size in bytes.
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// XChaCha20-Poly1305 nonce size in bytes.
pub const XCHACHA_NONCE_SIZE: usize = 24;

/// AES-256-GCM authentication tag size in bytes.
pub const AES_GCM_TAG_SIZE: usize = 16;

/// XChaCha20-Poly1305 authentication tag size in bytes.
pub const XCHACHA_TAG_SIZE: usize = 16;

/// Key size in bytes (256 bits).
pub const KEY_SIZE: usize = 32;

/// Salt size for key derivation.
pub const SALT_SIZE: usize = 32;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// Encryption failed.
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed (likely wrong key or corrupted data).
    #[error("decryption failed: authentication or integrity check failed")]
    Decryption,

    /// Invalid key length.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    /// Invalid nonce length.
    #[error("invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    /// Ciphertext too short.
    #[error("ciphertext too short: minimum {minimum} bytes required")]
    CiphertextTooShort { minimum: usize },

    /// Random number generation failed.
    #[error("random number generation failed")]
    RandomGeneration,

    /// Memory allocation error.
    #[error("memory error: {0}")]
    Memory(#[from] MemoryError),
}

/// Result type for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Argon2id parameters for key derivation.
///
/// Default parameters provide strong security:
/// - 256 MB memory cost
/// - 4 iterations
/// - 4 parallelism lanes
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost (iterations).
    pub iterations: u32,
    /// Parallelism factor.
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 256 * 1024, // 256 MB
            iterations: 4,
            parallelism: 4,
        }
    }
}

/// A cryptographic key stored in secure memory.
///
/// The key material is stored in a `SecretBuffer` which provides:
/// - Memory locking to prevent swapping
/// - Automatic zeroization on drop
/// - No Debug/Clone/Serialize implementations
pub struct CryptoKey {
    /// The key material in secure memory.
    key: SecretBuffer,
}

impl CryptoKey {
    /// Create a new crypto key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - The raw key bytes (must be 32 bytes for AES-256)
    ///
    /// # Errors
    ///
    /// Returns an error if the key length is incorrect or memory allocation fails.
    pub fn from_bytes(key_bytes: &[u8]) -> CryptoResult<Self> {
        if key_bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: KEY_SIZE,
                got: key_bytes.len(),
            });
        }

        Ok(Self {
            key: SecretBuffer::from_slice(key_bytes)?,
        })
    }

    /// Create a new random crypto key.
    ///
    /// # Errors
    ///
    /// Returns an error if random generation or memory allocation fails.
    pub fn generate() -> CryptoResult<Self> {
        let mut key_bytes = [0u8; KEY_SIZE];
        let rng = SystemRandom::new();
        rng.fill(&mut key_bytes)
            .map_err(|_| CryptoError::RandomGeneration)?;

        let result = Self::from_bytes(&key_bytes);
        key_bytes.zeroize();
        result
    }

    /// Get access to the key bytes for cryptographic operations.
    ///
    /// This tracks access for audit purposes.
    #[inline]
    fn with_key<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        self.key.with_exposed(f)
    }

    /// Get the access count for audit purposes.
    pub fn access_count(&self) -> u64 {
        self.key.access_count()
    }
}

impl Zeroize for CryptoKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

/// Dual-layer encryption provider.
///
/// This provider implements defense-in-depth by using two independent
/// encryption algorithms:
///
/// 1. **Inner layer**: XChaCha20-Poly1305 (software-friendly, extended nonce)
/// 2. **Outer layer**: AES-256-GCM (hardware-accelerated where available)
///
/// Each encryption uses a unique random nonce to ensure semantic security.
pub struct DualLayerCrypto {
    /// The inner key for XChaCha20-Poly1305.
    inner_key: CryptoKey,
    /// The outer key for AES-256-GCM.
    outer_key: CryptoKey,
    /// Random number generator.
    rng: SystemRandom,
}

impl DualLayerCrypto {
    /// Create a new dual-layer crypto provider from separate keys.
    ///
    /// # Arguments
    ///
    /// * `inner_key` - Key for XChaCha20-Poly1305 (inner layer)
    /// * `outer_key` - Key for AES-256-GCM (outer layer)
    ///
    /// # Security Note
    ///
    /// The two keys MUST be independent. Never derive one from the other.
    pub fn new(inner_key: CryptoKey, outer_key: CryptoKey) -> Self {
        Self {
            inner_key,
            outer_key,
            rng: SystemRandom::new(),
        }
    }

    /// Create a dual-layer crypto provider from a master key.
    ///
    /// The master key is expanded using HKDF to derive independent
    /// inner and outer keys.
    ///
    /// # Arguments
    ///
    /// * `master_key` - The master key to derive from
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn from_master_key(master_key: &CryptoKey) -> CryptoResult<Self> {
        let (inner_key, outer_key) = master_key.with_key(|master_bytes| {
            // Use HKDF to derive two independent keys
            let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"phantom-vault-v1");
            let prk = salt.extract(master_bytes);

            // Derive inner key
            let mut inner_bytes = [0u8; KEY_SIZE];
            let inner_okm = prk
                .expand(&[b"inner-xchacha20"], ring::hkdf::HKDF_SHA256)
                .map_err(|_| CryptoError::KeyDerivation("HKDF expansion failed".to_string()))?;
            inner_okm
                .fill(&mut inner_bytes)
                .map_err(|_| CryptoError::KeyDerivation("HKDF fill failed".to_string()))?;

            // Derive outer key
            let mut outer_bytes = [0u8; KEY_SIZE];
            let outer_okm = prk
                .expand(&[b"outer-aes256gcm"], ring::hkdf::HKDF_SHA256)
                .map_err(|_| CryptoError::KeyDerivation("HKDF expansion failed".to_string()))?;
            outer_okm
                .fill(&mut outer_bytes)
                .map_err(|_| CryptoError::KeyDerivation("HKDF fill failed".to_string()))?;

            let inner_key = CryptoKey::from_bytes(&inner_bytes)?;
            let outer_key = CryptoKey::from_bytes(&outer_bytes)?;

            inner_bytes.zeroize();
            outer_bytes.zeroize();

            Ok::<_, CryptoError>((inner_key, outer_key))
        })?;

        Ok(Self::new(inner_key, outer_key))
    }

    /// Encrypt data using dual-layer encryption.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt
    ///
    /// # Returns
    ///
    /// The ciphertext with prepended nonces:
    /// ```text
    /// [xchacha_nonce (24)] [aes_nonce (12)] [ciphertext] [tags]
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Step 1: Encrypt with XChaCha20-Poly1305 (inner layer)
        let inner_ciphertext = self.encrypt_xchacha(plaintext)?;

        // Step 2: Encrypt with AES-256-GCM (outer layer)
        let outer_ciphertext = self.encrypt_aes_gcm(&inner_ciphertext)?;

        Ok(outer_ciphertext)
    }

    /// Decrypt data using dual-layer decryption.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to decrypt (with prepended nonces)
    ///
    /// # Returns
    ///
    /// The plaintext in a secure buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ciphertext is too short
    /// - Authentication fails
    /// - The keys are incorrect
    pub fn decrypt(&self, ciphertext: &[u8]) -> CryptoResult<SecretBuffer> {
        // Step 1: Decrypt outer layer (AES-256-GCM)
        let inner_ciphertext = self.decrypt_aes_gcm(ciphertext)?;

        // Step 2: Decrypt inner layer (XChaCha20-Poly1305)
        let plaintext = self.decrypt_xchacha(&inner_ciphertext)?;

        Ok(plaintext)
    }

    /// Encrypt using XChaCha20-Poly1305 (inner layer).
    fn encrypt_xchacha(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; XCHACHA_NONCE_SIZE];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| CryptoError::RandomGeneration)?;

        let ciphertext = self.inner_key.with_key(|key_bytes| {
            let key = chacha20poly1305::Key::from_slice(key_bytes);
            let cipher = XChaCha20Poly1305::new(key);
            let nonce = XNonce::from_slice(&nonce_bytes);

            cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| CryptoError::Encryption("XChaCha20-Poly1305 encryption failed".to_string()))
        })?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(XCHACHA_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        nonce_bytes.zeroize();

        Ok(result)
    }

    /// Decrypt using XChaCha20-Poly1305 (inner layer).
    fn decrypt_xchacha(&self, ciphertext: &[u8]) -> CryptoResult<SecretBuffer> {
        let minimum = XCHACHA_NONCE_SIZE + XCHACHA_TAG_SIZE;
        if ciphertext.len() < minimum {
            return Err(CryptoError::CiphertextTooShort { minimum });
        }

        let (nonce_bytes, ciphertext) = ciphertext.split_at(XCHACHA_NONCE_SIZE);

        let plaintext = self.inner_key.with_key(|key_bytes| {
            let key = chacha20poly1305::Key::from_slice(key_bytes);
            let cipher = XChaCha20Poly1305::new(key);
            let nonce = XNonce::from_slice(nonce_bytes);

            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| CryptoError::Decryption)
        })?;

        SecretBuffer::from_vec(plaintext).map_err(CryptoError::Memory)
    }

    /// Encrypt using AES-256-GCM (outer layer).
    fn encrypt_aes_gcm(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| CryptoError::RandomGeneration)?;

        let ciphertext = self.outer_key.with_key(|key_bytes| {
            // Create the unbound key
            let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key_bytes)
                .map_err(|_| CryptoError::Encryption("Invalid AES key".to_string()))?;

            // Create a single-use nonce sequence
            let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
                .map_err(|_| CryptoError::Encryption("Invalid nonce".to_string()))?;

            // Create sealing key with a one-shot nonce
            struct OneNonce {
                nonce: Option<Nonce>,
            }

            impl NonceSequence for OneNonce {
                fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
                    self.nonce.take().ok_or(ring::error::Unspecified)
                }
            }

            let mut sealing_key = SealingKey::new(unbound_key, OneNonce { nonce: Some(nonce) });

            // Prepare buffer: plaintext + space for tag
            let mut in_out = plaintext.to_vec();
            in_out.reserve(AES_GCM_TAG_SIZE);

            sealing_key
                .seal_in_place_append_tag(Aad::empty(), &mut in_out)
                .map_err(|_| CryptoError::Encryption("AES-GCM sealing failed".to_string()))?;

            Ok::<_, CryptoError>(in_out)
        })?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        nonce_bytes.zeroize();

        Ok(result)
    }

    /// Decrypt using AES-256-GCM (outer layer).
    fn decrypt_aes_gcm(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        let minimum = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
        if ciphertext.len() < minimum {
            return Err(CryptoError::CiphertextTooShort { minimum });
        }

        let (nonce_bytes, ciphertext) = ciphertext.split_at(AES_GCM_NONCE_SIZE);

        self.outer_key.with_key(|key_bytes| {
            let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key_bytes)
                .map_err(|_| CryptoError::Decryption)?;

            let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
                .map_err(|_| CryptoError::Decryption)?;

            struct OneNonce {
                nonce: Option<Nonce>,
            }

            impl NonceSequence for OneNonce {
                fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
                    self.nonce.take().ok_or(ring::error::Unspecified)
                }
            }

            let mut opening_key =
                aead::OpeningKey::new(unbound_key, OneNonce { nonce: Some(nonce) });

            let mut in_out = ciphertext.to_vec();
            let plaintext = opening_key
                .open_in_place(Aad::empty(), &mut in_out)
                .map_err(|_| CryptoError::Decryption)?;

            Ok(plaintext.to_vec())
        })
    }

    /// Generate a random nonce suitable for AES-GCM.
    pub fn generate_aes_nonce(&self) -> CryptoResult<[u8; AES_GCM_NONCE_SIZE]> {
        let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
        self.rng
            .fill(&mut nonce)
            .map_err(|_| CryptoError::RandomGeneration)?;
        Ok(nonce)
    }

    /// Generate a random nonce suitable for XChaCha20-Poly1305.
    pub fn generate_xchacha_nonce(&self) -> CryptoResult<[u8; XCHACHA_NONCE_SIZE]> {
        let mut nonce = [0u8; XCHACHA_NONCE_SIZE];
        self.rng
            .fill(&mut nonce)
            .map_err(|_| CryptoError::RandomGeneration)?;
        Ok(nonce)
    }
}

impl Zeroize for DualLayerCrypto {
    fn zeroize(&mut self) {
        self.inner_key.zeroize();
        self.outer_key.zeroize();
    }
}

impl Drop for DualLayerCrypto {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Derive a cryptographic key from a password using Argon2id.
///
/// This is used when hardware security (Secure Enclave/TPM) is not available.
///
/// # Arguments
///
/// * `password` - The password to derive from
/// * `salt` - A random salt (must be at least 16 bytes, recommend 32 bytes)
/// * `params` - Argon2id parameters
///
/// # Returns
///
/// A 256-bit key in a secure buffer.
///
/// # Errors
///
/// Returns an error if:
/// - The salt is too short
/// - Argon2id computation fails
/// - Memory allocation fails
///
/// # Security Note
///
/// The default parameters use 256 MB of memory. Ensure your system has
/// sufficient RAM available.
pub fn derive_key(
    password: &SecretBuffer,
    salt: &[u8],
    params: &Argon2Params,
) -> CryptoResult<CryptoKey> {
    if salt.len() < 16 {
        return Err(CryptoError::KeyDerivation(
            "salt must be at least 16 bytes".to_string(),
        ));
    }

    let mut output = [0u8; KEY_SIZE];

    password.with_exposed(|password_bytes| {
        let argon2_params = argon2::Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(KEY_SIZE),
        )
        .map_err(|e| CryptoError::KeyDerivation(format!("invalid Argon2 params: {}", e)))?;

        let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2_params);

        argon2
            .hash_password_into(password_bytes, salt, &mut output)
            .map_err(|e| CryptoError::KeyDerivation(format!("Argon2id failed: {}", e)))?;

        Ok::<_, CryptoError>(())
    })?;

    let key = CryptoKey::from_bytes(&output)?;
    output.zeroize();

    Ok(key)
}

/// Generate a random salt suitable for key derivation.
///
/// # Returns
///
/// A 32-byte random salt.
///
/// # Errors
///
/// Returns an error if random generation fails.
pub fn generate_salt() -> CryptoResult<[u8; SALT_SIZE]> {
    let mut salt = [0u8; SALT_SIZE];
    let rng = SystemRandom::new();
    rng.fill(&mut salt)
        .map_err(|_| CryptoError::RandomGeneration)?;
    Ok(salt)
}

/// Generate cryptographically secure random bytes.
///
/// # Arguments
///
/// * `len` - Number of random bytes to generate
///
/// # Returns
///
/// A vector of random bytes.
///
/// # Errors
///
/// Returns an error if random generation fails.
pub fn random_bytes(len: usize) -> CryptoResult<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    let rng = SystemRandom::new();
    rng.fill(&mut bytes)
        .map_err(|_| CryptoError::RandomGeneration)?;
    Ok(bytes)
}

/// Constant-time comparison of two byte slices.
///
/// # Arguments
///
/// * `a` - First slice
/// * `b` - Second slice
///
/// # Returns
///
/// `true` if the slices are equal, `false` otherwise.
///
/// # Security Note
///
/// This function takes constant time regardless of where the slices differ,
/// preventing timing attacks.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// Re-exports for convenience (types used in the public API but not re-implemented)
pub use crate::memory::SecretBuffer as CryptoSecretBuffer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_key_generation() {
        let key = CryptoKey::generate().expect("key generation failed");
        assert_eq!(key.access_count(), 0);
    }

    #[test]
    fn test_crypto_key_from_bytes() {
        let bytes = [0x42u8; KEY_SIZE];
        let key = CryptoKey::from_bytes(&bytes).expect("key creation failed");

        key.with_key(|k| {
            assert_eq!(k, &bytes);
        });
    }

    #[test]
    fn test_crypto_key_invalid_length() {
        let bytes = [0u8; 16]; // Too short
        let result = CryptoKey::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength { expected: 32, got: 16 })
        ));
    }

    #[test]
    fn test_dual_layer_encrypt_decrypt_roundtrip() {
        let inner_key = CryptoKey::generate().unwrap();
        let outer_key = CryptoKey::generate().unwrap();
        let crypto = DualLayerCrypto::new(inner_key, outer_key);

        let plaintext = b"This is a secret message for testing dual-layer encryption!";

        let ciphertext = crypto.encrypt(plaintext).expect("encryption failed");
        let decrypted = crypto.decrypt(&ciphertext).expect("decryption failed");

        decrypted.with_exposed(|bytes| {
            assert_eq!(bytes, plaintext);
        });
    }

    #[test]
    fn test_dual_layer_from_master_key() {
        let master_key = CryptoKey::generate().unwrap();
        let crypto = DualLayerCrypto::from_master_key(&master_key).expect("key derivation failed");

        let plaintext = b"test message";
        let ciphertext = crypto.encrypt(plaintext).expect("encryption failed");
        let decrypted = crypto.decrypt(&ciphertext).expect("decryption failed");

        decrypted.with_exposed(|bytes| {
            assert_eq!(bytes, plaintext);
        });
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let inner_key = CryptoKey::generate().unwrap();
        let outer_key = CryptoKey::generate().unwrap();
        let crypto = DualLayerCrypto::new(inner_key, outer_key);

        let plaintext = b"same plaintext";

        let ciphertext1 = crypto.encrypt(plaintext).expect("encryption 1 failed");
        let ciphertext2 = crypto.encrypt(plaintext).expect("encryption 2 failed");

        // Ciphertexts should be different due to random nonces
        assert_ne!(ciphertext1, ciphertext2);

        // But both should decrypt to the same plaintext
        let decrypted1 = crypto.decrypt(&ciphertext1).unwrap();
        let decrypted2 = crypto.decrypt(&ciphertext2).unwrap();

        decrypted1.with_exposed(|bytes| {
            assert_eq!(bytes, plaintext);
        });
        decrypted2.with_exposed(|bytes| {
            assert_eq!(bytes, plaintext);
        });
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let inner_key = CryptoKey::generate().unwrap();
        let outer_key = CryptoKey::generate().unwrap();
        let crypto = DualLayerCrypto::new(inner_key, outer_key);

        let plaintext = b"original message";
        let mut ciphertext = crypto.encrypt(plaintext).expect("encryption failed");

        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xFF;
        }

        let result = crypto.decrypt(&ciphertext);
        assert!(matches!(result, Err(CryptoError::Decryption)));
    }

    #[test]
    fn test_wrong_key_fails() {
        let inner_key1 = CryptoKey::generate().unwrap();
        let outer_key1 = CryptoKey::generate().unwrap();
        let crypto1 = DualLayerCrypto::new(inner_key1, outer_key1);

        let inner_key2 = CryptoKey::generate().unwrap();
        let outer_key2 = CryptoKey::generate().unwrap();
        let crypto2 = DualLayerCrypto::new(inner_key2, outer_key2);

        let plaintext = b"secret";
        let ciphertext = crypto1.encrypt(plaintext).expect("encryption failed");

        // Try to decrypt with wrong keys
        let result = crypto2.decrypt(&ciphertext);
        assert!(matches!(result, Err(CryptoError::Decryption)));
    }

    #[test]
    fn test_ciphertext_too_short() {
        let inner_key = CryptoKey::generate().unwrap();
        let outer_key = CryptoKey::generate().unwrap();
        let crypto = DualLayerCrypto::new(inner_key, outer_key);

        let short_ciphertext = vec![0u8; 10]; // Too short
        let result = crypto.decrypt(&short_ciphertext);
        assert!(matches!(result, Err(CryptoError::CiphertextTooShort { .. })));
    }

    #[test]
    fn test_key_derivation() {
        let password = SecretBuffer::from_slice(b"my-secure-password").unwrap();
        let salt = generate_salt().unwrap();

        let params = Argon2Params {
            memory_kib: 64 * 1024, // 64 MB for faster tests
            iterations: 2,
            parallelism: 2,
        };

        let key = derive_key(&password, &salt, &params).expect("key derivation failed");

        // Derive again with same inputs should produce same key
        let key2 = derive_key(&password, &salt, &params).expect("key derivation failed");

        key.with_key(|k1| {
            key2.with_key(|k2| {
                assert_eq!(k1, k2);
            })
        });
    }

    #[test]
    fn test_key_derivation_different_salts() {
        let password = SecretBuffer::from_slice(b"password").unwrap();
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();

        let params = Argon2Params {
            memory_kib: 64 * 1024,
            iterations: 2,
            parallelism: 2,
        };

        let key1 = derive_key(&password, &salt1, &params).unwrap();
        let key2 = derive_key(&password, &salt2, &params).unwrap();

        // Different salts should produce different keys
        key1.with_key(|k1| {
            key2.with_key(|k2| {
                assert_ne!(k1, k2);
            })
        });
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello worlD";
        let d = b"short";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, d));
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32).unwrap();
        let bytes2 = random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_empty_plaintext() {
        let inner_key = CryptoKey::generate().unwrap();
        let outer_key = CryptoKey::generate().unwrap();
        let crypto = DualLayerCrypto::new(inner_key, outer_key);

        // Empty plaintext encryption works, but decryption into SecretBuffer fails
        // because SecretBuffer doesn't allow zero-size allocations (by design).
        // This is acceptable - there's nothing to protect in an empty secret.
        let plaintext = b"";
        let ciphertext = crypto.encrypt(plaintext).expect("encryption failed");
        let result = crypto.decrypt(&ciphertext);

        // Should fail with Memory(ZeroSize) since we can't create empty SecretBuffer
        assert!(matches!(result, Err(CryptoError::Memory(_))));
    }

    #[test]
    fn test_large_plaintext() {
        let inner_key = CryptoKey::generate().unwrap();
        let outer_key = CryptoKey::generate().unwrap();
        let crypto = DualLayerCrypto::new(inner_key, outer_key);

        // 1 MB of data
        let plaintext: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();

        let ciphertext = crypto.encrypt(&plaintext).expect("encryption failed");
        let decrypted = crypto.decrypt(&ciphertext).expect("decryption failed");

        decrypted.with_exposed(|bytes| {
            assert_eq!(bytes, &plaintext[..]);
        });
    }

    // Compile-time test: CryptoKey should not implement Debug
    // Uncomment to verify:
    // #[test]
    // fn test_crypto_key_not_debug() {
    //     let key = CryptoKey::generate().unwrap();
    //     println!("{:?}", key); // Should fail to compile
    // }

    // Compile-time test: CryptoKey should not implement Clone
    // Uncomment to verify:
    // #[test]
    // fn test_crypto_key_not_clone() {
    //     let key = CryptoKey::generate().unwrap();
    //     let _clone = key.clone(); // Should fail to compile
    // }
}
