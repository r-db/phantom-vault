//! Cryptographic operations for vault security
//!
//! - AES-256-GCM for symmetric encryption
//! - Argon2id for password-based key derivation
//! - Secure memory handling with zeroization

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Params, Version};
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{VaultError, VaultResult};
use crate::models::VaultConfig;

/// Size of AES-256 key in bytes
pub const KEY_SIZE: usize = 32;

/// Size of AES-GCM nonce in bytes
pub const NONCE_SIZE: usize = 12;

/// Size of Argon2 salt in bytes
pub const SALT_SIZE: usize = 32;

/// Derived keys from master password
/// Contains separate keys for vault encryption, HMAC, and audit log
pub struct DerivedKeys {
    /// Key for encrypting vault data
    vault_key: Secret<[u8; KEY_SIZE]>,
    /// Key for HMAC operations
    hmac_key: Secret<[u8; KEY_SIZE]>,
    /// Key for encrypting audit log
    audit_key: Secret<[u8; KEY_SIZE]>,
}

impl DerivedKeys {
    /// Derive keys from master password using Argon2id
    ///
    /// Uses recommended parameters for interactive use:
    /// - Memory: 64 MB
    /// - Iterations: 3
    /// - Parallelism: 4
    pub fn derive(password: &[u8], salt: &[u8; SALT_SIZE], config: &VaultConfig) -> VaultResult<Self> {
        let params = Params::new(
            config.argon2_memory_kb,
            config.argon2_iterations,
            config.argon2_parallelism,
            Some(96), // Output 96 bytes (3 x 32-byte keys)
        )
        .map_err(|e| VaultError::KeyDerivationError(e.to_string()))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let mut output = [0u8; 96];
        argon2
            .hash_password_into(password, salt, &mut output)
            .map_err(|e| VaultError::KeyDerivationError(e.to_string()))?;

        let mut vault_key = [0u8; KEY_SIZE];
        let mut hmac_key = [0u8; KEY_SIZE];
        let mut audit_key = [0u8; KEY_SIZE];

        vault_key.copy_from_slice(&output[0..32]);
        hmac_key.copy_from_slice(&output[32..64]);
        audit_key.copy_from_slice(&output[64..96]);

        // Zeroize intermediate buffer
        output.zeroize();

        Ok(Self {
            vault_key: Secret::new(vault_key),
            hmac_key: Secret::new(hmac_key),
            audit_key: Secret::new(audit_key),
        })
    }

    /// Encrypt data using AES-256-GCM with vault key
    pub fn encrypt(&self, plaintext: &[u8]) -> VaultResult<(Vec<u8>, [u8; NONCE_SIZE])> {
        let cipher = Aes256Gcm::new_from_slice(self.vault_key.expose_secret())
            .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

        Ok((ciphertext, nonce_bytes))
    }

    /// Decrypt data using AES-256-GCM with vault key
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; NONCE_SIZE]) -> VaultResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(self.vault_key.expose_secret())
            .map_err(|e| VaultError::DecryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| VaultError::DecryptionError("Decryption failed - wrong password or corrupted data".to_string()))?;

        Ok(plaintext)
    }

    /// Encrypt data for audit log (separate key)
    pub fn encrypt_audit(&self, plaintext: &[u8]) -> VaultResult<(Vec<u8>, [u8; NONCE_SIZE])> {
        let cipher = Aes256Gcm::new_from_slice(self.audit_key.expose_secret())
            .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

        Ok((ciphertext, nonce_bytes))
    }

    /// Decrypt audit log data
    pub fn decrypt_audit(&self, ciphertext: &[u8], nonce: &[u8; NONCE_SIZE]) -> VaultResult<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(self.audit_key.expose_secret())
            .map_err(|e| VaultError::DecryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| VaultError::DecryptionError("Audit log decryption failed".to_string()))?;

        Ok(plaintext)
    }

    /// Get HMAC key for additional integrity checks
    pub fn hmac_key(&self) -> &[u8; KEY_SIZE] {
        self.hmac_key.expose_secret()
    }
}

/// Generate a cryptographically secure random salt
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a cryptographically secure random nonce
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Compute SHA-256 checksum of data
pub fn compute_checksum(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Verify SHA-256 checksum
pub fn verify_checksum(data: &[u8], expected: &[u8; 32]) -> bool {
    let computed = compute_checksum(data);
    constant_time_compare(&computed, expected)
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Encrypt a single secret value
pub fn encrypt_value(keys: &DerivedKeys, value: &[u8]) -> VaultResult<(Vec<u8>, [u8; NONCE_SIZE])> {
    keys.encrypt(value)
}

/// Decrypt a single secret value
pub fn decrypt_value(keys: &DerivedKeys, ciphertext: &[u8], nonce: &[u8; NONCE_SIZE]) -> VaultResult<Vec<u8>> {
    keys.decrypt(ciphertext, nonce)
}

/// Securely clear a byte slice
pub fn secure_clear(data: &mut [u8]) {
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let password = b"test-password-123";
        let salt = generate_salt();
        let config = VaultConfig::default();

        let keys = DerivedKeys::derive(password, &salt, &config).unwrap();

        // Derive again with same inputs - should produce same keys
        let keys2 = DerivedKeys::derive(password, &salt, &config).unwrap();

        assert_eq!(
            keys.vault_key.expose_secret(),
            keys2.vault_key.expose_secret()
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = b"test-password";
        let salt = generate_salt();
        let config = VaultConfig::default();
        let keys = DerivedKeys::derive(password, &salt, &config).unwrap();

        let plaintext = b"Hello, secure world!";
        let (ciphertext, nonce) = keys.encrypt(plaintext).unwrap();

        let decrypted = keys.decrypt(&ciphertext, &nonce).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_password_fails() {
        let salt = generate_salt();
        let config = VaultConfig::default();

        let keys1 = DerivedKeys::derive(b"password1", &salt, &config).unwrap();
        let keys2 = DerivedKeys::derive(b"password2", &salt, &config).unwrap();

        let plaintext = b"Secret data";
        let (ciphertext, nonce) = keys1.encrypt(plaintext).unwrap();

        // Decrypting with wrong key should fail
        let result = keys2.decrypt(&ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_checksum() {
        let data = b"Some important data";
        let checksum = compute_checksum(data);

        assert!(verify_checksum(data, &checksum));
        assert!(!verify_checksum(b"Different data", &checksum));
    }

    #[test]
    fn test_nonce_uniqueness() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_salt_uniqueness() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1, salt2);
    }
}
