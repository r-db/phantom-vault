//! Vault operations for managing encrypted secret storage.
//!
//! The vault is the primary interface for interacting with secrets. It provides
//! methods to open, seal, and perform CRUD operations on secrets while ensuring
//! all data remains encrypted at rest.

use crate::crypto::{derive_key, generate_salt, Argon2Params, DualLayerCrypto};
use crate::memory::SecretBuffer;
use crate::namespace::Namespace;
use crate::storage::{SecretMetadata, SecretStore, StorageError};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info};

/// Errors that can occur during vault operations.
#[derive(Debug, Error)]
pub enum VaultError {
    /// The vault is sealed and cannot perform operations.
    #[error("vault is sealed")]
    Sealed,

    /// The vault is already open.
    #[error("vault is already open")]
    AlreadyOpen,

    /// The specified secret was not found.
    #[error("secret not found: {0}")]
    SecretNotFound(String),

    /// Authentication failed (wrong password/key).
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Storage error occurred.
    #[error("storage error: {0}")]
    Storage(String),

    /// Cryptographic error occurred.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// I/O error occurred.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<StorageError> for VaultError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::NotFound(name) => VaultError::SecretNotFound(name),
            StorageError::Crypto(e) => VaultError::Crypto(e),
            StorageError::Io(e) => VaultError::Io(e),
            _ => VaultError::Storage(err.to_string()),
        }
    }
}

impl From<crate::crypto::CryptoError> for VaultError {
    fn from(err: crate::crypto::CryptoError) -> Self {
        VaultError::Crypto(err.to_string())
    }
}

impl From<std::io::Error> for VaultError {
    fn from(err: std::io::Error) -> Self {
        VaultError::Io(err.to_string())
    }
}

/// Result type for vault operations.
pub type VaultResult<T> = Result<T, VaultError>;

/// Configuration for vault Argon2 parameters.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Argon2id parameters for key derivation.
    pub argon2_params: Argon2Params,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            argon2_params: Argon2Params::default(),
        }
    }
}

/// Salt file contents.
const SALT_FILE_NAME: &str = ".salt";
/// Auth check file - encrypted known value to verify password.
const AUTH_CHECK_FILE_NAME: &str = ".auth";
/// Known plaintext for auth verification.
const AUTH_CHECK_PLAINTEXT: &[u8] = b"phantom-vault-auth-check-v1";

/// A secure vault for storing and managing secrets.
///
/// The vault maintains an encrypted store of secrets and provides
/// controlled access through authentication.
pub struct Vault {
    path: PathBuf,
    store: Option<SecretStore>,
    crypto: Option<DualLayerCrypto>,
    namespace: Namespace,
    config: VaultConfig,
}

impl Vault {
    /// Create a new vault instance.
    ///
    /// The vault starts in a sealed state and must be opened with
    /// valid credentials before secrets can be accessed.
    pub fn new(path: &Path) -> VaultResult<Self> {
        Self::with_config(path, VaultConfig::default())
    }

    /// Create a new vault with custom configuration.
    pub fn with_config(path: &Path, config: VaultConfig) -> VaultResult<Self> {
        // Create vault directory if it doesn't exist
        if !path.exists() {
            std::fs::create_dir_all(path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            }
        }

        Ok(Self {
            path: path.to_path_buf(),
            store: None,
            crypto: None,
            namespace: Namespace::default(),
            config,
        })
    }

    /// Initialize a new vault with a master password.
    ///
    /// This creates the vault directory structure, generates a salt,
    /// and stores an encrypted auth check value.
    pub fn init(&mut self, password: &SecretBuffer) -> VaultResult<()> {
        if self.is_open() {
            return Err(VaultError::AlreadyOpen);
        }

        let salt_path = self.path.join(SALT_FILE_NAME);
        if salt_path.exists() {
            return Err(VaultError::Storage(
                "vault already initialized (salt file exists)".to_string(),
            ));
        }

        // Generate and save salt
        let salt = generate_salt()?;
        std::fs::write(&salt_path, salt)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&salt_path, std::fs::Permissions::from_mode(0o600))?;
        }

        // Derive master key
        let master_key = derive_key(password, &salt, &self.config.argon2_params)?;
        let crypto = DualLayerCrypto::from_master_key(&master_key)?;

        // Create auth check file
        let auth_check = crypto.encrypt(AUTH_CHECK_PLAINTEXT)?;
        let auth_path = self.path.join(AUTH_CHECK_FILE_NAME);
        std::fs::write(&auth_path, auth_check)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&auth_path, std::fs::Permissions::from_mode(0o600))?;
        }

        // Open the store
        let db_path = self.path.join("secrets.db");
        let store = SecretStore::open(&db_path, crypto)?;

        // Derive a new crypto instance for the vault (we gave the first one to the store)
        let crypto = DualLayerCrypto::from_master_key(&master_key)?;

        self.store = Some(store);
        self.crypto = Some(crypto);

        info!("Initialized new vault at {:?}", self.path);
        Ok(())
    }

    /// Open the vault with the given master password.
    ///
    /// This derives the encryption key using Argon2id and unlocks
    /// the vault for secret operations.
    pub fn open(&mut self, password: &SecretBuffer) -> VaultResult<()> {
        if self.is_open() {
            return Err(VaultError::AlreadyOpen);
        }

        // Read salt
        let salt_path = self.path.join(SALT_FILE_NAME);
        let salt = std::fs::read(&salt_path).map_err(|_| {
            VaultError::Storage("vault not initialized (salt file missing)".to_string())
        })?;

        // Derive master key
        let master_key = derive_key(password, &salt, &self.config.argon2_params)?;
        let crypto = DualLayerCrypto::from_master_key(&master_key)?;

        // Verify auth check
        let auth_path = self.path.join(AUTH_CHECK_FILE_NAME);
        let auth_check = std::fs::read(&auth_path).map_err(|_| {
            VaultError::Storage("vault not initialized (auth file missing)".to_string())
        })?;

        let decrypted = crypto.decrypt(&auth_check).map_err(|_| {
            VaultError::AuthenticationFailed
        })?;

        decrypted.with_exposed(|bytes| {
            if bytes != AUTH_CHECK_PLAINTEXT {
                return Err(VaultError::AuthenticationFailed);
            }
            Ok(())
        })?;

        // Open the store
        let db_path = self.path.join("secrets.db");
        let store = SecretStore::open(&db_path, crypto)?;

        // Derive a new crypto instance for the vault
        let crypto = DualLayerCrypto::from_master_key(&master_key)?;

        self.store = Some(store);
        self.crypto = Some(crypto);

        info!("Opened vault at {:?}", self.path);
        Ok(())
    }

    /// Seal the vault, clearing all sensitive data from memory.
    ///
    /// After sealing, the vault cannot perform operations until
    /// reopened with valid credentials.
    pub fn seal(&mut self) -> VaultResult<()> {
        if !self.is_open() {
            return Err(VaultError::Sealed);
        }

        // Drop store and crypto to zeroize keys
        self.store = None;
        self.crypto = None;

        debug!("Sealed vault at {:?}", self.path);
        Ok(())
    }

    /// Check if the vault is currently open.
    pub fn is_open(&self) -> bool {
        self.store.is_some() && self.crypto.is_some()
    }

    /// Get a secret by name.
    ///
    /// Returns the secret value in a secure buffer that will be
    /// automatically zeroized when dropped.
    pub fn get(&self, name: &str) -> VaultResult<SecretBuffer> {
        let store = self.store.as_ref().ok_or(VaultError::Sealed)?;
        let namespace = self.namespace.name();
        store.get(namespace, name).map_err(VaultError::from)
    }

    /// Get a secret with its metadata.
    pub fn get_with_metadata(&self, name: &str) -> VaultResult<(SecretBuffer, SecretMetadata)> {
        let store = self.store.as_ref().ok_or(VaultError::Sealed)?;
        let namespace = self.namespace.name();
        let value = store.get(namespace, name)?;
        let metadata = store.metadata(namespace, name)?;
        Ok((value, metadata))
    }

    /// Set a secret value.
    ///
    /// If the secret already exists, it will be updated.
    pub fn set(&mut self, name: &str, value: &SecretBuffer) -> VaultResult<()> {
        let store = self.store.as_mut().ok_or(VaultError::Sealed)?;
        let namespace = self.namespace.name();
        store.put(namespace, name, value)?;
        Ok(())
    }

    /// Set a secret with expiration.
    pub fn set_with_expiry(
        &mut self,
        name: &str,
        value: &SecretBuffer,
        expires_at: u64,
    ) -> VaultResult<()> {
        let store = self.store.as_mut().ok_or(VaultError::Sealed)?;
        let namespace = self.namespace.name();
        store.put_with_metadata(namespace, name, value, Some(expires_at), false)?;
        Ok(())
    }

    /// Delete a secret.
    pub fn delete(&mut self, name: &str) -> VaultResult<()> {
        let store = self.store.as_mut().ok_or(VaultError::Sealed)?;
        let namespace = self.namespace.name();
        store.delete(namespace, name)?;
        Ok(())
    }

    /// List all secret names in the current namespace.
    ///
    /// This does not return secret values, only their identifiers.
    pub fn list(&self) -> VaultResult<Vec<String>> {
        let store = self.store.as_ref().ok_or(VaultError::Sealed)?;
        let namespace = self.namespace.name();
        let metadata = store.list(namespace)?;
        Ok(metadata.into_iter().map(|m| m.name).collect())
    }

    /// List all secrets with metadata in the current namespace.
    pub fn list_with_metadata(&self) -> VaultResult<Vec<SecretMetadata>> {
        let store = self.store.as_ref().ok_or(VaultError::Sealed)?;
        let namespace = self.namespace.name();
        store.list(namespace).map_err(VaultError::from)
    }

    /// Check if a secret exists.
    pub fn exists(&self, name: &str) -> VaultResult<bool> {
        let store = self.store.as_ref().ok_or(VaultError::Sealed)?;
        let namespace = self.namespace.name();
        store.exists(namespace, name).map_err(VaultError::from)
    }

    /// Get the current namespace.
    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// Switch to a different namespace.
    pub fn switch_namespace(&mut self, namespace: Namespace) {
        self.namespace = namespace;
    }

    /// Get the vault path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get secrets expiring before a given timestamp.
    pub fn get_expiring(&self, before: u64) -> VaultResult<Vec<SecretMetadata>> {
        let store = self.store.as_ref().ok_or(VaultError::Sealed)?;
        store.get_expiring(before).map_err(VaultError::from)
    }

    /// Get the number of secrets in the current namespace.
    pub fn count(&self) -> VaultResult<usize> {
        let store = self.store.as_ref().ok_or(VaultError::Sealed)?;
        let namespace = self.namespace.name();
        store.count_in_namespace(namespace).map_err(VaultError::from)
    }

    /// Get the total number of secrets across all namespaces.
    pub fn total_count(&self) -> VaultResult<usize> {
        let store = self.store.as_ref().ok_or(VaultError::Sealed)?;
        store.count().map_err(VaultError::from)
    }

    /// Compact the vault storage.
    pub fn compact(&mut self) -> VaultResult<()> {
        let store = self.store.as_mut().ok_or(VaultError::Sealed)?;
        store.compact()?;
        Ok(())
    }

    /// Check if the vault is initialized (has salt and auth files).
    pub fn is_initialized(&self) -> bool {
        let salt_path = self.path.join(SALT_FILE_NAME);
        let auth_path = self.path.join(AUTH_CHECK_FILE_NAME);
        salt_path.exists() && auth_path.exists()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        // Ensure crypto is zeroized on drop
        let _ = self.seal();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_vault() -> (Vault, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");

        // Use faster Argon2 params for tests
        let config = VaultConfig {
            argon2_params: Argon2Params {
                memory_kib: 64 * 1024, // 64 MB
                iterations: 2,
                parallelism: 2,
            },
        };

        let vault = Vault::with_config(&vault_path, config).unwrap();
        (vault, temp_dir)
    }

    #[test]
    fn test_vault_creation() {
        let (vault, _temp) = create_test_vault();
        assert!(!vault.is_open());
        assert!(!vault.is_initialized());
    }

    #[test]
    fn test_vault_init_and_open() {
        let (mut vault, _temp) = create_test_vault();
        let password = SecretBuffer::from_slice(b"test_password").unwrap();

        // Initialize
        vault.init(&password).unwrap();
        assert!(vault.is_open());
        assert!(vault.is_initialized());

        // Seal
        vault.seal().unwrap();
        assert!(!vault.is_open());

        // Reopen
        vault.open(&password).unwrap();
        assert!(vault.is_open());
    }

    #[test]
    fn test_vault_wrong_password() {
        let (mut vault, _temp) = create_test_vault();
        let password = SecretBuffer::from_slice(b"correct_password").unwrap();
        let wrong_password = SecretBuffer::from_slice(b"wrong_password").unwrap();

        vault.init(&password).unwrap();
        vault.seal().unwrap();

        let result = vault.open(&wrong_password);
        assert!(matches!(result, Err(VaultError::AuthenticationFailed)));
    }

    #[test]
    fn test_vault_operations() {
        let (mut vault, _temp) = create_test_vault();
        let password = SecretBuffer::from_slice(b"password").unwrap();

        vault.init(&password).unwrap();

        // Set a secret
        let secret = SecretBuffer::from_slice(b"my_secret_value").unwrap();
        vault.set("API_KEY", &secret).unwrap();

        // Get the secret
        let retrieved = vault.get("API_KEY").unwrap();
        retrieved.with_exposed(|bytes| {
            assert_eq!(bytes, b"my_secret_value");
        });

        // Check exists
        assert!(vault.exists("API_KEY").unwrap());
        assert!(!vault.exists("NONEXISTENT").unwrap());

        // List secrets
        let secrets = vault.list().unwrap();
        assert_eq!(secrets, vec!["API_KEY"]);

        // Delete secret
        vault.delete("API_KEY").unwrap();
        assert!(!vault.exists("API_KEY").unwrap());
    }

    #[test]
    fn test_vault_sealed_operations() {
        let (mut vault, _temp) = create_test_vault();
        let password = SecretBuffer::from_slice(b"password").unwrap();

        vault.init(&password).unwrap();
        vault.seal().unwrap();

        // All operations should fail when sealed
        assert!(matches!(vault.get("KEY"), Err(VaultError::Sealed)));
        assert!(matches!(vault.list(), Err(VaultError::Sealed)));
        assert!(matches!(vault.exists("KEY"), Err(VaultError::Sealed)));

        let secret = SecretBuffer::from_slice(b"value").unwrap();
        assert!(matches!(vault.set("KEY", &secret), Err(VaultError::Sealed)));
        assert!(matches!(vault.delete("KEY"), Err(VaultError::Sealed)));
    }

    #[test]
    fn test_vault_already_open() {
        let (mut vault, _temp) = create_test_vault();
        let password = SecretBuffer::from_slice(b"password").unwrap();

        vault.init(&password).unwrap();

        let result = vault.open(&password);
        assert!(matches!(result, Err(VaultError::AlreadyOpen)));
    }

    #[test]
    fn test_vault_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path().join("vault");
        let password = SecretBuffer::from_slice(b"password").unwrap();

        // Create and initialize vault
        {
            let config = VaultConfig {
                argon2_params: Argon2Params {
                    memory_kib: 64 * 1024,
                    iterations: 2,
                    parallelism: 2,
                },
            };
            let mut vault = Vault::with_config(&vault_path, config).unwrap();
            vault.init(&password).unwrap();

            let secret = SecretBuffer::from_slice(b"persistent_secret").unwrap();
            vault.set("PERSIST_KEY", &secret).unwrap();
        }

        // Reopen and verify
        {
            let config = VaultConfig {
                argon2_params: Argon2Params {
                    memory_kib: 64 * 1024,
                    iterations: 2,
                    parallelism: 2,
                },
            };
            let mut vault = Vault::with_config(&vault_path, config).unwrap();
            vault.open(&password).unwrap();

            let retrieved = vault.get("PERSIST_KEY").unwrap();
            retrieved.with_exposed(|bytes| {
                assert_eq!(bytes, b"persistent_secret");
            });
        }
    }

    #[test]
    fn test_vault_count() {
        let (mut vault, _temp) = create_test_vault();
        let password = SecretBuffer::from_slice(b"password").unwrap();

        vault.init(&password).unwrap();

        assert_eq!(vault.count().unwrap(), 0);

        let secret = SecretBuffer::from_slice(b"value").unwrap();
        vault.set("KEY1", &secret).unwrap();
        vault.set("KEY2", &secret).unwrap();

        assert_eq!(vault.count().unwrap(), 2);
    }

    #[test]
    fn test_vault_secret_not_found() {
        let (mut vault, _temp) = create_test_vault();
        let password = SecretBuffer::from_slice(b"password").unwrap();

        vault.init(&password).unwrap();

        let result = vault.get("NONEXISTENT");
        assert!(matches!(result, Err(VaultError::SecretNotFound(_))));
    }
}
