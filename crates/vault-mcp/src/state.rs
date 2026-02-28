//! Vault state management for MCP server
//!
//! Maintains the unlocked vault state, encryption keys, and audit logger

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

use vault_core::{
    audit::AuditLogger,
    crypto::DerivedKeys,
    filter::OutputFilter,
    models::{VaultConfig, VaultData},
    storage,
    VaultError, VaultResult,
};

/// Unlocked vault state
pub struct UnlockedVault {
    /// Vault data (secrets metadata + encrypted values)
    pub data: VaultData,
    /// Derived encryption keys
    pub keys: DerivedKeys,
    /// Salt for key derivation
    pub salt: [u8; 32],
    /// Output filter with loaded secrets
    pub filter: OutputFilter,
    /// Last activity timestamp (for auto-lock)
    pub last_activity: Instant,
}

/// Vault state for MCP server
pub struct VaultState {
    /// Base directory for vault storage
    base_dir: PathBuf,
    /// Vault configuration
    config: VaultConfig,
    /// Unlocked vault (None if locked)
    vault: Option<UnlockedVault>,
    /// Audit logger
    audit_logger: AuditLogger,
    /// Auto-lock timeout
    auto_lock_timeout: Duration,
    /// Failed unlock attempts counter
    failed_attempts: u32,
    /// Lockout end time (if locked out)
    lockout_until: Option<Instant>,
}

impl VaultState {
    /// Create new vault state
    pub async fn new(base_dir: PathBuf) -> VaultResult<Self> {
        let config = storage::load_config(&base_dir).await.unwrap_or_default();
        let audit_logger = AuditLogger::new(&base_dir, None);
        let auto_lock_timeout = Duration::from_secs(config.auto_lock_timeout_seconds);

        Ok(Self {
            base_dir,
            config,
            vault: None,
            audit_logger,
            auto_lock_timeout,
            failed_attempts: 0,
            lockout_until: None,
        })
    }

    /// Check if vault exists
    pub async fn vault_exists(&self) -> bool {
        storage::vault_exists(&self.base_dir).await
    }

    /// Check if vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    /// Check if locked out due to failed attempts
    pub fn is_locked_out(&self) -> bool {
        if let Some(until) = self.lockout_until {
            Instant::now() < until
        } else {
            false
        }
    }

    /// Get remaining lockout seconds
    pub fn lockout_remaining_seconds(&self) -> u64 {
        if let Some(until) = self.lockout_until {
            let now = Instant::now();
            if now < until {
                return (until - now).as_secs();
            }
        }
        0
    }

    /// Create a new vault
    pub async fn create_vault(&mut self, password: &[u8]) -> VaultResult<()> {
        storage::create_vault(&self.base_dir, password, &self.config).await?;

        // Auto-unlock after creation
        self.unlock(password).await
    }

    /// Unlock the vault
    pub async fn unlock(&mut self, password: &[u8]) -> VaultResult<()> {
        // Check lockout
        if self.is_locked_out() {
            return Err(VaultError::LockedOut(self.lockout_remaining_seconds()));
        }

        // Try to load and decrypt vault
        match storage::load_vault(&self.base_dir, password, &self.config).await {
            Ok((data, keys)) => {
                // Get the salt from the encrypted vault file
                let vault_path = storage::vault_file_path(&self.base_dir);
                let encrypted = tokio::fs::read(&vault_path).await?;
                let encrypted_vault: vault_core::models::EncryptedVault =
                    serde_json::from_slice(&encrypted)?;
                let salt = encrypted_vault.salt;

                // Build output filter with loaded secrets
                let mut filter = OutputFilter::new();
                for (id, encrypted_value) in &data.encrypted_values {
                    // Decrypt the value to add to filter
                    if let Ok(value) = keys.decrypt(&encrypted_value.ciphertext, &encrypted_value.nonce) {
                        if let Some(entry) = data.find_by_id(id) {
                            let value_str = String::from_utf8_lossy(&value).to_string();
                            filter.add_secret(value_str, Some(entry.reference.clone()));
                        }
                    }
                }

                // Reset failed attempts on success
                self.failed_attempts = 0;
                self.lockout_until = None;

                // Set keys for audit logger
                let mut audit_keys = DerivedKeys::derive(password, &salt, &self.config)?;
                self.audit_logger.set_keys(audit_keys);

                self.vault = Some(UnlockedVault {
                    data,
                    keys,
                    salt,
                    filter,
                    last_activity: Instant::now(),
                });

                Ok(())
            }
            Err(e) => {
                // Increment failed attempts
                self.failed_attempts += 1;

                if self.failed_attempts >= self.config.max_unlock_attempts {
                    // Lock out
                    let lockout_duration = Duration::from_secs(self.config.lockout_duration_seconds);
                    self.lockout_until = Some(Instant::now() + lockout_duration);
                }

                Err(VaultError::InvalidPassword)
            }
        }
    }

    /// Lock the vault
    pub fn lock(&mut self) {
        self.vault = None;
        self.audit_logger.clear_keys();
    }

    /// Touch activity (reset auto-lock timer)
    pub fn touch(&mut self) {
        if let Some(ref mut vault) = self.vault {
            vault.last_activity = Instant::now();
        }
    }

    /// Check if auto-lock is due
    pub fn should_auto_lock(&self) -> bool {
        if let Some(ref vault) = self.vault {
            vault.last_activity.elapsed() > self.auto_lock_timeout
        } else {
            false
        }
    }

    /// Get vault data (if unlocked)
    pub fn data(&self) -> VaultResult<&VaultData> {
        self.vault
            .as_ref()
            .map(|v| &v.data)
            .ok_or(VaultError::VaultLocked)
    }

    /// Get mutable vault data (if unlocked)
    pub fn data_mut(&mut self) -> VaultResult<&mut VaultData> {
        self.vault
            .as_mut()
            .map(|v| &mut v.data)
            .ok_or(VaultError::VaultLocked)
    }

    /// Get keys (if unlocked)
    pub fn keys(&self) -> VaultResult<&DerivedKeys> {
        self.vault
            .as_ref()
            .map(|v| &v.keys)
            .ok_or(VaultError::VaultLocked)
    }

    /// Get output filter (if unlocked)
    pub fn filter(&self) -> VaultResult<&OutputFilter> {
        self.vault
            .as_ref()
            .map(|v| &v.filter)
            .ok_or(VaultError::VaultLocked)
    }

    /// Get mutable output filter (if unlocked)
    pub fn filter_mut(&mut self) -> VaultResult<&mut OutputFilter> {
        self.vault
            .as_mut()
            .map(|v| &mut v.filter)
            .ok_or(VaultError::VaultLocked)
    }

    /// Get audit logger
    pub fn audit_logger(&self) -> &AuditLogger {
        &self.audit_logger
    }

    /// Save vault data
    pub async fn save(&self) -> VaultResult<()> {
        let vault = self.vault.as_ref().ok_or(VaultError::VaultLocked)?;

        storage::save_vault(&self.base_dir, &vault.data, &vault.keys, &vault.salt).await
    }

    /// Get a decrypted secret value by reference
    pub fn get_secret_value(&self, reference: &str) -> VaultResult<String> {
        let vault = self.vault.as_ref().ok_or(VaultError::VaultLocked)?;

        let entry = vault
            .data
            .find_by_reference(reference)
            .ok_or_else(|| VaultError::SecretNotFound(reference.to_string()))?;

        let encrypted_value = vault
            .data
            .encrypted_values
            .get(&entry.id)
            .ok_or_else(|| VaultError::SecretNotFound(reference.to_string()))?;

        let decrypted = vault.keys.decrypt(&encrypted_value.ciphertext, &encrypted_value.nonce)?;

        String::from_utf8(decrypted)
            .map_err(|_| VaultError::DecryptionError("Invalid UTF-8 in secret value".to_string()))
    }

    /// Get secret ID by reference
    pub fn get_secret_id(&self, reference: &str) -> VaultResult<Uuid> {
        let vault = self.vault.as_ref().ok_or(VaultError::VaultLocked)?;

        vault
            .data
            .find_by_reference(reference)
            .map(|e| e.id)
            .ok_or_else(|| VaultError::SecretNotFound(reference.to_string()))
    }

    /// Get vault config
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// Get base directory
    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }
}

/// Thread-safe vault state wrapper
pub type SharedVaultState = Arc<RwLock<VaultState>>;

/// Create a new shared vault state
pub async fn create_shared_state(base_dir: PathBuf) -> VaultResult<SharedVaultState> {
    let state = VaultState::new(base_dir).await?;
    Ok(Arc::new(RwLock::new(state)))
}
