//! Tauri commands for vault operations
//!
//! These commands are exposed to the Flutter frontend via Tauri IPC.
//! All functions are designed to be wrapped as `#[tauri::command]` when
//! the Tauri app shell is created.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use vault_core::{
    crypto::{decrypt_value, encrypt_value, DerivedKeys},
    models::{EncryptedValue, SecretEntry, SecretType, VaultConfig, VaultData},
    storage,
    VaultError, VaultResult,
};

/// Shared app state managed by Tauri
pub struct AppState {
    /// Vault directory
    pub vault_dir: PathBuf,
    /// Vault data (when unlocked)
    pub vault_data: Option<VaultData>,
    /// Derived keys (when unlocked)
    pub keys: Option<DerivedKeys>,
    /// Salt for key derivation
    pub salt: Option<[u8; 32]>,
    /// Configuration
    pub config: VaultConfig,
    /// Failed unlock attempts counter
    pub failed_attempts: u32,
    /// Lockout until timestamp
    pub lockout_until: Option<std::time::Instant>,
}

impl AppState {
    /// Create new app state with default vault directory
    pub fn new() -> Self {
        Self {
            vault_dir: storage::default_vault_dir(),
            vault_data: None,
            keys: None,
            salt: None,
            config: VaultConfig::default(),
            failed_attempts: 0,
            lockout_until: None,
        }
    }

    /// Check if vault is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.vault_data.is_some() && self.keys.is_some()
    }

    /// Check if locked out due to too many failed attempts
    pub fn is_locked_out(&self) -> bool {
        if let Some(until) = self.lockout_until {
            std::time::Instant::now() < until
        } else {
            false
        }
    }

    /// Clear sensitive data (lock the vault)
    pub fn lock(&mut self) {
        self.vault_data = None;
        self.keys = None;
        self.salt = None;
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Command result wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> CommandResult<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

/// Secret info for UI display (no sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInfo {
    pub id: String,
    pub reference: String,
    pub secret_type: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
    pub days_until_expiration: Option<i64>,
    pub is_expired: bool,
    pub needs_rotation: bool,
    pub usage_count: u64,
    pub usage_limit: Option<u64>,
    pub is_usage_exceeded: bool,
}

impl From<&SecretEntry> for SecretInfo {
    fn from(entry: &SecretEntry) -> Self {
        Self {
            id: entry.id.to_string(),
            reference: entry.reference.clone(),
            secret_type: format!("{:?}", entry.secret_type)
                .split('{')
                .next()
                .unwrap_or("Unknown")
                .trim()
                .to_string(),
            description: entry.description.clone(),
            tags: entry.tags.clone(),
            created_at: entry.created_at.to_rfc3339(),
            updated_at: entry.updated_at.to_rfc3339(),
            expires_at: entry.expires_at.map(|d| d.to_rfc3339()),
            days_until_expiration: entry.days_until_expiration(),
            is_expired: entry.is_expired(),
            needs_rotation: entry.needs_rotation(),
            usage_count: entry.usage_count,
            usage_limit: entry.usage_limit,
            is_usage_exceeded: entry.is_usage_exceeded(),
        }
    }
}

/// Vault status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    pub exists: bool,
    pub unlocked: bool,
    pub secret_count: usize,
    pub expired_count: usize,
    pub rotation_due_count: usize,
}

// Note: These functions are designed to be wrapped as Tauri commands.
// When Tauri is set up, they will be annotated with #[tauri::command]

/// Check if vault exists
pub async fn vault_exists(vault_dir: &PathBuf) -> bool {
    storage::vault_exists(vault_dir).await
}

/// Create a new vault
pub async fn create_vault(
    vault_dir: &PathBuf,
    password: &str,
) -> VaultResult<()> {
    let config = VaultConfig::default();
    storage::create_vault(vault_dir, password.as_bytes(), &config).await
}

/// Unlock the vault
pub async fn unlock_vault(
    vault_dir: &PathBuf,
    password: &str,
    config: &VaultConfig,
) -> VaultResult<(VaultData, vault_core::crypto::DerivedKeys, [u8; 32])> {
    let (data, keys) = storage::load_vault(vault_dir, password.as_bytes(), config).await?;

    // Get salt from encrypted vault
    let vault_path = storage::vault_file_path(vault_dir);
    let encrypted = tokio::fs::read(&vault_path).await?;
    let encrypted_vault: vault_core::models::EncryptedVault =
        serde_json::from_slice(&encrypted)?;

    Ok((data, keys, encrypted_vault.salt))
}

/// List all secrets
pub fn list_secrets(vault_data: &VaultData) -> Vec<SecretInfo> {
    vault_data
        .entries
        .iter()
        .map(SecretInfo::from)
        .collect()
}

/// Get secret info by reference
pub fn get_secret_info(vault_data: &VaultData, reference: &str) -> Option<SecretInfo> {
    vault_data
        .find_by_reference(reference)
        .map(SecretInfo::from)
}

/// Get vault status
pub fn get_vault_status(vault_data: Option<&VaultData>, exists: bool) -> VaultStatus {
    match vault_data {
        Some(data) => {
            let expired_count = data.entries.iter().filter(|e| e.is_expired()).count();
            let rotation_due_count = data.entries.iter().filter(|e| e.needs_rotation()).count();

            VaultStatus {
                exists,
                unlocked: true,
                secret_count: data.entries.len(),
                expired_count,
                rotation_due_count,
            }
        }
        None => VaultStatus {
            exists,
            unlocked: false,
            secret_count: 0,
            expired_count: 0,
            rotation_due_count: 0,
        },
    }
}

// ============================================================================
// SECRET CRUD OPERATIONS
// ============================================================================

/// Input for adding a new secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddSecretInput {
    pub reference: String,
    pub secret_type: SecretType,
    pub value: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub expires_at: Option<String>,
    pub rotation_reminder_days: Option<u32>,
    pub allowed_tools: Vec<String>,
}

/// Add a new secret to the vault
pub fn add_secret(
    vault_data: &mut VaultData,
    keys: &DerivedKeys,
    input: AddSecretInput,
) -> VaultResult<SecretInfo> {
    // Check if reference already exists
    if vault_data.reference_exists(&input.reference) {
        return Err(VaultError::DuplicateReference(input.reference));
    }

    // Create entry
    let mut entry = SecretEntry::new(input.reference, input.secret_type);
    entry.description = input.description;
    entry.tags = input.tags;
    entry.allowed_tools = input.allowed_tools;

    // Parse expiration date if provided
    if let Some(exp_str) = input.expires_at {
        entry.expires_at = chrono::DateTime::parse_from_rfc3339(&exp_str)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc));
    }

    entry.rotation_reminder_days = input.rotation_reminder_days;

    // Encrypt the secret value
    let (ciphertext, nonce) = encrypt_value(keys, input.value.as_bytes())?;
    let encrypted_value = EncryptedValue { nonce, ciphertext };

    // Store encrypted value
    vault_data.encrypted_values.insert(entry.id, encrypted_value);

    // Create info before moving entry
    let info = SecretInfo::from(&entry);

    // Add entry
    vault_data.entries.push(entry);

    Ok(info)
}

/// Delete a secret by reference
pub fn delete_secret(vault_data: &mut VaultData, reference: &str) -> VaultResult<()> {
    let id = vault_data
        .find_by_reference(reference)
        .map(|e| e.id)
        .ok_or_else(|| VaultError::SecretNotFound(reference.to_string()))?;

    // Remove encrypted value
    vault_data.encrypted_values.remove(&id);

    // Remove entry
    vault_data.entries.retain(|e| e.id != id);

    Ok(())
}

/// Delete a secret by ID
pub fn delete_secret_by_id(vault_data: &mut VaultData, id: &Uuid) -> VaultResult<()> {
    if !vault_data.entries.iter().any(|e| &e.id == id) {
        return Err(VaultError::SecretNotFound(id.to_string()));
    }

    vault_data.encrypted_values.remove(id);
    vault_data.entries.retain(|e| &e.id != id);

    Ok(())
}

/// Input for updating a secret's metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSecretInput {
    pub reference: String,
    pub new_reference: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub expires_at: Option<String>,
    pub rotation_reminder_days: Option<u32>,
    pub allowed_tools: Option<Vec<String>>,
}

/// Update secret metadata (not the value)
pub fn update_secret(
    vault_data: &mut VaultData,
    input: UpdateSecretInput,
) -> VaultResult<SecretInfo> {
    // Find entry index
    let idx = vault_data
        .entries
        .iter()
        .position(|e| e.reference == input.reference)
        .ok_or_else(|| VaultError::SecretNotFound(input.reference.clone()))?;

    // Check new reference doesn't conflict
    if let Some(ref new_ref) = input.new_reference {
        if new_ref != &input.reference && vault_data.reference_exists(new_ref) {
            return Err(VaultError::DuplicateReference(new_ref.clone()));
        }
    }

    let entry = &mut vault_data.entries[idx];

    // Update fields
    if let Some(new_ref) = input.new_reference {
        entry.reference = new_ref;
    }
    if let Some(desc) = input.description {
        entry.description = Some(desc);
    }
    if let Some(tags) = input.tags {
        entry.tags = tags;
    }
    if let Some(exp_str) = input.expires_at {
        entry.expires_at = chrono::DateTime::parse_from_rfc3339(&exp_str)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc));
    }
    if let Some(days) = input.rotation_reminder_days {
        entry.rotation_reminder_days = Some(days);
    }
    if let Some(tools) = input.allowed_tools {
        entry.allowed_tools = tools;
    }

    entry.updated_at = chrono::Utc::now();

    Ok(SecretInfo::from(&vault_data.entries[idx]))
}

/// Update a secret's value (rotate)
pub fn update_secret_value(
    vault_data: &mut VaultData,
    keys: &DerivedKeys,
    reference: &str,
    new_value: &str,
) -> VaultResult<()> {
    let entry = vault_data
        .entries
        .iter_mut()
        .find(|e| e.reference == reference)
        .ok_or_else(|| VaultError::SecretNotFound(reference.to_string()))?;

    // Encrypt new value
    let (ciphertext, nonce) = encrypt_value(keys, new_value.as_bytes())?;
    let encrypted_value = EncryptedValue { nonce, ciphertext };

    // Update
    vault_data.encrypted_values.insert(entry.id, encrypted_value);
    entry.last_rotated_at = Some(chrono::Utc::now());
    entry.updated_at = chrono::Utc::now();

    Ok(())
}

/// Get decrypted secret value (for MCP server use)
pub fn get_decrypted_value(
    vault_data: &mut VaultData,
    keys: &DerivedKeys,
    reference: &str,
) -> VaultResult<String> {
    let entry = vault_data
        .entries
        .iter_mut()
        .find(|e| e.reference == reference)
        .ok_or_else(|| VaultError::SecretNotFound(reference.to_string()))?;

    // Check if expired or usage exceeded
    if entry.is_expired() {
        return Err(VaultError::SecretExpired(reference.to_string()));
    }
    if entry.is_usage_exceeded() {
        return Err(VaultError::UsageLimitExceeded(reference.to_string()));
    }

    let encrypted = vault_data
        .encrypted_values
        .get(&entry.id)
        .ok_or_else(|| VaultError::SecretNotFound(reference.to_string()))?;

    let plaintext = decrypt_value(keys, &encrypted.ciphertext, &encrypted.nonce)?;

    // Record usage
    entry.record_usage();

    String::from_utf8(plaintext)
        .map_err(|_| VaultError::DecryptionError("Invalid UTF-8 in secret value".to_string()))
}

/// Get decrypted value by ID
pub fn get_decrypted_value_by_id(
    vault_data: &mut VaultData,
    keys: &DerivedKeys,
    id: &Uuid,
) -> VaultResult<String> {
    let reference = vault_data
        .find_by_id(id)
        .map(|e| e.reference.clone())
        .ok_or_else(|| VaultError::SecretNotFound(id.to_string()))?;

    get_decrypted_value(vault_data, keys, &reference)
}

// ============================================================================
// SEARCH AND FILTER
// ============================================================================

/// Search filter options
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SearchFilter {
    pub query: Option<String>,
    pub tags: Option<Vec<String>>,
    pub secret_type: Option<String>,
    pub expired_only: bool,
    pub rotation_due_only: bool,
}

/// Search secrets with filters
pub fn search_secrets(vault_data: &VaultData, filter: SearchFilter) -> Vec<SecretInfo> {
    vault_data
        .entries
        .iter()
        .filter(|e| {
            // Text search in reference and description
            if let Some(ref query) = filter.query {
                let q = query.to_lowercase();
                let matches_ref = e.reference.to_lowercase().contains(&q);
                let matches_desc = e
                    .description
                    .as_ref()
                    .map(|d| d.to_lowercase().contains(&q))
                    .unwrap_or(false);
                if !matches_ref && !matches_desc {
                    return false;
                }
            }

            // Tag filter
            if let Some(ref tags) = filter.tags {
                if !tags.iter().any(|t| e.tags.contains(t)) {
                    return false;
                }
            }

            // Type filter
            if let Some(ref type_str) = filter.secret_type {
                let entry_type = format!("{:?}", e.secret_type)
                    .split('{')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_lowercase();
                if !entry_type.contains(&type_str.to_lowercase()) {
                    return false;
                }
            }

            // Expired filter
            if filter.expired_only && !e.is_expired() {
                return false;
            }

            // Rotation due filter
            if filter.rotation_due_only && !e.needs_rotation() {
                return false;
            }

            true
        })
        .map(SecretInfo::from)
        .collect()
}

// ============================================================================
// VAULT OPERATIONS
// ============================================================================

/// Save the current vault state to disk
pub async fn save_vault_state(
    vault_dir: &PathBuf,
    vault_data: &VaultData,
    keys: &DerivedKeys,
    salt: &[u8; 32],
) -> VaultResult<()> {
    storage::save_vault(vault_dir, vault_data, keys, salt).await
}

/// Change the master password
pub async fn change_password(
    vault_dir: &PathBuf,
    vault_data: &VaultData,
    old_password: &str,
    new_password: &str,
    config: &VaultConfig,
) -> VaultResult<DerivedKeys> {
    // Verify old password works
    let _ = storage::load_vault(vault_dir, old_password.as_bytes(), config).await?;

    // Generate new salt and derive new keys
    let new_salt = vault_core::crypto::generate_salt();
    let new_keys = DerivedKeys::derive(new_password.as_bytes(), &new_salt, config)?;

    // Save with new encryption
    storage::save_vault(vault_dir, vault_data, &new_keys, &new_salt).await?;

    Ok(new_keys)
}

/// Load vault configuration
pub async fn load_config(vault_dir: &PathBuf) -> VaultResult<VaultConfig> {
    storage::load_config(vault_dir).await
}

/// Save vault configuration
pub async fn save_config(vault_dir: &PathBuf, config: &VaultConfig) -> VaultResult<()> {
    storage::save_config(vault_dir, config).await
}

// ============================================================================
// TAURI STATE WRAPPER (for use with Tauri's State<>)
// ============================================================================

/// Thread-safe wrapper for AppState
pub type SharedAppState = Arc<RwLock<AppState>>;

/// Create a new shared app state
pub fn create_shared_state() -> SharedAppState {
    Arc::new(RwLock::new(AppState::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_result_ok() {
        let result: CommandResult<String> = CommandResult::ok("test".to_string());
        assert!(result.success);
        assert_eq!(result.data, Some("test".to_string()));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_command_result_err() {
        let result: CommandResult<String> = CommandResult::err("error message");
        assert!(!result.success);
        assert!(result.data.is_none());
        assert_eq!(result.error, Some("error message".to_string()));
    }
}
