//! API exposed to Flutter via flutter_rust_bridge
//!
//! These functions will be automatically wrapped for Dart

use std::path::PathBuf;
use crate::biometric;

/// Check if vault exists at the default location
pub fn vault_exists(vault_dir: String) -> bool {
    let path = PathBuf::from(vault_dir);
    path.join("vault.enc").exists()
}

/// Create a new vault with optional biometric enrollment
pub fn create_vault(vault_dir: String, password: String, enroll_biometric: bool) -> Result<(), String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let path = PathBuf::from(&vault_dir);
        let config = vault_core::models::VaultConfig::default();
        vault_core::storage::create_vault(&path, password.as_bytes(), &config)
            .await
            .map_err(|e| e.to_string())?;

        // Optionally enroll biometric
        if enroll_biometric && biometric::is_biometric_available() {
            biometric::enroll_biometric(&vault_dir, password.as_bytes())
                .map_err(|e| format!("Biometric enrollment failed: {}", e))?;
        }

        Ok(())
    })
}

/// Unlock vault with password and return number of secrets
pub fn unlock_vault(vault_dir: String, password: String) -> Result<usize, String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let path = PathBuf::from(vault_dir);
        let config = vault_core::models::VaultConfig::default();
        let (data, _keys, _salt) = vault_core::storage::load_vault(&path, password.as_bytes(), &config)
            .await
            .map_err(|e| e.to_string())?;
        Ok(data.entries.len())
    })
}

/// Unlock vault using biometric authentication
pub fn unlock_vault_biometric(vault_dir: String) -> Result<usize, String> {
    // First, get the password from biometric-protected storage
    let password = biometric::unlock_with_biometric(&vault_dir)
        .map_err(|e| format!("Biometric unlock failed: {}", e))?;

    // Then unlock the vault with that password
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let path = PathBuf::from(&vault_dir);
        let config = vault_core::models::VaultConfig::default();
        let (data, _keys, _salt) = vault_core::storage::load_vault(&path, &password, &config)
            .await
            .map_err(|e| e.to_string())?;
        Ok(data.entries.len())
    })
}

/// Check biometric status for a vault
pub fn get_biometric_status(vault_dir: String) -> BiometricStatusResult {
    let status = biometric::check_biometric_status(&vault_dir);
    BiometricStatusResult {
        available: status.available,
        biometric_type: status.biometric_type,
        key_enrolled: status.key_enrolled,
    }
}

/// Result type for biometric status (FFI-friendly)
#[derive(Debug, Clone)]
pub struct BiometricStatusResult {
    pub available: bool,
    pub biometric_type: String,
    pub key_enrolled: bool,
}

/// Enroll biometric for an existing vault
pub fn enroll_vault_biometric(vault_dir: String, password: String) -> Result<(), String> {
    // First verify the password is correct
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let path = PathBuf::from(&vault_dir);
        let config = vault_core::models::VaultConfig::default();
        vault_core::storage::load_vault(&path, password.as_bytes(), &config)
            .await
            .map_err(|e| format!("Invalid password: {}", e))?;

        // Password is correct, enroll biometric
        biometric::enroll_biometric(&vault_dir, password.as_bytes())
            .map_err(|e| format!("Biometric enrollment failed: {}", e))
    })
}

/// Remove biometric enrollment
pub fn unenroll_vault_biometric(vault_dir: String) -> Result<(), String> {
    biometric::unenroll_biometric(&vault_dir)
        .map_err(|e| format!("Failed to remove biometric: {}", e))
}

/// Get list of secret references (names only, no values)
pub fn list_secret_references(vault_dir: String, password: String) -> Result<Vec<String>, String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let path = PathBuf::from(vault_dir);
        let config = vault_core::models::VaultConfig::default();
        let (data, _keys, _salt) = vault_core::storage::load_vault(&path, password.as_bytes(), &config)
            .await
            .map_err(|e| e.to_string())?;
        Ok(data.entries.iter().map(|e| e.reference.clone()).collect())
    })
}

/// Get the default vault directory for the platform
pub fn default_vault_dir() -> String {
    vault_core::storage::default_vault_dir()
        .to_string_lossy()
        .to_string()
}

/// Check if biometric authentication is available on this system
pub fn check_biometric_available() -> bool {
    biometric::is_biometric_available()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_exists_nonexistent() {
        assert!(!vault_exists("/nonexistent/path".to_string()));
    }

    #[test]
    fn test_default_vault_dir() {
        let dir = default_vault_dir();
        assert!(!dir.is_empty());
        assert!(dir.contains(".vault-secrets"));
    }

    #[test]
    fn test_biometric_status() {
        let status = get_biometric_status("/tmp/test-vault".to_string());
        assert!(!status.biometric_type.is_empty());
    }
}
