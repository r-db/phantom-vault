//! API exposed to Flutter via flutter_rust_bridge
//!
//! These functions will be automatically wrapped for Dart

use std::path::PathBuf;

/// Check if vault exists at the default location
pub fn vault_exists(vault_dir: String) -> bool {
    let path = PathBuf::from(vault_dir);
    path.join("vault.enc").exists()
}

/// Create a new vault
pub fn create_vault(vault_dir: String, password: String) -> Result<(), String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let path = PathBuf::from(vault_dir);
        let config = vault_core::models::VaultConfig::default();
        vault_core::storage::create_vault(&path, password.as_bytes(), &config)
            .await
            .map_err(|e| e.to_string())
    })
}

/// Unlock vault and return number of secrets
pub fn unlock_vault(vault_dir: String, password: String) -> Result<usize, String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let path = PathBuf::from(vault_dir);
        let config = vault_core::models::VaultConfig::default();
        let (data, _keys) = vault_core::storage::load_vault(&path, password.as_bytes(), &config)
            .await
            .map_err(|e| e.to_string())?;
        Ok(data.entries.len())
    })
}

/// Get list of secret references (names only, no values)
pub fn list_secret_references(vault_dir: String, password: String) -> Result<Vec<String>, String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let path = PathBuf::from(vault_dir);
        let config = vault_core::models::VaultConfig::default();
        let (data, _keys) = vault_core::storage::load_vault(&path, password.as_bytes(), &config)
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
}
