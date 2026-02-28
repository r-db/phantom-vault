//! Encrypted file storage for vault data
//!
//! Handles reading/writing encrypted vault files with:
//! - Atomic writes (write to temp, then rename)
//! - Automatic backups before writes
//! - Version checking for migrations

use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::crypto::{compute_checksum, generate_salt, verify_checksum, DerivedKeys};
use crate::error::{VaultError, VaultResult};
use crate::models::{EncryptedVault, VaultConfig, VaultData};

/// Default vault directory name
const VAULT_DIR: &str = ".vault-secrets";

/// Main vault file name
const VAULT_FILE: &str = "vault.enc";

/// Backup file name
const BACKUP_FILE: &str = "vault.enc.backup";

/// Config file name
const CONFIG_FILE: &str = "config.toml";

/// Get the default vault directory path
pub fn default_vault_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(VAULT_DIR)
}

/// Get the vault file path
pub fn vault_file_path(base_dir: &Path) -> PathBuf {
    base_dir.join(VAULT_FILE)
}

/// Get the backup file path
pub fn backup_file_path(base_dir: &Path) -> PathBuf {
    base_dir.join(BACKUP_FILE)
}

/// Get the config file path
pub fn config_file_path(base_dir: &Path) -> PathBuf {
    base_dir.join(CONFIG_FILE)
}

/// Ensure the vault directory exists with proper permissions
pub async fn ensure_vault_dir(base_dir: &Path) -> VaultResult<()> {
    if !base_dir.exists() {
        fs::create_dir_all(base_dir).await?;

        // Set directory permissions to 700 (owner only) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(base_dir, perms)?;
        }
    }
    Ok(())
}

/// Check if a vault exists at the given path
pub async fn vault_exists(base_dir: &Path) -> bool {
    vault_file_path(base_dir).exists()
}

/// Create a new empty vault
pub async fn create_vault(
    base_dir: &Path,
    password: &[u8],
    config: &VaultConfig,
) -> VaultResult<()> {
    ensure_vault_dir(base_dir).await?;

    let vault_path = vault_file_path(base_dir);
    if vault_path.exists() {
        return Err(VaultError::ConfigError(
            "Vault already exists".to_string(),
        ));
    }

    // Generate salt for key derivation
    let salt = generate_salt();

    // Derive keys from password
    let keys = DerivedKeys::derive(password, &salt, config)?;

    // Create empty vault data
    let vault_data = VaultData::new();
    let plaintext = serde_json::to_vec(&vault_data)?;

    // Compute checksum
    let checksum = compute_checksum(&plaintext);

    // Encrypt
    let (ciphertext, nonce) = keys.encrypt(&plaintext)?;

    // Create encrypted vault structure
    let encrypted = EncryptedVault {
        version: EncryptedVault::CURRENT_VERSION,
        salt,
        nonce,
        ciphertext,
        checksum,
    };

    // Write to file
    write_vault_file(&vault_path, &encrypted).await?;

    // Save config
    save_config(base_dir, config).await?;

    Ok(())
}

/// Load and decrypt vault data
pub async fn load_vault(
    base_dir: &Path,
    password: &[u8],
    config: &VaultConfig,
) -> VaultResult<(VaultData, DerivedKeys)> {
    let vault_path = vault_file_path(base_dir);

    if !vault_path.exists() {
        return Err(VaultError::VaultNotFound(
            vault_path.display().to_string(),
        ));
    }

    // Read encrypted vault
    let encrypted = read_vault_file(&vault_path).await?;

    // Check version
    if encrypted.version > EncryptedVault::CURRENT_VERSION {
        return Err(VaultError::ConfigError(format!(
            "Vault version {} is newer than supported version {}",
            encrypted.version,
            EncryptedVault::CURRENT_VERSION
        )));
    }

    // Derive keys
    let keys = DerivedKeys::derive(password, &encrypted.salt, config)?;

    // Decrypt
    let plaintext = keys.decrypt(&encrypted.ciphertext, &encrypted.nonce)?;

    // Verify checksum
    if !verify_checksum(&plaintext, &encrypted.checksum) {
        return Err(VaultError::VaultCorrupted);
    }

    // Deserialize
    let vault_data: VaultData = serde_json::from_slice(&plaintext)?;

    Ok((vault_data, keys))
}

/// Save vault data (creates backup first)
pub async fn save_vault(
    base_dir: &Path,
    vault_data: &VaultData,
    keys: &DerivedKeys,
    salt: &[u8; 32],
) -> VaultResult<()> {
    let vault_path = vault_file_path(base_dir);
    let backup_path = backup_file_path(base_dir);

    // Create backup of existing vault
    if vault_path.exists() {
        if backup_path.exists() {
            fs::remove_file(&backup_path).await?;
        }
        fs::copy(&vault_path, &backup_path).await?;
    }

    // Serialize vault data
    let plaintext = serde_json::to_vec(vault_data)?;

    // Compute checksum
    let checksum = compute_checksum(&plaintext);

    // Encrypt
    let (ciphertext, nonce) = keys.encrypt(&plaintext)?;

    // Create encrypted vault structure
    let encrypted = EncryptedVault {
        version: EncryptedVault::CURRENT_VERSION,
        salt: *salt,
        nonce,
        ciphertext,
        checksum,
    };

    // Write atomically (write to temp, then rename)
    let temp_path = vault_path.with_extension("enc.tmp");
    write_vault_file(&temp_path, &encrypted).await?;
    fs::rename(&temp_path, &vault_path).await?;

    Ok(())
}

/// Read encrypted vault from file
async fn read_vault_file(path: &Path) -> VaultResult<EncryptedVault> {
    let mut file = fs::File::open(path).await?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).await?;

    let encrypted: EncryptedVault = serde_json::from_slice(&data)?;
    Ok(encrypted)
}

/// Write encrypted vault to file
async fn write_vault_file(path: &Path, encrypted: &EncryptedVault) -> VaultResult<()> {
    let data = serde_json::to_vec(encrypted)?;

    let mut file = fs::File::create(path).await?;
    file.write_all(&data).await?;
    file.sync_all().await?;

    // Set file permissions to 600 (owner only) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Load vault configuration
pub async fn load_config(base_dir: &Path) -> VaultResult<VaultConfig> {
    let config_path = config_file_path(base_dir);

    if !config_path.exists() {
        return Ok(VaultConfig::default());
    }

    let content = fs::read_to_string(&config_path).await?;
    let config: VaultConfig = toml::from_str(&content)
        .map_err(|e| VaultError::ConfigError(e.to_string()))?;

    Ok(config)
}

/// Save vault configuration
pub async fn save_config(base_dir: &Path, config: &VaultConfig) -> VaultResult<()> {
    ensure_vault_dir(base_dir).await?;

    let config_path = config_file_path(base_dir);
    let content = toml::to_string_pretty(config)
        .map_err(|e| VaultError::ConfigError(e.to_string()))?;

    fs::write(&config_path, content).await?;

    Ok(())
}

/// Delete the vault (requires confirmation)
pub async fn delete_vault(base_dir: &Path) -> VaultResult<()> {
    let vault_path = vault_file_path(base_dir);
    let backup_path = backup_file_path(base_dir);

    if vault_path.exists() {
        fs::remove_file(&vault_path).await?;
    }

    if backup_path.exists() {
        fs::remove_file(&backup_path).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_create_and_load_vault() {
        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path();
        let password = b"test-password";
        let config = VaultConfig::default();

        // Create vault
        create_vault(base_dir, password, &config).await.unwrap();
        assert!(vault_exists(base_dir).await);

        // Load vault
        let (vault_data, _keys) = load_vault(base_dir, password, &config).await.unwrap();
        assert!(vault_data.entries.is_empty());
    }

    #[tokio::test]
    async fn test_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path();
        let config = VaultConfig::default();

        create_vault(base_dir, b"password1", &config).await.unwrap();

        let result = load_vault(base_dir, b"password2", &config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_save_and_reload() {
        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path();
        let password = b"test-password";
        let config = VaultConfig::default();

        create_vault(base_dir, password, &config).await.unwrap();
        let (mut vault_data, keys) = load_vault(base_dir, password, &config).await.unwrap();

        // Add a secret entry
        let entry = crate::models::SecretEntry::new(
            "test-secret".to_string(),
            crate::models::SecretType::default(),
        );
        vault_data.entries.push(entry);

        // Read the encrypted vault to get the salt
        let vault_path = vault_file_path(base_dir);
        let encrypted = read_vault_file(&vault_path).await.unwrap();

        // Save
        save_vault(base_dir, &vault_data, &keys, &encrypted.salt).await.unwrap();

        // Reload
        let (reloaded, _) = load_vault(base_dir, password, &config).await.unwrap();
        assert_eq!(reloaded.entries.len(), 1);
        assert_eq!(reloaded.entries[0].reference, "test-secret");
    }
}
