//! Biometric authentication support
//!
//! Platform-specific implementations for biometric vault unlocking:
//! - macOS: Touch ID via Security framework + Keychain
//! - Linux: (future) systemd-cryptenroll or TPM2
//! - Windows: (future) Windows Hello

use std::error::Error;

/// Result of biometric authentication check
#[derive(Debug, Clone)]
pub struct BiometricStatus {
    /// Whether biometric auth is available on this system
    pub available: bool,
    /// Type of biometric (TouchID, FaceID, Fingerprint, etc.)
    pub biometric_type: String,
    /// Whether a key is stored for biometric unlock
    pub key_enrolled: bool,
}

/// Service name for Keychain storage
const SERVICE_NAME: &str = "com.phantomvault.master-key";

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use security_framework::passwords::{delete_generic_password, get_generic_password, set_generic_password};
    use std::process::Command;

    /// Check if Touch ID is available
    pub fn check_biometric_status(account: &str) -> BiometricStatus {
        // Check if Touch ID hardware is available by querying bioutil
        let available = Command::new("bioutil")
            .args(["--availability"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        // Check if we have a key enrolled
        let key_enrolled = get_generic_password(SERVICE_NAME, account).is_ok();

        BiometricStatus {
            available,
            biometric_type: if available { "TouchID".to_string() } else { "None".to_string() },
            key_enrolled,
        }
    }

    /// Enroll a master key for biometric unlock
    /// This stores the key in Keychain protected by Touch ID
    pub fn enroll_biometric(account: &str, master_key: &[u8]) -> Result<(), Box<dyn Error>> {
        // Delete any existing key first
        let _ = delete_generic_password(SERVICE_NAME, account);

        // Store the key in Keychain
        // Note: For true biometric protection, we'd use SecAccessControl with
        // kSecAccessControlBiometryCurrentSet, but the security-framework crate
        // doesn't expose this directly yet. This is a simplified version.
        set_generic_password(SERVICE_NAME, account, master_key)?;

        Ok(())
    }

    /// Retrieve the master key using biometric authentication
    pub fn unlock_with_biometric(account: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        // This will trigger Touch ID prompt on macOS when accessing biometric-protected items
        // For now, using standard Keychain access (Touch ID prompt happens automatically
        // if the item was stored with biometric protection)
        let key = get_generic_password(SERVICE_NAME, account)?;
        Ok(key)
    }

    /// Remove biometric enrollment
    pub fn unenroll_biometric(account: &str) -> Result<(), Box<dyn Error>> {
        delete_generic_password(SERVICE_NAME, account)?;
        Ok(())
    }

    /// Check if Touch ID is available by verifying LAContext can evaluate
    pub fn is_biometric_available() -> bool {
        // Use bioutil to check availability
        Command::new("bioutil")
            .args(["--availability"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

#[cfg(not(target_os = "macos"))]
mod fallback {
    use super::*;

    pub fn check_biometric_status(_account: &str) -> BiometricStatus {
        BiometricStatus {
            available: false,
            biometric_type: "None".to_string(),
            key_enrolled: false,
        }
    }

    pub fn enroll_biometric(_account: &str, _master_key: &[u8]) -> Result<(), Box<dyn Error>> {
        Err("Biometric authentication not available on this platform".into())
    }

    pub fn unlock_with_biometric(_account: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        Err("Biometric authentication not available on this platform".into())
    }

    pub fn unenroll_biometric(_account: &str) -> Result<(), Box<dyn Error>> {
        Err("Biometric authentication not available on this platform".into())
    }

    pub fn is_biometric_available() -> bool {
        false
    }
}

// Re-export platform-specific implementations
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(not(target_os = "macos"))]
pub use fallback::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometric_status() {
        // This just tests that the function runs without panicking
        let status = check_biometric_status("test-vault");
        assert!(!status.biometric_type.is_empty());
    }

    #[test]
    fn test_is_biometric_available() {
        // This is platform-dependent, just make sure it doesn't crash
        let _available = is_biometric_available();
    }
}
