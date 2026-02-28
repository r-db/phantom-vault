//! Encrypted audit logging for vault operations
//!
//! Tracks all access to secrets without exposing actual values:
//! - Secret access (which reference was accessed, not the value)
//! - Vault unlock/lock events
//! - Failed authentication attempts
//! - Credential leak detections
//! - Secret modifications (add/update/delete)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::crypto::DerivedKeys;
use crate::error::{VaultError, VaultResult};

/// Audit log file name
const AUDIT_FILE: &str = "audit.log";

/// Maximum audit entries before rotation
const MAX_ENTRIES: usize = 10000;

/// Types of auditable events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum AuditEvent {
    /// Vault was unlocked
    VaultUnlocked {
        /// Whether biometric was used
        biometric: bool,
    },

    /// Vault was locked
    VaultLocked {
        /// Reason for locking
        reason: LockReason,
    },

    /// Failed unlock attempt
    UnlockFailed {
        /// Number of consecutive failures
        attempt_count: u32,
    },

    /// Account locked out due to failed attempts
    LockedOut {
        /// Duration of lockout in seconds
        duration_seconds: u64,
    },

    /// Secret was accessed (value retrieved)
    SecretAccessed {
        /// Secret reference name (NOT the value)
        reference: String,
        /// Secret ID
        secret_id: Uuid,
        /// Tool that accessed it (if via MCP)
        tool_name: Option<String>,
    },

    /// Secret was created
    SecretCreated {
        /// Secret reference name
        reference: String,
        /// Secret ID
        secret_id: Uuid,
        /// Type of secret
        secret_type: String,
    },

    /// Secret was updated
    SecretUpdated {
        /// Secret reference name
        reference: String,
        /// Secret ID
        secret_id: Uuid,
        /// What was updated (e.g., "value", "metadata", "tags")
        updated_field: String,
    },

    /// Secret was deleted
    SecretDeleted {
        /// Secret reference name
        reference: String,
        /// Secret ID
        secret_id: Uuid,
    },

    /// Secret was rotated
    SecretRotated {
        /// Secret reference name
        reference: String,
        /// Secret ID
        secret_id: Uuid,
    },

    /// Credential leak detected and blocked
    LeakBlocked {
        /// Tool that tried to leak
        tool_name: String,
        /// Pattern that detected the leak
        pattern_name: String,
        /// Secret reference if known
        secret_reference: Option<String>,
    },

    /// MCP tool was called
    ToolCalled {
        /// Tool name
        tool_name: String,
        /// Whether credentials were injected
        credentials_injected: bool,
        /// References of injected credentials
        injected_references: Vec<String>,
    },

    /// Configuration changed
    ConfigChanged {
        /// What setting was changed
        setting: String,
        /// Old value (non-sensitive only)
        old_value: String,
        /// New value (non-sensitive only)
        new_value: String,
    },

    /// Vault was backed up
    VaultBackedUp {
        /// Backup destination (path, not contents)
        destination: String,
    },

    /// Vault was restored from backup
    VaultRestored {
        /// Backup source (path)
        source: String,
    },

    /// Export was performed (e.g., for migration)
    SecretsExported {
        /// Number of secrets exported
        count: usize,
        /// Whether encrypted
        encrypted: bool,
    },

    /// Import was performed
    SecretsImported {
        /// Number of secrets imported
        count: usize,
        /// Source format
        format: String,
    },
}

/// Reason for vault lock
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LockReason {
    /// User manually locked
    Manual,
    /// Auto-lock timeout
    Timeout,
    /// Application exit
    AppExit,
    /// System sleep/suspend
    SystemSleep,
    /// Too many failed attempts
    FailedAttempts,
}

/// Single audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID
    pub id: Uuid,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Event details
    pub event: AuditEvent,
    /// Optional client identifier (e.g., device name)
    pub client_id: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry
    pub fn new(event: AuditEvent, client_id: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event,
            client_id,
        }
    }
}

/// Encrypted audit log entry (stored format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedAuditEntry {
    /// Entry ID (unencrypted for indexing)
    pub id: Uuid,
    /// Timestamp (unencrypted for filtering)
    pub timestamp: DateTime<Utc>,
    /// AES-GCM nonce
    pub nonce: [u8; 12],
    /// Encrypted event data
    pub ciphertext: Vec<u8>,
}

/// Audit logger
pub struct AuditLogger {
    /// Base directory for audit log
    base_dir: PathBuf,
    /// Encryption keys
    keys: Option<DerivedKeys>,
    /// Client identifier
    client_id: Option<String>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(base_dir: &Path, client_id: Option<String>) -> Self {
        Self {
            base_dir: base_dir.to_path_buf(),
            keys: None,
            client_id,
        }
    }

    /// Set encryption keys (required for logging encrypted entries)
    pub fn set_keys(&mut self, keys: DerivedKeys) {
        self.keys = Some(keys);
    }

    /// Clear encryption keys (on vault lock)
    pub fn clear_keys(&mut self) {
        self.keys = None;
    }

    /// Get audit log file path
    fn audit_file_path(&self) -> PathBuf {
        self.base_dir.join(AUDIT_FILE)
    }

    /// Log an event (encrypted)
    pub async fn log(&self, event: AuditEvent) -> VaultResult<()> {
        let keys = self.keys.as_ref().ok_or(VaultError::VaultLocked)?;

        let entry = AuditEntry::new(event, self.client_id.clone());
        let entry_json = serde_json::to_vec(&entry.event)?;

        let (ciphertext, nonce) = keys.encrypt_audit(&entry_json)?;

        let encrypted_entry = EncryptedAuditEntry {
            id: entry.id,
            timestamp: entry.timestamp,
            nonce,
            ciphertext,
        };

        self.append_entry(&encrypted_entry).await?;

        Ok(())
    }

    /// Append encrypted entry to log file
    async fn append_entry(&self, entry: &EncryptedAuditEntry) -> VaultResult<()> {
        let audit_path = self.audit_file_path();

        // Ensure parent directory exists
        if let Some(parent) = audit_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_path)
            .await?;

        let line = serde_json::to_string(entry)?;
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.sync_all().await?;

        Ok(())
    }

    /// Read and decrypt audit log entries
    pub async fn read_entries(
        &self,
        limit: Option<usize>,
        since: Option<DateTime<Utc>>,
    ) -> VaultResult<Vec<AuditEntry>> {
        let keys = self.keys.as_ref().ok_or(VaultError::VaultLocked)?;
        let audit_path = self.audit_file_path();

        if !audit_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&audit_path).await?;
        let mut entries = Vec::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let encrypted: EncryptedAuditEntry = serde_json::from_str(line)?;

            // Filter by timestamp if specified
            if let Some(since_time) = since {
                if encrypted.timestamp < since_time {
                    continue;
                }
            }

            // Decrypt the event
            let decrypted = keys.decrypt_audit(&encrypted.ciphertext, &encrypted.nonce)?;
            let event: AuditEvent = serde_json::from_slice(&decrypted)?;

            entries.push(AuditEntry {
                id: encrypted.id,
                timestamp: encrypted.timestamp,
                event,
                client_id: None, // Client ID is stored in encrypted event
            });

            // Apply limit
            if let Some(max) = limit {
                if entries.len() >= max {
                    break;
                }
            }
        }

        Ok(entries)
    }

    /// Get audit entries for a specific secret
    pub async fn get_secret_history(&self, secret_id: &Uuid) -> VaultResult<Vec<AuditEntry>> {
        let all_entries = self.read_entries(None, None).await?;

        let filtered: Vec<AuditEntry> = all_entries
            .into_iter()
            .filter(|e| match &e.event {
                AuditEvent::SecretAccessed { secret_id: sid, .. }
                | AuditEvent::SecretCreated { secret_id: sid, .. }
                | AuditEvent::SecretUpdated { secret_id: sid, .. }
                | AuditEvent::SecretDeleted { secret_id: sid, .. }
                | AuditEvent::SecretRotated { secret_id: sid, .. } => sid == secret_id,
                _ => false,
            })
            .collect();

        Ok(filtered)
    }

    /// Count entries in audit log
    pub async fn count_entries(&self) -> VaultResult<usize> {
        let audit_path = self.audit_file_path();

        if !audit_path.exists() {
            return Ok(0);
        }

        let content = fs::read_to_string(&audit_path).await?;
        Ok(content.lines().filter(|l| !l.trim().is_empty()).count())
    }

    /// Rotate audit log if it exceeds max entries
    pub async fn rotate_if_needed(&self) -> VaultResult<bool> {
        let count = self.count_entries().await?;

        if count > MAX_ENTRIES {
            let audit_path = self.audit_file_path();
            let archive_path = self.base_dir.join(format!(
                "audit-{}.log",
                Utc::now().format("%Y%m%d-%H%M%S")
            ));

            fs::rename(&audit_path, &archive_path).await?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Clear audit log (requires explicit confirmation)
    pub async fn clear(&self) -> VaultResult<()> {
        let audit_path = self.audit_file_path();

        if audit_path.exists() {
            fs::remove_file(&audit_path).await?;
        }

        Ok(())
    }
}

/// Log a vault unlock event
pub async fn log_unlock(logger: &AuditLogger, biometric: bool) -> VaultResult<()> {
    logger.log(AuditEvent::VaultUnlocked { biometric }).await
}

/// Log a vault lock event
pub async fn log_lock(logger: &AuditLogger, reason: LockReason) -> VaultResult<()> {
    logger.log(AuditEvent::VaultLocked { reason }).await
}

/// Log a secret access event
pub async fn log_secret_access(
    logger: &AuditLogger,
    reference: &str,
    secret_id: &Uuid,
    tool_name: Option<&str>,
) -> VaultResult<()> {
    logger
        .log(AuditEvent::SecretAccessed {
            reference: reference.to_string(),
            secret_id: *secret_id,
            tool_name: tool_name.map(|s| s.to_string()),
        })
        .await
}

/// Log a credential leak blocked event
pub async fn log_leak_blocked(
    logger: &AuditLogger,
    tool_name: &str,
    pattern_name: &str,
    secret_reference: Option<&str>,
) -> VaultResult<()> {
    logger
        .log(AuditEvent::LeakBlocked {
            tool_name: tool_name.to_string(),
            pattern_name: pattern_name.to_string(),
            secret_reference: secret_reference.map(|s| s.to_string()),
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_salt;
    use crate::models::VaultConfig;
    use tempfile::TempDir;

    async fn setup_logger() -> (AuditLogger, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let mut logger = AuditLogger::new(temp_dir.path(), Some("test-client".to_string()));

        let salt = generate_salt();
        let config = VaultConfig::default();
        let keys = DerivedKeys::derive(b"test-password", &salt, &config).unwrap();
        logger.set_keys(keys);

        (logger, temp_dir)
    }

    #[tokio::test]
    async fn test_log_unlock() {
        let (logger, _temp) = setup_logger().await;

        log_unlock(&logger, false).await.unwrap();

        let entries = logger.read_entries(None, None).await.unwrap();
        assert_eq!(entries.len(), 1);

        match &entries[0].event {
            AuditEvent::VaultUnlocked { biometric } => {
                assert!(!biometric);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[tokio::test]
    async fn test_log_secret_access() {
        let (logger, _temp) = setup_logger().await;
        let secret_id = Uuid::new_v4();

        log_secret_access(&logger, "prod-db", &secret_id, Some("exec_sql")).await.unwrap();

        let entries = logger.read_entries(None, None).await.unwrap();
        assert_eq!(entries.len(), 1);

        match &entries[0].event {
            AuditEvent::SecretAccessed {
                reference,
                secret_id: sid,
                tool_name,
            } => {
                assert_eq!(reference, "prod-db");
                assert_eq!(sid, &secret_id);
                assert_eq!(tool_name, &Some("exec_sql".to_string()));
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[tokio::test]
    async fn test_log_leak_blocked() {
        let (logger, _temp) = setup_logger().await;

        log_leak_blocked(&logger, "shell_exec", "aws_access_key", Some("aws-prod"))
            .await
            .unwrap();

        let entries = logger.read_entries(None, None).await.unwrap();
        assert_eq!(entries.len(), 1);

        match &entries[0].event {
            AuditEvent::LeakBlocked {
                tool_name,
                pattern_name,
                secret_reference,
            } => {
                assert_eq!(tool_name, "shell_exec");
                assert_eq!(pattern_name, "aws_access_key");
                assert_eq!(secret_reference, &Some("aws-prod".to_string()));
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[tokio::test]
    async fn test_multiple_entries() {
        let (logger, _temp) = setup_logger().await;

        log_unlock(&logger, false).await.unwrap();
        log_secret_access(&logger, "api-key", &Uuid::new_v4(), None).await.unwrap();
        log_lock(&logger, LockReason::Timeout).await.unwrap();

        let entries = logger.read_entries(None, None).await.unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn test_entry_count() {
        let (logger, _temp) = setup_logger().await;

        log_unlock(&logger, false).await.unwrap();
        log_unlock(&logger, true).await.unwrap();

        let count = logger.count_entries().await.unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_read_with_limit() {
        let (logger, _temp) = setup_logger().await;

        for _ in 0..5 {
            log_unlock(&logger, false).await.unwrap();
        }

        let entries = logger.read_entries(Some(3), None).await.unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn test_get_secret_history() {
        let (logger, _temp) = setup_logger().await;
        let secret_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();

        log_secret_access(&logger, "my-secret", &secret_id, None).await.unwrap();
        log_secret_access(&logger, "other-secret", &other_id, None).await.unwrap();
        log_secret_access(&logger, "my-secret", &secret_id, Some("tool")).await.unwrap();

        let history = logger.get_secret_history(&secret_id).await.unwrap();
        assert_eq!(history.len(), 2);
    }

    #[tokio::test]
    async fn test_clear_log() {
        let (logger, _temp) = setup_logger().await;

        log_unlock(&logger, false).await.unwrap();
        assert_eq!(logger.count_entries().await.unwrap(), 1);

        logger.clear().await.unwrap();
        assert_eq!(logger.count_entries().await.unwrap(), 0);
    }
}
