//! HMAC-chained audit logging.
//!
//! Provides tamper-evident logging of all vault operations. Each log entry
//! includes an HMAC of the previous entry, forming a chain that can detect
//! if any entries have been modified or deleted.

use ring::hmac;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors that can occur during audit operations.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Chain integrity verification failed.
    #[error("audit chain integrity failed at entry {0}")]
    IntegrityFailed(u64),

    /// Log storage error.
    #[error("audit log storage error: {0}")]
    Storage(String),

    /// Invalid audit entry.
    #[error("invalid audit entry: {0}")]
    InvalidEntry(String),

    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Result type for audit operations.
pub type AuditResult<T> = Result<T, AuditError>;

/// Type of audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Vault was opened.
    VaultOpened,
    /// Vault was sealed.
    VaultSealed,
    /// Secret was created.
    SecretCreated,
    /// Secret was read.
    SecretRead,
    /// Secret was updated.
    SecretUpdated,
    /// Secret was deleted.
    SecretDeleted,
    /// Secret was rotated.
    SecretRotated,
    /// Canary was triggered.
    CanaryTriggered,
    /// Command was executed with secrets.
    CommandExecuted,
    /// Sanitization blocked potential leak.
    LeakBlocked,
}

impl AuditEventType {
    /// Convert event type to string for storage.
    fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::VaultOpened => "vault_opened",
            AuditEventType::VaultSealed => "vault_sealed",
            AuditEventType::SecretCreated => "secret_created",
            AuditEventType::SecretRead => "secret_read",
            AuditEventType::SecretUpdated => "secret_updated",
            AuditEventType::SecretDeleted => "secret_deleted",
            AuditEventType::SecretRotated => "secret_rotated",
            AuditEventType::CanaryTriggered => "canary_triggered",
            AuditEventType::CommandExecuted => "command_executed",
            AuditEventType::LeakBlocked => "leak_blocked",
        }
    }

    /// Parse event type from string.
    fn from_str(s: &str) -> AuditResult<Self> {
        match s {
            "vault_opened" => Ok(AuditEventType::VaultOpened),
            "vault_sealed" => Ok(AuditEventType::VaultSealed),
            "secret_created" => Ok(AuditEventType::SecretCreated),
            "secret_read" => Ok(AuditEventType::SecretRead),
            "secret_updated" => Ok(AuditEventType::SecretUpdated),
            "secret_deleted" => Ok(AuditEventType::SecretDeleted),
            "secret_rotated" => Ok(AuditEventType::SecretRotated),
            "canary_triggered" => Ok(AuditEventType::CanaryTriggered),
            "command_executed" => Ok(AuditEventType::CommandExecuted),
            "leak_blocked" => Ok(AuditEventType::LeakBlocked),
            _ => Err(AuditError::InvalidEntry(format!(
                "unknown event type: {}",
                s
            ))),
        }
    }
}

/// An entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Sequence number.
    pub sequence: u64,
    /// Timestamp (Unix epoch nanoseconds).
    pub timestamp: u128,
    /// Event type.
    pub event_type: AuditEventType,
    /// Namespace affected.
    pub namespace: String,
    /// Secret name (if applicable).
    pub secret_name: Option<String>,
    /// Request lineage ID (for MCP tracking).
    pub lineage_id: Option<String>,
    /// Additional context.
    pub context: Option<String>,
    /// HMAC of this entry chained with previous.
    pub hmac: [u8; 32],
}

impl AuditEntry {
    /// Compute the canonical bytes for HMAC computation.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(self.event_type.as_str().as_bytes());
        bytes.push(0); // separator
        bytes.extend_from_slice(self.namespace.as_bytes());
        bytes.push(0);
        if let Some(ref name) = self.secret_name {
            bytes.extend_from_slice(name.as_bytes());
        }
        bytes.push(0);
        if let Some(ref id) = self.lineage_id {
            bytes.extend_from_slice(id.as_bytes());
        }
        bytes.push(0);
        if let Some(ref ctx) = self.context {
            bytes.extend_from_slice(ctx.as_bytes());
        }
        bytes
    }
}

/// HMAC-chained audit log.
pub struct AuditLog {
    /// Database connection.
    conn: Connection,
    /// Path to the database file.
    path: Option<PathBuf>,
    /// HMAC key for chain verification.
    chain_key: hmac::Key,
    /// Cached last HMAC for chaining.
    last_hmac: [u8; 32],
    /// Cached last sequence number.
    last_sequence: u64,
}

impl AuditLog {
    /// Create a new in-memory audit log.
    pub fn new(chain_key: [u8; 32]) -> Self {
        let conn = Connection::open_in_memory().expect("Failed to open in-memory database");
        Self::init_db(&conn).expect("Failed to initialize database");

        Self {
            conn,
            path: None,
            chain_key: hmac::Key::new(hmac::HMAC_SHA256, &chain_key),
            last_hmac: [0u8; 32],
            last_sequence: 0,
        }
    }

    /// Open an existing audit log or create a new one.
    pub fn open(path: &Path, chain_key: [u8; 32]) -> AuditResult<Self> {
        // Set file permissions to 0600 before opening (for new files)
        #[cfg(unix)]
        if !path.exists() {
            // Create parent directory if needed
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        // Set WAL mode for better concurrency
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        // Initialize schema
        Self::init_db(&conn)?;

        // Set file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }

        // Load last entry state
        let (last_hmac, last_sequence) = Self::load_last_state(&conn)?;

        Ok(Self {
            conn,
            path: Some(path.to_path_buf()),
            chain_key: hmac::Key::new(hmac::HMAC_SHA256, &chain_key),
            last_hmac,
            last_sequence,
        })
    }

    /// Initialize the database schema.
    fn init_db(conn: &Connection) -> AuditResult<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS audit_log (
                sequence INTEGER PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                namespace TEXT NOT NULL,
                secret_name TEXT,
                lineage_id TEXT,
                context TEXT,
                hmac BLOB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_namespace ON audit_log(namespace);
            CREATE INDEX IF NOT EXISTS idx_audit_secret_name ON audit_log(secret_name);
            CREATE INDEX IF NOT EXISTS idx_audit_lineage ON audit_log(lineage_id);
            "#,
        )?;
        Ok(())
    }

    /// Load the last HMAC and sequence from the database.
    fn load_last_state(conn: &Connection) -> AuditResult<([u8; 32], u64)> {
        let mut stmt = conn.prepare(
            "SELECT sequence, hmac FROM audit_log ORDER BY sequence DESC LIMIT 1",
        )?;

        let result: Option<(u64, Vec<u8>)> = stmt
            .query_row([], |row| {
                let seq: u64 = row.get(0)?;
                let hmac: Vec<u8> = row.get(1)?;
                Ok((seq, hmac))
            })
            .ok();

        match result {
            Some((seq, hmac_vec)) => {
                let mut hmac = [0u8; 32];
                if hmac_vec.len() == 32 {
                    hmac.copy_from_slice(&hmac_vec);
                }
                Ok((hmac, seq))
            }
            None => Ok(([0u8; 32], 0)),
        }
    }

    /// Compute HMAC for an entry, chained with the previous HMAC.
    fn compute_hmac(&self, entry_bytes: &[u8], prev_hmac: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::with_capacity(entry_bytes.len() + 32);
        data.extend_from_slice(prev_hmac);
        data.extend_from_slice(entry_bytes);

        let tag = hmac::sign(&self.chain_key, &data);
        let mut result = [0u8; 32];
        result.copy_from_slice(tag.as_ref());
        result
    }

    /// Append an event to the log.
    pub fn append(
        &mut self,
        event_type: AuditEventType,
        namespace: &str,
        secret_name: Option<&str>,
        lineage_id: Option<&str>,
        context: Option<&str>,
    ) -> AuditResult<u64> {
        let sequence = self.last_sequence + 1;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        // Create entry (without HMAC yet)
        let mut entry = AuditEntry {
            sequence,
            timestamp,
            event_type,
            namespace: namespace.to_string(),
            secret_name: secret_name.map(String::from),
            lineage_id: lineage_id.map(String::from),
            context: context.map(String::from),
            hmac: [0u8; 32],
        };

        // Compute chained HMAC
        let entry_bytes = entry.canonical_bytes();
        entry.hmac = self.compute_hmac(&entry_bytes, &self.last_hmac);

        // Insert into database atomically
        self.conn.execute(
            r#"
            INSERT INTO audit_log (sequence, timestamp, event_type, namespace, secret_name, lineage_id, context, hmac)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                entry.sequence as i64,
                entry.timestamp as i64,
                entry.event_type.as_str(),
                entry.namespace,
                entry.secret_name,
                entry.lineage_id,
                entry.context,
                entry.hmac.as_slice(),
            ],
        )?;

        // Update cached state
        self.last_hmac = entry.hmac;
        self.last_sequence = sequence;

        Ok(sequence)
    }

    /// Verify the integrity of the entire chain.
    pub fn verify(&self) -> AuditResult<()> {
        let mut stmt = self.conn.prepare(
            "SELECT sequence, timestamp, event_type, namespace, secret_name, lineage_id, context, hmac FROM audit_log ORDER BY sequence ASC",
        )?;

        let mut prev_hmac = [0u8; 32];
        let mut expected_seq = 1u64;

        let rows = stmt.query_map([], |row| {
            let sequence: i64 = row.get(0)?;
            let timestamp: i64 = row.get(1)?;
            let event_type_str: String = row.get(2)?;
            let namespace: String = row.get(3)?;
            let secret_name: Option<String> = row.get(4)?;
            let lineage_id: Option<String> = row.get(5)?;
            let context: Option<String> = row.get(6)?;
            let hmac_vec: Vec<u8> = row.get(7)?;

            Ok((
                sequence as u64,
                timestamp as u128,
                event_type_str,
                namespace,
                secret_name,
                lineage_id,
                context,
                hmac_vec,
            ))
        })?;

        for row in rows {
            let (sequence, timestamp, event_type_str, namespace, secret_name, lineage_id, context, hmac_vec) = row?;

            // Check sequence continuity
            if sequence != expected_seq {
                return Err(AuditError::IntegrityFailed(sequence));
            }

            let event_type = AuditEventType::from_str(&event_type_str)?;

            let entry = AuditEntry {
                sequence,
                timestamp,
                event_type,
                namespace,
                secret_name,
                lineage_id,
                context,
                hmac: [0u8; 32], // Not used for verification
            };

            // Compute expected HMAC
            let entry_bytes = entry.canonical_bytes();
            let expected_hmac = self.compute_hmac(&entry_bytes, &prev_hmac);

            // Extract stored HMAC
            let mut stored_hmac = [0u8; 32];
            if hmac_vec.len() != 32 {
                return Err(AuditError::IntegrityFailed(sequence));
            }
            stored_hmac.copy_from_slice(&hmac_vec);

            // Compare
            if !constant_time_eq(&expected_hmac, &stored_hmac) {
                return Err(AuditError::IntegrityFailed(sequence));
            }

            prev_hmac = stored_hmac;
            expected_seq = sequence + 1;
        }

        Ok(())
    }

    /// Query entries by time range.
    pub fn query_by_time(&self, start: u128, end: u128) -> Vec<AuditEntry> {
        self.query_with_filter(|entry| entry.timestamp >= start && entry.timestamp <= end)
    }

    /// Query entries by secret name.
    pub fn query_by_secret(&self, namespace: &str, name: &str) -> Vec<AuditEntry> {
        let namespace = namespace.to_string();
        let name = name.to_string();
        self.query_with_filter(move |entry| {
            entry.namespace == namespace
                && entry.secret_name.as_ref().map(|s| s == &name).unwrap_or(false)
        })
    }

    /// Query entries by lineage ID.
    pub fn query_by_lineage(&self, lineage_id: &str) -> Vec<AuditEntry> {
        let lineage_id = lineage_id.to_string();
        self.query_with_filter(move |entry| {
            entry.lineage_id.as_ref().map(|id| id == &lineage_id).unwrap_or(false)
        })
    }

    /// Get the last N entries.
    pub fn tail(&self, n: usize) -> Vec<AuditEntry> {
        let mut stmt = self.conn.prepare(
            "SELECT sequence, timestamp, event_type, namespace, secret_name, lineage_id, context, hmac
             FROM audit_log ORDER BY sequence DESC LIMIT ?1",
        ).expect("Failed to prepare statement");

        let rows = stmt.query_map(params![n as i64], |row| {
            Self::row_to_entry(row)
        }).expect("Failed to query");

        let mut entries: Vec<AuditEntry> = rows.filter_map(|r| r.ok()).collect();
        entries.reverse(); // Return in chronological order
        entries
    }

    /// Export log to JSON.
    pub fn export_json(&self) -> AuditResult<String> {
        let entries = self.all_entries();
        serde_json::to_string_pretty(&entries)
            .map_err(|e| AuditError::Serialization(e.to_string()))
    }

    /// Get the path to the database file.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Get all entries.
    fn all_entries(&self) -> Vec<AuditEntry> {
        let mut stmt = self.conn.prepare(
            "SELECT sequence, timestamp, event_type, namespace, secret_name, lineage_id, context, hmac
             FROM audit_log ORDER BY sequence ASC",
        ).expect("Failed to prepare statement");

        let rows = stmt.query_map([], |row| {
            Self::row_to_entry(row)
        }).expect("Failed to query");

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Query with a filter predicate.
    fn query_with_filter<F>(&self, predicate: F) -> Vec<AuditEntry>
    where
        F: Fn(&AuditEntry) -> bool,
    {
        self.all_entries().into_iter().filter(predicate).collect()
    }

    /// Convert a database row to an AuditEntry.
    fn row_to_entry(row: &rusqlite::Row) -> rusqlite::Result<AuditEntry> {
        let sequence: i64 = row.get(0)?;
        let timestamp: i64 = row.get(1)?;
        let event_type_str: String = row.get(2)?;
        let namespace: String = row.get(3)?;
        let secret_name: Option<String> = row.get(4)?;
        let lineage_id: Option<String> = row.get(5)?;
        let context: Option<String> = row.get(6)?;
        let hmac_vec: Vec<u8> = row.get(7)?;

        let event_type = AuditEventType::from_str(&event_type_str)
            .unwrap_or(AuditEventType::SecretRead);

        let mut hmac = [0u8; 32];
        if hmac_vec.len() == 32 {
            hmac.copy_from_slice(&hmac_vec);
        }

        Ok(AuditEntry {
            sequence: sequence as u64,
            timestamp: timestamp as u128,
            event_type,
            namespace,
            secret_name,
            lineage_id,
            context,
            hmac,
        })
    }

    /// Get the entry count.
    pub fn len(&self) -> usize {
        let count: i64 = self.conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap_or(0);
        count as usize
    }

    /// Check if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the last sequence number.
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
}

/// Constant-time comparison of two byte slices.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_append_and_verify() {
        let mut log = AuditLog::new(test_key());

        // Append entries
        for i in 0..10 {
            log.append(
                AuditEventType::SecretRead,
                "test",
                Some(&format!("secret_{}", i)),
                Some("lineage_1"),
                None,
            )
            .unwrap();
        }

        assert_eq!(log.len(), 10);
        assert!(log.verify().is_ok());
    }

    #[test]
    fn test_verify_detects_tampering() {
        let mut log = AuditLog::new(test_key());

        // Append entries
        for i in 0..5 {
            log.append(
                AuditEventType::SecretCreated,
                "prod",
                Some(&format!("key_{}", i)),
                None,
                None,
            )
            .unwrap();
        }

        // Tamper with an entry
        log.conn
            .execute(
                "UPDATE audit_log SET context = 'tampered' WHERE sequence = 3",
                [],
            )
            .unwrap();

        // Verification should fail
        let result = log.verify();
        assert!(matches!(result, Err(AuditError::IntegrityFailed(3))));
    }

    #[test]
    fn test_verify_detects_deletion() {
        let mut log = AuditLog::new(test_key());

        // Append entries
        for i in 0..5 {
            log.append(
                AuditEventType::SecretRead,
                "test",
                Some(&format!("secret_{}", i)),
                None,
                None,
            )
            .unwrap();
        }

        // Delete an entry
        log.conn
            .execute("DELETE FROM audit_log WHERE sequence = 3", [])
            .unwrap();

        // Verification should fail (sequence gap)
        let result = log.verify();
        assert!(matches!(result, Err(AuditError::IntegrityFailed(_))));
    }

    #[test]
    fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("audit.db");
        let key = test_key();

        // Create and populate
        {
            let mut log = AuditLog::open(&db_path, key).unwrap();
            log.append(AuditEventType::VaultOpened, "default", None, None, None)
                .unwrap();
            log.append(
                AuditEventType::SecretCreated,
                "default",
                Some("API_KEY"),
                None,
                None,
            )
            .unwrap();
        }

        // Reopen and verify
        {
            let log = AuditLog::open(&db_path, key).unwrap();
            assert_eq!(log.len(), 2);
            assert!(log.verify().is_ok());

            let entries = log.tail(10);
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].event_type, AuditEventType::VaultOpened);
            assert_eq!(entries[1].event_type, AuditEventType::SecretCreated);
        }
    }

    #[test]
    fn test_query_by_secret() {
        let mut log = AuditLog::new(test_key());

        log.append(AuditEventType::SecretRead, "prod", Some("API_KEY"), None, None).unwrap();
        log.append(AuditEventType::SecretRead, "prod", Some("DB_PASS"), None, None).unwrap();
        log.append(AuditEventType::SecretRead, "staging", Some("API_KEY"), None, None).unwrap();
        log.append(AuditEventType::SecretUpdated, "prod", Some("API_KEY"), None, None).unwrap();

        let results = log.query_by_secret("prod", "API_KEY");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_by_lineage() {
        let mut log = AuditLog::new(test_key());

        log.append(AuditEventType::SecretRead, "prod", Some("KEY1"), Some("req_1"), None).unwrap();
        log.append(AuditEventType::SecretRead, "prod", Some("KEY2"), Some("req_1"), None).unwrap();
        log.append(AuditEventType::SecretRead, "prod", Some("KEY3"), Some("req_2"), None).unwrap();

        let results = log.query_by_lineage("req_1");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_tail() {
        let mut log = AuditLog::new(test_key());

        for i in 0..20 {
            log.append(
                AuditEventType::SecretRead,
                "test",
                Some(&format!("secret_{}", i)),
                None,
                None,
            )
            .unwrap();
        }

        let last_5 = log.tail(5);
        assert_eq!(last_5.len(), 5);
        assert_eq!(last_5[0].sequence, 16); // 0-indexed from sequence 1
        assert_eq!(last_5[4].sequence, 20);
    }

    #[test]
    fn test_export_json() {
        let mut log = AuditLog::new(test_key());

        log.append(AuditEventType::VaultOpened, "test", None, None, None).unwrap();
        log.append(AuditEventType::SecretCreated, "test", Some("KEY"), None, Some("created by admin")).unwrap();

        let json = log.export_json().unwrap();
        assert!(json.contains("vault_opened"));
        assert!(json.contains("secret_created"));
        assert!(json.contains("created by admin"));
    }

    #[test]
    fn test_large_log_performance() {
        let mut log = AuditLog::new(test_key());

        // Append 100 entries
        for i in 0..100 {
            log.append(
                AuditEventType::SecretRead,
                &format!("ns_{}", i % 10),
                Some(&format!("secret_{}", i)),
                Some(&format!("lineage_{}", i % 5)),
                None,
            )
            .unwrap();
        }

        // Verify should complete reasonably fast
        let start = std::time::Instant::now();
        assert!(log.verify().is_ok());
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 1000, "Verification took too long: {:?}", elapsed);
    }

    #[cfg(unix)]
    #[test]
    fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("audit.db");

        let _log = AuditLog::open(&db_path, test_key()).unwrap();

        let perms = std::fs::metadata(&db_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
