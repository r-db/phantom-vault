//! Encrypted SQLite storage for secrets.
//!
//! Provides persistent storage with encryption at rest using
//! the vault's master key.

use crate::crypto::DualLayerCrypto;
use crate::memory::SecretBuffer;
use rusqlite::{params, Connection, OpenFlags};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::debug;

/// Errors that can occur during storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Database error.
    #[error("database error: {0}")]
    Database(String),

    /// Secret not found.
    #[error("secret not found: {0}")]
    NotFound(String),

    /// Secret already exists.
    #[error("secret already exists: {0}")]
    AlreadyExists(String),

    /// Encryption/decryption error.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<rusqlite::Error> for StorageError {
    fn from(err: rusqlite::Error) -> Self {
        StorageError::Database(err.to_string())
    }
}

impl From<crate::crypto::CryptoError> for StorageError {
    fn from(err: crate::crypto::CryptoError) -> Self {
        StorageError::Crypto(err.to_string())
    }
}

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Metadata associated with a stored secret.
#[derive(Debug, Clone)]
pub struct SecretMetadata {
    /// Secret name/identifier.
    pub name: String,
    /// Namespace the secret belongs to.
    pub namespace: String,
    /// Creation timestamp (Unix epoch).
    pub created_at: u64,
    /// Last modification timestamp (Unix epoch).
    pub updated_at: u64,
    /// Version number for rotation tracking.
    pub version: u32,
    /// Optional expiration timestamp.
    pub expires_at: Option<u64>,
    /// Whether this is a canary secret.
    pub is_canary: bool,
}

/// Encrypted storage backend for secrets.
pub struct SecretStore {
    conn: Connection,
    db_path: PathBuf,
    crypto: DualLayerCrypto,
}

impl SecretStore {
    /// Open or create a secret store at the given path.
    pub fn open(path: &Path, crypto: DualLayerCrypto) -> StorageResult<Self> {
        // Set file permissions to 0600 before opening
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if !path.exists() {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|e| StorageError::Io(e.to_string()))?;
            }
        }

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        // Enable WAL mode for better concurrency
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let store = Self {
            conn,
            db_path: path.to_path_buf(),
            crypto,
        };

        store.init_schema()?;

        debug!("Opened secret store at {:?}", path);
        Ok(store)
    }

    /// Initialize the database schema.
    pub fn init_schema(&self) -> StorageResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace TEXT NOT NULL,
                name TEXT NOT NULL,
                encrypted_value BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                expires_at INTEGER,
                is_canary INTEGER NOT NULL DEFAULT 0,
                UNIQUE(namespace, name)
            );

            CREATE INDEX IF NOT EXISTS idx_secrets_namespace ON secrets(namespace);
            CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at) WHERE expires_at IS NOT NULL;
            "#,
        )?;

        Ok(())
    }

    /// Store a secret.
    pub fn put(
        &mut self,
        namespace: &str,
        name: &str,
        value: &SecretBuffer,
    ) -> StorageResult<()> {
        let now = current_timestamp();

        // Encrypt the secret value
        let encrypted = value.with_exposed(|bytes| self.crypto.encrypt(bytes))?;

        // Check if secret exists
        let exists: bool = self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM secrets WHERE namespace = ? AND name = ?",
            params![namespace, name],
            |row| row.get(0),
        )?;

        if exists {
            // Update existing secret
            self.conn.execute(
                "UPDATE secrets SET encrypted_value = ?, updated_at = ?, version = version + 1
                 WHERE namespace = ? AND name = ?",
                params![encrypted, now, namespace, name],
            )?;
        } else {
            // Insert new secret
            self.conn.execute(
                "INSERT INTO secrets (namespace, name, encrypted_value, created_at, updated_at, version)
                 VALUES (?, ?, ?, ?, ?, 1)",
                params![namespace, name, encrypted, now, now],
            )?;
        }

        debug!("Stored secret {}/{}", namespace, name);
        Ok(())
    }

    /// Store a secret with metadata.
    pub fn put_with_metadata(
        &mut self,
        namespace: &str,
        name: &str,
        value: &SecretBuffer,
        expires_at: Option<u64>,
        is_canary: bool,
    ) -> StorageResult<()> {
        let now = current_timestamp();

        // Encrypt the secret value
        let encrypted = value.with_exposed(|bytes| self.crypto.encrypt(bytes))?;

        // Check if secret exists
        let exists: bool = self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM secrets WHERE namespace = ? AND name = ?",
            params![namespace, name],
            |row| row.get(0),
        )?;

        if exists {
            // Update existing secret
            self.conn.execute(
                "UPDATE secrets SET encrypted_value = ?, updated_at = ?, version = version + 1,
                 expires_at = ?, is_canary = ?
                 WHERE namespace = ? AND name = ?",
                params![encrypted, now, expires_at, is_canary as i32, namespace, name],
            )?;
        } else {
            // Insert new secret
            self.conn.execute(
                "INSERT INTO secrets (namespace, name, encrypted_value, created_at, updated_at, version, expires_at, is_canary)
                 VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                params![namespace, name, encrypted, now, now, expires_at, is_canary as i32],
            )?;
        }

        debug!("Stored secret {}/{} (canary={})", namespace, name, is_canary);
        Ok(())
    }

    /// Retrieve a secret.
    pub fn get(&self, namespace: &str, name: &str) -> StorageResult<SecretBuffer> {
        let encrypted: Vec<u8> = self
            .conn
            .query_row(
                "SELECT encrypted_value FROM secrets WHERE namespace = ? AND name = ?",
                params![namespace, name],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StorageError::NotFound(format!("{}/{}", namespace, name))
                }
                _ => StorageError::Database(e.to_string()),
            })?;

        let decrypted = self.crypto.decrypt(&encrypted)?;
        Ok(decrypted)
    }

    /// Delete a secret.
    pub fn delete(&mut self, namespace: &str, name: &str) -> StorageResult<()> {
        let rows = self.conn.execute(
            "DELETE FROM secrets WHERE namespace = ? AND name = ?",
            params![namespace, name],
        )?;

        if rows == 0 {
            return Err(StorageError::NotFound(format!("{}/{}", namespace, name)));
        }

        debug!("Deleted secret {}/{}", namespace, name);
        Ok(())
    }

    /// List all secrets in a namespace.
    pub fn list(&self, namespace: &str) -> StorageResult<Vec<SecretMetadata>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, namespace, created_at, updated_at, version, expires_at, is_canary
             FROM secrets WHERE namespace = ? ORDER BY name",
        )?;

        let rows = stmt.query_map(params![namespace], |row| {
            Ok(SecretMetadata {
                name: row.get(0)?,
                namespace: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
                version: row.get(4)?,
                expires_at: row.get(5)?,
                is_canary: row.get::<_, i32>(6)? != 0,
            })
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }

        Ok(result)
    }

    /// List all secrets across all namespaces.
    pub fn list_all(&self) -> StorageResult<Vec<SecretMetadata>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, namespace, created_at, updated_at, version, expires_at, is_canary
             FROM secrets ORDER BY namespace, name",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(SecretMetadata {
                name: row.get(0)?,
                namespace: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
                version: row.get(4)?,
                expires_at: row.get(5)?,
                is_canary: row.get::<_, i32>(6)? != 0,
            })
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }

        Ok(result)
    }

    /// Get metadata for a specific secret.
    pub fn metadata(&self, namespace: &str, name: &str) -> StorageResult<SecretMetadata> {
        self.conn
            .query_row(
                "SELECT name, namespace, created_at, updated_at, version, expires_at, is_canary
                 FROM secrets WHERE namespace = ? AND name = ?",
                params![namespace, name],
                |row| {
                    Ok(SecretMetadata {
                        name: row.get(0)?,
                        namespace: row.get(1)?,
                        created_at: row.get(2)?,
                        updated_at: row.get(3)?,
                        version: row.get(4)?,
                        expires_at: row.get(5)?,
                        is_canary: row.get::<_, i32>(6)? != 0,
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StorageError::NotFound(format!("{}/{}", namespace, name))
                }
                _ => StorageError::Database(e.to_string()),
            })
    }

    /// Check if a secret exists.
    pub fn exists(&self, namespace: &str, name: &str) -> StorageResult<bool> {
        let count: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM secrets WHERE namespace = ? AND name = ?",
            params![namespace, name],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }

    /// Get secrets expiring before a given timestamp.
    pub fn get_expiring(&self, before: u64) -> StorageResult<Vec<SecretMetadata>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, namespace, created_at, updated_at, version, expires_at, is_canary
             FROM secrets WHERE expires_at IS NOT NULL AND expires_at < ? ORDER BY expires_at",
        )?;

        let rows = stmt.query_map(params![before], |row| {
            Ok(SecretMetadata {
                name: row.get(0)?,
                namespace: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
                version: row.get(4)?,
                expires_at: row.get(5)?,
                is_canary: row.get::<_, i32>(6)? != 0,
            })
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }

        Ok(result)
    }

    /// Compact the database to reclaim space.
    pub fn compact(&mut self) -> StorageResult<()> {
        self.conn.execute("VACUUM", [])?;
        debug!("Compacted secret store");
        Ok(())
    }

    /// Get the path to the database file.
    pub fn path(&self) -> &Path {
        &self.db_path
    }

    /// Get the number of secrets in the store.
    pub fn count(&self) -> StorageResult<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM secrets", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get the number of secrets in a namespace.
    pub fn count_in_namespace(&self, namespace: &str) -> StorageResult<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM secrets WHERE namespace = ?",
            params![namespace],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoKey, DualLayerCrypto};
    use tempfile::TempDir;

    fn create_test_crypto() -> DualLayerCrypto {
        let inner_key = CryptoKey::generate().unwrap();
        let outer_key = CryptoKey::generate().unwrap();
        DualLayerCrypto::new(inner_key, outer_key)
    }

    fn create_test_store() -> (SecretStore, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("secrets.db");
        let crypto = create_test_crypto();
        let store = SecretStore::open(&db_path, crypto).unwrap();
        (store, temp_dir)
    }

    #[test]
    fn test_store_open() {
        let (store, _temp) = create_test_store();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_put_get_secret() {
        let (mut store, _temp) = create_test_store();
        let value = SecretBuffer::from_slice(b"super_secret_value").unwrap();

        store.put("default", "API_KEY", &value).unwrap();

        let retrieved = store.get("default", "API_KEY").unwrap();
        retrieved.with_exposed(|bytes| {
            assert_eq!(bytes, b"super_secret_value");
        });
    }

    #[test]
    fn test_update_secret() {
        let (mut store, _temp) = create_test_store();
        let value1 = SecretBuffer::from_slice(b"original").unwrap();
        let value2 = SecretBuffer::from_slice(b"updated").unwrap();

        store.put("default", "KEY", &value1).unwrap();
        let meta1 = store.metadata("default", "KEY").unwrap();
        assert_eq!(meta1.version, 1);

        store.put("default", "KEY", &value2).unwrap();
        let meta2 = store.metadata("default", "KEY").unwrap();
        assert_eq!(meta2.version, 2);

        let retrieved = store.get("default", "KEY").unwrap();
        retrieved.with_exposed(|bytes| {
            assert_eq!(bytes, b"updated");
        });
    }

    #[test]
    fn test_delete_secret() {
        let (mut store, _temp) = create_test_store();
        let value = SecretBuffer::from_slice(b"value").unwrap();

        store.put("default", "TO_DELETE", &value).unwrap();
        assert!(store.exists("default", "TO_DELETE").unwrap());

        store.delete("default", "TO_DELETE").unwrap();
        assert!(!store.exists("default", "TO_DELETE").unwrap());
    }

    #[test]
    fn test_delete_nonexistent() {
        let (mut store, _temp) = create_test_store();
        let result = store.delete("default", "NONEXISTENT");
        assert!(matches!(result, Err(StorageError::NotFound(_))));
    }

    #[test]
    fn test_list_secrets() {
        let (mut store, _temp) = create_test_store();
        let value = SecretBuffer::from_slice(b"value").unwrap();

        store.put("ns1", "KEY_A", &value).unwrap();
        store.put("ns1", "KEY_B", &value).unwrap();
        store.put("ns2", "KEY_C", &value).unwrap();

        let ns1_secrets = store.list("ns1").unwrap();
        assert_eq!(ns1_secrets.len(), 2);
        assert_eq!(ns1_secrets[0].name, "KEY_A");
        assert_eq!(ns1_secrets[1].name, "KEY_B");

        let ns2_secrets = store.list("ns2").unwrap();
        assert_eq!(ns2_secrets.len(), 1);
    }

    #[test]
    fn test_list_all() {
        let (mut store, _temp) = create_test_store();
        let value = SecretBuffer::from_slice(b"value").unwrap();

        store.put("ns1", "KEY_A", &value).unwrap();
        store.put("ns2", "KEY_B", &value).unwrap();

        let all = store.list_all().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_exists() {
        let (mut store, _temp) = create_test_store();
        let value = SecretBuffer::from_slice(b"value").unwrap();

        assert!(!store.exists("default", "KEY").unwrap());
        store.put("default", "KEY", &value).unwrap();
        assert!(store.exists("default", "KEY").unwrap());
    }

    #[test]
    fn test_get_nonexistent() {
        let (store, _temp) = create_test_store();
        let result = store.get("default", "NONEXISTENT");
        assert!(matches!(result, Err(StorageError::NotFound(_))));
    }

    #[test]
    fn test_metadata() {
        let (mut store, _temp) = create_test_store();
        let value = SecretBuffer::from_slice(b"value").unwrap();

        store
            .put_with_metadata("default", "KEY", &value, Some(9999999999), true)
            .unwrap();

        let meta = store.metadata("default", "KEY").unwrap();
        assert_eq!(meta.name, "KEY");
        assert_eq!(meta.namespace, "default");
        assert_eq!(meta.version, 1);
        assert_eq!(meta.expires_at, Some(9999999999));
        assert!(meta.is_canary);
    }

    #[test]
    fn test_expiring_secrets() {
        let (mut store, _temp) = create_test_store();
        let value = SecretBuffer::from_slice(b"value").unwrap();

        let now = current_timestamp();
        store
            .put_with_metadata("default", "EXPIRING", &value, Some(now + 100), false)
            .unwrap();
        store
            .put_with_metadata("default", "NOT_EXPIRING", &value, Some(now + 10000), false)
            .unwrap();
        store.put("default", "NO_EXPIRY", &value).unwrap();

        let expiring = store.get_expiring(now + 500).unwrap();
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].name, "EXPIRING");
    }

    #[test]
    fn test_count() {
        let (mut store, _temp) = create_test_store();
        let value = SecretBuffer::from_slice(b"value").unwrap();

        assert_eq!(store.count().unwrap(), 0);

        store.put("ns1", "KEY_A", &value).unwrap();
        store.put("ns1", "KEY_B", &value).unwrap();
        store.put("ns2", "KEY_C", &value).unwrap();

        assert_eq!(store.count().unwrap(), 3);
        assert_eq!(store.count_in_namespace("ns1").unwrap(), 2);
        assert_eq!(store.count_in_namespace("ns2").unwrap(), 1);
    }

    #[test]
    fn test_compact() {
        let (mut store, _temp) = create_test_store();
        let value = SecretBuffer::from_slice(b"value").unwrap();

        // Add and delete some data
        for i in 0..10 {
            store.put("default", &format!("KEY_{}", i), &value).unwrap();
        }
        for i in 0..5 {
            store.delete("default", &format!("KEY_{}", i)).unwrap();
        }

        // Compact should not fail
        store.compact().unwrap();
    }
}
