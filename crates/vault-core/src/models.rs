//! Data models for vault secrets and metadata

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Supported secret types with type-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum SecretType {
    /// API key with provider info
    ApiKey {
        provider: String,
        scopes: Vec<String>,
    },
    /// Authentication token
    Token {
        token_type: TokenType,
    },
    /// Database connection string
    ConnectionString {
        db_type: DatabaseType,
        host: String,
        port: u16,
        database: String,
        username: String,
    },
    /// SSH private key
    SshKey {
        key_type: SshKeyType,
        public_key: String,
        passphrase_protected: bool,
    },
    /// TLS/Code signing certificate
    Certificate {
        cert_type: CertType,
        public_cert: String,
        chain: Vec<String>,
    },
    /// Generic secret
    Generic {
        format: String,
    },
}

impl Default for SecretType {
    fn default() -> Self {
        SecretType::Generic {
            format: "text".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    Bearer,
    Basic,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DatabaseType {
    Postgres,
    MySQL,
    MongoDB,
    Redis,
    SQLite,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SshKeyType {
    Rsa,
    Ed25519,
    Ecdsa,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CertType {
    Tls,
    CodeSigning,
    Custom(String),
}

/// Core secret entry (metadata only - value stored separately encrypted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Unique identifier
    pub id: Uuid,

    /// Human-readable reference name (e.g., "prod-db", "my-railway")
    pub reference: String,

    /// Type-specific metadata
    pub secret_type: SecretType,

    /// Optional description
    pub description: Option<String>,

    /// Tags for organization
    pub tags: Vec<String>,

    /// When the secret was created
    pub created_at: DateTime<Utc>,

    /// Last update time
    pub updated_at: DateTime<Utc>,

    /// Optional expiration date
    pub expires_at: Option<DateTime<Utc>>,

    /// Rotation reminder in days (e.g., 30, 60, 90)
    pub rotation_reminder_days: Option<u32>,

    /// When the secret was last rotated
    pub last_rotated_at: Option<DateTime<Utc>>,

    /// Optional usage limit
    pub usage_limit: Option<u64>,

    /// Current usage count
    pub usage_count: u64,

    /// Last time the secret was used
    pub last_used_at: Option<DateTime<Utc>>,

    /// Which MCP tools can access this secret
    pub allowed_tools: Vec<String>,

    /// Auto-inject when matching tool is called
    pub auto_inject: bool,
}

impl SecretEntry {
    /// Create a new secret entry
    pub fn new(reference: String, secret_type: SecretType) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            reference,
            secret_type,
            description: None,
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
            expires_at: None,
            rotation_reminder_days: None,
            last_rotated_at: None,
            usage_limit: None,
            usage_count: 0,
            last_used_at: None,
            allowed_tools: Vec::new(),
            auto_inject: true,
        }
    }

    /// Check if the secret is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Utc::now() > exp)
            .unwrap_or(false)
    }

    /// Check if rotation is due
    pub fn needs_rotation(&self) -> bool {
        if let Some(days) = self.rotation_reminder_days {
            let last = self.last_rotated_at.unwrap_or(self.created_at);
            let elapsed = Utc::now().signed_duration_since(last);
            return elapsed.num_days() >= days as i64;
        }
        false
    }

    /// Check if usage limit exceeded
    pub fn is_usage_exceeded(&self) -> bool {
        self.usage_limit
            .map(|limit| self.usage_count >= limit)
            .unwrap_or(false)
    }

    /// Days until expiration (None if no expiration set)
    pub fn days_until_expiration(&self) -> Option<i64> {
        self.expires_at.map(|exp| {
            exp.signed_duration_since(Utc::now()).num_days()
        })
    }

    /// Record a usage
    pub fn record_usage(&mut self) {
        self.usage_count += 1;
        self.last_used_at = Some(Utc::now());
    }
}

/// Encrypted vault file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedVault {
    /// Schema version for migrations
    pub version: u32,

    /// Argon2 salt (32 bytes)
    pub salt: [u8; 32],

    /// AES-GCM nonce (12 bytes)
    pub nonce: [u8; 12],

    /// Encrypted vault data
    pub ciphertext: Vec<u8>,

    /// SHA-256 checksum of plaintext for integrity
    pub checksum: [u8; 32],
}

impl EncryptedVault {
    pub const CURRENT_VERSION: u32 = 1;
}

/// Decrypted vault data (in-memory only, never persisted)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    /// Secret entries (metadata only)
    pub entries: Vec<SecretEntry>,

    /// Encrypted secret values keyed by entry ID
    pub encrypted_values: HashMap<Uuid, EncryptedValue>,

    /// Tool-to-credential bindings
    pub tool_bindings: HashMap<String, ToolBinding>,
}

impl VaultData {
    pub fn new() -> Self {
        Self::default()
    }

    /// Find entry by reference name
    pub fn find_by_reference(&self, reference: &str) -> Option<&SecretEntry> {
        self.entries.iter().find(|e| e.reference == reference)
    }

    /// Find entry by ID
    pub fn find_by_id(&self, id: &Uuid) -> Option<&SecretEntry> {
        self.entries.iter().find(|e| &e.id == id)
    }

    /// Check if reference exists
    pub fn reference_exists(&self, reference: &str) -> bool {
        self.entries.iter().any(|e| e.reference == reference)
    }
}

/// Individual encrypted secret value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedValue {
    /// AES-GCM nonce (12 bytes)
    pub nonce: [u8; 12],

    /// Encrypted value
    pub ciphertext: Vec<u8>,
}

/// Tool-to-credential binding for auto-injection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolBinding {
    /// Tool name
    pub tool_name: String,

    /// Parameter name to secret reference mapping
    pub parameter_mappings: HashMap<String, SecretReference>,
}

/// Reference to a secret value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretReference {
    /// Secret entry ID
    pub secret_id: Uuid,

    /// Optional field path for structured secrets
    pub field_path: Option<String>,
}

/// Vault configuration (non-sensitive, stored in plaintext)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Auto-lock timeout in seconds
    pub auto_lock_timeout_seconds: u64,

    /// Maximum unlock attempts before lockout
    pub max_unlock_attempts: u32,

    /// Lockout duration in seconds
    pub lockout_duration_seconds: u64,

    /// Argon2 memory cost in KB
    pub argon2_memory_kb: u32,

    /// Argon2 iterations
    pub argon2_iterations: u32,

    /// Argon2 parallelism
    pub argon2_parallelism: u32,

    /// MCP server mode
    pub mcp_server_mode: McpServerMode,

    /// HTTP port (if using HTTP mode)
    pub mcp_http_port: u16,

    /// Show expiration warnings this many days before
    pub expiration_warning_days: u32,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            auto_lock_timeout_seconds: 300, // 5 minutes
            max_unlock_attempts: 5,
            lockout_duration_seconds: 300,
            argon2_memory_kb: 65536, // 64 MB
            argon2_iterations: 3,
            argon2_parallelism: 4,
            mcp_server_mode: McpServerMode::Stdio,
            mcp_http_port: 3000,
            expiration_warning_days: 14,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum McpServerMode {
    Stdio,
    Http,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_entry_creation() {
        let entry = SecretEntry::new(
            "test-api".to_string(),
            SecretType::ApiKey {
                provider: "openai".to_string(),
                scopes: vec!["read".to_string()],
            },
        );

        assert_eq!(entry.reference, "test-api");
        assert_eq!(entry.usage_count, 0);
        assert!(!entry.is_expired());
        assert!(!entry.needs_rotation());
    }

    #[test]
    fn test_expiration_check() {
        let mut entry = SecretEntry::new("test".to_string(), SecretType::default());
        entry.expires_at = Some(Utc::now() - chrono::Duration::days(1));
        assert!(entry.is_expired());

        entry.expires_at = Some(Utc::now() + chrono::Duration::days(1));
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_rotation_check() {
        let mut entry = SecretEntry::new("test".to_string(), SecretType::default());
        entry.rotation_reminder_days = Some(30);
        entry.last_rotated_at = Some(Utc::now() - chrono::Duration::days(31));
        assert!(entry.needs_rotation());

        entry.last_rotated_at = Some(Utc::now() - chrono::Duration::days(10));
        assert!(!entry.needs_rotation());
    }
}
