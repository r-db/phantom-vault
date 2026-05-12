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

    /// Namespace for organization (e.g., "work", "personal")
    #[serde(default)]
    pub namespace: Option<String>,
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
            namespace: None,
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

    /// Canary (honeypot) secrets for detecting exfiltration
    #[serde(default)]
    pub canaries: Vec<CanarySecret>,

    /// Spending guardrails per secret — periodically polled against provider usage APIs
    /// to alert/lock before users wake up to a surprise bill.
    #[serde(default)]
    pub guardrails: Vec<Guardrail>,
}

impl VaultData {
    pub fn new() -> Self {
        Self::default()
    }

    /// Find entry by reference name (searches all namespaces - use find_by_reference_in_namespace for namespace-specific lookup)
    pub fn find_by_reference(&self, reference: &str) -> Option<&SecretEntry> {
        self.entries.iter().find(|e| e.reference == reference)
    }

    /// Find entry by reference within a specific namespace
    pub fn find_by_reference_in_namespace(
        &self,
        reference: &str,
        namespace: Option<&str>,
    ) -> Option<&SecretEntry> {
        self.entries.iter().find(|e| {
            e.reference == reference && e.namespace.as_deref() == namespace
        })
    }

    /// Find mutable entry by reference within a specific namespace
    pub fn find_by_reference_in_namespace_mut(
        &mut self,
        reference: &str,
        namespace: Option<&str>,
    ) -> Option<&mut SecretEntry> {
        self.entries.iter_mut().find(|e| {
            e.reference == reference && e.namespace.as_deref() == namespace
        })
    }

    /// Find entry by ID
    pub fn find_by_id(&self, id: &Uuid) -> Option<&SecretEntry> {
        self.entries.iter().find(|e| &e.id == id)
    }

    /// Check if reference exists
    pub fn reference_exists(&self, reference: &str) -> bool {
        self.entries.iter().any(|e| e.reference == reference)
    }

    /// List all unique namespaces
    pub fn list_namespaces(&self) -> Vec<String> {
        let mut namespaces: Vec<String> = self
            .entries
            .iter()
            .filter_map(|e| e.namespace.clone())
            .collect();
        namespaces.sort();
        namespaces.dedup();
        namespaces
    }

    /// Filter entries by namespace (None = show all)
    pub fn filter_by_namespace(&self, namespace: Option<&str>) -> Vec<&SecretEntry> {
        match namespace {
            None => self.entries.iter().collect(),
            Some(ns) => self
                .entries
                .iter()
                .filter(|e| e.namespace.as_deref() == Some(ns))
                .collect(),
        }
    }

    /// Count entries in a namespace
    pub fn count_in_namespace(&self, namespace: Option<&str>) -> usize {
        self.filter_by_namespace(namespace).len()
    }

    /// Validate that all entries have corresponding encrypted values
    pub fn validate_consistency(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        for entry in &self.entries {
            if !self.encrypted_values.contains_key(&entry.id) {
                errors.push(format!(
                    "Entry '{}' (id: {}) has no encrypted value",
                    entry.reference, entry.id
                ));
            }
        }

        // Also check for orphaned encrypted values (values without entries)
        for id in self.encrypted_values.keys() {
            if !self.entries.iter().any(|e| &e.id == id) {
                errors.push(format!(
                    "Encrypted value with id {} has no corresponding entry",
                    id
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
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

/// Canary (honeypot) secret for detecting exfiltration attempts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanarySecret {
    /// Unique identifier
    pub id: Uuid,

    /// Human-readable name
    pub name: String,

    /// Pattern type used to generate the canary
    pub pattern: CanaryPattern,

    /// The generated fake credential value
    pub value: String,

    /// When the canary was created
    pub created_at: DateTime<Utc>,

    /// Number of times this canary was detected in output
    pub alert_count: u32,

    /// Last time an alert was triggered
    pub last_alert_at: Option<DateTime<Utc>>,
}

/// A spending cap on a secret (typically an AI provider API key).
/// Periodically polled against the provider's usage API; warns or locks the key
/// when usage approaches the configured monthly cap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guardrail {
    /// Reference name of the secret this guards — must match an entry.reference
    pub secret_ref: String,

    /// Provider identifier — "openai", "anthropic", "gemini", "stripe", "twilio",
    /// "elevenlabs", "deepgram", or "manual" for user-reported usage
    pub provider: String,

    /// Monthly cap in USD
    pub cap_usd: f64,

    /// Latest observed spend in USD (cached from last successful poll)
    #[serde(default)]
    pub current_usd: f64,

    /// When we last polled the provider successfully (None = never polled yet)
    #[serde(default)]
    pub last_polled_at: Option<DateTime<Utc>>,

    /// Last poll error message, if the most recent poll failed
    #[serde(default)]
    pub last_error: Option<String>,

    /// Soft-alert threshold as a percentage of cap (default 80%)
    #[serde(default = "default_alert_pct")]
    pub alert_at_pct: u8,

    /// When this guardrail was created
    pub created_at: DateTime<Utc>,
}

fn default_alert_pct() -> u8 {
    80
}

impl Guardrail {
    pub fn new(secret_ref: String, provider: String, cap_usd: f64) -> Self {
        Self {
            secret_ref,
            provider,
            cap_usd,
            current_usd: 0.0,
            last_polled_at: None,
            last_error: None,
            alert_at_pct: 80,
            created_at: Utc::now(),
        }
    }

    /// Percentage of cap currently used. Returns 0.0 if cap is 0 (defensive).
    pub fn pct_used(&self) -> f64 {
        if self.cap_usd <= 0.0 {
            0.0
        } else {
            (self.current_usd / self.cap_usd) * 100.0
        }
    }

    /// True if usage has crossed the soft alert threshold
    pub fn is_alerting(&self) -> bool {
        self.pct_used() >= self.alert_at_pct as f64
    }

    /// True if usage has met or exceeded the cap
    pub fn is_over_cap(&self) -> bool {
        self.current_usd >= self.cap_usd
    }
}

impl CanarySecret {
    /// Create a new canary with a generated value
    pub fn new(name: String, pattern: CanaryPattern) -> Self {
        let value = pattern.generate();
        Self {
            id: Uuid::new_v4(),
            name,
            pattern,
            value,
            created_at: Utc::now(),
            alert_count: 0,
            last_alert_at: None,
        }
    }

    /// Create a new canary, checking for value collision with existing canaries
    /// Returns Err if the generated value collides (regenerate and retry)
    pub fn new_checked(name: String, pattern: CanaryPattern, existing_canaries: &[CanarySecret]) -> Result<Self, String> {
        let value = pattern.generate();

        // Check for collision with existing canary values
        for existing in existing_canaries {
            if existing.value == value {
                return Err("Generated canary value collides with existing canary. Please retry.".to_string());
            }
        }

        Ok(Self {
            id: Uuid::new_v4(),
            name,
            pattern,
            value,
            created_at: Utc::now(),
            alert_count: 0,
            last_alert_at: None,
        })
    }

    /// Record an alert (canary detected in output)
    pub fn record_alert(&mut self) {
        self.alert_count += 1;
        self.last_alert_at = Some(Utc::now());
    }
}

/// Pattern types for generating realistic-looking fake credentials
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CanaryPattern {
    /// AWS Access Key format (AKIA...)
    AwsAccessKey,
    /// Stripe API key format (sk_test_...)
    StripeKey,
    /// GitHub personal access token (ghp_...)
    GitHubToken,
    /// Generic API key with custom format
    Custom {
        prefix: String,
        length: usize,
    },
}

impl CanaryPattern {
    /// Generate a realistic-looking fake credential
    pub fn generate(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        match self {
            CanaryPattern::AwsAccessKey => {
                // AWS Access Key: AKIA + 16 alphanumeric chars
                let suffix: String = (0..16)
                    .map(|_| {
                        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                        chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
                    })
                    .collect();
                format!("AKIA{}", suffix)
            }
            CanaryPattern::StripeKey => {
                // Stripe test key: sk_test_ + 24 alphanumeric chars
                let suffix: String = (0..24)
                    .map(|_| {
                        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                        chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
                    })
                    .collect();
                format!("sk_test_{}", suffix)
            }
            CanaryPattern::GitHubToken => {
                // GitHub PAT: ghp_ + 36 alphanumeric chars
                let suffix: String = (0..36)
                    .map(|_| {
                        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                        chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
                    })
                    .collect();
                format!("ghp_{}", suffix)
            }
            CanaryPattern::Custom { prefix, length } => {
                let suffix: String = (0..*length)
                    .map(|_| {
                        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                        chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
                    })
                    .collect();
                format!("{}{}", prefix, suffix)
            }
        }
    }

    /// Get pattern name for display
    pub fn name(&self) -> &str {
        match self {
            CanaryPattern::AwsAccessKey => "aws",
            CanaryPattern::StripeKey => "stripe",
            CanaryPattern::GitHubToken => "github",
            CanaryPattern::Custom { .. } => "custom",
        }
    }
}

impl std::str::FromStr for CanaryPattern {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aws" | "aws-access-key" => Ok(CanaryPattern::AwsAccessKey),
            "stripe" | "stripe-key" => Ok(CanaryPattern::StripeKey),
            "github" | "github-token" => Ok(CanaryPattern::GitHubToken),
            _ => Err(format!("Unknown pattern '{}'. Use: aws, stripe, or github", s)),
        }
    }
}

/// SSH host key verification mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum SshHostKeyMode {
    /// Accept new keys, reject changed keys (secure default)
    #[default]
    AcceptNew,
    /// Strict: only accept keys in known_hosts
    Yes,
    /// Insecure: accept all keys (NOT recommended)
    No,
}

impl SshHostKeyMode {
    /// Get the SSH option value
    pub fn as_ssh_option(&self) -> &'static str {
        match self {
            SshHostKeyMode::AcceptNew => "accept-new",
            SshHostKeyMode::Yes => "yes",
            SshHostKeyMode::No => "no",
        }
    }
}

/// Security policy for controlling secret access
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityPolicy {
    /// Allowed tools (empty = all allowed)
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// Blocked tools (takes precedence over allowed)
    #[serde(default)]
    pub blocked_tools: Vec<String>,

    /// Tools that require explicit confirmation
    #[serde(default)]
    pub require_confirmation: Vec<String>,

    /// Maximum secret accesses per hour (None = unlimited)
    #[serde(default)]
    pub rate_limit: Option<u32>,

    /// Time-based access restrictions
    #[serde(default)]
    pub time_restrictions: Option<TimeRestriction>,

    /// SSH host key verification mode (default: accept-new)
    #[serde(default)]
    pub ssh_host_key_mode: SshHostKeyMode,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allowed_tools: vec![],
            blocked_tools: vec![],
            require_confirmation: vec!["shell_exec".to_string()],
            rate_limit: None,
            time_restrictions: None,
            ssh_host_key_mode: SshHostKeyMode::default(),
        }
    }
}

impl SecurityPolicy {
    /// Check if a tool is allowed by this policy
    pub fn is_tool_allowed(&self, tool_name: &str) -> bool {
        // Blocked takes precedence
        if self.blocked_tools.contains(&tool_name.to_string()) {
            return false;
        }

        // If allowed_tools is empty, all non-blocked tools are allowed
        if self.allowed_tools.is_empty() {
            return true;
        }

        // Otherwise, tool must be in allowed list
        self.allowed_tools.contains(&tool_name.to_string())
    }

    /// Check if a tool requires confirmation
    pub fn requires_confirmation(&self, tool_name: &str) -> bool {
        self.require_confirmation.contains(&tool_name.to_string())
    }

    /// Format policy as TOML for display
    pub fn to_toml(&self) -> String {
        let mut lines = vec![];

        if !self.allowed_tools.is_empty() {
            lines.push(format!("allowed_tools = {:?}", self.allowed_tools));
        }

        if !self.blocked_tools.is_empty() {
            lines.push(format!("blocked_tools = {:?}", self.blocked_tools));
        }

        if !self.require_confirmation.is_empty() {
            lines.push(format!("require_confirmation = {:?}", self.require_confirmation));
        }

        if let Some(limit) = self.rate_limit {
            lines.push(format!("rate_limit = {}", limit));
        }

        if let Some(ref tr) = self.time_restrictions {
            lines.push(String::new());
            lines.push("[time_restrictions]".to_string());
            lines.push(format!("enabled = {}", tr.enabled));
            lines.push(format!("start_hour = {}", tr.start_hour));
            lines.push(format!("end_hour = {}", tr.end_hour));
            if let Some(ref tz) = tr.timezone {
                lines.push(format!("timezone = \"{}\"", tz));
            }
        }

        if lines.is_empty() {
            "# Default policy (no restrictions)".to_string()
        } else {
            lines.join("\n")
        }
    }
}

/// Time-based access restrictions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimeRestriction {
    /// Whether time restrictions are enabled
    pub enabled: bool,

    /// Start hour (0-23) when access is allowed
    pub start_hour: u8,

    /// End hour (0-23) when access is allowed
    pub end_hour: u8,

    /// Timezone (e.g., "America/New_York")
    pub timezone: Option<String>,
}

impl TimeRestriction {
    /// Create a new time restriction with validated hours
    pub fn new(start_hour: u8, end_hour: u8, timezone: Option<String>) -> Result<Self, String> {
        if start_hour > 23 {
            return Err(format!("start_hour {} is invalid (must be 0-23)", start_hour));
        }
        if end_hour > 23 {
            return Err(format!("end_hour {} is invalid (must be 0-23)", end_hour));
        }
        Ok(Self {
            enabled: true,
            start_hour,
            end_hour,
            timezone,
        })
    }

    /// Validate that hours are in valid range
    pub fn validate(&self) -> Result<(), String> {
        if self.start_hour > 23 {
            return Err(format!("start_hour {} is invalid (must be 0-23)", self.start_hour));
        }
        if self.end_hour > 23 {
            return Err(format!("end_hour {} is invalid (must be 0-23)", self.end_hour));
        }
        Ok(())
    }
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

    /// Security policy for access control
    #[serde(default)]
    pub security_policy: SecurityPolicy,
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
            security_policy: SecurityPolicy::default(),
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
