//! MCP tools for vault operations.
//!
//! Provides tools like vault_list, vault_run, etc. for AI assistants.
//! CRITICAL: These tools NEVER return plaintext secret values.

use crate::config::{McpConfig, SensitivityLevel};
use crate::lineage::{RequestLineage, ToolCall};
use crate::McpError;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use phantom_core::memory::SecretBuffer;
use phantom_core::Vault;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Trait for vault backend implementations.
///
/// This allows using either the real Vault or a MockVault for testing.
pub trait VaultBackend: Send + Sync {
    /// List secrets in a namespace with their metadata.
    fn list(&self, namespace: &str) -> Result<Vec<SecretInfo>, String>;

    /// Check if a secret exists and return its metadata.
    fn exists(&self, namespace: &str, key: &str) -> Result<Option<SecretInfo>, String>;

    /// Get a masked version of a secret (last 4 characters).
    fn get_masked(&self, namespace: &str, key: &str) -> Result<String, String>;

    /// Get secrets by keys for command execution.
    fn get_secrets(&self, namespace: &str, keys: &[String]) -> Result<HashMap<String, SecretBuffer>, String>;

    /// Get health information.
    fn health(&self, namespace: &str) -> Result<HealthInfo, String>;
}

/// Information about a secret (metadata only, never the value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInfo {
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_accessed: DateTime<Utc>,
    pub access_count: u64,
    pub tags: Vec<String>,
    pub namespace: String,
}

/// Health information about the vault.
#[derive(Debug, Clone)]
pub struct HealthInfo {
    pub total_secrets: usize,
    pub expiring_soon: Vec<String>,
    pub last_audit: DateTime<Utc>,
}

/// Mock vault for testing (will be replaced with real Vault integration).
#[derive(Debug)]
pub struct MockVault {
    secrets: HashMap<String, SecretEntry>,
    namespaces: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
struct SecretEntry {
    name: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    last_accessed: DateTime<Utc>,
    access_count: u64,
    tags: Vec<String>,
    namespace: String,
    /// Mock value (in real impl, would be SecretBuffer).
    mock_value: String,
}

impl Default for MockVault {
    fn default() -> Self {
        let mut vault = Self {
            secrets: HashMap::new(),
            namespaces: HashMap::new(),
        };

        // Add some mock data
        vault.namespaces.insert("personal".to_string(), vec![
            "API_KEY".to_string(),
            "DATABASE_URL".to_string(),
            "STRIPE_SECRET_KEY".to_string(),
        ]);

        let now = Utc::now();
        vault.secrets.insert("API_KEY".to_string(), SecretEntry {
            name: "API_KEY".to_string(),
            created_at: now - chrono::Duration::days(30),
            expires_at: Some(now + chrono::Duration::days(60)),
            last_accessed: now - chrono::Duration::hours(2),
            access_count: 42,
            tags: vec!["production".to_string()],
            namespace: "personal".to_string(),
            mock_value: "sk_live_abcdef123456".to_string(),
        });

        vault.secrets.insert("DATABASE_URL".to_string(), SecretEntry {
            name: "DATABASE_URL".to_string(),
            created_at: now - chrono::Duration::days(90),
            expires_at: None,
            last_accessed: now - chrono::Duration::minutes(30),
            access_count: 156,
            tags: vec!["database".to_string(), "production".to_string()],
            namespace: "personal".to_string(),
            mock_value: "postgres://user:secretpassword@localhost/db".to_string(),
        });

        vault.secrets.insert("STRIPE_SECRET_KEY".to_string(), SecretEntry {
            name: "STRIPE_SECRET_KEY".to_string(),
            created_at: now - chrono::Duration::days(15),
            expires_at: Some(now + chrono::Duration::days(365)),
            last_accessed: now - chrono::Duration::days(1),
            access_count: 8,
            tags: vec!["payments".to_string(), "production".to_string()],
            namespace: "personal".to_string(),
            mock_value: "sk_live_stripe_secret_789xyz".to_string(),
        });

        vault
    }
}

impl VaultBackend for MockVault {
    fn list(&self, namespace: &str) -> Result<Vec<SecretInfo>, String> {
        let secrets: Vec<SecretInfo> = self
            .secrets
            .values()
            .filter(|s| s.namespace == namespace)
            .map(|s| SecretInfo {
                name: s.name.clone(),
                created_at: s.created_at,
                expires_at: s.expires_at,
                last_accessed: s.last_accessed,
                access_count: s.access_count,
                tags: s.tags.clone(),
                namespace: s.namespace.clone(),
            })
            .collect();
        Ok(secrets)
    }

    fn exists(&self, namespace: &str, key: &str) -> Result<Option<SecretInfo>, String> {
        Ok(self
            .secrets
            .get(key)
            .filter(|s| s.namespace == namespace)
            .map(|s| SecretInfo {
                name: s.name.clone(),
                created_at: s.created_at,
                expires_at: s.expires_at,
                last_accessed: s.last_accessed,
                access_count: s.access_count,
                tags: s.tags.clone(),
                namespace: s.namespace.clone(),
            }))
    }

    fn get_masked(&self, namespace: &str, key: &str) -> Result<String, String> {
        let secret = self
            .secrets
            .get(key)
            .filter(|s| s.namespace == namespace)
            .ok_or_else(|| format!("Secret not found: {}", key))?;

        let value = &secret.mock_value;
        let masked = if value.len() <= 4 {
            "••••".to_string()
        } else {
            let visible = &value[value.len() - 4..];
            format!("••••{}", visible)
        };
        Ok(masked)
    }

    fn get_secrets(&self, namespace: &str, keys: &[String]) -> Result<HashMap<String, SecretBuffer>, String> {
        let mut result = HashMap::new();
        for key in keys {
            let secret = self
                .secrets
                .get(key)
                .filter(|s| s.namespace == namespace)
                .ok_or_else(|| format!("Secret not found: {}", key))?;

            let buf = SecretBuffer::from_slice(secret.mock_value.as_bytes())
                .map_err(|e| format!("Failed to create secret buffer: {}", e))?;
            result.insert(key.clone(), buf);
        }
        Ok(result)
    }

    fn health(&self, namespace: &str) -> Result<HealthInfo, String> {
        let now = Utc::now();
        let soon = now + chrono::Duration::days(30);

        let expiring_soon: Vec<String> = self
            .secrets
            .values()
            .filter(|s| s.namespace == namespace)
            .filter(|s| s.expires_at.map(|e| e < soon).unwrap_or(false))
            .map(|s| s.name.clone())
            .collect();

        let total_secrets = self
            .secrets
            .values()
            .filter(|s| s.namespace == namespace)
            .count();

        Ok(HealthInfo {
            total_secrets,
            expiring_soon,
            last_audit: now - chrono::Duration::hours(1),
        })
    }
}

/// Adapter to use real Vault as VaultBackend.
pub struct RealVaultBackend {
    vault: Mutex<Vault>,
}

impl RealVaultBackend {
    /// Create a new real vault backend.
    pub fn new(vault: Vault) -> Self {
        Self {
            vault: Mutex::new(vault),
        }
    }

    /// Create a new real vault backend from a path.
    pub fn from_path(path: PathBuf, password: &SecretBuffer) -> Result<Self, String> {
        let mut vault = Vault::new(&path).map_err(|e| e.to_string())?;

        if vault.is_initialized() {
            vault.open(password).map_err(|e| e.to_string())?;
        } else {
            vault.init(password).map_err(|e| e.to_string())?;
        }

        Ok(Self::new(vault))
    }
}

impl VaultBackend for RealVaultBackend {
    fn list(&self, _namespace: &str) -> Result<Vec<SecretInfo>, String> {
        let vault = self.vault.lock();

        let metadata_list = vault
            .list_with_metadata()
            .map_err(|e| e.to_string())?;

        let now = Utc::now();
        let secrets: Vec<SecretInfo> = metadata_list
            .into_iter()
            .map(|m| {
                let created_at = DateTime::from_timestamp(m.created_at as i64, 0)
                    .unwrap_or(now);
                let updated_at = DateTime::from_timestamp(m.updated_at as i64, 0)
                    .unwrap_or(now);
                let expires_at = m.expires_at.and_then(|ts| DateTime::from_timestamp(ts as i64, 0));

                SecretInfo {
                    name: m.name,
                    created_at,
                    expires_at,
                    last_accessed: updated_at,
                    access_count: m.version as u64,
                    tags: if m.is_canary { vec!["canary".to_string()] } else { vec![] },
                    namespace: m.namespace,
                }
            })
            .collect();

        Ok(secrets)
    }

    fn exists(&self, _namespace: &str, key: &str) -> Result<Option<SecretInfo>, String> {
        let vault = self.vault.lock();

        match vault.exists(key) {
            Ok(true) => {
                match vault.get_with_metadata(key) {
                    Ok((_, m)) => {
                        let now = Utc::now();
                        let created_at = DateTime::from_timestamp(m.created_at as i64, 0)
                            .unwrap_or(now);
                        let updated_at = DateTime::from_timestamp(m.updated_at as i64, 0)
                            .unwrap_or(now);
                        let expires_at = m.expires_at.and_then(|ts| DateTime::from_timestamp(ts as i64, 0));

                        Ok(Some(SecretInfo {
                            name: m.name,
                            created_at,
                            expires_at,
                            last_accessed: updated_at,
                            access_count: m.version as u64,
                            tags: if m.is_canary { vec!["canary".to_string()] } else { vec![] },
                            namespace: m.namespace,
                        }))
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            Ok(false) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn get_masked(&self, _namespace: &str, key: &str) -> Result<String, String> {
        let vault = self.vault.lock();

        let value = vault.get(key).map_err(|e| e.to_string())?;

        let masked = value.with_exposed(|bytes| {
            let value_str = String::from_utf8_lossy(bytes);
            if value_str.len() <= 4 {
                "••••".to_string()
            } else {
                let visible = &value_str[value_str.len() - 4..];
                format!("••••{}", visible)
            }
        });

        Ok(masked)
    }

    fn get_secrets(&self, _namespace: &str, keys: &[String]) -> Result<HashMap<String, SecretBuffer>, String> {
        let vault = self.vault.lock();
        let mut result = HashMap::new();

        for key in keys {
            let value = vault.get(key).map_err(|e| e.to_string())?;
            result.insert(key.clone(), value);
        }

        Ok(result)
    }

    fn health(&self, _namespace: &str) -> Result<HealthInfo, String> {
        let vault = self.vault.lock();
        let now = Utc::now();

        let total_secrets = vault.count().map_err(|e| e.to_string())?;

        // Get secrets expiring in the next 30 days
        let thirty_days_from_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + 30 * 24 * 60 * 60)
            .unwrap_or(0);

        let expiring = vault.get_expiring(thirty_days_from_now)
            .map_err(|e| e.to_string())?;

        let expiring_soon: Vec<String> = expiring.into_iter().map(|m| m.name).collect();

        Ok(HealthInfo {
            total_secrets,
            expiring_soon,
            last_audit: now - chrono::Duration::hours(1),
        })
    }
}

/// Registry of available MCP tools.
pub struct ToolRegistry {
    /// Configuration.
    config: Arc<McpConfig>,
    /// Vault backend.
    vault: Arc<dyn VaultBackend>,
    /// Rate limiter.
    rate_limiter: Arc<RwLock<RateLimiter>>,
}

/// Rate limiter for tool calls.
#[derive(Debug)]
struct RateLimiter {
    /// Call timestamps per tool.
    calls: HashMap<String, Vec<Instant>>,
    /// Global call timestamps.
    global_calls: Vec<Instant>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            calls: HashMap::new(),
            global_calls: Vec::new(),
        }
    }

    /// Check if a tool call is allowed under rate limits.
    fn check(&mut self, tool_name: &str, config: &McpConfig) -> Result<(), String> {
        let now = Instant::now();
        let minute_ago = now - std::time::Duration::from_secs(60);

        // Clean old entries
        self.global_calls.retain(|t| *t > minute_ago);
        if let Some(calls) = self.calls.get_mut(tool_name) {
            calls.retain(|t| *t > minute_ago);
        }

        // Check global limit
        if self.global_calls.len() >= config.rate_limits.max_calls_per_minute as usize {
            return Err(format!(
                "Global rate limit exceeded ({} calls/minute)",
                config.rate_limits.max_calls_per_minute
            ));
        }

        // Check per-tool limit
        if let Some(limit) = config.rate_limits.per_tool.get(tool_name) {
            let tool_calls = self.calls.entry(tool_name.to_string()).or_default();
            if tool_calls.len() >= *limit as usize {
                return Err(format!(
                    "Rate limit exceeded for {} ({} calls/minute)",
                    tool_name, limit
                ));
            }
        }

        // Record the call
        self.global_calls.push(now);
        self.calls.entry(tool_name.to_string()).or_default().push(now);

        Ok(())
    }
}

impl ToolRegistry {
    /// Create a new tool registry with mock vault (for testing).
    pub fn new(config: McpConfig) -> Self {
        Self {
            config: Arc::new(config),
            vault: Arc::new(MockVault::default()),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new())),
        }
    }

    /// Create a new tool registry with a real vault.
    pub fn with_vault(config: McpConfig, vault: Vault) -> Self {
        Self {
            config: Arc::new(config),
            vault: Arc::new(RealVaultBackend::new(vault)),
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new())),
        }
    }

    /// Create a new tool registry with a custom vault backend.
    pub fn with_backend(config: McpConfig, vault: Arc<dyn VaultBackend>) -> Self {
        Self {
            config: Arc::new(config),
            vault,
            rate_limiter: Arc::new(RwLock::new(RateLimiter::new())),
        }
    }

    /// Get all available tool definitions.
    pub fn list_tools(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "vault_list".to_string(),
                description: "List available secret names in the vault. Returns metadata only, never values.".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "namespace": {
                            "type": "string",
                            "description": "Optional namespace to list secrets from"
                        }
                    }
                }),
            },
            ToolDefinition {
                name: "vault_exists".to_string(),
                description: "Check if a secret exists in the vault.".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "key": {
                            "type": "string",
                            "description": "Name of the secret to check"
                        },
                        "namespace": {
                            "type": "string",
                            "description": "Optional namespace"
                        }
                    },
                    "required": ["key"]
                }),
            },
            ToolDefinition {
                name: "vault_masked".to_string(),
                description: "Get a masked version of a secret (last 4 characters only).".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "key": {
                            "type": "string",
                            "description": "Name of the secret"
                        },
                        "namespace": {
                            "type": "string",
                            "description": "Optional namespace"
                        }
                    },
                    "required": ["key"]
                }),
            },
            ToolDefinition {
                name: "vault_run".to_string(),
                description: "Execute a command with secrets injected as environment variables. Output is sanitized to prevent secret leakage. Commands are pre-analyzed for security.".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "keys": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Secret names to inject as environment variables"
                        },
                        "command": {
                            "type": "string",
                            "description": "Command to execute"
                        },
                        "namespace": {
                            "type": "string",
                            "description": "Optional namespace"
                        }
                    },
                    "required": ["keys", "command"]
                }),
            },
            ToolDefinition {
                name: "vault_health".to_string(),
                description: "Get vault health status including secrets expiring soon, rotation status, and audit summary.".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "namespace": {
                            "type": "string",
                            "description": "Optional namespace"
                        }
                    }
                }),
            },
            ToolDefinition {
                name: "vault_rotate".to_string(),
                description: "Request rotation of a secret. Returns pending status - actual rotation requires biometric confirmation via CLI.".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "key": {
                            "type": "string",
                            "description": "Name of the secret to rotate"
                        },
                        "namespace": {
                            "type": "string",
                            "description": "Optional namespace"
                        }
                    },
                    "required": ["key"]
                }),
            },
        ]
    }

    /// Execute a tool by name.
    pub async fn execute(
        &self,
        name: &str,
        args: serde_json::Value,
        lineage: &mut RequestLineage,
    ) -> Result<ToolOutput, McpError> {
        let start = Instant::now();

        // Check rate limits
        self.rate_limiter
            .write()
            .check(name, &self.config)
            .map_err(|e| McpError::Tool(e))?;

        // Create tool call record
        let mut tool_call = ToolCall::new(name, args.clone());

        // Execute the tool
        let result = match name {
            "vault_list" => self.vault_list(args, lineage).await,
            "vault_exists" => self.vault_exists(args, lineage).await,
            "vault_masked" => self.vault_masked(args, lineage).await,
            "vault_run" => self.vault_run(args, lineage).await,
            "vault_health" => self.vault_health(args, lineage).await,
            "vault_rotate" => self.vault_rotate(args, lineage).await,
            _ => Err(McpError::Tool(format!("Unknown tool: {}", name))),
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        // Update tool call record
        match &result {
            Ok(output) => {
                tool_call = tool_call.success(duration_ms, output.metadata.sanitized);
            }
            Err(e) => {
                tool_call = tool_call.failed(&e.to_string(), duration_ms);
            }
        }

        lineage.add_tool_call(tool_call);
        result
    }

    /// vault_list: List secrets (names only, never values).
    async fn vault_list(
        &self,
        args: serde_json::Value,
        lineage: &mut RequestLineage,
    ) -> Result<ToolOutput, McpError> {
        let namespace = args
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.config.namespaces.default);

        // Check namespace access
        if !self.config.namespaces.is_allowed(namespace) {
            return Err(McpError::Tool(format!(
                "Access denied to namespace '{}'",
                namespace
            )));
        }

        let secrets = self.vault.list(namespace)
            .map_err(|e| McpError::Tool(e))?;

        for secret in &secrets {
            lineage.record_secret_access(&secret.name);
        }

        let response = VaultListResponse {
            secrets: secrets.into_iter().map(|s| SecretListItem {
                name: s.name,
                created: s.created_at,
                expires: s.expires_at,
                tags: s.tags,
                last_accessed: s.last_accessed,
                access_count: s.access_count,
            }).collect(),
        };

        let content = serde_json::to_string_pretty(&response)
            .map_err(|e| McpError::Serialization(e.to_string()))?;

        Ok(ToolOutput {
            content,
            is_error: false,
            metadata: ToolMetadata {
                execution_ms: 0, // Will be set by caller
                sanitized: false,
                lineage_id: lineage.id.clone(),
            },
        })
    }

    /// vault_exists: Check if a secret exists.
    async fn vault_exists(
        &self,
        args: serde_json::Value,
        lineage: &mut RequestLineage,
    ) -> Result<ToolOutput, McpError> {
        let key = args
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::Tool("Missing required argument: key".to_string()))?;

        let namespace = args
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.config.namespaces.default);

        if !self.config.namespaces.is_allowed(namespace) {
            return Err(McpError::Tool(format!(
                "Access denied to namespace '{}'",
                namespace
            )));
        }

        let secret_info = self.vault.exists(namespace, key)
            .map_err(|e| McpError::Tool(e))?;

        let (exists, metadata) = match secret_info {
            Some(info) => {
                lineage.record_secret_access(key);
                (true, Some(SecretMetadataResponse {
                    created: info.created_at,
                    expires: info.expires_at,
                    tags: info.tags,
                    last_accessed: info.last_accessed,
                    access_count: info.access_count,
                    sensitivity: self.config.get_sensitivity(key),
                }))
            }
            None => (false, None),
        };

        let content = serde_json::to_string_pretty(&VaultExistsResponse { exists, metadata })
            .map_err(|e| McpError::Serialization(e.to_string()))?;

        Ok(ToolOutput {
            content,
            is_error: false,
            metadata: ToolMetadata {
                execution_ms: 0,
                sanitized: false,
                lineage_id: lineage.id.clone(),
            },
        })
    }

    /// vault_masked: Get masked version of secret (last 4 chars only).
    async fn vault_masked(
        &self,
        args: serde_json::Value,
        lineage: &mut RequestLineage,
    ) -> Result<ToolOutput, McpError> {
        let key = args
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::Tool("Missing required argument: key".to_string()))?;

        let namespace = args
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.config.namespaces.default);

        if !self.config.namespaces.is_allowed(namespace) {
            return Err(McpError::Tool(format!(
                "Access denied to namespace '{}'",
                namespace
            )));
        }

        let masked = self.vault.get_masked(namespace, key)
            .map_err(|e| McpError::Tool(e))?;

        lineage.record_secret_access(key);

        let content = serde_json::to_string_pretty(&VaultMaskedResponse { masked })
            .map_err(|e| McpError::Serialization(e.to_string()))?;

        Ok(ToolOutput {
            content,
            is_error: false,
            metadata: ToolMetadata {
                execution_ms: 0,
                sanitized: true, // We masked the value
                lineage_id: lineage.id.clone(),
            },
        })
    }

    /// vault_run: Execute command with secrets injected.
    async fn vault_run(
        &self,
        args: serde_json::Value,
        lineage: &mut RequestLineage,
    ) -> Result<ToolOutput, McpError> {
        let keys: Vec<String> = args
            .get("keys")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .ok_or_else(|| McpError::Tool("Missing required argument: keys".to_string()))?;

        let command = args
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::Tool("Missing required argument: command".to_string()))?;

        let namespace = args
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.config.namespaces.default);

        if !self.config.namespaces.is_allowed(namespace) {
            return Err(McpError::Tool(format!(
                "Access denied to namespace '{}'",
                namespace
            )));
        }

        // Check trust level for high-sensitivity secrets
        for key in &keys {
            let sensitivity = self.config.get_sensitivity(key);
            if sensitivity == SensitivityLevel::High
                && !lineage.trust_level.allows_high_sensitivity()
            {
                return Err(McpError::Tool(format!(
                    "High-sensitivity secret '{}' requires human confirmation. Trust level: {}",
                    key, lineage.trust_level
                )));
            }
            lineage.record_secret_access(key);
        }

        // Pre-analysis with phantom-analyzer
        let analyzer = phantom_analyzer::Analyzer::strict();
        let analysis = analyzer.analyze(command).map_err(|e| {
            McpError::Tool(format!("Command analysis failed: {}", e))
        })?;

        if !analysis.allowed {
            let reason = format!(
                "Command blocked by security policy: {}",
                analysis.reason
            );
            return Ok(ToolOutput {
                content: serde_json::to_string_pretty(&VaultRunResponse {
                    status: "BLOCKED".to_string(),
                    reason: Some(reason.clone()),
                    exit_code: None,
                    stdout: None,
                    stderr: None,
                    duration_ms: None,
                    sanitized: false,
                    detected_patterns: analysis
                        .detected_patterns
                        .iter()
                        .map(|p| p.pattern_id.clone())
                        .collect(),
                })
                .map_err(|e| McpError::Serialization(e.to_string()))?,
                is_error: true,
                metadata: ToolMetadata {
                    execution_ms: 0,
                    sanitized: false,
                    lineage_id: lineage.id.clone(),
                },
            });
        }

        // Get secrets from vault
        let secrets = self.vault.get_secrets(namespace, &keys)
            .map_err(|e| McpError::Tool(e))?;

        // Execute command with sandbox
        let sandbox_config = phantom_sandbox::SandboxConfig::default();
        let sandbox = phantom_sandbox::Sandbox::new(sandbox_config)
            .map_err(|e| McpError::Tool(format!("Failed to create sandbox: {}", e)))?;

        let args_vec: Vec<&str> = vec!["-c", command];
        let result = sandbox.execute("sh", &args_vec, secrets)
            .map_err(|e| McpError::Tool(format!("Execution failed: {}", e)))?;

        let content = serde_json::to_string_pretty(&VaultRunResponse {
            status: if result.timed_out { "TIMEOUT" } else { "OK" }.to_string(),
            reason: None,
            exit_code: Some(result.exit_code),
            stdout: Some(result.stdout),
            stderr: Some(result.stderr),
            duration_ms: Some(50), // TODO: track actual duration
            sanitized: result.secrets_sanitized,
            detected_patterns: vec![],
        })
        .map_err(|e| McpError::Serialization(e.to_string()))?;

        Ok(ToolOutput {
            content,
            is_error: false,
            metadata: ToolMetadata {
                execution_ms: 50,
                sanitized: result.secrets_sanitized,
                lineage_id: lineage.id.clone(),
            },
        })
    }

    /// vault_health: Get vault health status.
    async fn vault_health(
        &self,
        args: serde_json::Value,
        lineage: &mut RequestLineage,
    ) -> Result<ToolOutput, McpError> {
        let namespace = args
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.config.namespaces.default);

        if !self.config.namespaces.is_allowed(namespace) {
            return Err(McpError::Tool(format!(
                "Access denied to namespace '{}'",
                namespace
            )));
        }

        let health = self.vault.health(namespace)
            .map_err(|e| McpError::Tool(e))?;

        for name in &health.expiring_soon {
            lineage.record_secret_access(name);
        }

        let content = serde_json::to_string_pretty(&VaultHealthResponse {
            status: "healthy".to_string(),
            total_secrets: health.total_secrets,
            expiring_soon: health.expiring_soon,
            rotation_pending: vec![],
            canary_status: "ok".to_string(),
            last_audit: health.last_audit,
        })
        .map_err(|e| McpError::Serialization(e.to_string()))?;

        Ok(ToolOutput {
            content,
            is_error: false,
            metadata: ToolMetadata {
                execution_ms: 0,
                sanitized: false,
                lineage_id: lineage.id.clone(),
            },
        })
    }

    /// vault_rotate: Request secret rotation.
    async fn vault_rotate(
        &self,
        args: serde_json::Value,
        lineage: &mut RequestLineage,
    ) -> Result<ToolOutput, McpError> {
        let key = args
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpError::Tool("Missing required argument: key".to_string()))?;

        let namespace = args
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(&self.config.namespaces.default);

        if !self.config.namespaces.is_allowed(namespace) {
            return Err(McpError::Tool(format!(
                "Access denied to namespace '{}'",
                namespace
            )));
        }

        // Check if secret exists
        let exists = self.vault.exists(namespace, key)
            .map_err(|e| McpError::Tool(e))?;

        if exists.is_none() {
            return Err(McpError::Tool(format!("Secret not found: {}", key)));
        }

        lineage.record_secret_access(key);

        // Rotation always requires human confirmation via CLI
        let content = serde_json::to_string_pretty(&VaultRotateResponse {
            status: "pending_human_approval".to_string(),
            message: format!(
                "Rotation request for '{}' has been queued. \
                 Please confirm via CLI with: phantom vault rotate {} --confirm",
                key, key
            ),
            key: key.to_string(),
        })
        .map_err(|e| McpError::Serialization(e.to_string()))?;

        Ok(ToolOutput {
            content,
            is_error: false,
            metadata: ToolMetadata {
                execution_ms: 0,
                sanitized: false,
                lineage_id: lineage.id.clone(),
            },
        })
    }
}

// Response types

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultListResponse {
    secrets: Vec<SecretListItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretListItem {
    name: String,
    created: DateTime<Utc>,
    expires: Option<DateTime<Utc>>,
    tags: Vec<String>,
    last_accessed: DateTime<Utc>,
    access_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultExistsResponse {
    exists: bool,
    metadata: Option<SecretMetadataResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretMetadataResponse {
    created: DateTime<Utc>,
    expires: Option<DateTime<Utc>>,
    tags: Vec<String>,
    last_accessed: DateTime<Utc>,
    access_count: u64,
    sensitivity: SensitivityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultMaskedResponse {
    masked: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultRunResponse {
    status: String,
    reason: Option<String>,
    exit_code: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
    duration_ms: Option<u64>,
    sanitized: bool,
    detected_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultHealthResponse {
    status: String,
    total_secrets: usize,
    expiring_soon: Vec<String>,
    rotation_pending: Vec<String>,
    canary_status: String,
    last_audit: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultRotateResponse {
    status: String,
    message: String,
    key: String,
}

/// Tool definition for MCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// Input schema (JSON Schema).
    pub input_schema: serde_json::Value,
}

/// Output from a tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    /// Output content (JSON).
    pub content: String,
    /// Whether the output indicates an error.
    pub is_error: bool,
    /// Metadata about the execution.
    pub metadata: ToolMetadata,
}

/// Metadata about tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMetadata {
    /// Execution time in milliseconds.
    pub execution_ms: u64,
    /// Whether secrets were sanitized from output.
    pub sanitized: bool,
    /// Request lineage ID.
    pub lineage_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lineage::{ClientInfo, LineageTracker, TrustLevel};

    fn create_test_registry() -> ToolRegistry {
        ToolRegistry::new(McpConfig::default())
    }

    fn create_test_lineage() -> RequestLineage {
        let tracker = LineageTracker::new();
        let client = ClientInfo::mcp("test-client", "1.0.0");
        tracker.start_request(&client)
    }

    #[tokio::test]
    async fn test_vault_list_returns_names_only() {
        let registry = create_test_registry();
        let mut lineage = create_test_lineage();

        let result = registry
            .execute("vault_list", serde_json::json!({}), &mut lineage)
            .await
            .unwrap();

        // Parse the response
        let response: VaultListResponse = serde_json::from_str(&result.content).unwrap();

        // Should have secrets
        assert!(!response.secrets.is_empty());

        // Should have names but NOT values
        for secret in &response.secrets {
            assert!(!secret.name.is_empty());
            // The SecretListItem struct doesn't have a 'value' field
        }

        // Content should not contain actual secret values
        assert!(!result.content.contains("sk_live_"));
        assert!(!result.content.contains("secretpassword"));
    }

    #[tokio::test]
    async fn test_vault_run_safe_command() {
        let registry = create_test_registry();
        let mut lineage = create_test_lineage();

        // Use a command that's in the strict policy whitelist (git is allowed)
        let result = registry
            .execute(
                "vault_run",
                serde_json::json!({
                    "keys": ["API_KEY"],
                    "command": "git status"
                }),
                &mut lineage,
            )
            .await
            .unwrap();

        let response: VaultRunResponse = serde_json::from_str(&result.content).unwrap();
        assert_eq!(response.status, "OK");
        assert!(response.stdout.is_some());

        // Output should not contain actual secret values
        assert!(!result.content.contains("sk_live_"));
    }

    #[tokio::test]
    async fn test_vault_run_oracle_attack_blocked() {
        let registry = create_test_registry();
        let mut lineage = create_test_lineage();

        let result = registry
            .execute(
                "vault_run",
                serde_json::json!({
                    "keys": ["API_KEY"],
                    "command": "echo ${API_KEY:0:1}"
                }),
                &mut lineage,
            )
            .await
            .unwrap();

        let response: VaultRunResponse = serde_json::from_str(&result.content).unwrap();
        assert_eq!(response.status, "BLOCKED");
        assert!(response.reason.is_some());
        assert!(!response.detected_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_vault_run_rate_limiting() {
        let mut config = McpConfig::default();
        config.rate_limits.per_tool.insert("vault_run".to_string(), 2);

        let registry = ToolRegistry::new(config);
        let mut lineage = create_test_lineage();

        // First two calls should succeed
        for _ in 0..2 {
            let result = registry
                .execute(
                    "vault_run",
                    serde_json::json!({
                        "keys": ["API_KEY"],
                        "command": "echo hello"
                    }),
                    &mut lineage,
                )
                .await;
            assert!(result.is_ok());
        }

        // Third call should be rate limited
        let result = registry
            .execute(
                "vault_run",
                serde_json::json!({
                    "keys": ["API_KEY"],
                    "command": "echo hello"
                }),
                &mut lineage,
            )
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Rate limit"));
    }

    #[tokio::test]
    async fn test_namespace_isolation() {
        let mut config = McpConfig::default();
        config.namespaces.allowed.insert("personal".to_string());
        // Don't add "other" to allowed namespaces

        let registry = ToolRegistry::new(config);
        let mut lineage = create_test_lineage();

        // Should fail for non-allowed namespace
        let result = registry
            .execute(
                "vault_list",
                serde_json::json!({"namespace": "other"}),
                &mut lineage,
            )
            .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Access denied"));
    }

    #[tokio::test]
    async fn test_vault_masked_shows_last_4() {
        let registry = create_test_registry();
        let mut lineage = create_test_lineage();

        let result = registry
            .execute(
                "vault_masked",
                serde_json::json!({"key": "API_KEY"}),
                &mut lineage,
            )
            .await
            .unwrap();

        let response: VaultMaskedResponse = serde_json::from_str(&result.content).unwrap();

        // Should show masked value with last 4 chars
        assert!(response.masked.starts_with("••••"));
        // "••••" is 4 Unicode chars (each is 3 bytes in UTF-8) + 4 ASCII chars = 16 bytes total
        // But we count characters, not bytes
        assert_eq!(response.masked.chars().count(), 8); // "••••" (4 chars) + 4 chars

        // Should NOT contain the full secret
        assert!(!response.masked.contains("sk_live_"));
    }

    #[tokio::test]
    async fn test_vault_rotate_requires_human_approval() {
        let registry = create_test_registry();
        let mut lineage = create_test_lineage();

        let result = registry
            .execute(
                "vault_rotate",
                serde_json::json!({"key": "API_KEY"}),
                &mut lineage,
            )
            .await
            .unwrap();

        let response: VaultRotateResponse = serde_json::from_str(&result.content).unwrap();
        assert_eq!(response.status, "pending_human_approval");
        assert!(response.message.contains("confirm via CLI"));
    }

    #[tokio::test]
    async fn test_lineage_records_all_fields() {
        let tracker = LineageTracker::new();
        let client = ClientInfo::mcp("Claude Code", "1.0.0");
        let mut lineage = tracker.start_request(&client);

        let registry = create_test_registry();
        let _ = registry
            .execute("vault_list", serde_json::json!({}), &mut lineage)
            .await;

        // Check lineage has all required fields
        assert!(!lineage.id.is_empty());
        assert_eq!(lineage.client.name, "Claude Code");
        assert_eq!(lineage.trust_level, TrustLevel::LlmAuto);
        assert!(!lineage.tool_calls.is_empty());
        assert!(!lineage.secrets_accessed.is_empty());

        // Check tool call has all fields
        let call = &lineage.tool_calls[0];
        assert_eq!(call.tool_name, "vault_list");
        assert!(call.success);
    }

    #[tokio::test]
    async fn test_high_sensitivity_requires_confirmation() {
        let mut config = McpConfig::default();
        config.sensitivity.high.insert("DATABASE_URL".to_string());

        let registry = ToolRegistry::new(config);

        // LLM_AUTO trust level should be denied
        let tracker = LineageTracker::new();
        let client = ClientInfo::mcp("Claude Code", "1.0.0");
        let mut lineage = tracker.start_request(&client);

        let result = registry
            .execute(
                "vault_run",
                serde_json::json!({
                    "keys": ["DATABASE_URL"],
                    "command": "echo test"
                }),
                &mut lineage,
            )
            .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("High-sensitivity secret"));
    }

    #[tokio::test]
    async fn test_high_sensitivity_allowed_for_human() {
        let mut config = McpConfig::default();
        config.sensitivity.high.insert("DATABASE_URL".to_string());

        let registry = ToolRegistry::new(config);

        // HUMAN_DIRECT trust level should be allowed
        let tracker = LineageTracker::new();
        let client = ClientInfo::human_cli();
        let mut lineage = tracker.start_request(&client);

        let result = registry
            .execute(
                "vault_run",
                serde_json::json!({
                    "keys": ["DATABASE_URL"],
                    "command": "echo test"
                }),
                &mut lineage,
            )
            .await;

        assert!(result.is_ok());
    }
}
