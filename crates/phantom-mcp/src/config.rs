//! MCP server configuration.
//!
//! Configuration is loaded from ~/.phantom/mcp-config.toml

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// MCP server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Server settings.
    #[serde(default)]
    pub server: ServerConfig,
    /// Namespace settings.
    #[serde(default)]
    pub namespaces: NamespaceConfig,
    /// Sensitivity classification for secrets.
    #[serde(default)]
    pub sensitivity: SensitivityConfig,
    /// Rate limiting settings.
    #[serde(default)]
    pub rate_limits: RateLimitConfig,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            namespaces: NamespaceConfig::default(),
            sensitivity: SensitivityConfig::default(),
            rate_limits: RateLimitConfig::default(),
        }
    }
}

impl McpConfig {
    /// Load configuration from the default path (~/.phantom/mcp-config.toml).
    pub fn load() -> Result<Self, ConfigError> {
        let config_path = Self::default_path()?;
        if config_path.exists() {
            Self::load_from(&config_path)
        } else {
            Ok(Self::default())
        }
    }

    /// Load configuration from a specific path.
    pub fn load_from(path: &PathBuf) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(e.to_string()))?;
        toml::from_str(&content)
            .map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Get the default configuration path.
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        let home = dirs::home_dir()
            .ok_or_else(|| ConfigError::Io("Could not determine home directory".to_string()))?;
        Ok(home.join(".phantom").join("mcp-config.toml"))
    }

    /// Save configuration to the default path.
    pub fn save(&self) -> Result<(), ConfigError> {
        let config_path = Self::default_path()?;
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ConfigError::Io(e.to_string()))?;
        }
        let content = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::Parse(e.to_string()))?;
        std::fs::write(&config_path, content)
            .map_err(|e| ConfigError::Io(e.to_string()))
    }

    /// Get the sensitivity level for a secret.
    pub fn get_sensitivity(&self, secret_name: &str) -> SensitivityLevel {
        if self.sensitivity.high.contains(secret_name) {
            SensitivityLevel::High
        } else if self.sensitivity.medium.contains(secret_name) {
            SensitivityLevel::Medium
        } else if self.sensitivity.low.contains(secret_name) {
            SensitivityLevel::Low
        } else {
            SensitivityLevel::Unknown
        }
    }
}

/// Server-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Idle timeout in minutes before auto-lock.
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_minutes: u64,
    /// Maximum vault_run calls per minute.
    #[serde(default = "default_max_runs")]
    pub max_runs_per_minute: u32,
    /// Whether biometric authentication is required.
    #[serde(default = "default_require_biometric")]
    pub require_biometric: bool,
    /// Human interaction timeout in seconds (for trust level).
    #[serde(default = "default_human_interaction_timeout")]
    pub human_interaction_timeout_seconds: u64,
}

fn default_idle_timeout() -> u64 {
    15
}

fn default_max_runs() -> u32 {
    10
}

fn default_require_biometric() -> bool {
    true
}

fn default_human_interaction_timeout() -> u64 {
    300 // 5 minutes
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            idle_timeout_minutes: default_idle_timeout(),
            max_runs_per_minute: default_max_runs(),
            require_biometric: default_require_biometric(),
            human_interaction_timeout_seconds: default_human_interaction_timeout(),
        }
    }
}

/// Namespace configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceConfig {
    /// Default namespace.
    #[serde(default = "default_namespace")]
    pub default: String,
    /// Allowed namespaces.
    #[serde(default)]
    pub allowed: HashSet<String>,
}

fn default_namespace() -> String {
    "personal".to_string()
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert("personal".to_string());
        Self {
            default: default_namespace(),
            allowed,
        }
    }
}

impl NamespaceConfig {
    /// Check if a namespace is allowed.
    pub fn is_allowed(&self, namespace: &str) -> bool {
        self.allowed.is_empty() || self.allowed.contains(namespace)
    }
}

/// Sensitivity classification for secrets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SensitivityConfig {
    /// High-sensitivity secrets (require confirmation for LLM_AUTO).
    #[serde(default)]
    pub high: HashSet<String>,
    /// Medium-sensitivity secrets.
    #[serde(default)]
    pub medium: HashSet<String>,
    /// Low-sensitivity secrets.
    #[serde(default)]
    pub low: HashSet<String>,
}

/// Sensitivity level for a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensitivityLevel {
    High,
    Medium,
    Low,
    Unknown,
}

impl SensitivityLevel {
    /// Check if this level requires human confirmation for LLM_AUTO access.
    pub fn requires_confirmation(&self) -> bool {
        matches!(self, SensitivityLevel::High)
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum tool calls per minute.
    #[serde(default = "default_max_calls")]
    pub max_calls_per_minute: u32,
    /// Per-tool rate limits (tool_name -> max per minute).
    #[serde(default)]
    pub per_tool: HashMap<String, u32>,
}

fn default_max_calls() -> u32 {
    60
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        let mut per_tool = HashMap::new();
        per_tool.insert("vault_run".to_string(), 10);
        per_tool.insert("vault_rotate".to_string(), 5);
        Self {
            max_calls_per_minute: default_max_calls(),
            per_tool,
        }
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = McpConfig::default();
        assert_eq!(config.server.idle_timeout_minutes, 15);
        assert_eq!(config.server.max_runs_per_minute, 10);
        assert!(config.server.require_biometric);
        assert_eq!(config.namespaces.default, "personal");
    }

    #[test]
    fn test_sensitivity_lookup() {
        let mut config = McpConfig::default();
        config.sensitivity.high.insert("DATABASE_URL".to_string());
        config.sensitivity.medium.insert("RAILWAY_TOKEN".to_string());
        config.sensitivity.low.insert("PUBLIC_API_KEY".to_string());

        assert_eq!(config.get_sensitivity("DATABASE_URL"), SensitivityLevel::High);
        assert_eq!(config.get_sensitivity("RAILWAY_TOKEN"), SensitivityLevel::Medium);
        assert_eq!(config.get_sensitivity("PUBLIC_API_KEY"), SensitivityLevel::Low);
        assert_eq!(config.get_sensitivity("UNKNOWN_KEY"), SensitivityLevel::Unknown);
    }

    #[test]
    fn test_namespace_allowed() {
        let mut config = NamespaceConfig::default();
        config.allowed.insert("personal".to_string());
        config.allowed.insert("work".to_string());

        assert!(config.is_allowed("personal"));
        assert!(config.is_allowed("work"));
        assert!(!config.is_allowed("other"));
    }

    #[test]
    fn test_parse_toml() {
        let toml_str = r#"
[server]
idle_timeout_minutes = 30
max_runs_per_minute = 20
require_biometric = false

[namespaces]
default = "work"
allowed = ["work", "personal"]

[sensitivity]
high = ["DATABASE_URL", "STRIPE_SECRET_KEY"]
medium = ["RAILWAY_TOKEN"]
low = ["PUBLIC_KEY"]
"#;

        let config: McpConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.idle_timeout_minutes, 30);
        assert_eq!(config.server.max_runs_per_minute, 20);
        assert!(!config.server.require_biometric);
        assert_eq!(config.namespaces.default, "work");
        assert!(config.sensitivity.high.contains("DATABASE_URL"));
        assert!(config.sensitivity.high.contains("STRIPE_SECRET_KEY"));
    }
}
