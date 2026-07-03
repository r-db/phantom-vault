//! Canary and honeypot secret management.
//!
//! Canary secrets are fake credentials that, if used, indicate
//! a potential breach or exfiltration attempt. They help detect
//! when an attacker (or misbehaving LLM) has extracted secrets.

use crate::memory::SecretBuffer;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{error, info, warn};

/// Errors that can occur during canary operations.
#[derive(Debug, Error)]
pub enum CanaryError {
    /// Canary was triggered (breach detected).
    #[error("BREACH DETECTED: canary '{0}' was accessed")]
    Triggered(String),

    /// Canary not found.
    #[error("canary not found: {0}")]
    NotFound(String),

    /// Invalid canary configuration.
    #[error("invalid canary configuration: {0}")]
    InvalidConfig(String),

    /// Memory allocation error.
    #[error("memory error: {0}")]
    Memory(#[from] crate::memory::MemoryError),

    /// Webhook delivery failed.
    #[error("webhook delivery failed: {0}")]
    WebhookFailed(String),
}

/// Result type for canary operations.
pub type CanaryResult<T> = Result<T, CanaryError>;

/// Configuration for a canary secret.
#[derive(Debug, Clone)]
pub struct CanaryConfig {
    /// Name of the canary secret.
    pub name: String,
    /// Pattern to generate realistic-looking fake values.
    pub pattern: CanaryPattern,
    /// Action to take when triggered.
    pub on_trigger: TriggerAction,
    /// Optional webhook URL for alerts.
    pub webhook_url: Option<String>,
    /// Optional namespace (defaults to "default").
    pub namespace: Option<String>,
}

/// Patterns for generating realistic-looking canary values.
#[derive(Debug, Clone)]
pub enum CanaryPattern {
    /// AWS-style access key (AKIA prefix, 20 chars).
    AwsAccessKey,
    /// AWS-style secret key (40 chars).
    AwsSecretKey,
    /// GitHub personal access token (ghp_ prefix).
    GithubToken,
    /// Stripe API key (sk_live_ or sk_test_ prefix).
    StripeKey { test_mode: bool },
    /// Generic API key (alphanumeric).
    ApiKey { length: usize },
    /// Database connection string.
    DatabaseUrl { db_type: String },
    /// Custom pattern (literal string).
    Custom(String),
}

/// Action to take when a canary is triggered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerAction {
    /// Log the event only.
    Log,
    /// Log and send alert to webhook.
    Alert,
    /// Log, alert, and seal the vault.
    SealVault,
}

/// A canary secret that detects exfiltration.
pub struct Canary {
    /// Canary configuration.
    pub config: CanaryConfig,
    /// The fake secret value.
    pub value: SecretBuffer,
    /// Number of times this canary has been accessed.
    pub access_count: u64,
    /// Timestamp of last access (Unix epoch seconds).
    pub last_accessed: Option<u64>,
    /// Whether this canary has been triggered.
    pub triggered: bool,
}

impl Canary {
    /// Create a new canary from a configuration.
    fn new(config: CanaryConfig, value: SecretBuffer) -> Self {
        Self {
            config,
            value,
            access_count: 0,
            last_accessed: None,
            triggered: false,
        }
    }

    /// Get the canary name.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get the namespace.
    pub fn namespace(&self) -> &str {
        self.config.namespace.as_deref().unwrap_or("default")
    }

    /// Check if the canary value appears in the given output.
    pub fn check_leaked(&self, output: &str) -> bool {
        self.value.with_exposed(|bytes| {
            if let Ok(value_str) = std::str::from_utf8(bytes) {
                output.contains(value_str)
            } else {
                false
            }
        })
    }
}

/// Alert details for a triggered canary.
#[derive(Debug, Clone)]
pub struct CanaryAlert {
    /// Canary name.
    pub canary_name: String,
    /// Namespace.
    pub namespace: String,
    /// Timestamp of the trigger.
    pub timestamp: u64,
    /// Number of times accessed.
    pub access_count: u64,
    /// Context about the access (command, lineage, etc.).
    pub context: Option<String>,
}

/// Manager for canary secrets.
pub struct CanaryManager {
    canaries: HashMap<String, Canary>,
}

impl CanaryManager {
    /// Create a new canary manager.
    pub fn new() -> Self {
        Self {
            canaries: HashMap::new(),
        }
    }

    /// Create a new canary secret.
    pub fn create(&mut self, config: CanaryConfig) -> CanaryResult<&Canary> {
        // Validate configuration
        if config.name.is_empty() {
            return Err(CanaryError::InvalidConfig("name cannot be empty".to_string()));
        }

        if self.canaries.contains_key(&config.name) {
            return Err(CanaryError::InvalidConfig(format!(
                "canary '{}' already exists",
                config.name
            )));
        }

        // Generate the canary value
        let value = Self::generate_value(&config.pattern)?;

        // Store the canary
        let canary = Canary::new(config.clone(), value);
        self.canaries.insert(config.name.clone(), canary);

        Ok(self.canaries.get(&config.name).unwrap())
    }

    /// Get a canary by name.
    pub fn get(&self, name: &str) -> Option<&Canary> {
        self.canaries.get(name)
    }

    /// Get a mutable canary by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Canary> {
        self.canaries.get_mut(name)
    }

    /// Check if a value matches any canary.
    ///
    /// This should be called when sanitizing output to detect
    /// if a canary value has leaked.
    pub fn check_leaked(&self, output: &str) -> Option<&Canary> {
        for canary in self.canaries.values() {
            if canary.check_leaked(output) {
                return Some(canary);
            }
        }
        None
    }

    /// Record an access to a canary (triggers alerts).
    pub fn record_access(&mut self, name: &str) -> CanaryResult<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let canary = self.canaries.get_mut(name).ok_or_else(|| {
            CanaryError::NotFound(name.to_string())
        })?;

        canary.access_count += 1;
        canary.last_accessed = Some(timestamp);
        canary.triggered = true;

        let alert = CanaryAlert {
            canary_name: canary.config.name.clone(),
            namespace: canary.namespace().to_string(),
            timestamp,
            access_count: canary.access_count,
            context: None,
        };

        // Extract data needed for actions before releasing the mutable borrow
        let on_trigger = canary.config.on_trigger.clone();
        let access_count = canary.access_count;
        let webhook_url = canary.config.webhook_url.clone();

        // Take action based on configuration
        match on_trigger {
            TriggerAction::Log => {
                warn!(
                    "CANARY TRIGGERED: '{}' was accessed (count: {})",
                    name, access_count
                );
            }
            TriggerAction::Alert => {
                warn!(
                    "CANARY TRIGGERED: '{}' was accessed (count: {})",
                    name, access_count
                );
                self.send_alert(&alert, webhook_url.as_deref());
            }
            TriggerAction::SealVault => {
                error!(
                    "CANARY TRIGGERED - SEALING VAULT: '{}' was accessed",
                    name
                );
                self.send_alert(&alert, webhook_url.as_deref());
                // The caller should check for SealVault action and seal the vault
            }
        }

        Err(CanaryError::Triggered(name.to_string()))
    }

    /// Record an access with context.
    pub fn record_access_with_context(
        &mut self,
        name: &str,
        context: &str,
    ) -> CanaryResult<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let canary = self.canaries.get_mut(name).ok_or_else(|| {
            CanaryError::NotFound(name.to_string())
        })?;

        canary.access_count += 1;
        canary.last_accessed = Some(timestamp);
        canary.triggered = true;

        let alert = CanaryAlert {
            canary_name: canary.config.name.clone(),
            namespace: canary.namespace().to_string(),
            timestamp,
            access_count: canary.access_count,
            context: Some(context.to_string()),
        };

        // Extract data needed for actions before releasing the mutable borrow
        let on_trigger = canary.config.on_trigger.clone();
        let webhook_url = canary.config.webhook_url.clone();

        warn!(
            "CANARY TRIGGERED: '{}' was accessed. Context: {}",
            name, context
        );

        if on_trigger == TriggerAction::Alert || on_trigger == TriggerAction::SealVault {
            self.send_alert(&alert, webhook_url.as_deref());
        }

        Err(CanaryError::Triggered(name.to_string()))
    }

    /// Send an alert to a webhook.
    fn send_alert(&self, alert: &CanaryAlert, webhook_url: Option<&str>) {
        let Some(url) = webhook_url else {
            return;
        };

        // Build alert payload
        let payload = serde_json::json!({
            "event": "canary_triggered",
            "canary": alert.canary_name,
            "namespace": alert.namespace,
            "timestamp": alert.timestamp,
            "access_count": alert.access_count,
            "context": alert.context,
        });

        info!("Sending canary alert to webhook: {}", url);

        // Note: In production, this should be async and use a proper HTTP client.
        // For now, we just log the alert payload.
        info!("Alert payload: {}", payload);
    }

    /// Generate a realistic-looking fake value.
    pub fn generate_value(pattern: &CanaryPattern) -> CanaryResult<SecretBuffer> {
        let rng = SystemRandom::new();
        let value = match pattern {
            CanaryPattern::AwsAccessKey => {
                // AWS access keys: AKIA + 16 alphanumeric chars
                let mut chars = String::with_capacity(20);
                chars.push_str("AKIA");
                chars.push_str(&generate_alphanumeric(&rng, 16)?);
                chars.into_bytes()
            }
            CanaryPattern::AwsSecretKey => {
                // AWS secret keys: 40 base64-like chars
                generate_base64_like(&rng, 40)?
            }
            CanaryPattern::GithubToken => {
                // GitHub PAT: ghp_ + 36 alphanumeric chars
                let mut chars = String::with_capacity(40);
                chars.push_str("ghp_");
                chars.push_str(&generate_alphanumeric(&rng, 36)?);
                chars.into_bytes()
            }
            CanaryPattern::StripeKey { test_mode } => {
                // Stripe keys: sk_live_ or sk_test_ + 24 alphanumeric
                let mut chars = String::with_capacity(32);
                if *test_mode {
                    chars.push_str("sk_test_");
                } else {
                    chars.push_str("sk_live_");
                }
                chars.push_str(&generate_alphanumeric(&rng, 24)?);
                chars.into_bytes()
            }
            CanaryPattern::ApiKey { length } => {
                let len = if *length == 0 { 32 } else { *length };
                generate_alphanumeric(&rng, len)?.into_bytes()
            }
            CanaryPattern::DatabaseUrl { db_type } => {
                // Generate a realistic-looking database URL
                let password = generate_alphanumeric(&rng, 16)?;
                let url = format!(
                    "{}://canary_user:{}@canary-db.internal:5432/canary_db",
                    db_type, password
                );
                url.into_bytes()
            }
            CanaryPattern::Custom(value) => value.as_bytes().to_vec(),
        };

        SecretBuffer::from_vec(value).map_err(CanaryError::Memory)
    }

    /// List all canaries.
    pub fn list(&self) -> Vec<&Canary> {
        self.canaries.values().collect()
    }

    /// List canaries by namespace.
    pub fn list_by_namespace(&self, namespace: &str) -> Vec<&Canary> {
        self.canaries
            .values()
            .filter(|c| c.namespace() == namespace)
            .collect()
    }

    /// Remove a canary.
    pub fn remove(&mut self, name: &str) -> Option<Canary> {
        self.canaries.remove(name)
    }

    /// Get the number of canaries.
    pub fn len(&self) -> usize {
        self.canaries.len()
    }

    /// Check if there are no canaries.
    pub fn is_empty(&self) -> bool {
        self.canaries.is_empty()
    }

    /// Check if a canary exists.
    pub fn exists(&self, name: &str) -> bool {
        self.canaries.contains_key(name)
    }

    /// Create default canaries for a namespace.
    pub fn create_defaults_for_namespace(&mut self, namespace: &str) -> CanaryResult<()> {
        // Create a few realistic-looking canaries
        let defaults = [
            ("BACKUP_AWS_ACCESS_KEY_ID", CanaryPattern::AwsAccessKey),
            ("OLD_API_KEY", CanaryPattern::ApiKey { length: 32 }),
            ("DEPRECATED_STRIPE_KEY", CanaryPattern::StripeKey { test_mode: false }),
        ];

        for (name, pattern) in defaults {
            let config = CanaryConfig {
                name: name.to_string(),
                pattern,
                on_trigger: TriggerAction::Alert,
                webhook_url: None,
                namespace: Some(namespace.to_string()),
            };

            // Skip if already exists
            if !self.exists(name) {
                self.create(config)?;
            }
        }

        Ok(())
    }
}

impl Default for CanaryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate random alphanumeric characters.
fn generate_alphanumeric(rng: &SystemRandom, len: usize) -> CanaryResult<String> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut result = String::with_capacity(len);
    let mut random_bytes = vec![0u8; len];

    rng.fill(&mut random_bytes)
        .map_err(|_| CanaryError::InvalidConfig("random generation failed".to_string()))?;

    for byte in random_bytes {
        let idx = (byte as usize) % CHARSET.len();
        result.push(CHARSET[idx] as char);
    }

    Ok(result)
}

/// Generate base64-like random characters.
fn generate_base64_like(rng: &SystemRandom, len: usize) -> CanaryResult<Vec<u8>> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::with_capacity(len);
    let mut random_bytes = vec![0u8; len];

    rng.fill(&mut random_bytes)
        .map_err(|_| CanaryError::InvalidConfig("random generation failed".to_string()))?;

    for byte in random_bytes {
        let idx = (byte as usize) % CHARSET.len();
        result.push(CHARSET[idx]);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_manager_creation() {
        let manager = CanaryManager::new();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_create_canary() {
        let mut manager = CanaryManager::new();

        let config = CanaryConfig {
            name: "TEST_CANARY".to_string(),
            pattern: CanaryPattern::ApiKey { length: 32 },
            on_trigger: TriggerAction::Log,
            webhook_url: None,
            namespace: None,
        };

        let canary = manager.create(config).unwrap();
        assert_eq!(canary.name(), "TEST_CANARY");
        assert_eq!(canary.access_count, 0);
        assert!(!canary.triggered);
    }

    #[test]
    fn test_create_duplicate_fails() {
        let mut manager = CanaryManager::new();

        let config = CanaryConfig {
            name: "DUPLICATE".to_string(),
            pattern: CanaryPattern::ApiKey { length: 16 },
            on_trigger: TriggerAction::Log,
            webhook_url: None,
            namespace: None,
        };

        manager.create(config.clone()).unwrap();
        let result = manager.create(config);

        assert!(matches!(result, Err(CanaryError::InvalidConfig(_))));
    }

    #[test]
    fn test_aws_access_key_format() {
        let value = CanaryManager::generate_value(&CanaryPattern::AwsAccessKey).unwrap();
        value.with_exposed(|bytes| {
            let s = std::str::from_utf8(bytes).unwrap();
            assert!(s.starts_with("AKIA"));
            assert_eq!(s.len(), 20);
        });
    }

    #[test]
    fn test_github_token_format() {
        let value = CanaryManager::generate_value(&CanaryPattern::GithubToken).unwrap();
        value.with_exposed(|bytes| {
            let s = std::str::from_utf8(bytes).unwrap();
            assert!(s.starts_with("ghp_"));
            assert_eq!(s.len(), 40);
        });
    }

    #[test]
    fn test_stripe_key_format() {
        let value = CanaryManager::generate_value(&CanaryPattern::StripeKey { test_mode: false }).unwrap();
        value.with_exposed(|bytes| {
            let s = std::str::from_utf8(bytes).unwrap();
            assert!(s.starts_with("sk_live_"));
            assert_eq!(s.len(), 32);
        });

        let test_value = CanaryManager::generate_value(&CanaryPattern::StripeKey { test_mode: true }).unwrap();
        test_value.with_exposed(|bytes| {
            let s = std::str::from_utf8(bytes).unwrap();
            assert!(s.starts_with("sk_test_"));
        });
    }

    #[test]
    fn test_check_leaked() {
        let mut manager = CanaryManager::new();

        let config = CanaryConfig {
            name: "LEAK_TEST".to_string(),
            pattern: CanaryPattern::Custom("super_secret_canary_value".to_string()),
            on_trigger: TriggerAction::Log,
            webhook_url: None,
            namespace: None,
        };

        manager.create(config).unwrap();

        // Should detect the canary in output
        let leaked = manager.check_leaked("Some output containing super_secret_canary_value here");
        assert!(leaked.is_some());
        assert_eq!(leaked.unwrap().name(), "LEAK_TEST");

        // Should not detect in innocent output
        let not_leaked = manager.check_leaked("Normal output without secrets");
        assert!(not_leaked.is_none());
    }

    #[test]
    fn test_record_access() {
        let mut manager = CanaryManager::new();

        let config = CanaryConfig {
            name: "ACCESS_TEST".to_string(),
            pattern: CanaryPattern::ApiKey { length: 16 },
            on_trigger: TriggerAction::Log,
            webhook_url: None,
            namespace: None,
        };

        manager.create(config).unwrap();

        // Recording access should return Triggered error
        let result = manager.record_access("ACCESS_TEST");
        assert!(matches!(result, Err(CanaryError::Triggered(_))));

        // Check that access was recorded
        let canary = manager.get("ACCESS_TEST").unwrap();
        assert_eq!(canary.access_count, 1);
        assert!(canary.triggered);
        assert!(canary.last_accessed.is_some());
    }

    #[test]
    fn test_list_by_namespace() {
        let mut manager = CanaryManager::new();

        for i in 0..3 {
            let config = CanaryConfig {
                name: format!("CANARY_{}", i),
                pattern: CanaryPattern::ApiKey { length: 16 },
                on_trigger: TriggerAction::Log,
                webhook_url: None,
                namespace: Some(if i < 2 { "prod" } else { "staging" }.to_string()),
            };
            manager.create(config).unwrap();
        }

        let prod_canaries = manager.list_by_namespace("prod");
        assert_eq!(prod_canaries.len(), 2);

        let staging_canaries = manager.list_by_namespace("staging");
        assert_eq!(staging_canaries.len(), 1);
    }

    #[test]
    fn test_create_defaults() {
        let mut manager = CanaryManager::new();
        manager.create_defaults_for_namespace("production").unwrap();

        assert!(manager.exists("BACKUP_AWS_ACCESS_KEY_ID"));
        assert!(manager.exists("OLD_API_KEY"));
        assert!(manager.exists("DEPRECATED_STRIPE_KEY"));

        let canary = manager.get("BACKUP_AWS_ACCESS_KEY_ID").unwrap();
        assert_eq!(canary.namespace(), "production");
    }

    #[test]
    fn test_remove_canary() {
        let mut manager = CanaryManager::new();

        let config = CanaryConfig {
            name: "TO_REMOVE".to_string(),
            pattern: CanaryPattern::ApiKey { length: 16 },
            on_trigger: TriggerAction::Log,
            webhook_url: None,
            namespace: None,
        };

        manager.create(config).unwrap();
        assert!(manager.exists("TO_REMOVE"));

        manager.remove("TO_REMOVE");
        assert!(!manager.exists("TO_REMOVE"));
    }
}
