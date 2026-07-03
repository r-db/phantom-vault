//! Policy engine for command allow/deny rules.
//!
//! Provides configurable policies that determine which commands
//! are allowed to execute with secrets. Policies are signed with
//! HMAC to prevent tampering.
//!
//! # Policy Structure (YAML)
//!
//! ```yaml
//! name: "production-policy"
//! version: 1
//! default_action: deny
//!
//! allowed_commands:
//!   - psql
//!   - mysql
//!   - git
//!
//! blocked_patterns:
//!   - SUBSTR_BASH
//!   - COND_TEST
//!   - DIRECT_PRINTENV
//!
//! allowed_domains:
//!   - api.stripe.com
//!   - api.github.com
//!
//! secret_rules:
//!   DATABASE_URL:
//!     allowed_commands: [psql, pg_dump]
//!   API_KEY:
//!     allowed_commands: [curl]
//!     allowed_domains: [api.stripe.com]
//! ```

use crate::patterns::{PatternCategory, PatternMatch};
use hex;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Errors that can occur during policy evaluation.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Policy syntax error.
    #[error("policy syntax error: {0}")]
    Syntax(String),

    /// Conflicting rules.
    #[error("conflicting rules: {0}")]
    Conflict(String),

    /// Invalid rule.
    #[error("invalid rule: {0}")]
    InvalidRule(String),

    /// Policy signature is invalid.
    #[error("policy signature verification failed")]
    InvalidSignature,

    /// Policy file error.
    #[error("policy file error: {0}")]
    FileError(String),

    /// YAML parsing error.
    #[error("YAML parsing error: {0}")]
    YamlError(String),
}

/// Result type for policy operations.
pub type PolicyResult<T> = Result<T, PolicyError>;

/// Action to take for a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    /// Allow the command to execute.
    Allow,
    /// Deny the command.
    Deny,
    /// Require user confirmation.
    Confirm,
    /// Allow but with additional sanitization.
    Sanitize,
    /// Warn but allow.
    Warn,
}

impl Default for PolicyAction {
    fn default() -> Self {
        Self::Deny
    }
}

impl std::fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Deny => write!(f, "DENY"),
            Self::Confirm => write!(f, "CONFIRM"),
            Self::Sanitize => write!(f, "SANITIZE"),
            Self::Warn => write!(f, "WARN"),
        }
    }
}

/// Per-secret command restrictions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretRule {
    /// Commands allowed for this secret.
    #[serde(default)]
    pub allowed_commands: HashSet<String>,
    /// Domains allowed for this secret (for curl/wget).
    #[serde(default)]
    pub allowed_domains: HashSet<String>,
    /// Blocked pattern IDs for this secret.
    #[serde(default)]
    pub blocked_patterns: HashSet<String>,
    /// Override default action for this secret.
    #[serde(default)]
    pub default_action: Option<PolicyAction>,
}

/// A policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule name for logging.
    pub name: String,
    /// Condition for when rule applies.
    pub condition: RuleCondition,
    /// Action to take.
    pub action: PolicyAction,
    /// Priority (higher = evaluated first).
    #[serde(default)]
    pub priority: i32,
}

/// Condition for a policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleCondition {
    /// Match specific command.
    Command { command: String },
    /// Match command prefix.
    CommandPrefix { prefix: String },
    /// Match regex pattern.
    Regex { pattern: String },
    /// Match commands accessing specific secrets.
    AccessesSecret { secret: String },
    /// Match specific pattern category.
    PatternCategory { category: PatternCategory },
    /// Boolean AND of conditions.
    And { conditions: Vec<RuleCondition> },
    /// Boolean OR of conditions.
    Or { conditions: Vec<RuleCondition> },
    /// Negate condition.
    Not { condition: Box<RuleCondition> },
    /// Always matches.
    Always,
}

impl RuleCondition {
    /// Check if this condition matches the given context.
    pub fn matches(&self, ctx: &EvaluationContext) -> bool {
        match self {
            Self::Command { command } => ctx.command_name == *command,
            Self::CommandPrefix { prefix } => ctx.raw_command.starts_with(prefix),
            Self::Regex { pattern } => {
                regex::Regex::new(pattern)
                    .map(|re| re.is_match(&ctx.raw_command))
                    .unwrap_or(false)
            }
            Self::AccessesSecret { secret } => ctx.accessed_secrets.contains(secret),
            Self::PatternCategory { category } => {
                ctx.matched_patterns.iter().any(|p| &p.pattern.category == category)
            }
            Self::And { conditions } => conditions.iter().all(|c| c.matches(ctx)),
            Self::Or { conditions } => conditions.iter().any(|c| c.matches(ctx)),
            Self::Not { condition } => !condition.matches(ctx),
            Self::Always => true,
        }
    }
}

/// Context for policy evaluation.
#[derive(Debug)]
pub struct EvaluationContext<'a> {
    /// Raw command string.
    pub raw_command: &'a str,
    /// Extracted command name (first token).
    pub command_name: String,
    /// Secrets accessed by this command.
    pub accessed_secrets: HashSet<String>,
    /// Pattern matches found.
    pub matched_patterns: Vec<PatternMatch>,
    /// Domains accessed by this command.
    pub accessed_domains: HashSet<String>,
}

/// Result of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyEvaluation {
    /// The action to take.
    pub action: PolicyAction,
    /// The rule that matched (if any).
    pub matched_rule: Option<String>,
    /// Explanation of why this action was taken.
    pub reason: String,
    /// Risk score (0.0 = safe, 1.0 = definitely malicious).
    pub risk_score: f64,
    /// Suggestions for the user.
    pub suggestions: Vec<String>,
}

/// YAML policy definition (for parsing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefinition {
    /// Policy name.
    pub name: String,
    /// Policy version.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Default action when no rules match.
    #[serde(default)]
    pub default_action: PolicyAction,
    /// Whitelisted commands.
    #[serde(default)]
    pub allowed_commands: HashSet<String>,
    /// Blocked pattern IDs.
    #[serde(default)]
    pub blocked_patterns: HashSet<String>,
    /// Allowed domains for network access.
    #[serde(default)]
    pub allowed_domains: HashSet<String>,
    /// Per-secret rules.
    #[serde(default)]
    pub secret_rules: HashMap<String, SecretRule>,
    /// Custom rules.
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    /// HMAC signature (hex-encoded).
    #[serde(skip)]
    pub signature: Option<String>,
}

fn default_version() -> u32 {
    1
}

impl Default for PolicyDefinition {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            version: 1,
            default_action: PolicyAction::Deny,
            allowed_commands: HashSet::new(),
            blocked_patterns: HashSet::new(),
            allowed_domains: HashSet::new(),
            secret_rules: HashMap::new(),
            rules: Vec::new(),
            signature: None,
        }
    }
}

/// A policy for command execution.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Policy definition.
    definition: PolicyDefinition,
    /// Compiled regex patterns for blocked patterns.
    blocked_pattern_ids: HashSet<String>,
}

impl Policy {
    /// Create a strict policy that blocks most patterns.
    pub fn strict() -> Self {
        let mut definition = PolicyDefinition {
            name: "strict".to_string(),
            version: 1,
            default_action: PolicyAction::Deny,
            ..Default::default()
        };

        // Block all dangerous pattern categories
        definition.blocked_patterns = [
            "SUBSTR_BASH", "SUBSTR_CUT", "SUBSTR_AWK", "SUBSTR_SED",
            "SUBSTR_PYTHON", "SUBSTR_NODE", "SUBSTR_RUBY", "SUBSTR_PERL",
            "COND_TEST", "COND_CASE", "COND_GREP",
            "ENCODE_BASE64", "ENCODE_HEX", "ENCODE_OCTAL",
            "EXFIL_CURL_URL", "EXFIL_DNS", "EXFIL_NETCAT",
            "DIRECT_PRINTENV", "DIRECT_EXPORT", "DIRECT_PROC_ENVIRON", "DIRECT_PS_ENV", "DIRECT_SET",
            "WRITE_REDIRECT", "WRITE_TMP",
            "TIMING_SLEEP",
        ].iter().map(|s| s.to_string()).collect();

        // Allow only safe commands
        definition.allowed_commands = [
            "psql", "mysql", "mongosh", "redis-cli",
            "aws", "gcloud", "az", "heroku", "vercel", "fly",
            "npm", "yarn", "pnpm", "cargo", "pip", "poetry",
            "git", "gh",
            "docker", "docker-compose", "kubectl", "helm",
        ].iter().map(|s| s.to_string()).collect();

        Self {
            blocked_pattern_ids: definition.blocked_patterns.clone(),
            definition,
        }
    }

    /// Create a permissive policy that allows most commands.
    pub fn permissive() -> Self {
        let definition = PolicyDefinition {
            name: "permissive".to_string(),
            version: 1,
            default_action: PolicyAction::Warn,
            blocked_patterns: [
                "DIRECT_PRINTENV", "DIRECT_PROC_ENVIRON",
                "TIMING_SLEEP",
            ].iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };

        Self {
            blocked_pattern_ids: definition.blocked_patterns.clone(),
            definition,
        }
    }

    /// Create an empty policy (deny all).
    pub fn empty() -> Self {
        let definition = PolicyDefinition::default();
        Self {
            blocked_pattern_ids: HashSet::new(),
            definition,
        }
    }

    /// Create a new policy from a definition.
    pub fn from_definition(definition: PolicyDefinition) -> Self {
        Self {
            blocked_pattern_ids: definition.blocked_patterns.clone(),
            definition,
        }
    }

    /// Load policy from YAML string.
    pub fn load_yaml(yaml: &str) -> PolicyResult<Self> {
        let definition: PolicyDefinition = serde_yaml::from_str(yaml)
            .map_err(|e| PolicyError::YamlError(e.to_string()))?;

        Ok(Self::from_definition(definition))
    }

    /// Load policy from YAML file.
    pub fn load_yaml_file(path: &str) -> PolicyResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| PolicyError::FileError(e.to_string()))?;

        Self::load_yaml(&content)
    }

    /// Load a signed policy from YAML string.
    ///
    /// The YAML should have a `---` separator followed by the HMAC signature.
    pub fn load_signed_yaml(yaml: &str, key: &[u8]) -> PolicyResult<Self> {
        // Split content and signature
        let parts: Vec<&str> = yaml.splitn(2, "\n---\n").collect();

        if parts.len() != 2 {
            return Err(PolicyError::InvalidSignature);
        }

        let policy_content = parts[0];
        let signature_line = parts[1].trim();

        // Verify signature
        let expected_sig = signature_line.strip_prefix("signature: ")
            .ok_or(PolicyError::InvalidSignature)?;

        let expected_bytes = hex::decode(expected_sig)
            .map_err(|_| PolicyError::InvalidSignature)?;

        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::verify(&signing_key, policy_content.as_bytes(), &expected_bytes)
            .map_err(|_| PolicyError::InvalidSignature)?;

        // Parse the policy
        Self::load_yaml(policy_content)
    }

    /// Export policy to YAML.
    pub fn to_yaml(&self) -> PolicyResult<String> {
        serde_yaml::to_string(&self.definition)
            .map_err(|e| PolicyError::YamlError(e.to_string()))
    }

    /// Export policy to signed YAML.
    pub fn to_signed_yaml(&self, key: &[u8]) -> PolicyResult<String> {
        let yaml = self.to_yaml()?;

        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let signature = hmac::sign(&signing_key, yaml.as_bytes());
        let sig_hex = hex::encode(signature.as_ref());

        Ok(format!("{}\n---\nsignature: {}", yaml, sig_hex))
    }

    /// Load policy from JSON.
    pub fn load_json(json: &str) -> PolicyResult<Self> {
        let definition: PolicyDefinition = serde_json::from_str(json)
            .map_err(|e| PolicyError::Syntax(e.to_string()))?;

        Ok(Self::from_definition(definition))
    }

    /// Export policy to JSON.
    pub fn to_json(&self) -> PolicyResult<String> {
        serde_json::to_string_pretty(&self.definition)
            .map_err(|e| PolicyError::Syntax(e.to_string()))
    }

    /// Add a rule to the policy.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.definition.rules.push(rule);
        // Sort by priority (descending)
        self.definition.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Add an allowed command.
    pub fn allow_command(&mut self, command: &str) {
        self.definition.allowed_commands.insert(command.to_string());
    }

    /// Add an allowed domain.
    pub fn allow_domain(&mut self, domain: &str) {
        self.definition.allowed_domains.insert(domain.to_string());
    }

    /// Add a blocked pattern.
    pub fn block_pattern(&mut self, pattern_id: &str) {
        self.definition.blocked_patterns.insert(pattern_id.to_string());
        self.blocked_pattern_ids.insert(pattern_id.to_string());
    }

    /// Add a secret-specific rule.
    pub fn add_secret_rule(&mut self, secret_name: &str, rule: SecretRule) {
        self.definition.secret_rules.insert(secret_name.to_string(), rule);
    }

    /// Set the default action.
    pub fn set_default_action(&mut self, action: PolicyAction) {
        self.definition.default_action = action;
    }

    /// Get the policy name.
    pub fn name(&self) -> &str {
        &self.definition.name
    }

    /// Get the default action.
    pub fn default_action(&self) -> PolicyAction {
        self.definition.default_action
    }

    /// Check if a command is in the allowed list.
    pub fn is_command_allowed(&self, command: &str) -> bool {
        self.definition.allowed_commands.contains(command)
    }

    /// Check if a domain is allowed.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        if self.definition.allowed_domains.is_empty() {
            return true; // No restrictions
        }

        self.definition.allowed_domains.iter().any(|allowed| {
            domain == allowed || domain.ends_with(&format!(".{}", allowed))
        })
    }

    /// Check if a pattern ID is blocked.
    pub fn is_pattern_blocked(&self, pattern_id: &str) -> bool {
        self.blocked_pattern_ids.contains(pattern_id)
    }

    /// Evaluate a command against the policy.
    pub fn evaluate(&self, ctx: &EvaluationContext) -> PolicyEvaluation {
        let mut reasons = Vec::new();
        let suggestions = Vec::new();
        let mut max_severity: f64 = 0.0;

        // Check for blocked patterns
        for pattern_match in &ctx.matched_patterns {
            if self.is_pattern_blocked(pattern_match.pattern.id) {
                reasons.push(format!(
                    "Blocked pattern '{}': {}",
                    pattern_match.pattern.id,
                    pattern_match.pattern.description
                ));
                max_severity = max_severity.max(pattern_match.pattern.severity);
            }
        }

        // If we have blocked patterns, deny
        if !reasons.is_empty() {
            return PolicyEvaluation {
                action: PolicyAction::Deny,
                matched_rule: Some("blocked_pattern".to_string()),
                reason: reasons.join("; "),
                risk_score: max_severity,
                suggestions,
            };
        }

        // Check custom rules (sorted by priority)
        for rule in &self.definition.rules {
            if rule.condition.matches(ctx) {
                return PolicyEvaluation {
                    action: rule.action,
                    matched_rule: Some(rule.name.clone()),
                    reason: format!("Rule '{}' matched", rule.name),
                    risk_score: match rule.action {
                        PolicyAction::Allow => 0.0,
                        PolicyAction::Warn => 0.3,
                        PolicyAction::Sanitize => 0.5,
                        PolicyAction::Confirm => 0.6,
                        PolicyAction::Deny => 1.0,
                    },
                    suggestions,
                };
            }
        }

        // Check per-secret rules
        for secret in &ctx.accessed_secrets {
            if let Some(secret_rule) = self.definition.secret_rules.get(secret) {
                // Check if command is allowed for this secret
                if !secret_rule.allowed_commands.is_empty() {
                    if secret_rule.allowed_commands.contains(&ctx.command_name) {
                        // Command is explicitly allowed for this secret
                        return PolicyEvaluation {
                            action: PolicyAction::Allow,
                            matched_rule: Some(format!("secret_rule:{}", secret)),
                            reason: format!(
                                "Command '{}' is allowed for secret '{}'",
                                ctx.command_name, secret
                            ),
                            risk_score: 0.0,
                            suggestions: vec![],
                        };
                    } else {
                        // Command is not in the allowed list
                        return PolicyEvaluation {
                            action: PolicyAction::Deny,
                            matched_rule: Some(format!("secret_rule:{}", secret)),
                            reason: format!(
                                "Command '{}' is not allowed for secret '{}'. Allowed: {:?}",
                                ctx.command_name, secret, secret_rule.allowed_commands
                            ),
                            risk_score: 0.8,
                            suggestions: vec![format!(
                                "Use one of: {}",
                                secret_rule.allowed_commands.iter().cloned().collect::<Vec<_>>().join(", ")
                            )],
                        };
                    }
                }

                // Check domain restrictions
                if !secret_rule.allowed_domains.is_empty() {
                    for domain in &ctx.accessed_domains {
                        let domain_allowed = secret_rule.allowed_domains.iter().any(|allowed| {
                            domain == allowed || domain.ends_with(&format!(".{}", allowed))
                        });

                        if !domain_allowed {
                            return PolicyEvaluation {
                                action: PolicyAction::Deny,
                                matched_rule: Some(format!("secret_rule:{}:domain", secret)),
                                reason: format!(
                                    "Domain '{}' is not allowed for secret '{}'. Allowed: {:?}",
                                    domain, secret, secret_rule.allowed_domains
                                ),
                                risk_score: 0.9,
                                suggestions: vec![],
                            };
                        }
                    }
                }

                // Use secret-specific default action if set
                if let Some(action) = secret_rule.default_action {
                    return PolicyEvaluation {
                        action,
                        matched_rule: Some(format!("secret_rule:{}:default", secret)),
                        reason: format!("Secret '{}' has default action {:?}", secret, action),
                        risk_score: 0.0,
                        suggestions: vec![],
                    };
                }
            }
        }

        // Check if command is in allowed list
        if self.is_command_allowed(&ctx.command_name) {
            return PolicyEvaluation {
                action: PolicyAction::Allow,
                matched_rule: Some("allowed_commands".to_string()),
                reason: format!("Command '{}' is in allowed list", ctx.command_name),
                risk_score: 0.0,
                suggestions,
            };
        }

        // Check domain restrictions for network commands
        if !ctx.accessed_domains.is_empty() && !self.definition.allowed_domains.is_empty() {
            for domain in &ctx.accessed_domains {
                if !self.is_domain_allowed(domain) {
                    return PolicyEvaluation {
                        action: PolicyAction::Deny,
                        matched_rule: Some("allowed_domains".to_string()),
                        reason: format!("Domain '{}' is not in allowed list", domain),
                        risk_score: 0.9,
                        suggestions: vec![format!(
                            "Allowed domains: {}",
                            self.definition.allowed_domains.iter().cloned().collect::<Vec<_>>().join(", ")
                        )],
                    };
                }
            }
        }

        // Default action
        PolicyEvaluation {
            action: self.definition.default_action,
            matched_rule: None,
            reason: format!("No rules matched, using default action: {:?}", self.definition.default_action),
            risk_score: match self.definition.default_action {
                PolicyAction::Allow => 0.0,
                PolicyAction::Warn => 0.3,
                PolicyAction::Sanitize => 0.5,
                PolicyAction::Confirm => 0.6,
                PolicyAction::Deny => 0.7,
            },
            suggestions,
        }
    }

    /// Get the rule that matched (for logging).
    pub fn matching_rule(&self, ctx: &EvaluationContext) -> Option<&PolicyRule> {
        self.definition.rules.iter().find(|rule| rule.condition.matches(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::{BlockedPattern, PatternCategory};

    fn make_context<'a>(
        raw: &'a str,
        command: &str,
        secrets: &[&str],
        patterns: Vec<PatternMatch>,
    ) -> EvaluationContext<'a> {
        EvaluationContext {
            raw_command: raw,
            command_name: command.to_string(),
            accessed_secrets: secrets.iter().map(|s| s.to_string()).collect(),
            matched_patterns: patterns,
            accessed_domains: HashSet::new(),
        }
    }

    #[test]
    fn test_strict_policy_blocks_printenv() {
        let policy = Policy::strict();

        // Create a pattern match for printenv
        static PAT: BlockedPattern = BlockedPattern {
            id: "DIRECT_PRINTENV",
            category: PatternCategory::DirectAccess,
            description: "printenv exposes all environment variables",
            severity: 1.0,
            overridable: false,
        };

        let ctx = make_context(
            "printenv",
            "printenv",
            &[],
            vec![PatternMatch {
                pattern: &PAT,
                matched_text: "printenv".to_string(),
                involved_variables: vec![],
                context: None,
            }],
        );

        let result = policy.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Deny);
    }

    #[test]
    fn test_strict_policy_allows_psql() {
        let policy = Policy::strict();
        let ctx = make_context("psql $DATABASE_URL", "psql", &["DATABASE_URL"], vec![]);

        let result = policy.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Allow);
    }

    #[test]
    fn test_permissive_policy_warns() {
        let policy = Policy::permissive();
        let ctx = make_context("some_command", "some_command", &[], vec![]);

        let result = policy.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Warn);
    }

    #[test]
    fn test_load_yaml() {
        let yaml = r#"
name: "test-policy"
version: 1
default_action: deny
allowed_commands:
  - git
  - cargo
blocked_patterns:
  - DIRECT_PRINTENV
allowed_domains:
  - github.com
"#;

        let policy = Policy::load_yaml(yaml).unwrap();
        assert_eq!(policy.name(), "test-policy");
        assert!(policy.is_command_allowed("git"));
        assert!(policy.is_command_allowed("cargo"));
        assert!(!policy.is_command_allowed("curl"));
        assert!(policy.is_pattern_blocked("DIRECT_PRINTENV"));
        assert!(policy.is_domain_allowed("github.com"));
        assert!(policy.is_domain_allowed("api.github.com"));
    }

    #[test]
    fn test_signed_yaml() {
        let policy = Policy::strict();
        let key = b"test-secret-key-for-signing";

        let signed = policy.to_signed_yaml(key).unwrap();

        // Should be able to load it back
        let loaded = Policy::load_signed_yaml(&signed, key).unwrap();
        assert_eq!(loaded.name(), policy.name());

        // Should fail with wrong key
        let wrong_key = b"wrong-key";
        let result = Policy::load_signed_yaml(&signed, wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_specific_rules() {
        let yaml = r#"
name: "secret-rules-test"
default_action: deny
secret_rules:
  DATABASE_URL:
    allowed_commands:
      - psql
      - pg_dump
  STRIPE_KEY:
    allowed_commands:
      - curl
    allowed_domains:
      - api.stripe.com
"#;

        let policy = Policy::load_yaml(yaml).unwrap();

        // psql with DATABASE_URL should be allowed
        let ctx = make_context("psql $DATABASE_URL", "psql", &["DATABASE_URL"], vec![]);
        let result = policy.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Allow);

        // curl with DATABASE_URL should be denied
        let ctx = make_context("curl $DATABASE_URL", "curl", &["DATABASE_URL"], vec![]);
        let result = policy.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Deny);
    }

    #[test]
    fn test_domain_restrictions() {
        let yaml = r#"
name: "domain-test"
default_action: allow
allowed_domains:
  - api.example.com
  - trusted.com
"#;

        let policy = Policy::load_yaml(yaml).unwrap();

        // Allowed domain
        let mut ctx = make_context("curl https://api.example.com", "curl", &[], vec![]);
        ctx.accessed_domains.insert("api.example.com".to_string());
        let result = policy.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Allow);

        // Subdomain of allowed domain
        ctx.accessed_domains.clear();
        ctx.accessed_domains.insert("v1.api.example.com".to_string());
        let result = policy.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Allow);

        // Disallowed domain
        ctx.accessed_domains.clear();
        ctx.accessed_domains.insert("evil.com".to_string());
        let result = policy.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Deny);
    }

    #[test]
    fn test_custom_rules() {
        let mut policy = Policy::empty();

        policy.add_rule(PolicyRule {
            name: "allow-git".to_string(),
            condition: RuleCondition::CommandPrefix { prefix: "git ".to_string() },
            action: PolicyAction::Allow,
            priority: 10,
        });

        policy.add_rule(PolicyRule {
            name: "warn-rm".to_string(),
            condition: RuleCondition::Command { command: "rm".to_string() },
            action: PolicyAction::Warn,
            priority: 5,
        });

        // Git should be allowed
        let ctx = make_context("git status", "git", &[], vec![]);
        let result = policy.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Allow);

        // rm should warn
        let ctx = make_context("rm -rf /", "rm", &[], vec![]);
        let result = policy.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Warn);

        // Other commands get default (deny)
        let ctx = make_context("curl http://example.com", "curl", &[], vec![]);
        let result = policy.evaluate(&ctx);
        assert_eq!(result.action, PolicyAction::Deny);
    }

    #[test]
    fn test_to_json_and_back() {
        let policy = Policy::strict();
        let json = policy.to_json().unwrap();
        let loaded = Policy::load_json(&json).unwrap();
        assert_eq!(loaded.name(), policy.name());
    }
}
