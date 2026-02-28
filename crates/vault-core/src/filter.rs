//! Output filtering to detect and redact credential leaks
//!
//! Scans all output before returning to LLM using:
//! - 30+ regex patterns for common credential formats
//! - Exact match against actual vault secret values
//! - Configurable redaction (replace with [REDACTED] or reference name)

use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

use crate::error::{FilterError, FilterResult};

/// Redaction placeholder
const REDACTED: &str = "[REDACTED]";

/// Credential pattern with metadata
#[derive(Debug, Clone)]
pub struct CredentialPattern {
    /// Pattern name for logging
    pub name: &'static str,
    /// Regex pattern
    pub pattern: &'static str,
    /// Description of what this detects
    pub description: &'static str,
}

/// All known credential patterns
pub static CREDENTIAL_PATTERNS: &[CredentialPattern] = &[
    // AWS
    CredentialPattern {
        name: "aws_access_key",
        pattern: r"AKIA[0-9A-Z]{16}",
        description: "AWS Access Key ID",
    },
    CredentialPattern {
        name: "aws_secret_key",
        pattern: r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:][\s]*['"]?([A-Za-z0-9/+=]{40})['"]?"#,
        description: "AWS Secret Access Key",
    },
    CredentialPattern {
        name: "aws_session_token",
        pattern: r#"(?i)aws[_\-]?session[_\-]?token[\s]*[=:][\s]*['"]?([A-Za-z0-9/+=]+)['"]?"#,
        description: "AWS Session Token",
    },

    // GitHub
    CredentialPattern {
        name: "github_pat",
        pattern: r"ghp_[0-9a-zA-Z]{36}",
        description: "GitHub Personal Access Token",
    },
    CredentialPattern {
        name: "github_oauth",
        pattern: r"gho_[0-9a-zA-Z]{36}",
        description: "GitHub OAuth Access Token",
    },
    CredentialPattern {
        name: "github_app",
        pattern: r"ghu_[0-9a-zA-Z]{36}",
        description: "GitHub User-to-Server Token",
    },
    CredentialPattern {
        name: "github_refresh",
        pattern: r"ghr_[0-9a-zA-Z]{36}",
        description: "GitHub Refresh Token",
    },
    CredentialPattern {
        name: "github_fine_grained",
        pattern: r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}",
        description: "GitHub Fine-Grained PAT",
    },

    // OpenAI / AI Services
    CredentialPattern {
        name: "openai_key",
        pattern: r"sk-[0-9a-zA-Z]{48,}",
        description: "OpenAI API Key",
    },
    CredentialPattern {
        name: "openai_proj",
        pattern: r"sk-proj-[0-9a-zA-Z\-_]{48,}",
        description: "OpenAI Project API Key",
    },
    CredentialPattern {
        name: "anthropic_key",
        pattern: r"sk-ant-[0-9a-zA-Z\-_]{48,}",
        description: "Anthropic API Key",
    },

    // Stripe
    CredentialPattern {
        name: "stripe_live",
        pattern: r"sk_live_[0-9a-zA-Z]{24,}",
        description: "Stripe Live Secret Key",
    },
    CredentialPattern {
        name: "stripe_test",
        pattern: r"sk_test_[0-9a-zA-Z]{24,}",
        description: "Stripe Test Secret Key",
    },
    CredentialPattern {
        name: "stripe_restricted",
        pattern: r"rk_live_[0-9a-zA-Z]{24,}",
        description: "Stripe Restricted Key",
    },

    // Google
    CredentialPattern {
        name: "google_api_key",
        pattern: r"AIza[0-9A-Za-z\-_]{35}",
        description: "Google API Key",
    },
    CredentialPattern {
        name: "google_oauth",
        pattern: r"ya29\.[0-9A-Za-z\-_]+",
        description: "Google OAuth Token",
    },
    CredentialPattern {
        name: "google_service_account",
        pattern: r#""type":\s*"service_account""#,
        description: "Google Service Account JSON",
    },

    // Database URLs
    CredentialPattern {
        name: "postgres_url",
        pattern: r"postgres(?:ql)?://[^:]+:[^@]+@[^\s]+",
        description: "PostgreSQL Connection URL",
    },
    CredentialPattern {
        name: "mysql_url",
        pattern: r"mysql://[^:]+:[^@]+@[^\s]+",
        description: "MySQL Connection URL",
    },
    CredentialPattern {
        name: "mongodb_url",
        pattern: r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s]+",
        description: "MongoDB Connection URL",
    },
    CredentialPattern {
        name: "redis_url",
        pattern: r"redis://[^:]*:[^@]+@[^\s]+",
        description: "Redis Connection URL",
    },

    // Private Keys
    CredentialPattern {
        name: "rsa_private_key",
        pattern: r"-----BEGIN RSA PRIVATE KEY-----",
        description: "RSA Private Key",
    },
    CredentialPattern {
        name: "openssh_private_key",
        pattern: r"-----BEGIN OPENSSH PRIVATE KEY-----",
        description: "OpenSSH Private Key",
    },
    CredentialPattern {
        name: "ec_private_key",
        pattern: r"-----BEGIN EC PRIVATE KEY-----",
        description: "EC Private Key",
    },
    CredentialPattern {
        name: "pgp_private_key",
        pattern: r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        description: "PGP Private Key",
    },
    CredentialPattern {
        name: "generic_private_key",
        pattern: r"-----BEGIN PRIVATE KEY-----",
        description: "Generic Private Key (PKCS#8)",
    },

    // JWT / Tokens
    CredentialPattern {
        name: "jwt_token",
        pattern: r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        description: "JWT Token",
    },
    CredentialPattern {
        name: "bearer_token",
        pattern: r"(?i)bearer\s+[a-zA-Z0-9\-_.~+/]+=*",
        description: "Bearer Token",
    },
    CredentialPattern {
        name: "basic_auth",
        pattern: r"(?i)basic\s+[a-zA-Z0-9+/]+=*",
        description: "Basic Auth Header",
    },

    // Cloud Providers
    CredentialPattern {
        name: "azure_storage",
        pattern: r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
        description: "Azure Storage Connection String",
    },
    CredentialPattern {
        name: "azure_sas",
        pattern: r"[?&]sig=[a-zA-Z0-9%]+",
        description: "Azure SAS Token",
    },
    CredentialPattern {
        name: "digitalocean",
        pattern: r"dop_v1_[0-9a-f]{64}",
        description: "DigitalOcean PAT",
    },
    CredentialPattern {
        name: "heroku_api",
        pattern: r"[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        description: "Heroku API Key",
    },

    // Messaging / Communication
    CredentialPattern {
        name: "slack_token",
        pattern: r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        description: "Slack Token",
    },
    CredentialPattern {
        name: "slack_webhook",
        pattern: r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        description: "Slack Webhook URL",
    },
    CredentialPattern {
        name: "discord_token",
        pattern: r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
        description: "Discord Bot Token",
    },
    CredentialPattern {
        name: "discord_webhook",
        pattern: r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        description: "Discord Webhook URL",
    },
    CredentialPattern {
        name: "twilio_sid",
        pattern: r"AC[a-z0-9]{32}",
        description: "Twilio Account SID",
    },
    CredentialPattern {
        name: "twilio_token",
        pattern: r"SK[a-z0-9]{32}",
        description: "Twilio Auth Token",
    },

    // Payment / Financial
    CredentialPattern {
        name: "paypal_braintree",
        pattern: r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        description: "PayPal/Braintree Access Token",
    },
    CredentialPattern {
        name: "square_access",
        pattern: r"sq0atp-[0-9A-Za-z\-_]{22}",
        description: "Square Access Token",
    },
    CredentialPattern {
        name: "square_oauth",
        pattern: r"sq0csp-[0-9A-Za-z\-_]{43}",
        description: "Square OAuth Secret",
    },

    // Version Control
    CredentialPattern {
        name: "gitlab_pat",
        pattern: r"glpat-[0-9a-zA-Z\-_]{20}",
        description: "GitLab PAT",
    },
    CredentialPattern {
        name: "bitbucket_token",
        pattern: r"ATBB[a-zA-Z0-9]{32}",
        description: "Bitbucket App Token",
    },

    // Infrastructure
    CredentialPattern {
        name: "npm_token",
        pattern: r"npm_[a-zA-Z0-9]{36}",
        description: "NPM Access Token",
    },
    CredentialPattern {
        name: "pypi_token",
        pattern: r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}",
        description: "PyPI API Token",
    },
    CredentialPattern {
        name: "docker_token",
        pattern: r"dckr_pat_[A-Za-z0-9\-_]{27}",
        description: "Docker PAT",
    },

    // Email Services
    CredentialPattern {
        name: "sendgrid_key",
        pattern: r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        description: "SendGrid API Key",
    },
    CredentialPattern {
        name: "mailgun_key",
        pattern: r"key-[0-9a-zA-Z]{32}",
        description: "Mailgun API Key",
    },
    CredentialPattern {
        name: "mailchimp_key",
        pattern: r"[0-9a-f]{32}-us[0-9]{1,2}",
        description: "Mailchimp API Key",
    },

    // Misc
    CredentialPattern {
        name: "generic_api_key",
        pattern: r#"(?i)api[_\-]?key[\s]*[=:][\s]*['"]?([a-zA-Z0-9\-_]{32,})['"]?"#,
        description: "Generic API Key Assignment",
    },
    CredentialPattern {
        name: "generic_secret",
        pattern: r#"(?i)secret[\s]*[=:][\s]*['"]?([a-zA-Z0-9\-_]{32,})['"]?"#,
        description: "Generic Secret Assignment",
    },
    CredentialPattern {
        name: "generic_password",
        pattern: r#"(?i)password[\s]*[=:][\s]*['"]?([^\s'"]{8,})['"]?"#,
        description: "Generic Password Assignment",
    },
];

/// Compiled regex patterns (lazy initialized)
static COMPILED_PATTERNS: LazyLock<Vec<(CredentialPattern, Regex)>> = LazyLock::new(|| {
    CREDENTIAL_PATTERNS
        .iter()
        .filter_map(|p| {
            Regex::new(p.pattern)
                .ok()
                .map(|r| (p.clone(), r))
        })
        .collect()
});

/// Result of scanning output for credentials
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Whether any credentials were detected
    pub has_credentials: bool,
    /// List of detected credential types
    pub detected_types: Vec<String>,
    /// Redacted output (safe to return to LLM)
    pub redacted_output: String,
    /// Number of redactions made
    pub redaction_count: usize,
}

/// Output filter for credential detection and redaction
#[derive(Debug, Default)]
pub struct OutputFilter {
    /// Additional exact-match secrets to detect
    known_secrets: HashSet<String>,
    /// Reference names for known secrets (for better redaction messages)
    secret_references: std::collections::HashMap<String, String>,
}

impl OutputFilter {
    /// Create a new output filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a known secret value to detect (exact match)
    pub fn add_secret(&mut self, value: String, reference: Option<String>) {
        if let Some(ref_name) = reference {
            self.secret_references.insert(value.clone(), ref_name);
        }
        self.known_secrets.insert(value);
    }

    /// Remove a known secret
    pub fn remove_secret(&mut self, value: &str) {
        self.known_secrets.remove(value);
        self.secret_references.remove(value);
    }

    /// Clear all known secrets
    pub fn clear_secrets(&mut self) {
        self.known_secrets.clear();
        self.secret_references.clear();
    }

    /// Scan output for credentials and redact them
    pub fn scan_and_redact(&self, output: &str) -> ScanResult {
        let mut redacted = output.to_string();
        let mut detected_types = Vec::new();
        let mut redaction_count = 0;

        // First, check for exact matches of known secrets
        for secret in &self.known_secrets {
            if redacted.contains(secret) {
                let replacement = if let Some(ref_name) = self.secret_references.get(secret) {
                    format!("[REDACTED:{}]", ref_name)
                } else {
                    REDACTED.to_string()
                };
                redacted = redacted.replace(secret, &replacement);
                detected_types.push("known_secret".to_string());
                redaction_count += 1;
            }
        }

        // Then, check regex patterns
        for (pattern_info, regex) in COMPILED_PATTERNS.iter() {
            if regex.is_match(&redacted) {
                redacted = regex.replace_all(&redacted, REDACTED).to_string();
                detected_types.push(pattern_info.name.to_string());
                redaction_count += 1;
            }
        }

        ScanResult {
            has_credentials: !detected_types.is_empty(),
            detected_types,
            redacted_output: redacted,
            redaction_count,
        }
    }

    /// Check if output contains any credentials (without redacting)
    pub fn contains_credentials(&self, output: &str) -> bool {
        // Check known secrets
        for secret in &self.known_secrets {
            if output.contains(secret) {
                return true;
            }
        }

        // Check patterns
        for (_, regex) in COMPILED_PATTERNS.iter() {
            if regex.is_match(output) {
                return true;
            }
        }

        false
    }

    /// Get all pattern names that match in the output
    pub fn detect_patterns(&self, output: &str) -> Vec<&'static str> {
        let mut matches = Vec::new();

        for (pattern_info, regex) in COMPILED_PATTERNS.iter() {
            if regex.is_match(output) {
                matches.push(pattern_info.name);
            }
        }

        matches
    }
}

/// Scan output using default filter (no known secrets)
pub fn scan_output(output: &str) -> ScanResult {
    let filter = OutputFilter::new();
    filter.scan_and_redact(output)
}

/// Quick check if output contains any credential patterns
pub fn contains_credential_patterns(output: &str) -> bool {
    for (_, regex) in COMPILED_PATTERNS.iter() {
        if regex.is_match(output) {
            return true;
        }
    }
    false
}

/// Create a filter with specific secret values
pub fn create_filter_with_secrets<I, S>(secrets: I) -> FilterResult<OutputFilter>
where
    I: IntoIterator<Item = (S, Option<String>)>,
    S: Into<String>,
{
    let mut filter = OutputFilter::new();
    for (secret, reference) in secrets {
        filter.add_secret(secret.into(), reference);
    }
    Ok(filter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_key_detection() {
        let output = "Found key: AKIAIOSFODNN7EXAMPLE";
        let result = scan_output(output);
        assert!(result.has_credentials);
        assert!(result.detected_types.contains(&"aws_access_key".to_string()));
        assert!(result.redacted_output.contains(REDACTED));
    }

    #[test]
    fn test_github_pat_detection() {
        let output = "Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = scan_output(output);
        assert!(result.has_credentials);
        assert!(result.detected_types.contains(&"github_pat".to_string()));
    }

    #[test]
    fn test_openai_key_detection() {
        let output = "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = scan_output(output);
        assert!(result.has_credentials);
        assert!(result.detected_types.contains(&"openai_key".to_string()));
    }

    #[test]
    fn test_postgres_url_detection() {
        let output = "DATABASE_URL=postgres://user:password123@localhost:5432/mydb";
        let result = scan_output(output);
        assert!(result.has_credentials);
        assert!(result.detected_types.contains(&"postgres_url".to_string()));
    }

    #[test]
    fn test_jwt_detection() {
        let output = "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let result = scan_output(output);
        assert!(result.has_credentials);
        assert!(result.detected_types.contains(&"jwt_token".to_string()));
    }

    #[test]
    fn test_private_key_detection() {
        let output = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...";
        let result = scan_output(output);
        assert!(result.has_credentials);
        assert!(result.detected_types.contains(&"rsa_private_key".to_string()));
    }

    #[test]
    fn test_known_secret_detection() {
        let mut filter = OutputFilter::new();
        filter.add_secret("my-super-secret-api-key-12345".to_string(), Some("prod-api".to_string()));

        let output = "Using key: my-super-secret-api-key-12345 for API call";
        let result = filter.scan_and_redact(output);

        assert!(result.has_credentials);
        assert!(result.redacted_output.contains("[REDACTED:prod-api]"));
        assert!(!result.redacted_output.contains("my-super-secret-api-key-12345"));
    }

    #[test]
    fn test_clean_output() {
        let output = "Deployment successful! URL: https://myapp.railway.app";
        let result = scan_output(output);
        assert!(!result.has_credentials);
        assert_eq!(result.redacted_output, output);
    }

    #[test]
    fn test_multiple_credentials() {
        let output = "AWS_KEY=AKIAIOSFODNN7EXAMPLE GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = scan_output(output);
        assert!(result.has_credentials);
        assert!(result.detected_types.len() >= 2);
    }

    #[test]
    fn test_stripe_key_detection() {
        // Using sk_test_ prefix which is for test mode, not live
        let output = "STRIPE_SECRET_KEY=sk_test_EXAMPLEKEY1234567890abc";
        let result = scan_output(output);
        assert!(result.has_credentials);
        assert!(result.detected_types.contains(&"stripe_test".to_string()));
    }

    #[test]
    fn test_slack_token_detection() {
        // Using xoxp- prefix (user token) with placeholder pattern
        let output = "SLACK_TOKEN=xoxp-FAKE-FAKE-FAKE-FAKETOKEN123";
        let result = scan_output(output);
        assert!(result.has_credentials);
        assert!(result.detected_types.contains(&"slack_token".to_string()));
    }

    #[test]
    fn test_sendgrid_key_detection() {
        let output = "SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = scan_output(output);
        assert!(result.has_credentials);
        assert!(result.detected_types.contains(&"sendgrid_key".to_string()));
    }

    #[test]
    fn test_bearer_token_detection() {
        let output = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let result = scan_output(output);
        assert!(result.has_credentials);
    }

    #[test]
    fn test_contains_credentials() {
        let filter = OutputFilter::new();

        assert!(filter.contains_credentials("Key: AKIAIOSFODNN7EXAMPLE"));
        assert!(!filter.contains_credentials("Hello, world!"));
    }

    #[test]
    fn test_detect_patterns() {
        let filter = OutputFilter::new();
        // Using sk_test_ prefix which is for test mode
        let output = "AKIAIOSFODNN7EXAMPLE and sk_test_EXAMPLEKEY1234567890abc";
        let patterns = filter.detect_patterns(output);

        assert!(patterns.contains(&"aws_access_key"));
        assert!(patterns.contains(&"stripe_test"));
    }
}
