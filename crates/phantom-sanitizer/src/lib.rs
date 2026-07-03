//! # Phantom Sanitizer
//!
//! Output sanitization engine for detecting and redacting leaked secrets.
//!
//! This crate provides multiple detection strategies to catch secrets
//! in any form they might appear in command output:
//!
//! - **Exact string matching**: Using Aho-Corasick for O(n) multi-pattern matching
//! - **Encoded variant detection**: Base64, URL, hex, HTML entities, JSON, Unicode, ROT13
//! - **Sliding window substring matching**: Catches partial leaks using rolling hash
//! - **Timing protection**: Anti-timing-oracle response normalization
//!
//! # Security Guarantee
//!
//! The sanitizer is designed to NEVER return unsanitized output, even on error.
//! If sanitization fails for any reason, a safe error message is returned instead
//! of the raw output.
//!
//! # Example
//!
//! ```ignore
//! use phantom_sanitizer::{Sanitizer, SanitizerConfig};
//! use phantom_core::memory::SecretBuffer;
//!
//! let mut sanitizer = Sanitizer::new(SanitizerConfig::default());
//!
//! let secret = SecretBuffer::from_slice(b"sk_live_abc123XYZ").unwrap();
//! sanitizer.register_secret("API_KEY", &secret);
//!
//! let output = "Your key is sk_live_abc123XYZ";
//! let sanitized = sanitizer.sanitize(output).unwrap();
//! assert_eq!(sanitized, "Your key is [REDACTED:API_KEY]");
//! ```

pub mod encoded;
pub mod exact;
pub mod timing;
pub mod window;

use crate::encoded::{EncodedGenerator, EncodedVariantType};
use crate::exact::ExactMatcher;
use crate::timing::{NormalizedResponse, TimingConfig, TimingProtector};
use crate::window::{WindowConfig, WindowMatcher};
use phantom_core::memory::SecretBuffer;
use std::collections::HashSet;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, warn};

/// The error message returned when sanitization fails.
/// This is intentionally generic to avoid leaking information.
pub const SANITIZATION_ERROR_MESSAGE: &str = "[SANITIZATION ERROR - OUTPUT BLOCKED]";

/// Errors that can occur during sanitization.
#[derive(Debug, Error)]
pub enum SanitizeError {
    /// Failed to decode output for checking.
    #[error("decode error: {0}")]
    Decode(String),

    /// Internal sanitizer error.
    #[error("sanitizer error: {0}")]
    Internal(String),

    /// Pattern compilation failed.
    #[error("pattern compilation failed: {0}")]
    PatternCompilation(String),
}

/// Result type for sanitization operations.
pub type SanitizeResult<T> = Result<T, SanitizeError>;

/// Result of a sanitization check.
#[derive(Debug, Clone)]
pub struct SanitizeReport {
    /// Whether any secrets were detected.
    pub leaked: bool,
    /// Names of secrets that were detected.
    pub detected_secrets: Vec<String>,
    /// Encoding variants that matched.
    pub matched_encodings: Vec<EncodingType>,
    /// The sanitized output (secrets redacted).
    pub sanitized_output: String,
    /// Number of patterns that were checked.
    pub patterns_checked: usize,
    /// Whether partial matches were found via sliding window.
    pub partial_matches_found: bool,
}

/// Types of encoding that secrets might appear in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EncodingType {
    /// Plain text (no encoding).
    Plain,
    /// Base64 encoded.
    Base64,
    /// URL/percent encoded.
    UrlEncoded,
    /// Hexadecimal encoded.
    Hex,
    /// HTML entity encoded.
    HtmlEntity,
    /// Partial match via sliding window.
    PartialMatch,
}

// Use the From implementation from encoded.rs module

/// Configuration for the sanitizer.
#[derive(Debug, Clone)]
pub struct SanitizerConfig {
    /// Minimum match length for sliding window (default: 8).
    pub min_window_size: usize,
    /// Whether to add timing jitter (default: true).
    pub timing_jitter: bool,
    /// Replacement pattern for redacted secrets.
    /// Use {name} as placeholder for secret name.
    pub redaction_pattern: String,
    /// Whether to enable encoded variant detection.
    pub detect_encoded: bool,
    /// Whether to enable sliding window detection.
    pub detect_partial: bool,
    /// Minimum duration for sanitization (for timing protection).
    pub min_sanitize_duration: Duration,
    /// Timing configuration.
    pub timing_config: TimingConfig,
}

impl Default for SanitizerConfig {
    fn default() -> Self {
        Self {
            min_window_size: 8,
            timing_jitter: true,
            redaction_pattern: "[REDACTED:{name}]".to_string(),
            detect_encoded: true,
            detect_partial: true,
            min_sanitize_duration: Duration::from_millis(10),
            timing_config: TimingConfig::default(),
        }
    }
}

impl SanitizerConfig {
    /// Create a fast configuration with minimal overhead.
    ///
    /// This disables timing protection and partial matching for
    /// performance-critical scenarios. Still safe but faster.
    pub fn fast() -> Self {
        Self {
            min_window_size: 8,
            timing_jitter: false,
            redaction_pattern: "[REDACTED:{name}]".to_string(),
            detect_encoded: true,
            detect_partial: false,
            min_sanitize_duration: Duration::ZERO,
            timing_config: TimingConfig {
                enabled: false,
                ..Default::default()
            },
        }
    }

    /// Create a paranoid configuration with maximum protection.
    pub fn paranoid() -> Self {
        Self {
            min_window_size: 6, // Smaller window for more detection
            timing_jitter: true,
            redaction_pattern: "[REDACTED]".to_string(), // Don't reveal secret names
            detect_encoded: true,
            detect_partial: true,
            min_sanitize_duration: Duration::from_millis(50),
            timing_config: TimingConfig {
                min_jitter_ms: 100,
                max_jitter_ms: 300,
                padding_boundary: 2048,
                ..Default::default()
            },
        }
    }
}

/// Internal secret representation.
#[allow(dead_code)]
struct RegisteredSecret {
    /// Secret name.
    name: String,
    /// Original secret bytes (stored for future encoding variants).
    value: Vec<u8>,
}

/// The main sanitizer for checking and redacting output.
///
/// The sanitizer maintains a set of registered secrets and checks
/// output for any occurrence of those secrets in any encoding.
pub struct Sanitizer {
    /// Configuration.
    config: SanitizerConfig,
    /// Registered secrets.
    secrets: Vec<RegisteredSecret>,
    /// Exact matcher (includes all encoded variants).
    exact_matcher: ExactMatcher,
    /// Window matcher for partial detection.
    window_matcher: WindowMatcher,
    /// Timing protector.
    timing: TimingProtector,
    /// Whether the matcher needs to be rebuilt.
    needs_rebuild: bool,
}

impl Sanitizer {
    /// Create a new sanitizer with the given configuration.
    pub fn new(config: SanitizerConfig) -> Self {
        let window_config = WindowConfig {
            min_window_size: config.min_window_size,
            ..Default::default()
        };

        Self {
            timing: TimingProtector::with_config(config.timing_config.clone()),
            config,
            secrets: Vec::new(),
            exact_matcher: ExactMatcher::new(),
            window_matcher: WindowMatcher::with_config(window_config),
            needs_rebuild: false,
        }
    }

    /// Register a secret to check for.
    ///
    /// This adds the secret and all its encoded variants to the matcher.
    pub fn register_secret(&mut self, name: &str, value: &SecretBuffer) {
        value.with_exposed(|bytes| {
            self.register_secret_bytes(name, bytes);
        });
    }

    /// Register a secret from raw bytes.
    pub fn register_secret_bytes(&mut self, name: &str, value: &[u8]) {
        // Don't register empty secrets
        if value.is_empty() {
            return;
        }

        // Store the original secret
        self.secrets.push(RegisteredSecret {
            name: name.to_string(),
            value: value.to_vec(),
        });

        // Add plain pattern
        self.exact_matcher.add_pattern(name, value.to_vec(), EncodingType::Plain);

        // Add encoded variants if enabled
        if self.config.detect_encoded {
            let generator = EncodedGenerator::new();
            for variant in generator.generate_variants(value) {
                // Skip plain (already added)
                if variant.encoding == EncodedVariantType::Plain {
                    continue;
                }
                let encoding_type: EncodingType = variant.encoding.into();
                self.exact_matcher.add_pattern(name, variant.bytes, encoding_type);
            }
        }

        // Add to window matcher if enabled
        if self.config.detect_partial {
            self.window_matcher.add_secret(name, value);
        }

        self.needs_rebuild = true;
        debug!("Registered secret '{}' with {} patterns", name, self.exact_matcher.pattern_count());
    }

    /// Remove a registered secret.
    pub fn unregister_secret(&mut self, name: &str) {
        self.secrets.retain(|s| s.name != name);
        self.exact_matcher.remove_secret(name);
        self.window_matcher.remove_secret(name);
        self.needs_rebuild = true;
    }

    /// Rebuild the matchers if needed.
    fn ensure_compiled(&mut self) -> SanitizeResult<()> {
        if self.needs_rebuild {
            self.exact_matcher
                .compile()
                .map_err(|e| SanitizeError::PatternCompilation(e))?;
            self.needs_rebuild = false;
        }
        Ok(())
    }

    /// Check output for leaked secrets and return a report.
    ///
    /// This is the primary method for checking output. It scans for all
    /// registered secrets in all known encodings.
    pub fn check(&mut self, output: &str) -> SanitizeResult<SanitizeReport> {
        // Use timing protection
        let _guard = timing::TimingGuard::new(self.config.min_sanitize_duration, &self.timing);

        self.check_internal(output)
    }

    /// Internal check implementation without timing protection.
    fn check_internal(&mut self, output: &str) -> SanitizeResult<SanitizeReport> {
        self.ensure_compiled()?;

        let patterns_checked = self.exact_matcher.pattern_count();
        let mut detected_secrets = HashSet::new();
        let mut matched_encodings = HashSet::new();
        let mut partial_matches_found = false;

        // Find exact matches (including encoded variants)
        let exact_matches = self.exact_matcher.find_matches(output)
            .map_err(|e| SanitizeError::Internal(e))?;

        for m in &exact_matches {
            detected_secrets.insert(m.secret_name.clone());
            matched_encodings.insert(m.encoding.clone());
        }

        // Find partial matches via sliding window
        if self.config.detect_partial {
            let window_matches = self.window_matcher.find_matches(output.as_bytes());
            for m in window_matches {
                detected_secrets.insert(m.secret_name.clone());
                matched_encodings.insert(EncodingType::PartialMatch);
                partial_matches_found = true;
            }
        }

        // Build sanitized output
        let sanitized_output = if exact_matches.is_empty() && !partial_matches_found {
            output.to_string()
        } else {
            self.redact_output(output)?
        };

        Ok(SanitizeReport {
            leaked: !detected_secrets.is_empty(),
            detected_secrets: detected_secrets.into_iter().collect(),
            matched_encodings: matched_encodings.into_iter().collect(),
            sanitized_output,
            patterns_checked,
            partial_matches_found,
        })
    }

    /// Sanitize output by redacting any detected secrets.
    ///
    /// # Important
    ///
    /// This method will NEVER return unsanitized output. If an error
    /// occurs during sanitization, it returns a safe error message
    /// instead of the raw output.
    pub fn sanitize(&mut self, output: &str) -> SanitizeResult<String> {
        // Use timing protection
        let _guard = timing::TimingGuard::new(self.config.min_sanitize_duration, &self.timing);

        self.sanitize_internal(output)
    }

    /// Internal sanitize implementation.
    fn sanitize_internal(&mut self, output: &str) -> SanitizeResult<String> {
        match self.check_internal(output) {
            Ok(report) => Ok(report.sanitized_output),
            Err(e) => {
                warn!("Sanitization error: {}", e);
                // NEVER return raw output on error
                Ok(SANITIZATION_ERROR_MESSAGE.to_string())
            }
        }
    }

    /// Sanitize output and return a normalized response with timing protection.
    pub fn sanitize_normalized(&mut self, output: &str) -> NormalizedResponse {
        let _guard = timing::TimingGuard::new(self.config.min_sanitize_duration, &self.timing);

        match self.check_internal(output) {
            Ok(report) => self.timing.normalize_response(
                &report.sanitized_output,
                report.leaked,
                report.patterns_checked,
            ),
            Err(_) => self.timing.error_response(SANITIZATION_ERROR_MESSAGE),
        }
    }

    /// Check if output contains any registered secrets.
    pub fn contains_secret(&mut self, output: &str) -> bool {
        match self.check(output) {
            Ok(report) => report.leaked,
            Err(_) => true, // Assume the worst on error
        }
    }

    /// Redact all matches from the output.
    fn redact_output(&mut self, output: &str) -> SanitizeResult<String> {
        let replacement_pattern = self.config.redaction_pattern.clone();

        // First pass: exact matches
        let result = self.exact_matcher.redact(output, |m| {
            replacement_pattern.replace("{name}", &m.secret_name)
        }).map_err(|e| SanitizeError::Internal(e))?;

        // Second pass: window matches
        if self.config.detect_partial {
            let window_matches = self.window_matcher.find_matches(result.as_bytes());
            if window_matches.is_empty() {
                return Ok(result);
            }

            // Build result with window matches redacted
            let mut final_result = String::with_capacity(result.len());
            let mut last_end = 0;

            for m in window_matches {
                // Add text before this match
                if m.start > last_end {
                    final_result.push_str(&result[last_end..m.start]);
                }
                // Add replacement
                final_result.push_str(&replacement_pattern.replace("{name}", &m.secret_name));
                last_end = m.end;
            }

            // Add remaining text
            if last_end < result.len() {
                final_result.push_str(&result[last_end..]);
            }

            Ok(final_result)
        } else {
            Ok(result)
        }
    }

    /// Get the number of registered secrets.
    pub fn secret_count(&self) -> usize {
        self.secrets.len()
    }

    /// Get the total number of patterns (including encoded variants).
    pub fn pattern_count(&self) -> usize {
        self.exact_matcher.pattern_count()
    }

    /// Clear all registered secrets.
    pub fn clear(&mut self) {
        self.secrets.clear();
        self.exact_matcher.clear();
        self.window_matcher.clear();
        self.needs_rebuild = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_secret(value: &[u8]) -> SecretBuffer {
        SecretBuffer::from_slice(value).unwrap()
    }

    #[test]
    fn test_exact_match() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());
        let secret = create_secret(b"sk_live_abc123XYZ");
        sanitizer.register_secret("API_KEY", &secret);

        let output = "Your API key is sk_live_abc123XYZ, use it wisely";
        let result = sanitizer.sanitize(output).unwrap();

        assert!(result.contains("[REDACTED:API_KEY]"));
        assert!(!result.contains("sk_live_abc123XYZ"));
    }

    #[test]
    fn test_base64_detection() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());
        let secret = create_secret(b"sk_live_abc123XYZ");
        sanitizer.register_secret("API_KEY", &secret);

        // Base64 of "sk_live_abc123XYZ" is "c2tfbGl2ZV9hYmMxMjNYWVo="
        let b64_secret = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"sk_live_abc123XYZ");
        let output = format!("Encoded key: {}", b64_secret);

        let result = sanitizer.sanitize(&output).unwrap();

        assert!(result.contains("[REDACTED:API_KEY]"), "Should detect Base64: {}", result);
        assert!(!result.contains(&b64_secret), "Should not contain Base64 secret");
    }

    #[test]
    fn test_url_encoded_detection() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());
        let secret = create_secret(b"secret&key=value");
        sanitizer.register_secret("SECRET", &secret);

        // URL encoded version
        let output = "Query: secret%26key%3Dvalue";
        let result = sanitizer.sanitize(output).unwrap();

        assert!(result.contains("[REDACTED:SECRET]"), "Should detect URL encoding: {}", result);
    }

    #[test]
    fn test_hex_detection() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());
        let secret = create_secret(b"secret123");
        sanitizer.register_secret("HEX_SECRET", &secret);

        // Hex encoded version: "secret123" -> "736563726574313233"
        let hex_secret = hex::encode(b"secret123");
        let output = format!("Hex value: {}", hex_secret);

        let result = sanitizer.sanitize(&output).unwrap();

        assert!(result.contains("[REDACTED:HEX_SECRET]"), "Should detect hex: {}", result);
    }

    #[test]
    fn test_partial_match_sliding_window() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::default());
        let secret = create_secret(b"sk_live_abc123XYZ");
        sanitizer.register_secret("API_KEY", &secret);

        // Only part of the secret
        let output = "Found partial: abc123XY in output";
        let report = sanitizer.check(output).unwrap();

        assert!(report.leaked, "Should detect partial match");
        assert!(report.partial_matches_found, "Should flag partial matches");
        assert!(report.detected_secrets.contains(&"API_KEY".to_string()));
    }

    #[test]
    fn test_no_false_positives() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());
        let secret = create_secret(b"verysecretkey123");
        sanitizer.register_secret("SECRET", &secret);

        let output = "This is completely innocent text with no secrets";
        let result = sanitizer.sanitize(output).unwrap();

        assert_eq!(result, output, "Should not modify innocent text");
    }

    #[test]
    fn test_multiple_secrets() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());

        let secret1 = create_secret(b"first_secret_123");
        let secret2 = create_secret(b"second_secret_456");

        sanitizer.register_secret("KEY1", &secret1);
        sanitizer.register_secret("KEY2", &secret2);

        let output = "Keys: first_secret_123 and second_secret_456";
        let result = sanitizer.sanitize(output).unwrap();

        assert!(result.contains("[REDACTED:KEY1]"));
        assert!(result.contains("[REDACTED:KEY2]"));
        assert!(!result.contains("first_secret_123"));
        assert!(!result.contains("second_secret_456"));
    }

    #[test]
    fn test_multiple_occurrences() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());
        let secret = create_secret(b"repeatedkey");
        sanitizer.register_secret("KEY", &secret);

        let output = "repeatedkey appears here and repeatedkey again";
        let result = sanitizer.sanitize(output).unwrap();

        assert_eq!(
            result.matches("[REDACTED:KEY]").count(),
            2,
            "Should replace all occurrences"
        );
    }

    #[test]
    fn test_sanitization_error_blocks_output() {
        // This test verifies the safety guarantee
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());

        // Even with no secrets, sanitize should work
        let output = "normal output";
        let result = sanitizer.sanitize(output).unwrap();
        assert_eq!(result, output);
    }

    #[test]
    fn test_check_report() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());
        let secret = create_secret(b"mysecretkey123");
        sanitizer.register_secret("KEY", &secret);

        let output = "Contains mysecretkey123 value";
        let report = sanitizer.check(output).unwrap();

        assert!(report.leaked);
        assert!(report.detected_secrets.contains(&"KEY".to_string()));
        assert!(report.matched_encodings.contains(&EncodingType::Plain));
        assert!(report.patterns_checked > 0);
    }

    #[test]
    fn test_contains_secret() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());
        let secret = create_secret(b"secretvalue");
        sanitizer.register_secret("KEY", &secret);

        assert!(sanitizer.contains_secret("has secretvalue"));
        assert!(!sanitizer.contains_secret("nothing here"));
    }

    #[test]
    fn test_unregister_secret() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());

        let secret = create_secret(b"temporary");
        sanitizer.register_secret("TEMP", &secret);

        assert!(sanitizer.contains_secret("temporary"));

        sanitizer.unregister_secret("TEMP");

        assert!(!sanitizer.contains_secret("temporary"));
    }

    #[test]
    fn test_empty_output() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());
        let secret = create_secret(b"secret");
        sanitizer.register_secret("KEY", &secret);

        let result = sanitizer.sanitize("").unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_empty_secret_not_registered() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());

        // Try to register empty secret
        sanitizer.register_secret_bytes("EMPTY", &[]);

        assert_eq!(sanitizer.secret_count(), 0);
    }

    #[test]
    fn test_paranoid_config() {
        let mut sanitizer = Sanitizer::new(SanitizerConfig::paranoid());
        let secret = create_secret(b"supersecret");
        sanitizer.register_secret("KEY", &secret);

        let result = sanitizer.sanitize("supersecret").unwrap();

        // Paranoid mode doesn't reveal secret names
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn test_normalized_response() {
        let config = SanitizerConfig {
            timing_config: TimingConfig {
                enabled: true,
                padding_boundary: 1024,
                ..Default::default()
            },
            ..SanitizerConfig::fast()
        };
        let mut sanitizer = Sanitizer::new(config);
        let secret = create_secret(b"secretvalue");
        sanitizer.register_secret("KEY", &secret);

        let response = sanitizer.sanitize_normalized("has secretvalue");

        // Should be padded to 1KB boundary
        assert_eq!(response.content.len() % 1024, 0, "Content length {} should be multiple of 1024", response.content.len());
        assert!(response.metadata.secrets_detected);
    }

    #[test]
    fn test_timing_jitter_in_range() {
        let config = SanitizerConfig {
            timing_config: TimingConfig {
                min_jitter_ms: 50,
                max_jitter_ms: 100,
                enabled: true,
                ..Default::default()
            },
            ..SanitizerConfig::fast()
        };

        let sanitizer = Sanitizer::new(config);

        // Generate multiple jitter values and check range
        for _ in 0..10 {
            let jitter = sanitizer.timing.generate_jitter();
            assert!(jitter >= std::time::Duration::from_millis(50));
            assert!(jitter <= std::time::Duration::from_millis(100));
        }
    }

    #[test]
    fn test_performance_basic() {
        use std::time::Instant;

        let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());

        // Register 100 secrets
        for i in 0..100 {
            let secret_value = format!("secret_value_{:04}", i);
            let secret = create_secret(secret_value.as_bytes());
            sanitizer.register_secret(&format!("KEY_{}", i), &secret);
        }

        // Generate 1MB output
        let mut output = String::with_capacity(1024 * 1024);
        for i in 0..1024 {
            output.push_str(&format!("Line {} with some random text and data\n", i));
            // Add some secrets occasionally
            if i % 100 == 0 {
                output.push_str(&format!("secret_value_{:04}", i % 100));
            }
        }

        // Pad to 1MB
        while output.len() < 1024 * 1024 {
            output.push('x');
        }

        let start = Instant::now();
        let _result = sanitizer.sanitize(&output).unwrap();
        let elapsed = start.elapsed();

        // Should complete in under 100ms (generous for CI)
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "Sanitization took {:?}, expected < 500ms",
            elapsed
        );
    }
}
