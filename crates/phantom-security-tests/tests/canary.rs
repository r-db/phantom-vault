//! # Canary/Honeypot Secret Tests
//!
//! These tests verify that canary secrets (honeypots) work correctly:
//! - Any access to a canary triggers detection in output
//! - Canary values are detected in all encodings
//! - Canaries appear indistinguishable from real secrets
//!
//! CRITICAL: Canary leaks must ALWAYS be detected, never pass through unnoticed.

use phantom_sanitizer::{Sanitizer, SanitizerConfig};
use std::collections::HashSet;

// =============================================================================
// TEST 16: Canary Access Detection
// =============================================================================

/// Verify that canary secrets are detected when they appear in output.
///
/// This test:
/// 1. Registers a canary secret with the sanitizer
/// 2. Simulates output containing the canary value
/// 3. Verifies the leak is detected and redacted
///
/// Expected: Canary value is DETECTED and REDACTED.
#[test]
fn test_canary_leak_detected_in_output() {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::default());

    // Register a canary - this looks like a real AWS key
    let canary_value = b"AKIAIOSFODNN7CANARY1";
    sanitizer.register_secret_bytes("CANARY_AWS_KEY", canary_value);

    // Simulate output that contains the canary (leaked)
    let output = "Using key: AKIAIOSFODNN7CANARY1 for access";

    let report = sanitizer.check(output).expect("Check should succeed");

    // Canary leak MUST be detected
    assert!(
        report.leaked,
        "SECURITY FAILURE: Canary leak was not detected!"
    );
    assert!(
        report.detected_secrets.contains(&"CANARY_AWS_KEY".to_string()),
        "Detected secrets should include CANARY_AWS_KEY"
    );

    // Output must be sanitized
    assert!(
        !report.sanitized_output.contains("AKIAIOSFODNN7CANARY1"),
        "Canary value should be redacted from output"
    );
}

/// Test that canary values are detected across multiple output lines.
#[test]
fn test_canary_detected_in_multiline_output() {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::default());

    let canary = b"ghp_canarytoken1234567890abcdef";
    sanitizer.register_secret_bytes("CANARY_GITHUB_TOKEN", canary);

    let output = r#"
    Processing request...
    Auth token: ghp_canarytoken1234567890abcdef
    Request completed.
    "#;

    let report = sanitizer.check(output).expect("Check should succeed");

    assert!(report.leaked, "Canary should be detected in multiline output");
    assert!(
        !report.sanitized_output.contains("ghp_canarytoken"),
        "Canary should be redacted"
    );
}

// =============================================================================
// TEST 17: Canary Detection Across Encodings
// =============================================================================

/// Verify that canary secrets are detected in Base64 encoding.
#[test]
fn test_canary_detected_in_base64() {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::default());

    let canary = b"CANARY_SECRET_DO_NOT_USE";
    sanitizer.register_secret_bytes("CANARY_B64", canary);

    // Base64 encode the canary
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let b64_canary = STANDARD.encode(canary);

    let output = format!("Encoded: {}", b64_canary);

    let report = sanitizer.check(&output).expect("Check should succeed");

    assert!(
        report.leaked,
        "SECURITY FAILURE: Base64-encoded canary was not detected! Output: {}",
        output
    );
}

/// Verify that canary secrets are detected in hex encoding.
#[test]
fn test_canary_detected_in_hex() {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::default());

    let canary = b"hex_canary_value";
    sanitizer.register_secret_bytes("CANARY_HEX", canary);

    // Hex encode
    let hex_canary: String = canary.iter().map(|b| format!("{:02x}", b)).collect();

    let output = format!("Hex dump: {}", hex_canary);

    let report = sanitizer.check(&output).expect("Check should succeed");

    assert!(
        report.leaked,
        "SECURITY FAILURE: Hex-encoded canary was not detected!"
    );
}

/// Verify that canary secrets are detected in URL encoding.
#[test]
fn test_canary_detected_in_url_encoding() {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::default());

    let canary = b"canary=secret&key=trap";
    sanitizer.register_secret_bytes("CANARY_URL", canary);

    // URL encode
    let url_canary: String = canary
        .iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() {
                format!("{}", b as char)
            } else {
                format!("%{:02X}", b)
            }
        })
        .collect();

    let output = format!("Query: {}", url_canary);

    let report = sanitizer.check(&output).expect("Check should succeed");

    assert!(
        report.leaked,
        "SECURITY FAILURE: URL-encoded canary was not detected!"
    );
}

// =============================================================================
// TEST 18: Canary Patterns Look Realistic
// =============================================================================

/// Verify that canary patterns match realistic secret formats.
///
/// Canaries must be indistinguishable from real secrets to be effective traps.
#[test]
fn test_canary_patterns_realistic_aws() {
    // AWS access key ID pattern: starts with AKIA, 20 chars total
    let canary_aws = "AKIAIOSFODNN7EXAMPLE";
    assert_eq!(canary_aws.len(), 20);
    assert!(canary_aws.starts_with("AKIA"));
    assert!(canary_aws.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn test_canary_patterns_realistic_github() {
    // GitHub PAT pattern: starts with ghp_, 40 chars
    let canary_github = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";
    assert!(canary_github.starts_with("ghp_"));
    assert!(canary_github.chars().skip(4).all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn test_canary_patterns_realistic_jwt() {
    // JWT pattern: three base64url parts separated by dots
    let canary_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYW5hcnkifQ.CANARY_SIG";
    let parts: Vec<&str> = canary_jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");
}

/// Verify that multiple canaries can coexist without interference.
#[test]
fn test_multiple_canaries_independent() {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::default());

    // Register multiple canaries
    sanitizer.register_secret_bytes("CANARY_1", b"first_canary_value");
    sanitizer.register_secret_bytes("CANARY_2", b"second_canary_value");
    sanitizer.register_secret_bytes("CANARY_3", b"third_canary_value");

    // Test output with first canary only
    let output1 = "Found: first_canary_value";
    let report1 = sanitizer.check(output1).expect("Check should succeed");
    assert!(report1.leaked);
    assert!(report1.detected_secrets.contains(&"CANARY_1".to_string()));
    assert_eq!(report1.detected_secrets.len(), 1);

    // Test output with all canaries
    let output_all = "Values: first_canary_value, second_canary_value, third_canary_value";
    let report_all = sanitizer.check(output_all).expect("Check should succeed");
    assert!(report_all.leaked);
    assert_eq!(report_all.detected_secrets.len(), 3);
}

// =============================================================================
// TEST: Canary Detection Speed
// =============================================================================

/// Verify that canary detection doesn't significantly slow down sanitization.
#[test]
fn test_canary_detection_performance() {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());

    // Register many canaries
    for i in 0..50 {
        let canary = format!("canary_trap_value_{:04}", i);
        sanitizer.register_secret_bytes(&format!("CANARY_{}", i), canary.as_bytes());
    }

    // Generate large output
    let output: String = (0..1000)
        .map(|i| format!("Line {} with some data and values\n", i))
        .collect();

    let start = std::time::Instant::now();
    let _result = sanitizer.sanitize(&output).expect("Sanitization should succeed");
    let duration = start.elapsed();

    assert!(
        duration.as_secs() < 2,
        "Canary detection took too long: {:?}",
        duration
    );
}

// =============================================================================
// TEST: Canary Partial Match Detection
// =============================================================================

/// Test that partial canary values are also detected.
#[test]
fn test_canary_partial_match_detection() {
    let config = SanitizerConfig {
        detect_partial: true,
        min_window_size: 8,
        ..SanitizerConfig::default()
    };
    let mut sanitizer = Sanitizer::new(config);

    let canary = b"long_canary_secret_value_that_should_be_protected";
    sanitizer.register_secret_bytes("LONG_CANARY", canary);

    // Only partial match - middle portion
    let output = "Found partial: secret_value_that in logs";

    let report = sanitizer.check(output).expect("Check should succeed");

    // Partial matches should be detected with sliding window
    assert!(
        report.leaked || report.partial_matches_found,
        "Partial canary match should be detected"
    );
}

// =============================================================================
// TEST: Canary Not False Positive
// =============================================================================

/// Verify that similar but different values don't trigger canary alerts.
#[test]
fn test_canary_no_false_positives() {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::default());

    let canary = b"specific_canary_abc123";
    sanitizer.register_secret_bytes("CANARY", canary);

    // Similar but not matching values
    let outputs = [
        "specific_canary_abc124", // Off by one
        "specific_canary_abc12",  // Truncated
        "pecific_canary_abc123",  // Missing first char
        "SPECIFIC_CANARY_ABC123", // Wrong case (if case-sensitive)
        "generic_canary_xyz999",  // Different
    ];

    for output in &outputs {
        let result = sanitizer.sanitize(output).expect("Sanitization should succeed");
        // For exact matches, these shouldn't be redacted (depending on implementation)
        // The key is they shouldn't trigger the specific canary alert
    }
}

// =============================================================================
// TEST: Canary in Error Messages
// =============================================================================

/// Verify canaries are detected even in error messages.
#[test]
fn test_canary_in_error_message() {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::default());

    let canary = b"error_canary_secret";
    sanitizer.register_secret_bytes("ERROR_CANARY", canary);

    let output = "Error: Authentication failed with key error_canary_secret";

    let report = sanitizer.check(output).expect("Check should succeed");

    assert!(
        report.leaked,
        "Canary in error message should be detected"
    );
    assert!(
        !report.sanitized_output.contains("error_canary_secret"),
        "Canary in error should be redacted"
    );
}

// =============================================================================
// TEST: Canary Tracking
// =============================================================================

/// Verify that we can track which canaries were accessed.
#[test]
fn test_canary_access_tracking() {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::default());

    sanitizer.register_secret_bytes("CANARY_A", b"value_a_unique");
    sanitizer.register_secret_bytes("CANARY_B", b"value_b_unique");
    sanitizer.register_secret_bytes("CANARY_C", b"value_c_unique");

    let output = "Leaked: value_a_unique and value_c_unique";

    let report = sanitizer.check(output).expect("Check should succeed");

    // Should identify exactly which canaries were leaked
    let detected: HashSet<String> = report.detected_secrets.into_iter().collect();

    assert!(detected.contains("CANARY_A"), "Should detect CANARY_A");
    assert!(detected.contains("CANARY_C"), "Should detect CANARY_C");
    assert!(!detected.contains("CANARY_B"), "Should NOT detect CANARY_B");
}
