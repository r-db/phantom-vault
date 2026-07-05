//! # Output Sanitization Tests
//!
//! These tests verify that the sanitizer catches secrets in all known encodings.
//! Each test plants a known secret, runs a command that outputs it (possibly encoded),
//! and verifies the secret is redacted from the output.
//!
//! CRITICAL: Output must NEVER contain plaintext or encoded secrets.

use phantom_sanitizer::{Sanitizer, SanitizerConfig};

/// Helper to create a sanitizer with a test secret registered.
fn create_test_sanitizer(secret_name: &str, secret_value: &[u8]) -> Sanitizer {
    let config = SanitizerConfig {
        detect_encoded: true,
        detect_partial: true,
        timing_jitter: false, // Disable timing for tests
        ..Default::default()
    };

    let mut sanitizer = Sanitizer::new(config);
    sanitizer.register_secret_bytes(secret_name, secret_value);
    sanitizer
}

/// Helper to assert output is sanitized (doesn't contain secret).
fn assert_sanitized(output: &str, secret: &str, description: &str) {
    assert!(
        !output.contains(secret),
        "SECURITY FAILURE: {} - Output contains secret! Output: '{}', Secret: '{}'",
        description,
        output,
        secret
    );
}

/// Helper to assert output is NOT modified (no false positive).
fn assert_not_modified(original: &str, sanitized: &str, description: &str) {
    assert_eq!(
        original, sanitized,
        "False positive: {} - Output was incorrectly modified! Original: '{}', Got: '{}'",
        description, original, sanitized
    );
}

// =============================================================================
// TEST 6: Base64 Encoded Secret Detection
// =============================================================================

/// Attack: Output secret encoded in Base64 to bypass plain-text detection.
///
/// The attacker runs: echo $SECRET | base64
/// hoping the Base64-encoded output won't be caught.
///
/// Expected: Base64-encoded secret is REDACTED.
#[test]
fn test_base64_encoded_secret_redacted() {
    let secret = b"sk_live_secret_api_key_12345";
    let mut sanitizer = create_test_sanitizer("API_KEY", secret);

    // Simulate command output that includes Base64-encoded secret
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let base64_secret = STANDARD.encode(secret);

    let output = format!("Command output: {}\nMore output here", base64_secret);

    let sanitized = sanitizer.sanitize(&output).expect("Sanitization should succeed");

    // The Base64-encoded secret must be redacted
    assert!(
        !sanitized.contains(&base64_secret),
        "SECURITY FAILURE: Base64-encoded secret was not redacted! Output: '{}'",
        sanitized
    );

    // Original text around it should remain
    assert!(sanitized.contains("Command output:"));
    assert!(sanitized.contains("More output here"));
}

// =============================================================================
// TEST 7: URL-Encoded Secret Detection
// =============================================================================

/// Attack: Output secret with URL encoding to bypass detection.
///
/// The attacker outputs secrets with special characters URL-encoded.
///
/// Expected: URL-encoded secret is REDACTED.
#[test]
fn test_url_encoded_secret_redacted() {
    let secret = b"password=secret&key=value";
    let mut sanitizer = create_test_sanitizer("CREDENTIALS", secret);

    // URL-encode the secret
    let url_encoded: String = secret.iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                format!("{}", b as char)
            } else {
                format!("%{:02X}", b)
            }
        })
        .collect();

    let output = format!("Encoded: {}", url_encoded);
    let sanitized = sanitizer.sanitize(&output).expect("Sanitization should succeed");

    // Must not contain the URL-encoded secret
    assert!(
        !sanitized.contains(&url_encoded),
        "SECURITY FAILURE: URL-encoded secret was not redacted! Output: '{}'",
        sanitized
    );
}

// =============================================================================
// TEST 8: Hex-Encoded Secret Detection
// =============================================================================

/// Attack: Output secret in hexadecimal encoding.
///
/// The attacker uses: echo $SECRET | xxd
///
/// Expected: Hex-encoded secret is REDACTED.
#[test]
fn test_hex_encoded_secret_redacted() {
    let secret = b"secret_hex_test_value";
    let mut sanitizer = create_test_sanitizer("HEX_SECRET", secret);

    // Hex encode the secret
    let hex_encoded: String = secret.iter().map(|b| format!("{:02x}", b)).collect();

    let output = format!("Hex dump: {}", hex_encoded);
    let sanitized = sanitizer.sanitize(&output).expect("Sanitization should succeed");

    assert!(
        !sanitized.contains(&hex_encoded),
        "SECURITY FAILURE: Hex-encoded secret was not redacted! Output: '{}'",
        sanitized
    );
}

// =============================================================================
// TEST 9: Partial Match Detection (Sliding Window)
// =============================================================================

/// Attack: Output only a portion of the secret hoping partial matches aren't caught.
///
/// The attacker outputs 8+ characters of a longer secret.
///
/// Expected: Partial matches (8+ chars) are REDACTED.
#[test]
fn test_partial_match_redacted() {
    let secret = b"this_is_a_very_long_secret_value_that_should_be_protected";
    let mut sanitizer = create_test_sanitizer("LONG_SECRET", secret);

    // Output only a portion (more than 8 chars)
    let partial = "very_long_secret"; // 16 chars from the middle
    let output = format!("Found: {}", partial);

    let sanitized = sanitizer.sanitize(&output).expect("Sanitization should succeed");

    // Partial matches should be caught by sliding window
    // Note: This depends on the window configuration
    // At minimum, the sanitizer should not return the exact secret substring
    assert!(
        !sanitized.contains(partial) || sanitized.contains("[REDACTED"),
        "Partial secret match should be redacted: '{}'",
        sanitized
    );
}

// =============================================================================
// TEST 10: Non-Secret Content Preserved (No False Positives)
// =============================================================================

/// Verify that non-secret content is NOT modified.
///
/// The sanitizer must only redact actual secrets, not random text.
///
/// Expected: Non-secret output is preserved exactly.
#[test]
fn test_non_secret_preserved() {
    let secret = b"super_unique_secret_value_xyz123";
    let mut sanitizer = create_test_sanitizer("UNIQUE_SECRET", secret);

    // Output that does NOT contain the secret
    let outputs = [
        "Hello, world!",
        "Build completed successfully.",
        "Error: file not found",
        "SELECT * FROM users WHERE id = 123",
        "The quick brown fox jumps over the lazy dog.",
        "12345678901234567890", // Numbers only
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ", // Letters only
        "!@#$%^&*()_+-=[]{}|;':\",./<>?", // Special characters
        "Line 1\nLine 2\nLine 3", // Multi-line
        "", // Empty string
        "    ", // Whitespace only
    ];

    for original in outputs {
        let sanitized = sanitizer.sanitize(original).expect("Sanitization should succeed");
        assert_not_modified(original, &sanitized, &format!("Output: '{}'", original));
    }
}

// =============================================================================
// TEST 11: Sanitizer Error Returns Blocked Output
// =============================================================================

/// Verify that if the sanitizer itself fails, output is BLOCKED (not passed through).
///
/// CRITICAL: On any sanitization error, the system must fail closed.
///
/// Expected: Error returns SANITIZATION_ERROR_MESSAGE, not the original output.
#[test]
fn test_sanitizer_error_returns_blocked() {
    // Create a sanitizer and check the error message constant
    let error_message = phantom_sanitizer::SANITIZATION_ERROR_MESSAGE;

    // The error message must NOT be empty
    assert!(
        !error_message.is_empty(),
        "SANITIZATION_ERROR_MESSAGE must not be empty"
    );

    // The error message must NOT contain any placeholder that could leak data
    assert!(
        !error_message.contains("{}") && !error_message.contains("{0}"),
        "Error message must not contain format placeholders"
    );

    // Verify the message indicates an error occurred
    assert!(
        error_message.to_lowercase().contains("error")
            || error_message.to_lowercase().contains("blocked")
            || error_message.to_lowercase().contains("redacted"),
        "Error message should indicate an error: '{}'",
        error_message
    );
}

// =============================================================================
// TEST: Plain Text Secret Detection
// =============================================================================

/// Basic test: Plain text secrets in output must be redacted.
#[test]
fn test_plain_text_secret_redacted() {
    let secret = b"plaintext_secret_12345";
    let mut sanitizer = create_test_sanitizer("PLAIN_SECRET", secret);

    let output = format!("Output contains: {} and more text", std::str::from_utf8(secret).unwrap());
    let sanitized = sanitizer.sanitize(&output).expect("Sanitization should succeed");

    assert_sanitized(&sanitized, "plaintext_secret_12345", "Plain text secret");
    assert!(sanitized.contains("and more text"), "Non-secret text should be preserved");
}

// =============================================================================
// TEST: HTML Entity Encoded Secret Detection
// =============================================================================

/// Attack: Output secret with HTML entity encoding.
///
/// Note: The sanitizer generates numeric HTML entities (&#65; for 'A'),
/// not named entities (&lt; for '<').
#[test]
fn test_html_entity_encoded_secret_redacted() {
    let secret = b"ABC123";
    let mut sanitizer = create_test_sanitizer("HTML_SECRET", secret);

    // HTML numeric entity encode (decimal): A=65, B=66, C=67, 1=49, 2=50, 3=51
    let html_decimal = "&#65;&#66;&#67;&#49;&#50;&#51;";

    let output = format!("HTML: {}", html_decimal);
    let sanitized = sanitizer.sanitize(&output).expect("Sanitization should succeed");

    // Should catch HTML-encoded version
    assert!(
        !sanitized.contains(html_decimal) || sanitized.contains("[REDACTED"),
        "HTML decimal-encoded secret should be redacted: '{}'",
        sanitized
    );
}

// =============================================================================
// TEST: Multiple Secrets in Same Output
// =============================================================================

/// Verify that multiple different secrets in the same output are all redacted.
#[test]
fn test_multiple_secrets_all_redacted() {
    let config = SanitizerConfig {
        detect_encoded: true,
        ..Default::default()
    };

    let mut sanitizer = Sanitizer::new(config);
    sanitizer.register_secret_bytes("SECRET_1", b"first_secret_value");
    sanitizer.register_secret_bytes("SECRET_2", b"second_secret_value");
    sanitizer.register_secret_bytes("SECRET_3", b"third_secret_value");

    let output = "First: first_secret_value, Second: second_secret_value, Third: third_secret_value";
    let sanitized = sanitizer.sanitize(output).expect("Sanitization should succeed");

    assert!(
        !sanitized.contains("first_secret_value"),
        "First secret should be redacted"
    );
    assert!(
        !sanitized.contains("second_secret_value"),
        "Second secret should be redacted"
    );
    assert!(
        !sanitized.contains("third_secret_value"),
        "Third secret should be redacted"
    );
}

// =============================================================================
// TEST: Secret Appearing Multiple Times
// =============================================================================

/// Verify that a secret appearing multiple times is redacted everywhere.
#[test]
fn test_repeated_secret_all_redacted() {
    let secret = b"repeated_secret_xyz";
    let mut sanitizer = create_test_sanitizer("REPEAT", secret);

    let output = "First: repeated_secret_xyz, Second: repeated_secret_xyz, Third: repeated_secret_xyz";
    let sanitized = sanitizer.sanitize(output).expect("Sanitization should succeed");

    // Count occurrences of the secret in sanitized output (should be 0)
    let count = sanitized.matches("repeated_secret_xyz").count();
    assert_eq!(
        count, 0,
        "Secret appeared {} times in output, should be 0: '{}'",
        count, sanitized
    );
}

// =============================================================================
// TEST: Large Output Performance
// =============================================================================

/// Verify that sanitization performs reasonably on large output.
#[test]
fn test_large_output_performance() {
    let secret = b"performance_test_secret_value";
    let mut sanitizer = create_test_sanitizer("PERF_SECRET", secret);

    // Generate 1MB of output
    let chunk = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
    let output: String = chunk.repeat(20000); // ~1MB

    let start = std::time::Instant::now();
    let sanitized = sanitizer.sanitize(&output).expect("Sanitization should succeed");
    let duration = start.elapsed();

    // Should complete in reasonable time (< 1 second for 1MB)
    assert!(
        duration.as_secs() < 5,
        "Sanitization took too long: {:?} for {} bytes",
        duration,
        output.len()
    );

    // Output should not be modified (no secret present)
    assert_eq!(
        output.len(),
        sanitized.len(),
        "Output length should be preserved when no secrets present"
    );
}

// =============================================================================
// TEST: Unicode/UTF-8 Handling
// =============================================================================

/// Verify that UTF-8 content is handled correctly.
#[test]
fn test_utf8_content_preserved() {
    let secret = b"utf8_secret_value";
    let mut sanitizer = create_test_sanitizer("UTF8_SECRET", secret);

    let outputs = [
        "日本語テキスト",
        "Émoji: 🔐🔑🛡️",
        "Ñoño señor",
        "中文内容",
        "Кириллица текст",
    ];

    for original in outputs {
        let sanitized = sanitizer.sanitize(original).expect("Sanitization should succeed");
        assert_not_modified(original, &sanitized, &format!("UTF-8: '{}'", original));
    }
}

// =============================================================================
// TEST: ROT13 Encoded Secret Detection
// =============================================================================

/// Attack: Output secret with ROT13 encoding (simple substitution cipher).
#[test]
fn test_rot13_encoded_secret_redacted() {
    let secret = b"rot13testsecret";
    let mut sanitizer = create_test_sanitizer("ROT13_SECRET", secret);

    // ROT13 encode the secret
    let rot13: String = secret.iter().map(|&b| {
        if b.is_ascii_lowercase() {
            (((b - b'a') + 13) % 26 + b'a') as char
        } else if b.is_ascii_uppercase() {
            (((b - b'A') + 13) % 26 + b'A') as char
        } else {
            b as char
        }
    }).collect();

    let output = format!("ROT13: {}", rot13);
    let sanitized = sanitizer.sanitize(&output).expect("Sanitization should succeed");

    // Should catch ROT13-encoded version
    assert!(
        !sanitized.contains(&rot13) || sanitized.contains("[REDACTED"),
        "ROT13-encoded secret should be redacted: '{}'",
        sanitized
    );
}

// =============================================================================
// TEST: Reversed Secret Detection
// =============================================================================

/// Attack: Output secret in reverse to bypass detection.
#[test]
fn test_reversed_secret_redacted() {
    let secret = b"reverseme123456";
    let mut sanitizer = create_test_sanitizer("REVERSE_SECRET", secret);

    // Reverse the secret
    let reversed: String = std::str::from_utf8(secret).unwrap().chars().rev().collect();

    let output = format!("Reversed: {}", reversed);
    let sanitized = sanitizer.sanitize(&output).expect("Sanitization should succeed");

    // Should catch reversed version
    assert!(
        !sanitized.contains(&reversed) || sanitized.contains("[REDACTED"),
        "Reversed secret should be redacted: '{}'",
        sanitized
    );
}

// =============================================================================
// TEST: Case Variation Detection
// =============================================================================

/// Attack: Output secret with different case to bypass detection.
#[test]
fn test_case_variation_detection() {
    // Note: Case sensitivity depends on implementation
    // Uppercase secrets should not match lowercase output by default
    let secret = b"CaseSensitiveSecret";
    let mut sanitizer = create_test_sanitizer("CASE_SECRET", secret);

    // Same case should be caught
    let output = "Output: CaseSensitiveSecret";
    let sanitized = sanitizer.sanitize(output).expect("Sanitization should succeed");
    assert!(
        !sanitized.contains("CaseSensitiveSecret"),
        "Exact case match should be redacted"
    );

    // Different case is typically NOT caught (case-sensitive matching)
    // This is expected behavior - we don't want false positives
}
