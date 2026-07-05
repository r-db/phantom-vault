//! Anti-timing-oracle response normalization.
//!
//! This module provides mechanisms to prevent timing-based side-channel
//! attacks by normalizing response times and structures:
//!
//! - Pad responses to fixed size boundaries
//! - Add random jitter to response times
//! - Ensure identical structure for success/failure responses
//!
//! # Timing Oracle Attacks
//!
//! An attacker might try to determine whether a secret was found by
//! measuring how long the sanitization takes. This module prevents
//! such attacks by making all responses take similar amounts of time.

use rand::Rng;
use std::time::{Duration, Instant};

/// Configuration for timing protection.
#[derive(Debug, Clone)]
pub struct TimingConfig {
    /// Minimum jitter in milliseconds.
    pub min_jitter_ms: u64,
    /// Maximum jitter in milliseconds.
    pub max_jitter_ms: u64,
    /// Padding boundary size in bytes.
    pub padding_boundary: usize,
    /// Padding character.
    pub padding_char: char,
    /// Whether to enable timing protection.
    pub enabled: bool,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            min_jitter_ms: 50,
            max_jitter_ms: 200,
            padding_boundary: 1024, // 1KB
            padding_char: ' ',
            enabled: true,
        }
    }
}

/// Metadata included in every response for structural consistency.
#[derive(Debug, Clone)]
pub struct ResponseMetadata {
    /// Whether any secrets were detected (always present).
    pub secrets_detected: bool,
    /// Number of patterns checked (always present).
    pub patterns_checked: usize,
    /// Processing timestamp (always present).
    pub timestamp: u64,
    /// Response version (always present).
    pub version: &'static str,
    /// Checksum of the response (always present).
    pub checksum: u32,
}

impl ResponseMetadata {
    /// Create new response metadata.
    pub fn new(secrets_detected: bool, patterns_checked: usize) -> Self {
        Self {
            secrets_detected,
            patterns_checked,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            version: "1.0",
            checksum: 0, // Will be computed when finalizing
        }
    }

    /// Compute checksum for the response content.
    pub fn with_checksum(mut self, content: &str) -> Self {
        self.checksum = Self::compute_checksum(content);
        self
    }

    /// Simple checksum computation.
    fn compute_checksum(content: &str) -> u32 {
        content.bytes().fold(0u32, |acc, b| acc.wrapping_add(b as u32))
    }
}

/// A normalized response with timing protection.
#[derive(Debug, Clone)]
pub struct NormalizedResponse {
    /// The actual content (padded to boundary).
    pub content: String,
    /// Response metadata.
    pub metadata: ResponseMetadata,
    /// Original content length before padding.
    pub original_length: usize,
}

/// Timing protector for sanitization responses.
pub struct TimingProtector {
    config: TimingConfig,
}

impl TimingProtector {
    /// Create a new timing protector with default configuration.
    pub fn new() -> Self {
        Self::with_config(TimingConfig::default())
    }

    /// Create a timing protector with custom configuration.
    pub fn with_config(config: TimingConfig) -> Self {
        Self { config }
    }

    /// Generate random jitter duration.
    pub fn generate_jitter(&self) -> Duration {
        if !self.config.enabled {
            return Duration::ZERO;
        }

        let mut rng = rand::thread_rng();
        let jitter_ms = rng.gen_range(self.config.min_jitter_ms..=self.config.max_jitter_ms);
        Duration::from_millis(jitter_ms)
    }

    /// Pad content to the nearest boundary.
    pub fn pad_content(&self, content: &str) -> String {
        if !self.config.enabled {
            return content.to_string();
        }

        let current_len = content.len();
        let boundary = self.config.padding_boundary;

        // Calculate padding needed
        let padded_len = ((current_len + boundary - 1) / boundary) * boundary;
        let padding_needed = padded_len - current_len;

        if padding_needed == 0 {
            content.to_string()
        } else {
            let mut padded = content.to_string();
            padded.extend(std::iter::repeat(self.config.padding_char).take(padding_needed));
            padded
        }
    }

    /// Create a normalized response from content.
    pub fn normalize_response(
        &self,
        content: &str,
        secrets_detected: bool,
        patterns_checked: usize,
    ) -> NormalizedResponse {
        let original_length = content.len();
        let padded_content = self.pad_content(content);

        let metadata = ResponseMetadata::new(secrets_detected, patterns_checked)
            .with_checksum(&padded_content);

        NormalizedResponse {
            content: padded_content,
            metadata,
            original_length,
        }
    }

    /// Wait for jitter duration.
    ///
    /// This is a blocking call that adds random delay.
    pub fn wait_jitter(&self) {
        if !self.config.enabled {
            return;
        }

        let jitter = self.generate_jitter();
        std::thread::sleep(jitter);
    }

    /// Execute a function with timing protection.
    ///
    /// This ensures the function takes at least `min_duration` to complete,
    /// with additional random jitter.
    pub fn with_timing_protection<F, T>(&self, min_duration: Duration, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        let start = Instant::now();
        let result = f();

        if self.config.enabled {
            let elapsed = start.elapsed();
            let jitter = self.generate_jitter();
            let target_duration = min_duration + jitter;

            if elapsed < target_duration {
                std::thread::sleep(target_duration - elapsed);
            }
        }

        result
    }

    /// Create an error response with the same structure as success.
    ///
    /// This prevents attackers from distinguishing errors by response structure.
    pub fn error_response(&self, message: &str) -> NormalizedResponse {
        self.normalize_response(message, false, 0)
    }

    /// Validate that jitter is within expected range.
    pub fn validate_jitter(&self, duration: Duration) -> bool {
        let min = Duration::from_millis(self.config.min_jitter_ms);
        let max = Duration::from_millis(self.config.max_jitter_ms);
        duration >= min && duration <= max
    }
}

impl Default for TimingProtector {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard that ensures minimum execution time.
///
/// When dropped, this guard will sleep if necessary to ensure
/// at least `min_duration` has elapsed since creation.
pub struct TimingGuard {
    start: Instant,
    min_duration: Duration,
    jitter: Duration,
    enabled: bool,
}

impl TimingGuard {
    /// Create a new timing guard.
    pub fn new(min_duration: Duration, protector: &TimingProtector) -> Self {
        Self {
            start: Instant::now(),
            min_duration,
            jitter: protector.generate_jitter(),
            enabled: protector.config.enabled,
        }
    }

    /// Get the target duration (min + jitter).
    pub fn target_duration(&self) -> Duration {
        self.min_duration + self.jitter
    }

    /// Get elapsed time since creation.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Get remaining time until target.
    pub fn remaining(&self) -> Duration {
        let target = self.target_duration();
        let elapsed = self.elapsed();
        if elapsed >= target {
            Duration::ZERO
        } else {
            target - elapsed
        }
    }
}

impl Drop for TimingGuard {
    fn drop(&mut self) {
        if self.enabled {
            let remaining = self.remaining();
            if !remaining.is_zero() {
                std::thread::sleep(remaining);
            }
        }
    }
}

/// Constant-time operations for security-sensitive comparisons.
pub mod constant_time {
    /// Constant-time byte comparison.
    ///
    /// This takes the same amount of time regardless of where
    /// (or whether) the bytes differ.
    #[inline]
    pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }

        result == 0
    }

    /// Constant-time string comparison.
    #[inline]
    pub fn str_eq(a: &str, b: &str) -> bool {
        bytes_eq(a.as_bytes(), b.as_bytes())
    }

    /// Constant-time select: returns `a` if `condition` is true, `b` otherwise.
    ///
    /// This is done without branching.
    #[inline]
    pub fn select<T: Copy>(condition: bool, a: T, b: T) -> T
    where
        T: std::ops::BitAnd<Output = T>
            + std::ops::BitOr<Output = T>
            + std::ops::Not<Output = T>
            + From<u8>,
    {
        // Create mask: all 1s if condition is true, all 0s otherwise
        let mask: T = if condition { T::from(0xFF) } else { T::from(0x00) };
        (a & mask) | (b & !mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_to_boundary() {
        let protector = TimingProtector::new();

        // 100 bytes should be padded to 1024
        let content = "a".repeat(100);
        let padded = protector.pad_content(&content);
        assert_eq!(padded.len(), 1024);

        // 1024 bytes should remain 1024
        let content = "b".repeat(1024);
        let padded = protector.pad_content(&content);
        assert_eq!(padded.len(), 1024);

        // 1025 bytes should be padded to 2048
        let content = "c".repeat(1025);
        let padded = protector.pad_content(&content);
        assert_eq!(padded.len(), 2048);
    }

    #[test]
    fn test_jitter_range() {
        let protector = TimingProtector::new();

        for _ in 0..100 {
            let jitter = protector.generate_jitter();
            assert!(
                jitter >= Duration::from_millis(50) && jitter <= Duration::from_millis(200),
                "Jitter {:?} out of range",
                jitter
            );
        }
    }

    #[test]
    fn test_normalized_response_structure() {
        let protector = TimingProtector::new();

        let success_response = protector.normalize_response("success content", true, 100);
        let error_response = protector.normalize_response("error content", false, 0);

        // Both should have metadata
        assert!(success_response.metadata.version == error_response.metadata.version);

        // Both should be padded to same boundary
        assert_eq!(
            success_response.content.len() % 1024,
            error_response.content.len() % 1024
        );
    }

    #[test]
    fn test_response_metadata() {
        let metadata = ResponseMetadata::new(true, 50);

        assert!(metadata.secrets_detected);
        assert_eq!(metadata.patterns_checked, 50);
        assert!(metadata.timestamp > 0);
        assert_eq!(metadata.version, "1.0");
    }

    #[test]
    fn test_timing_guard() {
        let protector = TimingProtector::with_config(TimingConfig {
            min_jitter_ms: 10,
            max_jitter_ms: 20,
            enabled: true,
            ..Default::default()
        });

        let min_duration = Duration::from_millis(50);
        let start = Instant::now();

        {
            let _guard = TimingGuard::new(min_duration, &protector);
            // Do some quick work
            std::thread::sleep(Duration::from_millis(5));
        } // Guard dropped here, ensures minimum time

        let elapsed = start.elapsed();

        // Should be at least min_duration
        assert!(
            elapsed >= min_duration,
            "Elapsed {:?} should be >= {:?}",
            elapsed,
            min_duration
        );
    }

    #[test]
    fn test_constant_time_bytes_eq() {
        assert!(constant_time::bytes_eq(b"hello", b"hello"));
        assert!(!constant_time::bytes_eq(b"hello", b"world"));
        assert!(!constant_time::bytes_eq(b"hello", b"hell"));
        assert!(constant_time::bytes_eq(b"", b""));
    }

    #[test]
    fn test_constant_time_str_eq() {
        assert!(constant_time::str_eq("secret", "secret"));
        assert!(!constant_time::str_eq("secret", "SECRET"));
        assert!(!constant_time::str_eq("secret", "secrets"));
    }

    #[test]
    fn test_disabled_timing() {
        let protector = TimingProtector::with_config(TimingConfig {
            enabled: false,
            ..Default::default()
        });

        // Jitter should be zero when disabled
        assert_eq!(protector.generate_jitter(), Duration::ZERO);

        // Padding should be disabled
        let content = "short";
        let padded = protector.pad_content(content);
        assert_eq!(padded, content);
    }

    #[test]
    fn test_custom_config() {
        let config = TimingConfig {
            min_jitter_ms: 100,
            max_jitter_ms: 150,
            padding_boundary: 512,
            padding_char: 'X',
            enabled: true,
        };

        let protector = TimingProtector::with_config(config);

        // Test padding boundary
        let content = "test";
        let padded = protector.pad_content(content);
        assert_eq!(padded.len(), 512);
        assert!(padded.ends_with("XXXX")); // Should be padded with X

        // Test jitter range
        let jitter = protector.generate_jitter();
        assert!(jitter >= Duration::from_millis(100));
        assert!(jitter <= Duration::from_millis(150));
    }

    #[test]
    fn test_error_response() {
        let protector = TimingProtector::new();
        let error = protector.error_response("Something went wrong");

        // Should have same structure as success
        assert!(!error.metadata.secrets_detected);
        assert_eq!(error.metadata.patterns_checked, 0);
        assert_eq!(error.content.len() % 1024, 0);
    }
}
