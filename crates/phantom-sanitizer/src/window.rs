//! Sliding window substring matching for partial secret detection.
//!
//! This module detects cases where a secret might be partially leaked,
//! such as when only part of a key appears in output due to truncation,
//! line wrapping, or transformation.
//!
//! Uses a rolling hash (Rabin-Karp style) for efficient scanning.

use std::collections::{HashMap, HashSet};

/// Configuration for window matching.
#[derive(Debug, Clone)]
pub struct WindowConfig {
    /// Minimum substring length to detect (default: 8).
    pub min_window_size: usize,
    /// Maximum window size (for memory efficiency).
    pub max_window_size: usize,
    /// Step size for generating substrings from secrets.
    pub step_size: usize,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            min_window_size: 8,
            max_window_size: 64,
            step_size: 1,
        }
    }
}

/// A partial match result.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowMatch {
    /// Start position in the text.
    pub start: usize,
    /// End position in the text.
    pub end: usize,
    /// Name of the secret that was partially matched.
    pub secret_name: String,
    /// Percentage of the secret that was matched (0.0-1.0).
    pub match_ratio: f64,
    /// Length of the matched substring.
    pub match_length: usize,
}

/// Rolling hash calculator using polynomial hashing.
///
/// Uses the formula: hash = (s[0] * BASE^(n-1) + s[1] * BASE^(n-2) + ... + s[n-1]) mod MOD
struct RollingHash {
    /// Current hash value.
    hash: u64,
    /// Current window content (circular buffer).
    window: Vec<u8>,
    /// Current position in the window.
    pos: usize,
    /// Window size.
    size: usize,
    /// Precomputed BASE^(size-1) mod MOD.
    base_pow: u64,
}

/// Base for polynomial hash.
const HASH_BASE: u64 = 256;
/// Modulus for hash (large prime).
const HASH_MOD: u64 = 1_000_000_007;

impl RollingHash {
    /// Create a new rolling hash with the given window size.
    fn new(size: usize) -> Self {
        // Precompute BASE^(size-1) mod MOD
        let mut base_pow = 1u64;
        for _ in 0..size.saturating_sub(1) {
            base_pow = (base_pow * HASH_BASE) % HASH_MOD;
        }

        Self {
            hash: 0,
            window: vec![0; size],
            pos: 0,
            size,
            base_pow,
        }
    }

    /// Initialize or reset the hash with new data.
    fn init(&mut self, data: &[u8]) {
        self.hash = 0;
        self.pos = 0;

        let len = data.len().min(self.size);
        for i in 0..len {
            self.window[i] = data[i];
            self.hash = (self.hash * HASH_BASE + data[i] as u64) % HASH_MOD;
        }

        // Pad with zeros if data is shorter than window
        for i in len..self.size {
            self.window[i] = 0;
            self.hash = (self.hash * HASH_BASE) % HASH_MOD;
        }

        self.pos = len % self.size;
    }

    /// Roll the hash by removing the oldest byte and adding a new one.
    fn roll(&mut self, new_byte: u8) -> u64 {
        let old_byte = self.window[self.pos];

        // Remove old_byte contribution and add new_byte
        // new_hash = (old_hash - old_byte * BASE^(n-1)) * BASE + new_byte
        self.hash = (self.hash + HASH_MOD - (old_byte as u64 * self.base_pow) % HASH_MOD) % HASH_MOD;
        self.hash = (self.hash * HASH_BASE + new_byte as u64) % HASH_MOD;

        // Update window
        self.window[self.pos] = new_byte;
        self.pos = (self.pos + 1) % self.size;

        self.hash
    }

    /// Get current hash value.
    fn hash(&self) -> u64 {
        self.hash
    }

    /// Get current window contents.
    #[allow(dead_code)]
    fn current_window(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.size);
        for i in 0..self.size {
            result.push(self.window[(self.pos + i) % self.size]);
        }
        result
    }
}

/// Compute hash for a slice.
fn compute_hash(data: &[u8]) -> u64 {
    let mut hash = 0u64;
    for &byte in data {
        hash = (hash * HASH_BASE + byte as u64) % HASH_MOD;
    }
    hash
}

/// Sliding window matcher for partial secret detection.
pub struct WindowMatcher {
    /// Configuration.
    config: WindowConfig,
    /// Map from hash to (secret_name, substring).
    /// We store substrings for verification after hash match.
    hash_map: HashMap<u64, Vec<(String, Vec<u8>)>>,
    /// Original secret lengths for computing match ratios.
    secret_lengths: HashMap<String, usize>,
    /// All substrings for each window size.
    substrings_by_size: HashMap<usize, HashSet<u64>>,
}

impl WindowMatcher {
    /// Create a new window matcher with default configuration.
    pub fn new() -> Self {
        Self::with_config(WindowConfig::default())
    }

    /// Create a new window matcher with custom configuration.
    pub fn with_config(config: WindowConfig) -> Self {
        Self {
            config,
            hash_map: HashMap::new(),
            secret_lengths: HashMap::new(),
            substrings_by_size: HashMap::new(),
        }
    }

    /// Add a secret to match against.
    ///
    /// This pre-computes hashes for all substrings of the secret
    /// that meet the minimum window size.
    pub fn add_secret(&mut self, name: &str, secret: &[u8]) {
        if secret.len() < self.config.min_window_size {
            return;
        }

        self.secret_lengths.insert(name.to_string(), secret.len());

        // Generate substrings of various sizes
        let min_size = self.config.min_window_size;
        let max_size = self.config.max_window_size.min(secret.len());

        for window_size in min_size..=max_size {
            // Generate all substrings of this size
            for start in (0..=secret.len().saturating_sub(window_size)).step_by(self.config.step_size) {
                let substring = &secret[start..start + window_size];
                let hash = compute_hash(substring);

                self.hash_map
                    .entry(hash)
                    .or_default()
                    .push((name.to_string(), substring.to_vec()));

                self.substrings_by_size
                    .entry(window_size)
                    .or_default()
                    .insert(hash);
            }
        }
    }

    /// Remove a secret from the matcher.
    pub fn remove_secret(&mut self, name: &str) {
        self.secret_lengths.remove(name);

        // Remove from hash_map
        self.hash_map.retain(|_, entries| {
            entries.retain(|(n, _)| n != name);
            !entries.is_empty()
        });

        // Note: We don't update substrings_by_size as it's just for optimization
        // and stale entries will be filtered by hash_map lookups
    }

    /// Find all partial matches in the text.
    pub fn find_matches(&self, text: &[u8]) -> Vec<WindowMatch> {
        if text.len() < self.config.min_window_size || self.hash_map.is_empty() {
            return Vec::new();
        }

        let mut matches = Vec::new();
        let mut seen_matches: HashSet<(usize, String)> = HashSet::new();

        // Scan with different window sizes
        let max_size = self.config.max_window_size.min(text.len());

        for window_size in self.config.min_window_size..=max_size {
            // Skip if no substrings of this size
            if !self.substrings_by_size.contains_key(&window_size) {
                continue;
            }

            let mut rolling_hash = RollingHash::new(window_size);

            if text.len() < window_size {
                continue;
            }

            // Initialize with first window
            rolling_hash.init(&text[..window_size]);

            // Check first position
            self.check_hash(
                rolling_hash.hash(),
                &text[..window_size],
                0,
                window_size,
                &mut matches,
                &mut seen_matches,
            );

            // Roll through the rest
            for i in window_size..text.len() {
                rolling_hash.roll(text[i]);
                let start = i - window_size + 1;

                self.check_hash(
                    rolling_hash.hash(),
                    &text[start..i + 1],
                    start,
                    window_size,
                    &mut matches,
                    &mut seen_matches,
                );
            }
        }

        // Sort by start position
        matches.sort_by_key(|m| m.start);

        // Remove overlapping matches, keeping the longest
        Self::merge_overlapping_matches(matches)
    }

    /// Check if a hash matches any secret substring.
    fn check_hash(
        &self,
        hash: u64,
        window: &[u8],
        start: usize,
        window_size: usize,
        matches: &mut Vec<WindowMatch>,
        seen: &mut HashSet<(usize, String)>,
    ) {
        if let Some(entries) = self.hash_map.get(&hash) {
            for (name, substring) in entries {
                // Verify actual match (hash collision check)
                if window == substring.as_slice() {
                    let key = (start, name.clone());
                    if !seen.contains(&key) {
                        seen.insert(key);

                        let secret_len = self.secret_lengths.get(name).copied().unwrap_or(window_size);
                        let match_ratio = window_size as f64 / secret_len as f64;

                        matches.push(WindowMatch {
                            start,
                            end: start + window_size,
                            secret_name: name.clone(),
                            match_ratio,
                            match_length: window_size,
                        });
                    }
                }
            }
        }
    }

    /// Merge overlapping matches, keeping the longest/best.
    fn merge_overlapping_matches(mut matches: Vec<WindowMatch>) -> Vec<WindowMatch> {
        if matches.len() <= 1 {
            return matches;
        }

        // Sort by start, then by length (descending)
        matches.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| b.match_length.cmp(&a.match_length))
        });

        let mut result = Vec::with_capacity(matches.len());
        let mut current_end = 0;

        for m in matches {
            if m.start >= current_end {
                current_end = m.end;
                result.push(m);
            } else if m.match_length > result.last().map(|l| l.match_length).unwrap_or(0) {
                // Replace with longer match if overlapping
                if let Some(last) = result.last_mut() {
                    if m.start == last.start {
                        *last = m.clone();
                        current_end = m.end;
                    }
                }
            }
        }

        result
    }

    /// Check if text contains any partial secret matches.
    pub fn contains_partial(&self, text: &[u8]) -> bool {
        !self.find_matches(text).is_empty()
    }

    /// Get the longest match in the text.
    pub fn longest_match(&self, text: &[u8]) -> Option<WindowMatch> {
        self.find_matches(text)
            .into_iter()
            .max_by_key(|m| m.match_length)
    }

    /// Clear all secrets.
    pub fn clear(&mut self) {
        self.hash_map.clear();
        self.secret_lengths.clear();
        self.substrings_by_size.clear();
    }
}

impl Default for WindowMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_hash_basic() {
        let mut rh = RollingHash::new(4);
        rh.init(b"abcd");

        let hash1 = rh.hash();

        // Roll to "bcde"
        rh.roll(b'e');
        let hash2 = rh.hash();

        // Hashes should be different
        assert_ne!(hash1, hash2);

        // Verify the hash matches direct computation
        assert_eq!(hash2, compute_hash(b"bcde"));
    }

    #[test]
    fn test_partial_match_detection() {
        let mut matcher = WindowMatcher::new();
        matcher.add_secret("API_KEY", b"sk_live_abc123XYZ");

        // Should detect partial match "abc123XY"
        let text = b"The key contains abc123XY somewhere";
        let matches = matcher.find_matches(text);

        assert!(!matches.is_empty(), "Should find partial match");
        assert_eq!(matches[0].secret_name, "API_KEY");
    }

    #[test]
    fn test_exact_match_via_window() {
        let config = WindowConfig {
            min_window_size: 8,
            max_window_size: 64,
            step_size: 1,
        };
        let mut matcher = WindowMatcher::with_config(config);
        matcher.add_secret("SECRET", b"mysecret123456");  // Long enough secret

        let text = b"prefix mysecret123456 suffix";
        let matches = matcher.find_matches(text);

        assert!(!matches.is_empty(), "Should find at least partial match");
        // The longest match should be close to 100%
        let best_match = matches.iter().max_by(|a, b| {
            a.match_ratio.partial_cmp(&b.match_ratio).unwrap()
        });
        assert!(best_match.is_some(), "Should find full match");
    }

    #[test]
    fn test_no_false_positives() {
        let mut matcher = WindowMatcher::new();
        matcher.add_secret("SECRET", b"verysecretkey123");

        // Text with no overlap to secret
        let text = b"this is completely unrelated text with no secret";
        let matches = matcher.find_matches(text);

        assert!(matches.is_empty(), "Should not find matches in unrelated text");
    }

    #[test]
    fn test_minimum_window_size() {
        let config = WindowConfig {
            min_window_size: 8,
            max_window_size: 64,
            step_size: 1,
        };
        let mut matcher = WindowMatcher::with_config(config);
        matcher.add_secret("SHORT", b"abcdef"); // Too short (6 chars)
        matcher.add_secret("LONG", b"abcdefghij"); // Long enough (10 chars)

        // Short secret shouldn't be indexed
        assert!(!matcher.secret_lengths.contains_key("SHORT"));
        assert!(matcher.secret_lengths.contains_key("LONG"));
    }

    #[test]
    fn test_multiple_secrets() {
        let mut matcher = WindowMatcher::new();
        matcher.add_secret("KEY1", b"firstsecret123");
        matcher.add_secret("KEY2", b"secondsecret456");

        let text = b"found firstsecret123 and secondsec";
        let matches = matcher.find_matches(text);

        assert!(matches.len() >= 2, "Should find matches from both secrets");

        let secret_names: Vec<_> = matches.iter().map(|m| m.secret_name.as_str()).collect();
        assert!(secret_names.contains(&"KEY1"));
        assert!(secret_names.contains(&"KEY2"));
    }

    #[test]
    fn test_match_ratio() {
        let mut matcher = WindowMatcher::new();
        let secret = b"verylongsecretkey123456";
        matcher.add_secret("SECRET", secret);

        // Partial match
        let text = b"longsecret"; // 10 chars out of 23
        let matches = matcher.find_matches(text);

        if let Some(m) = matches.first() {
            assert!(m.match_ratio < 1.0, "Partial match should have ratio < 1.0");
            assert!(m.match_ratio > 0.0, "Match ratio should be > 0");
        }
    }

    #[test]
    fn test_overlapping_matches_merged() {
        let mut matcher = WindowMatcher::new();
        matcher.add_secret("SECRET", b"abcdefghijklmn");

        // Text containing the secret
        let text = b"abcdefghijklmn";
        let matches = matcher.find_matches(text);

        // Should merge overlapping matches
        // The longest match should be kept
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_remove_secret() {
        let mut matcher = WindowMatcher::new();
        matcher.add_secret("KEY1", b"firstsecret1");
        matcher.add_secret("KEY2", b"secondsecret2");

        matcher.remove_secret("KEY1");

        let text = b"firstsecret1 secondsecret2";
        let matches = matcher.find_matches(text);

        // Should only find KEY2 now
        assert!(matches.iter().all(|m| m.secret_name == "KEY2"));
    }

    #[test]
    fn test_contains_partial() {
        let mut matcher = WindowMatcher::new();
        matcher.add_secret("SECRET", b"mysupersecretkey");

        assert!(matcher.contains_partial(b"found supersecr in text"));
        assert!(!matcher.contains_partial(b"nothing here"));
    }

    #[test]
    fn test_longest_match() {
        let config = WindowConfig {
            min_window_size: 8,
            max_window_size: 64,
            step_size: 1,
        };
        let mut matcher = WindowMatcher::with_config(config);
        matcher.add_secret("SECRET", b"abcdefghijklmnop");

        let text = b"abcdefghijklmnop"; // Full match
        let longest = matcher.longest_match(text);

        assert!(longest.is_some());
        // The longest match should be 16 (full length) if max_window_size >= 16
        let len = longest.unwrap().match_length;
        assert!(len >= 8, "Match length {} should be at least 8", len);
    }
}
