//! Exact string matching for secret detection.
//!
//! Uses the Aho-Corasick algorithm for efficient multi-pattern matching.
//! This provides O(n + m + z) complexity where:
//! - n = output length
//! - m = total length of all patterns
//! - z = number of matches found
//!
//! This is significantly faster than naive O(n * m) matching when there
//! are many patterns to match.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::collections::HashMap;

/// A match found in the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactMatch {
    /// Start position in the text (byte offset).
    pub start: usize,
    /// End position in the text (byte offset).
    pub end: usize,
    /// Index of the pattern that matched.
    pub pattern_index: usize,
    /// Name of the secret that matched.
    pub secret_name: String,
    /// The encoding type of this pattern.
    pub encoding: super::EncodingType,
}

/// Pattern information for tracking what each pattern represents.
#[derive(Debug, Clone)]
pub struct PatternInfo {
    /// Name of the secret this pattern belongs to.
    pub secret_name: String,
    /// The encoding type of this pattern.
    pub encoding: super::EncodingType,
    /// The actual pattern bytes.
    pub pattern: Vec<u8>,
}

/// Exact matcher using Aho-Corasick algorithm.
///
/// This matcher pre-computes an automaton from all patterns for
/// efficient multi-pattern matching.
pub struct ExactMatcher {
    /// The compiled Aho-Corasick automaton.
    automaton: Option<AhoCorasick>,
    /// Information about each pattern (indexed by pattern ID).
    pattern_info: Vec<PatternInfo>,
    /// Map from secret name to list of pattern indices.
    secret_patterns: HashMap<String, Vec<usize>>,
}

impl ExactMatcher {
    /// Create a new exact matcher.
    pub fn new() -> Self {
        Self {
            automaton: None,
            pattern_info: Vec::new(),
            secret_patterns: HashMap::new(),
        }
    }

    /// Add a pattern to match against.
    ///
    /// # Arguments
    ///
    /// * `secret_name` - Name of the secret this pattern belongs to
    /// * `pattern` - The bytes to match
    /// * `encoding` - The encoding type of this pattern
    ///
    /// # Note
    ///
    /// After adding patterns, you must call `compile()` before matching.
    pub fn add_pattern(&mut self, secret_name: &str, pattern: Vec<u8>, encoding: super::EncodingType) {
        // Skip empty patterns
        if pattern.is_empty() {
            return;
        }

        let index = self.pattern_info.len();

        self.pattern_info.push(PatternInfo {
            secret_name: secret_name.to_string(),
            encoding,
            pattern,
        });

        self.secret_patterns
            .entry(secret_name.to_string())
            .or_default()
            .push(index);

        // Invalidate the automaton since we added a new pattern
        self.automaton = None;
    }

    /// Compile the automaton from all added patterns.
    ///
    /// This must be called after adding patterns and before matching.
    /// It is automatically called by `find_matches` if needed.
    pub fn compile(&mut self) -> Result<(), String> {
        if self.pattern_info.is_empty() {
            self.automaton = None;
            return Ok(());
        }

        let patterns: Vec<&[u8]> = self.pattern_info.iter().map(|p| p.pattern.as_slice()).collect();

        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&patterns)
            .map_err(|e| format!("Failed to build Aho-Corasick automaton: {}", e))?;

        self.automaton = Some(ac);
        Ok(())
    }

    /// Check if the automaton needs to be compiled.
    #[inline]
    pub fn needs_compile(&self) -> bool {
        self.automaton.is_none() && !self.pattern_info.is_empty()
    }

    /// Find all matches in the given text.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to search
    ///
    /// # Returns
    ///
    /// A vector of all matches found, sorted by start position.
    pub fn find_matches(&mut self, text: &str) -> Result<Vec<ExactMatch>, String> {
        // Compile if needed
        if self.needs_compile() {
            self.compile()?;
        }

        let Some(ref ac) = self.automaton else {
            return Ok(Vec::new());
        };

        let mut matches: Vec<ExactMatch> = ac
            .find_iter(text.as_bytes())
            .map(|m| {
                let info = &self.pattern_info[m.pattern().as_usize()];
                ExactMatch {
                    start: m.start(),
                    end: m.end(),
                    pattern_index: m.pattern().as_usize(),
                    secret_name: info.secret_name.clone(),
                    encoding: info.encoding.clone(),
                }
            })
            .collect();

        // Sort by start position
        matches.sort_by_key(|m| m.start);

        Ok(matches)
    }

    /// Check if the text contains any of the patterns.
    ///
    /// This is faster than `find_matches` when you only need to know
    /// if there are any matches.
    pub fn contains_any(&mut self, text: &str) -> Result<bool, String> {
        if self.needs_compile() {
            self.compile()?;
        }

        let Some(ref ac) = self.automaton else {
            return Ok(false);
        };

        Ok(ac.is_match(text.as_bytes()))
    }

    /// Get the number of patterns.
    pub fn pattern_count(&self) -> usize {
        self.pattern_info.len()
    }

    /// Get all secret names.
    pub fn secret_names(&self) -> Vec<&str> {
        self.secret_patterns.keys().map(|s| s.as_str()).collect()
    }

    /// Clear all patterns.
    pub fn clear(&mut self) {
        self.automaton = None;
        self.pattern_info.clear();
        self.secret_patterns.clear();
    }

    /// Remove all patterns for a specific secret.
    pub fn remove_secret(&mut self, secret_name: &str) {
        if self.secret_patterns.remove(secret_name).is_some() {
            // Rebuild the entire matcher without this secret
            let remaining_patterns: Vec<_> = self.pattern_info
                .iter()
                .filter(|p| p.secret_name != secret_name)
                .cloned()
                .collect();

            self.pattern_info = remaining_patterns;

            // Rebuild secret_patterns index
            self.secret_patterns.clear();
            for (idx, info) in self.pattern_info.iter().enumerate() {
                self.secret_patterns
                    .entry(info.secret_name.clone())
                    .or_default()
                    .push(idx);
            }

            // Invalidate the automaton
            self.automaton = None;
        }
    }

    /// Redact all matches in the text with replacement strings.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to redact
    /// * `replacement_fn` - Function that generates replacement text for each match
    ///
    /// # Returns
    ///
    /// The redacted text.
    pub fn redact<F>(&mut self, text: &str, replacement_fn: F) -> Result<String, String>
    where
        F: Fn(&ExactMatch) -> String,
    {
        let matches = self.find_matches(text)?;

        if matches.is_empty() {
            return Ok(text.to_string());
        }

        // Build the result by replacing matches
        // Handle overlapping matches by processing non-overlapping ones
        let non_overlapping = Self::remove_overlapping_matches(matches);

        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for m in non_overlapping {
            // Add text before this match
            result.push_str(&text[last_end..m.start]);
            // Add replacement
            result.push_str(&replacement_fn(&m));
            last_end = m.end;
        }

        // Add remaining text
        result.push_str(&text[last_end..]);

        Ok(result)
    }

    /// Remove overlapping matches, keeping the longest/earliest match.
    fn remove_overlapping_matches(matches: Vec<ExactMatch>) -> Vec<ExactMatch> {
        if matches.is_empty() {
            return matches;
        }

        let mut result = Vec::with_capacity(matches.len());
        let mut current_end = 0;

        for m in matches {
            if m.start >= current_end {
                current_end = m.end;
                result.push(m);
            }
            // If overlapping, skip this match (keep the earlier one)
        }

        result
    }
}

impl Default for ExactMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EncodingType;

    #[test]
    fn test_exact_match_single_pattern() {
        let mut matcher = ExactMatcher::new();
        matcher.add_pattern("API_KEY", b"sk_live_abc123".to_vec(), EncodingType::Plain);

        let matches = matcher
            .find_matches("Your API key is sk_live_abc123, use it wisely")
            .unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].start, 16);
        assert_eq!(matches[0].end, 30);
        assert_eq!(matches[0].secret_name, "API_KEY");
    }

    #[test]
    fn test_exact_match_multiple_patterns() {
        let mut matcher = ExactMatcher::new();
        matcher.add_pattern("KEY1", b"secret1".to_vec(), EncodingType::Plain);
        matcher.add_pattern("KEY2", b"secret2".to_vec(), EncodingType::Plain);
        matcher.add_pattern("KEY3", b"secret3".to_vec(), EncodingType::Plain);

        let matches = matcher
            .find_matches("secret1 and secret3 but not secret4")
            .unwrap();

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].secret_name, "KEY1");
        assert_eq!(matches[1].secret_name, "KEY3");
    }

    #[test]
    fn test_exact_match_multiple_occurrences() {
        let mut matcher = ExactMatcher::new();
        matcher.add_pattern("KEY", b"password".to_vec(), EncodingType::Plain);

        let matches = matcher
            .find_matches("password is password, not PASSWORD")
            .unwrap();

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].start, 0);
        assert_eq!(matches[1].start, 12);
    }

    #[test]
    fn test_contains_any() {
        let mut matcher = ExactMatcher::new();
        matcher.add_pattern("KEY", b"secretkey123".to_vec(), EncodingType::Plain);

        assert!(matcher.contains_any("this contains secretkey123 data").unwrap());
        assert!(!matcher.contains_any("this contains no matching patterns").unwrap());
    }

    #[test]
    fn test_redact() {
        let mut matcher = ExactMatcher::new();
        matcher.add_pattern("KEY", b"secret123".to_vec(), EncodingType::Plain);

        let result = matcher
            .redact("my secret123 is secret123", |m| {
                format!("[REDACTED:{}]", m.secret_name)
            })
            .unwrap();

        assert_eq!(result, "my [REDACTED:KEY] is [REDACTED:KEY]");
    }

    #[test]
    fn test_no_false_positives() {
        let mut matcher = ExactMatcher::new();
        matcher.add_pattern("KEY", b"exactsecret123".to_vec(), EncodingType::Plain);

        let matches = matcher.find_matches("this has no matching patterns at all").unwrap();

        assert!(matches.is_empty());
    }

    #[test]
    fn test_overlapping_patterns() {
        let mut matcher = ExactMatcher::new();
        matcher.add_pattern("KEY1", b"abcd".to_vec(), EncodingType::Plain);
        matcher.add_pattern("KEY2", b"cdef".to_vec(), EncodingType::Plain);

        // "abcdef" contains overlapping patterns "abcd" and "cdef"
        let result = matcher
            .redact("abcdef", |m| format!("[{}]", m.secret_name))
            .unwrap();

        // First match wins, so "abcd" is replaced, leaving "ef"
        assert_eq!(result, "[KEY1]ef");
    }

    #[test]
    fn test_empty_matcher() {
        let mut matcher = ExactMatcher::new();
        let matches = matcher.find_matches("any text").unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn test_empty_pattern_ignored() {
        let mut matcher = ExactMatcher::new();
        matcher.add_pattern("KEY", vec![], EncodingType::Plain);
        assert_eq!(matcher.pattern_count(), 0);
    }
}
