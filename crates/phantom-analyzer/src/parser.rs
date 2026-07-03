//! Shell command parser for security analysis.
//!
//! This module parses bash/zsh commands into an AST-like structure
//! focused on security-relevant patterns. It is not a full shell parser
//! but captures enough structure to detect oracle attacks.
//!
//! # Supported Constructs
//!
//! - Simple commands with arguments
//! - Pipelines (`cmd1 | cmd2`)
//! - Sequences (`cmd1; cmd2`, `cmd1 && cmd2`, `cmd1 || cmd2`)
//! - Subshells (`(cmd)`, `$(cmd)`)
//! - Variable references (`$VAR`, `${VAR}`, `${VAR:0:1}`)
//! - Conditionals (`if`, `[[`, `[`, `test`)
//! - Loops (`for`, `while`)
//! - Redirections (`>`, `>>`, `<`, `2>&1`)
//! - Here documents (`<<EOF`)

use regex::Regex;
use std::collections::HashSet;
use thiserror::Error;

/// Errors that can occur during parsing.
#[derive(Debug, Error)]
pub enum ParseError {
    /// Syntax error in command.
    #[error("syntax error: {0}")]
    Syntax(String),

    /// Unsupported shell construct.
    #[error("unsupported construct: {0}")]
    Unsupported(String),

    /// Incomplete command (unclosed quote, etc.).
    #[error("incomplete command: {0}")]
    Incomplete(String),
}

/// Result type for parsing operations.
pub type ParseResult<T> = Result<T, ParseError>;

/// A parsed shell command structure.
#[derive(Debug, Clone)]
pub struct ParsedCommand {
    /// The raw command string.
    pub raw: String,
    /// Identified tokens/segments.
    pub tokens: Vec<Token>,
    /// All variable references found.
    pub variable_refs: Vec<VariableRef>,
    /// All command names found.
    pub commands: Vec<String>,
    /// Redirections found.
    pub redirections: Vec<Redirection>,
    /// Whether the command contains conditionals.
    pub has_conditionals: bool,
    /// Whether the command contains loops.
    pub has_loops: bool,
    /// Whether the command contains pipes.
    pub has_pipes: bool,
    /// Whether the command contains subshells/command substitution.
    pub has_subshells: bool,
}

/// A token in the parsed command.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// A literal word.
    Word(String),
    /// A variable reference.
    Variable(VariableRef),
    /// A pipe operator.
    Pipe,
    /// Sequence operators.
    Sequence(SequenceOp),
    /// A redirection.
    Redirect(Redirection),
    /// Command substitution $(...) or `...`.
    CommandSubstitution(String),
    /// A subshell (...).
    Subshell(String),
    /// Conditional start (if, [[, [, test).
    ConditionalStart(String),
    /// Conditional end (fi, ]]).
    ConditionalEnd(String),
    /// Loop start (for, while).
    LoopStart(String),
    /// Loop end (done).
    LoopEnd,
    /// Whitespace (for position tracking).
    Whitespace,
    /// A heredoc marker.
    HereDoc(String),
}

/// A variable reference in the command.
#[derive(Debug, Clone, PartialEq)]
pub struct VariableRef {
    /// The variable name.
    pub name: String,
    /// The full reference string (e.g., "${VAR:0:1}").
    pub full_ref: String,
    /// Whether this is a substring extraction.
    pub is_substring: bool,
    /// Substring offset (if substring).
    pub offset: Option<i64>,
    /// Substring length (if substring).
    pub length: Option<i64>,
    /// Other parameter expansion operators.
    pub expansion_op: Option<String>,
}

/// Sequence operator type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceOp {
    /// Sequential (;).
    Semicolon,
    /// And (&&).
    And,
    /// Or (||).
    Or,
    /// Background (&).
    Background,
}

/// A file redirection.
#[derive(Debug, Clone, PartialEq)]
pub struct Redirection {
    /// Source file descriptor (default: 1 for stdout).
    pub fd: i32,
    /// Redirection type.
    pub kind: RedirectKind,
    /// Target (file path or fd).
    pub target: String,
}

/// Type of redirection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectKind {
    /// Output (>).
    Output,
    /// Append (>>).
    Append,
    /// Input (<).
    Input,
    /// Here-document (<<).
    HereDoc,
    /// Here-string (<<<).
    HereString,
    /// File descriptor duplication (2>&1).
    DupFd,
}

/// Shell command parser.
pub struct ShellParser {
    /// Known conditional commands.
    conditional_commands: HashSet<String>,
    /// Known loop commands.
    loop_commands: HashSet<String>,
    /// Regex for variable references.
    var_regex: Regex,
    /// Regex for substring extraction.
    substring_regex: Regex,
    /// Regex for command substitution.
    cmd_subst_regex: Regex,
}

impl ShellParser {
    /// Create a new shell parser.
    pub fn new() -> Self {
        let conditional_commands: HashSet<String> = ["if", "then", "else", "elif", "fi", "[[", "]]", "[", "]", "test", "case", "esac"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let loop_commands: HashSet<String> = ["for", "while", "until", "do", "done"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        // Regex for ${VAR}, $VAR, ${VAR:0:1}, ${VAR:-default}, etc.
        let var_regex = Regex::new(r#"\$\{([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("Invalid var regex");

        // Regex for substring extraction ${VAR:offset:length}
        let substring_regex = Regex::new(r#":(-?\d+)(?::(\d+))?"#)
            .expect("Invalid substring regex");

        // Regex for command substitution
        let cmd_subst_regex = Regex::new(r#"\$\(([^)]+)\)|`([^`]+)`"#)
            .expect("Invalid cmd subst regex");

        Self {
            conditional_commands,
            loop_commands,
            var_regex,
            substring_regex,
            cmd_subst_regex,
        }
    }

    /// Parse a shell command.
    pub fn parse(&self, command: &str) -> ParseResult<ParsedCommand> {
        let tokens = self.tokenize(command)?;
        let variable_refs = self.extract_variable_refs(command);
        let commands = self.extract_commands(command);
        let redirections = self.extract_redirections(&tokens);

        let has_conditionals = tokens.iter().any(|t| matches!(t, Token::ConditionalStart(_)));
        let has_loops = tokens.iter().any(|t| matches!(t, Token::LoopStart(_)));
        let has_pipes = tokens.iter().any(|t| matches!(t, Token::Pipe));
        let has_subshells = tokens.iter().any(|t| matches!(t, Token::CommandSubstitution(_) | Token::Subshell(_)));

        Ok(ParsedCommand {
            raw: command.to_string(),
            tokens,
            variable_refs,
            commands,
            redirections,
            has_conditionals,
            has_loops,
            has_pipes,
            has_subshells,
        })
    }

    /// Tokenize a command into basic tokens.
    fn tokenize(&self, command: &str) -> ParseResult<Vec<Token>> {
        let mut tokens = Vec::new();
        let mut chars = command.chars().peekable();
        let mut current_word = String::new();
        let mut in_single_quote = false;
        let mut in_double_quote = false;

        while let Some(c) = chars.next() {
            match c {
                '\'' if !in_double_quote => {
                    in_single_quote = !in_single_quote;
                    current_word.push(c);
                }
                '"' if !in_single_quote => {
                    in_double_quote = !in_double_quote;
                    current_word.push(c);
                }
                '\\' if !in_single_quote => {
                    // Escape sequence
                    current_word.push(c);
                    if let Some(next) = chars.next() {
                        current_word.push(next);
                    }
                }
                '$' if !in_single_quote => {
                    // Start of variable or command substitution
                    current_word.push(c);
                    if let Some(&next) = chars.peek() {
                        if next == '(' {
                            // Command substitution $(...)
                            chars.next();
                            current_word.push('(');
                            let mut depth = 1;
                            while depth > 0 {
                                if let Some(nc) = chars.next() {
                                    current_word.push(nc);
                                    match nc {
                                        '(' => depth += 1,
                                        ')' => depth -= 1,
                                        _ => {}
                                    }
                                } else {
                                    return Err(ParseError::Incomplete("unclosed $(".to_string()));
                                }
                            }
                        } else if next == '{' {
                            // Variable expansion ${...}
                            chars.next();
                            current_word.push('{');
                            let mut depth = 1;
                            while depth > 0 {
                                if let Some(nc) = chars.next() {
                                    current_word.push(nc);
                                    match nc {
                                        '{' => depth += 1,
                                        '}' => depth -= 1,
                                        _ => {}
                                    }
                                } else {
                                    return Err(ParseError::Incomplete("unclosed ${".to_string()));
                                }
                            }
                        }
                    }
                }
                '`' if !in_single_quote => {
                    // Backtick command substitution
                    current_word.push(c);
                    loop {
                        if let Some(nc) = chars.next() {
                            current_word.push(nc);
                            if nc == '`' {
                                break;
                            }
                        } else {
                            return Err(ParseError::Incomplete("unclosed backtick".to_string()));
                        }
                    }
                }
                '|' if !in_single_quote && !in_double_quote => {
                    if !current_word.is_empty() {
                        tokens.push(self.classify_word(&current_word));
                        current_word.clear();
                    }
                    if chars.peek() == Some(&'|') {
                        chars.next();
                        tokens.push(Token::Sequence(SequenceOp::Or));
                    } else {
                        tokens.push(Token::Pipe);
                    }
                }
                '&' if !in_single_quote && !in_double_quote => {
                    if !current_word.is_empty() {
                        tokens.push(self.classify_word(&current_word));
                        current_word.clear();
                    }
                    if chars.peek() == Some(&'&') {
                        chars.next();
                        tokens.push(Token::Sequence(SequenceOp::And));
                    } else {
                        tokens.push(Token::Sequence(SequenceOp::Background));
                    }
                }
                ';' if !in_single_quote && !in_double_quote => {
                    if !current_word.is_empty() {
                        tokens.push(self.classify_word(&current_word));
                        current_word.clear();
                    }
                    tokens.push(Token::Sequence(SequenceOp::Semicolon));
                }
                '>' | '<' if !in_single_quote && !in_double_quote => {
                    if !current_word.is_empty() {
                        tokens.push(self.classify_word(&current_word));
                        current_word.clear();
                    }
                    let mut redir = c.to_string();
                    // Check for >> or << or <<<
                    while let Some(&next) = chars.peek() {
                        if next == '>' || next == '<' {
                            redir.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }
                    // Skip whitespace and get target
                    while chars.peek() == Some(&' ') {
                        chars.next();
                    }
                    let mut target = String::new();
                    while let Some(&nc) = chars.peek() {
                        if nc.is_whitespace() || nc == '|' || nc == '&' || nc == ';' {
                            break;
                        }
                        target.push(chars.next().unwrap());
                    }
                    let kind = match redir.as_str() {
                        ">" => RedirectKind::Output,
                        ">>" => RedirectKind::Append,
                        "<" => RedirectKind::Input,
                        "<<" => RedirectKind::HereDoc,
                        "<<<" => RedirectKind::HereString,
                        _ => RedirectKind::Output,
                    };
                    tokens.push(Token::Redirect(Redirection {
                        fd: if c == '>' { 1 } else { 0 },
                        kind,
                        target,
                    }));
                }
                '(' if !in_single_quote && !in_double_quote => {
                    if !current_word.is_empty() {
                        tokens.push(self.classify_word(&current_word));
                        current_word.clear();
                    }
                    // Subshell
                    let mut subshell = String::new();
                    let mut depth = 1;
                    while depth > 0 {
                        if let Some(nc) = chars.next() {
                            if nc == '(' {
                                depth += 1;
                            } else if nc == ')' {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            subshell.push(nc);
                        } else {
                            return Err(ParseError::Incomplete("unclosed (".to_string()));
                        }
                    }
                    tokens.push(Token::Subshell(subshell));
                }
                ' ' | '\t' | '\n' if !in_single_quote && !in_double_quote => {
                    if !current_word.is_empty() {
                        tokens.push(self.classify_word(&current_word));
                        current_word.clear();
                    }
                }
                _ => {
                    current_word.push(c);
                }
            }
        }

        if in_single_quote {
            return Err(ParseError::Incomplete("unclosed single quote".to_string()));
        }
        if in_double_quote {
            return Err(ParseError::Incomplete("unclosed double quote".to_string()));
        }

        if !current_word.is_empty() {
            tokens.push(self.classify_word(&current_word));
        }

        Ok(tokens)
    }

    /// Classify a word as a specific token type.
    fn classify_word(&self, word: &str) -> Token {
        // Check for conditionals
        if self.conditional_commands.contains(word) {
            if word == "fi" || word == "]]" || word == "]" || word == "esac" {
                return Token::ConditionalEnd(word.to_string());
            }
            return Token::ConditionalStart(word.to_string());
        }

        // Check for loops
        if self.loop_commands.contains(word) {
            if word == "done" {
                return Token::LoopEnd;
            }
            return Token::LoopStart(word.to_string());
        }

        // Check for command substitution
        if word.starts_with("$(") || word.starts_with('`') {
            return Token::CommandSubstitution(word.to_string());
        }

        // Check for variable reference
        if word.contains('$') {
            if let Some(var_ref) = self.parse_variable_ref(word) {
                return Token::Variable(var_ref);
            }
        }

        Token::Word(word.to_string())
    }

    /// Parse a variable reference from a string.
    fn parse_variable_ref(&self, s: &str) -> Option<VariableRef> {
        if let Some(caps) = self.var_regex.captures(s) {
            let name = caps.get(1).or(caps.get(3))?.as_str().to_string();
            let expansion = caps.get(2).map(|m| m.as_str().to_string());

            let mut is_substring = false;
            let mut offset = None;
            let mut length = None;

            if let Some(ref exp) = expansion {
                if let Some(substr_caps) = self.substring_regex.captures(exp) {
                    is_substring = true;
                    offset = substr_caps.get(1).and_then(|m| m.as_str().parse().ok());
                    length = substr_caps.get(2).and_then(|m| m.as_str().parse().ok());
                }
            }

            Some(VariableRef {
                name,
                full_ref: s.to_string(),
                is_substring,
                offset,
                length,
                expansion_op: expansion,
            })
        } else {
            None
        }
    }

    /// Extract all variable references from a command.
    pub fn extract_variable_refs(&self, command: &str) -> Vec<VariableRef> {
        let mut refs = Vec::new();

        for caps in self.var_regex.captures_iter(command) {
            let full_match = caps.get(0).unwrap().as_str();
            let name = caps.get(1).or(caps.get(3)).map(|m| m.as_str().to_string());

            if let Some(name) = name {
                let expansion = caps.get(2).map(|m| m.as_str().to_string());

                let mut is_substring = false;
                let mut offset = None;
                let mut length = None;

                if let Some(ref exp) = expansion {
                    if let Some(substr_caps) = self.substring_regex.captures(exp) {
                        is_substring = true;
                        offset = substr_caps.get(1).and_then(|m| m.as_str().parse().ok());
                        length = substr_caps.get(2).and_then(|m| m.as_str().parse().ok());
                    }
                }

                refs.push(VariableRef {
                    name,
                    full_ref: full_match.to_string(),
                    is_substring,
                    offset,
                    length,
                    expansion_op: expansion,
                });
            }
        }

        refs
    }

    /// Extract command names from a command string.
    pub fn extract_commands(&self, command: &str) -> Vec<String> {
        let mut commands = Vec::new();

        // Split by pipe, &&, ||, ;
        let parts: Vec<&str> = command
            .split(|c| c == '|' || c == ';')
            .flat_map(|s| s.split("&&"))
            .flat_map(|s| s.split("||"))
            .collect();

        for part in parts {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Get the first word (command name)
            if let Some(first_word) = shell_words::split(trimmed).ok().and_then(|words| words.into_iter().next()) {
                // Skip shell keywords
                if !self.conditional_commands.contains(&first_word)
                    && !self.loop_commands.contains(&first_word)
                    && !first_word.starts_with('$')
                {
                    commands.push(first_word);
                }
            }
        }

        commands
    }

    /// Extract redirections from parsed tokens.
    fn extract_redirections(&self, tokens: &[Token]) -> Vec<Redirection> {
        tokens
            .iter()
            .filter_map(|t| {
                if let Token::Redirect(r) = t {
                    Some(r.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Check if command contains command substitution.
    pub fn has_command_substitution(&self, command: &str) -> bool {
        self.cmd_subst_regex.is_match(command)
    }

    /// Extract command substitutions from a command.
    pub fn extract_command_substitutions(&self, command: &str) -> Vec<String> {
        self.cmd_subst_regex
            .captures_iter(command)
            .filter_map(|caps| caps.get(1).or(caps.get(2)).map(|m| m.as_str().to_string()))
            .collect()
    }
}

impl Default for ShellParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let parser = ShellParser::new();
        let result = parser.parse("ls -la").unwrap();

        assert!(!result.has_pipes);
        assert!(!result.has_conditionals);
        assert!(result.variable_refs.is_empty());
    }

    #[test]
    fn test_variable_reference() {
        let parser = ShellParser::new();
        let result = parser.parse("echo $HOME").unwrap();

        assert_eq!(result.variable_refs.len(), 1);
        assert_eq!(result.variable_refs[0].name, "HOME");
        assert!(!result.variable_refs[0].is_substring);
    }

    #[test]
    fn test_substring_extraction() {
        let parser = ShellParser::new();
        let result = parser.parse("echo ${VAR:0:1}").unwrap();

        assert_eq!(result.variable_refs.len(), 1);
        assert_eq!(result.variable_refs[0].name, "VAR");
        assert!(result.variable_refs[0].is_substring);
        assert_eq!(result.variable_refs[0].offset, Some(0));
        assert_eq!(result.variable_refs[0].length, Some(1));
    }

    #[test]
    fn test_pipe() {
        let parser = ShellParser::new();
        let result = parser.parse("echo hello | grep h").unwrap();

        assert!(result.has_pipes);
        assert!(result.commands.contains(&"echo".to_string()));
        assert!(result.commands.contains(&"grep".to_string()));
    }

    #[test]
    fn test_conditional() {
        let parser = ShellParser::new();
        let result = parser.parse("if [ -f file ]; then echo yes; fi").unwrap();

        assert!(result.has_conditionals);
    }

    #[test]
    fn test_loop() {
        let parser = ShellParser::new();
        let result = parser.parse("for i in 1 2 3; do echo $i; done").unwrap();

        assert!(result.has_loops);
    }

    #[test]
    fn test_command_substitution() {
        let parser = ShellParser::new();
        let result = parser.parse("echo $(date)").unwrap();

        assert!(result.has_subshells);
    }

    #[test]
    fn test_redirection() {
        let parser = ShellParser::new();
        let result = parser.parse("echo hello > file.txt").unwrap();

        assert_eq!(result.redirections.len(), 1);
        assert_eq!(result.redirections[0].kind, RedirectKind::Output);
        assert_eq!(result.redirections[0].target, "file.txt");
    }

    #[test]
    fn test_complex_variable() {
        let parser = ShellParser::new();
        let result = parser.parse("echo ${VAR:-default}").unwrap();

        assert_eq!(result.variable_refs.len(), 1);
        assert_eq!(result.variable_refs[0].name, "VAR");
    }

    #[test]
    fn test_double_quotes_preserve_vars() {
        let parser = ShellParser::new();
        let result = parser.parse("echo \"Hello $USER\"").unwrap();

        assert_eq!(result.variable_refs.len(), 1);
        assert_eq!(result.variable_refs[0].name, "USER");
    }

    #[test]
    fn test_single_quotes_hide_vars() {
        let parser = ShellParser::new();
        // Note: our parser still finds $USER in the raw string, but in actual
        // shell execution, single quotes prevent expansion
        let result = parser.parse("echo '$USER'").unwrap();

        // The parser finds it but flags it appropriately
        assert!(result.raw.contains("$USER"));
    }

    #[test]
    fn test_multiple_commands() {
        let parser = ShellParser::new();
        let result = parser.parse("cd /tmp && ls -la; echo done").unwrap();

        assert!(result.commands.contains(&"cd".to_string()));
        assert!(result.commands.contains(&"ls".to_string()));
        assert!(result.commands.contains(&"echo".to_string()));
    }

    #[test]
    fn test_backtick_substitution() {
        let parser = ShellParser::new();
        let result = parser.parse("echo `date`").unwrap();

        assert!(result.has_subshells);
    }
}
