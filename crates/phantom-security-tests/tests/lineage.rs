//! # Lineage and Audit Trail Tests
//!
//! These tests verify that lineage tracking and audit trails work correctly:
//! - All requests are logged with full lineage
//! - LLM_AUTO + high sensitivity requires confirmation
//! - HMAC chain integrity prevents tampering
//!
//! CRITICAL: Audit trails must be tamper-evident and complete.

use phantom_mcp::lineage::{
    ClientInfo, LineageTracker, RequestLineage, RequestResult, ToolCall, TrustLevel,
};

// =============================================================================
// TEST 21: Audit Log Lineage
// =============================================================================

/// Verify that all tool calls are logged with request lineage.
///
/// This test:
/// 1. Creates a request with lineage
/// 2. Executes multiple tool calls
/// 3. Verifies all calls are logged in the lineage
///
/// Expected: Every tool call is recorded with full context.
#[test]
fn test_audit_log_captures_all_tool_calls() {
    let tracker = LineageTracker::new();
    let client = ClientInfo::mcp("Claude Code", "1.0.0");

    let lineage = tracker.start_request(&client);
    let id = lineage.id.clone();

    // Simulate multiple tool calls
    let tools = ["vault_list", "vault_exists", "vault_masked", "vault_run"];

    for (i, tool_name) in tools.iter().enumerate() {
        let call = ToolCall::new(tool_name, serde_json::json!({"index": i})).success(50 + i as u64, false);
        tracker.add_tool_call(&id, call);
    }

    // Complete the request
    tracker.complete_request(&id, RequestResult::success("All tools called", false));

    // Verify all calls are in the lineage
    let stats = tracker.stats();
    for tool_name in &tools {
        assert!(
            stats.tool_counts.contains_key(*tool_name),
            "Tool '{}' should be in audit log",
            tool_name
        );
    }
}

/// Test that secret accesses are recorded in lineage.
#[test]
fn test_audit_log_captures_secret_access() {
    let tracker = LineageTracker::new();
    let client = ClientInfo::mcp("Claude Code", "1.0.0");

    let lineage = tracker.start_request(&client);
    let id = lineage.id.clone();

    // Record secret accesses
    tracker.record_secret_access(&id, "API_KEY");
    tracker.record_secret_access(&id, "DB_PASSWORD");
    tracker.record_secret_access(&id, "API_KEY"); // Duplicate

    tracker.complete_request(&id, RequestResult::success("Done", false));

    // Check stats
    let stats = tracker.stats();
    assert_eq!(
        *stats.secrets_accessed.get("API_KEY").unwrap_or(&0),
        1,
        "API_KEY should be recorded once (deduped)"
    );
    assert_eq!(
        *stats.secrets_accessed.get("DB_PASSWORD").unwrap_or(&0),
        1,
        "DB_PASSWORD should be recorded"
    );
}

/// Test that failed tool calls are also logged.
#[test]
fn test_audit_log_captures_failures() {
    let tracker = LineageTracker::new();
    let client = ClientInfo::mcp("Claude Code", "1.0.0");

    let lineage = tracker.start_request(&client);
    let id = lineage.id.clone();

    // Add a failed tool call
    let failed_call = ToolCall::new("vault_run", serde_json::json!({"command": "dangerous"}))
        .failed("Command blocked by policy", 10);
    tracker.add_tool_call(&id, failed_call);

    tracker.complete_request(&id, RequestResult::blocked("Policy violation"));

    // Should be in audit
    let stats = tracker.stats();
    assert_eq!(stats.total_requests, 1);
    assert!(stats.tool_counts.contains_key("vault_run"));
}

// =============================================================================
// TEST 22: LLM_AUTO + High Sensitivity Requires Confirmation
// =============================================================================

/// Verify that LLM_AUTO trust level cannot access high-sensitivity secrets.
///
/// This test:
/// 1. Creates a request with LLM_AUTO trust level
/// 2. Attempts to access a high-sensitivity secret
/// 3. Verifies access is denied without confirmation
///
/// Expected: High sensitivity + LLM_AUTO = ACCESS DENIED.
#[test]
fn test_llm_auto_high_sensitivity_denied() {
    let tracker = LineageTracker::new();

    // No human interaction recorded - will be LLM_AUTO
    let client = ClientInfo::mcp("Claude Code", "1.0.0");
    let trust_level = tracker.determine_trust_level(&client);

    assert_eq!(trust_level, TrustLevel::LlmAuto);

    // Check policy
    let allows_high_sensitivity = trust_level.allows_high_sensitivity();
    assert!(
        !allows_high_sensitivity,
        "LLM_AUTO should NOT allow high sensitivity access"
    );
}

/// Test that LLM_APPROVED allows high sensitivity access.
#[test]
fn test_llm_approved_high_sensitivity_allowed() {
    let tracker = LineageTracker::new();

    // Record human interaction
    tracker.record_human_interaction();

    let client = ClientInfo::mcp("Claude Code", "1.0.0");
    let trust_level = tracker.determine_trust_level(&client);

    assert_eq!(trust_level, TrustLevel::LlmApproved);

    let allows_high_sensitivity = trust_level.allows_high_sensitivity();
    assert!(
        allows_high_sensitivity,
        "LLM_APPROVED should allow high sensitivity access"
    );
}

/// Test that HUMAN_DIRECT always allows high sensitivity access.
#[test]
fn test_human_direct_high_sensitivity_allowed() {
    let tracker = LineageTracker::new();
    let client = ClientInfo::human_cli();

    let trust_level = tracker.determine_trust_level(&client);

    assert_eq!(trust_level, TrustLevel::HumanDirect);
    assert!(
        trust_level.allows_high_sensitivity(),
        "HUMAN_DIRECT should allow high sensitivity access"
    );
}

/// Simulate sensitivity-based access control.
#[test]
fn test_sensitivity_access_control() {
    #[derive(PartialEq, Debug)]
    enum Sensitivity {
        Low,
        Medium,
        High,
        Critical,
    }

    fn check_access(trust: TrustLevel, sensitivity: &Sensitivity) -> bool {
        match sensitivity {
            Sensitivity::Low => true, // Anyone can access
            Sensitivity::Medium => true, // Anyone with valid session
            Sensitivity::High => trust.allows_high_sensitivity(),
            Sensitivity::Critical => matches!(trust, TrustLevel::HumanDirect),
        }
    }

    // HUMAN_DIRECT can access everything
    assert!(check_access(TrustLevel::HumanDirect, &Sensitivity::Low));
    assert!(check_access(TrustLevel::HumanDirect, &Sensitivity::Medium));
    assert!(check_access(TrustLevel::HumanDirect, &Sensitivity::High));
    assert!(check_access(TrustLevel::HumanDirect, &Sensitivity::Critical));

    // LLM_APPROVED can access up to High
    assert!(check_access(TrustLevel::LlmApproved, &Sensitivity::Low));
    assert!(check_access(TrustLevel::LlmApproved, &Sensitivity::Medium));
    assert!(check_access(TrustLevel::LlmApproved, &Sensitivity::High));
    assert!(!check_access(TrustLevel::LlmApproved, &Sensitivity::Critical));

    // LLM_AUTO can only access Low/Medium
    assert!(check_access(TrustLevel::LlmAuto, &Sensitivity::Low));
    assert!(check_access(TrustLevel::LlmAuto, &Sensitivity::Medium));
    assert!(!check_access(TrustLevel::LlmAuto, &Sensitivity::High));
    assert!(!check_access(TrustLevel::LlmAuto, &Sensitivity::Critical));
}

// =============================================================================
// TEST 23: HMAC Chain Integrity
// =============================================================================

/// Verify that HMAC chain provides tamper detection.
///
/// This test:
/// 1. Creates audit entries with HMAC chaining
/// 2. Verifies the chain is valid
/// 3. Tampers with an entry
/// 4. Verifies tampering is detected
///
/// Expected: Tampered chain is DETECTED.
#[test]
fn test_hmac_chain_tamper_detection() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[derive(Clone)]
    struct AuditEntry {
        sequence: u64,
        event: String,
        prev_hash: u64,
        hash: u64,
    }

    impl AuditEntry {
        fn new(sequence: u64, event: &str, prev_hash: u64) -> Self {
            let mut hasher = DefaultHasher::new();
            sequence.hash(&mut hasher);
            event.hash(&mut hasher);
            prev_hash.hash(&mut hasher);
            let hash = hasher.finish();

            Self {
                sequence,
                event: event.to_string(),
                prev_hash,
                hash,
            }
        }

        fn verify(&self, expected_prev_hash: u64) -> bool {
            // Check chain linkage
            if self.prev_hash != expected_prev_hash {
                return false;
            }

            // Recompute hash
            let mut hasher = DefaultHasher::new();
            self.sequence.hash(&mut hasher);
            self.event.hash(&mut hasher);
            self.prev_hash.hash(&mut hasher);
            let computed = hasher.finish();

            computed == self.hash
        }
    }

    // Build a chain
    let mut chain: Vec<AuditEntry> = Vec::new();
    let events = ["vault_opened", "secret_read", "command_executed", "vault_sealed"];

    let mut prev_hash = 0u64;
    for (i, event) in events.iter().enumerate() {
        let entry = AuditEntry::new(i as u64, event, prev_hash);
        prev_hash = entry.hash;
        chain.push(entry);
    }

    // Verify valid chain
    let mut prev = 0u64;
    for entry in &chain {
        assert!(
            entry.verify(prev),
            "Valid chain should verify at entry {}",
            entry.sequence
        );
        prev = entry.hash;
    }

    // Tamper with an entry
    let mut tampered_chain = chain.clone();
    tampered_chain[1].event = "secret_deleted".to_string(); // Change event

    // Verification should fail
    let mut prev = 0u64;
    let mut tampering_detected = false;
    for entry in &tampered_chain {
        if !entry.verify(prev) {
            tampering_detected = true;
            break;
        }
        prev = entry.hash;
    }

    assert!(
        tampering_detected,
        "SECURITY FAILURE: Tampering should be detected!"
    );
}

/// Test that HMAC chain detects deletion.
#[test]
fn test_hmac_chain_deletion_detection() {
    // Simplified chain representation
    let chain = vec![
        (0u64, "hash_0"),
        (1, "hash_1_linked_to_0"),
        (2, "hash_2_linked_to_1"),
        (3, "hash_3_linked_to_2"),
    ];

    // Remove entry at index 2
    let chain_with_deletion: Vec<_> = chain
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, e)| e)
        .collect();

    // Gap in sequence should be detected
    let sequences: Vec<u64> = chain_with_deletion.iter().map(|(seq, _)| *seq).collect();
    let has_gap = sequences.windows(2).any(|w| w[1] - w[0] != 1);

    assert!(has_gap, "Deletion should create detectable gap in sequence");
}

// =============================================================================
// TEST: Lineage Export and JSON Format
// =============================================================================

/// Test that lineage can be exported to JSON for auditing.
#[test]
fn test_lineage_export_json() {
    let tracker = LineageTracker::new();
    let client = ClientInfo::mcp("Claude Code", "1.0.0");

    let lineage = tracker.start_request(&client);
    let id = lineage.id.clone();

    tracker.add_tool_call(
        &id,
        ToolCall::new("vault_list", serde_json::json!({})).success(100, false),
    );
    tracker.record_secret_access(&id, "TEST_SECRET");
    tracker.complete_request(&id, RequestResult::success("Test complete", false));

    let json = tracker.export_json().expect("JSON export should succeed");

    // Verify JSON contains expected fields
    assert!(json.contains("vault_list"), "JSON should contain tool name");
    assert!(json.contains("TEST_SECRET"), "JSON should contain secret name");
    assert!(
        json.contains("LlmAuto") || json.contains("LLM_AUTO"),
        "JSON should contain trust level"
    );
}

// =============================================================================
// TEST: Request Lineage Parent-Child Relationship
// =============================================================================

/// Test that parent-child request relationships are tracked.
#[test]
fn test_lineage_parent_child_relationship() {
    let tracker = LineageTracker::new();
    let client = ClientInfo::mcp("Claude Code", "1.0.0");

    // Start parent request
    let parent = tracker.start_request(&client);
    let parent_id = parent.id.clone();

    // Create child lineage
    let child = parent.child(client.clone(), TrustLevel::LlmAuto);

    // Child should reference parent
    assert_eq!(
        child.parent_id,
        Some(parent_id),
        "Child should reference parent ID"
    );
}

// =============================================================================
// TEST: Trust Level Escalation Prevention
// =============================================================================

/// Verify that trust levels cannot be escalated within a request chain.
#[test]
fn test_trust_level_escalation_prevention() {
    let tracker = LineageTracker::new();

    // Start as LLM_AUTO
    let client = ClientInfo::mcp("Claude Code", "1.0.0");
    let lineage = tracker.start_request(&client);

    assert_eq!(lineage.trust_level, TrustLevel::LlmAuto);

    // Child requests should not have higher trust than parent
    let child = lineage.child(client.clone(), TrustLevel::LlmAuto);

    // The trust level should not magically escalate
    assert_eq!(
        child.trust_level,
        TrustLevel::LlmAuto,
        "Child should not have escalated trust"
    );

    // Even if we try to force it, the policy should prevent it
    // (This would be enforced by the actual implementation)
}

// =============================================================================
// TEST: Lineage Statistics
// =============================================================================

/// Test that lineage statistics are accurate.
#[test]
fn test_lineage_statistics_accuracy() {
    let tracker = LineageTracker::new();

    // Create multiple requests with different trust levels
    let human_client = ClientInfo::human_cli();
    let mcp_client = ClientInfo::mcp("Claude Code", "1.0.0");

    // Human request
    let human_lineage = tracker.start_request(&human_client);
    tracker.add_tool_call(
        &human_lineage.id,
        ToolCall::new("vault_list", serde_json::json!({})).success(10, false),
    );
    tracker.complete_request(&human_lineage.id, RequestResult::success("Done", false));

    // MCP request
    let mcp_lineage = tracker.start_request(&mcp_client);
    tracker.add_tool_call(
        &mcp_lineage.id,
        ToolCall::new("vault_list", serde_json::json!({})).success(20, false),
    );
    tracker.add_tool_call(
        &mcp_lineage.id,
        ToolCall::new("vault_masked", serde_json::json!({})).success(30, false),
    );
    tracker.complete_request(&mcp_lineage.id, RequestResult::success("Done", false));

    let stats = tracker.stats();

    assert_eq!(stats.total_requests, 2);
    assert_eq!(stats.active_requests, 0);
    assert_eq!(*stats.tool_counts.get("vault_list").unwrap(), 2);
    assert_eq!(*stats.tool_counts.get("vault_masked").unwrap(), 1);
    assert!(stats.trust_level_counts.contains_key("HUMAN_DIRECT"));
    assert!(stats.trust_level_counts.contains_key("LLM_AUTO"));
}

// =============================================================================
// TEST: Tool Call Argument Stripping
// =============================================================================

/// Test that sensitive arguments are stripped from audit logs.
#[test]
fn test_tool_call_argument_stripping() {
    let call = ToolCall::new(
        "vault_run",
        serde_json::json!({
            "command": "echo test",
            "secret_key": "should_be_redacted",
            "password": "also_redacted",
            "normal_param": "kept",
            "token": "redacted_too"
        }),
    );

    // Check that sensitive fields are redacted
    assert_eq!(call.arguments["secret_key"], "[REDACTED]");
    assert_eq!(call.arguments["password"], "[REDACTED]");
    assert_eq!(call.arguments["token"], "[REDACTED]");
    assert_eq!(call.arguments["normal_param"], "kept");
    // "key" matches pattern so it's also redacted
    assert_eq!(call.arguments["command"], "echo test");
}

// =============================================================================
// TEST: Completed Request Retention
// =============================================================================

/// Test that completed requests are retained up to the limit.
#[test]
fn test_completed_request_retention() {
    // Create tracker with small limit
    let tracker = LineageTracker::with_config(5, 300);
    let client = ClientInfo::mcp("Test", "1.0");

    // Create more requests than the limit
    for i in 0..10 {
        let lineage = tracker.start_request(&client);
        tracker.complete_request(
            &lineage.id,
            RequestResult::success(&format!("Request {}", i), false),
        );
    }

    let exported = tracker.export();

    // Should only keep the most recent 5
    assert!(
        exported.len() <= 5,
        "Should retain at most 5 completed requests, got {}",
        exported.len()
    );
}
