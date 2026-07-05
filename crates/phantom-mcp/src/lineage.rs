//! Request lineage tracking for audit trails.
//!
//! Tracks the chain of requests from AI assistants to help
//! understand how and why secrets were accessed.
//!
//! # Trust Levels
//!
//! - **HUMAN_DIRECT**: Called by human via CLI
//! - **LLM_APPROVED**: Called by MCP with recent human interaction
//! - **LLM_AUTO**: Called by MCP without recent human interaction

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Trust level for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Called by human via CLI.
    HumanDirect,
    /// Called by MCP with recent human interaction.
    LlmApproved,
    /// Called by MCP without recent human interaction.
    LlmAuto,
}

impl TrustLevel {
    /// Check if this trust level allows access to high-sensitivity secrets.
    pub fn allows_high_sensitivity(&self) -> bool {
        matches!(self, TrustLevel::HumanDirect | TrustLevel::LlmApproved)
    }
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustLevel::HumanDirect => write!(f, "HUMAN_DIRECT"),
            TrustLevel::LlmApproved => write!(f, "LLM_APPROVED"),
            TrustLevel::LlmAuto => write!(f, "LLM_AUTO"),
        }
    }
}

/// Lineage tracker for request chains.
pub struct LineageTracker {
    /// Active requests indexed by ID.
    requests: Arc<RwLock<HashMap<String, RequestLineage>>>,
    /// Completed requests for audit (limited history).
    completed: Arc<RwLock<Vec<RequestLineage>>>,
    /// Maximum completed requests to keep.
    max_completed: usize,
    /// Last human interaction timestamp.
    last_human_interaction: Arc<RwLock<Option<Instant>>>,
    /// Human interaction timeout.
    human_timeout: Duration,
}

impl LineageTracker {
    /// Create a new lineage tracker.
    pub fn new() -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            completed: Arc::new(RwLock::new(Vec::new())),
            max_completed: 1000,
            last_human_interaction: Arc::new(RwLock::new(None)),
            human_timeout: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create with custom settings.
    pub fn with_config(max_completed: usize, human_timeout_secs: u64) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            completed: Arc::new(RwLock::new(Vec::new())),
            max_completed,
            last_human_interaction: Arc::new(RwLock::new(None)),
            human_timeout: Duration::from_secs(human_timeout_secs),
        }
    }

    /// Record a human interaction (updates trust level calculation).
    pub fn record_human_interaction(&self) {
        *self.last_human_interaction.write() = Some(Instant::now());
    }

    /// Check if there was recent human interaction.
    pub fn has_recent_human_interaction(&self) -> bool {
        if let Some(last) = *self.last_human_interaction.read() {
            last.elapsed() < self.human_timeout
        } else {
            false
        }
    }

    /// Determine the trust level for a request.
    pub fn determine_trust_level(&self, client_info: &ClientInfo) -> TrustLevel {
        // CLI clients are always HUMAN_DIRECT
        if client_info.name.to_lowercase().contains("cli")
            || client_info.name.to_lowercase().contains("terminal")
            || client_info.is_human_direct
        {
            return TrustLevel::HumanDirect;
        }

        // MCP clients with recent human interaction are LLM_APPROVED
        if self.has_recent_human_interaction() {
            return TrustLevel::LlmApproved;
        }

        // Otherwise LLM_AUTO
        TrustLevel::LlmAuto
    }

    /// Start tracking a new request.
    pub fn start_request(&self, client_info: &ClientInfo) -> RequestLineage {
        let trust_level = self.determine_trust_level(client_info);
        let lineage = RequestLineage::new(client_info.clone(), trust_level);
        let id = lineage.id.clone();

        self.requests.write().insert(id, lineage.clone());
        lineage
    }

    /// Get an active request by ID.
    pub fn get(&self, lineage_id: &str) -> Option<RequestLineage> {
        self.requests.read().get(lineage_id).cloned()
    }

    /// Update a request with a tool call.
    pub fn add_tool_call(&self, lineage_id: &str, tool_call: ToolCall) {
        if let Some(lineage) = self.requests.write().get_mut(lineage_id) {
            lineage.tool_calls.push(tool_call);
        }
    }

    /// Record a secret access.
    pub fn record_secret_access(&self, lineage_id: &str, secret_name: &str) {
        if let Some(lineage) = self.requests.write().get_mut(lineage_id) {
            if !lineage.secrets_accessed.contains(&secret_name.to_string()) {
                lineage.secrets_accessed.push(secret_name.to_string());
            }
        }
    }

    /// Update a request with modified lineage data.
    pub fn update_request(&self, lineage: &RequestLineage) {
        if let Some(stored) = self.requests.write().get_mut(&lineage.id) {
            stored.tool_calls = lineage.tool_calls.clone();
            stored.secrets_accessed = lineage.secrets_accessed.clone();
        }
    }

    /// Complete a request.
    pub fn complete_request(&self, lineage_id: &str, result: RequestResult) {
        if let Some(mut lineage) = self.requests.write().remove(lineage_id) {
            lineage.completed_at = Some(Utc::now());
            lineage.result = Some(result);

            let mut completed = self.completed.write();
            completed.push(lineage);

            // Trim if over limit
            while completed.len() > self.max_completed {
                completed.remove(0);
            }
        }
    }

    /// Complete a request with updated lineage data.
    pub fn complete_request_with_lineage(&self, lineage: &RequestLineage, result: RequestResult) {
        // First update the stored version with modifications
        self.update_request(lineage);
        // Then complete it
        self.complete_request(&lineage.id, result);
    }

    /// Export all lineage data for audit.
    pub fn export(&self) -> Vec<RequestLineage> {
        let mut all = self.completed.read().clone();
        all.extend(self.requests.read().values().cloned());
        all.sort_by(|a, b| a.started_at.cmp(&b.started_at));
        all
    }

    /// Export as JSON for audit logging.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.export())
    }

    /// Get statistics about recent activity.
    pub fn stats(&self) -> LineageStats {
        let completed = self.completed.read();
        let active = self.requests.read();

        let mut tool_counts: HashMap<String, u64> = HashMap::new();
        let mut secrets_accessed: HashMap<String, u64> = HashMap::new();
        let mut trust_level_counts: HashMap<String, u64> = HashMap::new();

        for lineage in completed.iter().chain(active.values()) {
            *trust_level_counts
                .entry(lineage.trust_level.to_string())
                .or_default() += 1;

            for call in &lineage.tool_calls {
                *tool_counts.entry(call.tool_name.clone()).or_default() += 1;
            }

            for secret in &lineage.secrets_accessed {
                *secrets_accessed.entry(secret.clone()).or_default() += 1;
            }
        }

        LineageStats {
            total_requests: completed.len() + active.len(),
            active_requests: active.len(),
            tool_counts,
            secrets_accessed,
            trust_level_counts,
        }
    }
}

impl Default for LineageTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Lineage information for a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLineage {
    /// Unique lineage ID.
    pub id: String,
    /// Parent lineage ID (for chained requests).
    pub parent_id: Option<String>,
    /// Client that initiated the request.
    pub client: ClientInfo,
    /// Trust level for this request.
    pub trust_level: TrustLevel,
    /// When the request started.
    pub started_at: DateTime<Utc>,
    /// When the request completed.
    pub completed_at: Option<DateTime<Utc>>,
    /// Tool invocations within this request.
    pub tool_calls: Vec<ToolCall>,
    /// Secrets accessed during this request.
    pub secrets_accessed: Vec<String>,
    /// Result of the request.
    pub result: Option<RequestResult>,
}

impl RequestLineage {
    /// Create a new lineage.
    pub fn new(client: ClientInfo, trust_level: TrustLevel) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            parent_id: None,
            client,
            trust_level,
            started_at: Utc::now(),
            completed_at: None,
            tool_calls: Vec::new(),
            secrets_accessed: Vec::new(),
            result: None,
        }
    }

    /// Create a child lineage (for chained requests).
    pub fn child(&self, client: ClientInfo, trust_level: TrustLevel) -> Self {
        let mut child = Self::new(client, trust_level);
        child.parent_id = Some(self.id.clone());
        child
    }

    /// Add a tool call to the lineage.
    pub fn add_tool_call(&mut self, call: ToolCall) {
        self.tool_calls.push(call);
    }

    /// Record a secret access.
    pub fn record_secret_access(&mut self, secret_name: &str) {
        if !self.secrets_accessed.contains(&secret_name.to_string()) {
            self.secrets_accessed.push(secret_name.to_string());
        }
    }

    /// Mark the request as completed.
    pub fn complete(&mut self, result: RequestResult) {
        self.completed_at = Some(Utc::now());
        self.result = Some(result);
    }

    /// Get duration of the request (if completed).
    pub fn duration(&self) -> Option<chrono::Duration> {
        self.completed_at.map(|end| end - self.started_at)
    }
}

/// Information about the requesting client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client name (e.g., "Claude Code").
    pub name: String,
    /// Client version.
    pub version: String,
    /// Session ID (if available).
    pub session_id: Option<String>,
    /// Whether this is a direct human interaction.
    #[serde(default)]
    pub is_human_direct: bool,
}

impl ClientInfo {
    /// Create client info for an MCP client.
    pub fn mcp(name: &str, version: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            session_id: None,
            is_human_direct: false,
        }
    }

    /// Create client info for a human CLI user.
    pub fn human_cli() -> Self {
        Self {
            name: "phantom-cli".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            session_id: None,
            is_human_direct: true,
        }
    }
}

/// A tool invocation within a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Tool name.
    pub tool_name: String,
    /// Arguments (with secret values stripped).
    pub arguments: serde_json::Value,
    /// When the tool was called.
    pub timestamp: DateTime<Utc>,
    /// Whether the call succeeded.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
    /// Whether output was redacted.
    pub output_redacted: bool,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

impl ToolCall {
    /// Create a new tool call record.
    pub fn new(tool_name: &str, arguments: serde_json::Value) -> Self {
        Self {
            tool_name: tool_name.to_string(),
            arguments: Self::strip_secrets(arguments),
            timestamp: Utc::now(),
            success: false,
            error: None,
            output_redacted: false,
            duration_ms: 0,
        }
    }

    /// Strip secret values from arguments for logging.
    fn strip_secrets(args: serde_json::Value) -> serde_json::Value {
        match args {
            serde_json::Value::Object(mut map) => {
                // Strip any values that look like secrets
                for (key, value) in map.iter_mut() {
                    let key_lower = key.to_lowercase();
                    if key_lower.contains("secret")
                        || key_lower.contains("password")
                        || key_lower.contains("key")
                        || key_lower.contains("token")
                    {
                        if value.is_string() {
                            *value = serde_json::Value::String("[REDACTED]".to_string());
                        }
                    } else {
                        *value = Self::strip_secrets(value.take());
                    }
                }
                serde_json::Value::Object(map)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.into_iter().map(Self::strip_secrets).collect())
            }
            other => other,
        }
    }

    /// Mark as successful.
    pub fn success(mut self, duration_ms: u64, output_redacted: bool) -> Self {
        self.success = true;
        self.duration_ms = duration_ms;
        self.output_redacted = output_redacted;
        self
    }

    /// Mark as failed.
    pub fn failed(mut self, error: &str, duration_ms: u64) -> Self {
        self.success = false;
        self.error = Some(error.to_string());
        self.duration_ms = duration_ms;
        self
    }
}

/// Result of a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResult {
    /// Whether the request succeeded.
    pub success: bool,
    /// Summary of the result.
    pub summary: String,
    /// Whether any secrets were redacted from output.
    pub secrets_redacted: bool,
    /// Whether the request was blocked.
    pub blocked: bool,
    /// Block reason (if blocked).
    pub block_reason: Option<String>,
}

impl RequestResult {
    /// Create a successful result.
    pub fn success(summary: &str, secrets_redacted: bool) -> Self {
        Self {
            success: true,
            summary: summary.to_string(),
            secrets_redacted,
            blocked: false,
            block_reason: None,
        }
    }

    /// Create a failed result.
    pub fn failed(summary: &str) -> Self {
        Self {
            success: false,
            summary: summary.to_string(),
            secrets_redacted: false,
            blocked: false,
            block_reason: None,
        }
    }

    /// Create a blocked result.
    pub fn blocked(reason: &str) -> Self {
        Self {
            success: false,
            summary: "Request blocked".to_string(),
            secrets_redacted: false,
            blocked: true,
            block_reason: Some(reason.to_string()),
        }
    }
}

/// Statistics about lineage tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageStats {
    /// Total requests tracked.
    pub total_requests: usize,
    /// Currently active requests.
    pub active_requests: usize,
    /// Tool call counts.
    pub tool_counts: HashMap<String, u64>,
    /// Secret access counts.
    pub secrets_accessed: HashMap<String, u64>,
    /// Trust level distribution.
    pub trust_level_counts: HashMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_human_direct() {
        let tracker = LineageTracker::new();
        let client = ClientInfo::human_cli();
        let level = tracker.determine_trust_level(&client);
        assert_eq!(level, TrustLevel::HumanDirect);
    }

    #[test]
    fn test_trust_level_llm_auto() {
        let tracker = LineageTracker::new();
        let client = ClientInfo::mcp("Claude Code", "1.0.0");
        let level = tracker.determine_trust_level(&client);
        assert_eq!(level, TrustLevel::LlmAuto);
    }

    #[test]
    fn test_trust_level_llm_approved() {
        let tracker = LineageTracker::new();
        tracker.record_human_interaction();

        let client = ClientInfo::mcp("Claude Code", "1.0.0");
        let level = tracker.determine_trust_level(&client);
        assert_eq!(level, TrustLevel::LlmApproved);
    }

    #[test]
    fn test_lineage_tracking() {
        let tracker = LineageTracker::new();
        let client = ClientInfo::mcp("Claude Code", "1.0.0");

        let lineage = tracker.start_request(&client);
        let id = lineage.id.clone();

        tracker.add_tool_call(
            &id,
            ToolCall::new("vault_list", serde_json::json!({})).success(50, false),
        );
        tracker.record_secret_access(&id, "API_KEY");

        let result = RequestResult::success("Listed 5 secrets", false);
        tracker.complete_request(&id, result);

        let stats = tracker.stats();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.active_requests, 0);
        assert_eq!(*stats.tool_counts.get("vault_list").unwrap(), 1);
        assert_eq!(*stats.secrets_accessed.get("API_KEY").unwrap(), 1);
    }

    #[test]
    fn test_strip_secrets() {
        let args = serde_json::json!({
            "key": "API_KEY",
            "secret_value": "should_be_stripped",
            "password": "also_stripped",
            "normal_arg": "kept"
        });

        let stripped = ToolCall::strip_secrets(args);
        assert_eq!(stripped["key"], "[REDACTED]");
        assert_eq!(stripped["secret_value"], "[REDACTED]");
        assert_eq!(stripped["password"], "[REDACTED]");
        assert_eq!(stripped["normal_arg"], "kept");
    }

    #[test]
    fn test_high_sensitivity_access() {
        assert!(TrustLevel::HumanDirect.allows_high_sensitivity());
        assert!(TrustLevel::LlmApproved.allows_high_sensitivity());
        assert!(!TrustLevel::LlmAuto.allows_high_sensitivity());
    }

    #[test]
    fn test_export_json() {
        let tracker = LineageTracker::new();
        let client = ClientInfo::human_cli();
        let lineage = tracker.start_request(&client);
        tracker.complete_request(&lineage.id, RequestResult::success("done", false));

        let json = tracker.export_json().unwrap();
        // Trust level is serialized as "HumanDirect" (enum variant name)
        assert!(json.contains("HumanDirect") || json.contains("HUMAN_DIRECT"));
    }
}
