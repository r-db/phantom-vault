//! Tool handlers for MCP server
//!
//! Handles tool execution with credential injection and output filtering

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Stdio;
use tokio::process::Command;
use uuid::Uuid;

use vault_core::{
    audit::{log_leak_blocked, log_secret_access, AuditEvent},
    filter::ScanResult,
    McpError, McpResult,
};

use crate::state::SharedVaultState;

/// Tool call arguments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallArgs {
    /// Arguments as key-value pairs
    #[serde(flatten)]
    pub args: HashMap<String, Value>,
}

impl ToolCallArgs {
    /// Get a string argument
    pub fn get_string(&self, key: &str) -> Option<String> {
        self.args.get(key).and_then(|v| v.as_str()).map(String::from)
    }

    /// Get a required string argument
    pub fn require_string(&self, key: &str) -> McpResult<String> {
        self.get_string(key)
            .ok_or_else(|| McpError::InvalidArguments(format!("Missing required argument: {}", key)))
    }

    /// Get an optional string argument
    pub fn opt_string(&self, key: &str) -> Option<String> {
        self.get_string(key)
    }

    /// Get a string array argument
    pub fn get_string_array(&self, key: &str) -> Vec<String> {
        self.args
            .get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get object argument
    pub fn get_object(&self, key: &str) -> Option<&serde_json::Map<String, Value>> {
        self.args.get(key).and_then(|v| v.as_object())
    }
}

/// Tool execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Whether execution was successful
    pub success: bool,
    /// Result content (already filtered for credential leaks)
    pub content: Value,
    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Whether credentials were injected
    #[serde(default)]
    pub credentials_injected: bool,
    /// Number of credential references injected
    #[serde(default)]
    pub injected_count: usize,
}

impl ToolResult {
    /// Create a successful result
    pub fn success(content: Value) -> Self {
        Self {
            success: true,
            content,
            error: None,
            credentials_injected: false,
            injected_count: 0,
        }
    }

    /// Create an error result
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            content: Value::Null,
            error: Some(message.into()),
            credentials_injected: false,
            injected_count: 0,
        }
    }

    /// Mark as having injected credentials
    pub fn with_injection(mut self, count: usize) -> Self {
        self.credentials_injected = true;
        self.injected_count = count;
        self
    }
}

/// Handle tool calls
pub struct ToolHandler {
    /// Shared vault state
    state: SharedVaultState,
}

impl ToolHandler {
    /// Create a new tool handler
    pub fn new(state: SharedVaultState) -> Self {
        Self { state }
    }

    /// Handle a tool call
    pub async fn handle(&self, tool_name: &str, args: ToolCallArgs) -> McpResult<ToolResult> {
        // Touch activity to prevent auto-lock
        {
            let mut state = self.state.write().await;
            state.touch();
        }

        match tool_name {
            "vault_list_secrets" => self.handle_list_secrets(args).await,
            "vault_get_secret_info" => self.handle_get_secret_info(args).await,
            "vault_check_secret_status" => self.handle_check_secret_status(args).await,
            "vault_execute_with_credential" => self.handle_execute_with_credential(args).await,
            "vault_http_request" => self.handle_http_request(args).await,
            "vault_database_query" => self.handle_database_query(args).await,
            "vault_git_operation" => self.handle_git_operation(args).await,
            "vault_record_usage" => self.handle_record_usage(args).await,
            _ => Err(McpError::ToolNotFound(tool_name.to_string())),
        }
    }

    /// List secrets (metadata only)
    async fn handle_list_secrets(&self, args: ToolCallArgs) -> McpResult<ToolResult> {
        let state = self.state.read().await;
        let data = state.data().map_err(|_| McpError::VaultLocked)?;

        let tag_filter = args.opt_string("tag");
        let type_filter = args.opt_string("type");

        let secrets: Vec<Value> = data
            .entries
            .iter()
            .filter(|e| {
                // Filter by tag
                if let Some(ref tag) = tag_filter {
                    if !e.tags.contains(tag) {
                        return false;
                    }
                }
                // Filter by type (simplified check)
                if let Some(ref t) = type_filter {
                    let type_name = format!("{:?}", e.secret_type);
                    if !type_name.to_lowercase().contains(&t.to_lowercase()) {
                        return false;
                    }
                }
                true
            })
            .map(|e| {
                json!({
                    "reference": e.reference,
                    "type": format!("{:?}", e.secret_type).split('{').next().unwrap_or("Unknown").trim(),
                    "description": e.description,
                    "tags": e.tags,
                    "created_at": e.created_at.to_rfc3339(),
                    "expires_at": e.expires_at.map(|d| d.to_rfc3339()),
                    "is_expired": e.is_expired(),
                    "needs_rotation": e.needs_rotation(),
                })
            })
            .collect();

        Ok(ToolResult::success(json!({
            "secrets": secrets,
            "count": secrets.len()
        })))
    }

    /// Get secret metadata (NOT the value)
    async fn handle_get_secret_info(&self, args: ToolCallArgs) -> McpResult<ToolResult> {
        let reference = args.require_string("reference")?;

        let state = self.state.read().await;
        let data = state.data().map_err(|_| McpError::VaultLocked)?;

        let entry = data
            .find_by_reference(&reference)
            .ok_or_else(|| McpError::SecretNotFound(reference.clone()))?;

        Ok(ToolResult::success(json!({
            "reference": entry.reference,
            "id": entry.id.to_string(),
            "type": format!("{:?}", entry.secret_type),
            "description": entry.description,
            "tags": entry.tags,
            "created_at": entry.created_at.to_rfc3339(),
            "updated_at": entry.updated_at.to_rfc3339(),
            "expires_at": entry.expires_at.map(|d| d.to_rfc3339()),
            "days_until_expiration": entry.days_until_expiration(),
            "rotation_reminder_days": entry.rotation_reminder_days,
            "last_rotated_at": entry.last_rotated_at.map(|d| d.to_rfc3339()),
            "needs_rotation": entry.needs_rotation(),
            "is_expired": entry.is_expired(),
            "usage_limit": entry.usage_limit,
            "usage_count": entry.usage_count,
            "is_usage_exceeded": entry.is_usage_exceeded(),
            "last_used_at": entry.last_used_at.map(|d| d.to_rfc3339()),
            "allowed_tools": entry.allowed_tools,
            "auto_inject": entry.auto_inject,
        })))
    }

    /// Check secret status
    async fn handle_check_secret_status(&self, args: ToolCallArgs) -> McpResult<ToolResult> {
        let reference = args.require_string("reference")?;

        let state = self.state.read().await;
        let data = state.data().map_err(|_| McpError::VaultLocked)?;

        let entry = data
            .find_by_reference(&reference)
            .ok_or_else(|| McpError::SecretNotFound(reference.clone()))?;

        let mut warnings = Vec::new();

        if entry.is_expired() {
            warnings.push("Secret has EXPIRED");
        } else if let Some(days) = entry.days_until_expiration() {
            if days <= 7 {
                warnings.push("Secret expires in less than 7 days");
            } else if days <= 14 {
                warnings.push("Secret expires in less than 14 days");
            }
        }

        if entry.needs_rotation() {
            warnings.push("Secret rotation is due");
        }

        if entry.is_usage_exceeded() {
            warnings.push("Secret usage limit has been exceeded");
        }

        Ok(ToolResult::success(json!({
            "reference": reference,
            "is_healthy": warnings.is_empty(),
            "is_expired": entry.is_expired(),
            "needs_rotation": entry.needs_rotation(),
            "is_usage_exceeded": entry.is_usage_exceeded(),
            "warnings": warnings,
            "days_until_expiration": entry.days_until_expiration(),
            "usage_count": entry.usage_count,
            "usage_limit": entry.usage_limit,
        })))
    }

    /// Execute command with credential injected
    async fn handle_execute_with_credential(&self, args: ToolCallArgs) -> McpResult<ToolResult> {
        let credential_ref = args.require_string("credential_ref")?;
        let env_var_name = args.require_string("env_var_name")?;
        let command = args.require_string("command")?;
        let working_dir = args.opt_string("working_dir");

        // Get credential value
        let (secret_value, secret_id) = {
            let state = self.state.read().await;
            let value = state
                .get_secret_value(&credential_ref)
                .map_err(|_| McpError::SecretNotFound(credential_ref.clone()))?;
            let id = state
                .get_secret_id(&credential_ref)
                .map_err(|_| McpError::SecretNotFound(credential_ref.clone()))?;
            (value, id)
        };

        // Log the access
        {
            let state = self.state.read().await;
            let _ = log_secret_access(
                state.audit_logger(),
                &credential_ref,
                &secret_id,
                Some("vault_execute_with_credential"),
            )
            .await;
        }

        // Execute command with injected credential
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(&command);
        cmd.env(&env_var_name, &secret_value);

        if let Some(dir) = working_dir {
            cmd.current_dir(dir);
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = cmd
            .output()
            .await
            .map_err(|e| McpError::ExecutionError(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Filter output for credential leaks
        let (filtered_stdout, stdout_leaked) = self.filter_output(&stdout, &credential_ref).await?;
        let (filtered_stderr, stderr_leaked) = self.filter_output(&stderr, &credential_ref).await?;

        if stdout_leaked || stderr_leaked {
            return Err(McpError::CredentialLeakBlocked);
        }

        Ok(ToolResult::success(json!({
            "exit_code": output.status.code(),
            "stdout": filtered_stdout,
            "stderr": filtered_stderr,
            "success": output.status.success(),
        }))
        .with_injection(1))
    }

    /// Make HTTP request with auth
    async fn handle_http_request(&self, args: ToolCallArgs) -> McpResult<ToolResult> {
        let method = args.require_string("method")?;
        let url = args.require_string("url")?;
        let auth_ref = args.require_string("auth_ref")?;
        let auth_type = args.opt_string("auth_type").unwrap_or_else(|| "bearer".to_string());
        let auth_header_name = args.opt_string("auth_header_name");
        let body = args.opt_string("body");
        let headers = args.get_object("headers");

        // Get credential value
        let (secret_value, secret_id) = {
            let state = self.state.read().await;
            let value = state
                .get_secret_value(&auth_ref)
                .map_err(|_| McpError::SecretNotFound(auth_ref.clone()))?;
            let id = state
                .get_secret_id(&auth_ref)
                .map_err(|_| McpError::SecretNotFound(auth_ref.clone()))?;
            (value, id)
        };

        // Log the access
        {
            let state = self.state.read().await;
            let _ = log_secret_access(
                state.audit_logger(),
                &auth_ref,
                &secret_id,
                Some("vault_http_request"),
            )
            .await;
        }

        // Build curl command (using curl for simplicity)
        let mut curl_args = vec!["-s".to_string(), "-X".to_string(), method.clone()];

        // Add auth header
        match auth_type.as_str() {
            "bearer" => {
                curl_args.push("-H".to_string());
                curl_args.push(format!("Authorization: Bearer {}", secret_value));
            }
            "header" => {
                let header_name = auth_header_name.unwrap_or_else(|| "X-API-Key".to_string());
                curl_args.push("-H".to_string());
                curl_args.push(format!("{}: {}", header_name, secret_value));
            }
            "basic" => {
                curl_args.push("-H".to_string());
                curl_args.push(format!("Authorization: Basic {}", secret_value));
            }
            _ => {
                return Err(McpError::InvalidArguments(format!(
                    "Invalid auth_type: {}",
                    auth_type
                )));
            }
        }

        // Add custom headers
        if let Some(hdrs) = headers {
            for (key, value) in hdrs {
                if let Some(v) = value.as_str() {
                    curl_args.push("-H".to_string());
                    curl_args.push(format!("{}: {}", key, v));
                }
            }
        }

        // Add body
        if let Some(b) = body {
            curl_args.push("-d".to_string());
            curl_args.push(b);
        }

        // Add URL
        curl_args.push(url);

        // Execute
        let output = Command::new("curl")
            .args(&curl_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| McpError::ExecutionError(e.to_string()))?;

        let response = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Filter output for credential leaks
        let (filtered_response, leaked) = self.filter_output(&response, &auth_ref).await?;

        if leaked {
            return Err(McpError::CredentialLeakBlocked);
        }

        Ok(ToolResult::success(json!({
            "response": filtered_response,
            "success": output.status.success(),
        }))
        .with_injection(1))
    }

    /// Execute database query (placeholder - would need actual DB driver integration)
    async fn handle_database_query(&self, args: ToolCallArgs) -> McpResult<ToolResult> {
        let connection_ref = args.require_string("connection_ref")?;
        let query = args.require_string("query")?;
        let params = args.get_string_array("params");

        // Get connection string
        let (connection_string, secret_id) = {
            let state = self.state.read().await;
            let value = state
                .get_secret_value(&connection_ref)
                .map_err(|_| McpError::SecretNotFound(connection_ref.clone()))?;
            let id = state
                .get_secret_id(&connection_ref)
                .map_err(|_| McpError::SecretNotFound(connection_ref.clone()))?;
            (value, id)
        };

        // Log the access
        {
            let state = self.state.read().await;
            let _ = log_secret_access(
                state.audit_logger(),
                &connection_ref,
                &secret_id,
                Some("vault_database_query"),
            )
            .await;
        }

        // For now, use psql if it looks like a postgres connection
        // In a real implementation, you'd use proper database drivers
        if connection_string.starts_with("postgres") {
            let mut cmd = Command::new("psql");
            cmd.arg(&connection_string);
            cmd.arg("-c").arg(&query);
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            let output = cmd
                .output()
                .await
                .map_err(|e| McpError::ExecutionError(e.to_string()))?;

            let result = String::from_utf8_lossy(&output.stdout).to_string();

            // Filter output
            let (filtered_result, leaked) = self.filter_output(&result, &connection_ref).await?;

            if leaked {
                return Err(McpError::CredentialLeakBlocked);
            }

            return Ok(ToolResult::success(json!({
                "result": filtered_result,
                "success": output.status.success(),
            }))
            .with_injection(1));
        }

        // Unsupported database type
        Ok(ToolResult::error("Database type not supported. Only PostgreSQL is currently supported."))
    }

    /// Git operation with SSH key
    async fn handle_git_operation(&self, args: ToolCallArgs) -> McpResult<ToolResult> {
        let ssh_key_ref = args.require_string("ssh_key_ref")?;
        let operation = args.require_string("operation")?;
        let repository = args.require_string("repository")?;
        let branch = args.opt_string("branch");

        // Get SSH key
        let (ssh_key, secret_id) = {
            let state = self.state.read().await;
            let value = state
                .get_secret_value(&ssh_key_ref)
                .map_err(|_| McpError::SecretNotFound(ssh_key_ref.clone()))?;
            let id = state
                .get_secret_id(&ssh_key_ref)
                .map_err(|_| McpError::SecretNotFound(ssh_key_ref.clone()))?;
            (value, id)
        };

        // Log the access
        {
            let state = self.state.read().await;
            let _ = log_secret_access(
                state.audit_logger(),
                &ssh_key_ref,
                &secret_id,
                Some("vault_git_operation"),
            )
            .await;
        }

        // Write SSH key to temporary file
        let temp_key_path = format!("/tmp/vault-ssh-key-{}", uuid::Uuid::new_v4());
        tokio::fs::write(&temp_key_path, &ssh_key)
            .await
            .map_err(|e| McpError::ExecutionError(e.to_string()))?;
        tokio::fs::set_permissions(&temp_key_path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|e| McpError::ExecutionError(e.to_string()))?;

        // Build git command
        let git_ssh_command = format!("ssh -i {} -o StrictHostKeyChecking=no", temp_key_path);

        let mut git_args = match operation.as_str() {
            "clone" => {
                let mut args = vec!["clone".to_string()];
                if let Some(ref b) = branch {
                    args.push("-b".to_string());
                    args.push(b.clone());
                }
                args.push(repository.clone());
                args
            }
            "pull" => vec!["-C".to_string(), repository.clone(), "pull".to_string()],
            "push" => vec!["-C".to_string(), repository.clone(), "push".to_string()],
            "fetch" => vec!["-C".to_string(), repository.clone(), "fetch".to_string()],
            _ => {
                // Clean up temp key
                let _ = tokio::fs::remove_file(&temp_key_path).await;
                return Err(McpError::InvalidArguments(format!(
                    "Invalid git operation: {}",
                    operation
                )));
            }
        };

        let output = Command::new("git")
            .args(&git_args)
            .env("GIT_SSH_COMMAND", git_ssh_command)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| McpError::ExecutionError(e.to_string()))?;

        // Clean up temp key
        let _ = tokio::fs::remove_file(&temp_key_path).await;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Filter output
        let (filtered_stdout, _) = self.filter_output(&stdout, &ssh_key_ref).await?;
        let (filtered_stderr, _) = self.filter_output(&stderr, &ssh_key_ref).await?;

        Ok(ToolResult::success(json!({
            "stdout": filtered_stdout,
            "stderr": filtered_stderr,
            "success": output.status.success(),
        }))
        .with_injection(1))
    }

    /// Record secret usage
    async fn handle_record_usage(&self, args: ToolCallArgs) -> McpResult<ToolResult> {
        let reference = args.require_string("reference")?;

        let mut state = self.state.write().await;
        let data = state.data_mut().map_err(|_| McpError::VaultLocked)?;

        let entry = data
            .entries
            .iter_mut()
            .find(|e| e.reference == reference)
            .ok_or_else(|| McpError::SecretNotFound(reference.clone()))?;

        entry.record_usage();

        // Save the updated vault
        drop(data);
        state.save().await.map_err(|e| McpError::ExecutionError(e.to_string()))?;

        Ok(ToolResult::success(json!({
            "reference": reference,
            "usage_count": state.data().unwrap().find_by_reference(&reference).unwrap().usage_count,
            "recorded": true,
        })))
    }

    /// Filter output for credential leaks
    async fn filter_output(
        &self,
        output: &str,
        credential_ref: &str,
    ) -> McpResult<(String, bool)> {
        let state = self.state.read().await;
        let filter = state.filter().map_err(|_| McpError::VaultLocked)?;

        let result = filter.scan_and_redact(output);

        if result.has_credentials {
            // Log the blocked leak
            for pattern_name in &result.detected_types {
                let _ = log_leak_blocked(
                    state.audit_logger(),
                    "output_filter",
                    pattern_name,
                    Some(credential_ref),
                )
                .await;
            }
        }

        Ok((result.redacted_output, result.has_credentials))
    }
}

// Unix-specific imports for file permissions
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_tool_call_args_get_string() {
        let args = ToolCallArgs {
            args: {
                let mut map = HashMap::new();
                map.insert("name".to_string(), json!("test-value"));
                map.insert("count".to_string(), json!(42));
                map
            },
        };

        assert_eq!(args.get_string("name"), Some("test-value".to_string()));
        assert_eq!(args.get_string("missing"), None);
        assert_eq!(args.get_string("count"), None); // Not a string
    }

    #[test]
    fn test_tool_call_args_require_string() {
        let args = ToolCallArgs {
            args: {
                let mut map = HashMap::new();
                map.insert("present".to_string(), json!("value"));
                map
            },
        };

        assert!(args.require_string("present").is_ok());
        assert!(args.require_string("missing").is_err());
    }

    #[test]
    fn test_tool_call_args_get_string_array() {
        let args = ToolCallArgs {
            args: {
                let mut map = HashMap::new();
                map.insert("tags".to_string(), json!(["a", "b", "c"]));
                map.insert("empty".to_string(), json!([]));
                map
            },
        };

        assert_eq!(args.get_string_array("tags"), vec!["a", "b", "c"]);
        assert_eq!(args.get_string_array("empty"), Vec::<String>::new());
        assert_eq!(args.get_string_array("missing"), Vec::<String>::new());
    }

    #[test]
    fn test_tool_result_success() {
        let result = ToolResult::success(json!({"data": "test"}));
        assert!(result.success);
        assert!(result.error.is_none());
        assert!(!result.credentials_injected);
    }

    #[test]
    fn test_tool_result_error() {
        let result = ToolResult::error("Something went wrong");
        assert!(!result.success);
        assert_eq!(result.error, Some("Something went wrong".to_string()));
    }

    #[test]
    fn test_tool_result_with_injection() {
        let result = ToolResult::success(json!({})).with_injection(3);
        assert!(result.credentials_injected);
        assert_eq!(result.injected_count, 3);
    }
}
