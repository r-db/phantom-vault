//! MCP protocol server implementation.
//!
//! Implements the Model Context Protocol for AI assistant integration.
//! Uses stdio transport (stdin/stdout JSON-RPC).

use crate::config::McpConfig;
use crate::lineage::{ClientInfo, LineageTracker, RequestResult};
use crate::tools::{ToolDefinition, ToolRegistry};
use crate::McpError;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// MCP protocol version.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// Server name.
const SERVER_NAME: &str = "phantom-vault";

/// Server version.
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// MCP server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Idle timeout before auto-lock.
    pub idle_timeout: Duration,
    /// Maximum concurrent requests.
    pub max_concurrent: usize,
    /// Request timeout.
    pub timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(15 * 60), // 15 minutes
            max_concurrent: 10,
            timeout: Duration::from_secs(300),
        }
    }
}

impl From<&McpConfig> for ServerConfig {
    fn from(config: &McpConfig) -> Self {
        Self {
            idle_timeout: Duration::from_secs(config.server.idle_timeout_minutes * 60),
            max_concurrent: 10,
            timeout: Duration::from_secs(300),
        }
    }
}

/// Session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Not initialized.
    Uninitialized,
    /// Active and ready.
    Active,
    /// Locked due to idle timeout.
    Locked,
    /// Shutdown requested.
    Shutdown,
}

/// MCP server for Phantom Vault.
pub struct McpServer {
    /// Server configuration.
    config: ServerConfig,
    /// MCP configuration.
    #[allow(dead_code)]
    mcp_config: Arc<McpConfig>,
    /// Tool registry.
    tools: Arc<ToolRegistry>,
    /// Lineage tracker.
    lineage: Arc<LineageTracker>,
    /// Session state.
    state: Arc<RwLock<SessionState>>,
    /// Last activity timestamp.
    last_activity: Arc<RwLock<Instant>>,
    /// Connected client info.
    client_info: Arc<RwLock<Option<ClientInfo>>>,
}

impl McpServer {
    /// Create a new MCP server.
    pub fn new(mcp_config: McpConfig) -> Self {
        let server_config = ServerConfig::from(&mcp_config);
        let lineage = Arc::new(LineageTracker::with_config(
            1000,
            mcp_config.server.human_interaction_timeout_seconds,
        ));

        Self {
            config: server_config,
            tools: Arc::new(ToolRegistry::new(mcp_config.clone())),
            mcp_config: Arc::new(mcp_config),
            lineage,
            state: Arc::new(RwLock::new(SessionState::Uninitialized)),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            client_info: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a new MCP server with a pre-built tool registry (e.g. one
    /// backed by a real vault via `ToolRegistry::with_vault`).
    pub fn with_registry(mcp_config: McpConfig, registry: ToolRegistry) -> Self {
        let server_config = ServerConfig::from(&mcp_config);
        let lineage = Arc::new(LineageTracker::with_config(
            1000,
            mcp_config.server.human_interaction_timeout_seconds,
        ));

        Self {
            config: server_config,
            tools: Arc::new(registry),
            mcp_config: Arc::new(mcp_config),
            lineage,
            state: Arc::new(RwLock::new(SessionState::Uninitialized)),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            client_info: Arc::new(RwLock::new(None)),
        }
    }

    /// Run the server using stdio transport.
    pub async fn run_stdio(&self) -> Result<(), McpError> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin);

        // Start idle timeout checker
        let state = self.state.clone();
        let last_activity = self.last_activity.clone();
        let idle_timeout = self.config.idle_timeout;

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;

                let current_state = *state.read();
                if current_state == SessionState::Shutdown {
                    break;
                }

                if current_state == SessionState::Active {
                    let elapsed = last_activity.read().elapsed();
                    if elapsed > idle_timeout {
                        tracing::info!("Idle timeout reached, locking session");
                        *state.write() = SessionState::Locked;
                    }
                }
            }
        });

        let mut line = String::new();
        loop {
            line.clear();

            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // EOF
                    tracing::info!("Received EOF, shutting down");
                    break;
                }
                Ok(_) => {
                    // Update last activity
                    *self.last_activity.write() = Instant::now();

                    // Handle the request
                    let response = self.handle_request(&line).await;

                    // Write response
                    stdout
                        .write_all(response.as_bytes())
                        .await
                        .map_err(|e| McpError::Server(e.to_string()))?;
                    stdout
                        .write_all(b"\n")
                        .await
                        .map_err(|e| McpError::Server(e.to_string()))?;
                    stdout
                        .flush()
                        .await
                        .map_err(|e| McpError::Server(e.to_string()))?;
                }
                Err(e) => {
                    tracing::error!("Error reading from stdin: {}", e);
                    break;
                }
            }

            // Check for shutdown
            if *self.state.read() == SessionState::Shutdown {
                break;
            }
        }

        *self.state.write() = SessionState::Shutdown;
        Ok(())
    }

    /// Handle a JSON-RPC request.
    pub async fn handle_request(&self, request: &str) -> String {
        let request: JsonRpcRequest = match serde_json::from_str(request.trim()) {
            Ok(r) => r,
            Err(e) => {
                return self.error_response(None, -32700, &format!("Parse error: {}", e));
            }
        };

        let response = match request.method.as_str() {
            "initialize" => self.handle_initialize(&request).await,
            "initialized" => self.handle_initialized(&request).await,
            "tools/list" => self.handle_tools_list(&request).await,
            "tools/call" => self.handle_tools_call(&request).await,
            "ping" => self.handle_ping(&request).await,
            "shutdown" => self.handle_shutdown(&request).await,
            _ => Err(McpError::Protocol(format!(
                "Unknown method: {}",
                request.method
            ))),
        };

        match response {
            Ok(result) => self.success_response(request.id, result),
            Err(e) => self.error_response(request.id, -32603, &e.to_string()),
        }
    }

    /// Handle initialize request.
    async fn handle_initialize(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, McpError> {
        let params: InitializeParams = serde_json::from_value(
            request.params.clone().unwrap_or(serde_json::Value::Null),
        )
        .map_err(|e| McpError::Protocol(format!("Invalid params: {}", e)))?;

        // Store client info
        let client_info = ClientInfo {
            name: params.client_info.name.clone(),
            version: params.client_info.version.clone(),
            session_id: None,
            is_human_direct: false,
        };
        *self.client_info.write() = Some(client_info);

        // Build capabilities
        let capabilities = ServerCapabilities {
            tools: Some(ToolsCapability {}),
        };

        let result = InitializeResult {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities,
            server_info: ServerInfo {
                name: SERVER_NAME.to_string(),
                version: SERVER_VERSION.to_string(),
            },
        };

        *self.state.write() = SessionState::Active;

        Ok(serde_json::to_value(result).unwrap())
    }

    /// Handle initialized notification.
    async fn handle_initialized(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, McpError> {
        // This is a notification, no response needed
        tracing::info!("Client initialization complete");
        Ok(serde_json::Value::Null)
    }

    /// Handle tools/list request.
    async fn handle_tools_list(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, McpError> {
        self.check_session_active()?;

        let tools = self.tools.list_tools();
        let mcp_tools: Vec<McpTool> = tools
            .into_iter()
            .map(|t| McpTool {
                name: t.name,
                description: Some(t.description),
                input_schema: t.input_schema,
            })
            .collect();

        let result = ToolsListResult { tools: mcp_tools };
        Ok(serde_json::to_value(result).unwrap())
    }

    /// Handle tools/call request.
    async fn handle_tools_call(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, McpError> {
        self.check_session_active()?;

        let params: ToolCallParams = serde_json::from_value(
            request.params.clone().unwrap_or(serde_json::Value::Null),
        )
        .map_err(|e| McpError::Protocol(format!("Invalid params: {}", e)))?;

        // Get client info
        let client_info = self
            .client_info
            .read()
            .clone()
            .unwrap_or_else(|| ClientInfo::mcp("unknown", "0.0.0"));

        // Start lineage tracking
        let mut lineage = self.lineage.start_request(&client_info);

        // Execute the tool
        let result = self
            .tools
            .execute(&params.name, params.arguments.unwrap_or_default(), &mut lineage)
            .await;

        // Complete lineage with updated data
        let request_result = match &result {
            Ok(output) => {
                if output.is_error {
                    RequestResult::failed(&output.content)
                } else {
                    RequestResult::success("Tool executed successfully", output.metadata.sanitized)
                }
            }
            Err(e) => RequestResult::failed(&e.to_string()),
        };
        self.lineage.complete_request_with_lineage(&lineage, request_result);

        match result {
            Ok(output) => {
                let content = vec![ToolResultContent {
                    content_type: "text".to_string(),
                    text: output.content,
                }];

                let result = ToolCallResult {
                    content,
                    is_error: Some(output.is_error),
                };

                Ok(serde_json::to_value(result).unwrap())
            }
            Err(e) => {
                let content = vec![ToolResultContent {
                    content_type: "text".to_string(),
                    text: format!("Error: {}", e),
                }];

                let result = ToolCallResult {
                    content,
                    is_error: Some(true),
                };

                Ok(serde_json::to_value(result).unwrap())
            }
        }
    }

    /// Handle ping request.
    async fn handle_ping(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, McpError> {
        Ok(serde_json::json!({}))
    }

    /// Handle shutdown request.
    async fn handle_shutdown(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, McpError> {
        *self.state.write() = SessionState::Shutdown;
        Ok(serde_json::json!({}))
    }

    /// Check if session is active.
    fn check_session_active(&self) -> Result<(), McpError> {
        match *self.state.read() {
            SessionState::Active => Ok(()),
            SessionState::Locked => Err(McpError::Server(
                "Session locked due to idle timeout. Please re-authenticate.".to_string(),
            )),
            SessionState::Uninitialized => Err(McpError::Server(
                "Session not initialized. Call 'initialize' first.".to_string(),
            )),
            SessionState::Shutdown => Err(McpError::Server("Server is shutting down.".to_string())),
        }
    }

    /// Record human interaction (for trust level).
    pub fn record_human_interaction(&self) {
        self.lineage.record_human_interaction();
    }

    /// Unlock the session after it was locked.
    pub fn unlock(&self) {
        *self.state.write() = SessionState::Active;
        *self.last_activity.write() = Instant::now();
    }

    /// Get current session state.
    pub fn state(&self) -> SessionState {
        *self.state.read()
    }

    /// Get lineage statistics.
    pub fn lineage_stats(&self) -> crate::lineage::LineageStats {
        self.lineage.stats()
    }

    /// Build a success response.
    fn success_response(&self, id: Option<serde_json::Value>, result: serde_json::Value) -> String {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        };
        serde_json::to_string(&response).unwrap()
    }

    /// Build an error response.
    fn error_response(&self, id: Option<serde_json::Value>, code: i32, message: &str) -> String {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        };
        serde_json::to_string(&response).unwrap()
    }
}

// JSON-RPC types

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

// MCP protocol types

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
    capabilities: ClientCapabilities,
    #[serde(rename = "clientInfo")]
    client_info: McpClientInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientCapabilities {
    #[serde(default)]
    experimental: Option<serde_json::Value>,
    #[serde(default)]
    sampling: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpClientInfo {
    name: String,
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
    capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    server_info: ServerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<ToolsCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolsCapability {}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerInfo {
    name: String,
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolsListResult {
    tools: Vec<McpTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct McpTool {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "inputSchema")]
    input_schema: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolCallResult {
    content: Vec<ToolResultContent>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    is_error: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolResultContent {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

/// Server capabilities advertised to clients (exported for external use).
#[derive(Debug, Clone)]
pub struct ExportedCapabilities {
    /// Protocol version.
    pub protocol_version: String,
    /// Available tools.
    pub tools: Vec<ToolDefinition>,
    /// Whether lineage tracking is enabled.
    pub lineage_tracking: bool,
}

impl McpServer {
    /// Get server capabilities (for external use).
    pub fn capabilities(&self) -> ExportedCapabilities {
        ExportedCapabilities {
            protocol_version: PROTOCOL_VERSION.to_string(),
            tools: self.tools.list_tools(),
            lineage_tracking: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_server() -> McpServer {
        McpServer::new(McpConfig::default())
    }

    #[tokio::test]
    async fn test_initialize() {
        let server = create_test_server();

        let request = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }"#;

        let response = server.handle_request(request).await;
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();

        assert!(parsed.result.is_some());
        assert!(parsed.error.is_none());

        let result = parsed.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
    }

    #[tokio::test]
    async fn test_tools_list_before_initialize() {
        let server = create_test_server();

        let request = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }"#;

        let response = server.handle_request(request).await;
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();

        // Should fail because session is not initialized
        assert!(parsed.error.is_some());
        assert!(parsed.error.unwrap().message.contains("not initialized"));
    }

    #[tokio::test]
    async fn test_tools_list_after_initialize() {
        let server = create_test_server();

        // Initialize first
        let init_request = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }"#;
        server.handle_request(init_request).await;

        // Now list tools
        let request = r#"{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }"#;

        let response = server.handle_request(request).await;
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();

        assert!(parsed.result.is_some());
        let tools = &parsed.result.unwrap()["tools"];
        assert!(tools.is_array());
        assert!(!tools.as_array().unwrap().is_empty());

        // Check that expected tools are present
        let tool_names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();

        assert!(tool_names.contains(&"vault_list"));
        assert!(tool_names.contains(&"vault_run"));
        assert!(tool_names.contains(&"vault_exists"));
        assert!(tool_names.contains(&"vault_masked"));
        assert!(tool_names.contains(&"vault_health"));
        assert!(tool_names.contains(&"vault_rotate"));
    }

    #[tokio::test]
    async fn test_tools_call() {
        let server = create_test_server();

        // Initialize first
        let init_request = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }"#;
        server.handle_request(init_request).await;

        // Call vault_list
        let request = r#"{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "vault_list",
                "arguments": {}
            }
        }"#;

        let response = server.handle_request(request).await;
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();

        assert!(parsed.result.is_some());
        let result = parsed.result.unwrap();
        assert!(result["content"].is_array());
        assert!(!result["content"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_auto_lock_after_idle() {
        let mut config = McpConfig::default();
        config.server.idle_timeout_minutes = 0; // Immediate timeout for testing

        let server = McpServer::new(config);

        // Initialize
        let init_request = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }"#;
        server.handle_request(init_request).await;

        // Force the state to locked (simulating idle timeout)
        *server.state.write() = SessionState::Locked;

        // Try to call a tool
        let request = r#"{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }"#;

        let response = server.handle_request(request).await;
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();

        assert!(parsed.error.is_some());
        assert!(parsed.error.unwrap().message.contains("locked"));
    }

    #[tokio::test]
    async fn test_unlock_after_lock() {
        let server = create_test_server();

        // Initialize
        let init_request = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }"#;
        server.handle_request(init_request).await;

        // Lock the session
        *server.state.write() = SessionState::Locked;
        assert_eq!(server.state(), SessionState::Locked);

        // Unlock
        server.unlock();
        assert_eq!(server.state(), SessionState::Active);

        // Should be able to call tools now
        let request = r#"{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }"#;

        let response = server.handle_request(request).await;
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();
        assert!(parsed.result.is_some());
    }

    #[tokio::test]
    async fn test_invalid_json() {
        let server = create_test_server();

        let response = server.handle_request("not valid json").await;
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();

        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, -32700);
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let server = create_test_server();

        let request = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "unknown_method"
        }"#;

        let response = server.handle_request(request).await;
        let parsed: JsonRpcResponse = serde_json::from_str(&response).unwrap();

        assert!(parsed.error.is_some());
        assert!(parsed.error.unwrap().message.contains("Unknown method"));
    }

    #[tokio::test]
    async fn test_lineage_stats() {
        let server = create_test_server();

        // Initialize
        let init_request = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }"#;
        server.handle_request(init_request).await;

        // Call some tools
        let request = r#"{
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "vault_list",
                "arguments": {}
            }
        }"#;
        server.handle_request(request).await;

        // Check stats
        let stats = server.lineage_stats();
        assert_eq!(stats.total_requests, 1);
        assert!(stats.tool_counts.get("vault_list").is_some());
    }
}
