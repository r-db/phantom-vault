//! MCP Server implementation
//!
//! Handles the Model Context Protocol for Claude Code integration

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::handlers::{ToolCallArgs, ToolHandler, ToolResult};
use crate::registry::ToolRegistry;
use crate::state::SharedVaultState;

/// JSON-RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
    pub id: Option<Value>,
}

/// JSON-RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Option<Value>,
}

/// JSON-RPC error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }
}

/// Error codes
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    pub const VAULT_LOCKED: i32 = -32000;
    pub const SECRET_NOT_FOUND: i32 = -32001;
    pub const CREDENTIAL_LEAK: i32 = -32002;
}

/// MCP Server
pub struct McpServer {
    /// Tool registry
    registry: ToolRegistry,
    /// Tool handler
    handler: ToolHandler,
    /// Vault state
    state: SharedVaultState,
    /// Server info
    server_info: ServerInfo,
}

/// Server info for initialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self {
            name: "vault-secrets".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl McpServer {
    /// Create a new MCP server
    pub fn new(state: SharedVaultState) -> Self {
        Self {
            registry: ToolRegistry::new(),
            handler: ToolHandler::new(state.clone()),
            state,
            server_info: ServerInfo::default(),
        }
    }

    /// Handle a JSON-RPC request
    pub async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        debug!("Handling request: {}", request.method);

        match request.method.as_str() {
            "initialize" => self.handle_initialize(request.id, request.params).await,
            "initialized" => self.handle_initialized(request.id).await,
            "tools/list" => self.handle_tools_list(request.id).await,
            "tools/call" => self.handle_tools_call(request.id, request.params).await,
            "ping" => self.handle_ping(request.id).await,
            _ => JsonRpcResponse::error(
                request.id,
                error_codes::METHOD_NOT_FOUND,
                format!("Method not found: {}", request.method),
            ),
        }
    }

    /// Handle initialize request
    async fn handle_initialize(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        info!("MCP server initializing");

        JsonRpcResponse::success(
            id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {
                        "listChanged": true
                    }
                },
                "serverInfo": {
                    "name": self.server_info.name,
                    "version": self.server_info.version
                }
            }),
        )
    }

    /// Handle initialized notification
    async fn handle_initialized(&self, id: Option<Value>) -> JsonRpcResponse {
        info!("MCP server initialized");
        JsonRpcResponse::success(id, json!({}))
    }

    /// Handle tools/list request
    async fn handle_tools_list(&self, id: Option<Value>) -> JsonRpcResponse {
        let tools: Vec<Value> = self
            .registry
            .get_all()
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema
                })
            })
            .collect();

        JsonRpcResponse::success(id, json!({ "tools": tools }))
    }

    /// Handle tools/call request
    async fn handle_tools_call(&self, id: Option<Value>, params: Option<Value>) -> JsonRpcResponse {
        let params = match params {
            Some(p) => p,
            None => {
                return JsonRpcResponse::error(
                    id,
                    error_codes::INVALID_PARAMS,
                    "Missing params",
                );
            }
        };

        let tool_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(n) => n.to_string(),
            None => {
                return JsonRpcResponse::error(
                    id,
                    error_codes::INVALID_PARAMS,
                    "Missing tool name",
                );
            }
        };

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));

        let args: ToolCallArgs = match serde_json::from_value(json!({ "args": arguments })) {
            Ok(a) => ToolCallArgs {
                args: arguments.as_object().cloned().unwrap_or_default(),
            },
            Err(e) => {
                return JsonRpcResponse::error(
                    id,
                    error_codes::INVALID_PARAMS,
                    format!("Invalid arguments: {}", e),
                );
            }
        };

        // Check if vault is unlocked (for most tools)
        if !tool_name.starts_with("vault_") || tool_name != "vault_list_secrets" {
            let state = self.state.read().await;
            if !state.is_unlocked() {
                return JsonRpcResponse::error(
                    id,
                    error_codes::VAULT_LOCKED,
                    "Vault is locked. Please unlock the vault first.",
                );
            }
        }

        // Execute tool
        match self.handler.handle(&tool_name, args).await {
            Ok(result) => {
                let content = if result.success {
                    json!([{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&result.content).unwrap_or_default()
                    }])
                } else {
                    json!([{
                        "type": "text",
                        "text": result.error.unwrap_or_else(|| "Unknown error".to_string())
                    }])
                };

                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": content,
                        "isError": !result.success
                    }),
                )
            }
            Err(e) => {
                let (code, message) = match e {
                    vault_core::McpError::VaultLocked => {
                        (error_codes::VAULT_LOCKED, "Vault is locked".to_string())
                    }
                    vault_core::McpError::SecretNotFound(ref s) => {
                        (error_codes::SECRET_NOT_FOUND, format!("Secret not found: {}", s))
                    }
                    vault_core::McpError::CredentialLeakBlocked => {
                        (error_codes::CREDENTIAL_LEAK, "Credential leak detected and blocked".to_string())
                    }
                    _ => (error_codes::INTERNAL_ERROR, e.to_string()),
                };

                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": message
                        }],
                        "isError": true
                    }),
                )
            }
        }
    }

    /// Handle ping request
    async fn handle_ping(&self, id: Option<Value>) -> JsonRpcResponse {
        JsonRpcResponse::success(id, json!({}))
    }

    /// Run the server on stdio
    pub async fn run_stdio(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting MCP server on stdio");

        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let reader = TokioBufReader::new(stdin);
        let mut lines = reader.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }

            debug!("Received: {}", line);

            let request: JsonRpcRequest = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    let response = JsonRpcResponse::error(
                        None,
                        error_codes::PARSE_ERROR,
                        format!("Parse error: {}", e),
                    );
                    let response_str = serde_json::to_string(&response)?;
                    stdout.write_all(response_str.as_bytes()).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
                    continue;
                }
            };

            let response = self.handle_request(request).await;
            let response_str = serde_json::to_string(&response)?;

            debug!("Sending: {}", response_str);

            stdout.write_all(response_str.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }

        Ok(())
    }
}

/// Run the MCP server
pub async fn run_server(state: SharedVaultState) -> Result<(), Box<dyn std::error::Error>> {
    let server = McpServer::new(state);
    server.run_stdio().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_rpc_response_success() {
        let response = JsonRpcResponse::success(Some(json!(1)), json!({"result": "ok"}));
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_json_rpc_response_error() {
        let response = JsonRpcResponse::error(Some(json!(1)), -32600, "Invalid request");
        assert!(response.result.is_none());
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32600);
    }

    #[test]
    fn test_parse_request() {
        let json = r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.method, "tools/list");
        assert_eq!(request.id, Some(json!(1)));
    }
}
