//! Tool registry for MCP server
//!
//! Defines the available tools and their schemas

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

/// Tool definition for MCP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Tool name
    pub name: String,
    /// Tool description
    pub description: String,
    /// Input schema (JSON Schema)
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// Parameter definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterDef {
    /// Parameter type
    #[serde(rename = "type")]
    pub param_type: String,
    /// Description
    pub description: String,
    /// Is required
    #[serde(default)]
    pub required: bool,
    /// Default value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
}

/// Tool registry
#[derive(Debug, Default)]
pub struct ToolRegistry {
    /// Registered tools
    tools: HashMap<String, ToolDefinition>,
}

impl ToolRegistry {
    /// Create a new tool registry with default vault tools
    pub fn new() -> Self {
        let mut registry = Self::default();
        registry.register_default_tools();
        registry
    }

    /// Register default vault management tools
    fn register_default_tools(&mut self) {
        // List secrets tool
        self.register(ToolDefinition {
            name: "vault_list_secrets".to_string(),
            description: "List all secrets in the vault (shows references and metadata, not values)".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "tag": {
                        "type": "string",
                        "description": "Optional tag to filter secrets"
                    },
                    "type": {
                        "type": "string",
                        "description": "Optional type to filter (ApiKey, Token, ConnectionString, SshKey, Certificate, Generic)"
                    }
                },
                "required": []
            }),
        });

        // Get secret metadata tool (no value!)
        self.register(ToolDefinition {
            name: "vault_get_secret_info".to_string(),
            description: "Get metadata about a secret (NOT the actual value)".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "reference": {
                        "type": "string",
                        "description": "Secret reference name (e.g., 'prod-db', 'openai-key')"
                    }
                },
                "required": ["reference"]
            }),
        });

        // Check secret status tool
        self.register(ToolDefinition {
            name: "vault_check_secret_status".to_string(),
            description: "Check if a secret is expired, needs rotation, or has exceeded usage limit".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "reference": {
                        "type": "string",
                        "description": "Secret reference name"
                    }
                },
                "required": ["reference"]
            }),
        });

        // Execute with credential tool
        self.register(ToolDefinition {
            name: "vault_execute_with_credential".to_string(),
            description: "Execute a command with a credential injected as an environment variable. The LLM never sees the actual credential value.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "credential_ref": {
                        "type": "string",
                        "description": "Secret reference name to inject"
                    },
                    "env_var_name": {
                        "type": "string",
                        "description": "Environment variable name to set (e.g., 'API_KEY', 'DATABASE_URL')"
                    },
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute"
                    },
                    "working_dir": {
                        "type": "string",
                        "description": "Optional working directory"
                    }
                },
                "required": ["credential_ref", "env_var_name", "command"]
            }),
        });

        // HTTP request with auth tool
        self.register(ToolDefinition {
            name: "vault_http_request".to_string(),
            description: "Make an HTTP request with authentication from vault. Credentials are injected server-side and never exposed to the LLM.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "description": "HTTP method (GET, POST, PUT, DELETE, PATCH)",
                        "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]
                    },
                    "url": {
                        "type": "string",
                        "description": "Request URL"
                    },
                    "auth_ref": {
                        "type": "string",
                        "description": "Secret reference for authentication"
                    },
                    "auth_type": {
                        "type": "string",
                        "description": "How to apply auth: 'bearer' (Authorization: Bearer), 'header' (custom header), 'basic' (Basic auth)",
                        "enum": ["bearer", "header", "basic"],
                        "default": "bearer"
                    },
                    "auth_header_name": {
                        "type": "string",
                        "description": "Custom header name if auth_type is 'header' (e.g., 'X-API-Key')"
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body (for POST/PUT/PATCH)"
                    },
                    "headers": {
                        "type": "object",
                        "description": "Additional headers (key-value pairs)"
                    }
                },
                "required": ["method", "url", "auth_ref"]
            }),
        });

        // Database query tool
        self.register(ToolDefinition {
            name: "vault_database_query".to_string(),
            description: "Execute a database query using credentials from vault. Connection string is never exposed to the LLM.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "connection_ref": {
                        "type": "string",
                        "description": "Secret reference for database connection string"
                    },
                    "query": {
                        "type": "string",
                        "description": "SQL query to execute"
                    },
                    "params": {
                        "type": "array",
                        "description": "Query parameters (for prepared statements)",
                        "items": {
                            "type": "string"
                        }
                    }
                },
                "required": ["connection_ref", "query"]
            }),
        });

        // Git operation with SSH key tool
        self.register(ToolDefinition {
            name: "vault_git_operation".to_string(),
            description: "Perform a git operation using SSH key from vault".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "ssh_key_ref": {
                        "type": "string",
                        "description": "Secret reference for SSH key"
                    },
                    "operation": {
                        "type": "string",
                        "description": "Git operation (clone, pull, push, fetch)",
                        "enum": ["clone", "pull", "push", "fetch"]
                    },
                    "repository": {
                        "type": "string",
                        "description": "Repository URL (for clone) or path (for other operations)"
                    },
                    "branch": {
                        "type": "string",
                        "description": "Optional branch name"
                    }
                },
                "required": ["ssh_key_ref", "operation", "repository"]
            }),
        });

        // Record secret usage tool
        self.register(ToolDefinition {
            name: "vault_record_usage".to_string(),
            description: "Record that a secret was used (for usage tracking)".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "reference": {
                        "type": "string",
                        "description": "Secret reference name"
                    }
                },
                "required": ["reference"]
            }),
        });
    }

    /// Register a tool
    pub fn register(&mut self, tool: ToolDefinition) {
        self.tools.insert(tool.name.clone(), tool);
    }

    /// Get all tool definitions
    pub fn get_all(&self) -> Vec<&ToolDefinition> {
        self.tools.values().collect()
    }

    /// Get a specific tool
    pub fn get(&self, name: &str) -> Option<&ToolDefinition> {
        self.tools.get(name)
    }

    /// Check if a tool exists
    pub fn exists(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// Get tool names
    pub fn tool_names(&self) -> Vec<&str> {
        self.tools.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_tools() {
        let registry = ToolRegistry::new();

        assert!(registry.exists("vault_list_secrets"));
        assert!(registry.exists("vault_get_secret_info"));
        assert!(registry.exists("vault_execute_with_credential"));
        assert!(registry.exists("vault_http_request"));
        assert!(registry.exists("vault_database_query"));
    }

    #[test]
    fn test_get_all_tools() {
        let registry = ToolRegistry::new();
        let tools = registry.get_all();

        assert!(!tools.is_empty());

        for tool in tools {
            assert!(!tool.name.is_empty());
            assert!(!tool.description.is_empty());
        }
    }

    #[test]
    fn test_custom_tool() {
        let mut registry = ToolRegistry::new();

        registry.register(ToolDefinition {
            name: "custom_tool".to_string(),
            description: "A custom tool".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        });

        assert!(registry.exists("custom_tool"));
        assert_eq!(registry.get("custom_tool").unwrap().name, "custom_tool");
    }
}
