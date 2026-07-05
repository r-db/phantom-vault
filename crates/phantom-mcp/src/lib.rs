//! # Phantom MCP
//!
//! MCP (Model Context Protocol) server for Claude Code integration.
//!
//! This crate provides a secure interface for AI assistants to interact
//! with the Phantom Vault. It NEVER returns plaintext secret values.
//!
//! # Features
//!
//! - **MCP Protocol**: JSON-RPC over stdio transport
//! - **Tool Definitions**: vault_list, vault_exists, vault_masked, vault_run, vault_health, vault_rotate
//! - **Request Lineage**: Full audit trail with trust levels
//! - **Security**: Pre-analysis of commands, output sanitization, rate limiting
//!
//! # Configuration
//!
//! MCP config is loaded from `~/.phantom/mcp-config.toml`:
//!
//! ```toml
//! [server]
//! idle_timeout_minutes = 15
//! max_runs_per_minute = 10
//! require_biometric = true
//!
//! [namespaces]
//! default = "personal"
//! allowed = ["personal", "work"]
//!
//! [sensitivity]
//! high = ["DATABASE_URL", "STRIPE_SECRET_KEY"]
//! medium = ["RAILWAY_TOKEN"]
//! low = ["PUBLIC_API_KEY"]
//! ```
//!
//! # Example Usage
//!
//! ```rust,no_run
//! use phantom_mcp::{McpServer, McpConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = McpConfig::load().unwrap_or_default();
//!     let server = McpServer::new(config);
//!     server.run_stdio().await.unwrap();
//! }
//! ```
//!
//! # Trust Levels
//!
//! Every request is assigned a trust level:
//!
//! - **HUMAN_DIRECT**: Called by human via CLI
//! - **LLM_APPROVED**: Called by MCP with recent human interaction
//! - **LLM_AUTO**: Called by MCP without recent human interaction
//!
//! High-sensitivity secrets require HUMAN_DIRECT or LLM_APPROVED trust level.

pub mod config;
pub mod lineage;
pub mod server;
pub mod tools;

pub use config::{McpConfig, SensitivityLevel};
pub use lineage::{
    ClientInfo, LineageStats, LineageTracker, RequestLineage, RequestResult, ToolCall, TrustLevel,
};
pub use server::{McpServer, ServerConfig, SessionState};
pub use tools::{ToolDefinition, ToolMetadata, ToolOutput, ToolRegistry};

use thiserror::Error;

/// Errors that can occur during MCP operations.
#[derive(Debug, Error)]
pub enum McpError {
    /// Server error.
    #[error("server error: {0}")]
    Server(String),

    /// Protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Tool execution error.
    #[error("tool error: {0}")]
    Tool(String),

    /// Vault error.
    #[error("vault error: {0}")]
    Vault(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded: {0}")]
    RateLimit(String),

    /// Access denied.
    #[error("access denied: {0}")]
    AccessDenied(String),
}

/// Result type for MCP operations.
pub type McpResult<T> = Result<T, McpError>;

impl From<config::ConfigError> for McpError {
    fn from(e: config::ConfigError) -> Self {
        McpError::Config(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_error_display() {
        let err = McpError::Tool("test error".to_string());
        assert_eq!(err.to_string(), "tool error: test error");
    }

    #[test]
    fn test_default_config() {
        let config = McpConfig::default();
        assert_eq!(config.server.idle_timeout_minutes, 15);
        assert_eq!(config.server.max_runs_per_minute, 10);
    }
}
