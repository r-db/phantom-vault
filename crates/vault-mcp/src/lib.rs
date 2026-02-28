//! Vault MCP Server - Secure credential injection for LLM tools
//!
//! This crate provides an MCP (Model Context Protocol) server that:
//! - Intercepts tool calls from Claude Code
//! - Injects real credentials from the vault using symbolic references
//! - Executes tools with injected credentials
//! - Scans output for credential leaks before returning to LLM
//! - Logs all credential access for audit

pub mod server;
pub mod handlers;
pub mod registry;
pub mod state;

pub use server::*;
pub use handlers::*;
pub use registry::*;
pub use state::*;
