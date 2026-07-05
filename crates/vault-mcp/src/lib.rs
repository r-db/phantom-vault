//! Vault MCP Server — the safe scheme.
//!
//! This crate is the `vault-mcp` binary that Claude Code launches as an MCP
//! server. It exposes ONLY the leak-resistant tool set from `phantom-mcp`
//! (`vault_list`, `vault_exists`, `vault_masked`, `vault_run`, `vault_health`,
//! `vault_rotate`) — every command runs through the analyzer, an egress-jailed
//! sandbox, and the output sanitizer.
//!
//! The prior credential-injection tools (`vault_execute_with_credential`,
//! `vault_http_request`, raw `vault_database_query`, `vault_git_operation`) were
//! DELETED in the Option A merge: they let an LLM exfiltrate raw secrets over
//! the network before any output filtering could run.
//!
//! All server logic lives in `main.rs`.
