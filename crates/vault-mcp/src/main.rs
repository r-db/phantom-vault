//! Vault MCP Server - Entry Point
//!
//! Secure credential management server for Claude Code integration

use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use vault_core::storage::default_vault_dir;
use vault_mcp::{create_shared_state, run_server};

/// Initialize logging
fn init_logging() {
    // Log to stderr (stdout is used for MCP protocol)
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .compact(),
        )
        .with(filter)
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    info!("Vault MCP Server starting...");

    // Get vault directory from environment or use default
    let vault_dir = std::env::var("VAULT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_vault_dir());

    info!("Using vault directory: {}", vault_dir.display());

    // Create shared state
    let state = match create_shared_state(vault_dir.clone()).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to initialize vault state: {}", e);
            return Err(e.into());
        }
    };

    // Check if vault exists
    {
        let state_read = state.read().await;
        if !state_read.vault_exists().await {
            info!("No vault found at {}. Create one using the UI or CLI first.", vault_dir.display());
        }
    }

    // Check for auto-unlock via environment (for testing/development only)
    if let Ok(password) = std::env::var("VAULT_PASSWORD") {
        info!("Auto-unlocking vault from environment variable");
        let mut state_write = state.write().await;
        if let Err(e) = state_write.unlock(password.as_bytes()).await {
            error!("Failed to unlock vault: {}", e);
        } else {
            info!("Vault unlocked successfully");
        }
    }

    // Run the MCP server
    info!("Starting MCP server on stdio...");
    run_server(state).await?;

    info!("Vault MCP Server shutting down");
    Ok(())
}
