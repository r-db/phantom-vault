//! Vault MCP Server - Entry Point
//!
//! Secure credential management server for Claude Code integration

use std::path::PathBuf;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use vault_core::storage::default_vault_dir;
use vault_mcp::{create_shared_state, run_server};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Handle command-line arguments
fn handle_args() -> bool {
    let args: Vec<String> = std::env::args().collect();

    for arg in &args[1..] {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("phantom-vault {}", VERSION);
                return true;
            }
            "--help" | "-h" => {
                println!("Phantom Vault - MCP Server");
                println!("The API key vault where secrets are used but never seen.");
                println!();
                println!("USAGE:");
                println!("    phantom [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("    -h, --help       Print help information");
                println!("    -V, --version    Print version information");
                println!();
                println!("ENVIRONMENT:");
                println!("    VAULT_DIR        Override default vault directory");
                println!("    VAULT_PASSWORD   Auto-unlock vault (development only)");
                println!();
                println!("This binary is meant to be run as an MCP server by Claude Code.");
                println!("For interactive usage, see: phantom --help");
                return true;
            }
            _ => {}
        }
    }
    false
}

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
    // Handle --version and --help before anything else
    if handle_args() {
        return Ok(());
    }

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
    let vault_exists = {
        let state_read = state.read().await;
        let exists = state_read.vault_exists().await;
        if !exists {
            info!("No vault found at {}. Create one using the UI or CLI first.", vault_dir.display());
        }
        exists
    };

    // Auto-unlock from OS Keychain (biometric enrollment).
    // This is the production path: user runs `phantom biometric enable` once on their
    // machine, master password lands in Keychain, MCP server auto-unlocks at boot.
    // No prompt — there's no TTY when launched by Claude Code's MCP client.
    if vault_exists && std::env::var("PHANTOM_NO_BIOMETRIC").map(|v| v == "1").unwrap_or(false) == false {
        if let Some(password) = get_master_from_keychain(&vault_dir.to_string_lossy()) {
            let mut state_write = state.write().await;
            match state_write.unlock(&password).await {
                Ok(_) => info!("Vault auto-unlocked from Keychain (biometric enrollment)"),
                Err(e) => warn!("Keychain entry present but unlock failed: {}. Vault remains locked.", e),
            }
            // Drop password explicitly to encourage zeroization
            drop(password);
        } else {
            info!("No Keychain entry for this vault. Vault starts locked. Enable biometric via: phantom biometric enable");
        }
    }

    // Auto-unlock via environment (DEVELOPMENT ONLY - do not use in production!)
    // This is insecure as the password is stored in plain text in the environment.
    #[cfg(debug_assertions)]
    if let Ok(password) = std::env::var("VAULT_PASSWORD") {
        warn!("VAULT_PASSWORD env var is set - this is INSECURE and for development only!");
        let mut state_write = state.write().await;
        if let Err(_) = state_write.unlock(password.as_bytes()).await {
            error!("Failed to auto-unlock vault");
        } else {
            info!("Vault auto-unlocked (development mode)");
        }
        // Clear the password from memory
        drop(password);
    }

    // Run the MCP server
    info!("Starting MCP server on stdio...");
    run_server(state).await?;

    info!("Vault MCP Server shutting down");
    Ok(())
}

/// Retrieve the master password from the macOS Keychain (set there by `phantom biometric enable`).
/// Returns None on non-macOS platforms or if the keychain entry is missing.
#[cfg(target_os = "macos")]
fn get_master_from_keychain(vault_id: &str) -> Option<Vec<u8>> {
    use security_framework::passwords::get_generic_password;
    get_generic_password("com.phantomvault.master-key", vault_id).ok()
}

#[cfg(not(target_os = "macos"))]
fn get_master_from_keychain(_vault_id: &str) -> Option<Vec<u8>> {
    None
}
