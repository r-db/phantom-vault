//! Vault MCP Server — Entry Point (safe scheme).
//!
//! Launches the `phantom-mcp` server backed by the `phantom-core` vault. Only
//! the leak-resistant tools are exposed; every `vault_run` command flows through
//! the analyzer, an egress-jailed sandbox, and the output sanitizer. There is no
//! credential-injection / arbitrary-HTTP tool anymore.

use std::io::Read;
use std::path::PathBuf;

use phantom_core::memory::SecretBuffer;
use phantom_core::Vault;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Handle `--version` / `--help` and return `true` if we should exit early.
fn handle_args() -> bool {
    let args: Vec<String> = std::env::args().collect();
    for arg in &args[1..] {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("vault-mcp {VERSION}");
                return true;
            }
            "--help" | "-h" => {
                println!("Phantom Vault — MCP Server (safe scheme)");
                println!("The API key vault where secrets are used but never seen.");
                println!();
                println!("USAGE:");
                println!("    vault-mcp");
                println!();
                println!("This binary is launched as an MCP server by Claude Code and speaks");
                println!("JSON-RPC on stdio. It exposes only leak-resistant tools:");
                println!("    vault_list, vault_exists, vault_masked, vault_run, vault_health, vault_rotate");
                println!();
                println!("ENVIRONMENT:");
                println!("    PHANTOM_VAULT_DIR            Vault directory (default: ~/.phantom-vault)");
                println!("    PHANTOM_VAULT_PASSWORD_FILE  Path to a 0600 file holding the master password");
                println!("    PHANTOM_VAULT_PASSWORD       Master password (discouraged; visible in /proc)");
                return true;
            }
            _ => {}
        }
    }
    false
}

fn init_logging() {
    // Log to stderr — stdout is the MCP JSON-RPC channel.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
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

/// Default vault location: `~/.phantom-vault` (override with `PHANTOM_VAULT_DIR`).
fn vault_dir() -> anyhow::Result<PathBuf> {
    if let Ok(dir) = std::env::var("PHANTOM_VAULT_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("could not determine home directory (set PHANTOM_VAULT_DIR)"))?;
    Ok(home.join(".phantom-vault"))
}

/// Read the master password for headless (MCP) operation.
///
/// The MCP server's stdin is the JSON-RPC pipe, so it is never a TTY — the only
/// supported sources are a 0600 file or an env var. We deliberately do NOT
/// silently unlock from the OS keychain here (that silent-auto-unlock path was a
/// confused-deputy hazard); enrollment/biometric remains a CLI concern.
fn read_master_password() -> anyhow::Result<SecretBuffer> {
    if let Ok(file) = std::env::var("PHANTOM_VAULT_PASSWORD_FILE") {
        let mut buf = String::new();
        std::fs::File::open(&file)
            .map_err(|e| anyhow::anyhow!("cannot open PHANTOM_VAULT_PASSWORD_FILE {file}: {e}"))?
            .read_to_string(&mut buf)?;
        let trimmed = buf.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            anyhow::bail!("password file {file} is empty");
        }
        return SecretBuffer::from_slice(trimmed.as_bytes())
            .map_err(|e| anyhow::anyhow!("secure buffer: {e}"));
    }
    if let Ok(pw) = std::env::var("PHANTOM_VAULT_PASSWORD") {
        if !pw.is_empty() {
            return SecretBuffer::from_slice(pw.as_bytes())
                .map_err(|e| anyhow::anyhow!("secure buffer: {e}"));
        }
    }
    anyhow::bail!(
        "no master password available — set PHANTOM_VAULT_PASSWORD_FILE (a 0600 file) or \
         PHANTOM_VAULT_PASSWORD; the MCP server has no TTY to prompt on"
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if handle_args() {
        return Ok(());
    }

    init_logging();
    info!("vault-mcp {VERSION} starting (safe scheme)...");

    let dir = vault_dir()?;
    info!("Using vault directory: {}", dir.display());

    let mut vault = Vault::new(&dir).map_err(|e| anyhow::anyhow!("vault: {e}"))?;
    if !vault.is_initialized() {
        error!(
            "vault at {} is not initialized — create one with the CLI first",
            dir.display()
        );
        anyhow::bail!("vault not initialized at {}", dir.display());
    }

    let password = read_master_password()?;
    vault
        .open(&password)
        .map_err(|e| anyhow::anyhow!("failed to open vault: {e}"))?;
    drop(password);
    info!("Vault unlocked.");

    let mcp_config =
        phantom_mcp::McpConfig::load().map_err(|e| anyhow::anyhow!("mcp config: {e}"))?;
    let registry = phantom_mcp::ToolRegistry::with_vault(mcp_config.clone(), vault);
    let server = phantom_mcp::McpServer::with_registry(mcp_config, registry);

    info!("Starting MCP server on stdio...");
    server
        .run_stdio()
        .await
        .map_err(|e| anyhow::anyhow!("mcp server: {e}"))?;

    info!("vault-mcp shutting down");
    Ok(())
}
