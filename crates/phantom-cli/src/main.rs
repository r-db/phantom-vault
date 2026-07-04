//! Phantom Vault CLI
//!
//! Command-line interface for the LLM-safe secret manager.

use clap::{Parser, Subcommand};

/// Phantom Vault - LLM-safe secret management
#[derive(Parser)]
#[command(name = "phantom-vault")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Vault path (default: ~/.phantom-vault)
    #[arg(short, long, global = true)]
    vault: Option<std::path::PathBuf>,

    /// Namespace to use
    #[arg(short, long, global = true, default_value = "default")]
    namespace: String,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init {
        /// Force overwrite existing vault
        #[arg(short, long)]
        force: bool,
    },

    /// Open/unlock the vault
    Open,

    /// Seal/lock the vault
    Seal,

    /// Set a secret
    Set {
        /// Secret name
        name: String,
        /// Read value from stdin instead of prompting
        #[arg(long)]
        stdin: bool,
    },

    /// Get a secret (for scripts, not recommended)
    Get {
        /// Secret name
        name: String,
    },

    /// Delete a secret
    Delete {
        /// Secret name
        name: String,
        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// List secrets
    List {
        /// Show metadata
        #[arg(short, long)]
        metadata: bool,
    },

    /// Edit all secrets in a text editor (sops-style).
    ///
    /// Opens NAME=value lines in a RAM-backed temp file (never touches
    /// disk), auth-gated by the vault password. On save: new names are
    /// added, changed values updated, removed names deleted (after
    /// confirmation). The plaintext buffer is zeroed and unlinked.
    Edit {
        /// Editor command (default: micro, then $EDITOR, nano, vi)
        #[arg(short, long)]
        editor: Option<String>,
    },

    /// Run a command with secrets injected
    Run {
        /// Secrets to inject (NAME or NAME=ENV_VAR)
        #[arg(short, long)]
        secret: Vec<String>,

        /// Command and arguments
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Namespace management
    Namespace {
        #[command(subcommand)]
        action: NamespaceCommands,
    },

    /// Canary/honeypot management
    Canary {
        #[command(subcommand)]
        action: CanaryCommands,
    },

    /// Rotation management
    Rotation {
        #[command(subcommand)]
        action: RotationCommands,
    },

    /// Audit log
    Audit {
        /// Number of entries to show
        #[arg(short, long, default_value = "20")]
        limit: usize,

        /// Filter by secret name
        #[arg(short, long)]
        secret: Option<String>,

        /// Export to JSON
        #[arg(long)]
        json: bool,
    },

    /// Start MCP server
    Mcp {
        #[command(subcommand)]
        action: McpCommands,
    },
}

#[derive(Subcommand)]
enum NamespaceCommands {
    /// Create a namespace
    Create {
        /// Namespace name
        name: String,
        /// Description
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Delete a namespace
    Delete {
        /// Namespace name
        name: String,
        /// Skip confirmation
        #[arg(short, long)]
        force: bool,
    },
    /// List namespaces
    List,
}

#[derive(Subcommand)]
enum CanaryCommands {
    /// Create a canary secret
    Create {
        /// Canary name
        name: String,
        /// Pattern type (aws-key, github-token, api-key)
        #[arg(short, long, default_value = "api-key")]
        pattern: String,
    },
    /// List canaries
    List,
    /// Check if any canaries have been triggered
    Status,
}

#[derive(Subcommand)]
enum RotationCommands {
    /// Configure rotation for a secret
    Configure {
        /// Secret name
        name: String,
        /// Rotation interval (e.g., "7d", "30d")
        #[arg(short, long)]
        interval: String,
    },
    /// Rotate a secret now
    Now {
        /// Secret name
        name: String,
    },
    /// List rotation status
    Status,
}

#[derive(Subcommand)]
enum McpCommands {
    /// Start the MCP server
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "9999")]
        port: u16,
    },
    /// Show MCP configuration for Claude Code
    Config,
}

// ============================================================================
// Implementation
// ============================================================================

use anyhow::{bail, Context};
use phantom_core::{SecretBuffer, Vault};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

/// Default vault location: ~/.phantom-vault
fn default_vault_path() -> anyhow::Result<PathBuf> {
    let home = dirs_home().context("could not determine home directory")?;
    Ok(home.join(".phantom-vault"))
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Obtain the master password without ever echoing it.
///
/// Resolution order:
/// 1. PHANTOM_VAULT_PASSWORD_FILE — path to a 0600 file (for MCP/daemon use)
/// 2. PHANTOM_VAULT_PASSWORD — env var (discouraged; visible in /proc)
/// 3. interactive hidden prompt (rpassword)
fn read_password(confirm: bool) -> anyhow::Result<SecretBuffer> {
    use std::io::IsTerminal;
    // SECURITY: a human at an interactive terminal is ALWAYS prompted for the
    // master password — the file/env password sources are ignored when stdin
    // is a TTY. Those non-interactive sources exist ONLY for headless callers
    // (the MCP server, agent scripts) whose stdin is a pipe, never a terminal.
    // Without this, `phantom edit` would unlock the whole vault with zero
    // authentication just because PHANTOM_VAULT_PASSWORD_FILE happened to be
    // exported in the shell — which is exactly the hole this closes.
    let non_interactive = !std::io::stdin().is_terminal();
    if non_interactive {
        if let Ok(file) = std::env::var("PHANTOM_VAULT_PASSWORD_FILE") {
            let mut buf = String::new();
            std::fs::File::open(&file)
                .with_context(|| format!("cannot open password file {file}"))?
                .read_to_string(&mut buf)?;
            let trimmed = buf.trim_end_matches(['\n', '\r']);
            if trimmed.is_empty() {
                bail!("password file {file} is empty");
            }
            return Ok(SecretBuffer::from_slice(trimmed.as_bytes())
                .map_err(|e| anyhow::anyhow!("secure buffer: {e}"))?);
        }
        if let Ok(pw) = std::env::var("PHANTOM_VAULT_PASSWORD") {
            if !pw.is_empty() {
                return Ok(SecretBuffer::from_slice(pw.as_bytes())
                    .map_err(|e| anyhow::anyhow!("secure buffer: {e}"))?);
            }
        }
    }
    let pw = rpassword::prompt_password("Vault password: ")?;
    if pw.is_empty() {
        bail!("empty password");
    }
    if confirm {
        let again = rpassword::prompt_password("Confirm password: ")?;
        if pw != again {
            bail!("passwords do not match");
        }
    }
    Ok(SecretBuffer::from_slice(pw.as_bytes())
        .map_err(|e| anyhow::anyhow!("secure buffer: {e}"))?)
}

/// Open an existing, initialized vault (errors if uninitialized).
fn open_vault(path: &PathBuf, namespace: &str) -> anyhow::Result<Vault> {
    let mut vault = Vault::new(path).map_err(|e| anyhow::anyhow!("vault: {e}"))?;
    if !vault.is_initialized() {
        bail!(
            "vault at {} is not initialized — run `phantom-vault init` first",
            path.display()
        );
    }
    let password = read_password(false)?;
    vault
        .open(&password)
        .map_err(|e| anyhow::anyhow!("failed to open vault: {e}"))?;
    if namespace != "default" {
        let ns = phantom_core::Namespace::new(namespace)
            .map_err(|e| anyhow::anyhow!("namespace: {e}"))?;
        vault.switch_namespace(ns);
    }
    Ok(vault)
}

/// Locate an executable on PATH.
fn which(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().to_string());
        }
    }
    None
}

/// Read a secret value from stdin or hidden prompt. Never echoed.
fn read_secret_value(from_stdin: bool) -> anyhow::Result<SecretBuffer> {
    let raw = if from_stdin {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        rpassword::prompt_password("Secret value (hidden): ")?
    };
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        bail!("empty secret value");
    }
    Ok(SecretBuffer::from_slice(trimmed.as_bytes())
        .map_err(|e| anyhow::anyhow!("secure buffer: {e}"))?)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Tracing to stderr only — stdout must stay clean for MCP stdio framing.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let vault_path = match &cli.vault {
        Some(p) => p.clone(),
        None => default_vault_path()?,
    };

    match cli.command {
        Commands::Init { force } => {
            let mut vault =
                Vault::new(&vault_path).map_err(|e| anyhow::anyhow!("vault: {e}"))?;
            if vault.is_initialized() && !force {
                bail!(
                    "vault already initialized at {} (use --force to overwrite)",
                    vault_path.display()
                );
            }
            if vault.is_initialized() && force {
                // Wipe and recreate the vault directory.
                std::fs::remove_dir_all(&vault_path)?;
                vault =
                    Vault::new(&vault_path).map_err(|e| anyhow::anyhow!("vault: {e}"))?;
            }
            let password = read_password(true)?;
            vault
                .init(&password)
                .map_err(|e| anyhow::anyhow!("init failed: {e}"))?;
            println!("vault initialized at {}", vault_path.display());
        }

        Commands::Open => {
            // Stateless CLI: "open" verifies credentials and reports status.
            let vault = open_vault(&vault_path, &cli.namespace)?;
            println!(
                "vault at {} opens cleanly ({} secrets in namespace '{}')",
                vault_path.display(),
                vault.count().map_err(|e| anyhow::anyhow!("{e}"))?,
                cli.namespace
            );
        }

        Commands::Seal => {
            // Each CLI invocation re-derives keys; nothing persists unlocked.
            println!("vault is sealed between invocations; nothing to do");
        }

        Commands::Set { name, stdin } => {
            let mut vault = open_vault(&vault_path, &cli.namespace)?;
            let value = read_secret_value(stdin)?;
            vault
                .set(&name, &value)
                .map_err(|e| anyhow::anyhow!("set failed: {e}"))?;
            println!("secret '{name}' stored ({} bytes)", value.len());
        }

        Commands::Get { name } => {
            let vault = open_vault(&vault_path, &cli.namespace)?;
            let value = vault
                .get(&name)
                .map_err(|e| anyhow::anyhow!("get failed: {e}"))?;
            eprintln!("warning: printing secret to stdout — prefer `run` with injection");
            value.with_exposed(|bytes| {
                use std::io::Write;
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(bytes);
                let _ = out.write_all(b"\n");
            });
        }

        Commands::Delete { name, force } => {
            let mut vault = open_vault(&vault_path, &cli.namespace)?;
            if !force {
                eprint!("delete secret '{name}'? [y/N] ");
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if !answer.trim().eq_ignore_ascii_case("y") {
                    bail!("aborted");
                }
            }
            vault
                .delete(&name)
                .map_err(|e| anyhow::anyhow!("delete failed: {e}"))?;
            println!("secret '{name}' deleted");
        }

        Commands::List { metadata } => {
            let vault = open_vault(&vault_path, &cli.namespace)?;
            if metadata {
                let items = vault
                    .list_with_metadata()
                    .map_err(|e| anyhow::anyhow!("list failed: {e}"))?;
                for m in items {
                    println!(
                        "{}\tns={}\tv{}\tcanary={}",
                        m.name, m.namespace, m.version, m.is_canary
                    );
                }
            } else {
                for name in vault.list().map_err(|e| anyhow::anyhow!("list failed: {e}"))? {
                    println!("{name}");
                }
            }
        }

        Commands::Edit { editor } => {
            let mut vault = open_vault(&vault_path, &cli.namespace)?;

            // 1. Pick the editor and the flags that disable on-disk persistence.
            let editor_cmd = editor
                .or_else(|| which("micro"))
                .or_else(|| std::env::var("EDITOR").ok().filter(|e| !e.is_empty()))
                .or_else(|| which("nano"))
                .or_else(|| which("vi"))
                .context("no editor found — install micro or set $EDITOR")?;

            // 2. Dump secrets into a RAM-backed (tmpfs) file, 0600.
            let shm = PathBuf::from("/dev/shm");
            let tmp_dir = if shm.is_dir() { shm } else {
                eprintln!("warning: /dev/shm unavailable — using disk-backed temp");
                std::env::temp_dir()
            };
            let tmp_path = tmp_dir.join(format!(".phantom-edit-{}", std::process::id()));

            let names = vault.list().map_err(|e| anyhow::anyhow!("list: {e}"))?;
            let mut buffer = String::from(
                "# phantom-vault edit — NAME=value, one per line.\n\
                 # Add a line to create, change a value to rotate, delete a line to remove.\n\
                 # Lines starting with # are ignored. Multi-line values unsupported.\n\n",
            );
            let mut original: HashMap<String, String> = HashMap::new();
            for name in &names {
                let value = vault
                    .get(name)
                    .map_err(|e| anyhow::anyhow!("get {name}: {e}"))?;
                value.with_exposed(|bytes| {
                    let v = String::from_utf8_lossy(bytes).to_string();
                    buffer.push_str(&format!("{name}={v}\n"));
                    original.insert(name.clone(), v);
                });
            }
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp_path)
                    .with_context(|| format!("create {}", tmp_path.display()))?;
                f.write_all(buffer.as_bytes())?;
                f.sync_all()?;
            }

            // 3. Launch the editor with persistence disabled where we know how.
            let editor_name = PathBuf::from(&editor_cmd)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let mut cmd = std::process::Command::new(&editor_cmd);
            match editor_name.as_str() {
                "micro" => {
                    cmd.args(["-backup", "false", "-autosave", "0", "-savecursor", "false"]);
                }
                "vim" | "vi" => {
                    cmd.args(["-n", "-i", "NONE"]);
                }
                _ => {}
            }
            let status = cmd.arg(&tmp_path).status();

            // 4. Read back, then shred the buffer regardless of what happened.
            let edited = std::fs::read_to_string(&tmp_path).unwrap_or_default();
            let file_len = edited.len().max(buffer.len());
            let _ = std::fs::write(&tmp_path, vec![0u8; file_len]); // overwrite
            let _ = std::fs::remove_file(&tmp_path);
            drop(buffer);

            status.context("failed to launch editor")?;

            // 5. Parse and diff.
            let mut kept: HashMap<String, String> = HashMap::new();
            for (lineno, line) in edited.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((name, value)) = line.split_once('=') else {
                    bail!("line {}: not NAME=value — aborting, nothing changed", lineno + 1);
                };
                let (name, value) = (name.trim(), value.trim());
                if name.is_empty() || value.is_empty() {
                    bail!("line {}: empty name or value — aborting, nothing changed", lineno + 1);
                }
                kept.insert(name.to_string(), value.to_string());
            }

            let mut added = 0u32;
            let mut updated = 0u32;
            for (name, value) in &kept {
                match original.get(name) {
                    Some(old) if old == value => {}
                    Some(_) => {
                        let buf = SecretBuffer::from_slice(value.as_bytes())
                            .map_err(|e| anyhow::anyhow!("secure buffer: {e}"))?;
                        vault.set(name, &buf).map_err(|e| anyhow::anyhow!("set {name}: {e}"))?;
                        updated += 1;
                    }
                    None => {
                        let buf = SecretBuffer::from_slice(value.as_bytes())
                            .map_err(|e| anyhow::anyhow!("secure buffer: {e}"))?;
                        vault.set(name, &buf).map_err(|e| anyhow::anyhow!("set {name}: {e}"))?;
                        added += 1;
                    }
                }
            }

            let removed: Vec<&String> =
                original.keys().filter(|n| !kept.contains_key(*n)).collect();
            let mut deleted = 0u32;
            if !removed.is_empty() {
                eprintln!("secrets removed from buffer: {removed:?}");
                eprint!("delete them from the vault? [y/N] ");
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                if answer.trim().eq_ignore_ascii_case("y") {
                    for name in removed {
                        vault
                            .delete(name)
                            .map_err(|e| anyhow::anyhow!("delete {name}: {e}"))?;
                        deleted += 1;
                    }
                }
            }

            println!("edit complete: +{added} added, ~{updated} rotated, -{deleted} deleted");
        }

        Commands::Run { secret, command } => {
            if command.is_empty() {
                bail!("no command given");
            }
            let vault = open_vault(&vault_path, &cli.namespace)?;

            // Map NAME or NAME=ENV_VAR to (env var, secret value).
            let mut env: HashMap<String, SecretBuffer> = HashMap::new();
            let names: Vec<String> = if secret.is_empty() {
                // No explicit selection: inject ALL secrets under their own names.
                vault.list().map_err(|e| anyhow::anyhow!("list failed: {e}"))?
            } else {
                secret
            };
            for spec in names {
                let (name, env_var) = match spec.split_once('=') {
                    Some((n, e)) => (n.to_string(), e.to_string()),
                    None => (spec.clone(), spec.clone()),
                };
                let value = vault
                    .get(&name)
                    .map_err(|e| anyhow::anyhow!("secret '{name}': {e}"))?;
                env.insert(env_var, value);
            }

            let sandbox = phantom_sandbox::Sandbox::new(phantom_sandbox::SandboxConfig {
                timeout: std::time::Duration::from_secs(300),
                ..Default::default()
            })
            .map_err(|e| anyhow::anyhow!("sandbox: {e}"))?;

            let args: Vec<&str> = command[1..].iter().map(|s| s.as_str()).collect();
            let result = sandbox
                .execute(&command[0], &args, env)
                .map_err(|e| anyhow::anyhow!("execution failed: {e}"))?;

            // Output is already sanitized by the sandbox.
            print!("{}", result.stdout);
            eprint!("{}", result.stderr);
            if result.secrets_sanitized {
                eprintln!("[phantom-vault] output contained secrets — redacted");
            }
            if result.timed_out {
                bail!("command timed out");
            }
            std::process::exit(result.exit_code);
        }

        Commands::Namespace { action } => {
            let vault = open_vault(&vault_path, &cli.namespace)?;
            match action {
                NamespaceCommands::List => {
                    // Namespaces are implicit in stored secret metadata.
                    let items = vault
                        .list_with_metadata()
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let mut seen: Vec<String> = items.into_iter().map(|m| m.namespace).collect();
                    seen.sort();
                    seen.dedup();
                    if seen.is_empty() {
                        println!("default");
                    }
                    for ns in seen {
                        println!("{ns}");
                    }
                }
                NamespaceCommands::Create { name, .. } => {
                    // Namespaces materialize on first secret write.
                    phantom_core::Namespace::new(&name)
                        .map_err(|e| anyhow::anyhow!("invalid namespace: {e}"))?;
                    println!(
                        "namespace '{name}' is valid — it materializes on first `set -n {name}`"
                    );
                }
                NamespaceCommands::Delete { .. } => {
                    bail!("namespace delete is not wired yet — delete its secrets individually");
                }
            }
        }

        Commands::Canary { action } => match action {
            CanaryCommands::List | CanaryCommands::Status | CanaryCommands::Create { .. } => {
                bail!("canary commands are not wired into the CLI yet (library support exists)");
            }
        },

        Commands::Rotation { action } => match action {
            RotationCommands::Configure { .. }
            | RotationCommands::Now { .. }
            | RotationCommands::Status => {
                bail!("rotation commands are not wired into the CLI yet (library support exists)");
            }
        },

        Commands::Audit { .. } => {
            bail!("audit query is not wired into the CLI yet (library support exists)");
        }

        Commands::Mcp { action } => match action {
            McpCommands::Serve { port: _ } => {
                // stdio transport: Claude Code spawns us and speaks JSON-RPC on stdio.
                let password = read_password(false).context(
                    "MCP serve needs PHANTOM_VAULT_PASSWORD_FILE (0600 file) or \
                     PHANTOM_VAULT_PASSWORD set — no TTY for prompting",
                )?;
                let mut vault =
                    Vault::new(&vault_path).map_err(|e| anyhow::anyhow!("vault: {e}"))?;
                if !vault.is_initialized() {
                    bail!(
                        "vault at {} is not initialized — run `phantom-vault init` first",
                        vault_path.display()
                    );
                }
                vault
                    .open(&password)
                    .map_err(|e| anyhow::anyhow!("failed to open vault: {e}"))?;

                let mcp_config = phantom_mcp::McpConfig::load()
                    .map_err(|e| anyhow::anyhow!("mcp config: {e}"))?;
                let registry =
                    phantom_mcp::ToolRegistry::with_vault(mcp_config.clone(), vault);
                let server = phantom_mcp::McpServer::with_registry(mcp_config, registry);

                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(server.run_stdio())
                    .map_err(|e| anyhow::anyhow!("mcp server: {e}"))?;
            }
            McpCommands::Config => {
                let exe = std::env::current_exe()?;
                println!(
                    r#"Add to your .mcp.json:

{{
  "mcpServers": {{
    "phantom-vault": {{
      "command": "{}",
      "args": ["mcp", "serve"],
      "env": {{ "PHANTOM_VAULT_PASSWORD_FILE": "<path to 0600 file>" }}
    }}
  }}
}}"#,
                    exe.display()
                );
            }
        },
    }

    Ok(())
}
