//! Phantom Vault CLI
//!
//! The API key vault where secrets are used but never seen.
//! Built for the age of AI agents.

use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// SINGLE SECURE BACKEND: the CLI now uses phantom-core (mlock memory, AES-GCM +
// Argon2, encrypted SQLite) exactly like the MCP server (crates/vault-mcp), so
// both read/write ONE vault at ~/.phantom-vault. vault-core is no longer used.
use phantom_core::memory::SecretBuffer;
use phantom_core::vault::VaultError;
use phantom_core::{Namespace, Vault};

mod interactive;

// Filesystem containment for `run` (Landlock; Linux only).
#[cfg(target_os = "linux")]
mod sandbox_fs;

// === Single-source-of-truth vault location + phantom-core helpers ===

/// Default vault location: `~/.phantom-vault` (override with `PHANTOM_VAULT_DIR`).
///
/// This MUST match the MCP server (crates/vault-mcp `vault_dir()`) so the CLI and
/// the MCP server operate on the SAME secure vault — one source of truth.
pub(crate) fn default_vault_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PHANTOM_VAULT_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".phantom-vault")
}

/// A vault is initialized when phantom-core's salt + auth-check files exist.
/// (Mirrors `Vault::is_initialized` without constructing a `Vault`, which would
/// otherwise create the directory as a side effect.)
pub(crate) fn vault_initialized(vault_dir: &Path) -> bool {
    vault_dir.join(".salt").exists() && vault_dir.join(".auth").exists()
}

/// Open the phantom-core vault: unlock (Keychain or password), then optionally
/// switch to a namespace. Returns the opened `Vault`.
pub(crate) fn open_vault(
    vault_dir: &PathBuf,
    namespace: Option<&str>,
) -> Result<Vault, Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }
    let password = unlock_password(vault_dir)?;
    let mut vault = Vault::new(vault_dir).map_err(|e| format!("vault: {}", e))?;
    let pw = SecretBuffer::from_slice(password.as_bytes())
        .map_err(|e| format!("secure buffer: {}", e))?;
    vault.open(&pw).map_err(|e| match e {
        VaultError::AuthenticationFailed => "Invalid password".to_string(),
        other => format!("failed to open vault: {}", other),
    })?;
    drop(pw);
    if let Some(ns) = namespace {
        if ns != Namespace::DEFAULT {
            let namespace =
                Namespace::new(ns).map_err(|e| format!("invalid namespace '{}': {}", ns, e))?;
            vault.switch_namespace(namespace);
        }
    }
    Ok(vault)
}

/// Expiry status tag for `list` display, given metadata `expires_at` (unix secs).
fn expiry_status(expires_at: Option<u64>, now: u64) -> &'static str {
    match expires_at {
        Some(exp) if exp <= now => " [EXPIRED]",
        Some(exp) if exp.saturating_sub(now) <= 14 * 86400 => " [EXPIRES SOON]",
        _ => "",
    }
}

/// Format a unix-seconds timestamp for human display.
fn fmt_ts(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("{}", secs))
}

/// Honest error for vault-core-only features that phantom-core's Vault API does
/// not (yet) expose. Used so the CLI has ONE backend instead of a split brain.
fn secure_core_unsupported(feature: &str) -> Box<dyn std::error::Error> {
    format!(
        "`phantom {feature}` is not available on the secure-core (phantom-core) backend. \
         The CLI now shares the phantom-core vault (~/.phantom-vault) with the MCP server; \
         `{feature}` was a vault-core-only feature and has no phantom-core Vault API yet."
    )
    .into()
}

#[derive(Parser)]
#[command(name = "phantom")]
#[command(author = "Riscent")]
#[command(version)]
#[command(about = "Phantom Vault - secrets exist but are never observable")]
#[command(after_help = "EXAMPLES:
  phantom init                                       Create a new vault
  phantom edit                                       Edit all secrets in $EDITOR (encrypted notepad)
  phantom biometric enable                           Enable Keychain auto-unlock (one-time)
  phantom mcp install                                Wire Phantom into Claude Code
  phantom guardrail set NAME --cap 50 --provider openai   Set monthly USD cap
  phantom run -s API_KEY -- cmd                      Run command with secret injected

DOCS: https://phantomvault.riscent.com")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init {
        /// Enable biometric unlock (Touch ID on macOS)
        #[arg(long)]
        biometric: bool,
    },

    /// Manage biometric authentication
    Biometric {
        #[command(subcommand)]
        action: BiometricCommands,
    },

    /// Add a secret to the vault
    #[command(after_help = "EXAMPLES:
  phantom add API_KEY                    Prompts for value (secure, hidden)
  phantom add DB_URL --from-env MY_VAR   Import from environment variable
  phantom add TOKEN --expires 30d        Secret expires in 30 days")]
    Add {
        /// Name of the secret
        name: String,
        /// Import from environment variable
        #[arg(long)]
        from_env: Option<String>,
        /// Set expiration (e.g., 7d, 30d, 90d)
        #[arg(long)]
        expires: Option<String>,
        /// Namespace for this secret
        #[arg(long)]
        namespace: Option<String>,
    },

    /// List all secrets (names only, never values)
    List {
        /// Namespace to list from
        #[arg(short, long)]
        namespace: Option<String>,
    },

    /// Show masked secret (last 4 characters)
    Show {
        /// Name of the secret
        name: String,
        /// Show masked value
        #[arg(long)]
        masked: bool,
    },

    /// Get a secret value (requires authentication)
    Get {
        /// Name of the secret
        name: String,
    },

    /// Remove a secret from the vault
    Remove {
        /// Name of the secret
        name: String,
    },

    /// Run a command with secrets injected as environment variables
    #[command(after_help = "EXAMPLES:
  phantom run -s API_KEY -- curl https://api.example.com
  phantom run -s DB_URL -s REDIS_URL -- node server.js
  phantom run -s MY_KEY=CUSTOM_VAR -- env   # inject as CUSTOM_VAR")]
    Run {
        /// Secrets to inject (use -s NAME or -s NAME=ENV_VAR)
        #[arg(short, long, action = clap::ArgAction::Append)]
        secret: Vec<String>,
        /// Command and arguments
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// Manage namespaces for secret isolation
    Namespace {
        #[command(subcommand)]
        action: NamespaceCommands,
    },

    /// Rotate a secret (update its value)
    #[command(after_help = "EXAMPLES:
  phantom rotate API_KEY                 Prompts for new value (secure)")]
    Rotate {
        /// Name of the secret
        name: String,
    },

    /// View audit log
    Audit {
        /// Number of entries to show
        #[arg(long, default_value = "20")]
        last: usize,
    },

    /// Check vault health status
    Health,

    /// Manage canary (honeypot) secrets
    Canary {
        #[command(subcommand)]
        action: CanaryCommands,
    },

    /// Manage security policies
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },

    /// MCP server management
    Mcp {
        #[command(subcommand)]
        action: McpCommands,
    },

    /// Import secrets from .env file
    Import {
        /// Path to .env file
        path: String,
    },

    /// Update phantom to the latest version
    #[command(after_help = "Downloads and installs the latest version from GitHub releases.")]
    Update,

    /// Open the vault in $EDITOR — like an encrypted notepad
    #[command(after_help = "EXAMPLES:
  phantom edit                      Open all secrets in $EDITOR (KEY=VALUE format)
  EDITOR=nano phantom edit          Use a specific editor

Format: KEY=VALUE per line. Add/modify lines to add/update secrets.
Remove a line to delete a secret. Lines starting with # are comments.")]
    Edit,

    /// Change the master password (re-encrypts the vault)
    #[command(after_help = "Prompts for the old password (or auto-unlocks from Keychain if enrolled),
then for a new password twice. Re-encrypts the entire vault with the new key.
If biometric was enrolled, the Keychain entry is automatically updated to the new password.")]
    Passwd,

    /// Set spending caps on credentials — never wake up to a surprise bill
    #[command(after_help = "EXAMPLES:
  phantom guardrail set openai-key --cap 50 --provider openai
  phantom guardrail list
  phantom guardrail status
  phantom guardrail remove openai-key

Caps are monthly USD amounts. Providers polled at `phantom guardrail status`.
Soft alert at 80% (configurable via --alert-at).")]
    Guardrail {
        #[command(subcommand)]
        action: GuardrailCommands,
    },
}

#[derive(Subcommand)]
enum NamespaceCommands {
    /// List all namespaces
    List,
    /// Create a new namespace
    Create { name: String },
    /// Switch to a namespace
    Use { name: String },
    /// Delete a namespace
    Delete { name: String },
}

#[derive(Subcommand)]
enum CanaryCommands {
    /// Create a canary secret
    Create {
        /// Name of the canary
        name: String,
        /// Pattern type (aws-access-key, stripe-key, etc.)
        #[arg(long)]
        pattern: Option<String>,
    },
    /// List canary secrets
    List,
    /// Delete a canary
    Delete { name: String },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Show current policy
    Show,
    /// Set policy from file
    Set { path: String },
    /// Reset to default policy
    Reset,
}

#[derive(Subcommand)]
enum McpCommands {
    /// Install MCP server for Claude Code
    Install,
    /// Uninstall MCP server
    Uninstall,
    /// Show MCP server status
    Status,
}

#[derive(Subcommand)]
enum GuardrailCommands {
    /// Set or update a guardrail on a secret
    Set {
        /// Reference name of the secret (must already exist in vault)
        name: String,
        /// Monthly cap in USD
        #[arg(long)]
        cap: f64,
        /// Provider — openai, anthropic, gemini, stripe, twilio, elevenlabs, deepgram, or "manual"
        #[arg(long)]
        provider: String,
        /// Alert threshold percentage (default 80)
        #[arg(long, default_value_t = 80)]
        alert_at: u8,
    },
    /// List all configured guardrails
    List,
    /// Remove a guardrail (the secret itself stays)
    Remove {
        /// Reference name of the guarded secret
        name: String,
    },
    /// Show current usage vs cap for every guardrail (polls providers where supported)
    Status,
}

#[derive(Subcommand)]
enum BiometricCommands {
    /// Check biometric status
    Status,
    /// Enable biometric unlock
    Enable,
    /// Disable biometric unlock
    Disable,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        None => {
            // Bare `phantom` → interactive wizard / menu
            let vault_dir = default_vault_dir();
            if let Err(e) = interactive::run_default(&vault_dir).await {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            return;
        }
        Some(cmd) => {
            if let Err(e) = handle_command(cmd).await {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

async fn handle_command(cmd: Commands) -> Result<(), Box<dyn std::error::Error>> {
    let vault_dir = default_vault_dir();

    match cmd {
        Commands::Init { biometric } => {
            handle_init(&vault_dir, biometric).await?;
        }
        Commands::Biometric { action } => match action {
            BiometricCommands::Status => {
                handle_biometric_status().await?;
            }
            BiometricCommands::Enable => {
                handle_biometric_enable(&vault_dir).await?;
            }
            BiometricCommands::Disable => {
                handle_biometric_disable(&vault_dir).await?;
            }
        },
        Commands::Add { name, from_env, expires, namespace } => {
            handle_add(&vault_dir, &name, from_env, expires, namespace).await?;
        }
        Commands::List { namespace } => {
            handle_list(&vault_dir, namespace).await?;
        }
        Commands::Show { name, masked } => {
            handle_show(&vault_dir, &name, masked).await?;
        }
        Commands::Get { name } => {
            handle_get(&vault_dir, &name).await?;
        }
        Commands::Remove { name } => {
            handle_remove(&vault_dir, &name).await?;
        }
        Commands::Run { secret, command } => {
            handle_run(&vault_dir, &secret, &command).await?;
        }
        Commands::Namespace { action } => match action {
            NamespaceCommands::List => handle_namespace_list(&vault_dir).await?,
            NamespaceCommands::Create { name } => handle_namespace_create(&vault_dir, &name).await?,
            NamespaceCommands::Use { name } => handle_namespace_use(&vault_dir, &name).await?,
            NamespaceCommands::Delete { name } => handle_namespace_delete(&vault_dir, &name).await?,
        },
        Commands::Rotate { name } => {
            handle_rotate(&vault_dir, &name).await?;
        }
        Commands::Audit { last } => {
            handle_audit(&vault_dir, last).await?;
        }
        Commands::Health => {
            handle_health(&vault_dir).await?;
        }
        Commands::Canary { action } => match action {
            CanaryCommands::Create { name, pattern } => {
                handle_canary_create(&vault_dir, &name, pattern).await?;
            }
            CanaryCommands::List => handle_canary_list(&vault_dir).await?,
            CanaryCommands::Delete { name } => handle_canary_delete(&vault_dir, &name).await?,
        },
        Commands::Policy { action } => match action {
            PolicyCommands::Show => handle_policy_show(&vault_dir).await?,
            PolicyCommands::Set { path } => handle_policy_set(&vault_dir, &path).await?,
            PolicyCommands::Reset => handle_policy_reset(&vault_dir).await?,
        },
        Commands::Mcp { action } => match action {
            McpCommands::Install => {
                handle_mcp_install().await?;
            }
            McpCommands::Uninstall => {
                handle_mcp_uninstall().await?;
            }
            McpCommands::Status => {
                handle_mcp_status().await?;
            }
        },
        Commands::Import { path } => {
            handle_import(&vault_dir, &path).await?;
        }
        Commands::Update => {
            handle_update().await?;
        }
        Commands::Edit => {
            handle_edit(&vault_dir).await?;
        }
        Commands::Passwd => {
            handle_passwd(&vault_dir).await?;
        }
        Commands::Guardrail { action } => match action {
            GuardrailCommands::Set { name, cap, provider, alert_at } => {
                handle_guardrail_set(&vault_dir, &name, cap, &provider, alert_at).await?;
            }
            GuardrailCommands::List => handle_guardrail_list(&vault_dir).await?,
            GuardrailCommands::Remove { name } => {
                handle_guardrail_remove(&vault_dir, &name).await?;
            }
            GuardrailCommands::Status => handle_guardrail_status(&vault_dir).await?,
        },
    }

    Ok(())
}

// === Command Handlers ===

async fn handle_init(vault_dir: &PathBuf, enable_biometric: bool) -> Result<(), Box<dyn std::error::Error>> {
    if vault_initialized(vault_dir) {
        println!("Vault already exists at {}", vault_dir.display());
        return Ok(());
    }

    // Prompt for + confirm password
    let password = prompt_password("Enter master password: ")?;
    let confirm = prompt_password("Confirm master password: ")?;
    if password != confirm {
        return Err("Passwords do not match".into());
    }

    create_vault_with_password(vault_dir, &password, enable_biometric).await?;
    print_post_init_next_steps(enable_biometric);
    Ok(())
}

/// Create a vault with a password that has already been collected.
/// Reused by `handle_init` and by the interactive first-run wizard.
pub(crate) async fn create_vault_with_password(
    vault_dir: &PathBuf,
    password: &str,
    enable_biometric: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if password.is_empty() {
        return Err("Password cannot be empty".into());
    }

    println!("Creating new vault at {}", vault_dir.display());
    println!();

    let biometric_available = is_biometric_available();
    if enable_biometric && !biometric_available {
        println!("Note: Biometric hardware not detected. Keychain entry will be encrypted by your login.");
        println!();
    }

    // Create + initialize the phantom-core vault (same backend as the MCP server).
    let mut vault = Vault::new(vault_dir).map_err(|e| format!("vault: {}", e))?;
    let pw = SecretBuffer::from_slice(password.as_bytes())
        .map_err(|e| format!("secure buffer: {}", e))?;
    vault
        .init(&pw)
        .map_err(|e| format!("failed to initialize vault: {}", e))?;
    drop(pw);
    let _ = vault.seal();

    if enable_biometric {
        println!("Enabling Keychain auto-unlock...");
        match enroll_biometric(&vault_dir.to_string_lossy(), password.as_bytes()) {
            Ok(_) => {
                if biometric_available {
                    println!("Touch ID auto-unlock enabled.");
                } else {
                    println!("Keychain auto-unlock enabled.");
                }
            }
            Err(e) => println!("Note: Could not enable auto-unlock: {}", e),
        }
        println!();
    }

    println!("Vault created successfully!");
    println!();
    Ok(())
}

fn print_post_init_next_steps(enable_biometric_already_done: bool) {
    println!("Next steps:");
    println!("  phantom                          Open the interactive menu (recommended)");
    println!("  phantom edit                     Add many secrets at once (notepad mode)");
    println!("  phantom mcp install              Wire your AI tools (Claude Code, Cursor, …)");
    if !enable_biometric_already_done && is_biometric_available() {
        println!("  phantom biometric enable         Enable Keychain auto-unlock (one-time)");
    }
}

async fn handle_biometric_status() -> Result<(), Box<dyn std::error::Error>> {
    println!("Biometric Authentication Status");
    println!("================================");
    println!();

    let available = is_biometric_available();
    if available {
        println!("[OK] Touch ID is available");
    } else {
        println!("[--] No biometric hardware detected");
        return Ok(());
    }

    let vault_dir = default_vault_dir();
    let status = check_biometric_status(&vault_dir.to_string_lossy());

    if status.key_enrolled {
        println!("[OK] Biometric unlock is enabled for this vault");
    } else {
        println!("[--] Biometric unlock is not enabled");
        println!();
        println!("Enable with: phantom biometric enable");
    }

    Ok(())
}

async fn handle_biometric_enable(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Note: this enrolls the vault for Keychain auto-unlock. Touch ID hardware (when present)
    // adds an extra prompt layer; without it, the Keychain entry is still encrypted and
    // tied to your logged-in user session. Either way the master password leaves the prompt
    // path and `phantom` / `vault-mcp` will auto-unlock without typing.
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    // Verify password first (open the phantom-core vault to confirm it unlocks).
    let password = prompt_password("Enter master password to enable Keychain auto-unlock: ")?;
    {
        let mut vault = Vault::new(vault_dir).map_err(|e| format!("vault: {}", e))?;
        let pw = SecretBuffer::from_slice(password.as_bytes())
            .map_err(|e| format!("secure buffer: {}", e))?;
        vault.open(&pw).map_err(|_| "Invalid password")?;
    }

    // Enroll into Keychain
    enroll_biometric(&vault_dir.to_string_lossy(), password.as_bytes())
        .map_err(|e| format!("Failed to enable Keychain auto-unlock: {}", e))?;

    println!("Keychain auto-unlock enabled.");
    if is_biometric_available() {
        println!("Touch ID is present — your unlock will be biometric-protected.");
    } else {
        println!("Touch ID not detected. Keychain entry is still encrypted by your macOS login.");
    }
    println!("Future phantom commands and vault-mcp will unlock without prompting.");

    Ok(())
}

async fn handle_biometric_disable(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found.".into());
    }

    unenroll_biometric(&vault_dir.to_string_lossy())
        .map_err(|e| format!("Failed to disable biometric: {}", e))?;

    println!("Biometric unlock disabled.");
    println!("You will need to use your password to unlock the vault.");

    Ok(())
}

// Biometric functions (platform-specific implementations in vault-native)
// FIX (2026-05-15, M4 biometric bug): `bioutil --availability` is not a real flag.
// The macOS bioutil(8) tool has no `--availability` option — running it always
// exits non-zero, so this function unconditionally returned false on every Mac,
// preventing all biometric-based unlock flows from working (including agent
// usage of `phantom run -s` since the TTY fallback was the only remaining path).
//
// Correct command is `bioutil -r` which reads biometric settings. It exits 0
// when biometric hardware is present and outputs configuration including
// "Effective biometrics for unlock: 1" when TouchID is actually usable.
#[cfg(target_os = "macos")]
pub(crate) fn is_biometric_available() -> bool {
    std::process::Command::new("bioutil")
        .args(["-r"])
        .output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .contains("Effective biometrics for unlock: 1")
        })
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn is_biometric_available() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn check_biometric_status(vault_id: &str) -> BiometricStatus {
    use security_framework::passwords::get_generic_password;
    let key_enrolled = get_generic_password("com.phantomvault.master-key", vault_id).is_ok();
    BiometricStatus {
        available: is_biometric_available(),
        biometric_type: "TouchID".to_string(),
        key_enrolled,
    }
}

#[cfg(not(target_os = "macos"))]
fn check_biometric_status(_vault_id: &str) -> BiometricStatus {
    BiometricStatus {
        available: false,
        biometric_type: "None".to_string(),
        key_enrolled: false,
    }
}

struct BiometricStatus {
    available: bool,
    biometric_type: String,
    key_enrolled: bool,
}

#[cfg(target_os = "macos")]
pub(crate) fn enroll_biometric(vault_id: &str, password: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use security_framework::passwords::{delete_generic_password, set_generic_password};
    let _ = delete_generic_password("com.phantomvault.master-key", vault_id);
    set_generic_password("com.phantomvault.master-key", vault_id, password)?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn enroll_biometric(_vault_id: &str, _password: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    Err("Biometric not available on this platform".into())
}

#[cfg(target_os = "macos")]
fn unenroll_biometric(vault_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    use security_framework::passwords::delete_generic_password;
    delete_generic_password("com.phantomvault.master-key", vault_id)?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn unenroll_biometric(_vault_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    Ok(()) // Nothing to do
}

/// Retrieve the master password from the OS keychain if biometric is enrolled.
/// Returns None if biometric isn't set up, the keychain entry is missing, or we're not on macOS.
#[cfg(target_os = "macos")]
pub(crate) fn get_master_from_keychain(vault_id: &str) -> Option<Vec<u8>> {
    use security_framework::passwords::get_generic_password;
    get_generic_password("com.phantomvault.master-key", vault_id).ok()
}

#[cfg(not(target_os = "macos"))]
fn get_master_from_keychain(_vault_id: &str) -> Option<Vec<u8>> {
    None
}

/// Unified password retrieval — tries Keychain (biometric) first, falls back to interactive prompt.
/// If PHANTOM_NO_BIOMETRIC=1 is set, skips Keychain entirely (forces password prompt).
/// Caller can use the returned String's .as_bytes() interchangeably with the prior pattern.
pub(crate) fn unlock_password(vault_dir: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let opt_out = std::env::var("PHANTOM_NO_BIOMETRIC")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !opt_out {
        let vault_id = vault_dir.to_string_lossy();
        if let Some(pw_bytes) = get_master_from_keychain(&vault_id) {
            // Keychain blob should be UTF-8 (set_generic_password stores the master password we typed).
            if let Ok(s) = String::from_utf8(pw_bytes) {
                return Ok(s);
            }
            // If somehow not UTF-8, fall through to prompt rather than panic.
        }
    }
    prompt_password("Enter master password: ").map_err(|e| e.into())
}

async fn handle_add(
    vault_dir: &PathBuf,
    name: &str,
    from_env: Option<String>,
    expires: Option<String>,
    namespace: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    // Handle namespace (use provided, active, or default) — open the vault on it.
    let effective_namespace = namespace.or_else(read_active_namespace);
    let mut vault = open_vault(vault_dir, effective_namespace.as_deref())?;

    // Check if name already exists
    if vault.exists(name)? {
        return Err(format!("Secret '{}' already exists. Use 'phantom rotate' to update.", name).into());
    }

    // Get the secret value (from_env or secure prompt)
    let secret_value = if let Some(env_var) = from_env {
        std::env::var(&env_var)
            .map_err(|_| format!("Environment variable '{}' not found", env_var))?
    } else {
        // Interactive prompt with confirmation
        let entered = prompt_password(&format!("Enter value for '{}': ", name))?;

        if entered.is_empty() {
            return Err("Secret value cannot be empty".into());
        }

        // Show masked value for confirmation
        let masked = mask_value(&entered);
        println!("Value: {}", masked);

        print!("Is this correct? [Y/n]: ");
        io::stdout().flush()?;
        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm)?;

        if confirm.trim().eq_ignore_ascii_case("n") {
            return Err("Cancelled.".into());
        }

        entered
    };

    if secret_value.is_empty() {
        return Err("Secret value cannot be empty".into());
    }

    // Encrypt + store via phantom-core (mlock buffer, AES-GCM + Argon2).
    let buf = SecretBuffer::from_slice(secret_value.as_bytes())
        .map_err(|e| format!("secure buffer: {}", e))?;

    if let Some(exp) = expires {
        let days = parse_duration(&exp)?;
        let ts = (chrono::Utc::now().timestamp() + days * 86_400).max(0) as u64;
        vault.set_with_expiry(name, &buf, ts)?;
    } else {
        vault.set(name, &buf)?;
    }

    if let Some(ns) = effective_namespace {
        println!("Secret '{}' added to namespace '{}'", name, ns);
    } else {
        println!("Secret '{}' added successfully", name);
    }

    Ok(())
}

pub(crate) async fn handle_list(vault_dir: &PathBuf, namespace: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        println!("No vault found. Run 'phantom init' first.");
        return Ok(());
    }

    // Priority: CLI flag > active namespace > default namespace.
    // (phantom-core lists are namespace-scoped, mirroring the MCP server.)
    let active_ns = read_active_namespace();
    let filter_ns: Option<String> = namespace.or(active_ns);

    let vault = open_vault(vault_dir, filter_ns.as_deref())?;
    let metas = vault.list_with_metadata()?;
    // Never surface canary/honeypot entries in the normal listing.
    let entries: Vec<_> = metas.into_iter().filter(|m| !m.is_canary).collect();

    if entries.is_empty() {
        if let Some(ref ns) = filter_ns {
            if ns != "default" {
                println!("No secrets in namespace '{}'.", ns);
            } else {
                println!("No secrets stored.");
            }
        } else {
            println!("No secrets stored.");
        }
        println!();
        println!("Add a secret with: phantom add <name>");
        return Ok(());
    }

    // Print header with namespace info
    if let Some(ref ns) = filter_ns {
        if ns != "default" {
            println!("Secrets in namespace '{}':", ns);
        } else {
            println!("Secrets in vault:");
        }
    } else {
        println!("Secrets in vault:");
    }
    println!();

    let now = chrono::Utc::now().timestamp().max(0) as u64;
    for m in &entries {
        let status = expiry_status(m.expires_at, now);
        println!("  {} {}{}", "*", m.name, status);
    }

    println!();
    println!("Total: {} secret(s)", entries.len());

    Ok(())
}

async fn handle_show(
    vault_dir: &PathBuf,
    name: &str,
    masked: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let vault = open_vault(vault_dir, read_active_namespace().as_deref())?;
    let (buf, meta) = vault.get_with_metadata(name).map_err(|e| match e {
        VaultError::SecretNotFound(_) => format!("Secret '{}' not found", name),
        other => other.to_string(),
    })?;
    let value = buf.with_exposed(|b| String::from_utf8_lossy(b).to_string());

    println!("Secret: {}", name);
    println!("Created: {}", fmt_ts(meta.created_at));

    if let Some(exp) = meta.expires_at {
        println!("Expires: {}", fmt_ts(exp));
    }

    if masked || !atty::is(atty::Stream::Stdout) {
        // Show masked value (last 4 chars)
        let chars: Vec<char> = value.chars().collect();
        let len = chars.len();
        let masked_value = if len > 4 {
            let last: String = chars[len-4..].iter().collect();
            format!("{}...{}", "*".repeat(len - 4), last)
        } else {
            "*".repeat(len)
        };
        println!("Value: {}", masked_value);
    } else {
        println!();
        println!("Use --masked to see partial value, or 'phantom get' for full value.");
    }

    Ok(())
}

async fn handle_get(
    vault_dir: &PathBuf,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Security check: only allow on direct TTY
    if !atty::is(atty::Stream::Stdout) {
        return Err("'phantom get' requires direct terminal access. Use MCP for programmatic access.".into());
    }

    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let vault = open_vault(vault_dir, read_active_namespace().as_deref())?;
    let buf = vault.get(name).map_err(|e| match e {
        VaultError::SecretNotFound(_) => format!("Secret '{}' not found", name),
        other => other.to_string(),
    })?;

    // Print value directly (for piping)
    buf.with_exposed(|b| {
        println!("{}", String::from_utf8_lossy(b));
    });

    Ok(())
}

async fn handle_remove(
    vault_dir: &PathBuf,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let mut vault = open_vault(vault_dir, read_active_namespace().as_deref())?;

    if !vault.exists(name)? {
        return Err(format!("Secret '{}' not found", name).into());
    }

    // Confirm deletion
    print!("Delete secret '{}'? [y/N]: ", name);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Cancelled.");
        return Ok(());
    }

    vault.delete(name)?;

    println!("Secret '{}' removed", name);

    Ok(())
}

async fn handle_run(
    vault_dir: &PathBuf,
    secrets: &[String],
    command: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if command.is_empty() {
        return Err("No command specified".into());
    }

    if secrets.is_empty() {
        return Err("No secrets specified. Use -s <name> to inject secrets.".into());
    }

    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    // Unlock the phantom-core vault (same backend/store as the MCP server).
    let vault = open_vault(vault_dir, read_active_namespace().as_deref())?;

    // Build environment with secrets
    let mut env_vars: Vec<(String, String)> = Vec::new();

    for secret_ref in secrets {
        // Parse NAME or NAME=ENV_VAR format
        let (secret_name, env_name) = if let Some(idx) = secret_ref.find('=') {
            (secret_ref[..idx].to_string(), secret_ref[idx+1..].to_string())
        } else {
            (secret_ref.clone(), secret_ref.to_uppercase().replace('-', "_"))
        };

        // Validate environment variable name (POSIX standard)
        if !is_valid_env_var_name(&env_name) {
            return Err(format!(
                "Invalid environment variable name '{}'. Must contain only alphanumeric characters and underscores, and cannot start with a digit.",
                env_name
            ).into());
        }

        let buf = vault.get(&secret_name).map_err(|e| match e {
            VaultError::SecretNotFound(_) => format!("Secret '{}' not found", secret_name),
            other => other.to_string(),
        })?;
        let value = buf.with_exposed(|b| String::from_utf8_lossy(b).to_string());

        env_vars.push((env_name, value));
    }

    // Run command with injected environment, FILESYSTEM-CONTAINED (approach A):
    // the subprocess may write ONLY beneath a per-run scratch dir (wiped after) + /dev/null,
    // so an injected secret cannot be written to an agent-chosen file (EXFIL_FILE_SINK).
    #[cfg(target_os = "linux")]
    let status = {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::RawFd;
        use std::os::unix::process::CommandExt;

        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let scratch =
            std::env::temp_dir().join(format!("phantom-run-{}-{}", std::process::id(), uniq));
        std::fs::create_dir_all(&scratch)?;

        let open_pathfd = |p: &std::path::Path| -> std::io::Result<RawFd> {
            let c = std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has NUL")
            })?;
            let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if fd < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(fd)
            }
        };
        let scratch_fd = open_pathfd(&scratch)?;
        let devnull_fd = open_pathfd(std::path::Path::new("/dev/null"))?;

        let mut cmd = std::process::Command::new(&command[0]);
        cmd.args(&command[1..]).envs(env_vars).current_dir(&scratch);
        // SAFETY: restrict_writes_to is async-signal-safe (raw syscalls, no alloc).
        unsafe {
            cmd.pre_exec(move || {
                sandbox_fs::restrict_writes_to(&[scratch_fd], &[devnull_fd])
                    .map_err(std::io::Error::from_raw_os_error)
            });
        }
        let spawn_res = cmd.spawn();
        unsafe {
            libc::close(scratch_fd);
            libc::close(devnull_fd);
        }
        let mut child = spawn_res?;
        let status = child.wait()?;
        let _ = std::fs::remove_dir_all(&scratch);
        status
    };

    #[cfg(not(target_os = "linux"))]
    let status = {
        let mut child = std::process::Command::new(&command[0])
            .args(&command[1..])
            .envs(env_vars)
            .spawn()?;
        child.wait()?
    };

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

async fn handle_rotate(
    vault_dir: &PathBuf,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let mut vault = open_vault(vault_dir, read_active_namespace().as_deref())?;

    if !vault.exists(name)? {
        return Err(format!("Secret '{}' not found", name).into());
    }

    // Get new value with confirmation
    let new_value = prompt_password(&format!("Enter new value for '{}': ", name))?;

    if new_value.is_empty() {
        return Err("Secret value cannot be empty".into());
    }

    // Show masked value for confirmation
    let masked = mask_value(&new_value);
    println!("Value: {}", masked);

    print!("Is this correct? [Y/n]: ");
    io::stdout().flush()?;
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm)?;

    if confirm.trim().eq_ignore_ascii_case("n") {
        return Err("Cancelled.".into());
    }

    // Encrypt + update via phantom-core (set() bumps the version internally).
    let buf = SecretBuffer::from_slice(new_value.as_bytes())
        .map_err(|e| format!("secure buffer: {}", e))?;
    vault.set(name, &buf)?;

    println!("Secret '{}' rotated successfully", name);

    Ok(())
}

async fn handle_health(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("Vault Health Check");
    println!("==================");
    println!();

    // Check vault exists
    if vault_initialized(vault_dir) {
        println!("[OK] Vault found at {}", vault_dir.display());
    } else {
        println!("[!!] No vault found. Run 'phantom init' to create one.");
        return Ok(());
    }

    // Check secrets DB file permissions (phantom-core store: secrets.db)
    let db_path = vault_dir.join("secrets.db");
    #[cfg(unix)]
    if db_path.exists() {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&db_path)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode == 0o600 {
            println!("[OK] Vault file permissions: 600 (owner only)");
        } else {
            println!("[!!] Vault file permissions: {:o} (should be 600)", mode);
        }
    }

    // Try to open the vault + count secrets.
    let password = prompt_password("Enter master password to verify: ")?;
    let mut vault = Vault::new(vault_dir).map_err(|e| format!("vault: {}", e))?;
    let pw = SecretBuffer::from_slice(password.as_bytes())
        .map_err(|e| format!("secure buffer: {}", e))?;

    match vault.open(&pw) {
        Ok(()) => {
            println!("[OK] Vault decryption successful");
            let total = vault.total_count().unwrap_or(0);
            println!("[OK] {} secret(s) stored", total);

            // Count expired secrets in the default namespace.
            let now = chrono::Utc::now().timestamp().max(0) as u64;
            if let Ok(metas) = vault.list_with_metadata() {
                let expired = metas
                    .iter()
                    .filter(|m| m.expires_at.map(|e| e <= now).unwrap_or(false))
                    .count();
                if expired > 0 {
                    println!("[!!] {} secret(s) have expired", expired);
                }
            }
        }
        Err(e) => {
            println!("[!!] Failed to decrypt vault: {}", e);
        }
    }

    Ok(())
}

async fn handle_audit(
    _vault_dir: &PathBuf,
    _last: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // The vault-core encrypted audit log is not part of the phantom-core Vault
    // API. phantom-core has a separate `audit::AuditLog` (HMAC-chained) that is
    // not yet wired into CLI read operations — see report.
    Err(secure_core_unsupported("audit"))
}

// === Namespace Handlers ===

fn get_active_namespace_file() -> PathBuf {
    default_vault_dir().join("active_namespace")
}

fn read_active_namespace() -> Option<String> {
    let path = get_active_namespace_file();
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "default")
}

fn write_active_namespace(namespace: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let path = get_active_namespace_file();
    if let Some(ns) = namespace {
        std::fs::write(&path, ns)?;
    } else {
        let _ = std::fs::remove_file(&path);
    }
    Ok(())
}

async fn handle_namespace_list(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let active = read_active_namespace();

    // phantom-core lists are namespace-scoped and it exposes no "enumerate all
    // namespaces" API, so we report the default namespace + the active one
    // (from the active_namespace marker file).
    let default_count = {
        let vault = open_vault(vault_dir, None)?;
        vault.count().unwrap_or(0)
    };

    println!("Namespaces:");
    println!();

    let default_marker = if active.is_none() { " (active)" } else { "" };
    println!("  default{} ({} secrets)", default_marker, default_count);

    if let Some(ref ns) = active {
        let count = {
            let vault = open_vault(vault_dir, Some(ns))?;
            vault.count().unwrap_or(0)
        };
        println!("  {} (active) ({} secrets)", ns, count);
    } else {
        println!();
        println!("Note: only the default and active namespaces are shown — the");
        println!("secure-core backend does not enumerate all namespaces.");
    }

    Ok(())
}

async fn handle_namespace_create(vault_dir: &PathBuf, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    // Validate namespace name
    if name.is_empty() || name == "default" {
        return Err("Invalid namespace name. Cannot use empty string or 'default'.".into());
    }
    Namespace::validate_name(name)
        .map_err(|e| format!("Invalid namespace name: {}", e))?;

    // Set as active (namespaces are created lazily when a secret is first added).
    write_active_namespace(Some(name))?;

    println!("Created namespace '{}'", name);
    println!("Active namespace set to '{}'", name);
    println!();
    println!("New secrets will be added to this namespace.");
    println!("To add an existing secret to this namespace, use:");
    println!("  phantom add <name> --namespace {}", name);

    Ok(())
}

async fn handle_namespace_use(vault_dir: &PathBuf, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    if name == "default" || name.is_empty() {
        write_active_namespace(None)?;
        println!("Active namespace set to 'default'");
        return Ok(());
    }

    Namespace::validate_name(name)
        .map_err(|e| format!("Invalid namespace name: {}", e))?;

    let count = {
        let vault = open_vault(vault_dir, Some(name))?;
        vault.count().unwrap_or(0)
    };
    if count == 0 {
        println!("Warning: Namespace '{}' has no secrets yet.", name);
    }

    write_active_namespace(Some(name))?;
    println!("Active namespace set to '{}'", name);
    if count > 0 {
        println!("{} secret(s) in this namespace", count);
    }

    Ok(())
}

async fn handle_namespace_delete(vault_dir: &PathBuf, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    if name == "default" || name.is_empty() {
        return Err("Cannot delete the default namespace.".into());
    }
    Namespace::validate_name(name)
        .map_err(|e| format!("Invalid namespace name: {}", e))?;

    // Gather every secret in the namespace (name + plaintext value).
    let mut moved: Vec<(String, Vec<u8>)> = Vec::new();
    {
        let vault = open_vault(vault_dir, Some(name))?;
        for secret_name in vault.list()? {
            let buf = vault.get(&secret_name)?;
            let value = buf.with_exposed(|b| b.to_vec());
            moved.push((secret_name, value));
        }
    }

    let count = moved.len();
    if count == 0 {
        if read_active_namespace().as_deref() == Some(name) {
            write_active_namespace(None)?;
        }
        println!("Namespace '{}' has no secrets. Nothing to delete.", name);
        return Ok(());
    }

    // Confirm deletion
    print!("Delete namespace '{}' ({} secrets will be moved to default)? [y/N]: ", name, count);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Cancelled.");
        return Ok(());
    }

    // Re-open, copy each into default, then delete from the source namespace.
    let mut vault = open_vault(vault_dir, Some(name))?;
    for (secret_name, value) in &moved {
        let buf = SecretBuffer::from_slice(value).map_err(|e| format!("secure buffer: {}", e))?;
        vault.switch_namespace(Namespace::default());
        vault.set(secret_name, &buf)?;
        vault.switch_namespace(
            Namespace::new(name).map_err(|e| format!("invalid namespace: {}", e))?,
        );
        vault.delete(secret_name)?;
    }

    // Clear active namespace if it was this one
    if read_active_namespace().as_deref() == Some(name) {
        write_active_namespace(None)?;
    }

    println!("Namespace '{}' deleted. {} secret(s) moved to default.", name, count);

    Ok(())
}

// === Canary Handlers ===
//
// phantom-core has a `canary::CanaryManager` and an `is_canary` storage column,
// but the `Vault` API exposes no create/list/delete surface for canaries. Until
// that is wired, these commands report honestly instead of writing to a second
// (vault-core) store — the CLI keeps ONE backend.

async fn handle_canary_create(
    _vault_dir: &PathBuf,
    _name: &str,
    _pattern: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(secure_core_unsupported("canary create"))
}

async fn handle_canary_list(_vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    Err(secure_core_unsupported("canary list"))
}

async fn handle_canary_delete(
    _vault_dir: &PathBuf,
    _name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(secure_core_unsupported("canary delete"))
}

// === Policy Handlers ===
//
// Security policy lived in vault-core's `config.toml` (SecurityPolicy). The
// phantom-core backend has no config/policy concept, so these report honestly
// rather than reading/writing a vault-core-only config.

async fn handle_policy_show(_vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    Err(secure_core_unsupported("policy show"))
}

async fn handle_policy_set(
    _vault_dir: &PathBuf,
    _path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(secure_core_unsupported("policy set"))
}

async fn handle_policy_reset(_vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    Err(secure_core_unsupported("policy reset"))
}

async fn handle_import(
    vault_dir: &PathBuf,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let content = std::fs::read_to_string(path)?;
    let mut vault = open_vault(vault_dir, read_active_namespace().as_deref())?;

    let mut imported = 0;
    let mut skipped = 0;

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse KEY=VALUE
        if let Some(idx) = line.find('=') {
            let key = line[..idx].trim();
            let value = line[idx+1..].trim().trim_matches('"').trim_matches('\'');

            if vault.exists(key)? {
                eprintln!("Skipping '{}' (already exists)", key);
                skipped += 1;
                continue;
            }

            if value.is_empty() {
                eprintln!("Skipping '{}' (empty value)", key);
                skipped += 1;
                continue;
            }

            let buf = SecretBuffer::from_slice(value.as_bytes())
                .map_err(|e| format!("secure buffer: {}", e))?;
            vault.set(key, &buf)?;
            imported += 1;
        }
    }

    println!();
    println!("Imported {} secret(s), skipped {} (already exist)", imported, skipped);

    Ok(())
}

pub(crate) async fn handle_mcp_install() -> Result<(), Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;

    // Find the vault-mcp binary
    let mcp_binary = which_mcp_binary()?;

    // Claude Code config path
    let config_path = home.join(".claude").join("claude_desktop_config.json");

    // Read existing config or create new
    let mut config: serde_json::Value = if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)?;
        serde_json::from_str(&content)?
    } else {
        serde_json::json!({})
    };

    // Add mcpServers section if not present
    if config.get("mcpServers").is_none() {
        config["mcpServers"] = serde_json::json!({});
    }

    // Add phantom-vault server
    config["mcpServers"]["phantom-vault"] = serde_json::json!({
        "command": mcp_binary.to_string_lossy(),
        "args": []
    });

    // Create directory if needed
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write config
    let content = serde_json::to_string_pretty(&config)?;
    std::fs::write(&config_path, content)?;

    println!("MCP server installed for Claude Code");
    println!();
    println!("Configuration written to: {}", config_path.display());
    println!("MCP binary: {}", mcp_binary.display());
    println!();
    println!("Restart Claude Code to enable Phantom Vault integration.");

    Ok(())
}

async fn handle_mcp_uninstall() -> Result<(), Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let config_path = home.join(".claude").join("claude_desktop_config.json");

    if !config_path.exists() {
        println!("No Claude Code configuration found.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&config_path)?;
    let mut config: serde_json::Value = serde_json::from_str(&content)?;

    // Remove phantom-vault from mcpServers
    if let Some(servers) = config.get_mut("mcpServers") {
        if let Some(obj) = servers.as_object_mut() {
            if obj.remove("phantom-vault").is_some() {
                let content = serde_json::to_string_pretty(&config)?;
                std::fs::write(&config_path, content)?;
                println!("Phantom Vault MCP server removed from Claude Code configuration.");
                println!("Restart Claude Code to complete uninstallation.");
            } else {
                println!("Phantom Vault MCP server not found in configuration.");
            }
        }
    }

    Ok(())
}

async fn handle_mcp_status() -> Result<(), Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let config_path = home.join(".claude").join("claude_desktop_config.json");

    println!("MCP Server Status");
    println!("=================");
    println!();

    // Check binary
    match which_mcp_binary() {
        Ok(path) => println!("[OK] MCP binary found: {}", path.display()),
        Err(e) => println!("[!!] MCP binary not found: {}", e),
    }

    // Check config
    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)?;
        let config: serde_json::Value = serde_json::from_str(&content)?;

        if let Some(servers) = config.get("mcpServers") {
            if servers.get("phantom-vault").is_some() {
                println!("[OK] Phantom Vault registered in Claude Code");
            } else {
                println!("[!!] Phantom Vault not registered in Claude Code");
            }
        } else {
            println!("[!!] No MCP servers configured in Claude Code");
        }
    } else {
        println!("[!!] Claude Code configuration not found");
    }

    // Check vault
    let vault_dir = default_vault_dir();
    if vault_initialized(&vault_dir) {
        println!("[OK] Vault exists at {}", vault_dir.display());
    } else {
        println!("[!!] No vault found. Run 'phantom init' first.");
    }

    Ok(())
}

// === Helper Functions ===

// === Update Handler ===

async fn handle_update() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let current_version = env!("CARGO_PKG_VERSION");
    println!("Current version: {}", current_version);
    println!();

    // Detect OS and architecture
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    let os_target = match os {
        "macos" => "apple-darwin",
        "linux" => "unknown-linux-gnu",
        _ => return Err(format!("Unsupported OS: {}", os).into()),
    };

    let arch_target = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => return Err(format!("Unsupported architecture: {}", arch).into()),
    };

    println!("Checking for updates...");

    // Get latest version from GitHub API
    let output = Command::new("curl")
        .args(["-fsSL", "https://api.github.com/repos/r-db/phantom-vault/releases/latest"])
        .output()?;

    if !output.status.success() {
        return Err("Failed to check for updates. Check your internet connection.".into());
    }

    let response = String::from_utf8_lossy(&output.stdout);

    // Parse version from JSON response
    let json: serde_json::Value = serde_json::from_str(&response)
        .map_err(|_| "Failed to parse GitHub API response")?;

    let latest_version = json["tag_name"]
        .as_str()
        .ok_or("Failed to find tag_name in response")?
        .trim_start_matches('v');

    println!("Latest version:  {}", latest_version);

    if current_version == latest_version {
        println!();
        println!("You're already on the latest version!");
        return Ok(());
    }

    println!();
    println!("Downloading v{}...", latest_version);

    // Download new binary
    let download_url = format!(
        "https://github.com/r-db/phantom-vault/releases/download/v{}/phantom-{}-{}",
        latest_version, arch_target, os_target
    );

    let tmp_path = "/tmp/phantom-update";

    let download = Command::new("curl")
        .args(["-fsSL", "-o", tmp_path, &download_url])
        .status()?;

    if !download.success() {
        return Err(format!(
            "Failed to download update. Binary may not be available for {}-{}",
            arch_target, os_target
        ).into());
    }

    // Make executable
    Command::new("chmod")
        .args(["+x", tmp_path])
        .status()?;

    // Verify it runs
    let verify = Command::new(tmp_path)
        .arg("--version")
        .output()?;

    if !verify.status.success() {
        std::fs::remove_file(tmp_path)?;
        return Err("Downloaded binary failed verification".into());
    }

    let new_version = String::from_utf8_lossy(&verify.stdout);
    println!("Verified: {}", new_version.trim());

    // Find current binary location
    let current_exe = std::env::current_exe()?;
    let install_path = current_exe.to_string_lossy();

    println!();
    println!("Installing to {}...", install_path);

    // Need sudo for /usr/local/bin
    if install_path.contains("/usr/local/") {
        println!("(requires sudo)");
        let status = Command::new("sudo")
            .args(["mv", tmp_path, &install_path])
            .status()?;

        if !status.success() {
            return Err("Failed to install update (sudo required)".into());
        }
    } else {
        std::fs::rename(tmp_path, &*install_path)?;
    }

    println!();
    println!("Updated to v{}!", latest_version);

    Ok(())
}

// === Helper Functions ===

fn prompt_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::IsTerminal;
    // Headless channel (automation / MCP / gating): when stdin is NOT an interactive
    // terminal, read the master password from PHANTOM_VAULT_PASSWORD_FILE (preferred)
    // or PHANTOM_VAULT_PASSWORD — never prompt. Gated behind !is_terminal so an
    // interactive session always uses the hidden TTY prompt; env vars can't silently
    // downgrade an interactive unlock. (v01 headless-password fix, applied 2026-07-06.)
    if !io::stdin().is_terminal() {
        if let Ok(f) = std::env::var("PHANTOM_VAULT_PASSWORD_FILE") {
            let f = f.trim();
            if !f.is_empty() {
                let p = std::fs::read_to_string(f)?;
                return Ok(p.trim_end_matches(['\n', '\r']).to_string());
            }
        }
        if let Ok(p) = std::env::var("PHANTOM_VAULT_PASSWORD") {
            if !p.is_empty() {
                return Ok(p);
            }
        }
    }
    print!("{}", prompt);
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    Ok(password)
}

fn parse_duration(s: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let s = s.trim().to_lowercase();

    if let Some(days) = s.strip_suffix('d') {
        return Ok(days.parse()?);
    }
    if let Some(weeks) = s.strip_suffix('w') {
        return Ok(weeks.parse::<i64>()? * 7);
    }
    if let Some(months) = s.strip_suffix('m') {
        return Ok(months.parse::<i64>()? * 30);
    }

    Err(format!("Invalid duration '{}'. Use format like 7d, 2w, or 3m", s).into())
}

/// Validate environment variable name per POSIX standard
/// Must contain only alphanumeric characters and underscores, and cannot start with a digit
fn is_valid_env_var_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let first = match name.chars().next() {
        Some(c) => c,
        None => return false,
    };
    // First character must be letter or underscore
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    // Rest must be alphanumeric or underscore
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Mask a secret value for confirmation display
/// Shows first few and last few characters with ... in between
fn mask_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    if len <= 6 {
        // Very short values: show first char and asterisks
        if len <= 1 {
            "*".to_string()
        } else {
            let first: String = chars[..1].iter().collect();
            format!("{}{}*", first, "*".repeat(len - 1))
        }
    } else if len <= 12 {
        // Medium values: show first 2 and last 2
        let first: String = chars[..2].iter().collect();
        let last: String = chars[len-2..].iter().collect();
        format!("{}...{}", first, last)
    } else {
        // Longer values: show first 3 and last 3
        let first: String = chars[..3].iter().collect();
        let last: String = chars[len-3..].iter().collect();
        format!("{}...{}", first, last)
    }
}

pub(crate) async fn handle_edit(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_initialized(vault_dir) {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let mut vault = open_vault(vault_dir, read_active_namespace().as_deref())?;

    let mut current: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for meta in vault.list_with_metadata()?.into_iter().filter(|m| !m.is_canary) {
        let buf = vault.get(&meta.name)?;
        let value = buf.with_exposed(|b| String::from_utf8(b.to_vec()));
        let value = value
            .map_err(|_| format!("Secret '{}' contains non-UTF-8 data; edit not supported", meta.name))?;
        current.insert(meta.name.clone(), value);
    }

    let mut buf = String::new();
    buf.push_str("# Phantom Vault — edit secrets, save and quit to encrypt and persist.\n");
    buf.push_str("# Format: KEY=VALUE  (one per line)\n");
    buf.push_str("# - Add a new line to create a secret.\n");
    buf.push_str("# - Change a value to rotate a secret.\n");
    buf.push_str("# - Delete a line to remove a secret.\n");
    buf.push_str("# - Values containing spaces or = signs: KEY=\"my value\"\n");
    buf.push_str("# - Lines starting with # are ignored.\n");
    buf.push('\n');
    for (k, v) in &current {
        let needs_quote = v.contains(' ') || v.contains('=') || v.contains('"') || v.contains('\n') || v.contains('#');
        if needs_quote {
            let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
            buf.push_str(&format!("{}=\"{}\"\n", k, escaped));
        } else {
            buf.push_str(&format!("{}={}\n", k, v));
        }
    }

    let tmp_dir = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_name = format!("phantom-edit-{}-{}.env", std::process::id(), nanos);
    let tmp_path = tmp_dir.join(tmp_name);

    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(buf.as_bytes())?;
        file.sync_all()?;
    }

    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "vi".to_string());

    let status = std::process::Command::new(&editor)
        .arg(&tmp_path)
        .status();

    if status.is_err() || !status.as_ref().map(|s| s.success()).unwrap_or(false) {
        let _ = secure_shred(&tmp_path);
        return Err(format!("Editor '{}' did not exit cleanly. No changes saved.", editor).into());
    }

    let new_content = std::fs::read_to_string(&tmp_path)?;
    let shred_result = secure_shred(&tmp_path);

    let mut new_map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut parse_errors: Vec<String> = Vec::new();
    for (lineno, line) in new_content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let idx = match trimmed.find('=') {
            Some(i) => i,
            None => {
                parse_errors.push(format!("line {}: no '=' found, ignored", lineno + 1));
                continue;
            }
        };
        let key = trimmed[..idx].trim().to_string();
        if key.is_empty() {
            parse_errors.push(format!("line {}: empty key, ignored", lineno + 1));
            continue;
        }
        let raw_value = trimmed[idx + 1..].trim();
        let value = if raw_value.len() >= 2
            && raw_value.starts_with('"')
            && raw_value.ends_with('"')
        {
            raw_value[1..raw_value.len() - 1]
                .replace("\\\"", "\"")
                .replace("\\\\", "\\")
        } else if raw_value.len() >= 2
            && raw_value.starts_with('\'')
            && raw_value.ends_with('\'')
        {
            raw_value[1..raw_value.len() - 1].to_string()
        } else {
            raw_value.to_string()
        };
        new_map.insert(key, value);
    }

    let mut added = 0usize;
    let mut updated = 0usize;
    let mut removed = 0usize;

    let removed_keys: Vec<String> = current
        .keys()
        .filter(|k| !new_map.contains_key(*k))
        .cloned()
        .collect();
    for k in &removed_keys {
        vault.delete(k)?;
        removed += 1;
    }

    for (k, v) in &new_map {
        if v.is_empty() {
            parse_errors.push(format!("'{}': empty value, ignored", k));
            continue;
        }
        match current.get(k) {
            Some(old) if old == v => {}
            Some(_) => {
                let buf = SecretBuffer::from_slice(v.as_bytes())
                    .map_err(|e| format!("secure buffer: {}", e))?;
                vault.set(k, &buf)?;
                updated += 1;
            }
            None => {
                let buf = SecretBuffer::from_slice(v.as_bytes())
                    .map_err(|e| format!("secure buffer: {}", e))?;
                vault.set(k, &buf)?;
                added += 1;
            }
        }
    }

    shred_result?;

    println!();
    println!(
        "Saved: {} added, {} updated, {} removed",
        added, updated, removed
    );
    if !parse_errors.is_empty() {
        eprintln!();
        eprintln!("Parse warnings:");
        for w in &parse_errors {
            eprintln!("  {}", w);
        }
    }

    Ok(())
}

fn secure_shred(path: &PathBuf) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let len = std::fs::metadata(path)?.len() as usize;
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
        let zeros = vec![0u8; len];
        file.write_all(&zeros)?;
        file.sync_all()?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}

// === phantom passwd: rotate the master password ===
//
// vault-core exposed `storage::change_password` to re-key the whole vault.
// phantom-core's `Vault` has no change-password API yet (re-keying its salt +
// auth-check + encrypted store is not surfaced), so this reports honestly rather
// than silently doing nothing or reaching into a second backend.

pub(crate) async fn handle_passwd(_vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    Err(secure_core_unsupported("passwd"))
}

// === Guardrail handlers ===
//
// Guardrails (per-secret spending caps) lived in vault-core's VaultData. There
// is no phantom-core equivalent, so these report honestly. Keeping them on
// vault-core would re-introduce a second store — exactly the split-brain this
// migration removes.

pub(crate) async fn handle_guardrail_set(
    _vault_dir: &PathBuf,
    _name: &str,
    _cap: f64,
    _provider: &str,
    _alert_at: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(secure_core_unsupported("guardrail set"))
}

async fn handle_guardrail_list(_vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    Err(secure_core_unsupported("guardrail list"))
}

async fn handle_guardrail_remove(
    _vault_dir: &PathBuf,
    _name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(secure_core_unsupported("guardrail remove"))
}

async fn handle_guardrail_status(_vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    Err(secure_core_unsupported("guardrail status"))
}

fn which_mcp_binary() -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Check common locations
    let candidates = [
        dirs::home_dir().map(|h| h.join(".cargo/bin/vault-mcp")),
        Some(PathBuf::from("/usr/local/bin/vault-mcp")),
        Some(PathBuf::from("/usr/local/bin/phantom-vault")),
        dirs::home_dir().map(|h| h.join(".local/bin/vault-mcp")),
    ];

    for candidate in candidates.into_iter().flatten() {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // Try PATH
    if let Ok(output) = std::process::Command::new("which")
        .arg("vault-mcp")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout);
            return Ok(PathBuf::from(path.trim()));
        }
    }

    Err(
        "vault-mcp binary not found in ~/.cargo/bin, /usr/local/bin, or ~/.local/bin.\n\
         If you installed via the one-liner, re-run it:\n\
           curl -fsSL https://phantomvault.riscent.com/install | bash\n\
         If you built from source, build vault-mcp too:\n\
           cargo build --release -p vault-mcp"
            .into(),
    )
}
