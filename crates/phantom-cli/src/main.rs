//! Phantom Vault CLI
//!
//! The API key vault where secrets are used but never seen.
//! Built for the age of AI agents.

use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;

use vault_core::{
    create_vault, default_vault_dir, load_config, load_vault, save_vault,
    vault_exists, vault_file_path, EncryptedValue, Guardrail, SecretEntry, SecretType,
    VaultConfig,
};

mod interactive;

// Filesystem containment for `run` (Landlock; Linux only).
#[cfg(target_os = "linux")]
mod sandbox_fs;

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
    if vault_exists(vault_dir).await {
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
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".into());
    }

    println!("Creating new vault at {}", vault_dir.display());
    println!();

    let biometric_available = is_biometric_available();
    if enable_biometric && !biometric_available {
        println!("Note: Biometric hardware not detected. Keychain entry will be encrypted by your login.");
        println!();
    }

    let config = VaultConfig::default();
    create_vault(vault_dir, password.as_bytes(), &config).await?;

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
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    // Verify password first
    let password = prompt_password("Enter master password to enable Keychain auto-unlock: ")?;
    let config = load_config(vault_dir).await?;
    let _ = load_vault(vault_dir, password.as_bytes(), &config).await
        .map_err(|_| "Invalid password")?;

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
    if !vault_exists(vault_dir).await {
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
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (mut vault_data, keys, salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    // Check if name already exists
    if vault_data.reference_exists(name) {
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

    // Create entry
    let mut entry = SecretEntry::new(name.to_string(), SecretType::default());

    // Handle namespace (use provided, active, or default)
    let effective_namespace = namespace.or_else(read_active_namespace);
    entry.namespace = effective_namespace.clone();

    // Handle expiration
    if let Some(exp) = expires {
        let days = parse_duration(&exp)?;
        entry.expires_at = Some(chrono::Utc::now() + chrono::Duration::days(days));
    }

    // Encrypt the value
    let (ciphertext, nonce) = keys.encrypt(secret_value.as_bytes())?;
    let encrypted_value = EncryptedValue { nonce, ciphertext };

    // Store
    let entry_id = entry.id;
    vault_data.entries.push(entry);
    vault_data.encrypted_values.insert(entry_id, encrypted_value);

    save_vault(vault_dir, &vault_data, &keys, &salt).await?;

    if let Some(ns) = effective_namespace {
        println!("Secret '{}' added to namespace '{}'", name, ns);
    } else {
        println!("Secret '{}' added successfully", name);
    }

    Ok(())
}

pub(crate) async fn handle_list(vault_dir: &PathBuf, namespace: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        println!("No vault found. Run 'phantom init' first.");
        return Ok(());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (vault_data, _keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    if vault_data.entries.is_empty() {
        println!("No secrets stored.");
        println!();
        println!("Add your first secret with: phantom add <name>");
        return Ok(());
    }

    // Determine which namespace to filter by
    // Priority: CLI flag > active namespace > show all
    let active_ns = read_active_namespace();
    let filter_ns: Option<String> = namespace.or(active_ns);

    // Get filtered entries
    let entries: Vec<&SecretEntry> = if filter_ns.as_deref() == Some("default") || filter_ns.is_none() {
        // Show all if "default" or no filter
        vault_data.entries.iter().collect()
    } else {
        vault_data.filter_by_namespace(filter_ns.as_deref())
    };

    if entries.is_empty() {
        if let Some(ref ns) = filter_ns {
            println!("No secrets in namespace '{}'.", ns);
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

    for entry in &entries {
        let status = if entry.is_expired() {
            " [EXPIRED]"
        } else if entry.needs_rotation() {
            " [NEEDS ROTATION]"
        } else if let Some(days) = entry.days_until_expiration() {
            if days <= 14 {
                " [EXPIRES SOON]"
            } else {
                ""
            }
        } else {
            ""
        };

        // Show namespace tag if showing all
        let ns_tag = if filter_ns.is_none() || filter_ns.as_deref() == Some("default") {
            entry.namespace.as_ref().map(|n| format!(" [{}]", n)).unwrap_or_default()
        } else {
            String::new()
        };

        println!("  {} {}{}{}", "*", entry.reference, ns_tag, status);
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
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (vault_data, keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    let entry = vault_data.find_by_reference(name)
        .ok_or_else(|| format!("Secret '{}' not found", name))?;

    let encrypted_value = vault_data.encrypted_values.get(&entry.id)
        .ok_or("Secret value not found")?;

    let plaintext = keys.decrypt(&encrypted_value.ciphertext, &encrypted_value.nonce)?;
    let value = String::from_utf8_lossy(&plaintext);

    println!("Secret: {}", name);
    println!("Created: {}", entry.created_at.format("%Y-%m-%d %H:%M:%S UTC"));

    if let Some(exp) = entry.expires_at {
        println!("Expires: {}", exp.format("%Y-%m-%d %H:%M:%S UTC"));
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

    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (vault_data, keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    let entry = vault_data.find_by_reference(name)
        .ok_or_else(|| format!("Secret '{}' not found", name))?;

    let encrypted_value = vault_data.encrypted_values.get(&entry.id)
        .ok_or("Secret value not found")?;

    let plaintext = keys.decrypt(&encrypted_value.ciphertext, &encrypted_value.nonce)?;
    let value = String::from_utf8_lossy(&plaintext);

    // Print value directly (for piping)
    println!("{}", value);

    Ok(())
}

async fn handle_remove(
    vault_dir: &PathBuf,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (mut vault_data, keys, salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    let entry_idx = vault_data.entries.iter().position(|e| e.reference == name)
        .ok_or_else(|| format!("Secret '{}' not found", name))?;

    let entry_id = vault_data.entries[entry_idx].id;

    // Confirm deletion
    print!("Delete secret '{}'? [y/N]: ", name);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Cancelled.");
        return Ok(());
    }

    // Remove entry and value
    vault_data.entries.remove(entry_idx);
    vault_data.encrypted_values.remove(&entry_id);

    // Save
    save_vault(vault_dir, &vault_data, &keys, &salt).await?;

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

    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (vault_data, keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

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

        let entry = vault_data.find_by_reference(&secret_name)
            .ok_or_else(|| format!("Secret '{}' not found", secret_name))?;

        let encrypted_value = vault_data.encrypted_values.get(&entry.id)
            .ok_or_else(|| format!("Value for '{}' not found", secret_name))?;

        let plaintext = keys.decrypt(&encrypted_value.ciphertext, &encrypted_value.nonce)?;
        let value = String::from_utf8_lossy(&plaintext).to_string();

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
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (mut vault_data, keys, salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    let entry_idx = vault_data.entries.iter().position(|e| e.reference == name)
        .ok_or_else(|| format!("Secret '{}' not found", name))?;

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

    // Encrypt new value
    let (ciphertext, nonce) = keys.encrypt(new_value.as_bytes())?;
    let encrypted_value = EncryptedValue { nonce, ciphertext };

    // Update entry
    let entry_id = vault_data.entries[entry_idx].id;
    vault_data.entries[entry_idx].updated_at = chrono::Utc::now();
    vault_data.entries[entry_idx].last_rotated_at = Some(chrono::Utc::now());
    vault_data.encrypted_values.insert(entry_id, encrypted_value);

    // Save
    save_vault(vault_dir, &vault_data, &keys, &salt).await?;

    println!("Secret '{}' rotated successfully", name);

    Ok(())
}

async fn handle_health(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("Vault Health Check");
    println!("==================");
    println!();

    // Check vault exists
    if vault_exists(vault_dir).await {
        println!("[OK] Vault found at {}", vault_dir.display());
    } else {
        println!("[!!] No vault found. Run 'phantom init' to create one.");
        return Ok(());
    }

    // Check vault file permissions
    let vault_path = vault_file_path(vault_dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&vault_path)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode == 0o600 {
            println!("[OK] Vault file permissions: 600 (owner only)");
        } else {
            println!("[!!] Vault file permissions: {:o} (should be 600)", mode);
        }
    }

    // Try to load vault
    let password = prompt_password("Enter master password to verify: ")?;
    let config = load_config(vault_dir).await?;

    match load_vault(vault_dir, password.as_bytes(), &config).await {
        Ok((vault_data, _, _)) => {
            println!("[OK] Vault decryption successful");
            println!("[OK] {} secret(s) stored", vault_data.entries.len());

            // Check for issues
            let expired = vault_data.entries.iter().filter(|e| e.is_expired()).count();
            let needs_rotation = vault_data.entries.iter().filter(|e| e.needs_rotation()).count();

            if expired > 0 {
                println!("[!!] {} secret(s) have expired", expired);
            }
            if needs_rotation > 0 {
                println!("[!!] {} secret(s) need rotation", needs_rotation);
            }
        }
        Err(e) => {
            println!("[!!] Failed to decrypt vault: {}", e);
        }
    }

    Ok(())
}

async fn handle_audit(
    vault_dir: &PathBuf,
    last: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (_vault_data, keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    // Create audit logger
    let mut logger = vault_core::AuditLogger::new(vault_dir, None);
    logger.set_keys(keys);

    // Read entries
    let entries = logger.read_entries(Some(last), None).await?;

    if entries.is_empty() {
        println!("No audit entries found.");
        return Ok(());
    }

    println!("Audit Log (last {} entries)", last);
    println!("===========================");
    println!();

    for entry in entries.iter().rev() {
        let timestamp = entry.timestamp.format("%Y-%m-%d %H:%M:%S");
        let event_str = format_audit_event(&entry.event);
        println!("[{}] {}", timestamp, event_str);
    }

    Ok(())
}

fn format_audit_event(event: &vault_core::AuditEvent) -> String {
    use vault_core::AuditEvent;
    match event {
        AuditEvent::VaultUnlocked { biometric } => {
            format!("VaultUnlocked (biometric: {})", biometric)
        }
        AuditEvent::VaultLocked { reason } => {
            format!("VaultLocked (reason: {:?})", reason)
        }
        AuditEvent::UnlockFailed { attempt_count } => {
            format!("UnlockFailed (attempts: {})", attempt_count)
        }
        AuditEvent::LockedOut { duration_seconds } => {
            format!("LockedOut (duration: {}s)", duration_seconds)
        }
        AuditEvent::SecretAccessed { reference, tool_name, .. } => {
            if let Some(tool) = tool_name {
                format!("SecretAccessed: {} (tool: {})", reference, tool)
            } else {
                format!("SecretAccessed: {}", reference)
            }
        }
        AuditEvent::SecretCreated { reference, secret_type, .. } => {
            format!("SecretCreated: {} (type: {})", reference, secret_type)
        }
        AuditEvent::SecretUpdated { reference, updated_field, .. } => {
            format!("SecretUpdated: {} (field: {})", reference, updated_field)
        }
        AuditEvent::SecretDeleted { reference, .. } => {
            format!("SecretDeleted: {}", reference)
        }
        AuditEvent::SecretRotated { reference, .. } => {
            format!("SecretRotated: {}", reference)
        }
        AuditEvent::LeakBlocked { tool_name, pattern_name, secret_reference } => {
            if let Some(secret) = secret_reference {
                format!("LeakBlocked: {} detected {} in {}", pattern_name, secret, tool_name)
            } else {
                format!("LeakBlocked: {} pattern in {}", pattern_name, tool_name)
            }
        }
        AuditEvent::ToolCalled { tool_name, credentials_injected, .. } => {
            format!("ToolCalled: {} (credentials: {})", tool_name, credentials_injected)
        }
        AuditEvent::ConfigChanged { setting, old_value, new_value } => {
            format!("ConfigChanged: {} ('{}' -> '{}')", setting, old_value, new_value)
        }
        AuditEvent::VaultBackedUp { destination } => {
            format!("VaultBackedUp: {}", destination)
        }
        AuditEvent::VaultRestored { source } => {
            format!("VaultRestored: {}", source)
        }
        AuditEvent::SecretsExported { count, encrypted } => {
            format!("SecretsExported: {} secrets (encrypted: {})", count, encrypted)
        }
        AuditEvent::SecretsImported { count, format } => {
            format!("SecretsImported: {} secrets (format: {})", count, format)
        }
    }
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
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (vault_data, _keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    let namespaces = vault_data.list_namespaces();
    let active = read_active_namespace();

    println!("Namespaces:");
    println!();

    // Default namespace (no namespace assigned)
    let default_count = vault_data.entries.iter().filter(|e| e.namespace.is_none()).count();
    let default_marker = if active.is_none() { " (active)" } else { "" };
    println!("  default{} ({} secrets)", default_marker, default_count);

    // Named namespaces
    for ns in &namespaces {
        let count = vault_data.count_in_namespace(Some(ns));
        let marker = if active.as_deref() == Some(ns) { " (active)" } else { "" };
        println!("  {}{} ({} secrets)", ns, marker, count);
    }

    if namespaces.is_empty() && default_count > 0 {
        println!();
        println!("All secrets are in the default namespace.");
        println!("Create a namespace with: phantom namespace create <name>");
    }

    Ok(())
}

async fn handle_namespace_create(vault_dir: &PathBuf, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    // Validate namespace name
    if name.is_empty() || name == "default" {
        return Err("Invalid namespace name. Cannot use empty string or 'default'.".into());
    }

    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err("Namespace name can only contain alphanumeric characters, hyphens, and underscores.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (vault_data, _keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    // Check if namespace already exists
    let namespaces = vault_data.list_namespaces();
    if namespaces.contains(&name.to_string()) {
        println!("Namespace '{}' already exists.", name);
        println!();
        println!("Switch to it with: phantom namespace use {}", name);
        return Ok(());
    }

    // Set as active
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
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    if name == "default" || name.is_empty() {
        write_active_namespace(None)?;
        println!("Active namespace set to 'default' (showing all secrets)");
        return Ok(());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (vault_data, _keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    // Check if namespace exists (has any secrets)
    let namespaces = vault_data.list_namespaces();
    if !namespaces.contains(&name.to_string()) {
        println!("Warning: Namespace '{}' has no secrets yet.", name);
        println!("Creating it now...");
    }

    write_active_namespace(Some(name))?;
    println!("Active namespace set to '{}'", name);

    let count = vault_data.count_in_namespace(Some(name));
    if count > 0 {
        println!("{} secret(s) in this namespace", count);
    }

    Ok(())
}

async fn handle_namespace_delete(vault_dir: &PathBuf, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    if name == "default" || name.is_empty() {
        return Err("Cannot delete the default namespace.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (mut vault_data, keys, salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    // Count secrets in this namespace
    let count = vault_data.count_in_namespace(Some(name));

    if count == 0 {
        // If active namespace, clear it
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

    // Move all secrets in this namespace to default (None)
    for entry in &mut vault_data.entries {
        if entry.namespace.as_deref() == Some(name) {
            entry.namespace = None;
            entry.updated_at = chrono::Utc::now();
        }
    }

    // Save vault
    save_vault(vault_dir, &vault_data, &keys, &salt).await?;

    // Clear active namespace if it was this one
    if read_active_namespace().as_deref() == Some(name) {
        write_active_namespace(None)?;
    }

    println!("Namespace '{}' deleted. {} secret(s) moved to default.", name, count);

    Ok(())
}

// === Canary Handlers ===

async fn handle_canary_create(
    vault_dir: &PathBuf,
    name: &str,
    pattern: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use vault_core::{CanaryPattern, CanarySecret};

    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    // Parse pattern (default to AWS)
    let canary_pattern: CanaryPattern = match pattern.as_deref() {
        Some(p) => p.parse().map_err(|e: String| e)?,
        None => CanaryPattern::AwsAccessKey,
    };

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (mut vault_data, keys, salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    // Check if canary with this name already exists
    if vault_data.canaries.iter().any(|c| c.name == name) {
        return Err(format!("Canary '{}' already exists.", name).into());
    }

    // Create the canary
    let canary = CanarySecret::new(name.to_string(), canary_pattern.clone());
    let masked_value = mask_canary_value(&canary.value);

    vault_data.canaries.push(canary);

    // Save vault
    save_vault(vault_dir, &vault_data, &keys, &salt).await?;

    println!("Canary '{}' created ({} pattern)", name, canary_pattern.name());
    println!("Value: {}", masked_value);
    println!();
    println!("If this value appears in any command output, an alert will be logged.");

    Ok(())
}

fn mask_canary_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    if len > 8 {
        let first: String = chars[..4].iter().collect();
        let last: String = chars[len-4..].iter().collect();
        format!("{}...{}", first, last)
    } else {
        value.to_string()
    }
}

async fn handle_canary_list(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (vault_data, _keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    if vault_data.canaries.is_empty() {
        println!("No canary secrets configured.");
        println!();
        println!("Create one with: phantom canary create <name> --pattern aws");
        return Ok(());
    }

    println!("Canary Secrets:");
    println!();

    for canary in &vault_data.canaries {
        let masked_value = mask_canary_value(&canary.value);
        let alert_info = if canary.alert_count > 0 {
            format!(" [ALERTS: {}]", canary.alert_count)
        } else {
            String::new()
        };

        println!("  {} ({}) = {}{}", canary.name, canary.pattern.name(), masked_value, alert_info);

        if let Some(last_alert) = canary.last_alert_at {
            println!("    Last alert: {}", last_alert.format("%Y-%m-%d %H:%M:%S UTC"));
        }
    }

    println!();
    println!("Total: {} canary secret(s)", vault_data.canaries.len());

    Ok(())
}

async fn handle_canary_delete(
    vault_dir: &PathBuf,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (mut vault_data, keys, salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    let idx = vault_data.canaries.iter().position(|c| c.name == name)
        .ok_or_else(|| format!("Canary '{}' not found", name))?;

    // Confirm deletion
    print!("Delete canary '{}'? [y/N]: ", name);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Cancelled.");
        return Ok(());
    }

    vault_data.canaries.remove(idx);

    // Save vault
    save_vault(vault_dir, &vault_data, &keys, &salt).await?;

    println!("Canary '{}' deleted.", name);

    Ok(())
}

// === Policy Handlers ===

async fn handle_policy_show(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let config = load_config(vault_dir).await?;

    println!("Security Policy:");
    println!("================");
    println!();
    println!("{}", config.security_policy.to_toml());
    println!();

    if config.security_policy == vault_core::SecurityPolicy::default() {
        println!("(Using default policy)");
    }

    Ok(())
}

async fn handle_policy_set(
    vault_dir: &PathBuf,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use vault_core::SecurityPolicy;

    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    // Read and parse the policy file
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read policy file '{}': {}", path, e))?;

    let policy: SecurityPolicy = toml::from_str(&content)
        .map_err(|e| format!("Invalid policy file: {}", e))?;

    // Load current config
    let mut config = load_config(vault_dir).await?;
    config.security_policy = policy;

    // Save config
    let config_path = vault_dir.join("config.toml");
    let config_toml = toml::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(&config_path, config_toml)?;

    println!("Security policy updated from '{}'", path);
    println!();
    println!("New policy:");
    println!("{}", config.security_policy.to_toml());

    Ok(())
}

async fn handle_policy_reset(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    // Confirm reset
    print!("Reset security policy to defaults? [y/N]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Cancelled.");
        return Ok(());
    }

    // Load and reset config
    let mut config = load_config(vault_dir).await?;
    config.security_policy = vault_core::SecurityPolicy::default();

    // Save config
    let config_path = vault_dir.join("config.toml");
    let config_toml = toml::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(&config_path, config_toml)?;

    println!("Security policy reset to defaults.");
    println!();
    println!("{}", config.security_policy.to_toml());

    Ok(())
}

async fn handle_import(
    vault_dir: &PathBuf,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let content = std::fs::read_to_string(path)?;
    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (mut vault_data, keys, salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

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

            if vault_data.reference_exists(key) {
                eprintln!("Skipping '{}' (already exists)", key);
                skipped += 1;
                continue;
            }

            // Create entry
            let entry = SecretEntry::new(key.to_string(), SecretType::default());
            let entry_id = entry.id;

            // Encrypt value
            let (ciphertext, nonce) = keys.encrypt(value.as_bytes())?;
            let encrypted_value = EncryptedValue { nonce, ciphertext };

            vault_data.entries.push(entry);
            vault_data.encrypted_values.insert(entry_id, encrypted_value);
            imported += 1;
        }
    }

    // Save
    save_vault(vault_dir, &vault_data, &keys, &salt).await?;

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
    if vault_exists(&vault_dir).await {
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
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (mut vault_data, keys, salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    let mut current: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for entry in &vault_data.entries {
        if let Some(ev) = vault_data.encrypted_values.get(&entry.id) {
            let plaintext = keys.decrypt(&ev.ciphertext, &ev.nonce)?;
            let value = String::from_utf8(plaintext)
                .map_err(|_| format!("Secret '{}' contains non-UTF-8 data; edit not supported", entry.reference))?;
            current.insert(entry.reference.clone(), value);
        }
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
        let idx = vault_data.entries.iter().position(|e| &e.reference == k);
        if let Some(i) = idx {
            let id = vault_data.entries[i].id;
            vault_data.entries.remove(i);
            vault_data.encrypted_values.remove(&id);
            removed += 1;
        }
    }

    for (k, v) in &new_map {
        match current.get(k) {
            Some(old) if old == v => {}
            Some(_) => {
                if let Some(entry) = vault_data.entries.iter().find(|e| &e.reference == k) {
                    let id = entry.id;
                    let (ciphertext, nonce) = keys.encrypt(v.as_bytes())?;
                    vault_data
                        .encrypted_values
                        .insert(id, EncryptedValue { nonce, ciphertext });
                    updated += 1;
                }
            }
            None => {
                let entry = SecretEntry::new(k.clone(), SecretType::default());
                let id = entry.id;
                let (ciphertext, nonce) = keys.encrypt(v.as_bytes())?;
                vault_data.entries.push(entry);
                vault_data
                    .encrypted_values
                    .insert(id, EncryptedValue { nonce, ciphertext });
                added += 1;
            }
        }
    }

    save_vault(vault_dir, &vault_data, &keys, &salt).await?;
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

pub(crate) async fn handle_passwd(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    println!("Rotate master password");
    println!("This re-encrypts the entire vault with a new key.");
    println!();

    // Old password — accept Keychain auto-unlock OR an interactive prompt.
    // (We avoid `unlock_password` here because that path is silent on success;
    //  for password rotation the user should know explicitly when the old
    //  password is being read from Keychain vs typed.)
    let old_password: String = {
        let vault_id = vault_dir.to_string_lossy();
        match get_master_from_keychain(&vault_id) {
            Some(bytes) => match String::from_utf8(bytes) {
                Ok(s) => {
                    println!("Using current master password from macOS Keychain.");
                    s
                }
                Err(_) => prompt_password("Enter current master password: ")?,
            },
            None => prompt_password("Enter current master password: ")?,
        }
    };

    let new_password = prompt_password("New master password: ")?;
    let confirm = prompt_password("Confirm new master password: ")?;
    if new_password != confirm {
        return Err("New passwords do not match.".into());
    }
    if new_password.len() < 8 {
        return Err("New password must be at least 8 characters.".into());
    }
    if new_password == old_password {
        return Err("New password is the same as the old one.".into());
    }

    // Load vault data with the old password (this also verifies it works)
    let config = load_config(vault_dir).await?;
    let (vault_data, _keys, _salt) =
        load_vault(vault_dir, old_password.as_bytes(), &config).await?;

    // Re-encrypt with the new password via vault-core
    vault_core::storage::change_password(
        vault_dir,
        &vault_data,
        old_password.as_bytes(),
        new_password.as_bytes(),
        &config,
    )
    .await?;

    // Update Keychain entry if it was enrolled with the old password
    let vault_id = vault_dir.to_string_lossy();
    if get_master_from_keychain(&vault_id).is_some() {
        match enroll_biometric(&vault_id, new_password.as_bytes()) {
            Ok(_) => println!("Keychain entry updated to new password."),
            Err(e) => println!(
                "Warning: vault re-encrypted, but Keychain entry could not be updated ({}). \
                 Run `phantom biometric enable` manually to refresh.",
                e
            ),
        }
    }

    println!();
    println!("Master password rotated successfully.");
    println!("All future unlocks require the new password.");
    Ok(())
}

// === Guardrail handlers ===

const KNOWN_PROVIDERS: &[&str] = &[
    "openai", "anthropic", "gemini", "stripe", "twilio",
    "elevenlabs", "deepgram", "cohere", "mistral", "openrouter", "manual",
];

pub(crate) async fn handle_guardrail_set(
    vault_dir: &PathBuf,
    name: &str,
    cap: f64,
    provider: &str,
    alert_at: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    if cap <= 0.0 {
        return Err("Cap must be positive USD".into());
    }
    if alert_at == 0 || alert_at > 100 {
        return Err("alert-at must be between 1 and 100".into());
    }
    let provider_lc = provider.to_lowercase();
    if !KNOWN_PROVIDERS.contains(&provider_lc.as_str()) {
        return Err(format!(
            "Unknown provider '{}'. Known: {}",
            provider,
            KNOWN_PROVIDERS.join(", ")
        )
        .into());
    }

    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }

    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (mut vault_data, keys, salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    if vault_data.find_by_reference(name).is_none() {
        return Err(format!(
            "Secret '{}' not found in vault. Add it first with: phantom add {}",
            name, name
        )
        .into());
    }

    // If a guardrail already exists for this secret, update it; otherwise create new.
    if let Some(existing) = vault_data
        .guardrails
        .iter_mut()
        .find(|g| g.secret_ref == name)
    {
        existing.cap_usd = cap;
        existing.provider = provider_lc;
        existing.alert_at_pct = alert_at;
        println!("Updated guardrail on '{}' — cap ${:.2}/month, alert at {}%", name, cap, alert_at);
    } else {
        let mut g = Guardrail::new(name.to_string(), provider_lc, cap);
        g.alert_at_pct = alert_at;
        vault_data.guardrails.push(g);
        println!("Set guardrail on '{}' — cap ${:.2}/month, alert at {}%", name, cap, alert_at);
    }

    save_vault(vault_dir, &vault_data, &keys, &salt).await?;
    Ok(())
}

async fn handle_guardrail_list(
    vault_dir: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }
    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (vault_data, _keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    if vault_data.guardrails.is_empty() {
        println!("No guardrails set.");
        println!();
        println!("Add one: phantom guardrail set <secret-name> --cap 50 --provider openai");
        return Ok(());
    }

    println!("{:<24} {:<12} {:>10} {:>6}", "SECRET", "PROVIDER", "CAP", "ALERT");
    println!("{}", "─".repeat(58));
    for g in &vault_data.guardrails {
        println!(
            "{:<24} {:<12} ${:>8.2} {:>5}%",
            truncate(&g.secret_ref, 24),
            truncate(&g.provider, 12),
            g.cap_usd,
            g.alert_at_pct
        );
    }
    println!();
    println!("Run 'phantom guardrail status' to poll usage and see current % of cap.");
    Ok(())
}

async fn handle_guardrail_remove(
    vault_dir: &PathBuf,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }
    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (mut vault_data, keys, salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    let before = vault_data.guardrails.len();
    vault_data.guardrails.retain(|g| g.secret_ref != name);
    if vault_data.guardrails.len() == before {
        return Err(format!("No guardrail found on '{}'", name).into());
    }
    save_vault(vault_dir, &vault_data, &keys, &salt).await?;
    println!("Removed guardrail on '{}'. The secret itself is unchanged.", name);
    Ok(())
}

async fn handle_guardrail_status(
    vault_dir: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    if !vault_exists(vault_dir).await {
        return Err("No vault found. Run 'phantom init' first.".into());
    }
    let password = unlock_password(vault_dir)?;
    let config = load_config(vault_dir).await?;
    let (vault_data, _keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    if vault_data.guardrails.is_empty() {
        println!("No guardrails set.");
        return Ok(());
    }

    // For now: provider polling is not yet wired (research in flight for which providers
    // expose usage via user-level API keys). Print cached values + last poll time.
    // When adapters land in v1.7.x+, this handler will call poll_provider() per guardrail.
    println!(
        "{:<22} {:<10} {:>9} {:>9} {:>7} {:<14}",
        "SECRET", "PROVIDER", "CAP", "USED", "PCT", "STATUS"
    );
    println!("{}", "─".repeat(76));

    for g in &vault_data.guardrails {
        let pct = g.pct_used();
        let status = if g.last_polled_at.is_none() {
            "never polled".to_string()
        } else if g.is_over_cap() {
            "OVER CAP".to_string()
        } else if g.is_alerting() {
            "ALERTING".to_string()
        } else {
            "ok".to_string()
        };
        println!(
            "{:<22} {:<10} ${:>7.2} ${:>7.2} {:>6.1}% {:<14}",
            truncate(&g.secret_ref, 22),
            truncate(&g.provider, 10),
            g.cap_usd,
            g.current_usd,
            pct,
            status
        );
    }

    println!();
    println!("Note: provider polling lands incrementally — Deepgram, ElevenLabs, Twilio, and");
    println!("OpenRouter work with user-level keys (shipping in v1.7.1+). OpenAI + Anthropic");
    println!("require Admin API keys; setup guide will land alongside those adapters.");
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
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
