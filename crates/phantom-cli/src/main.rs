//! Phantom Vault CLI
//!
//! The API key vault where secrets are used but never seen.
//! Built for the age of AI agents.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "phantom")]
#[command(author = "Riscent")]
#[command(version = "1.0.0")]
#[command(about = "Phantom Vault - secrets exist but are never observable", long_about = None)]
#[command(after_help = "Documentation: https://phantomvault.riscent.com")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init,

    /// Add a secret to the vault
    Add {
        /// Name of the secret
        name: String,
        /// Import from environment variable
        #[arg(long)]
        from_env: Option<String>,
        /// Set expiration (e.g., 7d, 30d, 90d)
        #[arg(long)]
        expires: Option<String>,
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

    /// Get a secret value (requires biometric, direct TTY only)
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
    Run {
        /// Secrets to inject
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

    /// Rotate a secret
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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        None => {
            // No subcommand - show brief help
            println!("Phantom Vault - secrets exist but are never observable");
            println!();
            println!("Run 'phantom --help' for usage information.");
            println!("Run 'phantom init' to create a new vault.");
        }
        Some(cmd) => {
            handle_command(cmd);
        }
    }
}

fn handle_command(cmd: Commands) {
    match cmd {
        Commands::Init => {
            println!("phantom init: Not yet implemented");
            println!();
            println!("This will:");
            println!("  - Create an encrypted vault at ~/.phantom/vault.db");
            println!("  - Generate a master key in Secure Enclave (macOS) or TPM (Linux)");
            println!("  - Set up biometric authentication");
        }
        Commands::Add { name, from_env, expires } => {
            println!("phantom add {}: Not yet implemented", name);
            if let Some(env) = from_env {
                println!("  --from-env {}", env);
            }
            if let Some(exp) = expires {
                println!("  --expires {}", exp);
            }
        }
        Commands::List { namespace } => {
            println!("phantom list: Not yet implemented");
            if let Some(ns) = namespace {
                println!("  --namespace {}", ns);
            }
        }
        Commands::Show { name, masked } => {
            println!("phantom show {}: Not yet implemented", name);
            if masked {
                println!("  --masked");
            }
        }
        Commands::Get { name } => {
            println!("phantom get {}: Not yet implemented", name);
            println!();
            println!("This requires biometric confirmation and direct TTY access.");
        }
        Commands::Remove { name } => {
            println!("phantom remove {}: Not yet implemented", name);
        }
        Commands::Run { secret, command } => {
            println!("phantom run: Not yet implemented");
            println!("  secrets: {:?}", secret);
            println!("  command: {:?}", command);
        }
        Commands::Namespace { action } => match action {
            NamespaceCommands::List => println!("phantom namespace list: Not yet implemented"),
            NamespaceCommands::Create { name } => println!("phantom namespace create {}: Not yet implemented", name),
            NamespaceCommands::Use { name } => println!("phantom namespace use {}: Not yet implemented", name),
            NamespaceCommands::Delete { name } => println!("phantom namespace delete {}: Not yet implemented", name),
        },
        Commands::Rotate { name } => {
            println!("phantom rotate {}: Not yet implemented", name);
        }
        Commands::Audit { last } => {
            println!("phantom audit --last {}: Not yet implemented", last);
        }
        Commands::Health => {
            println!("phantom health: Not yet implemented");
        }
        Commands::Canary { action } => match action {
            CanaryCommands::Create { name, pattern } => {
                println!("phantom canary create {}: Not yet implemented", name);
                if let Some(p) = pattern {
                    println!("  --pattern {}", p);
                }
            }
            CanaryCommands::List => println!("phantom canary list: Not yet implemented"),
            CanaryCommands::Delete { name } => println!("phantom canary delete {}: Not yet implemented", name),
        },
        Commands::Policy { action } => match action {
            PolicyCommands::Show => println!("phantom policy show: Not yet implemented"),
            PolicyCommands::Set { path } => println!("phantom policy set {}: Not yet implemented", path),
            PolicyCommands::Reset => println!("phantom policy reset: Not yet implemented"),
        },
        Commands::Mcp { action } => match action {
            McpCommands::Install => {
                println!("phantom mcp install: Not yet implemented");
                println!();
                println!("This will configure Claude Code to use Phantom Vault's MCP server.");
            }
            McpCommands::Uninstall => println!("phantom mcp uninstall: Not yet implemented"),
            McpCommands::Status => println!("phantom mcp status: Not yet implemented"),
        },
        Commands::Import { path } => {
            println!("phantom import {}: Not yet implemented", path);
        }
    }
}
