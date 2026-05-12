//! Interactive entry point for `phantom` (no args).
//!
//! Renders a first-run wizard for new users and a returning-user menu for
//! existing vault holders. Uses `inquire` for portable prompts (works the
//! same on macOS / Linux / Windows).

use std::path::PathBuf;

use inquire::{Confirm, Password, PasswordDisplayMode, Select, Text};
use vault_core::{load_config, load_vault, save_vault, vault_exists, EncryptedValue, SecretEntry, SecretType};

use crate::{
    create_vault_with_password, get_master_from_keychain, handle_edit, handle_guardrail_set,
    handle_list, handle_mcp_install, handle_passwd,
};

/// Entry point for bare `phantom` — first-run wizard or returning-user menu.
pub(crate) async fn run_default(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Non-TTY fallback (e.g. `phantom | jq` in a CI script). inquire would
    // hang or crash; we print a quick-help instead.
    if !atty::is(atty::Stream::Stdin) || !atty::is(atty::Stream::Stdout) {
        println!("Phantom Vault — secrets exist but are never observable");
        println!();
        println!("Interactive mode requires a terminal. Use these for scripting:");
        println!("  phantom init                Create a new vault");
        println!("  phantom edit                Bulk-add secrets in $EDITOR");
        println!("  phantom mcp install         Wire Phantom into Claude Code");
        println!("  phantom --help              Full command list");
        return Ok(());
    }

    if vault_exists(vault_dir).await {
        returning_user_menu(vault_dir).await
    } else {
        first_run_wizard(vault_dir).await
    }
}

fn print_banner() {
    println!();
    println!("  Phantom Vault");
    println!("  ─────────────");
    println!("  Secrets exist but are never observable.");
    println!();
}

async fn first_run_wizard(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    print_banner();
    println!("Looks like you're new here. Let's set up your encrypted vault.");
    println!();

    // 1. Master password (with confirmation)
    let password = loop {
        let pw = Password::new("Choose a master password")
            .with_display_mode(PasswordDisplayMode::Masked)
            .with_help_message(
                "Minimum 8 characters. This is the ONLY thing that unlocks your secrets — choose carefully. Lost passwords are unrecoverable by design.",
            )
            .prompt()?;
        if pw.len() < 8 {
            println!("Too short — needs at least 8 characters. Try again.");
            continue;
        }
        break pw;
    };

    // 2. Optional: Keychain auto-unlock
    let enable_biometric = Confirm::new("Enable Keychain auto-unlock so you don't type the password again?")
        .with_default(true)
        .with_help_message(
            "Master password is stored encrypted in your macOS Keychain. You'll see one 'Always Allow' prompt the first time. Linux/Windows: skipped.",
        )
        .prompt()?;

    // 3. Create the vault
    create_vault_with_password(vault_dir, &password, enable_biometric).await?;

    // 4. Add first secret(s) — cascading loop
    println!("Now let's add your first secret(s).");
    println!("Tip: the value is hidden as you type. Press Enter on an empty name when done.");
    println!();
    add_secrets_loop(vault_dir, &password).await?;

    // 5. Offer MCP install
    let install_mcp = Confirm::new("Wire Phantom into Claude Code now?")
        .with_default(true)
        .with_help_message(
            "Updates ~/.claude/claude_desktop_config.json so Claude can use your secrets by reference name (never seeing the value). Restart Claude Code after.",
        )
        .prompt()?;
    if install_mcp {
        handle_mcp_install().await?;
    }

    // 6. Outro
    println!();
    println!("✨ You're set up.");
    println!();
    println!("Useful commands to remember:");
    println!("  phantom              Open this menu anytime");
    println!("  phantom edit         Bulk-edit all secrets in your editor");
    println!("  phantom passwd       Change your master password");
    println!("  phantom guardrail    Set spending caps on a credential");
    Ok(())
}

async fn returning_user_menu(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    print_banner();

    // Unlock: Keychain auto-unlock first, fall back to interactive password prompt.
    let password = unlock_or_prompt(vault_dir).await?;

    // Quick stats line
    let config = load_config(vault_dir).await?;
    let (vault_data, _keys, _salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;
    let n = vault_data.entries.len();
    let g = vault_data.guardrails.len();
    println!(
        "{} secret{} stored, {} guardrail{} set.",
        n,
        if n == 1 { "" } else { "s" },
        g,
        if g == 1 { "" } else { "s" }
    );
    println!();

    // Main loop
    loop {
        let choice = Select::new(
            "What would you like to do?",
            vec![
                "Add secrets (guided)",
                "Bulk-edit all secrets in $EDITOR",
                "List secret names",
                "Set up Claude Code integration",
                "Set or update a spending guardrail",
                "Change master password",
                "Quit",
            ],
        )
        .prompt()?;

        match choice {
            "Add secrets (guided)" => {
                add_secrets_loop(vault_dir, &password).await?;
            }
            "Bulk-edit all secrets in $EDITOR" => {
                handle_edit(vault_dir).await?;
            }
            "List secret names" => {
                handle_list(vault_dir, None).await?;
            }
            "Set up Claude Code integration" => {
                handle_mcp_install().await?;
            }
            "Set or update a spending guardrail" => {
                guardrail_wizard(vault_dir).await?;
            }
            "Change master password" => {
                handle_passwd(vault_dir).await?;
                println!();
                println!("Password rotated. Re-run `phantom` to continue with the new password.");
                return Ok(());
            }
            "Quit" => return Ok(()),
            _ => {}
        }
        println!();
    }
}

/// Try Keychain auto-unlock first, fall back to interactive password prompt.
async fn unlock_or_prompt(vault_dir: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let vault_id = vault_dir.to_string_lossy();
    if let Some(bytes) = get_master_from_keychain(&vault_id) {
        if let Ok(s) = String::from_utf8(bytes) {
            return Ok(s);
        }
    }
    // No Keychain entry — ask the user
    let pw = Password::new("Master password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .without_confirmation()
        .prompt()?;
    Ok(pw)
}

/// Cascading add: name → hidden value → repeat until empty name. Reloads the
/// vault once at the start, batches every secret into a single save at the end.
async fn add_secrets_loop(
    vault_dir: &PathBuf,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config(vault_dir).await?;
    let (mut vault_data, keys, salt) = load_vault(vault_dir, password.as_bytes(), &config).await?;

    let mut added = 0usize;
    let mut updated = 0usize;
    loop {
        let name = Text::new("Secret name (empty to finish):")
            .with_help_message("e.g. OPENAI_KEY, STRIPE_SECRET, DATABASE_URL")
            .prompt()?;
        let name = name.trim().to_string();
        if name.is_empty() {
            break;
        }
        let value = Password::new(&format!("Value for '{}':", name))
            .with_display_mode(PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt()?;

        let existing_id = vault_data
            .find_by_reference(&name)
            .map(|e| e.id);

        let (ciphertext, nonce) = keys.encrypt(value.as_bytes())?;
        let encrypted = EncryptedValue { nonce, ciphertext };

        match existing_id {
            Some(id) => {
                vault_data.encrypted_values.insert(id, encrypted);
                updated += 1;
                println!("✓ Updated '{}'.", name);
            }
            None => {
                let entry = SecretEntry::new(name.clone(), SecretType::default());
                let id = entry.id;
                vault_data.entries.push(entry);
                vault_data.encrypted_values.insert(id, encrypted);
                added += 1;
                println!("✓ Stored '{}'.", name);
            }
        }
    }

    if added > 0 || updated > 0 {
        save_vault(vault_dir, &vault_data, &keys, &salt).await?;
        println!();
        println!(
            "Saved: {} new, {} updated.",
            added, updated
        );
    } else {
        println!("(No secrets added.)");
    }
    Ok(())
}

async fn guardrail_wizard(vault_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let name = Text::new("Which secret should we cap spend on?")
        .with_help_message("Must match a secret name in the vault. Run 'List secret names' first if unsure.")
        .prompt()?;

    let cap_str = Text::new("Monthly USD cap:")
        .with_placeholder("50")
        .prompt()?;
    let cap: f64 = cap_str
        .trim()
        .parse()
        .map_err(|_| "Cap must be a number (e.g. 50, 100.50)")?;

    let provider = Select::new(
        "Which provider issues this key?",
        vec![
            "openai",
            "anthropic",
            "gemini",
            "stripe",
            "twilio",
            "elevenlabs",
            "deepgram",
            "cohere",
            "mistral",
            "openrouter",
            "manual",
        ],
    )
    .prompt()?;

    handle_guardrail_set(vault_dir, name.trim(), cap, provider, 80).await?;
    Ok(())
}
