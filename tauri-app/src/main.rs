//! Vault Secrets - Tauri Desktop Application
//!
//! This is the main entry point for the desktop application.
//! It sets up the Tauri runtime and exposes commands to the Flutter frontend.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::sync::Arc;
use tauri::State;
use tokio::sync::RwLock;
use tracing::{error, info};

use vault_core::models::{SecretType, VaultConfig};
use vault_tauri::{
    AddSecretInput, AppState, CommandResult, SearchFilter, SecretInfo,
    UpdateSecretInput, VaultStatus,
};

/// Shared application state
type SharedState = Arc<RwLock<AppState>>;

// ============================================================================
// TAURI COMMANDS
// ============================================================================

/// Check if vault exists
#[tauri::command]
async fn check_vault_exists(state: State<'_, SharedState>) -> Result<bool, String> {
    let state = state.read().await;
    Ok(vault_tauri::vault_exists(&state.vault_dir).await)
}

/// Get current vault status
#[tauri::command]
async fn get_status(state: State<'_, SharedState>) -> Result<VaultStatus, String> {
    let state = state.read().await;
    let exists = vault_tauri::vault_exists(&state.vault_dir).await;
    Ok(vault_tauri::get_vault_status(
        state.vault_data.as_ref(),
        exists,
    ))
}

/// Create a new vault
#[tauri::command]
async fn create_vault(
    password: String,
    state: State<'_, SharedState>,
) -> Result<CommandResult<()>, String> {
    let state = state.read().await;

    match vault_tauri::create_vault(&state.vault_dir, &password).await {
        Ok(_) => {
            info!("Vault created successfully");
            Ok(CommandResult::ok(()))
        }
        Err(e) => {
            error!("Failed to create vault: {}", e);
            Ok(CommandResult::err(e.to_string()))
        }
    }
}

/// Unlock the vault
#[tauri::command]
async fn unlock_vault(
    password: String,
    state: State<'_, SharedState>,
) -> Result<CommandResult<VaultStatus>, String> {
    let mut state = state.write().await;

    // Check lockout
    if state.is_locked_out() {
        return Ok(CommandResult::err("Too many failed attempts. Please wait."));
    }

    match vault_tauri::unlock_vault(&state.vault_dir, &password, &state.config).await {
        Ok((data, keys, salt)) => {
            state.vault_data = Some(data);
            state.keys = Some(keys);
            state.salt = Some(salt);
            state.failed_attempts = 0;

            info!("Vault unlocked successfully");

            let status = vault_tauri::get_vault_status(state.vault_data.as_ref(), true);
            Ok(CommandResult::ok(status))
        }
        Err(e) => {
            state.failed_attempts += 1;

            // Set lockout if too many failures
            if state.failed_attempts >= state.config.max_unlock_attempts {
                state.lockout_until = Some(
                    std::time::Instant::now()
                        + std::time::Duration::from_secs(state.config.lockout_duration_seconds),
                );
            }

            error!("Failed to unlock vault: {}", e);
            Ok(CommandResult::err(e.to_string()))
        }
    }
}

/// Lock the vault
#[tauri::command]
async fn lock_vault(state: State<'_, SharedState>) -> Result<(), String> {
    let mut state = state.write().await;
    state.lock();
    info!("Vault locked");
    Ok(())
}

/// List all secrets
#[tauri::command]
async fn list_secrets(
    state: State<'_, SharedState>,
) -> Result<CommandResult<Vec<SecretInfo>>, String> {
    let state = state.read().await;

    match &state.vault_data {
        Some(data) => {
            let secrets = vault_tauri::list_secrets(data);
            Ok(CommandResult::ok(secrets))
        }
        None => Ok(CommandResult::err("Vault is locked")),
    }
}

/// Search secrets with filters
#[tauri::command]
async fn search_secrets(
    filter: SearchFilter,
    state: State<'_, SharedState>,
) -> Result<CommandResult<Vec<SecretInfo>>, String> {
    let state = state.read().await;

    match &state.vault_data {
        Some(data) => {
            let secrets = vault_tauri::search_secrets(data, filter);
            Ok(CommandResult::ok(secrets))
        }
        None => Ok(CommandResult::err("Vault is locked")),
    }
}

/// Get secret info by reference
#[tauri::command]
async fn get_secret(
    reference: String,
    state: State<'_, SharedState>,
) -> Result<CommandResult<SecretInfo>, String> {
    let state = state.read().await;

    match &state.vault_data {
        Some(data) => match vault_tauri::get_secret_info(data, &reference) {
            Some(info) => Ok(CommandResult::ok(info)),
            None => Ok(CommandResult::err(format!("Secret '{}' not found", reference))),
        },
        None => Ok(CommandResult::err("Vault is locked")),
    }
}

/// Add a new secret
#[tauri::command]
async fn add_secret(
    input: AddSecretInput,
    state: State<'_, SharedState>,
) -> Result<CommandResult<SecretInfo>, String> {
    let mut state = state.write().await;

    let (vault_data, keys) = match (&mut state.vault_data, &state.keys) {
        (Some(data), Some(keys)) => (data, keys),
        _ => return Ok(CommandResult::err("Vault is locked")),
    };

    match vault_tauri::add_secret(vault_data, keys, input) {
        Ok(info) => {
            // Save to disk
            if let Some(salt) = &state.salt {
                if let Err(e) = vault_tauri::save_vault_state(
                    &state.vault_dir,
                    vault_data,
                    keys,
                    salt,
                ).await {
                    error!("Failed to save vault: {}", e);
                    return Ok(CommandResult::err(format!("Failed to save: {}", e)));
                }
            }

            info!("Secret '{}' added", info.reference);
            Ok(CommandResult::ok(info))
        }
        Err(e) => {
            error!("Failed to add secret: {}", e);
            Ok(CommandResult::err(e.to_string()))
        }
    }
}

/// Update secret metadata
#[tauri::command]
async fn update_secret(
    input: UpdateSecretInput,
    state: State<'_, SharedState>,
) -> Result<CommandResult<SecretInfo>, String> {
    let mut state = state.write().await;

    let (vault_data, keys) = match (&mut state.vault_data, &state.keys) {
        (Some(data), Some(keys)) => (data, keys),
        _ => return Ok(CommandResult::err("Vault is locked")),
    };

    match vault_tauri::update_secret(vault_data, input) {
        Ok(info) => {
            // Save to disk
            if let Some(salt) = &state.salt {
                if let Err(e) = vault_tauri::save_vault_state(
                    &state.vault_dir,
                    vault_data,
                    keys,
                    salt,
                ).await {
                    error!("Failed to save vault: {}", e);
                    return Ok(CommandResult::err(format!("Failed to save: {}", e)));
                }
            }

            info!("Secret '{}' updated", info.reference);
            Ok(CommandResult::ok(info))
        }
        Err(e) => {
            error!("Failed to update secret: {}", e);
            Ok(CommandResult::err(e.to_string()))
        }
    }
}

/// Rotate (update) a secret's value
#[tauri::command]
async fn rotate_secret(
    reference: String,
    new_value: String,
    state: State<'_, SharedState>,
) -> Result<CommandResult<()>, String> {
    let mut state = state.write().await;

    let (vault_data, keys) = match (&mut state.vault_data, &state.keys) {
        (Some(data), Some(keys)) => (data, keys),
        _ => return Ok(CommandResult::err("Vault is locked")),
    };

    match vault_tauri::update_secret_value(vault_data, keys, &reference, &new_value) {
        Ok(_) => {
            // Save to disk
            if let Some(salt) = &state.salt {
                if let Err(e) = vault_tauri::save_vault_state(
                    &state.vault_dir,
                    vault_data,
                    keys,
                    salt,
                ).await {
                    error!("Failed to save vault: {}", e);
                    return Ok(CommandResult::err(format!("Failed to save: {}", e)));
                }
            }

            info!("Secret '{}' rotated", reference);
            Ok(CommandResult::ok(()))
        }
        Err(e) => {
            error!("Failed to rotate secret: {}", e);
            Ok(CommandResult::err(e.to_string()))
        }
    }
}

/// Delete a secret
#[tauri::command]
async fn delete_secret(
    reference: String,
    state: State<'_, SharedState>,
) -> Result<CommandResult<()>, String> {
    let mut state = state.write().await;

    let (vault_data, keys) = match (&mut state.vault_data, &state.keys) {
        (Some(data), Some(keys)) => (data, keys),
        _ => return Ok(CommandResult::err("Vault is locked")),
    };

    match vault_tauri::delete_secret(vault_data, &reference) {
        Ok(_) => {
            // Save to disk
            if let Some(salt) = &state.salt {
                if let Err(e) = vault_tauri::save_vault_state(
                    &state.vault_dir,
                    vault_data,
                    keys,
                    salt,
                ).await {
                    error!("Failed to save vault: {}", e);
                    return Ok(CommandResult::err(format!("Failed to save: {}", e)));
                }
            }

            info!("Secret '{}' deleted", reference);
            Ok(CommandResult::ok(()))
        }
        Err(e) => {
            error!("Failed to delete secret: {}", e);
            Ok(CommandResult::err(e.to_string()))
        }
    }
}

/// Change master password
#[tauri::command]
async fn change_password(
    old_password: String,
    new_password: String,
    state: State<'_, SharedState>,
) -> Result<CommandResult<()>, String> {
    let mut state = state.write().await;

    let vault_data = match &state.vault_data {
        Some(data) => data,
        None => return Ok(CommandResult::err("Vault is locked")),
    };

    match vault_tauri::change_password(
        &state.vault_dir,
        vault_data,
        &old_password,
        &new_password,
        &state.config,
    ).await {
        Ok(new_keys) => {
            state.keys = Some(new_keys);
            info!("Master password changed");
            Ok(CommandResult::ok(()))
        }
        Err(e) => {
            error!("Failed to change password: {}", e);
            Ok(CommandResult::err(e.to_string()))
        }
    }
}

/// Get vault configuration
#[tauri::command]
async fn get_config(state: State<'_, SharedState>) -> Result<VaultConfig, String> {
    let state = state.read().await;
    Ok(state.config.clone())
}

/// Update vault configuration
#[tauri::command]
async fn update_config(
    config: VaultConfig,
    state: State<'_, SharedState>,
) -> Result<CommandResult<()>, String> {
    let mut state = state.write().await;

    match vault_tauri::save_config(&state.vault_dir, &config).await {
        Ok(_) => {
            state.config = config;
            info!("Configuration updated");
            Ok(CommandResult::ok(()))
        }
        Err(e) => {
            error!("Failed to save config: {}", e);
            Ok(CommandResult::err(e.to_string()))
        }
    }
}

// ============================================================================
// MAIN
// ============================================================================

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("Starting Vault Secrets");

    // Create shared state
    let state: SharedState = Arc::new(RwLock::new(AppState::new()));

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            check_vault_exists,
            get_status,
            create_vault,
            unlock_vault,
            lock_vault,
            list_secrets,
            search_secrets,
            get_secret,
            add_secret,
            update_secret,
            rotate_secret,
            delete_secret,
            change_password,
            get_config,
            update_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
