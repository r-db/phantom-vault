//! Vault Tauri Plugin - Desktop integration for vault management
//!
//! Provides Tauri commands for:
//! - Vault creation, unlock, lock
//! - Secret management (add, update, delete, list)
//! - Configuration management
//! - Audit log viewing

pub mod commands;

pub use commands::*;
