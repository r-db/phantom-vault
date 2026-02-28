//! Vault Core - Secure credential storage and management
//!
//! This crate provides:
//! - AES-256-GCM encryption for secrets at rest
//! - Argon2id key derivation from master password
//! - Secure memory handling with automatic zeroization
//! - Output filtering to detect credential leaks
//! - Encrypted audit logging

pub mod models;
pub mod crypto;
pub mod storage;
pub mod filter;
pub mod audit;
pub mod error;

pub use models::*;
pub use crypto::*;
pub use storage::*;
pub use filter::*;
pub use audit::*;
pub use error::*;
