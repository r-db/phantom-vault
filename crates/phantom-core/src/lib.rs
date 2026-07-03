//! # Phantom Core
//!
//! Core encryption, storage, and memory protection primitives for Phantom Vault.
//!
//! This crate provides:
//! - Vault operations (open, seal, CRUD)
//! - Cryptographic primitives (AES-256-GCM, XChaCha20-Poly1305)
//! - Secure memory management (mlock, zeroize, SecretBuffer)
//! - Encrypted SQLite storage
//! - Multi-tenant namespace isolation
//! - Canary/honeypot secret management
//! - Secret dependency graphs
//! - Auto-rotation engine
//! - HMAC-chained audit logging

pub mod audit;
pub mod canary;
pub mod crypto;
pub mod dependency;
pub mod memory;
pub mod namespace;
pub mod rotation;
pub mod storage;
pub mod vault;

pub use audit::AuditLog;
pub use canary::CanaryManager;
pub use crypto::{
    Argon2Params, CryptoError, CryptoKey, CryptoResult, DualLayerCrypto,
    constant_time_eq, derive_key, generate_salt, random_bytes,
    AES_GCM_NONCE_SIZE, KEY_SIZE, SALT_SIZE, XCHACHA_NONCE_SIZE,
};
pub use dependency::DependencyGraph;
pub use memory::{MemoryError, MemoryResult, SecretBuffer, SecretString, secure_zero};
pub use namespace::Namespace;
pub use rotation::RotationEngine;
pub use storage::SecretStore;
pub use vault::Vault;
