//! Error types for vault operations

use thiserror::Error;

/// Errors that can occur during vault operations
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault is locked - unlock with master password first")]
    VaultLocked,

    #[error("Invalid master password")]
    InvalidPassword,

    #[error("Vault file not found: {0}")]
    VaultNotFound(String),

    #[error("Vault file corrupted or tampered")]
    VaultCorrupted,

    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    #[error("Secret reference already exists: {0}")]
    DuplicateReference(String),

    #[error("Secret has expired: {0}")]
    SecretExpired(String),

    #[error("Usage limit exceeded for secret: {0}")]
    UsageLimitExceeded(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Audit log error: {0}")]
    AuditError(String),

    #[error("Too many failed unlock attempts - locked out for {0} seconds")]
    LockedOut(u64),
}

/// Errors during output filtering
#[derive(Error, Debug)]
pub enum FilterError {
    #[error("Pattern compilation error: {0}")]
    PatternError(String),

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}

/// Errors during MCP operations
#[derive(Error, Debug)]
pub enum McpError {
    #[error("Vault is locked")]
    VaultLocked,

    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    #[error("Invalid tool arguments: {0}")]
    InvalidArguments(String),

    #[error("Secret reference not found: {0}")]
    SecretNotFound(String),

    #[error("Tool execution error: {0}")]
    ExecutionError(String),

    #[error("Credential leaked in output - blocked")]
    CredentialLeakBlocked,

    #[error("Transport error: {0}")]
    TransportError(String),

    #[error("Tool not allowed by security policy: {0}")]
    ToolNotAllowed(String),
}

pub type VaultResult<T> = Result<T, VaultError>;
pub type FilterResult<T> = Result<T, FilterError>;
pub type McpResult<T> = Result<T, McpError>;
