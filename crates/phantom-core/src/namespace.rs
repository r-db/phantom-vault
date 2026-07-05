//! Multi-tenant namespace isolation.
//!
//! Namespaces provide logical separation of secrets, allowing
//! multiple projects or environments to coexist in a single vault.

use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors that can occur during namespace operations.
#[derive(Debug, Error)]
pub enum NamespaceError {
    /// Namespace not found.
    #[error("namespace not found: {0}")]
    NotFound(String),

    /// Namespace already exists.
    #[error("namespace already exists: {0}")]
    AlreadyExists(String),

    /// Invalid namespace name.
    #[error("invalid namespace name: {0}")]
    InvalidName(String),

    /// Access denied to namespace.
    #[error("access denied to namespace: {0}")]
    AccessDenied(String),
}

/// Result type for namespace operations.
pub type NamespaceResult<T> = Result<T, NamespaceError>;

/// A namespace for organizing secrets.
#[derive(Debug, Clone)]
pub struct Namespace {
    /// Namespace identifier.
    name: String,
    /// Human-readable description.
    description: Option<String>,
    /// Creation timestamp.
    created_at: u64,
}

impl Namespace {
    /// The default namespace name.
    pub const DEFAULT: &'static str = "default";

    /// Create a new namespace.
    pub fn new(name: &str) -> NamespaceResult<Self> {
        Self::validate_name(name)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            name: name.to_string(),
            description: None,
            created_at: now,
        })
    }

    /// Create a new namespace with description.
    pub fn with_description(name: &str, description: &str) -> NamespaceResult<Self> {
        Self::validate_name(name)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            name: name.to_string(),
            description: Some(description.to_string()),
            created_at: now,
        })
    }

    /// Get the namespace name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the namespace description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Get the creation timestamp.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Validate a namespace name.
    ///
    /// Names must be lowercase alphanumeric with hyphens,
    /// 1-64 characters, and not start/end with a hyphen.
    pub fn validate_name(name: &str) -> NamespaceResult<()> {
        if name.is_empty() {
            return Err(NamespaceError::InvalidName(
                "namespace name cannot be empty".to_string(),
            ));
        }

        if name.len() > 64 {
            return Err(NamespaceError::InvalidName(
                "namespace name cannot exceed 64 characters".to_string(),
            ));
        }

        if name.starts_with('-') || name.ends_with('-') {
            return Err(NamespaceError::InvalidName(
                "namespace name cannot start or end with a hyphen".to_string(),
            ));
        }

        for c in name.chars() {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
                return Err(NamespaceError::InvalidName(format!(
                    "namespace name can only contain lowercase letters, digits, and hyphens (found '{}')",
                    c
                )));
            }
        }

        Ok(())
    }
}

impl Default for Namespace {
    fn default() -> Self {
        Self {
            name: Self::DEFAULT.to_string(),
            description: Some("Default namespace".to_string()),
            created_at: 0,
        }
    }
}

/// Manager for namespace operations.
pub struct NamespaceManager {
    namespaces: Vec<Namespace>,
}

impl NamespaceManager {
    /// Create a new namespace manager.
    pub fn new() -> Self {
        let mut manager = Self {
            namespaces: Vec::new(),
        };
        // Always have the default namespace
        manager.namespaces.push(Namespace::default());
        manager
    }

    /// Create a namespace.
    pub fn create(&mut self, name: &str, description: Option<&str>) -> NamespaceResult<Namespace> {
        // Check if already exists
        if self.namespaces.iter().any(|ns| ns.name == name) {
            return Err(NamespaceError::AlreadyExists(name.to_string()));
        }

        let namespace = match description {
            Some(desc) => Namespace::with_description(name, desc)?,
            None => Namespace::new(name)?,
        };

        self.namespaces.push(namespace.clone());
        Ok(namespace)
    }

    /// Delete a namespace and all its secrets.
    pub fn delete(&mut self, name: &str) -> NamespaceResult<()> {
        // Cannot delete default namespace
        if name == Namespace::DEFAULT {
            return Err(NamespaceError::AccessDenied(
                "cannot delete default namespace".to_string(),
            ));
        }

        let pos = self
            .namespaces
            .iter()
            .position(|ns| ns.name == name)
            .ok_or_else(|| NamespaceError::NotFound(name.to_string()))?;

        self.namespaces.remove(pos);
        Ok(())
    }

    /// List all namespaces.
    pub fn list(&self) -> Vec<&Namespace> {
        self.namespaces.iter().collect()
    }

    /// Get a namespace by name.
    pub fn get(&self, name: &str) -> NamespaceResult<&Namespace> {
        self.namespaces
            .iter()
            .find(|ns| ns.name == name)
            .ok_or_else(|| NamespaceError::NotFound(name.to_string()))
    }

    /// Check if a namespace exists.
    pub fn exists(&self, name: &str) -> bool {
        self.namespaces.iter().any(|ns| ns.name == name)
    }
}

impl Default for NamespaceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_creation() {
        let ns = Namespace::new("my-namespace").unwrap();
        assert_eq!(ns.name(), "my-namespace");
        assert!(ns.description().is_none());
    }

    #[test]
    fn test_namespace_with_description() {
        let ns = Namespace::with_description("production", "Production environment").unwrap();
        assert_eq!(ns.name(), "production");
        assert_eq!(ns.description(), Some("Production environment"));
    }

    #[test]
    fn test_namespace_validation_empty() {
        let result = Namespace::new("");
        assert!(matches!(result, Err(NamespaceError::InvalidName(_))));
    }

    #[test]
    fn test_namespace_validation_too_long() {
        let name = "a".repeat(65);
        let result = Namespace::new(&name);
        assert!(matches!(result, Err(NamespaceError::InvalidName(_))));
    }

    #[test]
    fn test_namespace_validation_hyphen_start() {
        let result = Namespace::new("-invalid");
        assert!(matches!(result, Err(NamespaceError::InvalidName(_))));
    }

    #[test]
    fn test_namespace_validation_hyphen_end() {
        let result = Namespace::new("invalid-");
        assert!(matches!(result, Err(NamespaceError::InvalidName(_))));
    }

    #[test]
    fn test_namespace_validation_uppercase() {
        let result = Namespace::new("InvalidUpper");
        assert!(matches!(result, Err(NamespaceError::InvalidName(_))));
    }

    #[test]
    fn test_namespace_validation_special_chars() {
        let result = Namespace::new("invalid_underscore");
        assert!(matches!(result, Err(NamespaceError::InvalidName(_))));
    }

    #[test]
    fn test_namespace_valid_names() {
        assert!(Namespace::new("a").is_ok());
        assert!(Namespace::new("abc").is_ok());
        assert!(Namespace::new("abc-123").is_ok());
        assert!(Namespace::new("my-namespace-2").is_ok());
    }

    #[test]
    fn test_namespace_default() {
        let ns = Namespace::default();
        assert_eq!(ns.name(), "default");
    }

    #[test]
    fn test_namespace_manager_creation() {
        let manager = NamespaceManager::new();
        assert_eq!(manager.list().len(), 1);
        assert!(manager.exists("default"));
    }

    #[test]
    fn test_namespace_manager_create() {
        let mut manager = NamespaceManager::new();
        let ns = manager.create("production", Some("Prod env")).unwrap();
        assert_eq!(ns.name(), "production");
        assert_eq!(manager.list().len(), 2);
    }

    #[test]
    fn test_namespace_manager_create_duplicate() {
        let mut manager = NamespaceManager::new();
        manager.create("test", None).unwrap();
        let result = manager.create("test", None);
        assert!(matches!(result, Err(NamespaceError::AlreadyExists(_))));
    }

    #[test]
    fn test_namespace_manager_delete() {
        let mut manager = NamespaceManager::new();
        manager.create("to-delete", None).unwrap();
        assert!(manager.exists("to-delete"));

        manager.delete("to-delete").unwrap();
        assert!(!manager.exists("to-delete"));
    }

    #[test]
    fn test_namespace_manager_delete_default() {
        let mut manager = NamespaceManager::new();
        let result = manager.delete("default");
        assert!(matches!(result, Err(NamespaceError::AccessDenied(_))));
    }

    #[test]
    fn test_namespace_manager_delete_nonexistent() {
        let mut manager = NamespaceManager::new();
        let result = manager.delete("nonexistent");
        assert!(matches!(result, Err(NamespaceError::NotFound(_))));
    }

    #[test]
    fn test_namespace_manager_get() {
        let manager = NamespaceManager::new();
        let ns = manager.get("default").unwrap();
        assert_eq!(ns.name(), "default");
    }

    #[test]
    fn test_namespace_manager_get_nonexistent() {
        let manager = NamespaceManager::new();
        let result = manager.get("nonexistent");
        assert!(matches!(result, Err(NamespaceError::NotFound(_))));
    }
}
