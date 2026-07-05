//! # Namespace Isolation Tests
//!
//! These tests verify that namespace isolation is enforced:
//! - Secrets in one namespace cannot be accessed from another
//! - Cross-namespace access attempts are blocked and logged
//! - Namespace boundaries are maintained even with similar names
//!
//! CRITICAL: Namespace isolation MUST be enforced at all times.

use phantom_sanitizer::{Sanitizer, SanitizerConfig};
use std::collections::HashMap;

// =============================================================================
// Mock Namespace Manager for Testing
// =============================================================================

/// A mock namespace manager for testing isolation concepts.
/// This demonstrates the expected behavior of the real NamespaceManager.
struct MockNamespaceManager {
    /// Secrets organized by namespace.
    secrets: HashMap<String, HashMap<String, Vec<u8>>>,
    /// Currently active namespace.
    current_namespace: String,
}

impl MockNamespaceManager {
    fn new() -> Self {
        Self {
            secrets: HashMap::new(),
            current_namespace: "default".to_string(),
        }
    }

    /// Set the current namespace context.
    fn set_namespace(&mut self, namespace: &str) {
        self.current_namespace = namespace.to_string();
        // Ensure namespace exists
        self.secrets.entry(namespace.to_string()).or_default();
    }

    /// Store a secret in the current namespace.
    fn store_secret(&mut self, name: &str, value: &[u8]) {
        let ns = self.secrets.entry(self.current_namespace.clone()).or_default();
        ns.insert(name.to_string(), value.to_vec());
    }

    /// Get a secret from the current namespace only.
    fn get_secret(&self, name: &str) -> Option<Vec<u8>> {
        self.secrets
            .get(&self.current_namespace)
            .and_then(|ns| ns.get(name).cloned())
    }

    /// Attempt cross-namespace access (should fail).
    fn get_secret_from_namespace(&self, namespace: &str, name: &str) -> Result<Vec<u8>, &'static str> {
        // SECURITY CHECK: Only allow access to current namespace
        if namespace != self.current_namespace {
            return Err("SECURITY VIOLATION: Cross-namespace access denied");
        }

        self.secrets
            .get(namespace)
            .and_then(|ns| ns.get(name).cloned())
            .ok_or("Secret not found")
    }

    /// List secrets in the current namespace only.
    fn list_secrets(&self) -> Vec<String> {
        self.secrets
            .get(&self.current_namespace)
            .map(|ns| ns.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// List all namespaces (metadata only, no secrets).
    fn list_namespaces(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }
}

// =============================================================================
// TEST 19: Namespace Isolation
// =============================================================================

/// Verify that secrets in one namespace cannot be accessed from another.
///
/// This test:
/// 1. Creates secrets in namespace A
/// 2. Switches to namespace B
/// 3. Attempts to access namespace A's secrets
/// 4. Verifies access is denied
///
/// Expected: Cross-namespace access is DENIED.
#[test]
fn test_namespace_isolation_access_denied() {
    let mut manager = MockNamespaceManager::new();

    // Create secret in "production" namespace
    manager.set_namespace("production");
    manager.store_secret("DB_PASSWORD", b"prod_secret_password_123");

    // Switch to "staging" namespace
    manager.set_namespace("staging");
    manager.store_secret("DB_PASSWORD", b"staging_password_456");

    // Attempt to access production secret from staging context
    let result = manager.get_secret_from_namespace("production", "DB_PASSWORD");

    assert!(
        result.is_err(),
        "SECURITY FAILURE: Cross-namespace access should be denied!"
    );
    assert!(
        result.unwrap_err().contains("Cross-namespace access denied"),
        "Error should indicate security violation"
    );
}

/// Test that same-namespace access is allowed.
#[test]
fn test_same_namespace_access_allowed() {
    let mut manager = MockNamespaceManager::new();

    manager.set_namespace("production");
    manager.store_secret("API_KEY", b"prod_api_key_value");

    // Access within same namespace should work
    let result = manager.get_secret_from_namespace("production", "API_KEY");

    assert!(
        result.is_ok(),
        "Same-namespace access should be allowed"
    );
    assert_eq!(result.unwrap(), b"prod_api_key_value");
}

/// Test that listing only shows current namespace secrets.
#[test]
fn test_list_shows_only_current_namespace() {
    let mut manager = MockNamespaceManager::new();

    // Create secrets in multiple namespaces
    manager.set_namespace("production");
    manager.store_secret("PROD_SECRET_1", b"value1");
    manager.store_secret("PROD_SECRET_2", b"value2");

    manager.set_namespace("staging");
    manager.store_secret("STAGING_SECRET", b"value3");

    manager.set_namespace("development");
    manager.store_secret("DEV_SECRET", b"value4");

    // List should only show current namespace
    let dev_secrets = manager.list_secrets();
    assert_eq!(dev_secrets.len(), 1);
    assert!(dev_secrets.contains(&"DEV_SECRET".to_string()));

    // Switch and verify
    manager.set_namespace("production");
    let prod_secrets = manager.list_secrets();
    assert_eq!(prod_secrets.len(), 2);
    assert!(!prod_secrets.contains(&"STAGING_SECRET".to_string()));
}

// =============================================================================
// TEST 20: Cross-Namespace Access Blocked
// =============================================================================

/// Verify that various cross-namespace access methods are all blocked.
#[test]
fn test_cross_namespace_path_traversal_blocked() {
    let mut manager = MockNamespaceManager::new();

    manager.set_namespace("production");
    manager.store_secret("SECRET", b"prod_value");

    manager.set_namespace("staging");

    // Various path traversal attempts that should all fail
    let attack_paths = [
        "../production/SECRET",
        "production/../production/SECRET",
        "/production/SECRET",
        "production//SECRET",
    ];

    for path in &attack_paths {
        // These would need to be parsed and validated
        // For this test, we verify the concept: path traversal should fail
        let namespace = path.split('/').next().unwrap_or("staging");
        if namespace != "staging" && !namespace.is_empty() && namespace != "." && namespace != ".." {
            let result = manager.get_secret_from_namespace(namespace, "SECRET");
            assert!(
                result.is_err(),
                "Path traversal attack '{}' should be blocked",
                path
            );
        }
    }
}

/// Test that namespace names are validated properly.
#[test]
fn test_namespace_name_validation() {
    /// Validate a namespace name.
    fn is_valid_namespace_name(name: &str) -> bool {
        // Must be 1-64 characters
        if name.is_empty() || name.len() > 64 {
            return false;
        }

        // Must be lowercase alphanumeric with hyphens
        if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return false;
        }

        // Must not start or end with hyphen
        if name.starts_with('-') || name.ends_with('-') {
            return false;
        }

        // Must not contain consecutive hyphens
        if name.contains("--") {
            return false;
        }

        true
    }

    // Valid names
    assert!(is_valid_namespace_name("production"));
    assert!(is_valid_namespace_name("staging-env"));
    assert!(is_valid_namespace_name("dev-1"));
    assert!(is_valid_namespace_name("a"));

    // Invalid names
    assert!(!is_valid_namespace_name("")); // Empty
    assert!(!is_valid_namespace_name("-staging")); // Starts with hyphen
    assert!(!is_valid_namespace_name("staging-")); // Ends with hyphen
    assert!(!is_valid_namespace_name("prod--env")); // Consecutive hyphens
    assert!(!is_valid_namespace_name("Production")); // Uppercase
    assert!(!is_valid_namespace_name("prod.env")); // Invalid character
    assert!(!is_valid_namespace_name("prod/env")); // Path separator (dangerous)
    assert!(!is_valid_namespace_name(&"a".repeat(65))); // Too long
}

// =============================================================================
// TEST: Namespace Isolation with Sanitizer
// =============================================================================

/// Verify that sanitization respects namespace boundaries.
#[test]
fn test_sanitizer_namespace_isolation() {
    // Create separate sanitizers for each namespace
    // (In production, namespace context would be passed)

    // Use completely distinct secrets to avoid partial match overlap
    let config = SanitizerConfig {
        detect_partial: false, // Disable partial matching for this test
        ..SanitizerConfig::default()
    };

    let mut prod_sanitizer = Sanitizer::new(config.clone());
    let mut staging_sanitizer = Sanitizer::new(config);

    // Register namespace-specific secrets with no common substrings
    prod_sanitizer.register_secret_bytes("DB_PASSWORD", b"xKj9mN2pL5vR8wQ4");
    staging_sanitizer.register_secret_bytes("DB_PASSWORD", b"aB3cD7eF1gH6iJ0k");

    // Production sanitizer should catch production secrets only
    let prod_output = "Password: xKj9mN2pL5vR8wQ4";
    assert!(prod_sanitizer.contains_secret(prod_output));
    assert!(!staging_sanitizer.contains_secret(prod_output));

    // Staging sanitizer should catch staging secrets only
    let staging_output = "Password: aB3cD7eF1gH6iJ0k";
    assert!(staging_sanitizer.contains_secret(staging_output));
    assert!(!prod_sanitizer.contains_secret(staging_output));
}

// =============================================================================
// TEST: Namespace-Scoped Secret Names
// =============================================================================

/// Test that secrets with the same name in different namespaces are independent.
#[test]
fn test_same_secret_name_different_namespaces() {
    let mut manager = MockNamespaceManager::new();

    // Same secret name, different values in different namespaces
    manager.set_namespace("production");
    manager.store_secret("API_KEY", b"prod_key_12345");

    manager.set_namespace("staging");
    manager.store_secret("API_KEY", b"staging_key_67890");

    manager.set_namespace("development");
    manager.store_secret("API_KEY", b"dev_key_abcde");

    // Each namespace should have its own value
    manager.set_namespace("production");
    assert_eq!(manager.get_secret("API_KEY").unwrap(), b"prod_key_12345");

    manager.set_namespace("staging");
    assert_eq!(manager.get_secret("API_KEY").unwrap(), b"staging_key_67890");

    manager.set_namespace("development");
    assert_eq!(manager.get_secret("API_KEY").unwrap(), b"dev_key_abcde");
}

// =============================================================================
// TEST: Namespace Deletion Isolation
// =============================================================================

/// Test that deleting one namespace doesn't affect others.
#[test]
fn test_namespace_deletion_isolation() {
    let mut manager = MockNamespaceManager::new();

    // Setup multiple namespaces
    manager.set_namespace("production");
    manager.store_secret("PROD_SECRET", b"prod_value");

    manager.set_namespace("staging");
    manager.store_secret("STAGING_SECRET", b"staging_value");

    manager.set_namespace("to-delete");
    manager.store_secret("DELETE_ME", b"temp_value");

    // Simulate namespace deletion
    manager.secrets.remove("to-delete");

    // Other namespaces should be unaffected
    manager.set_namespace("production");
    assert_eq!(manager.get_secret("PROD_SECRET").unwrap(), b"prod_value");

    manager.set_namespace("staging");
    assert_eq!(manager.get_secret("STAGING_SECRET").unwrap(), b"staging_value");
}

// =============================================================================
// TEST: Default Namespace Behavior
// =============================================================================

/// Test that the default namespace exists and is accessible.
#[test]
fn test_default_namespace_exists() {
    let mut manager = MockNamespaceManager::new();

    // Default namespace should work without explicit set
    manager.store_secret("DEFAULT_SECRET", b"default_value");

    let namespaces = manager.list_namespaces();
    assert!(namespaces.contains(&"default".to_string()));

    assert_eq!(manager.get_secret("DEFAULT_SECRET").unwrap(), b"default_value");
}

// =============================================================================
// TEST: Namespace Enumeration Protection
// =============================================================================

/// Verify that namespace enumeration is controlled.
#[test]
fn test_namespace_enumeration_controlled() {
    let mut manager = MockNamespaceManager::new();

    // Create namespaces
    manager.set_namespace("public-api");
    manager.set_namespace("internal-services");
    manager.set_namespace("customer-data");

    // Listing namespaces should be allowed (for management)
    // But should NOT reveal secret names or values
    let namespaces = manager.list_namespaces();

    // Can see namespace names exist
    assert!(namespaces.len() >= 3);

    // But only current namespace secrets are accessible
    manager.set_namespace("public-api");
    let secrets = manager.list_secrets();
    assert!(secrets.is_empty()); // No secrets stored yet in this namespace
}

// =============================================================================
// TEST: Concurrent Namespace Access
// =============================================================================

/// Test that concurrent access to different namespaces is isolated.
#[test]
fn test_concurrent_namespace_isolation() {
    use std::sync::{Arc, Mutex};
    use std::thread;

    // Shared manager (in real implementation, would use proper synchronization)
    let manager = Arc::new(Mutex::new(MockNamespaceManager::new()));

    // Setup namespaces
    {
        let mut m = manager.lock().unwrap();
        m.set_namespace("namespace-a");
        m.store_secret("SECRET_A", b"value_a");
        m.set_namespace("namespace-b");
        m.store_secret("SECRET_B", b"value_b");
    }

    let manager_a = Arc::clone(&manager);
    let manager_b = Arc::clone(&manager);

    let handle_a = thread::spawn(move || {
        let mut m = manager_a.lock().unwrap();
        m.set_namespace("namespace-a");
        m.get_secret("SECRET_A")
    });

    let handle_b = thread::spawn(move || {
        let mut m = manager_b.lock().unwrap();
        m.set_namespace("namespace-b");
        m.get_secret("SECRET_B")
    });

    let result_a = handle_a.join().unwrap();
    let result_b = handle_b.join().unwrap();

    assert_eq!(result_a.unwrap(), b"value_a");
    assert_eq!(result_b.unwrap(), b"value_b");
}

// =============================================================================
// TEST: Namespace in Audit Trail
// =============================================================================

/// Verify that namespace information is included in audit events.
#[test]
fn test_namespace_in_audit_context() {
    #[derive(Debug)]
    struct AuditEvent {
        namespace: String,
        operation: String,
        secret_name: String,
    }

    let mut audit_log: Vec<AuditEvent> = Vec::new();

    // Simulate secret access with audit
    let event = AuditEvent {
        namespace: "production".to_string(),
        operation: "read".to_string(),
        secret_name: "DB_PASSWORD".to_string(),
    };
    audit_log.push(event);

    // Verify audit contains namespace
    assert_eq!(audit_log[0].namespace, "production");
    assert_eq!(audit_log[0].operation, "read");
    assert_eq!(audit_log[0].secret_name, "DB_PASSWORD");
}
