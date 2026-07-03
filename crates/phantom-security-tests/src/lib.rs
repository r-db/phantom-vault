//! # Phantom Security Tests
//!
//! This crate contains security tests for Phantom Vault.
//!
//! The tests verify that the vault cannot be bypassed by any known attack vector:
//!
//! - **Oracle Attacks**: Character-by-character extraction attempts
//! - **Sanitization**: Output encoding bypass attempts
//! - **Memory Security**: Zeroization and protection verification
//! - **Canary Detection**: Honeypot secret alerting
//! - **Namespace Isolation**: Cross-namespace access attempts
//! - **Lineage Tracking**: Audit trail integrity
//!
//! Run the tests with: `cargo test -p phantom-security-tests`

// This crate exists only to provide security tests
// All test code is in the tests/ directory
