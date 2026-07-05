//! macOS sandboxing implementation.
//!
//! Uses sandbox-exec profiles and packet filter (pf) for isolation.

use crate::{SandboxConfig, SandboxError, SandboxResult};
use std::process::Command;
use tracing::{debug, warn};

/// macOS sandbox profile generator.
pub struct MacOsSandbox {
    config: SandboxConfig,
}

impl MacOsSandbox {
    /// Create a new macOS sandbox.
    pub fn new(config: SandboxConfig) -> SandboxResult<Self> {
        Ok(Self { config })
    }

    /// Generate a sandbox-exec profile.
    pub fn generate_profile(&self) -> String {
        let mut profile = String::new();

        profile.push_str("(version 1)\n");

        // Start with deny-all for security
        if self.config.isolate_network || self.config.drop_capabilities {
            profile.push_str("(deny default)\n");
        } else {
            profile.push_str("(allow default)\n");
        }

        // Always allow process execution basics
        profile.push_str("(allow process-exec)\n");
        profile.push_str("(allow process-fork)\n");
        profile.push_str("(allow signal)\n");

        // Allow file operations based on config
        profile.push_str(&self.generate_fs_rules());

        // Network rules
        profile.push_str(&self.generate_network_rules());

        // Allow sysctl reads (needed for many programs)
        profile.push_str("(allow sysctl-read)\n");

        // Allow mach lookups (needed for many system services)
        profile.push_str("(allow mach-lookup)\n");

        profile
    }

    /// Generate filesystem rules for the profile.
    fn generate_fs_rules(&self) -> String {
        let mut rules = String::new();

        // Always allow reading common system paths
        rules.push_str("(allow file-read*\n");
        rules.push_str("  (subpath \"/usr/lib\")\n");
        rules.push_str("  (subpath \"/usr/share\")\n");
        rules.push_str("  (subpath \"/System/Library\")\n");
        rules.push_str("  (subpath \"/Library/Frameworks\")\n");
        rules.push_str("  (subpath \"/private/var/db/dyld\")\n");
        rules.push_str(")\n");

        // Allow configured read paths
        for path in &self.config.allowed_paths_read {
            rules.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                path.display()
            ));
        }

        // Allow configured write paths
        for path in &self.config.allowed_paths_write {
            rules.push_str(&format!(
                "(allow file-write* (subpath \"{}\"))\n",
                path.display()
            ));
        }

        rules
    }

    /// Generate network rules for the profile.
    fn generate_network_rules(&self) -> String {
        let mut rules = String::new();

        if self.config.isolate_network {
            // Deny all network by default
            rules.push_str("(deny network*)\n");

            // Allow specific destinations if configured
            for dest in &self.config.allowed_network {
                // Parse host:port format
                if let Some((host, _port)) = dest.split_once(':') {
                    rules.push_str(&format!(
                        "(allow network-outbound (remote tcp \"{}:*\"))\n",
                        host
                    ));
                }
            }
        } else {
            // Allow all network
            rules.push_str("(allow network*)\n");
        }

        rules
    }

    /// Apply the sandbox to the current process.
    ///
    /// This should be called after fork() but before exec().
    pub fn apply(&self) -> SandboxResult<()> {
        let profile = self.generate_profile();

        // Write profile to a temp file
        let temp_path = std::env::temp_dir().join(format!(
            "phantom_sandbox_{}.sb",
            std::process::id()
        ));

        std::fs::write(&temp_path, &profile).map_err(|e| {
            SandboxError::Creation(format!("failed to write sandbox profile: {}", e))
        })?;

        debug!("Generated sandbox profile at {:?}", temp_path);

        // Note: Actually applying sandbox-exec requires calling sandbox_init()
        // which needs to be done via FFI. For now, we just generate the profile.
        warn!(
            "sandbox-exec profile generated but not applied. \
             Full sandboxing requires FFI integration with sandbox_init()"
        );

        Ok(())
    }

    /// Configure pf rules for network filtering.
    pub fn configure_pf(&self, pid: u32) -> SandboxResult<PfHandle> {
        let anchor_name = format!("phantom_vault_{}", pid);

        // Generate pf rules
        let mut rules = String::new();
        rules.push_str(&format!("anchor \"{}\"\n", anchor_name));

        if self.config.isolate_network {
            // Block all by default for this process
            rules.push_str("block out quick proto tcp all\n");
            rules.push_str("block out quick proto udp all\n");

            // Allow specific destinations
            for dest in &self.config.allowed_network {
                if let Some((host, port)) = dest.split_once(':') {
                    rules.push_str(&format!(
                        "pass out quick proto tcp to {} port {}\n",
                        host, port
                    ));
                }
            }

            // Always allow localhost
            rules.push_str("pass out quick proto tcp to 127.0.0.1\n");
            rules.push_str("pass out quick proto udp to 127.0.0.1\n");
        }

        // Note: Actually applying pf rules requires root privileges
        // and using pfctl. For now, we just prepare the rules.
        warn!(
            "pf rules prepared but not applied. \
             Network filtering requires root privileges."
        );

        Ok(PfHandle {
            anchor_name,
            rules,
        })
    }

    /// Check if sandbox-exec is available.
    pub fn is_available() -> bool {
        Command::new("sandbox-exec")
            .arg("-h")
            .output()
            .map(|o| o.status.success() || o.status.code() == Some(1))
            .unwrap_or(false)
    }
}

/// Handle to pf rules that cleans up on drop.
pub struct PfHandle {
    anchor_name: String,
    #[allow(dead_code)]
    rules: String,
}

impl PfHandle {
    /// Remove the pf rules.
    pub fn cleanup(&self) -> SandboxResult<()> {
        // Would use pfctl to remove the anchor
        debug!("Cleaning up pf anchor: {}", self.anchor_name);
        Ok(())
    }
}

impl Drop for PfHandle {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_sandbox_creation() {
        let config = SandboxConfig::default();
        let sandbox = MacOsSandbox::new(config);
        assert!(sandbox.is_ok());
    }

    #[test]
    fn test_profile_generation() {
        let config = SandboxConfig {
            allowed_paths_read: vec![PathBuf::from("/tmp/test")],
            allowed_paths_write: vec![PathBuf::from("/tmp/output")],
            ..Default::default()
        };

        let sandbox = MacOsSandbox::new(config).unwrap();
        let profile = sandbox.generate_profile();

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("/tmp/test"));
        assert!(profile.contains("/tmp/output"));
    }

    #[test]
    fn test_network_isolation_profile() {
        let config = SandboxConfig {
            isolate_network: true,
            allowed_network: vec!["api.example.com:443".to_string()],
            ..Default::default()
        };

        let sandbox = MacOsSandbox::new(config).unwrap();
        let profile = sandbox.generate_profile();

        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("api.example.com"));
    }

    #[test]
    fn test_is_available() {
        // Just check it doesn't panic
        let _ = MacOsSandbox::is_available();
    }
}
