//! # Phantom Sandbox
//!
//! Process sandboxing and network filtering for secure command execution.
//!
//! This crate provides:
//! - Sandboxed subprocess spawning
//! - Per-process network egress filtering
//! - Platform-specific isolation (macOS sandbox-exec, Linux namespaces/seccomp)

pub mod jail;
pub mod network;
pub mod spawn;

#[cfg(target_os = "macos")]
pub mod platform {
    pub mod macos;
}

#[cfg(target_os = "linux")]
pub mod platform {
    pub mod linux;
}

use phantom_core::memory::SecretBuffer;
use phantom_sanitizer::{Sanitizer, SanitizerConfig};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur during sandbox operations.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Failed to create sandbox.
    #[error("sandbox creation failed: {0}")]
    Creation(String),

    /// Command execution failed.
    #[error("execution failed: {0}")]
    Execution(String),

    /// Network filtering failed.
    #[error("network filter failed: {0}")]
    NetworkFilter(String),

    /// Platform not supported.
    #[error("platform not supported: {0}")]
    PlatformNotSupported(String),

    /// Permission denied.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Command timed out.
    #[error("command timed out after {0:?}")]
    Timeout(Duration),

    /// A fail-closed network egress jail could not be established, so the
    /// command was refused rather than run without isolation.
    #[error("network isolation unavailable, refusing to run command: {0}")]
    IsolationUnavailable(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for sandbox operations.
pub type SandboxResult<T> = Result<T, SandboxError>;

/// Configuration for the sandbox environment.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Allowed network destinations (host:port or CIDR).
    pub allowed_network: Vec<String>,
    /// Allowed file system paths (read-only).
    pub allowed_paths_read: Vec<PathBuf>,
    /// Allowed file system paths (read-write).
    pub allowed_paths_write: Vec<PathBuf>,
    /// Maximum execution time.
    pub timeout: Duration,
    /// Maximum memory usage.
    pub max_memory: Option<u64>,
    /// Whether to isolate the network namespace.
    pub isolate_network: bool,
    /// Whether to drop all capabilities.
    pub drop_capabilities: bool,
    /// Working directory for command execution.
    pub working_dir: Option<PathBuf>,
    /// Require a fail-closed network egress jail around the command.
    ///
    /// When `true` (the default) `execute()` establishes a structural network
    /// jail (Linux user+net namespace / macOS `sandbox-exec`) around the child,
    /// and **refuses to run the command at all** if that jail cannot be
    /// established. This is the primary control that makes network exfiltration
    /// impossible; the analyzer and sanitizer are defense-in-depth on top.
    pub require_network_isolation: bool,
    /// Test hook: force the fail-closed refuse path even where isolation is
    /// available. This only ever makes execution *stricter* (it can never turn
    /// a jailed run into an unjailed one), so it is safe to expose.
    pub simulate_isolation_failure: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            allowed_network: Vec::new(),
            allowed_paths_read: Vec::new(),
            allowed_paths_write: Vec::new(),
            timeout: Duration::from_secs(30),
            max_memory: None,
            isolate_network: false, // Disabled by default since it requires privileges
            drop_capabilities: false,
            working_dir: None,
            require_network_isolation: true,
            simulate_isolation_failure: false,
        }
    }
}

/// Result of a sandboxed command execution.
#[derive(Debug)]
pub struct ExecutionResult {
    /// Exit code.
    pub exit_code: i32,
    /// Standard output (sanitized).
    pub stdout: String,
    /// Standard error (sanitized).
    pub stderr: String,
    /// Whether the command was killed due to timeout.
    pub timed_out: bool,
    /// Whether any secrets were detected and sanitized.
    pub secrets_sanitized: bool,
}

/// A sandboxed execution environment.
pub struct Sandbox {
    config: SandboxConfig,
}

impl Sandbox {
    /// Create a new sandbox with the given configuration.
    pub fn new(config: SandboxConfig) -> SandboxResult<Self> {
        // Validate configuration
        if config.timeout.is_zero() {
            return Err(SandboxError::Creation(
                "timeout must be greater than 0".to_string(),
            ));
        }

        Ok(Self { config })
    }

    /// Execute a command in the sandbox.
    ///
    /// Secrets are injected as environment variables and output is sanitized
    /// to prevent leakage.
    pub fn execute(
        &self,
        command: &str,
        args: &[&str],
        env: HashMap<String, SecretBuffer>,
    ) -> SandboxResult<ExecutionResult> {
        debug!("Executing sandboxed command: {} {:?}", command, args);

        // FAIL-CLOSED egress jail. Before anything runs, make sure we can put the
        // child in an environment with no route to the network. If we cannot,
        // refuse — never fall back to running the command with live network.
        if self.config.require_network_isolation {
            if self.config.simulate_isolation_failure {
                return Err(SandboxError::IsolationUnavailable(
                    "forced via SandboxConfig.simulate_isolation_failure".to_string(),
                ));
            }
            jail::ensure_available().map_err(SandboxError::IsolationUnavailable)?;
        }

        // Build environment with secrets
        let mut env_strings: HashMap<String, String> = HashMap::new();
        for (key, value) in &env {
            value.with_exposed(|bytes| {
                if let Ok(s) = std::str::from_utf8(bytes) {
                    env_strings.insert(key.clone(), s.to_string());
                }
            });
        }

        // Under isolation the program may be rewritten (e.g. wrapped in
        // `sandbox-exec` on macOS); on Linux it is unchanged and the jail is
        // applied via a pre_exec hook below.
        let (program, run_args): (String, Vec<String>) = if self.config.require_network_isolation {
            jail::wrap(command, args)
        } else {
            (command.to_string(), args.iter().map(|s| s.to_string()).collect())
        };

        // Create the command
        let mut cmd = Command::new(&program);
        cmd.args(&run_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear(); // Start with clean environment

        // Add basic PATH
        cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");

        // Add secrets as environment variables
        for (key, value) in &env_strings {
            cmd.env(key, value);
        }

        // Set working directory if specified
        if let Some(ref cwd) = self.config.working_dir {
            cmd.current_dir(cwd);
        }

        // Enter the network namespace right before exec (Linux). If the unshare
        // fails, spawn() below fails and the command never runs — fail-closed.
        if self.config.require_network_isolation {
            jail::configure(&mut cmd);
        }

        // Spawn the process
        let mut child = cmd.spawn().map_err(|e| {
            // A spawn failure under isolation most often means the pre_exec
            // unshare was rejected — treat it as the fail-closed refuse path.
            if self.config.require_network_isolation {
                SandboxError::IsolationUnavailable(format!(
                    "failed to spawn under network jail ({}): {}",
                    jail::mechanism(),
                    e
                ))
            } else {
                SandboxError::Execution(format!("failed to spawn process: {}", e))
            }
        })?;

        // Wait with timeout
        let result = self.wait_with_timeout(&mut child, self.config.timeout);

        // Clear environment strings (they contain secrets)
        for (_, mut value) in env_strings {
            // SAFETY: We need to zeroize the string's internal buffer
            unsafe {
                let bytes = value.as_bytes_mut();
                for byte in bytes.iter_mut() {
                    *byte = 0;
                }
            }
        }

        let (exit_code, stdout_raw, stderr_raw, timed_out) = result?;

        // Build sanitizer with all secrets
        let mut sanitizer = Sanitizer::new(SanitizerConfig::default());
        for (key, value) in &env {
            sanitizer.register_secret(key, value);
        }

        // Sanitize output
        let stdout_str = String::from_utf8_lossy(&stdout_raw).to_string();
        let stderr_str = String::from_utf8_lossy(&stderr_raw).to_string();

        let stdout_sanitized = sanitizer
            .sanitize(&stdout_str)
            .unwrap_or_else(|_| "[SANITIZATION ERROR]".to_string());
        let stderr_sanitized = sanitizer
            .sanitize(&stderr_str)
            .unwrap_or_else(|_| "[SANITIZATION ERROR]".to_string());

        let secrets_sanitized =
            stdout_sanitized != stdout_str || stderr_sanitized != stderr_str;

        Ok(ExecutionResult {
            exit_code,
            stdout: stdout_sanitized,
            stderr: stderr_sanitized,
            timed_out,
            secrets_sanitized,
        })
    }

    /// Wait for a child process with timeout.
    fn wait_with_timeout(
        &self,
        child: &mut Child,
        timeout: Duration,
    ) -> SandboxResult<(i32, Vec<u8>, Vec<u8>, bool)> {
        let start = Instant::now();

        // Take ownership of stdout and stderr handles
        let mut stdout_handle = child.stdout.take();
        let mut stderr_handle = child.stderr.take();

        loop {
            // Check if process has exited
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process exited, read remaining output
                    let mut stdout = Vec::new();
                    let mut stderr = Vec::new();

                    if let Some(ref mut handle) = stdout_handle {
                        let _ = handle.read_to_end(&mut stdout);
                    }
                    if let Some(ref mut handle) = stderr_handle {
                        let _ = handle.read_to_end(&mut stderr);
                    }

                    return Ok((
                        status.code().unwrap_or(-1),
                        stdout,
                        stderr,
                        false,
                    ));
                }
                Ok(None) => {
                    // Still running, check timeout
                    if start.elapsed() > timeout {
                        // Kill the process
                        warn!("Command timed out, killing process");
                        let _ = child.kill();
                        let _ = child.wait(); // Reap the zombie

                        return Ok((-1, Vec::new(), b"Command timed out".to_vec(), true));
                    }

                    // Sleep briefly before checking again
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    return Err(SandboxError::Execution(format!(
                        "failed to check process status: {}",
                        e
                    )));
                }
            }
        }
    }

    /// Check if the current platform supports sandboxing.
    pub fn is_supported() -> bool {
        #[cfg(target_os = "macos")]
        {
            // Check if sandbox-exec is available
            std::process::Command::new("sandbox-exec")
                .arg("-h")
                .output()
                .is_ok()
        }

        #[cfg(target_os = "linux")]
        {
            // Check if we can use user namespaces
            std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
                .map(|s| s.trim() == "1")
                .unwrap_or(false)
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            false
        }
    }

    /// Get the sandboxing method used on this platform.
    pub fn method() -> &'static str {
        #[cfg(target_os = "macos")]
        {
            "sandbox-exec"
        }

        #[cfg(target_os = "linux")]
        {
            "namespaces+seccomp"
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            "none"
        }
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_creation() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(config);
        assert!(sandbox.is_ok());
    }

    #[test]
    fn test_sandbox_invalid_timeout() {
        let config = SandboxConfig {
            timeout: Duration::from_secs(0),
            ..Default::default()
        };
        let result = Sandbox::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_simple_command() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(config).unwrap();

        let result = sandbox
            .execute("echo", &["hello", "world"], HashMap::new())
            .unwrap();

        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("hello world"));
        assert!(!result.timed_out);
    }

    #[test]
    fn test_execute_with_timeout() {
        let config = SandboxConfig {
            timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let sandbox = Sandbox::new(config).unwrap();

        let result = sandbox
            .execute("sleep", &["10"], HashMap::new())
            .unwrap();

        assert!(result.timed_out);
        assert_eq!(result.exit_code, -1);
    }

    #[test]
    fn test_execute_with_secrets() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(config).unwrap();

        let mut env = HashMap::new();
        env.insert(
            "SECRET_KEY".to_string(),
            SecretBuffer::from_slice(b"super_secret_value_12345").unwrap(),
        );

        // Run a command that echoes the secret
        let result = sandbox
            .execute("sh", &["-c", "echo $SECRET_KEY"], env)
            .unwrap();

        assert_eq!(result.exit_code, 0);
        // The secret should be sanitized
        assert!(result.secrets_sanitized);
        assert!(!result.stdout.contains("super_secret_value_12345"));
        assert!(result.stdout.contains("[REDACTED"));
    }

    #[test]
    fn test_execute_env_cleared() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(config).unwrap();

        // Try to access host environment variables
        let result = sandbox
            .execute("sh", &["-c", "echo $HOME"], HashMap::new())
            .unwrap();

        // HOME should not be set (env was cleared)
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.trim().is_empty());
    }

    #[test]
    fn test_is_supported() {
        // Just verify it doesn't panic
        let _ = Sandbox::is_supported();
    }

    #[test]
    fn test_method() {
        let method = Sandbox::method();
        assert!(!method.is_empty());
    }
}
