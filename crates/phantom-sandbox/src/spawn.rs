//! Sandboxed subprocess spawning.
//!
//! Provides secure subprocess creation with secret injection
//! and output sanitization.

use crate::{ExecutionResult, SandboxConfig, SandboxError, SandboxResult};
use phantom_core::memory::SecretBuffer;
use phantom_sanitizer::{Sanitizer, SanitizerConfig};
use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Builder for sandboxed subprocess execution.
pub struct SandboxedCommand {
    command: String,
    args: Vec<String>,
    env: HashMap<String, SecretBuffer>,
    config: SandboxConfig,
    stdin: Option<Vec<u8>>,
}

impl SandboxedCommand {
    /// Create a new sandboxed command.
    pub fn new(command: &str) -> Self {
        Self {
            command: command.to_string(),
            args: Vec::new(),
            env: HashMap::new(),
            config: SandboxConfig::default(),
            stdin: None,
        }
    }

    /// Add an argument.
    pub fn arg(&mut self, arg: &str) -> &mut Self {
        self.args.push(arg.to_string());
        self
    }

    /// Add multiple arguments.
    pub fn args(&mut self, args: &[&str]) -> &mut Self {
        for arg in args {
            self.args.push((*arg).to_string());
        }
        self
    }

    /// Set an environment variable with a secret value.
    pub fn env_secret(&mut self, key: &str, value: SecretBuffer) -> &mut Self {
        self.env.insert(key.to_string(), value);
        self
    }

    /// Set sandbox configuration.
    pub fn config(&mut self, config: SandboxConfig) -> &mut Self {
        self.config = config;
        self
    }

    /// Set stdin data.
    pub fn stdin(&mut self, data: Vec<u8>) -> &mut Self {
        self.stdin = Some(data);
        self
    }

    /// Execute the command in a sandbox.
    pub fn execute(&self) -> SandboxResult<ExecutionResult> {
        debug!(
            "Executing sandboxed command: {} {:?}",
            self.command, self.args
        );

        // FAIL-CLOSED egress jail — same contract as Sandbox::execute().
        if self.config.require_network_isolation {
            if self.config.simulate_isolation_failure {
                return Err(SandboxError::IsolationUnavailable(
                    "forced via SandboxConfig.simulate_isolation_failure".to_string(),
                ));
            }
            crate::jail::ensure_available().map_err(SandboxError::IsolationUnavailable)?;
        }

        // Build environment with secrets exposed
        let mut env_strings: HashMap<String, String> = HashMap::new();
        for (key, value) in &self.env {
            value.with_exposed(|bytes| {
                if let Ok(s) = std::str::from_utf8(bytes) {
                    env_strings.insert(key.clone(), s.to_string());
                }
            });
        }

        // Under isolation the program may be rewritten (macOS sandbox-exec).
        let arg_refs: Vec<&str> = self.args.iter().map(|s| s.as_str()).collect();
        let (program, run_args): (String, Vec<String>) = if self.config.require_network_isolation {
            crate::jail::wrap(&self.command, &arg_refs)
        } else {
            (self.command.clone(), self.args.clone())
        };

        // Create the command
        let mut cmd = Command::new(&program);
        cmd.args(&run_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();

        // Set stdin
        if self.stdin.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

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

        // Enter the network namespace right before exec (Linux); fail-closed.
        if self.config.require_network_isolation {
            crate::jail::configure(&mut cmd);
        }

        // Spawn the process
        let mut child = cmd.spawn().map_err(|e| {
            if self.config.require_network_isolation {
                SandboxError::IsolationUnavailable(format!(
                    "failed to spawn under network jail ({}): {}",
                    crate::jail::mechanism(),
                    e
                ))
            } else {
                SandboxError::Execution(format!("failed to spawn process: {}", e))
            }
        })?;

        // Write stdin if provided
        if let Some(ref stdin_data) = self.stdin {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(stdin_data);
            }
        }

        // Wait with timeout
        let result = self.wait_with_timeout(&mut child, self.config.timeout);

        // Clear environment strings (they contain secrets)
        for (_, mut value) in env_strings {
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
        for (key, value) in &self.env {
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
        child: &mut std::process::Child,
        timeout: Duration,
    ) -> SandboxResult<(i32, Vec<u8>, Vec<u8>, bool)> {
        let start = Instant::now();

        // Take ownership of stdout and stderr handles
        let mut stdout_handle = child.stdout.take();
        let mut stderr_handle = child.stderr.take();

        loop {
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
                    if start.elapsed() > timeout {
                        warn!("Command timed out, killing process");
                        let _ = child.kill();
                        let _ = child.wait();

                        return Ok((-1, Vec::new(), b"Command timed out".to_vec(), true));
                    }

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

    /// Execute the command and return raw output (before sanitization).
    ///
    /// WARNING: This should only be used internally for further processing.
    #[allow(dead_code)]
    pub(crate) fn execute_raw(&self) -> SandboxResult<RawOutput> {
        // Build environment with secrets exposed
        let mut env_strings: HashMap<String, String> = HashMap::new();
        for (key, value) in &self.env {
            value.with_exposed(|bytes| {
                if let Ok(s) = std::str::from_utf8(bytes) {
                    env_strings.insert(key.clone(), s.to_string());
                }
            });
        }

        // Create the command
        let mut cmd = Command::new(&self.command);
        cmd.args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();

        // Add basic PATH
        cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");

        // Add secrets as environment variables
        for (key, value) in &env_strings {
            cmd.env(key, value);
        }

        // Spawn and wait
        let output = cmd.output().map_err(|e| {
            SandboxError::Execution(format!("failed to execute command: {}", e))
        })?;

        // Clear environment strings
        for (_, mut value) in env_strings {
            unsafe {
                let bytes = value.as_bytes_mut();
                for byte in bytes.iter_mut() {
                    *byte = 0;
                }
            }
        }

        Ok(RawOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

/// Raw output from a subprocess (before sanitization).
#[allow(dead_code)]
pub(crate) struct RawOutput {
    /// Exit code.
    pub exit_code: i32,
    /// Raw stdout bytes.
    pub stdout: Vec<u8>,
    /// Raw stderr bytes.
    pub stderr: Vec<u8>,
}

/// Spawn options for the subprocess.
#[derive(Debug, Clone)]
pub struct SpawnOptions {
    /// Working directory.
    pub cwd: Option<std::path::PathBuf>,
    /// Stdin handling.
    pub stdin: StdinOption,
    /// Stdout handling.
    pub stdout: StdioOption,
    /// Stderr handling.
    pub stderr: StdioOption,
}

/// Stdin options.
#[derive(Debug, Clone)]
pub enum StdinOption {
    /// No stdin.
    Null,
    /// Pipe data to stdin.
    Pipe(Vec<u8>),
    /// Inherit from parent.
    Inherit,
}

/// Stdio options for stdout/stderr.
#[derive(Debug, Clone)]
pub enum StdioOption {
    /// Capture output.
    Capture,
    /// Discard output.
    Null,
    /// Inherit from parent.
    Inherit,
}

impl Default for SpawnOptions {
    fn default() -> Self {
        Self {
            cwd: None,
            stdin: StdinOption::Null,
            stdout: StdioOption::Capture,
            stderr: StdioOption::Capture,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandboxed_command_builder() {
        let mut cmd = SandboxedCommand::new("echo");
        cmd.arg("hello").arg("world");

        let result = cmd.execute().unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("hello world"));
    }

    #[test]
    fn test_sandboxed_command_with_secrets() {
        let secret = SecretBuffer::from_slice(b"my_secret_password").unwrap();

        let mut cmd = SandboxedCommand::new("sh");
        cmd.args(&["-c", "echo $MY_SECRET"])
            .env_secret("MY_SECRET", secret);

        let result = cmd.execute().unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.secrets_sanitized);
        assert!(!result.stdout.contains("my_secret_password"));
    }

    #[test]
    fn test_sandboxed_command_args() {
        let mut cmd = SandboxedCommand::new("echo");
        cmd.args(&["-n", "no_newline"]);

        let result = cmd.execute().unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "no_newline");
    }
}
