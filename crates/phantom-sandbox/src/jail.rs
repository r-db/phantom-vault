//! Fail-closed network egress jail.
//!
//! This is the *primary* structural control that makes secret exfiltration
//! impossible for a command run via `vault_run`: the child process is placed in
//! an environment with **no route to any network** before it is `exec`'d. The
//! command-analyzer denylist and the output-sanitizer are defense-in-depth on
//! top of this, not the load-bearing control.
//!
//! # Linux
//!
//! The child enters a fresh **user + network namespace** via
//! `unshare(CLONE_NEWUSER | CLONE_NEWNET)` from a `pre_exec` hook (which runs in
//! the single-threaded forked child, so the otherwise-`EINVAL`-on-multithreaded
//! `CLONE_NEWUSER` succeeds). A brand-new network namespace contains only a
//! `lo` interface in the DOWN state and no default route, so `connect()`,
//! `sendto()` and DNS all fail — there is no path off the box, regardless of
//! what the command tries. If the `unshare` fails, the hook returns an error,
//! `spawn()` fails, and the command never runs.
//!
//! # macOS
//!
//! The command is wrapped in `sandbox-exec` with a `(deny network*)` profile.
//! If `sandbox-exec` is not available, execution is refused.
//!
//! # Fail-closed contract
//!
//! [`ensure_available`] must return `Ok(())` before a command is allowed to run
//! under isolation. On any platform where isolation cannot be established it
//! returns `Err`, and the caller ([`crate::Sandbox::execute`]) refuses to run.

use std::sync::OnceLock;

/// Human-readable description of the isolation mechanism on this platform.
pub fn mechanism() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux user+network namespace (unshare CLONE_NEWUSER|CLONE_NEWNET)"
    }
    #[cfg(target_os = "macos")]
    {
        "macos sandbox-exec (deny network*)"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "none"
    }
}

/// Verify that a fail-closed network jail can actually be established on this
/// host *right now*. Returns `Err(reason)` if it cannot — callers MUST refuse to
/// run the command in that case.
///
/// The real probe result is cached (it does not change over a process lifetime),
/// so repeated `vault_run` calls pay the cost once.
pub fn ensure_available() -> Result<(), String> {
    static PROBE: OnceLock<Result<(), String>> = OnceLock::new();
    PROBE.get_or_init(probe).clone()
}

#[cfg(target_os = "linux")]
fn probe() -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    // Spawn a throwaway child that only enters the namespaces and exits. If the
    // unshare in pre_exec fails, spawn() surfaces the error here and we report
    // isolation as unavailable (fail-closed).
    let mut cmd = Command::new("/bin/true");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear();
    // SAFETY: the closure only performs an async-signal-safe unshare() syscall.
    unsafe {
        cmd.pre_exec(enter_namespaces);
    }

    match cmd.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!(
            "network-namespace probe exited with {status}; cannot guarantee egress isolation"
        )),
        Err(e) => Err(format!(
            "cannot create isolated network namespace ({e}); \
             unprivileged user namespaces may be disabled (see \
             /proc/sys/kernel/unprivileged_userns_clone)"
        )),
    }
}

/// Enter a fresh user + network namespace. Runs inside the forked child, before
/// `exec`. MUST stay async-signal-safe: it performs a single `unshare` syscall
/// and no allocation.
#[cfg(target_os = "linux")]
fn enter_namespaces() -> std::io::Result<()> {
    use nix::sched::{unshare, CloneFlags};
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET)
        .map_err(|errno| std::io::Error::from_raw_os_error(errno as i32))
}

/// Apply the Linux egress jail to a command about to be spawned.
#[cfg(target_os = "linux")]
pub fn configure(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure only performs an async-signal-safe unshare() syscall.
    unsafe {
        cmd.pre_exec(enter_namespaces);
    }
}

/// Rewrite `(program, args)` so the command runs under isolation. On Linux the
/// jail is applied via [`configure`] instead, so the command is unchanged.
#[cfg(target_os = "linux")]
pub fn wrap(program: &str, args: &[&str]) -> (String, Vec<String>) {
    (program.to_string(), args.iter().map(|s| s.to_string()).collect())
}

// ---- macOS ----------------------------------------------------------------

#[cfg(target_os = "macos")]
fn probe() -> Result<(), String> {
    use std::process::{Command, Stdio};
    let ok = Command::new("sandbox-exec")
        .arg("-h")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success() || s.code() == Some(1))
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err("sandbox-exec not available; cannot establish network jail".to_string())
    }
}

/// A `sandbox-exec` profile that denies all network access.
#[cfg(target_os = "macos")]
const DENY_NETWORK_PROFILE: &str = "(version 1)(allow default)(deny network*)";

#[cfg(target_os = "macos")]
pub fn configure(_cmd: &mut std::process::Command) {
    // Isolation on macOS is applied by wrapping the program (see `wrap`).
}

/// On macOS, run the command under `sandbox-exec -p '(deny network*)'`.
#[cfg(target_os = "macos")]
pub fn wrap(program: &str, args: &[&str]) -> (String, Vec<String>) {
    let mut wrapped = vec![
        "-p".to_string(),
        DENY_NETWORK_PROFILE.to_string(),
        program.to_string(),
    ];
    wrapped.extend(args.iter().map(|s| s.to_string()));
    ("sandbox-exec".to_string(), wrapped)
}

// ---- unsupported platforms ------------------------------------------------

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn probe() -> Result<(), String> {
    Err("network isolation is not implemented on this platform".to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn configure(_cmd: &mut std::process::Command) {}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn wrap(program: &str, args: &[&str]) -> (String, Vec<String>) {
    (program.to_string(), args.iter().map(|s| s.to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mechanism_is_named() {
        assert!(!mechanism().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn egress_is_blocked_inside_jail() {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        // If this host can't establish the jail at all, skip — the fail-closed
        // path is exercised separately via SandboxConfig.
        if ensure_available().is_err() {
            eprintln!("skipping: isolation unavailable on this host");
            return;
        }

        // Inside the jail there is no route off-box: opening a TCP socket to a
        // public address must fail. We use python3's socket with a short timeout.
        let script = "import socket,sys\n\
                      s=socket.socket()\n\
                      s.settimeout(3)\n\
                      try:\n    s.connect(('1.1.1.1',443)); print('CONNECTED'); sys.exit(1)\n\
                      except Exception:\n    print('BLOCKED'); sys.exit(0)\n";
        let mut cmd = Command::new("python3");
        cmd.arg("-c")
            .arg(script)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(enter_namespaces);
        }
        let out = cmd.output().expect("spawn jailed python");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("BLOCKED"),
            "egress was NOT blocked inside the jail: {stdout}"
        );
    }
}
