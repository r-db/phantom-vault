//! Filesystem containment for `phantom run` (approach A: deny-all-writes-but-ephemeral).
//!
//! The sanitizer guards stdout, but an injected secret could be written to an
//! agent-chosen FILE — the filesystem side-channel (Magnus vault-containment
//! EXFIL_FILE_SINK). This applies Landlock (unprivileged kernel LSM, ABI>=1) so the
//! `run` subprocess may write ONLY beneath a per-run scratch dir (wiped after) plus
//! /dev/null. Every other filesystem write is denied by the kernel — a secret cannot
//! reach a persistent or agent-chosen path.
//!
//! Called from a post-fork `pre_exec` hook. It MUST be async-signal-safe: raw syscalls,
//! stack-only structs, zero allocation — so it is safe even though the parent is
//! multi-threaded (tokio). FDs are opened in the parent and passed in.

use std::os::unix::io::RawFd;

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_long = 1;

// Access-right bits (uapi/linux/landlock.h). We HANDLE (restrict) the write family
// only; read/execute are left unhandled so the command still runs.
const A_WRITE_FILE: u64 = 1 << 1;
const A_REMOVE_DIR: u64 = 1 << 4;
const A_REMOVE_FILE: u64 = 1 << 5;
const A_MAKE_CHAR: u64 = 1 << 6;
const A_MAKE_DIR: u64 = 1 << 7;
const A_MAKE_REG: u64 = 1 << 8;
const A_MAKE_SOCK: u64 = 1 << 9;
const A_MAKE_FIFO: u64 = 1 << 10;
const A_MAKE_BLOCK: u64 = 1 << 11;
const A_MAKE_SYM: u64 = 1 << 12;
const A_TRUNCATE: u64 = 1 << 14; // ABI>=3 (this kernel is ABI 6)

#[inline]
fn write_access() -> u64 {
    A_WRITE_FILE | A_REMOVE_DIR | A_REMOVE_FILE | A_MAKE_CHAR | A_MAKE_DIR | A_MAKE_REG
        | A_MAKE_SOCK | A_MAKE_FIFO | A_MAKE_BLOCK | A_MAKE_SYM | A_TRUNCATE
}

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[inline]
fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// Restrict the current process (and the command it execs) to write only beneath the
/// given directory FDs (full write family), plus write to the given file FDs
/// (WRITE_FILE|TRUNCATE only — granting dir-creation rights on a non-dir EINVALs).
/// Fail-CLOSED: any error is returned so the caller aborts the run rather than
/// silently losing containment.
///
/// # Safety
/// Must be called from a pre_exec context (post-fork, pre-exec). No allocation.
pub unsafe fn restrict_writes_to(dir_fds: &[RawFd], file_fds: &[RawFd]) -> Result<(), i32> {
    const FILE_ACCESS: u64 = A_WRITE_FILE | A_TRUNCATE;
    let attr = RulesetAttr { handled_access_fs: write_access() };
    let rs = libc::syscall(
        SYS_LANDLOCK_CREATE_RULESET,
        &attr as *const RulesetAttr,
        core::mem::size_of::<RulesetAttr>(),
        0usize,
    );
    if rs < 0 {
        return Err(errno());
    }
    let rs = rs as libc::c_int;

    let add = |fd: RawFd, access: u64| -> i32 {
        let pb = PathBeneathAttr { allowed_access: access, parent_fd: fd };
        let r = libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            rs,
            LANDLOCK_RULE_PATH_BENEATH,
            &pb as *const PathBeneathAttr,
            0usize,
        );
        if r < 0 { errno() } else { 0 }
    };
    for &fd in dir_fds {
        let e = add(fd, write_access());
        if e != 0 { libc::close(rs); return Err(e); }
    }
    for &fd in file_fds {
        let e = add(fd, FILE_ACCESS);
        if e != 0 { libc::close(rs); return Err(e); }
    }

    // restrict_self requires no_new_privs.
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
        let e = errno();
        libc::close(rs);
        return Err(e);
    }
    let r = libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, rs, 0usize);
    let e = if r < 0 { errno() } else { 0 };
    libc::close(rs);
    if e != 0 {
        Err(e)
    } else {
        Ok(())
    }
}
