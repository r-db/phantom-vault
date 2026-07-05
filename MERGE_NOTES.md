# Phantom-Vault — Option A Merge Notes

_Executed per `~/nous/phantom-vault-handoff/MERGE_PHASE1.md` + `AUDIT2_RECONCILE.md` (Option A)._
_Work done ONLY in `~/nous/phantom-vault-prod`. The fork `~/nous/phantom-vault` was read but never modified. Nothing pushed to `r-db`; commits are local only._

## What this merge did

1. **Vendored the fork's secure core** into prod's workspace (copied from `~/nous/phantom-vault/crates/`, unchanged except the egress-jail wiring below):
   - `phantom-core` — encryption, encrypted-SQLite storage, `SecretBuffer` (mlock/zeroize).
   - `phantom-sanitizer` — per-secret output redaction incl. encoded-variant detection.
   - `phantom-analyzer` — command pre-analysis (strict **default-deny allowlist** + oracle/exfil pattern denylist).
   - `phantom-sandbox` — sandboxed subprocess execution **+ the new fail-closed egress jail**.
   - `phantom-mcp` — the safe MCP tool scheme (`vault_run`, `vault_masked`, `vault_list`, `vault_exists`, `vault_health`, `vault_rotate`) with trust-lineage gating and rate limiting.
   - `phantom-security-tests` — the ported adversarial/red-team crate **+ the new `adversarial_exfil.rs` suite**.
   - Wired into `Cargo.toml` workspace `members` + `workspace.dependencies` (added `chacha20poly1305`, `rusqlite` bundled, `memsec`, `region`, `base64`, `tempfile`, `repository`, and the `phantom-*` path deps).

2. **Deleted prod's injection MCP tools.** `crates/vault-mcp/src/{handlers,registry,server,state}.rs` were removed — with them, `vault_execute_with_credential`, `vault_http_request`, raw `vault_database_query`, and the ignore-leak-flag `vault_git_operation` (audit findings P-C1/P-C2/P-H1/P-H2) are **gone**. `vault-mcp` is now a thin binary that launches the safe `phantom-mcp` server backed by a `phantom-core` vault (unlocked from `PHANTOM_VAULT_PASSWORD_FILE`/`PHANTOM_VAULT_PASSWORD`, never silently from the keychain). The binary name (`vault-mcp`) and the product shell (CLI, `install.sh`, CI) are unchanged.

3. **Wired the egress jail, FAIL-CLOSED** — the real §1b gap. See below.

4. **Kept prod's product shell**: `phantom-cli`, `vault-core` (crypto/at-rest), `vault-tauri`, `install.sh`, CI, docs are untouched.

## The egress jail (the load-bearing control)

Before this merge the fork's `Sandbox::execute()` spawned the child **directly** — `network.rs` and the platform profiles were built but never connected (`apply()` was a no-op that only logged a warning). The active network defense was the analyzer denylist alone.

Now `phantom-sandbox/src/jail.rs` connects a structural, fail-closed jail into **both** live execution paths (`Sandbox::execute` and `SandboxedCommand::execute`):

- **Linux:** a `pre_exec` hook runs `unshare(CLONE_NEWUSER | CLONE_NEWNET)` in the forked child before `exec`. A fresh network namespace has only a `lo` interface (DOWN) and no route, so `connect()`/`sendto()`/DNS all fail — there is no path off the box regardless of what the command does. `CLONE_NEWUSER` makes this work unprivileged (verified on this host: kernel 6.12, `unprivileged_userns_clone=1`).
- **macOS:** the command is wrapped in `sandbox-exec -p '(deny network*)'`.
- **Fail-closed:** `jail::ensure_available()` probes that isolation can actually be established. If it cannot (unavailable platform, disabled userns, `sandbox-exec` missing), `execute()` returns `SandboxError::IsolationUnavailable` and **refuses to run the command** — it never falls back to live network. `SandboxConfig.require_network_isolation` defaults to `true`.

The analyzer and sanitizer are now **defense-in-depth on top of** this structural control, not the primary control.

## Test results (all in `--release`)

```
phantom-analyzer          60 passed
phantom-core              87 passed
phantom-mcp               32 passed
phantom-sandbox           25 passed   (incl. jail::egress_is_blocked_inside_jail)
phantom-sanitizer         58 passed
phantom-security-tests:
  adversarial_exfil        5 passed   (NEW)
  canary                  14 passed
  lineage                 15 passed
  memory                  14 passed
  namespace               12 passed
  oracle_attack           15 passed
  sanitization            15 passed
TOTAL                    ~342 passed, 0 failed
```

### The adversarial suite (`tests/adversarial_exfil.rs`)

A simulated malicious LLM drives the real MCP `vault_run` against a canary
(`AKIAIOSFODNN7CANARY1`) with ~25 exfil vectors: env dump (`printenv`/`env`/`/proc/self/environ`),
`${VAR:o:l}` substring + chunking, encoding (`base64`/`xxd`/`od`/`rev`/`tr`),
network (`curl`/`nc`/`/dev/tcp`/pipeline-to-curl **and allowlisted `git ls-remote`/`git clone`**),
DNS (`getent`/`nslookup`), file write, and error/timing oracles.

- **Zero canary escapes**: the raw canary (and its base64) never appears in any tool output, and a localhost TCP sink never receives it.
- **Jail is load-bearing, proven non-vacuously**: the two allowlisted `git` network vectors actually **execute inside the jail** (analyzer permits `git`) and are contained by the jail alone — the run counts this and asserts `executed >= 1`.
- **Jail proven independent of the analyzer**: `test_egress_jail_blocks_network_even_without_analyzer` calls the sandbox directly (analyzer bypassed) with a blatant python socket exfil → sink receives nothing.
- **Fail-closed proven**: `test_egress_jail_is_fail_closed` forces isolation-unavailable → `execute()` refuses.
- **Controls guard against false passes**: one control confirms `vault_run` actually executes an allowlisted command (`git --version` → OK); another confirms the sink detects the canary when it *does* arrive.

## Residual gaps / follow-ups (honest)

1. **Two storage/crypto backends coexist.** The `phantom` CLI still writes to `vault-core` (AES-GCM + prod's file layout); the MCP server now reads `phantom-core`'s encrypted SQLite vault. They do **not** share at-rest data. For the security gate this is irrelevant (the gate is the MCP/exec exfil surface), but for a shippable product the CLI and MCP must share one vault. **Recommended follow-up:** unify on one backend (either port `phantom-mcp` onto `vault-core`, or make the CLI use `phantom-core`). This is a security-critical rewrite and was deliberately NOT guessed at here per the handoff's "note ambiguity rather than guess" instruction.
2. **Live wiring NOT migrated (by design).** `~/nous/.mcp.json` and `~/.local/bin/phantom` still point at the fork/live binary. Step 8 of the plan (repoint to the merged build, retire the password-file bypass) is left for Ryan to do after review.
3. **macOS jail is untested here.** The `sandbox-exec (deny network*)` path is implemented but this host is Linux; it needs validation on macOS before shipping there.
4. **Analyzer is a denylist-with-allowlist.** Novel encodings emitted by an *allowlisted* command could in principle bypass both the analyzer patterns and the sanitizer's known-encoding detection and reach the LLM as output. This cannot exfiltrate over the **network** (the jail is structural), but the output channel to the LLM is only as strong as the sanitizer for exotic encodings. This is the inherent residual of any output-filter approach; the jail is what makes network exfil impossible.
5. **CLI-side audit findings from `AUDIT2_RECONCILE §2b` are NOT addressed** (P-H3 `phantom run` has no filter/TTY guard; P-H4 silent keychain unlock; P-M1 plaintext not zeroized; P-H5 unverified `phantom update`). These live in `phantom-cli`/`vault-core` and are out of scope for Phase 1 (the MCP exfil surface). The MCP server itself no longer silently unlocks from the keychain.
6. **License/version not unified** (plan step 7). Vendored fork crates were `Apache-2.0`; they now inherit the workspace `license = "MIT"` via `license.workspace = true`. Workspace versions remain mixed (`vault-mcp` 1.8.0, `phantom-cli` 1.8.2, others 0.1.0). Unify before any crates.io/Homebrew publish.
7. **GUI crates need system libs.** `cargo build --release` for the whole workspace fails on `tauri-app`/`native` because GTK/`glib-2.0`/`gobject-2.0` dev libraries aren't installed in this headless environment (pre-existing, unrelated to the merge). All **non-GUI** crates build release-green. Build/test the security set with explicit `-p` flags (see below).
8. **Run the gate in `--release`.** The ported `sanitization::test_large_output_performance` asserts a wall-clock bound (<5s for ~1MB) that a **debug** build misses (~8s, unoptimized aho-corasick); it passes in release (~0.6s). This is a pre-existing perf-test design issue, not a correctness regression. The security assertions themselves pass in both profiles.
9. `phantom-sandbox` seccomp/capability-drop and `network.rs` userspace filter remain placeholders — they are not needed for the egress guarantee (the network namespace provides it structurally) and are left as future hardening.

## How to reproduce the gate

```bash
cd ~/nous/phantom-vault-prod
# Build the security-critical (non-GUI) set:
cargo build --release -p phantom-core -p phantom-sanitizer -p phantom-analyzer \
  -p phantom-sandbox -p phantom-mcp -p phantom-security-tests -p vault-core \
  -p vault-mcp -p phantom-cli
# Run the full security gate (release):
cargo test --release -p phantom-core -p phantom-sanitizer -p phantom-analyzer \
  -p phantom-sandbox -p phantom-mcp -p phantom-security-tests
```
