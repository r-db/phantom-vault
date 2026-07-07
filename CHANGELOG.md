# Changelog

All notable changes to Phantom Vault. This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-07-06

First tagged release of the **secure core**. This is the version the code actually reports (`Cargo.toml` = `0.1.0`). The `1.7.x`–`1.8.x` numbers below came from a pre-secure-core prototype line and did **not** correspond to an audited, secure release.

### Enforced (proven in the code)
- **Encryption at rest** — AES-256-GCM with an Argon2id-derived key.
- **Memory protection** — `zeroize` on drop + `mlock` (no swap to disk).
- **Output sanitizer / redaction** — value and its encoded variants (base64/hex/URL) scrubbed from returned output.
- **Network egress jail** — fail-closed egress jail around each command (no path to send a secret out).
- **Filesystem jail (Landlock)** — commands cannot write a secret to disk.
- **Canary honeypots** — decoy secrets that flag misuse.
- **Audit logging** of every access; **MCP server + CLI** (`vault_run` returns `[REDACTED]`).

### Not yet claimed (roadmap)
- End-to-end **"an AI can never exfiltrate a secret"** — under independent containment audit (Magnus's gate); not asserted until it passes.
- `guardrail`, `policy`, `passwd` CLI commands — not yet on the secure backend.
- Hardware backing (Secure Enclave / TPM / FIDO2) — planned.

---

## Historical — pre-secure-core prototype

> The `1.7.x`–`1.8.x` entries below belonged to an earlier, non-secure prototype line whose version numbers did not reflect a secure, audited release. They are kept for context and are superseded entirely by `0.1.0` above.

## [1.8.2] — 2026-05-15

### Fixed

- **Biometric detection on Apple Silicon (CRITICAL).** `is_biometric_available()` called `bioutil --availability`, which is not a real `bioutil(8)` flag. The command always exited non-zero, so the function returned `false` on EVERY Mac — including ones with working TouchID. Consequence: `phantom biometric status` reported `"No biometric hardware detected"` regardless of hardware, and `phantom biometric enable` couldn't enable. This silently forced ALL users — including automated agents — onto the password-via-/dev/tty path. Agents have no /dev/tty in subshells, so the vault was effectively inaccessible to any non-human caller. *Fix:* use `bioutil -r` (a real, documented `bioutil(8)` flag) and parse stdout for `"Effective biometrics for unlock: 1"` to confirm TouchID is usable. Verified on Apple Silicon Mac Mini: `phantom biometric status` now correctly reports `"Touch ID is available"`. Commit: `274e2e3`. Affected file: `crates/phantom-cli/src/main.rs:550-556`.

- **Release workflow asset-name mismatch (CRITICAL).** The `phantom update` command at `crates/phantom-cli/src/main.rs:1875-1878` downloads from `phantom-<arch>-<os_target>` where `arch ∈ {aarch64, x86_64}` and `os_target ∈ {apple-darwin, unknown-linux-gnu}` (Rust target triple form). But the GitHub Actions release workflow uploaded assets named `phantom-macos-arm64` / `phantom-macos-x64` / `phantom-linux-x64`. The names didn't match. Result: `phantom update` from any prior version would hit GitHub API, see the new version, attempt the download, get 404, and fail. This was masked because no actual update had been attempted between v1.7.1 and v1.8.0 by anyone who hit the path. *Fix:* the release workflow now uploads BOTH name patterns. The friendly `macos-arm64` names are kept for documentation; the Rust-target-triple names are added so existing v1.8.x binaries' update commands find them. Commit: `0070bba`. Affected file: `.github/workflows/release.yml`.

### Impact

Pre-1.8.2, automated agents could NOT use Phantom Vault at all (biometric was unreachable + TTY unavailable in subshells). Post-1.8.2, agents on Apple Silicon Macs with TouchID can `phantom run -s SECRET -- cmd` without any terminal interaction. This was a design goal of Phantom Vault from the start; the bugs above had silently broken it.

### Migration

```bash
# From any 1.7.x or 1.8.x:
phantom update              # jumps to 1.8.2
phantom biometric enable    # one-time keychain enrollment (TTY required for this step only)
# From now on, agents can:
phantom run -s GEMINI_API_KEY -- python3 your_agent_script.py
```

---

## [1.8.1] — 2026-05-15 (SUPERSEDED — DO NOT USE)

Tag was created and a release workflow ran, but the asset-name bug was still present, making the release un-downloadable via `phantom update`. The tag was deleted and v1.8.2 was published in its place. The associated GitHub release may still appear in the releases list as orphaned (tag removed) until manually deleted.

---

## [1.8.0] — Prior to 2026-05-15

(Pre-existing release. Detailed changelog entries to be backfilled from git history. Highlights: MCP integration shipped, biometric scaffolding present but non-functional per the 1.8.2 bug fixes above, edit command opens vault in `$EDITOR`.)

---

## [1.7.1] — Prior

(Pre-existing release. Details TBD.)

---

## Categories

This changelog uses the following section names per Keep a Changelog:

- **Added** — new features
- **Changed** — changes to existing functionality
- **Deprecated** — soon-to-be-removed features
- **Removed** — removed features
- **Fixed** — bug fixes
- **Security** — vulnerability fixes
- **Impact** *(custom)* — user-facing consequences when significant
- **Migration** *(custom)* — step-by-step upgrade instructions when non-trivial
