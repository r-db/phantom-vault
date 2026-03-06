# Known Issues - Phantom Vault

**Version:** 1.4.0
**Last Updated:** 2026-03-05
**Status:** PRODUCTION READY

---

## Quick Summary

| Severity | Total | Fixed | Open |
|----------|-------|-------|------|
| CRITICAL | 1 | 1 | 0 |
| HIGH | 3 | 3 | 0 |
| MEDIUM | 5 | 4 | 1 |
| LOW | 5 | 4 | 1 |

**Production Ready:** YES (schema migration and concurrent access remain as documented limitations)

---

## Critical Issues

### SSH Host Key Verification Disabled - FIXED in v1.3.0

**File:** `crates/vault-mcp/src/handlers.rs:559`
**Status:** FIXED
**Fixed in:** v1.3.0

**Description:**
The SSH git operation handler previously used `StrictHostKeyChecking=no`, which disabled SSH host key verification.

**Fix:**
Added configurable `SshHostKeyMode` enum with three options:
- `AcceptNew` (default) - Accept new keys, reject changed keys
- `Yes` - Strict: only accept keys in known_hosts
- `No` - Insecure: accept all (not recommended)

The default is now `AcceptNew`, which provides reasonable security while allowing new hosts.

---

## High Priority Issues

### No Schema Migration Framework

**File:** `crates/vault-core/src/storage.rs:137-144`
**Status:** OPEN
**Impact:** Data compatibility on upgrades

**Description:**
The vault file has a version number but no migration logic. When new fields are added to the vault schema, older vaults may fail to load.

**Mitigation:**
All new fields currently use `#[serde(default)]` to provide default values, which prevents immediate breakage. However, this is not a sustainable long-term solution.

**Fix Required:**
Implement proper schema migration framework that transforms old data formats to new ones.

---

### Namespace Shadowing - FIXED in v1.3.0

**File:** `crates/vault-core/src/models.rs:247`
**Status:** FIXED
**Fixed in:** v1.3.0

**Description:**
The same secret reference name can exist in multiple namespaces. The `find_by_reference()` function returns the first match.

**Fix:**
Added namespace-aware lookup methods:
- `find_by_reference_in_namespace(reference, namespace)`
- `find_by_reference_in_namespace_mut(reference, namespace)`

Callers should migrate to namespace-aware methods when namespace context is available.

---

### Missing Entry/Value Consistency Check - FIXED in v1.3.0

**File:** `crates/vault-core/src/models.rs`
**Status:** FIXED
**Fixed in:** v1.3.0

**Description:**
`VaultData` could have entries without corresponding encrypted values, leading to confusing errors.

**Fix:**
Added `validate_consistency()` method that checks:
- All entries have corresponding encrypted values
- All encrypted values have corresponding entries (no orphans)

Called on vault load with warning logging for any inconsistencies.

---

## Medium Priority Issues

### TimeRestriction Hour Validation - FIXED in v1.4.0

**File:** `crates/vault-core/src/models.rs:636-680`
**Status:** FIXED
**Fixed in:** v1.4.0

**Description:**
The `TimeRestriction` struct accepted `start_hour` and `end_hour` values greater than 23, which are invalid hours.

**Fix:**
Added `TimeRestriction::new()` constructor with validation and `validate()` method to check hour values are in 0-23 range.

---

### Invalid Environment Variable Names Allowed - FIXED in v1.4.0

**File:** `crates/phantom-cli/src/main.rs` (handle_run)
**Status:** FIXED
**Fixed in:** v1.4.0

**Description:**
The `-s key=value` flag in `phantom run` allowed invalid environment variable names (e.g., names with special characters like `!!!invalid!!!`). These failed at subprocess spawn time with unhelpful error messages.

**Fix:**
Added `is_valid_env_var_name()` validation function that checks environment variable names against POSIX standard (alphanumeric + underscore, not starting with digit). Invalid names now produce a clear error message before command execution.

---

### Nonce Uniqueness Not Validated

**File:** `crates/vault-core/src/crypto.rs:82-95`
**Status:** OPEN
**Impact:** Theoretical cryptographic weakness

**Description:**
Random nonces are generated without collision detection. While statistically unlikely (96-bit random values), reusing a nonce with the same key violates AES-GCM security guarantees.

**Note:** The probability of collision is approximately 2^-48 after 2^48 encryptions. This is not a practical concern for normal use but violates the formal security proof.

**Fix Required:**
Track used nonces or use a counter-based approach.

---

### Temporary SSH Key Disclosure Window - FIXED in v1.3.0

**File:** `crates/vault-mcp/src/handlers.rs:550`
**Status:** FIXED
**Fixed in:** v1.3.0

**Description:**
SSH keys were written to `/tmp` with default permissions before `chmod 600` was applied.

**Fix:**
Now uses `tempfile` crate which creates files with secure 0o600 permissions from the start, eliminating the disclosure window.

---

### Unwrap Panics in Production - FIXED in v1.3.0

**File:** `crates/vault-mcp/src/handlers.rs:632`
**Status:** FIXED
**Fixed in:** v1.3.0

**Description:**
Some `.unwrap()` calls could panic and crash the MCP server.

**Fix:**
Replaced double-unwrap pattern with storing the usage_count before the mutable borrow is released, eliminating potential panics.

---

## Low Priority Issues

### Redaction Count Logic Error - FIXED in v1.4.0

**File:** `crates/vault-core/src/filter.rs:386-420`
**Status:** FIXED
**Fixed in:** v1.4.0

**Description:**
The redaction count returned did not accurately reflect the number of redactions performed due to a logic error in counting multiple matches.

**Fix:**
Now counts actual occurrences using `matches().count()` for known secrets and `find_iter().count()` for regex patterns before performing replacements.

---

### Client ID Lost on Audit Read - FIXED in v1.4.0

**File:** `crates/vault-core/src/audit.rs:199-340`
**Status:** FIXED
**Fixed in:** v1.4.0

**Description:**
When reading audit entries, the client ID field was not properly deserialized because only the event (not client_id) was being encrypted.

**Fix:**
Added `AuditPayload` struct that bundles both event and client_id. Now both are encrypted together and properly deserialized on read. Backwards compatible with old entries (falls back to None for client_id).

---

### Canary Value Collision Possible - FIXED in v1.4.0

**File:** `crates/vault-core/src/models.rs:398-430`
**Status:** FIXED
**Fixed in:** v1.4.0

**Description:**
Canary secret values were generated randomly but without checking for collision with other canary values.

**Fix:**
Added `CanarySecret::new_checked()` method that checks for collision with existing canary values before accepting the new canary. Collision with encrypted real secret values cannot be checked, but the probability is astronomically low (16-36 random characters).

---

### Import Command Leaks Names to stdout - FIXED in v1.4.0

**File:** `crates/phantom-cli/src/main.rs` (import handler)
**Status:** FIXED
**Fixed in:** v1.4.0

**Description:**
The import command printed secret names to stdout during import. While values were not leaked, names may be considered sensitive in some contexts.

**Fix:**
Changed "Skipping" message from `println!` to `eprintln!` so it goes to stderr instead of stdout. This prevents secret names from appearing in stdout which could be piped or logged.

---

### No Lock File for Concurrent Access

**Files:** `crates/vault-core/src/storage.rs`
**Status:** OPEN
**Impact:** Data corruption if multiple processes write simultaneously

**Description:**
No file locking mechanism prevents concurrent writes to the vault file. Running multiple CLI instances or MCP servers simultaneously could corrupt the vault.

---

## Fixed Issues (v1.2.0)

### UTF-8 Panic in Mask Functions - FIXED

**File:** `crates/phantom-cli/src/main.rs`
**Fixed in:** v1.2.0

**Description:**
The `mask_value()` function used byte slicing which could panic on multi-byte UTF-8 characters (e.g., emojis).

**Fix:**
Changed to character-based slicing using `chars().collect()`.

---

### Race Condition in Vault Operations - FIXED

**Files:** `crates/vault-core/src/storage.rs`, all callers
**Fixed in:** v1.2.0

**Description:**
The salt was re-read from the vault file before each save operation. If the file was modified between read and write, the wrong salt could be used.

**Fix:**
`load_vault()` now returns `(VaultData, DerivedKeys, salt)` - salt is stored from initial load and passed through all operations.

---

### VAULT_PASSWORD Environment Variable Exposure - FIXED

**File:** `crates/vault-mcp/src/main.rs`
**Fixed in:** v1.2.0

**Description:**
The VAULT_PASSWORD environment variable auto-unlock feature was available in production builds.

**Fix:**
Wrapped in `#[cfg(debug_assertions)]` - only works in debug builds with warning log.

---

### Security Policy Enforcement - ADDED

**File:** `crates/vault-mcp/src/handlers.rs`
**Added in:** v1.2.0

**Description:**
Added security policy enforcement checking `allowed_tools` and `blocked_tools` before executing MCP tools.

---

## Testing Verification

After any fixes, verify with:

```bash
cd /Users/riscentrdb/Desktop/solutions/phantom_vault/secure_vault

# Run tests
cargo test --workspace

# Check for warnings/errors
cargo clippy --workspace -- -D warnings

# Manual verification
phantom add EMOJI_TEST    # Enter emoji value - should NOT panic
phantom list              # Should show entry
phantom --version         # Should show 1.4.0
phantom run -s "INVALID!!!NAME=test" -- echo $test  # Should error with validation message
```

---

## Reporting New Issues

If you discover a new issue:

1. Check this document first - it may already be known
2. For security issues, do NOT create public issues
3. Contact: security@phantomvault.io (or create private report)
4. Include: file location, reproduction steps, expected vs actual behavior

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.4.0 | 2026-03-05 | TimeRestriction validation, env var name validation, redaction count fix, client ID audit fix, canary collision check, import output fix |
| 1.3.0 | 2026-02-28 | SSH host key verification (CRITICAL), namespace shadowing fix, consistency check, unwrap panic fix, temp file security |
| 1.2.0 | 2026-02-28 | UTF-8 fix, race condition fix, policy enforcement, debug-only VAULT_PASSWORD |
| 1.1.5 | 2026-02-28 | Secret confirmation display, removed value-as-argument |
| 1.1.0 | 2026-02-28 | Namespace, audit, canary, policy features |
| 1.0.0 | 2026-02-27 | Initial release |
