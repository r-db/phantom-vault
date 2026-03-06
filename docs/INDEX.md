# Phantom Vault Documentation Index

**Version:** 1.4.0
**Last Updated:** 2026-03-05

---

## Quick Links

| Document | Purpose | Audience |
|----------|---------|----------|
| [QUICKSTART.md](../QUICKSTART.md) | **5-minute setup guide** | New users |
| [README.md](../README.md) | Project overview, architecture | All users |
| [USER_MANUAL.md](../USER_MANUAL.md) | Complete usage guide | End users |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System design, threat model | Developers |
| [SECURITY_RESEARCH.md](./SECURITY_RESEARCH.md) | Security analysis, blind spots | Security researchers |
| [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) | Current bugs, workarounds | Developers, users |

---

## For End Users

### Getting Started (5 minutes)

See **[QUICKSTART.md](../QUICKSTART.md)** for the fastest path:

1. **Install:** Download binary or build from source
2. **Create vault:** `phantom init`
3. **Add secrets:** `phantom add MY_KEY`
4. **Connect to Claude:** `phantom mcp-install`

### Complete Guide

The [USER_MANUAL.md](../USER_MANUAL.md) covers:
- Installation (all platforms)
- Adding and managing secrets
- Connecting to Claude Code
- Namespaces for project isolation
- Running commands with secrets
- Audit logging
- Canary secrets (honeypot detection)
- Troubleshooting

---

## For Developers

### Architecture

[ARCHITECTURE.md](./ARCHITECTURE.md) covers:
- System design philosophy
- 5-layer security model
- Blind spots in existing solutions
- Tech stack decisions (why Rust)
- MCP server design
- Command pre-analysis engine

### Crate Structure

```
crates/
  vault-core/     # Encryption, storage, models
    crypto.rs     # AES-256-GCM + Argon2id
    storage.rs    # Encrypted file I/O
    models.rs     # SecretEntry, VaultData
    filter.rs     # Credential detection (50+ patterns)
    audit.rs      # HMAC-chained audit log

  vault-mcp/      # MCP server for Claude Code
    main.rs       # Entry point
    server.rs     # MCP protocol handler
    handlers.rs   # Tool implementations
    state.rs      # Vault state management
    registry.rs   # Tool definitions

  phantom-cli/    # CLI binary
    main.rs       # All CLI commands

native/           # Mobile FFI (scaffold)
  api.rs          # flutter_rust_bridge bindings
```

### Building

```bash
# Build all crates
cargo build --workspace

# Build release binaries
cargo build --release --workspace

# Run tests
cargo test --workspace

# Check for issues
cargo clippy --workspace -- -D warnings
```

### Key Files

| File | What It Does |
|------|-------------|
| `vault-core/src/storage.rs` | Vault file I/O, salt handling |
| `vault-core/src/crypto.rs` | Encryption/decryption, key derivation |
| `vault-mcp/src/handlers.rs` | MCP tool implementations |
| `phantom-cli/src/main.rs` | All CLI command handlers |

---

## For Security Researchers

### Security Model

[SECURITY_RESEARCH.md](./SECURITY_RESEARCH.md) details:
- 14 blind spots in existing solutions
- Attack vectors considered
- Defense-in-depth approach
- Command pre-analysis (oracle prevention)
- Multi-encoding sanitization

### Known Security Issues

See [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) for:
- All CRITICAL and HIGH issues resolved
- Only minor theoretical issues remain (nonce tracking, file locking)
- Fixed issues and their resolutions

### Security Contact

For security vulnerabilities:
- Do NOT create public issues
- Email: security@phantomvault.io
- Include: detailed reproduction steps, impact assessment

---

## Current Status

### What Works (v1.4.0)

- Vault creation and management
- Secret add/list/show/get/remove
- MCP server integration with Claude Code
- Namespace isolation
- Credential filtering (50+ patterns)
- Audit logging with client ID
- Canary secrets with collision detection
- Security policy enforcement
- Input validation (env vars, time restrictions)
- SSH operations with secure host key verification

### Known Limitations

- Schema migrations (use serde defaults as mitigation)
- Concurrent access (no file locking - single process recommended)

### Roadmap

| Version | Focus |
|---------|-------|
| 1.5.0 | Schema migration framework |
| 1.6.0 | File locking for concurrent access |
| 2.0.0 | Mobile apps (iOS/Android) |

---

## Context Restoration

If you're an AI agent or developer picking this up with no prior context:

1. **Read this file** - you're here
2. **Read [KNOWN_ISSUES.md](./KNOWN_ISSUES.md)** - understand current bugs
3. **Read [ARCHITECTURE.md](./ARCHITECTURE.md)** - understand the design
4. **Check the plan file** - `~/.claude/plans/harmonic-wiggling-sifakis.md` has task status

### Key Design Decisions

1. **Secrets never visible to LLM** - Core security guarantee
2. **Hardware security preferred** - Secure Enclave > TPM > password
3. **Defense in depth** - 5 layers of protection
4. **Fail secure** - On error, block output rather than pass through
5. **Audit everything** - HMAC-chained tamper-evident logs

### Quick Debug

```bash
# Check if vault exists
phantom --version && ls -la ~/.vault-secrets/

# Test basic operations
phantom list
phantom health

# Check MCP server
phantom mcp status

# View recent audit
phantom audit tail
```

---

## Contributing

1. Check [KNOWN_ISSUES.md](./KNOWN_ISSUES.md) for existing bugs
2. Run full test suite before changes
3. Add tests for any new functionality
4. Follow existing code patterns
5. Update documentation with changes
