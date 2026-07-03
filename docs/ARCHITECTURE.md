# Phantom Vault Architecture

## Overview

Phantom Vault is a next-generation secret manager designed specifically for environments where AI assistants have access to development tools. It implements defense-in-depth strategies to prevent secret exfiltration through LLM-accessible channels.

## Core Principles

1. **Secrets Never in Cleartext Outside Controlled Contexts**
   - Secrets are encrypted at rest with AES-256-GCM
   - Memory is locked and zeroized after use
   - Cleartext only exists within sandboxed subprocess environments

2. **Output Sanitization at Every Boundary**
   - All subprocess output is scanned for secret leakage
   - Multiple encoding variants are detected (Base64, URL, hex, HTML)
   - Sliding window matching catches partial leaks

3. **Command Pre-Analysis**
   - Commands are analyzed before execution
   - Oracle attack patterns are blocked
   - Policy engine allows customization

4. **Hardware Security When Available**
   - Secure Enclave on macOS
   - TPM 2.0 on Linux
   - FIDO2/YubiKey support
   - Software fallback with Argon2id

## Crate Structure

```
phantom-vault/
├── phantom-core       # Encryption, storage, memory protection
├── phantom-sanitizer  # Output sanitization engine
├── phantom-analyzer   # Command pre-analysis
├── phantom-sandbox    # Process sandboxing
├── phantom-mcp        # MCP server for AI integration
├── phantom-hardware   # Hardware security abstraction
└── phantom-cli        # CLI binary
```

## Data Flow

```
                    ┌─────────────────┐
                    │   AI Assistant  │
                    │  (Claude Code)  │
                    └────────┬────────┘
                             │ MCP Protocol
                             ▼
                    ┌─────────────────┐
                    │  phantom-mcp    │
                    │  (MCP Server)   │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ phantom-analyzer│ │  phantom-core   │ │phantom-sanitizer│
│ (Pre-analysis)  │ │  (Vault Ops)    │ │ (Sanitization)  │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                   │
         │                   ▼                   │
         │          ┌─────────────────┐          │
         │          │phantom-hardware │          │
         │          │ (HSM/Enclave)   │          │
         │          └─────────────────┘          │
         │                                       │
         └──────────────────┬────────────────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │ phantom-sandbox │
                   │(Isolated Exec)  │
                   └─────────────────┘
```

## Security Model

### Threat Model

1. **Malicious/Compromised LLM**: The LLM may attempt to exfiltrate secrets through:
   - Direct output of secret values
   - Encoded variants (Base64, hex, etc.)
   - Timing oracles (conditional delays)
   - Exit code oracles
   - Network exfiltration

2. **Command Injection**: Commands constructed by the LLM may contain:
   - Hidden exfiltration channels
   - Character-by-character extraction
   - Process substitution tricks

### Mitigations

- **Output Sanitization**: All output is scanned and redacted
- **Command Analysis**: Dangerous patterns are blocked
- **Sandboxing**: Subprocesses run in isolated environments
- **Network Filtering**: Per-process egress control
- **Canary Secrets**: Fake credentials that detect exfiltration
- **Audit Logging**: HMAC-chained tamper-evident logs

## MCP Integration

The MCP server exposes these tools:

| Tool | Description |
|------|-------------|
| `vault_list` | List secret names (not values) |
| `vault_run` | Execute command with secrets injected |
| `vault_exists` | Check if secrets exist |
| `vault_audit` | Query audit log |

## Encryption

- **At Rest**: AES-256-GCM or XChaCha20-Poly1305
- **Key Derivation**: Argon2id (64 MiB memory, 3 iterations)
- **Hardware Binding**: Optional Secure Enclave/TPM integration

## Storage

- SQLite database with encrypted blob storage
- HMAC-chained audit log for tamper detection
- Automatic zeroization of decrypted data
