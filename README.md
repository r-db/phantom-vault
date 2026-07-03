# Phantom Vault

**A next-generation secret manager designed for the age of AI assistants.**

Phantom Vault addresses a critical gap in secret management: protecting sensitive credentials when AI coding assistants have access to your development environment. Traditional secret managers assume the threat model of "untrusted external access" — but what happens when you've granted a powerful LLM the ability to read files, execute commands, and inspect process output? Phantom Vault implements defense-in-depth strategies specifically designed for this scenario, including output sanitization that catches encoded variants, command pre-analysis to block oracle attacks, and canary secrets that detect exfiltration attempts.

The architecture is built around the principle of "secrets never in cleartext outside controlled contexts." Secrets are stored with AES-256-GCM encryption, protected in memory with mlock and automatic zeroization, and only exposed within sandboxed subprocess environments with filtered network egress. When an LLM requests to run a command that uses secrets, Phantom Vault injects credentials directly into the subprocess environment, sanitizes all output before returning it, and maintains an HMAC-chained audit log of every access. Hardware security module integration (Secure Enclave, TPM 2.0, FIDO2) provides an additional layer where available.

Phantom Vault integrates with Claude Code and other MCP-compatible AI assistants through a dedicated MCP server. Rather than exposing raw secret values, it provides tools like `vault_run` that execute commands with secrets injected, returning sanitized output. This allows AI assistants to work productively with credential-requiring workflows while maintaining strong security boundaries. The system supports multi-tenant namespace isolation, secret dependency graphs, automatic rotation, and comprehensive audit logging — everything needed for both individual developers and team environments.

## Quick Start

```bash
# Install
cargo install phantom-vault

# Initialize a vault
phantom-vault init

# Add a secret
phantom-vault set API_KEY

# Run a command with secrets injected
phantom-vault run -- curl -H "Authorization: Bearer $API_KEY" https://api.example.com

# Start MCP server for AI assistant integration
phantom-vault mcp serve
```

## License

Apache 2.0 — See [LICENSE](LICENSE) for details.
