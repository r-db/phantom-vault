# Phantom Vault Security Audit Checklist

## Pre-Release Checklist

### Cryptography

- [ ] AES-256-GCM implementation uses authenticated encryption
- [ ] XChaCha20-Poly1305 nonces are never reused
- [ ] Argon2id parameters meet OWASP recommendations
- [ ] Random number generation uses CSPRNG
- [ ] No cryptographic keys in source code
- [ ] Key derivation uses proper salt

### Memory Protection

- [ ] SecretBuffer zeroizes on drop (verified with tests)
- [ ] Memory is locked with mlock() before storing secrets
- [ ] No secret data in Debug implementations
- [ ] Constant-time comparison for secret equality
- [ ] Core dumps disabled for sensitive processes

### Output Sanitization

- [ ] Exact match detection works
- [ ] Base64 encoding variants detected
- [ ] URL encoding detected
- [ ] Hex encoding detected
- [ ] HTML entity encoding detected
- [ ] Partial matches caught (sliding window)
- [ ] False positive rate is acceptable

### Command Analysis

- [ ] Timing oracle patterns blocked
- [ ] Exit code oracle patterns blocked
- [ ] Network exfiltration patterns blocked
- [ ] Character iteration patterns blocked
- [ ] Process substitution patterns blocked
- [ ] Legitimate commands allowed

### Sandboxing

- [ ] macOS sandbox-exec profiles tested
- [ ] Linux namespace isolation tested
- [ ] Seccomp filters block dangerous syscalls
- [ ] Network egress filtering works
- [ ] File system access properly restricted

### MCP Server

- [ ] Input validation on all parameters
- [ ] Lineage tracking records all access
- [ ] Error messages don't leak secrets
- [ ] Rate limiting implemented
- [ ] Timeout handling works

### Audit Logging

- [ ] HMAC chain prevents tampering
- [ ] All secret access logged
- [ ] Canary triggers recorded
- [ ] Log rotation doesn't break chain
- [ ] Timestamps are accurate

### Hardware Security

- [ ] Secure Enclave integration tested (macOS)
- [ ] TPM 2.0 integration tested (Linux)
- [ ] FIDO2 integration tested
- [ ] Fallback to software works
- [ ] Key material never leaves HSM

### Dependencies

- [ ] All dependencies audited with cargo-audit
- [ ] No known vulnerabilities
- [ ] Minimal dependency tree
- [ ] Pinned versions in Cargo.lock

### Build & Release

- [ ] Release builds use LTO
- [ ] Debug symbols stripped
- [ ] No debug logging in release
- [ ] Reproducible builds verified

## Periodic Audit Tasks

### Weekly

- [ ] Run cargo-audit
- [ ] Review blocked pattern effectiveness
- [ ] Check canary access logs

### Monthly

- [ ] Full dependency audit
- [ ] Review audit log anomalies
- [ ] Update threat model if needed
- [ ] Test backup/restore procedures

### Quarterly

- [ ] External security review
- [ ] Penetration testing
- [ ] Update documentation
- [ ] Review user feedback for security issues

## Incident Response

### If Canary Triggered

1. Identify the lineage chain
2. Review all commands in that chain
3. Assess what secrets may be compromised
4. Rotate affected secrets
5. Update blocked patterns if needed

### If Sanitization Bypass Found

1. Immediately patch the bypass
2. Review audit logs for exploitation
3. Add regression test
4. Notify users if secrets exposed

### If Oracle Attack Detected

1. Block the pattern
2. Review audit logs for exploitation
3. Add to test suite
4. Update threat model

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | | | |
| Security Reviewer | | | |
| Release Manager | | | |
