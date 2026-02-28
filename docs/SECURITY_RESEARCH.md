# Secure API Key Vault for LLM Terminal Workflows

**Date:** February 26, 2026
**Purpose:** Architecture, logic, tech stack, and Claude Code implementation prompts for a zero-trust secret management system where LLMs can USE API keys but never SEE them.

---

## The Core Problem

When an LLM agent (Claude Code, Cursor, Copilot) runs in your terminal, it can:

1. Read `.env` files directly (Claude Code auto-loads them without asking)
2. See environment variables via `printenv` or `echo $SECRET`
3. Capture command output that contains secrets (API responses, debug logs)
4. Send all of this to the cloud API as conversation context
5. Be socially engineered via prompt injection to dump credentials

Research from Knostic (Feb 2026) confirmed Claude Code reads `.env` files without explicit permission. Check Point Research disclosed CVE-2025-59536 showing API token exfiltration through project files. And 48% of MCP servers store credentials in plaintext config files.

**The rule is simple: API keys must never enter the LLM context window. Period.**

---

## Architecture: The Three-Layer Defense

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: ENCRYPTED VAULT (At Rest)                        │
│                                                             │
│  secretctl / 1Password / SOPS+age / macOS Keychain         │
│  AES-256-GCM encryption, Argon2id key derivation           │
│  File permissions 0600, zero network access                 │
│  Master password never stored or transmitted                │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ Secrets injected as env vars
                       │ into subprocess only
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  LAYER 2: RUNTIME INJECTION (In Transit)                   │
│                                                             │
│  secretctl run / op run / doppler run                       │
│  Secrets exist ONLY in subprocess environment               │
│  Never written to disk, never in parent process             │
│  Process dies → secrets gone from memory                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ Output passes through
                       │ sanitization filter
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  LAYER 3: OUTPUT SANITIZATION (At Return)                  │
│                                                             │
│  Exact-match redaction: "sk_live_abc123" → [REDACTED]      │
│  Pattern-match redaction: sk_live_* → [REDACTED]           │
│  LLM sees only sanitized output                            │
│  MCP server returns masked values: ****WXYZ                │
└─────────────────────────────────────────────────────────────┘
```

**What the LLM sees:**
- Secret names/references (e.g., "STRIPE_SECRET_KEY") — yes
- Masked values (e.g., "****WXYZ") — yes
- Actual secret values — NEVER

**What the LLM can do:**
- Request a command to be run WITH secrets injected — yes
- Read the sanitized output of that command — yes
- Access the raw secret value — NEVER

---

## Tech Stack Options (Ranked by Security + Simplicity)

### Option A: secretctl (RECOMMENDED — Purpose-Built for This)

**What it is:** Single-binary, local-first secrets manager with built-in MCP server. Apache 2.0 open source. Designed specifically for AI agent safety.

**Why it wins:**
- Built for exactly this use case (LLM + secrets)
- Single binary, no infrastructure, no subscription
- MCP server built in (direct Claude Code integration)
- Output sanitization built in (automatic redaction)
- AES-256-GCM + Argon2id (strongest available)
- Zero network access (secrets never leave your machine)
- HMAC-chained audit logs (tamper detection)
- Cross-platform: macOS (Apple Silicon + Intel), Linux, Windows

**Storage:** SQLite database, encrypted at rest, 0600 file permissions
**Encryption:** AES-256-GCM authenticated encryption
**Key derivation:** Argon2id (memory-hard, brute-force resistant)

### Option B: 1Password CLI (`op run`)

**What it is:** Commercial password manager with developer CLI. `op run` creates a pseudoterminal that auto-redacts secrets from stdout.

**Why consider it:**
- You may already have 1Password
- `op run` auto-creates PTY for redaction
- Service accounts for least-privilege access
- Secret references (op://vault/item/field) in config files
- `op inject` for config file templating

**Downside:** Requires subscription, cloud-dependent, no built-in MCP server

### Option C: SOPS + age (Encryption at Rest Only)

**What it is:** Mozilla SOPS encrypts YAML/JSON/ENV files using age (modern encryption). Secrets stay in git as encrypted blobs. Decrypted at runtime only.

**Why consider it:**
- Git-friendly (encrypted secrets committed to repo)
- No cloud dependency (age keys are local)
- AES256-GCM via age backend
- Well-established (Mozilla, CNCF ecosystem)

**Downside:** No output sanitization, no MCP server, no auto-redaction. You get encryption at rest only. Must combine with another tool for Layer 2 and 3.

### Option D: Doppler

**What it is:** Cloud-based secrets management platform with CLI. `doppler run` injects secrets as env vars into subprocesses.

**Why consider it:**
- Team-friendly (centralized, multi-environment)
- `doppler run -- npm start` pattern (clean injection)
- Automatic secret rotation
- Audit logs

**Downside:** Cloud-dependent, subscription required, no output sanitization to LLM

### Option E: HashiCorp Vault + MCP Server

**What it is:** Enterprise-grade secrets management. Multiple MCP server implementations exist for LLM integration.

**Why consider it:**
- Most mature, most features, most integrations
- Dynamic secrets (generate on demand, auto-expire)
- Policy-based access control

**Downside:** Heavy infrastructure (runs as a server), overkill for small teams, complex setup

---

## Recommended Implementation: secretctl + Claude Code

This is the most secure option available today for a solo developer or small team using Claude Code in the terminal.

### How It Works End to End

```
Developer types in Claude Code:
  "Deploy the CRM backend to Railway"

Claude Code (LLM) decides it needs to run:
  railway deploy

Claude Code calls the MCP tool:
  secret_run(keys: ["railway/*"], command: "railway deploy")

secretctl MCP server:
  1. Reads encrypted vault (requires master password, already unlocked)
  2. Decrypts RAILWAY_TOKEN
  3. Spawns subprocess: RAILWAY_TOKEN=xxxxxxx railway deploy
  4. Captures stdout/stderr
  5. Scans output for "xxxxxxx" → replaces with [REDACTED:RAILWAY_TOKEN]
  6. Returns sanitized output to Claude Code

Claude Code sees:
  "Deploying to Railway...
   Token: [REDACTED:RAILWAY_TOKEN]
   Deployment successful: crm-block-theory-backend"

Claude Code NEVER sees the actual token value.
```

### Setup Flow

```
1. Install secretctl
   brew install secretctl  (or download binary from GitHub releases)

2. Initialize vault
   secretctl init
   → Enter master password (min 8 chars, recommend 20+)

3. Store your secrets
   echo "sk_live_xxxxx" | secretctl set STRIPE_SECRET_KEY
   echo "pk_live_xxxxx" | secretctl set CLERK_SECRET_KEY
   echo "xxxxxxx" | secretctl set RAILWAY_TOKEN
   echo "postgresql://..." | secretctl set DATABASE_URL
   echo "xxxxx" | secretctl set ELEVENLABS_API_KEY

4. Configure Claude Code MCP integration
   Add to ~/.claude.json or .mcp.json:
   {
     "mcpServers": {
       "secretctl": {
         "command": "/usr/local/bin/secretctl",
         "args": ["mcp-server"],
         "env": { "SECRETCTL_PASSWORD": "<your-master-password>" }
       }
     }
   }

5. Configure MCP policy (mcp-policy.yaml)
   Restrict which commands secretctl can run:
   allowed_commands:
     - railway *
     - vercel *
     - stripe *
     - psql *
     - npm run *
     - git push *
     - curl *

6. Test it
   In Claude Code, ask: "List my stored secrets"
   → Claude calls secret_list → sees key names only, no values

   Ask: "Run the health check against production"
   → Claude calls secret_run with DATABASE_URL
   → Sees sanitized output only
```

### What Claude Code Can Access via MCP

| MCP Tool | What It Returns | Secret Exposed? |
|----------|----------------|-----------------|
| secret_list | Key names + metadata | NO |
| secret_exists | Boolean + metadata | NO |
| secret_get_masked | Masked value (****WXYZ) | NO (last 4 chars only) |
| secret_run | Sanitized command output | NO |
| secret_list_fields | Field names for multi-field secrets | NO |

There is NO MCP tool that returns plaintext secrets. By design.

---

## Security Hardening Checklist

### Must Do (Non-Negotiable)

1. **Never store secrets in .env files** — use the vault exclusively
2. **Add .env* to .gitignore AND .claudeignore** — prevent Claude from reading them
3. **Block dangerous commands in Claude Code settings:**
   ```json
   // ~/.claude/settings.json
   {
     "permissions": {
       "deny": [
         "Bash(printenv*)",
         "Bash(env)",
         "Bash(echo $*)",
         "Bash(cat .env*)",
         "Bash(cat */.env*)",
         "Read(.env*)",
         "Read(*/.env*)"
       ]
     }
   }
   ```
4. **Set file permissions on vault:** `chmod 600 ~/.secretctl/vault.db`
5. **Use unique master password** — not reused from any other service
6. **Lock vault when not in use** — `secretctl lock`

### Should Do (Strongly Recommended)

7. **Rotate secrets regularly** — secretctl tracks expiration dates
8. **Review audit logs weekly** — `secretctl audit list`
9. **Verify audit chain integrity** — `secretctl audit verify`
10. **Use wildcard patterns for least-privilege:** only inject the secrets each command needs
11. **Keep secretctl updated** — security patches matter
12. **Encrypted backups:** `secretctl backup create --encrypt`

### Advanced (For Teams)

13. **Separate vaults per environment** (dev, staging, production)
14. **MCP policy files** restricting allowed commands per vault
15. **Service accounts** with limited secret access for CI/CD
16. **Integrate with macOS Keychain** for master password storage (avoid typing it)

---

## Known Limitations

1. **Exact-match sanitization only:** If a secret appears Base64-encoded, hex-encoded, or URL-encoded in output, secretctl will NOT catch it. The raw string must match exactly.
2. **Master password in MCP config:** The `SECRETCTL_PASSWORD` env var in `.mcp.json` is itself a secret stored in a config file. Mitigation: use macOS Keychain to retrieve it at launch, or use 1Password `op read` to inject it.
3. **Subprocess environment:** While the subprocess runs, secrets are in its process memory. A memory dump could theoretically extract them. Mitigation: short-lived processes, no long-running daemons.
4. **Claude Code can still run arbitrary commands:** If not policy-restricted, Claude could run `secretctl get KEY` directly if it discovers the binary path. Mitigation: use MCP policy to restrict allowed operations.

---

## Claude Code Implementation Prompts

The following prompts are designed to be copy-pasted into Claude Code to build out this system. Each prompt is self-contained and follows the research-first principle.

---

### PROMPT 1: Initial Vault Setup and Secret Migration

```
I need you to help me set up secretctl as my secure API key vault.

CONTEXT:
- I am on macOS (Apple Silicon)
- I currently have API keys scattered in .env files across my projects
- I need to migrate all secrets into secretctl
- I use: Clerk, Stripe, Neon PostgreSQL, Railway, Vercel, ElevenLabs, GitHub, OpenAI, Anthropic

CONSTRAINTS:
- Do NOT read any .env files. I will provide the key NAMES only.
- Do NOT display, echo, or log any secret values at any point.
- All secret values will be entered by me via stdin piping.

STEPS:
1. Check if secretctl is installed. If not, tell me how to install it.
2. Initialize a new vault with `secretctl init`
3. Give me the exact commands to store each secret, one at a time, using stdin:
   - CLERK_PUBLISHABLE_KEY
   - CLERK_SECRET_KEY
   - STRIPE_SECRET_KEY
   - STRIPE_PUBLISHABLE_KEY
   - STRIPE_WEBHOOK_SECRET
   - DATABASE_URL (Neon production)
   - DATABASE_URL_DEV (Neon dev branch)
   - RAILWAY_TOKEN
   - VERCEL_TOKEN
   - ELEVENLABS_API_KEY
   - GITHUB_TOKEN
   - OPENAI_API_KEY
   - ANTHROPIC_API_KEY
4. After all secrets are stored, run `secretctl list` to verify.
5. Show me how to configure the MCP server in my Claude Code config.
6. Show me how to add deny rules to ~/.claude/settings.json to block .env file reading.
7. Once confirmed working, tell me how to safely delete all .env files.

OUTPUT: Step-by-step commands I can run. No secret values anywhere.
```

---

### PROMPT 2: MCP Policy Configuration

```
I need to configure the MCP policy for my secretctl vault to enforce least-privilege access for Claude Code.

CONTEXT:
- My vault contains keys for: Clerk, Stripe, Neon, Railway, Vercel, ElevenLabs, GitHub, OpenAI, Anthropic
- Claude Code should be able to run deployments, database queries, and API calls
- Claude Code should NEVER be able to extract raw secret values

REQUIREMENTS:
1. Create an mcp-policy.yaml that:
   - Allows: railway deploy, vercel deploy, vercel dev, stripe listen, psql, npm run, npm install, git push, git pull, curl (for API health checks only)
   - Blocks: cat, echo, printenv, env, export, set, secretctl get (raw access)
   - Restricts wildcard patterns: each command group only gets the secrets it needs
     - Railway commands: RAILWAY_TOKEN only
     - Vercel commands: VERCEL_TOKEN only
     - Stripe commands: STRIPE_* only
     - Database commands: DATABASE_URL* only
     - Git commands: GITHUB_TOKEN only

2. Show me how to validate the policy
3. Show me how to test that blocked commands actually fail
4. Document the policy with inline comments explaining each rule

OUTPUT: Complete mcp-policy.yaml with documentation.
```

---

### PROMPT 3: Secure Deployment Workflow

```
I need a secure deployment workflow that uses secretctl for all secret injection.

CONTEXT:
- IB365 platform: Next.js frontends on Vercel, Python backends on Railway, Neon PostgreSQL
- All API keys are stored in secretctl vault (never in .env files)
- Claude Code has MCP access to secretctl

WORKFLOW TO IMPLEMENT:
1. Frontend deployment (Vercel):
   - Build locally with secrets injected via secretctl run
   - Push to feature branch (no secrets in code)
   - Vercel pulls its own env vars from dashboard (production)
   - For local dev: secretctl run injects CLERK and STRIPE test keys

2. Backend deployment (Railway):
   - Test locally with secretctl run injecting DATABASE_URL and CLERK keys
   - Push to feature branch
   - Railway pulls its own env vars (production)

3. Database migration:
   - secretctl run injects DATABASE_URL into psql subprocess
   - Migration runs against Neon branch (dev) or production
   - Output sanitized (connection string never visible)

4. Stripe webhook testing:
   - secretctl run injects STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET
   - stripe listen forwards to localhost
   - All Stripe output sanitized

For each workflow, give me:
- The exact secretctl run command
- What Claude Code sees (sanitized output example)
- What Claude Code NEVER sees
- Rollback procedure if something fails

OUTPUT: Complete workflow documentation with exact commands.
```

---

### PROMPT 4: Audit and Monitoring Setup

```
I need to set up audit logging and monitoring for my secretctl vault.

REQUIREMENTS:
1. Configure automatic audit logging for:
   - Every secret access (which key, when, by which process)
   - Every secret_run execution (command, keys used, exit code)
   - Failed access attempts
   - Policy violations

2. Create a weekly audit review process:
   - Command to view last 7 days of activity
   - Command to verify audit chain integrity (HMAC)
   - What to look for (anomalies, unexpected access patterns)
   - How to export audit logs for archival

3. Set up secret expiration tracking:
   - Tag each secret with an expiration date
   - Command to list secrets expiring in next 30 days
   - Rotation procedure for each vendor (Clerk, Stripe, etc.)

4. Create encrypted backup procedure:
   - Automated weekly backup command
   - Backup stored in separate encrypted location
   - Restore procedure and verification

OUTPUT: Complete audit and monitoring setup with cron jobs where applicable.
```

---

### PROMPT 5: Team Onboarding — Secure Vault for New Developer

```
I need to onboard a new developer to our secure vault workflow.

CONTEXT:
- We use secretctl for all API key management
- New developer needs access to development secrets only (not production)
- They will use Claude Code with MCP integration

CREATE:
1. A step-by-step onboarding checklist:
   - Install secretctl
   - Initialize their personal vault
   - Receive development secrets (securely, not via email/Slack)
   - Configure Claude Code MCP integration
   - Configure deny rules for .env access
   - Verify everything works

2. A secure secret transfer protocol:
   - How to share dev secrets without exposing them in transit
   - Options: encrypted file transfer, 1Password shared vault, manual entry
   - What NEVER to do (email, Slack, committed files, shared .env)

3. A verification test:
   - Commands to run to prove the vault works
   - Commands to run to prove Claude Code cannot see raw secrets
   - Commands to run to prove deny rules block .env access

4. Troubleshooting guide:
   - "secretctl: command not found"
   - "vault locked" errors
   - MCP server not connecting
   - Permission denied on vault file

OUTPUT: Complete onboarding document ready to hand to a new team member.
```

---

## Alternative Approach: macOS Keychain + Custom MCP Server

If you prefer not to use secretctl and want a zero-dependency solution using built-in macOS tools:

**Logic:**
1. Store secrets in macOS Keychain (encrypted by macOS, unlocked at login)
2. Build a minimal MCP server (Node.js or Python) that:
   - Reads from Keychain via `security find-generic-password` CLI
   - Injects into subprocess environment
   - Sanitizes output before returning to Claude
3. Register as MCP server in Claude Code config

**Keychain CLI commands:**
```bash
# Store a secret
security add-generic-password -a "ib365" -s "STRIPE_SECRET_KEY" -w "sk_live_xxx" -T ""

# Retrieve (for injection only, never shown to LLM)
security find-generic-password -a "ib365" -s "STRIPE_SECRET_KEY" -w
```

**Advantage:** Zero additional software, hardware-backed encryption (Secure Enclave on Apple Silicon), biometric unlock (Touch ID).

**Disadvantage:** macOS only, no built-in output sanitization, must build MCP server yourself.

---

## Summary: What Makes This the Most Secure Vault Possible

| Security Layer | Implementation |
|---------------|---------------|
| Encryption at rest | AES-256-GCM (strongest symmetric encryption) |
| Key derivation | Argon2id (memory-hard, GPU/ASIC resistant) |
| Storage isolation | Local SQLite, 0600 permissions, zero network |
| Runtime isolation | Subprocess injection only, secrets die with process |
| Output sanitization | Automatic redaction before LLM sees output |
| Access control | MCP policy restricts commands and key access |
| Audit trail | HMAC-chained logs, tamper-evident |
| LLM isolation | No MCP tool returns plaintext, .env reading blocked |
| Backup security | Encrypted backups with fresh salt |

The LLM can deploy your app, query your database, test your payments, and manage your infrastructure — all without ever seeing a single API key.

---

## Sources

- [secretctl — AI-Ready Secrets Manager](https://github.com/forest6511/secretctl)
- [OpenClaw Credential Leak Problem — API Stronghold](https://www.apistronghold.com/blog/openclaw-credential-leaks-how-to-protect-your-api-keys)
- [Claude Code Automatically Loads .env Secrets — Knostic](https://www.knostic.ai/blog/claude-loads-secrets-without-permission)
- [CVE-2025-59536: RCE and API Token Exfiltration — Check Point Research](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [Managing Secrets in MCP Servers — Infisical](https://infisical.com/blog/managing-secrets-mcp-servers)
- [Best Practices for MCP Secrets Management — WorkOS](https://workos.com/guide/best-practices-for-mcp-secrets-management)
- [Secure Environment Variables for LLMs — William Callahan](https://williamcallahan.com/blog/secure-environment-variables-1password-doppler-llms-mcps-ai-tools)
- [1Password CLI: op run — 1Password Developer](https://developer.1password.com/docs/cli/reference/commands/run/)
- [SOPS — Mozilla/getsops](https://github.com/getsops/sops)
- [Doppler Secrets Manager](https://www.doppler.com/)
- [HashiCorp Vault](https://www.vaultproject.io/)
- [Clerk Development Instances](https://clerk.com/docs/guides/development/managing-environments)
- [Advanced LLM Security: Preventing Secret Leakage — Doppler](https://www.doppler.com/blog/advanced-llm-security)
- [Token Vault for AI Agent Workflows — ScaleKit](https://www.scalekit.com/blog/token-vault-ai-agent-workflows)
- [Securing AI Agents Without Secrets — Aembit](https://aembit.io/blog/securing-ai-agents-without-secrets/)
- [Common Risks of Giving API Keys to AI Agents — Auth0](https://auth0.com/blog/api-key-security-for-ai-agents/)
- [Zero-Trust Architecture for Env Var Security — Claude Code Issue #2695](https://github.com/anthropics/claude-code/issues/2695)
- [Feature: Mark Sensitive Env Vars — Claude Code Issue #25053](https://github.com/anthropics/claude-code/issues/25053)
- [Claude Code Security Best Practices — Backslash](https://www.backslash.security/blog/claude-code-security-best-practices)
- [Secure MCP Server Practical Guide — William Ogou](https://blog.ogwilliam.com/post/secure-model-context-protocol-mcp-guide)
