# Phantom Vault - 5-Minute Quickstart

Get your API keys secured and connected to Claude in under 5 minutes.

---

## Step 1: Install (1 min)

### Option A: Download Binary (Recommended)
```bash
# macOS
curl -L https://github.com/yourrepo/phantom-vault/releases/latest/download/phantom-macos -o phantom
chmod +x phantom
sudo mv phantom /usr/local/bin/
```

### Option B: Build from Source
```bash
git clone https://github.com/yourrepo/phantom-vault.git
cd phantom-vault/secure_vault
cargo build --release
sudo cp target/release/phantom /usr/local/bin/
```

---

## Step 2: Create Your Vault (30 sec)

```bash
phantom init
```

Enter a master password when prompted. This encrypts all your secrets.

---

## Step 3: Add Your API Keys (1 min)

```bash
# Add your OpenAI key
phantom add openai-key

# Add your Anthropic key
phantom add anthropic-key

# Add any other keys
phantom add github-token
phantom add stripe-key
```

Each command prompts for the secret value securely (hidden input).

**Verify your keys:**
```bash
phantom list
```

---

## Step 4: Connect to Claude Code (2 min)

### Auto-Install (Easiest)
```bash
phantom mcp-install
```

This automatically configures Claude Code to use your vault.

### Manual Install
Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "phantom-vault": {
      "command": "/usr/local/bin/vault-mcp",
      "args": []
    }
  }
}
```

**Restart Claude Code** after configuration.

---

## Step 5: Use It! (Done!)

Talk to Claude naturally:

> "Use my openai-key to check my API usage"

> "Deploy to Railway using my railway-token"

> "Clone the private repo using github-token"

Claude sees only the reference name (e.g., `openai-key`), never the actual secret.

---

## Quick Reference

| Command | What it does |
|---------|--------------|
| `phantom init` | Create new vault |
| `phantom add NAME` | Add a secret |
| `phantom list` | List all secrets |
| `phantom get NAME` | View secret details |
| `phantom rotate NAME` | Update a secret value |
| `phantom delete NAME` | Remove a secret |
| `phantom mcp-install` | Connect to Claude Code |

---

## Security Guarantee

- Your actual API keys **never** appear in Claude's context
- Keys are encrypted with AES-256-GCM + Argon2id
- All output is scanned for leaked credentials before returning to Claude
- Full audit log of all access

---

## Troubleshooting

**"Vault is locked"** - Run `phantom unlock` or it auto-unlocks when needed

**"Command not found"** - Add to PATH: `export PATH=$PATH:/usr/local/bin`

**"Claude doesn't see vault"** - Restart Claude Code after `phantom mcp-install`

---

## Next Steps

- Read [USER_MANUAL.md](USER_MANUAL.md) for advanced features
- Set expiration dates on secrets: `phantom add key --expires 2026-12-31`
- Add tags for organization: `phantom add key --tags production,api`

---

**Total setup time: ~3-5 minutes**
