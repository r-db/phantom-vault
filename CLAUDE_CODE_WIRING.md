# Wiring Phantom Vault into Claude Code

After `curl … | bash`, two things remain to make your agent actually use the vault.

## 1 — Tell Claude Code where the MCP server lives

Phantom's `phantom mcp install` currently writes to `~/.claude/claude_desktop_config.json` — that's the **Claude Desktop app's** config file, not the **Claude Code CLI's**. If you use Claude Code in the terminal, you need to register the server manually:

```bash
claude mcp add phantom-vault $(which vault-mcp)
```

Verify it connects:

```bash
claude mcp list | grep phantom
# phantom-vault: /opt/homebrew/bin/vault-mcp - ✓ Connected
```

Restart any open Claude Code session (`/exit` then relaunch) so the new MCP server is loaded.

> **Known bug (filed):** `phantom mcp install` targets the desktop-app config. CLI users must use `claude mcp add` until this is patched.

## 2 — Tell your agent the vault exists

MCP registration makes the tools *available*. It does not make the agent *reach for them*. To make Claude Code actually call `vault.get` instead of asking you for a credential, add one of:

### Option A — Project `CLAUDE.md`

Add this to the `CLAUDE.md` in any repo where the agent will need credentials:

```markdown
## Credentials

Never ask the user for API keys, tokens, passwords, or other secrets. They live
in Phantom Vault. Call the MCP tool `vault.get` with the secret's name. If you
don't know the name, call `vault.list` first. If the secret isn't there, ask
the user to run `phantom add <name>` and try again.
```

### Option B — User-level instructions

Put the same paragraph in `~/.claude/CLAUDE.md` so every project inherits it.

### Option C — Per-task prompt

For one-off tasks: prefix the request with *"Use vault.get for any credentials you need."*

## 3 — Add your first real secret

```bash
phantom add OPENAI_API_KEY
# (paste value at prompt — the value never echoes)

phantom list
# Secrets in vault:
#   * OPENAI_API_KEY
```

Now the agent can do this on its own:

```
> deploy the function
[agent internally]: vault.get("OPENAI_API_KEY") → injected as env var
✓ deployed
```

## 4 — Run a command with secrets injected (no agent needed)

```bash
phantom run -- python my_script.py
# secrets are exported as env vars for the duration of the command
# never written to disk, never visible in `env`, never echoed
```

That's the whole loop. Install → register MCP → tell the agent → add secrets → use.
