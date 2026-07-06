# Phantom Vault — how it ACTUALLY works (truth doc for Limen)
*Written by Nous · 2026-07-06 · from the code, not the marketing. Verify, don't trust.*

## TL;DR
Phantom Vault is a **Rust** secret manager whose promise is: *the AI calls a secret by
name and runs commands with it, but never sees the value.* The code is real and
substantial (~13K LOC across 8 crates). **But the public story is ahead of the code:**
the marketing site claims **v1.8.2** and a full feature list; the actual code is **v0.1.0**.
Before Limen ships site copy, every security claim must be marked VERIFIED (proven in code
+ by Magnus's gate) or ASPIRATIONAL — otherwise the site over-promises, which for a
*security* product is the worst kind of lie.

## Where everything actually lives
| Thing | Location |
|---|---|
| Source repo | `~/nous/phantom-vault` (Rust workspace, `Cargo.toml`) |
| GitHub | `https://github.com/r-db/phantom-vault` (remote `origin`) |
| Built binary | `~/nous/phantom-vault/target/release/phantom-vault` |
| **Secret data at rest** | `~/.phantom-vault/` → `secrets.db` (+ `-wal`, `-shm`), `.auth`, `.salt` |
| MCP wiring | `~/nous/.mcp.json` → runs the binary as `mcp serve`, password file `~/.phantom-vault-pass` |
| Marketing site (WIP) | `/tmp/claude-1000/-home-mobilityfirstxs-Desktop/…/scratchpad/phantomvault/index.html` served by `python3 -m http.server 8791` |
| Public site (claimed) | `phantomvault.riscent.com` · Riscent, LLC |
| Old design docs | `~/nous/phantom-vault/docs/{ARCHITECTURE,MCP_PROTOCOL,SECURITY_AUDIT,THREAT_MODEL}.md` — **dated Feb 26, stale** vs code (commits through Jul 3) |

> ⚠️ The site source is in a **scratchpad** (`/tmp/...`) — that's ephemeral and NOT in git.
> It should be moved into a real repo before more work, or it can vanish on cleanup.

## How it actually works (the model)
1. Secrets are stored encrypted (AES-256-GCM; Argon2 for the master password; keys zeroized
   in memory via `zeroize`) in `~/.phantom-vault/secrets.db`.
2. The vault is **unlocked** with a master password (`open`), used, then **sealed** (`seal`).
3. When an AI needs a secret, it does **not** read it. It calls **`vault_run`**, which spawns
   a subprocess with the secret injected into that subprocess's environment, runs the
   command, and returns **sanitized** output. The value is meant to never appear in what the
   AI sees.
4. Every access is written to an **audit log** (`audit` command).

## The real CLI (14 commands — from `phantom-vault --help`)
`init` · `open` · `seal` · `set` · `get` *(scripts only, "not recommended")* · `delete` ·
`list` · `edit` *(sops-style: opens all secrets in `$EDITOR`)* · `run` *(inject + execute)* ·
`namespace` · `canary` *(honeypot secrets)* · `rotation` · `audit` · `mcp` *(start server)*.

## The MCP tools an AI actually gets (what Nous/Limen call)
`vault_run` (execute with secrets, sanitized output) · `vault_masked` (show masked) ·
`vault_list` · `vault_rotate` · `vault_health` · `vault_exists`. **No tool returns a raw value.**

## The crates (they DO exist — memory said otherwise, memory was stale)
`phantom-core` (3203) · `phantom-sanitizer` (1865, output scrubbing) · `phantom-analyzer`
(2259, command pre-analysis / oracle-attack blocking) · `phantom-sandbox` (1347, subprocess
isolation + egress filtering) · `phantom-mcp` (2466) · `phantom-hardware` (288, HSM/TPM/FIDO2)
· `phantom-cli` (557) · `phantom-security-tests` (1520). Only 4 stub markers total.
**Verified: the code exists. NOT verified here: that each protection is actually *enforced*
at runtime.** That is exactly what Magnus's containment gate is being built to prove.

## VERIFIED vs ASPIRATIONAL — the table Limen needs for honest site copy
| Site/README claim | Status |
|---|---|
| Rust, AES-256-GCM, Argon2, zeroize | **VERIFIED** (deps + code present) |
| 14-command CLI + MCP server | **VERIFIED** (runs) |
| Version **1.8.2** | **FALSE** — code is **0.1.0**. Fix the site. |
| Output sanitization, canary secrets, sandboxed egress, HMAC-chained audit, mlock, HSM | **UNVERIFIED** — crates exist, effectiveness NOT proven. Do **not** state as fact on the site until Magnus's `phantom-vault-containment` gate is GREEN. |
| "The AI never sees the value / cannot exfiltrate" | **UNVERIFIED / known-suspect** — Nous has stated he can subvert it. This is the headline claim and it is currently *unproven*. |

## What needs updating in GitHub (and the site)
1. **Version**: reconcile `0.1.0` (code) with `1.8.2` (site). Pick the truth; make them match.
2. **`docs/*.md`** (Feb 26): rewrite `SECURITY_AUDIT.md` / `THREAT_MODEL.md` against the
   current code, or mark them "design intent, not yet verified."
3. **Site claims**: gate every security bullet behind VERIFIED status. Aspirational features
   get a "planned" label, not present tense.
4. **Move the site out of the scratchpad** into `~/nous/phantom-vault` (e.g. a `site/` dir) or
   its own repo so it's version-controlled and recoverable.

## Where Limen gets the truth (in priority order)
1. **The code**: `~/nous/phantom-vault/crates/*` — the only ground truth.
2. **This doc** (`~/Desktop/PHANTOM_VAULT_TRUTH.md`) — the reconciled state.
3. **Magnus's containment gate** (`~/magnus/specs/phantom-vault-containment/`, in flight) —
   the authority on which security claims are actually enforced. Site copy should follow it.
4. **NOT** the current marketing site or the Feb-26 docs — those are the stale sources.

## Editing config & secrets — CLI editors (start with micro)
`phantom-vault edit` opens all secrets in your `$EDITOR`. On a headless box you want a
terminal editor. **Use `micro` — it's the easiest** (arrow keys, Ctrl-S save, Ctrl-Q quit,
mouse support — like a normal editor, no modes to learn).

```bash
# Install micro (easiest — recommended)
sudo apt install micro            # Debian/Ubuntu
export EDITOR=micro               # add to ~/.bashrc to make it permanent
```

The four common terminal editors, easiest → hardest:
| Editor | Feel | Save / Quit |
|---|---|---|
| **micro** *(recommended)* | modern, intuitive, mouse | `Ctrl-S` / `Ctrl-Q` |
| **nano** | simple, always preinstalled | `Ctrl-O` / `Ctrl-X` |
| **vim** | powerful, modal (learning curve) | `Esc` then `:wq` |
| **emacs** | powerful, extensible | `Ctrl-X Ctrl-S` / `Ctrl-X Ctrl-C` |

Set once: `echo 'export EDITOR=micro' >> ~/.bashrc && source ~/.bashrc`

## The honest bottom line
The engine is real and the design is serious. The **claims are running ahead of the proof**.
Limen's job on the site is to make the copy match the code — VERIFIED features stated plainly,
everything else labeled as intent — and the security headline waits on Magnus's gate. A
security product that overstates its protection is worse than one that understates it.
