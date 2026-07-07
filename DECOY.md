# Phantom Vault — Decoy Layer (honeypot design)

**Principle (Ryan, 2026-07-06):** a directory literally named for secrets advertises the
treasure. So the *obvious* path is a **decoy** holding only **fake** credentials plus a
**canary**; the **real** vault lives at a hidden, non-obvious name and is the one actually
used. An agent or attacker that grabs the easy target gets worthless fakes **and trips the
canary**, which records a `CanaryTriggered` breach event in the audit log — turning an
exfiltration attempt into an alarm.

## The two vaults

| | Decoy (honeypot) | Real vault |
|---|---|---|
| Location | the OBVIOUS path — e.g. `~/.vault-secrets` / `~/.phantom-vault` (the name a scanner or LLM tries first) | a HIDDEN, innocuous name that does not say "secret" or "vault" — e.g. `~/.config/.state-cache/` |
| Contents | only **fake** credentials + at least one **canary** secret (e.g. `AWS_KEY=AKIA_FAKE_DECOY…`) | the genuine secrets, actually read/written by CLI + MCP |
| On access | reading the canary fires a `CanaryTriggered` event (phantom-core `canary.rs`) → breach detected | normal use, no alarm |
| Who points here | nobody real; it exists to be found | `PHANTOM_VAULT_DIR` (CLI + `vault-mcp`) resolve here |

## Enforcement hooks (phantom-core, already present)
- **Canary:** `crates/phantom-core/src/canary.rs` — `is_canary` flag in the `secrets` table;
  access emits a breach event.
- **Audit:** `crates/phantom-core/src/audit.rs` — `CanaryTriggered` event type records the hit.

## Status (honest)
- **Designed + documented:** this file; canary + audit enforcement code exists in phantom-core.
- **Wiring (the deploy step, deliberate):** relocate the real vault from the obvious
  `~/.phantom-vault` to the hidden path, repoint `PHANTOM_VAULT_DIR` (CLI + `.mcp.json`) at it,
  then plant the decoy vault at the obvious path containing only fake secrets + one canary.
  This moves live secrets, so it runs as a guarded migration (backup first, verify read-back)
  — NOT silently. Real vault is currently at `~/.phantom-vault` and is backed up
  (`~/.phantom-vault.bak_*`).

The decoy is real security, not decor: it only counts once the real vault is at the hidden
name and the obvious path holds fakes+canary. Until that migration runs, this documents the
contract Magnus gates and the exact steps to wire it.
