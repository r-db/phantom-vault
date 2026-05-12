# Phantom Vault — Landing Page Draft

**Target URL:** phantomvault.com (or phantomvault.riscent.com)
**Audience:** Solo developers + hobbyists building with AI coding agents (Claude Code, Cursor, Aider, Continue, Windsurf)
**Positioning:** Free gift to the community from Riscent. Open source. Audit the crypto yourself. No tiers, no upsells, no nag screens.
**Tone:** Founder-direct. Sober about the risk, not fearmongering. Generous about the gift.

---

## HERO SECTION

### Headline
**Your AI assistant has your API keys. Make sure nobody else does.**

### Subhead
Phantom Vault is a free, open-source credential manager built for developers who code with AI. Store your keys once. Your AI uses them, but never sees them. Save what you saved into your shell, not into a public repo.

### Primary CTA
```
curl -fsSL https://raw.githubusercontent.com/r-db/phantom-vault/main/install.sh | bash
```
**[Copy installer]** — installs in 30 seconds on macOS or Linux. No account. No payment. Just works.

### Secondary CTA
**[View source on GitHub]** → r-db/phantom-vault — Apache 2.0

---

## SECTION 1 — THE WAKE-UP CALL (founder story)

### Headline
**Three months ago, a startup in Mexico woke up to an $82,314 bill.**

### Body
Their normal monthly spend was $180. Their Gemini API key had been stolen — embedded somewhere in client-side code, picked up by an automated scanner, and exploited over a 48-hour weekend. Three engineers, nearly bankrupted, no refund.

That's not an outlier. It's the new baseline. In April, Lakera scanned 46,500 npm packages and found that **1 in 13** that used Claude Code's "allow always" feature had leaked live API credentials. The credentials weren't in conversations — they were silently written to a project file the dev didn't know existed.

You're building with AI. So am I. The friction is supposed to be lower, not higher — but the credential surface area went up, not down. The tools weren't designed for it. We need a tool that was.

That's why this exists.

**[Citations: The Register on Gemini bill, bdtechtalks on Claude Code key leak — both linked in footer]**

---

## SECTION 2 — WHAT IT DOES

### Headline
**Three things, all free, forever.**

### Three columns

**1. Encrypted vault on your machine**
AES-256-GCM at rest, Argon2id key derivation. Audit the crypto yourself — it's all open source. Open the vault in your editor with `phantom edit`, type your keys like you're editing a config file, save, done. Encrypted on disk the moment you close the editor.

**2. AI integration via MCP**
One command (`phantom mcp install`) wires Phantom into Claude Code, Cursor, Aider, Continue, and Windsurf. Your AI requests a credential by name (`openai-key`). Phantom injects the value at execution. The actual key never enters your AI's conversation context.

**3. Spending guardrails (coming soon)**
Cap your monthly spend per key. Phantom polls the provider's billing API and warns you at 80%, locks you at 100%. You will not wake up to an $82,314 bill.

---

## SECTION 3 — WHY IT'S FREE

### Headline
**No tiers. No upsells. This is a gift.**

### Body
We build other software — voice agents for medical practices, AI workflows for content creators, healthcare platforms. That software pays our bills. Phantom Vault is the tool we wish existed when we started building with AI, so we built it and gave it to you. The whole thing.

If you find it useful and want to support the work, there's a sponsor button. If you don't, just use it. That's the deal.

**[GitHub Sponsors button]** — optional, never required.

---

## SECTION 4 — INSTALL

### Headline
**One command. Thirty seconds.**

### Body
```bash
curl -fsSL https://raw.githubusercontent.com/r-db/phantom-vault/main/install.sh | bash
```

The installer detects your OS and CPU, downloads the signed binary from a verified GitHub Release, verifies SHA256 checksums, and drops it into `/usr/local/bin` (or `~/.local/bin` if you don't have sudo). No package managers required, no curl-pipe-to-shell sketchiness — the script is **[readable here](https://github.com/r-db/phantom-vault/blob/main/install.sh)** before you run it.

Once installed:
```bash
phantom init                       # create your vault
phantom edit                       # add keys in $EDITOR
phantom biometric enable           # one-time Keychain unlock (macOS)
phantom mcp install                # wire Claude Code
```

---

## SECTION 5 — OPEN SOURCE FAQ

### Why open source?
Because security through obscurity isn't security. Kerckhoffs's principle has been the rule for 140 years: a cryptosystem should be secure even if everything except the key is publicly known. Every crypto library you depend on — OpenSSL, libsodium, age — is open source. We built Phantom the same way.

### Apache 2.0 — what does that mean?
You can use it, fork it, modify it, ship it inside your own commercial product. The only thing we ask is that you preserve the license header. We won't change the license out from under you.

### Will there ever be a paid tier?
Not planned. If we add hosted features in the future (sync, mobile), we'd offer them as a hosted convenience for people who want to pay for not running their own server — but the local CLI will always be free, full-featured, and have no nag screens.

### How do I know the binaries match the source?
Every release is built by GitHub Actions from the public source tree. The workflow file is [here](https://github.com/r-db/phantom-vault/blob/main/.github/workflows/release.yml). You can rebuild from source any time with `cargo build --release`.

---

## SECTION 6 — WHO MADE THIS

Short founder bio. Ryan Bolden, Riscent. Built Phantom Vault because three different times in 2025–2026, friends building with AI tools had keys leak and bills surprise them. Connecting AI agents to credentials safely is too important to leave to "the AI tools will figure it out eventually."

**[Email signup]** — get notified when we ship new features. No spam, no sales emails. ~1 email/month.

**[Twitter/X]** — @ryanbolden or @riscentai

---

## FOOTER

- GitHub: r-db/phantom-vault
- Apache 2.0
- Built by [Riscent](https://riscent.com)
- Citations: [The Register $82K Gemini bill](https://www.theregister.com/2026/03/03/gemini_api_key_82314_dollar_charge/) · [bdtechtalks Claude Code leak study](https://bdtechtalks.com/2026/04/27/claude-code-api-token-leak/) · [HN discussion](https://news.ycombinator.com/item?id=47584850)

---

## NOTES FOR THE PERSON BUILDING THIS

**Stack suggestion:** Next.js 16 + Tailwind, deployed on Vercel. ~1-2 days to build. Use the existing IB365 brand voice but more developer-flavored — slightly more terminal-aesthetic, less corporate.

**Visual direction:**
- Hero: dark terminal aesthetic, install command in monospace, blinking cursor.
- Sections separated by horizontal rules, not heavy borders.
- Code blocks should look like actual terminal output, not generic syntax highlighting.
- The $82K story section gets a slightly different background — sober, urgent, but not red-alert. Beige or muted amber works.
- The "why it's free" section is the warmest, most personal. Use a handwritten-style accent if it fits.

**What's NOT on the page (deliberate):**
- No pricing table
- No "compare plans"
- No "sign up for free trial"
- No marketing pixels other than basic Plausible/GoatCounter for traffic measurement
- No newsletter popup nag
- No "speak to sales" CTA

**Email capture:**
The only form on the page is "get notified when we ship features." Optional. Below the fold. ConvertKit or Buttondown — keep the list portable, never lock in.

**What to A/B test once live:**
1. Headline variants — "Make sure nobody else does" vs "Without ever showing them"
2. Hero CTA — copy-install-command vs "Install now" button
3. The $82K story placement — Section 1 (current) vs after What It Does
