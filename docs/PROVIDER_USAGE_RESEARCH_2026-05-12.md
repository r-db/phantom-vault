# Provider Usage API Research — 2026-05-12

**Purpose:** which AI/SaaS providers expose live USD spend to a regular user-level API key, so Phantom's spending guardrails can poll them?

**TL;DR:** Of 10 providers audited, **4 work with a regular user key today**. The two largest LLM providers (OpenAI, Anthropic) gate usage data behind admin keys. Three providers have no programmatic endpoint at all. The universal fallback for the gated cases is the **gateway pattern** (LiteLLM, Helicone, OpenRouter).

---

## Build priority

| Tier | Providers | Why |
|---|---|---|
| 1. Ship direct adapters | **Deepgram, ElevenLabs, Twilio, OpenRouter** | Regular user key works, no extra setup |
| 2. Ship with onboarding flow | **OpenAI** (mint `sk-admin-`), **Anthropic** (org accounts only) | User-creatable admin key, but it's a separate credential from the inference key |
| 3. Gateway-only | **Gemini, Cohere, Mistral** | No per-key usage endpoint exists |
| 4. Defer / out of scope | **Stripe** | Wrong shape (merchant balance, not fee burn) |

---

## ✅ Works with regular user key

### Deepgram
- **GET** `https://api.deepgram.com/v1/projects/{project_id}/balances` (+ `/billing/breakdown`)
- Auth: `Authorization: Token <API_KEY>`
- Response: `amount` (float), `units: "USD"`. Breakdown by date range.
- Caveat: discover `project_id` first via `GET /v1/projects`. Measures *remaining credit burn*, not invoiced spend.
- Source: [developers.deepgram.com/reference/manage/billing/list](https://developers.deepgram.com/reference/manage/billing/list)

### ElevenLabs
- **GET** `https://api.elevenlabs.io/v1/user/subscription`
- Auth: `xi-api-key: <API_KEY>` header
- Response: `character_count`, `character_limit`, `currency`, `next_character_count_reset_unix`
- Caveat: returns *characters*, not dollars. Phantom multiplies by plan's $/char rate to convert.
- Source: [elevenlabs.io/docs/api-reference/user/subscription/get](https://elevenlabs.io/docs/api-reference/user/subscription/get)

### Twilio
- **GET** `https://api.twilio.com/2010-04-01/Accounts/{AccountSid}/Usage/Records/ThisMonth.json`
- Auth: HTTP Basic — `AccountSid:AuthToken` (or scoped API Key SID/Secret)
- Response: records with `price`, `price_unit: "usd"`, `usage`, `category`
- Caveat: AuthToken is the root credential — encourage users to mint a scoped API Key/Secret in console.
- Source: [twilio.com/docs/usage/api/usage-record](https://www.twilio.com/docs/usage/api/usage-record)

### OpenRouter (with caveat)
- **GET** `https://openrouter.ai/api/v1/credits`
- Auth: `Authorization: Bearer <sk-or-v1-...>`
- Response: `total_credits`, `total_usage`
- Caveat: docs say "Management key required" but historically inference keys worked on `/credits`. The management/inference split rolled out late 2025. **Try inference key first, fall back to management-key prompt on 401.**
- Source: [openrouter.ai/docs/api/api-reference/credits/get-credits](https://openrouter.ai/docs/api/api-reference/credits/get-credits)

---

## ⚠️ Admin/org-only — onboarding flow required

### OpenAI
- **GET** `https://api.openai.com/v1/organization/costs` (and `/usage/*`)
- Auth: `sk-admin-...` (Admin API key only)
- Hard blocker for `sk-proj-` / legacy `sk-` keys → 401
- **Solo devs CAN mint `sk-admin-`** — they own the one-person org. Walk them through Settings → Organization → Admin keys. This is a separate credential from their inference key.
- Source: [platform.openai.com/docs/api-reference/admin-api-keys](https://platform.openai.com/docs/api-reference/admin-api-keys), [community thread](https://community.openai.com/t/why-cant-an-individual-access-budget-spend-without-is-an-organization-admin-key/1367032)

### Anthropic
- **GET** `https://api.anthropic.com/v1/organizations/usage_report/messages` (and `/cost_report`)
- Auth: `x-api-key: sk-ant-admin-...` (Admin API key only)
- **Hard blocker:** Anthropic docs explicitly state *"The Admin API is unavailable for individual accounts."* Phantom should disable polling for individual Anthropic users.
- Source: [platform.claude.com/docs/en/api/administration-api](https://platform.claude.com/docs/en/api/administration-api)

---

## ❌ No programmatic per-key usage endpoint

### Google AI Studio / Gemini
- `AIza...` keys cannot fetch usage. Billing data lives in Google Cloud Billing, queryable only via Cloud Billing API + service-account auth.
- April 2026 introduced tier-based spend caps natively in console.
- Phantom action: require a GCP service account for Gemini cost tracking, or skip and rely on Google's native tier caps.
- Source: [ai.google.dev/gemini-api/docs/billing](https://ai.google.dev/gemini-api/docs/billing)

### Cohere
- Trial vs Production keys + dashboard, but **no public REST endpoint** for programmatic spend retrieval.
- Source: [docs.cohere.com/docs/rate-limits](https://docs.cohere.com/docs/rate-limits)

### Mistral
- Billing lives in console.mistral.ai; public API surface (`api.mistral.ai/v1/`) only exposes inference, embeddings, fine-tuning, agents. **No documented usage endpoint.**
- Source: [docs.mistral.ai](https://docs.mistral.ai/)

---

## 🚫 Not applicable

### Stripe
- `/v1/balance` returns merchant balance (incoming customer money), not fee burn. Would require summing `application_fee` + `balance_transaction` — out of scope.

---

## The gateway fallback

For the 5 providers that don't work with user keys (OpenAI-individual, Anthropic-individual, Gemini, Cohere, Mistral), route inference through a gateway:

- **LiteLLM Proxy** — self-hosted. `/key/info` returns per-key spend in USD. `/user/daily/activity` returns time series. Open source. Fits Phantom's audience.
- **Helicone** — hosted (or self-hostable). One-URL swap, 300+ model pricing baked in. Query API for spend retrieval.
- **OpenRouter** — covered above. Acts as a gateway natively.

**Phantom UX recommendation:** for any provider where direct polling fails (401/403), surface a CTA: *"This provider doesn't expose spend to your API key. Route through LiteLLM / Helicone / OpenRouter to enable caps."*

---

## Universal failure mode

Treat any 401/403/404 from a usage endpoint as **"cap monitoring disabled for this credential"**. Log visibly. **Never** as "cap exceeded → block request." Phantom must never silently block inference because a usage poll failed.

---

## Sources

- Anthropic Admin API: [platform.claude.com/docs/en/api/administration-api](https://platform.claude.com/docs/en/api/administration-api)
- Anthropic Usage + Cost API: [platform.claude.com/docs/en/build-with-claude/usage-cost-api](https://platform.claude.com/docs/en/build-with-claude/usage-cost-api)
- OpenAI Admin API Keys: [platform.openai.com/docs/api-reference/admin-api-keys](https://platform.openai.com/docs/api-reference/admin-api-keys)
- OpenAI Costs: [developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage/methods/costs](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/usage/methods/costs)
- OpenAI individual access discussion: [community.openai.com/t/why-cant-an-individual-access-budget-spend-without-is-an-organization-admin-key/1367032](https://community.openai.com/t/why-cant-an-individual-access-budget-spend-without-is-an-organization-admin-key/1367032)
- Gemini billing: [ai.google.dev/gemini-api/docs/billing](https://ai.google.dev/gemini-api/docs/billing)
- Gemini 2026 billing tiers: [blog.google/innovation-and-ai/technology/developers-tools/more-control-over-gemini-api-costs/](https://blog.google/innovation-and-ai/technology/developers-tools/more-control-over-gemini-api-costs/)
- Deepgram Balances: [developers.deepgram.com/reference/manage/billing/list](https://developers.deepgram.com/reference/manage/billing/list)
- Deepgram Breakdown: [developers.deepgram.com/reference/manage/billing/breakdown/get](https://developers.deepgram.com/reference/manage/billing/breakdown/get)
- ElevenLabs subscription: [elevenlabs.io/docs/api-reference/user/subscription/get](https://elevenlabs.io/docs/api-reference/user/subscription/get)
- ElevenLabs usage stats: [elevenlabs.io/docs/api-reference/usage/get](https://elevenlabs.io/docs/api-reference/usage/get)
- Twilio Usage Records: [twilio.com/docs/usage/api/usage-record](https://www.twilio.com/docs/usage/api/usage-record)
- OpenRouter Credits: [openrouter.ai/docs/api/api-reference/credits/get-credits](https://openrouter.ai/docs/api/api-reference/credits/get-credits)
- OpenRouter Management keys: [openrouter.ai/docs/guides/overview/auth/management-api-keys](https://openrouter.ai/docs/guides/overview/auth/management-api-keys)
- LiteLLM cost tracking: [docs.litellm.ai/docs/proxy/cost_tracking](https://docs.litellm.ai/docs/proxy/cost_tracking)
- Helicone cost guide: [docs.helicone.ai/guides/cookbooks/cost-tracking](https://docs.helicone.ai/guides/cookbooks/cost-tracking)
