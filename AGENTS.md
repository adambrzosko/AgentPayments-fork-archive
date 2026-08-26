# AGENTS.md

Instructions for **any** coding agent (Claude, Copilot, Cursor, etc.) working in this repository.

For Claude-specific instructions, see [CLAUDE.md](CLAUDE.md).
For human contributors, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Product Direction (Non-Negotiable)

We are building a **Stripe-style integration**:
1. Install/import the AgentPayments package
2. Add a couple of lines of code
3. Bot-blocking + payment gate works

Therefore:
- **Shared gate logic belongs in `sdk/`.** This is the source of truth.
- **Deployment folders are thin wrappers only.** They contain integration glue, config, and demo assets — not gate logic.
- Do not duplicate or fork core gate logic into deployment folders unless explicitly asked.

## Project Layout

```
sdk/                              Source of truth for gate behavior
  constants.json                  Centralized constants (Solana addresses, limits)
  node/                           @agentpayments/node  (Express, CommonJS)
  edge/                           @agentpayments/edge  (Cloudflare/Netlify/Vercel, ESM)
  next/                           @agentpayments/next  (Next.js middleware wrapper)
  python/                         agentpayments-python  (Django/FastAPI/Flask)

node_implementation/              Express demo (thin wrapper)
next_implementation/              Next.js demo (thin wrapper)
edge_implementation/cloudflare_worker/   Cloudflare Worker demo
edge_implementation/netlify/             Netlify Edge demo
python_implementation/django/            Django demo
scripts/                          Utility and demo scripts
```

## Working Rules

1. Make minimal, targeted changes. Avoid unrelated refactors.
2. Prefer editing shared logic in `sdk/` when behavior changes are cross-platform.
3. In deployment folders, keep wiring concise — don't copy core gate logic.
4. Constants go in `sdk/constants.json`, not hardcoded in individual SDKs.
5. Do not move or delete deployment folders without explicit instruction.
6. Never commit secrets or private keys.
7. Keep edits ASCII unless the file already requires Unicode.
8. Preserve existing code style and naming conventions.

## Cross-Runtime Parity

When changing gate behavior, check whether the same change applies across:
- Node SDK (`sdk/node/index.js`)
- Edge SDK (`sdk/edge/index.js`)
- Python SDK (`sdk/python/agentpayments_python/`)

All SDKs should maintain the same security posture and response formats. See [SECURITY.md](SECURITY.md) and [API_REFERENCE.md](API_REFERENCE.md).

## Validation

| Change area | Command |
|---|---|
| Node SDK | `node -e "require('./sdk/node/index.js')"` |
| Edge/Cloudflare | `npx wrangler deploy` from `edge_implementation/cloudflare_worker/` |
| Python syntax | `python3 -c "import ast; ast.parse(open(f).read())"` for each changed file |
| Django | `python manage.py check` from `python_implementation/django/` (requires venv) |

## Change Notes

In PR or handoff summaries, include:
- What changed
- Why it changed
- What was run to validate
- Any remaining risks or follow-ups
