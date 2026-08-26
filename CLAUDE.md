# CLAUDE.md

Claude-specific instructions for this repo. See [AGENTS.md](AGENTS.md) for general agent rules.

## Product Intent

Treat this as a Stripe-style developer product.

Target developer experience:
1. Install/import AgentPayments package
2. Add a couple of lines in app bootstrap/middleware
3. Ship

Therefore:
- Shared gate logic belongs in central package-style code (`sdk/` for now).
- Deployment folders should only contain integration glue, config, and demo assets.
- Do not duplicate or fork core gate logic inside deployment folders unless explicitly asked.

## Repo Map

- `sdk/`: Shared AgentPayments gate implementation (source of truth for shared behavior).
  - `sdk/constants.json`: Centralized Solana addresses, limits, config — single source of truth.
  - `sdk/node/`: `@agentpayments/node` (Express-first, CommonJS, TypeScript types).
  - `sdk/edge/`: `@agentpayments/edge` (Cloudflare/Netlify/Vercel adapters, ESM, TypeScript types).
  - `sdk/python/`: `agentpayments-python` (Django/FastAPI/Flask adapters).
  - `sdk/next/`: `@agentpayments/next` (Next.js middleware wrapper).
  - Planned: proxy adapter.
- `python_implementation/django/`: Django integration demo.
- `edge_implementation/netlify/`: Netlify deployment files.
- `edge_implementation/cloudflare_worker/`: Cloudflare Worker integration demo.
- `node_implementation/`: Node/Express integration demo.
- `next_implementation/`: Next.js integration demo.
- `scripts/`: Demo and verification scripts.

## Key Patterns

- All constants centralized in `sdk/constants.json` — JS imports via `require`/`import`, Python reads via `pathlib`.
- Edge SDK uses `crypto.subtle` (Web Crypto API) + custom `timingSafeEqual()`, Node SDK uses `node:crypto`.
- Python uses `hmac.compare_digest()` for all timing-safe comparisons.
- All SDKs have payment verification caching (10-min TTL, 1000 entries max).
- All SDKs have rate limiting on challenge verify endpoint (20 req/min/IP) AND challenge issuance (30 req/min/IP).
- All SDKs use `commitment: 'finalized'` for Solana RPC calls — adds ~10-20s latency vs confirmed but guarantees irreversibility.
- `solanaRpcUrl` / `SOLANA_RPC_URL` / `solana_rpc_url` accepts a string or array — fallback across endpoints on failure.
- `requireHttps` defaults to `true` in production (debug: false) across all SDKs. Behind a proxy, set `trust proxy` (Express) or `SECURE_PROXY_SSL_HEADER` (Django).
- Edge SDK inlines constants from `sdk/constants.json`. Run `node scripts/check-edge-constants.js` to verify parity.
- Django reads config from `settings.*`, FastAPI/Flask from constructor args.
- Edge SDK runs per-request (env resolved each call), Node SDK resolves at init.

## Expectations

- Keep diffs focused and avoid unrelated refactors.
- Follow existing code style and structure.
- Avoid destructive git/file operations unless explicitly requested.
- Do not add secrets, keys, or sensitive values to tracked files.
- When changing gate behavior, check cross-runtime parity (Node, Edge, Python).

## Verification

| Change area | Command |
|---|---|
| Node SDK | `node -e "require('./sdk/node/index.js')"` |
| Node tests | `node --test sdk/node/index.test.js` |
| Edge/Cloudflare | `npx wrangler deploy` from `edge_implementation/cloudflare_worker/` |
| Edge constants parity | `node scripts/check-edge-constants.js` |
| Python syntax | `python3 -c "import ast; ast.parse(open(f).read())"` for each changed file |
| Python tests | `cd sdk/python && python3 -m pytest tests/` |
| Django | `python python_implementation/django/manage.py check` (requires venv) |

Report any command you could not run and why.

## Handoff Format

Summarize:
- Files changed
- Behavior impact
- Validation performed
- Known gaps
