# Contributing

Thanks for your interest in AgentPayments. This guide covers how to work with the codebase.

## Project Structure

```
sdk/                    Shared gate logic (source of truth)
  constants.json        Centralized constants (Solana addresses, limits)
  node/                 @agentpayments/node  (Express, CommonJS)
  edge/                 @agentpayments/edge  (Cloudflare/Netlify/Vercel, ESM)
  next/                 @agentpayments/next  (Next.js wrapper)
  python/               agentpayments-python (Django/FastAPI/Flask)

*_implementation/       Deployment demos (thin wrappers, not core logic)
scripts/                Utility and demo scripts
```

**Key principle:** core gate behavior lives in `sdk/`. Deployment folders are integration demos only — they should contain minimal wiring and config, not duplicated logic.

## Development Setup

### Node SDKs

```bash
# Verify Node SDK loads
node -e "require('./sdk/node/index.js')"

# Run the Express demo
cd node_implementation
npm install
npm start
```

### Edge SDK

```bash
# Cloudflare Worker demo
cd edge_implementation/cloudflare_worker
npm install
npm run dev

# Netlify demo (requires netlify CLI)
cd edge_implementation/netlify
netlify dev
```

### Python SDK

```bash
# Verify Python syntax
python3 -c "import ast; ast.parse(open('sdk/python/agentpayments_python/django_adapter.py').read())"

# Django demo (requires venv)
cd python_implementation/django
python -m venv venv
source venv/bin/activate
pip install django
python manage.py check
python manage.py runserver
```

## Making Changes

### Before You Start
1. Read `CLAUDE.md` for coding agent instructions and `AGENTS.md` for working rules.
2. Understand where your change belongs: `sdk/` (shared logic) vs `*_implementation/` (demo wiring).

### Guidelines
- **Keep diffs focused.** Avoid unrelated refactors in the same change.
- **Follow existing style.** Match the code style and naming conventions already in use.
- **No secrets.** Never commit API keys, wallet private keys, or sensitive values.
- **Constants go in `sdk/constants.json`.** Don't hardcode Solana addresses or limit values.
- **Cross-runtime parity.** If you change gate behavior in one SDK, check if the same change applies to Node, Edge, and Python.

### Validation

After changes, run the appropriate checks:

| Change area | Validation |
|---|---|
| Node SDK | `node -e "require('./sdk/node/index.js')"` |
| Edge SDK | `npx wrangler deploy` from `edge_implementation/cloudflare_worker/` |
| Python SDK | `python3 -c "import ast; ast.parse(open(f).read())"` for each changed file |
| Django | `python manage.py check` from `python_implementation/django/` |

### Change Notes

In PR descriptions, include:
- What changed
- Why it changed
- What was run to validate
- Any remaining risks or follow-ups

## Adding a New Adapter

To add support for a new platform (e.g., Fastify, Koa, or a new edge runtime):

1. Identify the closest existing SDK (Node for server frameworks, Edge for fetch runtimes).
2. Create a thin adapter that imports and wraps the core gate logic.
3. Add a README with usage examples, env var table, and security feature summary.
4. Add a demo in a new `*_implementation/` directory.
5. Update the root README's architecture diagram and SDK roadmap.

## Questions

Open an issue for questions about architecture decisions, new adapter proposals, or anything else.
