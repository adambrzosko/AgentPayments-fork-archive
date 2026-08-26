# Cloudflare Deployment

Cloudflare Workers + static assets deployment demo for AgentPayments.

## Integration Model

This folder is intentionally thin.
Core gate logic is imported from `sdk/edge/cloudflare.js` (the `@agentpayments/edge` package).

That keeps this deployment Stripe-style: small wrapper + config, with shared logic centralized.

## Files
- `wrangler.toml`: Worker config + static asset binding.
- `src/worker.js`: Thin wrapper that imports `createAgentPaymentsWorker` from the edge SDK.
- `public/`: Static site files served via Workers Assets.

## Environment Variables

| Variable | Required | Set via |
|---|---|---|
| `CHALLENGE_SECRET` | Yes | `wrangler secret put CHALLENGE_SECRET` |
| `HOME_WALLET_ADDRESS` | Yes | `wrangler secret put HOME_WALLET_ADDRESS` |
| `SOLANA_RPC_URL` | No | `wrangler.toml` vars or secret |
| `USDC_MINT` | No | `wrangler.toml` vars or secret |
| `DEBUG` | No | `wrangler.toml` vars |

## Local Dev
```bash
cd edge_implementation/cloudflare_worker
npm install
wrangler secret put CHALLENGE_SECRET
wrangler secret put HOME_WALLET_ADDRESS
npm run dev
```

## Deploy
```bash
npm run deploy
```

## Notes
- Public paths bypass the gate: `/robots.txt`, `/.well-known/*`
- `wrangler.toml` uses `run_worker_first = true` so gate logic runs before static assets.
- See [Edge SDK README](../../sdk/edge/README.md) for full adapter documentation.
