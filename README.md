# AgentPayments

Stripe-style payment gate for web resources. Vendors install an SDK, add a few lines of code, and their site is protected: browsers pass a JavaScript challenge, AI agents pay with Solana USDC.

## Quick Start

Pick your runtime and add the gate in under 5 lines:

**Node/Express**
```js
const { agentPaymentsGate } = require('@agentpayments/node');
app.use(agentPaymentsGate({
  challengeSecret: process.env.CHALLENGE_SECRET,
  homeWalletAddress: process.env.HOME_WALLET_ADDRESS,
}));
```

**Next.js** (`middleware.ts`)
```ts
import { createNextMiddleware } from '@agentpayments/next';
export default createNextMiddleware();
export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
```

**Cloudflare Workers**
```js
import { createAgentPaymentsWorker } from '@agentpayments/edge/cloudflare';
export default createAgentPaymentsWorker({ assetsBinding: 'ASSETS' });
```

**Django** (`settings.py`)
```python
MIDDLEWARE = [
    "agentpayments_python.django_adapter.GateMiddleware",
    # ...
]
```

**FastAPI / Flask** — see [Python SDK README](sdk/python/README.md).

## How It Works

1. **Browser visitors** receive a transparent JavaScript challenge page (canvas fingerprint + nonce). If they pass, a signed cookie grants access for 24 hours.
2. **API clients (agents)** without a browser get a `402 Payment Required` response containing a generated agent key. They send a USDC payment on Solana with the key as the transaction memo, then include `X-Agent-Key: <key>` on subsequent requests.
3. **Public paths** (`/robots.txt`, `/.well-known/*`) bypass the gate entirely.

See [API Reference](API_REFERENCE.md) for full request/response details.

## Architecture

```
sdk/                          Shared gate logic (source of truth)
  constants.json              Centralized Solana addresses, limits, config
  node/                       @agentpayments/node  (Express middleware, CommonJS)
  edge/                       @agentpayments/edge  (Cloudflare/Netlify/Vercel, ESM)
  next/                       @agentpayments/next  (Next.js middleware wrapper)
  python/                     agentpayments-python  (Django/FastAPI/Flask adapters)

node_implementation/          Express demo (thin wrapper)
next_implementation/          Next.js demo (thin wrapper)
edge_implementation/
  cloudflare_worker/          Cloudflare Worker demo
  netlify/                    Netlify Edge demo
python_implementation/
  django/                     Django demo
scripts/                      Utility and demo scripts
```

**Rule:** deployment folders stay thin. Core gate behavior belongs in `sdk/` packages.

## SDK Roadmap

1. :white_check_mark: `@agentpayments/node` — Express middleware (CommonJS + TypeScript types)
2. :white_check_mark: `@agentpayments/edge` — Fetch-runtime gate with Cloudflare, Netlify, and Vercel adapters (ESM + TypeScript types)
3. :white_check_mark: `agentpayments-python` — Django, FastAPI, and Flask adapters
4. :white_check_mark: `@agentpayments/next` — First-class Next.js middleware wrapper
5. :hourglass_flowing_sand: Proxy adapter (Nginx/Envoy style enforcement)

## Security Features

All SDKs share the same security posture:

- **Timing-safe comparison** for all HMAC checks (agent keys, cookies, nonce signatures)
- **Payment verification caching** — 10-minute TTL, 1000-entry max, avoids redundant RPC calls
- **Rate limiting** — 20 challenge verifications per minute per IP
- **Input size limits** — agent key (64), nonce (128), return URL (2048), fingerprint (128)
- **Wallet address validation** — base58 format, 32-44 characters, checked at init
- **Default secret detection** — warns in debug mode, throws/500s in production
- **Structured JSON logging** (Node/Edge SDKs)

See [SECURITY.md](SECURITY.md) for the full threat model.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `CHALLENGE_SECRET` | Yes (production) | HMAC secret for signing cookies, nonces, and agent keys. Must be unique and strong. |
| `HOME_WALLET_ADDRESS` | Yes | Solana wallet address to receive USDC payments. |
| `SOLANA_RPC_URL` | No | Custom Solana RPC endpoint. Defaults to devnet/mainnet based on `DEBUG`. |
| `USDC_MINT` | No | Custom USDC mint address. Defaults to devnet/mainnet based on `DEBUG`. |
| `DEBUG` | No | Set to `"false"` for production (mainnet). Defaults to `true` (devnet). |

## Public Demo URLs

- **Cloudflare Worker**: https://agentpayments-cloudflare.matthew-newell.workers.dev
- **Django (Oracle VM)**: https://clankertax.tearsheet.one
- **Next.js (Vercel)**: https://nextjsdeployment-five.vercel.app

## JSON Files

- `.test-keypair.json`: Local devnet Solana keypair used by test scripts. Safe to delete; scripts will recreate it.
- `bot-wallet.json`: Wallet data used by the bot visitor script.
- `wallet-keys.json`: Generated wallet keys used by local scripts.
- `edge_implementation/netlify/.well-known/agent-access.json`: Public discovery file for Netlify demo.
- `python_implementation/django/.well-known/agent-access.json`: Public discovery file for Django demo.

## Django (Oracle VM)

For Oracle Always Free VM deployment, see `python_implementation/django/DEPLOY_ORACLE.md`.
