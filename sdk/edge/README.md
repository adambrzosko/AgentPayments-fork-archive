# @agentpayments/edge

Shared fetch-runtime gate for edge platforms. One core gate, thin platform adapters.

## Adapters

| Import | Function | Platform |
|---|---|---|
| `@agentpayments/edge/cloudflare` | `createAgentPaymentsWorker()` | Cloudflare Workers |
| `@agentpayments/edge/netlify` | `createNetlifyGate()` | Netlify Edge Functions |
| `@agentpayments/edge/vercel` | `createVercelEdgeGate()` | Vercel Edge Middleware |
| `@agentpayments/edge` | `createEdgeGate()` | Generic fetch runtime |

## Cloudflare Workers

```js
import { createAgentPaymentsWorker } from '@agentpayments/edge/cloudflare';

export default createAgentPaymentsWorker({
  assetsBinding: 'ASSETS',          // Workers Assets binding name
  publicPathAllowlist: [],           // extra paths to bypass gate
  minPayment: 0.01,                  // minimum USDC amount
});
```

Environment variables are read from the Workers `env` object: `CHALLENGE_SECRET`, `HOME_WALLET_ADDRESS`, `SOLANA_RPC_URL`, `USDC_MINT`, `DEBUG`.

## Netlify Edge Functions

```ts
import { createNetlifyGate } from '@agentpayments/edge/netlify';

export default createNetlifyGate();
```

Set environment variables in the Netlify dashboard or `netlify.toml`.

## Vercel Edge Middleware

```ts
import { NextResponse } from 'next/server';
import { createVercelEdgeGate } from '@agentpayments/edge/vercel';

const gate = createVercelEdgeGate({
  env: {
    CHALLENGE_SECRET: process.env.CHALLENGE_SECRET,
    HOME_WALLET_ADDRESS: process.env.HOME_WALLET_ADDRESS,
    SOLANA_RPC_URL: process.env.SOLANA_RPC_URL,
    USDC_MINT: process.env.USDC_MINT,
    DEBUG: process.env.DEBUG,
  },
  upstreamNext: () => NextResponse.next(),
});

export default gate;
```

> For Next.js projects, prefer [`@agentpayments/next`](../next/README.md) which wraps this adapter.

## Generic / Custom Runtime

```js
import { createEdgeGate } from '@agentpayments/edge';

const gate = createEdgeGate({
  fetchUpstream: (request, env) => fetch(request),
  getClientIp: ({ request }) => request.headers.get('x-forwarded-for') || 'unknown',
  publicPathAllowlist: ['/health'],
  minPayment: 0.01,
});

// Use in any fetch-based handler:
export default { fetch: (req, env, ctx) => gate(req, env, ctx) };
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `CHALLENGE_SECRET` | Yes (production) | HMAC secret for signing cookies, nonces, and agent keys. |
| `HOME_WALLET_ADDRESS` | Yes | Solana wallet address to receive USDC payments. |
| `SOLANA_RPC_URL` | No | Custom Solana RPC endpoint. Defaults by debug flag. |
| `USDC_MINT` | No | Custom USDC mint address. Defaults by debug flag. |
| `DEBUG` | No | `"true"` = devnet. `"false"` = mainnet (default varies by adapter). |

## Security Features

- **Timing-safe HMAC comparison** — custom HMAC-then-XOR using Web Crypto API (`crypto.subtle`)
- **Payment verification cache** — 10-minute TTL, 1000-entry max
- **Rate limiting** — 20 challenge verifications per minute per IP
- **Input size limits** — key (64 chars), nonce (128), return URL (2048), fingerprint (128)
- **Wallet address validation** — base58 format, 32-44 chars, validated per-request
- **Default secret detection** — warns in debug, returns 500 in production
- **Structured JSON logging** — all gate events logged as JSON

## TypeScript

TypeScript types are included via `index.d.ts`. The core export:

```ts
import type { EdgeGateOptions } from '@agentpayments/edge';
import { createEdgeGate } from '@agentpayments/edge';
```

## Notes
- ESM module (`import`).
- Uses Web Crypto API (`crypto.subtle`) — no Node.js `crypto` dependency.
- Constants are inlined (not imported from `constants.json`) for Deno/Netlify compatibility.
- The canonical constant values live in `sdk/constants.json`.
