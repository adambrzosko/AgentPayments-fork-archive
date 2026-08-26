# @agentpayments/node

Express-first AgentPayments middleware. Blocks bots and gates access behind Solana USDC payments.

## Install

```bash
npm install @agentpayments/node
# or, in this monorepo:
# npm install file:../sdk/node
```

## Usage

```js
const express = require('express');
const { agentPaymentsGate } = require('@agentpayments/node');

const app = express();
app.use(express.urlencoded({ extended: false }));

app.use(agentPaymentsGate({
  challengeSecret: process.env.CHALLENGE_SECRET,
  homeWalletAddress: process.env.HOME_WALLET_ADDRESS,
}));

app.get('/', (req, res) => res.send('Hello, verified visitor!'));
app.listen(3000);
```

## Configuration

| Option | Type | Default | Description |
|---|---|---|---|
| `challengeSecret` | `string` | `'default-secret-change-me'` | HMAC secret for signing cookies, nonces, and agent keys. **Required in production.** |
| `homeWalletAddress` | `string` | `''` | Solana wallet address to receive USDC payments. |
| `solanaRpcUrl` | `string` | Auto (devnet/mainnet) | Custom Solana RPC endpoint. |
| `usdcMint` | `string` | Auto (devnet/mainnet) | Custom USDC mint address. |
| `debug` | `boolean` | `process.env.DEBUG !== 'false'` | `true` = devnet + warnings. `false` = mainnet + strict. |
| `apiKey` | `string` | none | AgentPayments hosted-platform API key (`ap_live_...`). When set, agent keys are issued and metered via the platform instead of self-signed locally. See **Hosted Platform Mode** below. |
| `platformApiUrl` | `string` | AgentPayments-hosted URL | Override for a self-hosted platform API. |

## Environment Variables

| Variable | Maps to |
|---|---|
| `CHALLENGE_SECRET` | `challengeSecret` |
| `HOME_WALLET_ADDRESS` | `homeWalletAddress` |
| `SOLANA_RPC_URL` | `solanaRpcUrl` |
| `USDC_MINT` | `usdcMint` |
| `DEBUG` | `debug` |
| `AGENTPAYMENTS_API_KEY` | `apiKey` |
| `AGENTPAYMENTS_PLATFORM_URL` | `platformApiUrl` |

## Hosted Platform Mode

Setting `apiKey` switches agent-key issuance from local (`ag_...`) to platform-issued (`agp_...`), and — when the platform account has an on-chain fee configured — every 402 response's `payment` object gains a `platform_fee` field:

```json
"payment": {
  "chain": "solana", "network": "devnet", "token": "USDC",
  "amount": "0.01", "wallet_address": "<vendor wallet>", "memo": "agp_...",
  "platform_fee": {
    "wallet_address": "<platform fee wallet>",
    "amount": "0.0002",
    "rate_pct": 2,
    "note": "Must be a second USDC transfer inside the SAME Solana transaction as the payment above, or access will be denied."
  }
}
```

The agent must send **both transfers in one Solana transaction** — the vendor payment and the platform fee — or the gate denies access exactly as it would for an unpaid key. This field is only ever present in hosted-platform mode with a fee configured; it's absent for self-hosted deployments (no `apiKey`), which are completely unaffected. It's deliberately not part of the standards-compliant `accepts[]`/`X-PAYMENT-REQUIRED` x402 fields — those still describe only the vendor leg, so generic x402 clients aren't misled into thinking they can pay either destination.

## Security Features

- **Timing-safe HMAC comparison** — uses `crypto.timingSafeEqual` for all signature checks
- **Payment verification cache** — 10-minute TTL, 1000-entry max, avoids redundant RPC calls
- **Rate limiting** — 20 challenge verifications per minute per IP
- **Input size limits** — key (64 chars), nonce (128), return URL (2048), fingerprint (128)
- **Wallet address validation** — base58 format, 32-44 chars, validated at init
- **Default secret detection** — warns in debug, throws in production
- **Structured JSON logging** — all gate events logged as JSON with timestamps

## How It Works

1. **Public paths** (`/robots.txt`, `/.well-known/*`) bypass the gate.
2. **Browser visitors** (detected via `Sec-Fetch-Mode`/`Sec-Fetch-Dest` headers) receive a JavaScript challenge page. Passing the challenge sets a signed `__agp_verified` cookie (24h TTL).
3. **API clients** without browser headers get a `402` response with an agent key. After paying, they include `X-Agent-Key: <key>` to access resources.

## Response Schema

See [API Reference](../../API_REFERENCE.md) for full 402/403/429 response formats.

## TypeScript

TypeScript types are included via `index.d.ts`. The package exports:

```ts
import type { AgentPaymentsGateConfig } from '@agentpayments/node';
import { agentPaymentsGate } from '@agentpayments/node';
```

## Notes
- CommonJS module (`require()`).
- Constants loaded from `sdk/constants.json`.
- Next wrappers planned: Fastify and Koa (same core behavior).
