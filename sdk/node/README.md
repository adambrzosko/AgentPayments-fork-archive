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

## Environment Variables

| Variable | Maps to |
|---|---|
| `CHALLENGE_SECRET` | `challengeSecret` |
| `HOME_WALLET_ADDRESS` | `homeWalletAddress` |
| `SOLANA_RPC_URL` | `solanaRpcUrl` |
| `USDC_MINT` | `usdcMint` |
| `DEBUG` | `debug` |

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
