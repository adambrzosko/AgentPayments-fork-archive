# @agentpayments/next

First-class Next.js middleware wrapper over `@agentpayments/edge`.

## Usage

Create `middleware.ts` in your project root:

```ts
import { createNextMiddleware } from '@agentpayments/next';

export default createNextMiddleware({
  publicPathAllowlist: ['/favicon.ico'],
  minPayment: 0.01,
});

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

That's it. The middleware reads environment variables automatically from `process.env`.

## Configuration

| Option | Type | Default | Description |
|---|---|---|---|
| `publicPathAllowlist` | `string[]` | `[]` | Extra paths that bypass the gate (added to built-in `/robots.txt`, `/.well-known/*`). |
| `minPayment` | `number` | `0.01` | Minimum USDC payment amount. |
| `env` | `object` | `process.env.*` | Override environment variable resolution (advanced). |

## Environment Variables

Set these in `.env.local` or your hosting platform (Vercel dashboard, etc.):

| Variable | Required | Description |
|---|---|---|
| `CHALLENGE_SECRET` | Yes (production) | HMAC secret for signing cookies, nonces, and agent keys. |
| `HOME_WALLET_ADDRESS` | Yes | Solana wallet address to receive USDC payments. |
| `SOLANA_RPC_URL` | No | Custom Solana RPC endpoint. Defaults to devnet/mainnet. |
| `USDC_MINT` | No | Custom USDC mint address. Defaults to devnet/mainnet. |
| `DEBUG` | No | `"true"` = devnet. `"false"` = mainnet. |

## How It Works

This package is a thin wrapper around `@agentpayments/edge`'s Vercel adapter. It:

1. Reads env vars from `process.env` (no manual passing needed)
2. Extracts client IP from `x-forwarded-for` header
3. Calls `NextResponse.next()` for approved requests

All security features (timing-safe HMAC, rate limiting, caching, input limits) are inherited from the edge SDK.

## Vercel Deployment

Set env vars in your Vercel project settings, then deploy as normal. For this monorepo, set the project root to `next_implementation` so that `file:../sdk/next` resolves during install.

## Notes
- This is implementation #4 in the SDK roadmap.
- Keep framework glue here; core gate behavior lives in `sdk/edge`.
- TypeScript source (`index.ts`) is compiled to `index.js` for the package.
