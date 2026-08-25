# LLM Wallet Hub (Devnet MVP)

Separate software that:
- creates a per-user Solana devnet wallet,
- lets user fund it from any external wallet,
- issues scoped API keys for LLM tool calls,
- enforces hard policy controls,
- exposes a payment tool endpoint and generated system prompt.

Tool payments are USDC SPL token transfers on Solana (memo/verification compatible with AgentPayments paywall).

## What this is
MVP for cross-LLM wallet execution via tools (GPT/Claude/Gemini).

LLM does **not** hold keys. It calls a tool endpoint with a user API key.
Server enforces policy and signs transactions.

## Run
```bash
cd llm_wallet_hub
npm install
cp .env.example .env
# set MASTER_KEY
npm run dev
# open http://localhost:8787

# run tests
npm test
```

## Core endpoints
- `POST /api/signup` -> create account + wallet
- `POST /api/login`
- `GET /api/me` -> wallet + balance
- `POST /api/faucet` -> top-up wallet (tries devnet airdrop, optional bot-wallet fallback)
- `POST /api/keys` -> issue tool key
- `GET /api/system-prompt?model=gpt|claude|gemini`
- `POST /api/tool/pay` (header `x-wallet-tool-key`)
- `GET /api/tool/balance` (header `x-wallet-tool-key`)

## Security model (hardened MVP)
- Passwords: `scrypt`
- Wallet secret key: encrypted (AES-256-GCM) under `MASTER_KEY` (required, min 32 chars)
- Session tokens + API keys stored hashed (SHA-256)
- API key raw value shown once at creation
- Rate limits on auth and payment endpoints
- Input validation for email, Solana addresses, numeric limits
- Hard policy checks:
  - max per payment
  - daily cap
  - optional recipient allowlist
- Optional idempotency via `x-idempotency-key` on `/api/tool/pay`

## Known gaps before production
- No MFA / no email verification
- If `DATABASE_URL` is unset, fallback JSON file storage is used (set Postgres in production)
- No key rotation UX, no signed challenge validation yet
- No per-domain policy / no challenge-price verification
- No idempotency keys / no approval workflow above thresholds

## Example tool call
```bash
curl -X POST http://localhost:8787/api/tool/pay \
  -H 'Content-Type: application/json' \
  -H 'x-wallet-tool-key: ak_...' \
  -d '{
    "recipient": "RecipientPublicKey",
    "amountUsdc": 0.01,
    "token": "USDC",
    "reason": "Need access to paywalled docs",
    "resourceUrl": "https://example.com/docs"
  }'
```
