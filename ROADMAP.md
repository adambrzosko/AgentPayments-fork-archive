# Roadmap to Production

Prioritized list of work required before real websites can rely on AgentPayments. Ordered by severity: P0 = exploitable today, P1 = adoption blocker, P2 = quality/scale.

## P0 — Security fixes (gate is currently bypassable)

### 1. Challenge bypass via faked headers — **mitigated**
`isBrowser()` only checks for `Sec-Fetch-Mode`/`Sec-Fetch-Dest`, which any HTTP client can set, and the verify endpoint accepted any `fp` ≥ 10 chars. Fixed: SHA-256 proof-of-work (default ~65k hashes per cookie, configurable), base64 fingerprint validation server-side, single-use nonces, and nonce/cookie binding to client IP. See SECURITY.md. Remaining: a determined attacker with native code can still solve PoW cheaply — raising difficulty, TLS/JA3 fingerprinting, or behavioral signals would be the next escalation.

### 2. Payment verification accepts non-payments — **fixed**
`verifyPaymentOnChain` accepted any `spl-token` `transfer` ≥ 0.01 of *any* token to *any* destination, in any transaction that merely referenced the vendor wallet. Fixed: payment now must land in one of the vendor's USDC token accounts, with the mint re-checked for `transferChecked`. Remaining hardening:

- Check commitment level (finalized vs. confirmed).
- Use post/pre token balance deltas instead of instruction parsing for robustness against exotic transaction shapes.

### 3. Cookies are not bound to a client — **fixed**
A verification cookie was `timestamp.hmac` — identical for every visitor, valid from any IP. Now the cookie HMAC includes a client-IP hash, so a captured cookie fails from any other IP. Trade-off: clients whose IP changes mid-session re-solve the challenge.

### 4. RPC exhaustion DoS on the agent path
Valid agent keys are free to mint (every 402 issues one) and each unpaid key triggers up to ~100+ `getTransaction` calls. Only successful verifications are cached.

- Cache negative results with a short TTL (e.g., 30–60s).
- Rate-limit the `X-Agent-Key` verification path per IP (the existing limiter only covers `/__challenge/verify`).
- Cap total `getTransaction` calls per verification.

### 5. Paid access silently expires
Verification re-scans the last 100 signatures, so a paid key stops working once the wallet receives 100 newer transactions — an attacker can force this with dust transfers. Persist successful verifications (grant record keyed by agent key) instead of re-scanning; the 10-min cache is not persistence.

### 6. Nonce replay — **fixed (best-effort on edge)**
Nonces now carry a random component and are tracked in an in-memory consumed set after use. On multi-isolate edge runtimes this is per-isolate until a shared state backend lands (see P1).

### 7. Private keys committed to git
`jsons/wallet-keys.json` (includes mnemonic) and `jsons/bot-wallet.json` (includes secret key) are tracked. Even devnet-only, purge them from git history (`git filter-repo`) before open-sourcing or publishing, rotate the wallets, and gitignore the whole `jsons/` directory.

## P1 — Adoption blockers

### SEO safety (the #1 objection from prospective sites)
Search crawlers hit the non-browser path and receive a 402. Add a verified-crawler allowlist: match UA, then confirm via reverse DNS (Googlebot, Bingbot) or published IP ranges. Make it on by default with config to disable.

### Legacy browser fallout
Browsers that don't send `Sec-Fetch-*` headers are classified as agents and shown a payment demand. Add a fallback signal (UA heuristic + Accept header) before classifying a request as an agent.

### Pluggable state backends
Rate limiter and payment cache are in-memory Maps — per-isolate on Cloudflare/Vercel, so limits barely apply and every isolate re-scans the chain. Support Cloudflare KV/Durable Objects, Redis, and a database-backed store; keep in-memory as the dev default.

### x402 protocol compatibility
LLM agents don't reliably parse the custom 402 JSON (noted in TODO). Emit x402-standard response fields/headers alongside the current body so existing agent payment clients interoperate without custom logic.

### Production RPC strategy
Public Solana endpoints heavily rate-limit `getSignaturesForAddress`/`getTransaction`. Document paid RPC (Helius/Triton/QuickNode) as a requirement for production, and add an optional webhook-based payment indexer so verification is a single lookup instead of a chain scan.

### Pricing & access model
One 0.01 USDC payment currently buys indefinite access. Vendors need: configurable price, payment-amount → access-duration mapping (or per-request metering), per-route pricing tiers, and key revocation.

### Publishing
Publish `@agentpayments/node`, `@agentpayments/edge`, `@agentpayments/next` to npm and `agentpayments-python` to PyPI. Until installable, nobody integrates.

## P2 — Quality and scale

- Vendor dashboard: payments received, keys issued/active, blocked-request stats (already in TODO).
- Proxy adapter (Nginx/Envoy) for non-Node/Python stacks.
- Structured logging for Python SDK (Node/Edge already have it).
- Configurable cookie lifetime and challenge difficulty.

## Test plan (currently zero automated tests)

| Suite | Coverage |
|---|---|
| Unit (per SDK) | Key generate/validate round-trip, malformed/truncated keys, cookie expiry & tampering, nonce expiry & tampering, rate-limiter windows, cache TTL/eviction |
| Cross-runtime parity | Same secret produces identical keys/cookies/nonce signatures across Node, Edge, Python; cookie issued by one runtime validates in another |
| Payment verification (mocked RPC) | Wrong mint, wrong destination, plain `transfer` of junk token, partial amount, memo-only tx, failed tx (`err` set), inner instructions, vendor with no ATA |
| Adversarial regression | Faked `Sec-Fetch-*` headers, junk `fp`, replayed nonces, crafted transactions referencing the vendor wallet without paying it |
| E2E | Script hitting all four live deployments: browser flow, agent 402 flow, paid-key flow, public paths (already in TODO — add to CI) |
| Load | Unpaid-key flood to confirm RPC DoS mitigations hold |

Suggested tooling: `node:test` for Node/Edge (Edge via miniflare/workerd), `pytest` for Python, GitHub Actions for CI.
