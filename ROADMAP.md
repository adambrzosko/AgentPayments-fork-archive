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

### 4. RPC exhaustion DoS on the agent path — **fixed**
Valid agent keys are free to mint (every 402 issues one) and each unpaid key triggered up to ~100+ `getTransaction` calls. Fixed: negative results cached 30 s (skips RPC on repeated attempts), agent-key verification path rate-limited at 10 req/min/IP, and `getTransaction` calls capped at 20 per verification. Remaining: negative results on the KV store propagate across isolates via the pluggable store interface, but the in-memory fallback is still per-isolate.

### 5. Paid access silently expires — **fixed**
Verification re-scans the last 100 signatures, so a paid key stopped working once the wallet received 100 newer transactions. Fixed: pluggable `grantStore` interface (Node: `sdk/node/grant-store.js`, Python: `sdk/python/agentpayments_python/grant_store.py`). Once a key is verified it is added to the store and never re-scanned. Default is in-memory (no persistence). `FileGrantStore` writes to a JSON file with atomic rename — survives restarts, not suitable for multi-process deployments. For multi-process use Redis or a database. Edge: the `CloudflareKVStore` already stores results durably with a 30-day TTL for positive results (set by `PAYMENT_CACHE_TTL` in `setCachedPayment`).

### 6. Nonce replay — **fixed (best-effort on edge)**
Nonces now carry a random component and are tracked in an in-memory consumed set after use. On multi-isolate edge runtimes this is per-isolate until a shared state backend lands (see P1).

### 7. Private keys committed to git — **gitignore fixed; history purge required**
`jsons/wallet-keys.json` and `jsons/bot-wallet.json` are tracked in git. `jsons/` is now in `.gitignore` so no new keys will be committed. The existing history still contains the keys — you must purge it before open-sourcing:

```bash
# Install git-filter-repo (pip install git-filter-repo)
git filter-repo --path jsons/ --invert-paths
# Rotate the wallets — assume the devnet keys are compromised.
```

## P1 — Adoption blockers

### SEO safety (the #1 objection from prospective sites) — **fixed**
Search crawlers received a 402 like any other non-browser. Fixed: all three SDKs now run a verified-crawler check before the gate — UA pattern match followed by reverse+forward DNS verification (Google's documented method). Googlebot, Bingbot, Slurp, DuckDuckBot, Baiduspider, YandexBot, and Applebot are supported. Results are cached 1 hour. On by default; disable with `verifyCrawlers: false` (Node/Edge/Next/Flask/FastAPI) or `AGENTPAYMENTS_VERIFY_CRAWLERS = False` (Django). Remaining: IPv6 reverse DNS not yet supported in the edge DoH path.

### Legacy browser fallout — **fixed**
Browsers without `Sec-Fetch-*` headers (Chrome < 76, Firefox < 90, some mobile WebViews) got a 402. Fixed: `isBrowser` now falls back to a UA regex (Chrome, Chromium, Firefox, Safari, Edge, Opera, Samsung Browser, UC Browser) when Sec-Fetch headers are absent, with an explicit bot-UA exclusion to stop scrapers spoofing a browser UA.

### Pluggable state backends — **fixed (Node)**
Rate limiter and payment cache are in-memory Maps — per-isolate on Cloudflare/Vercel, so limits barely apply and every isolate re-scans the chain. Fixed for Node: `sdk/node/redis-store.js` provides `RateLimiter`, `PaymentCache`, and `createRedisStore(redisClient)` — drop-in replacements for the in-memory stores, backed by atomic Lua INCR+EXPIRE for rate limiting and SET EX for payment cache. Fail-open on Redis errors. Pass via `rateLimiter`, `agentKeyRateLimiter`, `paymentCache` options to `agentPaymentsGate`. Edge/Python: still in-memory; Cloudflare KV/Durable Objects adapter is next.

### x402 protocol compatibility — **fixed**
LLM agents don't reliably parse the custom 402 JSON (noted in TODO). Fixed: all three SDKs (Node, Edge, Python) now emit `x402Version: 1`, `accepts: [PaymentRequirements]`, and an `X-PAYMENT-REQUIRED` base64-encoded header on every 402 response, following the x402 SVM `exact` scheme spec. Chain IDs use CAIP-2 format (`solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` mainnet, `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` devnet). Amount is in base units (micro-USDC). x402 utilities also exported from `agentpayments_python` (`build_payment_requirements`, `enrich_402_body`, `payment_required_header`).

### Production RPC strategy
Public Solana endpoints heavily rate-limit `getSignaturesForAddress`/`getTransaction`. Document paid RPC (Helius/Triton/QuickNode) as a requirement for production, and add an optional webhook-based payment indexer so verification is a single lookup instead of a chain scan.

### Pricing & access model
One 0.01 USDC payment currently buys indefinite access. Vendors need: configurable price, payment-amount → access-duration mapping (or per-request metering), per-route pricing tiers, and key revocation.

### Publishing — **package metadata complete**
npm packages (`@agentpayments/node`, `@agentpayments/edge`) have `package.json` with description, license, exports, files, keywords, repository, and `publishConfig`. Python package (`agentpayments-python`) has `pyproject.toml` with license, classifiers (Beta, Python 3.10–3.12, MIT), project URLs, and optional extras for each framework. Still required before shipping: README for each package, `npm publish` / `twine upload`, and git tag.

## P2 — Quality and scale

- Vendor dashboard: payments received, keys issued/active, blocked-request stats (already in TODO).
- Proxy adapter (Nginx/Envoy) for non-Node/Python stacks.
- Structured logging for Python SDK (Node/Edge already have it).
- Configurable cookie lifetime and challenge difficulty.

## Test plan — **initial suites written and passing**

| Suite | Coverage | Status |
|---|---|---|
| Unit (per SDK) | Key generate/validate round-trip, malformed/truncated keys, cookie expiry & tampering, nonce expiry & tampering, rate-limiter windows, cache TTL/eviction | **done** — 30 Node tests (`sdk/node/index.test.js`), 96 Python tests (`sdk/python/tests/test_core.py`) |
| Cross-runtime parity | Same secret produces identical keys/cookies/nonce signatures across Node and Python | **done** — covered in both suites |
| Payment verification (mocked RPC) | Wrong mint, wrong destination, partial amount, failed tx (`err` set on sig), no ATAs, TX cap, positive/negative cache | **done** — covered in both suites |
| Adversarial regression | Faked `Sec-Fetch-*` headers, junk `fp`, replayed nonces, tampered keys/cookies, keys from wrong secret | **done** — covered in both suites |
| E2E | Script hitting all four live deployments: browser flow, agent 402 flow, paid-key flow, public paths | pending — add to CI |
| Load | Unpaid-key flood to confirm RPC DoS mitigations hold | pending |

Run: `node --test sdk/node/index.test.js` and `cd sdk/python && pytest tests/`.
