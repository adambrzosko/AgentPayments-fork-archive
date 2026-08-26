# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- **Centralized constants** — `sdk/constants.json` is the single source of truth for Solana addresses, limits, cookie config, and input size caps. Node SDK imports via `require()`, Python via `pathlib`, Edge SDK inlines values for Deno compatibility.
- **TypeScript type definitions** — `index.d.ts` for both `@agentpayments/node` and `@agentpayments/edge` packages.
- **Payment verification caching** — 10-minute TTL, 1000-entry max across all SDKs. Avoids redundant Solana RPC calls for previously verified agent keys.
- **Rate limiting** — 20 requests per minute per IP on the `/__challenge/verify` endpoint. Returns `429 Too Many Requests` when exceeded. Thread-safe implementation in Python via `ratelimit.py`.
- **Input size limits** — All user-supplied fields are truncated: agent key (64), nonce (128), return URL (2048), fingerprint (128).
- **Wallet address validation** — Base58 regex check (32-44 chars) at initialization. Invalid addresses throw/raise immediately.
- **Default secret detection** — If `CHALLENGE_SECRET` is the insecure default: warns in debug mode, throws (Node), returns 500 (Edge), or raises `RuntimeError` (Python) in production.
- **Structured JSON logging** — `gateLog()` helper in Node and Edge SDKs outputs JSON with timestamps, log level, and component name.
- **Accessible challenge page** — CSS spinner, visible "Verifying your access..." text, `<noscript>` fallback, `role="status"`, `aria-live="polite"`.
- **Standardized 402 responses** — All SDKs return consistent JSON with `error`, `message`, `your_key`, and `payment` object containing chain, network, token, amount, wallet, and memo.
- **Edge SDK `rpcCall()` helper** — Extracted RPC call logic with `resp.ok` checking for better error handling.
- **Documentation** — SECURITY.md, API_REFERENCE.md, CHANGELOG.md, CONTRIBUTING.md. Expanded all SDK READMEs with env var tables, security features, response schemas.

### Fixed
- **Timing-safe comparison everywhere** — Node SDK now uses `crypto.timingSafeEqual` for cookie and nonce checks (was using `===`). Edge SDK uses custom HMAC-then-XOR via Web Crypto API. Python SDKs use `hmac.compare_digest()` for nonce verification.
- **Django Secure cookie flag** — Changed from `secure_cookie = False` to `secure_cookie = request.is_secure()` to auto-detect HTTPS.
- **Netlify deployment** — Edge functions can't import files outside the site base directory. Added build command in `netlify.toml` to copy SDK files locally at deploy time.
- **Cloudflare README** — Fixed incorrect path reference (`../sdk/cloudflare-gate.js` → `sdk/edge/cloudflare.js`).

### Removed
- **Duplicate Python package** — Deleted `sdk/python/agentpayments_gate/` (old copy of the Python SDK).

## [0.1.0] — Initial Release

### Added
- `@agentpayments/node` — Express middleware with agent key generation, payment verification, and browser challenge.
- `@agentpayments/edge` — Fetch-runtime gate with Cloudflare, Netlify, and Vercel adapters.
- `agentpayments-python` — Django, FastAPI, and Flask adapters.
- `@agentpayments/next` — Next.js middleware wrapper.
- Demo deployments for Cloudflare Workers, Netlify Edge, Django (Oracle VM), Node/Express, and Next.js (Vercel).
