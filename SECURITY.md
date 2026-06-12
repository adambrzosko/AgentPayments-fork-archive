# Security

This document describes the security model of AgentPayments, the threats it addresses, and the defenses built into the SDK.

## Threat Model

AgentPayments sits at the edge of a web application and decides whether to allow or block each request. The primary threats are:

| Threat | Impact | Mitigation |
|---|---|---|
| **Timing attacks on HMAC** | Attacker infers valid signatures byte-by-byte | Timing-safe comparison in all SDKs |
| **Agent key forgery** | Attacker crafts a key that passes validation without paying | HMAC-SHA256 signing; keys are `ag_<random>_<hmac>` |
| **Cookie forgery** | Attacker crafts a verification cookie to bypass the challenge | HMAC-signed timestamp cookies with expiry, bound to client IP |
| **Cookie sharing/theft** | One solved challenge feeds a fleet of scrapers | Cookie HMAC includes client IP hash — invalid from any other IP |
| **Nonce replay** | Attacker reuses a captured challenge nonce | 5-minute expiry + IP-bound HMAC + single-use tracking |
| **Bulk cookie minting** | Scripted client solves challenges at scale | SHA-256 proof-of-work (~16^4 hashes per cookie, configurable) |
| **Faked browser headers** | Scraper sends `Sec-Fetch-*` headers to reach the challenge | Challenge requires proof-of-work + server-validated fingerprint, not just headers |
| **Challenge endpoint abuse** | Attacker brute-forces verification to extract cookies | Rate limiting (20 req/min/IP) |
| **Oversized input injection** | Attacker sends huge payloads to cause memory issues | Input size limits on all user-supplied fields |
| **Invalid wallet address** | Misconfigured wallet causes silent payment failures | Base58 validation at init time |
| **Insecure default secret** | Deployed with `default-secret-change-me` | Warns in debug, throws/500s in production |
| **Redundant RPC calls** | Repeated on-chain lookups for the same agent key | Payment verification cache (10-min TTL) |
| **Bot detection bypass** | Headless browsers pass the challenge | Canvas fingerprint + `navigator.webdriver` check |

## Cryptographic Primitives

### HMAC-SHA256

All signatures (agent keys, cookies, nonces) use HMAC-SHA256 with the `CHALLENGE_SECRET` as the key.

- **Node SDK**: `crypto.createHmac('sha256', secret)` from `node:crypto`
- **Edge SDK**: `crypto.subtle.sign('HMAC', key, data)` via Web Crypto API
- **Python SDK**: `hmac.new(secret, data, hashlib.sha256)` from stdlib

### Timing-Safe Comparison

Every HMAC check uses constant-time comparison to prevent timing side-channels:

- **Node**: `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))`
- **Edge**: Custom HMAC-then-XOR — both values are HMAC'd with a fixed key, then XOR'd byte-by-byte. This avoids the lack of `timingSafeEqual` in Web Crypto.
- **Python**: `hmac.compare_digest(a, b)`

### Agent Key Format

```
ag_<16-char-random>_<16-char-hmac>
```

- `ag_` prefix identifies the key type.
- The random portion is a UUID fragment.
- The HMAC is `hmacSign(random, CHALLENGE_SECRET)` truncated to 16 hex chars.
- Max key length: 64 characters.

### Client Binding

A short client identifier binds nonces and cookies to the requester:

```
client_id = hmacSign("client:<ip>", CHALLENGE_SECRET)[:16]
```

A cookie or nonce captured by another machine fails validation because the
verifying request's IP produces a different `client_id`. Trade-off: clients
whose IP changes mid-session (e.g. mobile network handoff) re-solve the
challenge.

### Cookie Format

```
<timestamp>.<hmac>
```

- Timestamp is `Date.now()` at cookie creation.
- HMAC is `hmacSign("cookie:<timestamp>:<client_id>", CHALLENGE_SECRET)`.
- Cookie name: `__agp_verified`.
- Max age: 86400 seconds (24 hours).
- Flags: `HttpOnly`, `Secure`, `SameSite=Lax`.

### Nonce Format

```
<timestamp>.<random>.<hmac>
```

- Timestamp is `Date.now()` at nonce creation; random is 16 hex chars.
- HMAC is `hmacSign("nonce:<timestamp>:<random>:<client_id>", CHALLENGE_SECRET)`.
- Expires after 5 minutes (300,000 ms).
- Single-use: consumed nonces are tracked in memory and rejected on replay.
  (Best-effort on multi-instance/edge deployments until a shared state
  backend lands — see ROADMAP.)

### Proof-of-Work

The challenge page must find a decimal counter `pow` such that:

```
sha256("<nonce>:<pow>") starts with "0" * POW_DIFFICULTY   (default: 4 hex chars)
```

Verification costs the server one hash; solving costs ~16^difficulty hashes
(~65k at the default, sub-second in a real browser via Web Crypto). This makes
bulk cookie minting computationally expensive while staying invisible to
legitimate visitors. Configurable per SDK: `powDifficulty` (Node/Edge/Next),
`pow_difficulty` (FastAPI/Flask), `POW_DIFFICULTY` Django setting.

### Fingerprint Validation

The submitted canvas fingerprint must be base64 (`[A-Za-z0-9+/]`, ≥10 chars)
with at least 4 distinct characters. This is a plausibility filter, not proof
of a real browser — the proof-of-work and client binding carry the security
weight. Client-side checks (`navigator.webdriver`, canvas render, viewport
size) are friction for naive bots, not a security boundary.

## Input Validation

All user-supplied inputs are truncated before processing:

| Field | Max Length | Source |
|---|---|---|
| Agent key (`X-Agent-Key`) | 64 chars | `sdk/constants.json` |
| Nonce | 128 chars | `sdk/constants.json` |
| Return URL (`return_to`) | 2048 chars | `sdk/constants.json` |
| Canvas fingerprint (`fp`) | 128 chars | `sdk/constants.json` |

Wallet addresses are validated against the base58 regex `/^[1-9A-HJ-NP-Za-km-z]{32,44}$/` at initialization time.

## Rate Limiting

The `/__challenge/verify` endpoint is rate-limited to **20 requests per minute per IP**.

- Node/Edge: in-memory `Map` with sliding window cleanup.
- Python: thread-safe `RateLimiter` class with `threading.Lock`.

Exceeding the limit returns `429 Too Many Requests`.

## Payment Verification Cache

Successful on-chain payment verifications are cached to avoid repeated Solana RPC calls:

- **TTL**: 10 minutes
- **Max entries**: 1,000 (oldest evicted first)
- **Key**: agent key string
- Cache miss triggers a fresh RPC verification; cache hit returns immediately.

## Default Secret Detection

If `CHALLENGE_SECRET` is set to `'default-secret-change-me'`:

| Mode | Behavior |
|---|---|
| Debug (`DEBUG=true`) | Logs a warning, continues running |
| Production (`DEBUG=false`) | Node SDK throws, Edge SDK returns 500, Python raises `RuntimeError` |

## Browser Challenge

The challenge page served to browser visitors:

1. Checks `navigator.webdriver` (rejects headless browsers).
2. Renders a canvas fingerprint to detect non-browser environments.
3. Validates `window.innerWidth` is non-zero (screens have dimensions).
4. Solves the SHA-256 proof-of-work over the nonce via Web Crypto.
5. Submits nonce + fingerprint + proof-of-work + return URL via hidden form POST.
6. Includes `<noscript>` fallback for JavaScript-disabled users.
7. Uses `role="status"` and `aria-live="polite"` for accessibility.

Note: the challenge requires a secure context (HTTPS or localhost) because it
uses `crypto.subtle`.

## Responsible Disclosure

If you discover a security vulnerability, please report it privately. Do not open a public GitHub issue.

Contact the maintainers directly with details of the vulnerability, steps to reproduce, and any suggested fixes.
