# API Reference

This document describes the HTTP behavior of the AgentPayments gate — request routing, response formats, cookies, and the end-to-end agent key flow.

## Request Routing

Every incoming request is classified and handled in this order:

```
1. Public path?        → Pass through (no gate)
2. Challenge verify?   → Validate nonce, set cookie, redirect
3. Non-browser client? → Agent key flow (402 / 403 / pass)
4. Valid cookie?       → Pass through
5. Otherwise           → Serve challenge page
```

### Public Paths (Bypass)

These paths always pass through without any gate check:

- `/robots.txt`
- `/.well-known/*` (any path under `.well-known`)

Adapters may define additional bypass paths via `publicPathAllowlist`.

### Browser Detection

A request is classified as a "browser" if it includes either of these headers:
- `Sec-Fetch-Mode`
- `Sec-Fetch-Dest`

If these headers are absent, the gate falls back to a browser `User-Agent` heuristic (Chrome/Firefox/Safari/Edge/etc.) with an explicit bot/crawler UA exclusion.

All other requests (curl, AI agents, API clients) are treated as non-browser.

## Agent Key Flow

This is the end-to-end flow for AI agents and API clients.

### Step 1: Initial Request (No Key)

**Request:**
```
GET /any-path HTTP/1.1
Host: example.com
```

**Response: `402 Payment Required`**
```json
{
  "error": "payment_required",
  "message": "Access requires a paid API key. A key has been generated for you below. Send a USDC payment on Solana with this key as the memo to activate it, then retry your request with the X-Agent-Key header.",
  "your_key": "ag_abc123def456_9f8e7d6c5b4a3210",
  "payment": {
    "chain": "solana",
    "network": "devnet",
    "token": "USDC",
    "amount": "0.01",
    "wallet_address": "<vendor-wallet>",
    "memo": "ag_abc123def456_9f8e7d6c5b4a3210",
    "instructions": "Send 0.01 USDC on Solana devnet to <vendor-wallet> with memo \"ag_abc123def456_9f8e7d6c5b4a3210\". Then include the header X-Agent-Key: ag_abc123def456_9f8e7d6c5b4a3210 on all subsequent requests."
  }
}
```

### Step 2: Send USDC Payment

The agent sends a Solana transaction with:
- **Amount**: at least `0.01` USDC (configurable via `minPayment`)
- **Recipient**: the `wallet_address` from the 402 response
- **Memo**: the `your_key` value (attached via the SPL Memo program)

### Step 3: Retry with Key (Payment Not Yet Confirmed)

**Request:**
```
GET /any-path HTTP/1.1
Host: example.com
X-Agent-Key: ag_abc123def456_9f8e7d6c5b4a3210
```

**Response: `402 Payment Required`** (if payment not yet found on-chain)
```json
{
  "error": "payment_required",
  "message": "Key is valid but payment has not been verified on-chain yet. Please send the USDC payment and allow a few moments for confirmation.",
  "your_key": "ag_abc123def456_9f8e7d6c5b4a3210",
  "payment": {
    "chain": "solana",
    "network": "devnet",
    "token": "USDC",
    "amount": "0.01",
    "wallet_address": "<vendor-wallet>",
    "memo": "ag_abc123def456_9f8e7d6c5b4a3210"
  }
}
```

### Step 4: Retry with Key (Payment Confirmed)

**Request:**
```
GET /any-path HTTP/1.1
Host: example.com
X-Agent-Key: ag_abc123def456_9f8e7d6c5b4a3210
```

**Response:** The upstream resource is served normally. Subsequent requests with the same key are served from cache (10-min TTL) without additional RPC calls.

## Error Responses

### `403 Forbidden` — Invalid Agent Key

```json
{
  "error": "forbidden",
  "message": "Invalid API key. Keys must be issued by this server.",
  "details": "GET /.well-known/agent-access.json for access instructions."
}
```

### `403 Forbidden` — Challenge Verification Failed

```json
{
  "error": "forbidden",
  "message": "Challenge verification failed."
}
```

### `403 Forbidden` — Expired Challenge

```json
{
  "error": "forbidden",
  "message": "Challenge expired. Reload the page."
}
```

### `429 Too Many Requests` — Rate Limited

```json
{
  "error": "rate_limited",
  "message": "Too many verification attempts. Please wait and try again."
}
```

### `500 Internal Server Error` — No Wallet Configured

```json
{
  "error": "server_error",
  "message": "Payment verification unavailable."
}
```

### `500 Internal Server Error` — Insecure Secret in Production

Returned by the Edge SDK when `CHALLENGE_SECRET` is the default value and `DEBUG` is `false`. Node SDK throws at startup instead. Python raises `RuntimeError` at startup.

## Browser Challenge Flow

### Step 1: Serve Challenge Page

When a browser request arrives without a valid `__agp_verified` cookie, the gate returns:

```
HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: no-store
```

The HTML page contains a JavaScript challenge that:
1. Checks `navigator.webdriver` is falsy
2. Renders a canvas fingerprint
3. Validates `window.innerWidth > 0`
4. Auto-submits a hidden form to `/__challenge/verify`

### Step 2: Challenge Verification

**Request (auto-submitted by challenge page):**
```
POST /__challenge/verify HTTP/1.1
Content-Type: application/x-www-form-urlencoded

nonce=<timestamp>.<hmac>&return_to=/original-path&fp=<canvas-fingerprint>
```

**Response: `302 Found`**
```
Set-Cookie: __agp_verified=<timestamp>.<hmac>; Max-Age=86400; Path=/; HttpOnly; Secure; SameSite=Lax
Location: /original-path
```

### Step 3: Subsequent Requests

Browser includes the `__agp_verified` cookie automatically. The gate validates the cookie signature and timestamp, and passes the request through if valid. Cookie expires after 24 hours.

## Cookie Details

| Property | Value |
|---|---|
| Name | `__agp_verified` |
| Format | `<timestamp>.<hmac-signature>` |
| Max Age | 86400 seconds (24 hours) |
| Path | `/` |
| HttpOnly | Yes |
| Secure | Yes (Node/Edge always; Django uses `request.is_secure()`) |
| SameSite | `Lax` |

## Discovery Endpoint

Vendors can serve a `/.well-known/agent-access.json` file to help AI agents discover payment instructions. This path is always allowed through the gate.

Example:
```json
{
  "agent_payments": {
    "version": "1.0",
    "payment": {
      "chain": "solana",
      "token": "USDC",
      "wallet_address": "<vendor-wallet>",
      "min_amount": "0.01"
    },
    "instructions": "Send a USDC payment with your agent key as the memo, then include X-Agent-Key header on requests."
  }
}
```
