const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const {
  COOKIE_NAME, COOKIE_MAX_AGE, KEY_PREFIX,
  USDC_MINT_DEVNET, USDC_MINT_MAINNET,
  RPC_DEVNET, RPC_MAINNET,
  MEMO_PROGRAM, MIN_PAYMENT,
  MAX_KEY_LENGTH, MAX_NONCE_LENGTH, MAX_RETURN_TO_LENGTH, MAX_FP_LENGTH,
  POW_DIFFICULTY, MAX_POW_LENGTH, NONCE_TTL_MS,
  NEGATIVE_CACHE_TTL_MS,
  MAX_TRANSACTIONS_PER_VERIFY,
  AGENT_KEY_RATE_LIMIT_MAX,
  USDC_DECIMALS,
  X402_VERSION,
  SOLANA_CHAIN_ID_MAINNET,
  SOLANA_CHAIN_ID_DEVNET,
  PLATFORM_API_URL,
  HOSTED_KEY_PREFIX,
} = require('./constants.json');
const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const PAYMENT_CACHE_TTL = 10 * 60 * 1000; // 10 minutes
const PAYMENT_CACHE_MAX = 1000;
// Challenge page issuance: more permissive than verify (getting a nonce is cheap),
// but still rate-limited to prevent offline PoW mining with unlimited nonces.
const CHALLENGE_ISSUE_RATE_LIMIT_MAX = 30;

class PaymentCache {
  constructor(maxSize = PAYMENT_CACHE_MAX) {
    this.maxSize = maxSize;
    this.cache = new Map();
  }
  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return undefined;
    if (Date.now() - entry.ts > entry.ttl) { this.cache.delete(key); return undefined; }
    return entry.value;
  }
  // ttlMs defaults to PAYMENT_CACHE_TTL for positive results; pass NEGATIVE_CACHE_TTL_MS for negatives.
  set(key, value, ttlMs = PAYMENT_CACHE_TTL) {
    if (this.cache.size >= this.maxSize) {
      const oldest = this.cache.keys().next().value;
      this.cache.delete(oldest);
    }
    this.cache.set(key, { value, ts: Date.now(), ttl: ttlMs });
  }
}

function gateLog(level, message, data = {}) {
  const entry = JSON.stringify({ ts: new Date().toISOString(), level, component: 'agentpayments', message, ...data });
  if (level === 'error') console.error(entry);
  else if (level === 'warn') console.warn(entry);
  else console.log(entry);
}

const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 20; // max requests per window per IP

class RateLimiter {
  constructor(windowMs = RATE_LIMIT_WINDOW, max = RATE_LIMIT_MAX) {
    this.windowMs = windowMs;
    this.max = max;
    this.hits = new Map();
  }
  check(key) {
    const now = Date.now();
    const entry = this.hits.get(key);
    if (!entry || now - entry.start > this.windowMs) {
      this.hits.set(key, { start: now, count: 1 });
      return true;
    }
    entry.count++;
    if (entry.count > this.max) return false;
    return true;
  }
  cleanup() {
    const now = Date.now();
    for (const [key, entry] of this.hits) {
      if (now - entry.start > this.windowMs) this.hits.delete(key);
    }
  }
}

// ---------------------------------------------------------------------------
// Verified crawler allowlist
// UA heuristic + reverse/forward DNS verification (Google's documented method).
// Results are cached for 1 hour to avoid repeated DNS lookups.
// ---------------------------------------------------------------------------
const CRAWLER_PATTERNS = [
  { pattern: /googlebot/i,     suffix: '.googlebot.com' },
  { pattern: /google-inspectiontool/i, suffix: '.google.com' },
  { pattern: /bingbot/i,       suffix: '.search.msn.com' },
  { pattern: /slurp/i,         suffix: '.crawl.yahoo.net' },
  { pattern: /duckduckbot/i,   suffix: '.duckduckgo.com' },
  { pattern: /baiduspider/i,   suffix: '.crawl.baidu.com' },
  { pattern: /yandexbot/i,     suffix: '.yandex.com' },
  { pattern: /applebot/i,      suffix: '.applebot.apple.com' },
];
const CRAWLER_CACHE_TTL = 60 * 60 * 1000; // 1 hour
const _crawlerCache = new Map(); // ip -> { verified: boolean, exp: number }

async function isVerifiedCrawler(ip, userAgent) {
  if (!userAgent || !ip || ip === 'unknown') return false;
  const match = CRAWLER_PATTERNS.find((c) => c.pattern.test(userAgent));
  if (!match) return false;

  const cached = _crawlerCache.get(ip);
  if (cached && cached.exp > Date.now()) return cached.verified;

  let verified = false;
  try {
    const hostnames = await dns.reverse(ip);
    if (hostnames.length > 0) {
      const hostname = hostnames[0];
      if (hostname.endsWith(match.suffix)) {
        // Forward verify: resolve hostname back and confirm it contains the original IP.
        const addrs = await dns.lookup(hostname, { all: true });
        verified = addrs.some((a) => a.address === ip);
      }
    }
  } catch { /* DNS failure = not verified */ }

  _crawlerCache.set(ip, { verified, exp: Date.now() + CRAWLER_CACHE_TTL });
  return verified;
}

function hmacSign(data, secret) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Short HMAC of the client IP. Used to bind nonces and cookies to the client
// that solved the challenge, so a captured cookie is useless from another IP.
function clientIdForIp(ip, secret) {
  return hmacSign(`client:${ip}`, secret).slice(0, 16);
}

function getClientIp(req) {
  return req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}

// Canvas fingerprints are a base64 slice of a data URL. Reject anything that
// isn't base64 or is degenerate (e.g. a single repeated character).
const FP_RE = /^[A-Za-z0-9+/]{10,}$/;
function isPlausibleFingerprint(fp) {
  return FP_RE.test(fp) && new Set(fp).size >= 4;
}

// Proof-of-work: sha256(`${nonce}:${pow}`) must start with `difficulty` zero
// hex chars. Verification is a single hash; solving costs ~16^difficulty tries.
function verifyPow(nonce, pow, difficulty) {
  if (!/^\d{1,20}$/.test(pow)) return false;
  return sha256Hex(`${nonce}:${pow}`).startsWith('0'.repeat(difficulty));
}

// Single-use nonce tracking (best-effort, in-memory).
class ConsumedNonces {
  constructor(ttl = NONCE_TTL_MS, maxSize = 10000) {
    this.ttl = ttl;
    this.maxSize = maxSize;
    this.seen = new Map();
  }
  // Returns true if the nonce was fresh (and marks it consumed).
  consume(sig) {
    const now = Date.now();
    const exp = this.seen.get(sig);
    if (exp !== undefined && exp > now) return false;
    if (this.seen.size >= this.maxSize) {
      const oldest = this.seen.keys().next().value;
      this.seen.delete(oldest);
    }
    this.seen.set(sig, now + this.ttl);
    return true;
  }
  cleanup() {
    const now = Date.now();
    for (const [sig, exp] of this.seen) {
      if (exp <= now) this.seen.delete(sig);
    }
  }
}

function generateAgentKey(secret) {
  const random = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  const sig = hmacSign(random, secret);
  return `${KEY_PREFIX}${random}_${sig.slice(0, 16)}`;
}

function isValidAgentKey(key, secret) {
  if (!key || key.length > MAX_KEY_LENGTH || !key.startsWith(KEY_PREFIX)) return false;
  const rest = key.slice(KEY_PREFIX.length);
  const underscoreIndex = rest.indexOf('_');
  if (underscoreIndex === -1) return false;
  const random = rest.slice(0, underscoreIndex);
  const sig = rest.slice(underscoreIndex + 1);
  const expected = hmacSign(random, secret);
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected.slice(0, 16)));
}

/**
 * Verify a platform-issued agent key (agp_ prefix) using the vendor's
 * verificationSecret (derived by the platform, shared at registration).
 *
 * Key format: agp_${vendorId8}_${nonce16}_${sig16}
 * sig = hmac('agp:vendorId:nonce', verificationSecret).slice(0,16)
 */
function isValidHostedKey(key, verificationSecret) {
  if (!key || !key.startsWith(HOSTED_KEY_PREFIX)) return false;
  const parts = key.split('_');
  // Expected: ['agp', vendorId(8), nonce(16), sig(16)] → 4 parts
  if (parts.length !== 4) return false;
  const [, vendorId, nonce, sig] = parts;
  if (!vendorId || !nonce || !sig || sig.length !== 16) return false;
  const expected = hmacSign(`agp:${vendorId}:${nonce}`, verificationSecret).slice(0, 16);
  if (expected.length !== sig.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

/**
 * Thin client for the AgentPayments Platform API.
 *
 * Lazily fetches the verificationSecret on first key issuance (one API call per
 * process restart), then issues keys and verifies them locally with no further
 * platform round-trips.
 */
class PlatformClient {
  constructor(apiKey, platformUrl = PLATFORM_API_URL) {
    this.apiKey = apiKey;
    this.platformUrl = platformUrl.replace(/\/$/, '');
    this._verificationSecret = null;
    this._platformFeeInfo = undefined; // undefined = not fetched yet; null = fetched, no fee configured
    this._accountFetch = null;
  }

  _authHeaders() {
    return { Authorization: `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' };
  }

  /** Lazily fetch + cache the /v1/account response (verificationSecret + fee info). */
  _fetchAccount() {
    if (this._accountFetch) return this._accountFetch;
    this._accountFetch = fetch(`${this.platformUrl}/v1/account`, { headers: this._authHeaders() })
      .then((r) => {
        if (!r.ok) throw new Error(`Platform /v1/account returned ${r.status}`);
        return r.json();
      })
      .then((data) => {
        this._verificationSecret = data.verificationSecret;
        this._platformFeeInfo = data.platformFeeWallet
          ? { wallet: data.platformFeeWallet, ratePct: data.platformFeeRatePct }
          : null;
        return data;
      })
      .catch((err) => {
        this._accountFetch = null; // allow retry on next call
        throw err;
      });
    return this._accountFetch;
  }

  /** Lazily fetch + cache the verificationSecret from the platform. */
  async getVerificationSecret() {
    if (this._verificationSecret) return this._verificationSecret;
    await this._fetchAccount();
    return this._verificationSecret;
  }

  /**
   * Lazily fetch + cache the on-chain platform fee config (same request as
   * getVerificationSecret — no extra round trip if already fetched).
   * Returns { wallet, ratePct } or null if no fee is configured.
   */
  async getPlatformFeeInfo() {
    if (this._platformFeeInfo !== undefined) return this._platformFeeInfo;
    await this._fetchAccount();
    return this._platformFeeInfo;
  }

  /** Issue a single platform-signed agent key (agp_...). Metered server-side. */
  async issueKey() {
    const r = await fetch(`${this.platformUrl}/v1/keys/issue`, {
      method: 'POST',
      headers: this._authHeaders(),
      body: '{}',
    });
    if (!r.ok) throw new Error(`Platform /v1/keys/issue returned ${r.status}`);
    return r.json(); // { key, issuedAt }
  }
}

async function rpcCall(rpcUrl, method, params, { retries = 2, backoffMs = 300 } = {}) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, backoffMs * attempt));
    try {
      const resp = await fetch(rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      });
      // Only retry on 5xx (server-side transient errors); 4xx are permanent.
      if (resp.status >= 500) { lastError = new Error(`RPC ${method} failed: ${resp.status}`); continue; }
      if (!resp.ok) throw new Error(`RPC ${method} failed: ${resp.status}`);
      return resp.json();
    } catch (err) {
      // Network/timeout errors are always retriable.
      if (err.message?.includes('failed:')) throw err; // re-throw permanent 4xx
      lastError = err;
    }
  }
  throw lastError;
}

// Try each URL in order; move to the next only on network/5xx failure, not on
// 4xx (which are permanent errors from the endpoint itself).
async function rpcCallWithFallback(rpcUrls, method, params, opts) {
  let lastError;
  for (const url of rpcUrls) {
    try {
      return await rpcCall(url, method, params, opts);
    } catch (err) {
      lastError = err;
      if (rpcUrls.length > 1) gateLog('warn', 'RPC endpoint failed, trying fallback', { url, error: err.message });
    }
  }
  throw lastError;
}

/**
 * Verify payment on-chain.
 *
 * feeInfo, when set (hosted-platform mode with an on-chain fee configured), is
 * { wallet, ratePct }. When set, the SAME transaction that carries the vendor
 * payment must also carry a USDC transfer to feeInfo.wallet of at least
 * minPayment * ratePct / 100, or the payment is treated as unverified.
 */
async function verifyPaymentOnChain(agentKey, walletAddress, rpcUrls, usdcMint, minPayment = MIN_PAYMENT, feeInfo = null) {
  try {
    // commitment: 'finalized' — confirmed blocks can be rolled back (rare but possible).
    // Finalized adds ~10-20s latency vs confirmed but guarantees irreversibility.
    const ataData = await rpcCallWithFallback(rpcUrls, 'getTokenAccountsByOwner', [
      walletAddress,
      { mint: usdcMint },
      { encoding: 'jsonParsed', commitment: 'finalized' },
    ]);

    const tokenAccounts = (ataData.result?.value || []).map((a) => a.pubkey);
    // Only transfers landing in one of the vendor's USDC token accounts count as
    // payment. Token accounts are mint-bound, so membership also guarantees the
    // token is USDC for plain `transfer` instructions (which carry no mint field).
    const vendorUsdcAccounts = new Set(tokenAccounts);
    if (vendorUsdcAccounts.size === 0) return false; // vendor has no USDC account yet — no payment possible

    let feeUsdcAccounts = null;
    let feeAmountMicro = 0;
    if (feeInfo) {
      const feeAtaData = await rpcCallWithFallback(rpcUrls, 'getTokenAccountsByOwner', [
        feeInfo.wallet,
        { mint: usdcMint },
        { encoding: 'jsonParsed', commitment: 'finalized' },
      ]);
      feeUsdcAccounts = new Set((feeAtaData.result?.value || []).map((a) => a.pubkey));
      feeAmountMicro = Math.round(Math.round(minPayment * 1e6) * feeInfo.ratePct / 100);
      if (feeUsdcAccounts.size === 0) return false; // fee wallet has no USDC account — fee can never be satisfied
    }

    const addressesToScan = [walletAddress, ...tokenAccounts];
    const seen = new Set();
    const allSignatures = [];

    for (const addr of addressesToScan) {
      const sigsData = await rpcCallWithFallback(rpcUrls, 'getSignaturesForAddress', [addr, { limit: 100, commitment: 'finalized' }]);
      for (const sig of sigsData.result || []) {
        if (!seen.has(sig.signature)) {
          seen.add(sig.signature);
          allSignatures.push(sig);
        }
      }
    }

    let txCallCount = 0;
    for (const sigInfo of allSignatures) {
      if (txCallCount >= MAX_TRANSACTIONS_PER_VERIFY) {
        gateLog('warn', 'getTransaction cap reached', { key: agentKey.slice(0, 12) + '...', cap: MAX_TRANSACTIONS_PER_VERIFY });
        break;
      }
      if (sigInfo.err) continue;
      txCallCount++;

      const txData = await rpcCallWithFallback(rpcUrls, 'getTransaction', [
        sigInfo.signature,
        { encoding: 'jsonParsed', commitment: 'finalized', maxSupportedTransactionVersion: 0 },
      ]);
      const tx = txData.result;
      if (!tx) continue;

      const instructions = tx.transaction?.message?.instructions || [];
      const innerInstructions = tx.meta?.innerInstructions || [];
      const allInstructions = [...instructions, ...innerInstructions.flatMap((inner) => inner.instructions || [])];

      let hasMemo = false;
      let hasPayment = false;
      let hasFeePayment = !feeInfo; // vacuously satisfied when no fee is required

      for (const ix of allInstructions) {
        if (ix.program === 'spl-memo' || ix.programId === MEMO_PROGRAM) {
          const memo = typeof ix.parsed === 'string' ? ix.parsed : '';
          if (memo.includes(agentKey)) hasMemo = true;
        }

        if (ix.program === 'spl-token') {
          const parsed = ix.parsed || {};
          if (parsed.type === 'transfer' || parsed.type === 'transferChecked') {
            const info = parsed.info || {};
            // Payment must be delivered to one of the vendor's or fee wallet's USDC
            // token accounts — anything else is irrelevant.
            const isVendorDest = vendorUsdcAccounts.has(info.destination);
            const isFeeDest = feeUsdcAccounts !== null && feeUsdcAccounts.has(info.destination);
            if (!isVendorDest && !isFeeDest) continue;
            if (parsed.type === 'transferChecked' && info.mint !== usdcMint) continue;
            // Use integer base-unit comparison to avoid float precision issues at
            // the payment threshold. tokenAmount.amount (transferChecked) and
            // amount (transfer) are both integer strings in micro-USDC.
            const amountStr = info.tokenAmount?.amount ?? info.amount ?? '0';
            const amountMicro = parseInt(amountStr, 10);
            if (Number.isNaN(amountMicro)) continue;
            const minPaymentMicro = Math.round(minPayment * 1e6);
            if (isVendorDest && amountMicro >= minPaymentMicro) hasPayment = true;
            else if (isFeeDest && amountMicro >= feeAmountMicro) hasFeePayment = true;
          }
        }
      }

      if (hasMemo && hasPayment && hasFeePayment) return true;
    }
  } catch (error) {
    gateLog('error', 'Solana RPC error', { error: error.message });
  }

  return false;
}

function getCookie(req, name) {
  const cookies = req.headers.cookie || '';
  const match = cookies.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function isValidCookie(req, secret) {
  const cookie = getCookie(req, COOKIE_NAME);
  if (!cookie) return false;

  const dotIndex = cookie.indexOf('.');
  if (dotIndex === -1) return false;

  const timestamp = cookie.slice(0, dotIndex);
  const signature = cookie.slice(dotIndex + 1);
  const ts = Number.parseInt(timestamp, 10);
  if (Number.isNaN(ts) || Date.now() - ts > COOKIE_MAX_AGE * 1000) return false;

  // Cookie signature is bound to the client IP that solved the challenge.
  const clientId = clientIdForIp(getClientIp(req), secret);
  const expected = hmacSign(`cookie:${timestamp}:${clientId}`, secret);
  if (signature.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

// Detect HTTPS: Express sets req.secure when TLS is terminated at the process;
// behind a reverse proxy, trust X-Forwarded-Proto (requires app.set('trust proxy')).
function isHttps(req) {
  return req.secure || req.headers['x-forwarded-proto']?.startsWith('https');
}

function isPublicPath(pathname) {
  if (pathname === '/robots.txt') return true;
  if (pathname.startsWith('/.well-known/')) return true;
  return false;
}

// Sec-Fetch-* headers were introduced in Chrome 76 (2019) and Firefox 90 (2021).
// Fall back to UA heuristic for older browsers so they get a challenge, not a 402.
const BROWSER_UA_RE = /(Chrome|Chromium|Firefox|Safari|Edg|OPR|Opera|SamsungBrowser|UCBrowser|Mobile Safari)/i;
const BOT_UA_RE = /bot|crawl|spider|slurp|mediapartners|adsbot/i;

function isBrowser(req) {
  if (req.headers['sec-fetch-mode'] || req.headers['sec-fetch-dest']) return true;
  const ua = req.headers['user-agent'] || '';
  return Boolean(ua && !BOT_UA_RE.test(ua) && BROWSER_UA_RE.test(ua));
}

function challengePage(returnTo, nonce, powDifficulty = POW_DIFFICULTY) {
  const safePath = (returnTo.startsWith('/') && !returnTo.startsWith('//')) ? returnTo : '/';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verifying your access...</title>
  <style>body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#fafafa;color:#333}main{text-align:center;padding:2rem}.spinner{width:40px;height:40px;border:4px solid #e0e0e0;border-top-color:#333;border-radius:50%;animation:spin .8s linear infinite;margin:1rem auto}@keyframes spin{to{transform:rotate(360deg)}}</style>
</head>
<body>
  <main role="status" aria-live="polite">
    <div class="spinner" aria-hidden="true"></div>
    <p>Verifying your access&hellip;</p>
    <noscript><p><strong>JavaScript is required to verify your access. Please enable JavaScript and reload this page.</strong></p></noscript>
  </main>
  <script>
    (function() {
      if (navigator.webdriver) return;
      if (!window.crypto || !window.crypto.subtle) return;
      var c = document.createElement("canvas"); c.width = 200; c.height = 50;
      var ctx = c.getContext("2d");
      if (!ctx) return;
      ctx.font = "18px Arial"; ctx.fillStyle = "#1a1a2e"; ctx.fillText("verify", 10, 30);
      var data = c.toDataURL();
      if (!data || data.length < 100) return;
      if (typeof window.innerWidth === "undefined" || window.innerWidth === 0) return;
      var nonce = ${JSON.stringify(nonce)};
      var target = ${JSON.stringify('0'.repeat(powDifficulty))};
      var enc = new TextEncoder();
      var i = 0;
      function submit(pow) {
        var form = document.createElement("form"); form.method = "POST"; form.action = "/__challenge/verify";
        var fields = { nonce: nonce, return_to: ${JSON.stringify(safePath)}, fp: data.slice(22, 86), pow: pow };
        for (var key in fields) { var input = document.createElement("input"); input.type = "hidden"; input.name = key; input.value = fields[key]; form.appendChild(input); }
        document.body.appendChild(form); form.submit();
      }
      function mine() {
        window.crypto.subtle.digest("SHA-256", enc.encode(nonce + ":" + i)).then(function(buf) {
          var b = new Uint8Array(buf); var h = "";
          for (var j = 0; j < 4; j++) h += (b[j] < 16 ? "0" : "") + b[j].toString(16);
          if (h.slice(0, target.length) === target) return submit(String(i));
          i++; mine();
        });
      }
      mine();
    })();
  </script>
</body>
</html>`;
}

function json(res, status, body) {
  res.status(status).set('Content-Type', 'application/json').send(JSON.stringify(body, null, 2));
}

/**
 * Build an x402-standard PaymentRequirements object for the Solana exact scheme.
 * Spec: https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_svm.md
 *
 * @param {object} opts
 * @param {string} opts.walletAddress  - merchant wallet (payTo)
 * @param {string} opts.mint           - USDC mint address
 * @param {number} opts.minPayment     - human-readable amount (e.g. 0.01)
 * @param {boolean} opts.debug         - true → devnet chain ID
 * @param {string} [opts.agentKey]     - if present, included as extra.memo so
 *                                       x402 clients know which key to reference
 * @param {string} [opts.resource]     - URL of the gated resource
 * @returns {object} PaymentRequirements
 */
function buildX402PaymentRequirements({ walletAddress, mint, minPayment, debug, agentKey, resource }) {
  const chainId = debug ? SOLANA_CHAIN_ID_DEVNET : SOLANA_CHAIN_ID_MAINNET;
  const baseUnits = String(Math.round(minPayment * Math.pow(10, USDC_DECIMALS)));
  const req = {
    scheme: 'exact',
    network: chainId,
    amount: baseUnits,
    asset: mint,
    payTo: walletAddress,
    maxTimeoutSeconds: 300,
    extra: {
      name: 'USDC',
      decimals: USDC_DECIMALS,
      ...(agentKey ? { memo: agentKey } : {}),
    },
  };
  if (resource) req.resource = resource;
  return req;
}

/**
 * Builds the custom `payment` object (NOT part of the x402 spec — that's
 * buildX402PaymentRequirements above, which stays vendor-leg-only). When feeInfo
 * is set (hosted-platform mode with an on-chain fee configured), adds a
 * platform_fee field describing the second required transfer. Deliberately not
 * added as a second x402 accepts[] entry — that would read to a spec-compliant
 * client as an alternative payment method, not an additional requirement.
 */
function buildPaymentField({ network, minPayment, walletAddress, memo, feeInfo, instructions }) {
  const payment = { chain: 'solana', network, token: 'USDC', amount: String(minPayment), wallet_address: walletAddress, memo };
  if (feeInfo) {
    const feeAmountMicro = Math.round(Math.round(minPayment * 1e6) * feeInfo.ratePct / 100);
    payment.platform_fee = {
      wallet_address: feeInfo.wallet,
      amount: String(feeAmountMicro / 1e6),
      token: 'USDC',
      rate_pct: feeInfo.ratePct,
      note: 'Must be a second USDC transfer inside the SAME Solana transaction as the payment above, or access will be denied.',
    };
  }
  if (instructions) payment.instructions = instructions;
  return payment;
}

/**
 * Like json() but for 402 responses: adds x402Version, accepts[], and the
 * X-PAYMENT-REQUIRED header (base64-encoded PaymentRequirements per x402 spec).
 */
function paymentRequiredJson(res, body, x402Opts) {
  const payReq = buildX402PaymentRequirements(x402Opts);
  const enriched = {
    x402Version: X402_VERSION,
    accepts: [payReq],
    ...body,
  };
  const encoded = Buffer.from(JSON.stringify(payReq)).toString('base64');
  res
    .status(402)
    .set('Content-Type', 'application/json')
    .set('X-PAYMENT-REQUIRED', encoded)
    .send(JSON.stringify(enriched, null, 2));
}

function agentPaymentsGate(config = {}) {
  const {
    challengeSecret,
    homeWalletAddress,
    solanaRpcUrl,
    usdcMint,
    minPayment = MIN_PAYMENT,
    powDifficulty = POW_DIFFICULTY,
    debug = process.env.DEBUG !== 'false',
    // When true (default), verified search crawlers (Googlebot, Bingbot, etc.)
    // are allowed through without a challenge or payment. Verification uses
    // reverse+forward DNS so it adds latency only on the first request per IP.
    verifyCrawlers = true,
    // Optional persistent grant store. Once a key is added it is never
    // re-scanned on-chain, making paid access durable across wallet history
    // window limits. See sdk/node/grant-store.js for FileGrantStore.
    // Interface: { has(key): boolean, add(key): void } (sync or async).
    grantStore = null,
    // Optional pluggable rate limiters (drop-in for the built-in in-memory ones).
    // See sdk/node/redis-store.js for a Redis-backed implementation suitable
    // for multi-process deployments.  Interface: { check(ip): bool|Promise<bool> }
    rateLimiter: customRateLimiter = null,
    agentKeyRateLimiter: customAgentKeyRateLimiter = null,
    // Optional pluggable payment cache.  Interface: { get(key), set(key,value,ttlMs) }
    paymentCache: customPaymentCache = null,
    // Rate limiter for challenge page issuance (browser path). Separate from
    // the verify-endpoint limiter so a burst of bot traffic can't exhaust
    // nonces for legitimate browsers. Default: 30 req/min/IP.
    challengeRateLimiter: customChallengeRateLimiter = null,
    // When true (default in production), requests that do not arrive over HTTPS
    // are rejected with 400. Disable in local dev by setting debug: true or
    // requireHttps: false. Behind a reverse proxy, Express must have
    // app.set('trust proxy', 1) set for req.secure to be populated correctly.
    requireHttps: requireHttpsOpt,
    // -----------------------------------------------------------------------
    // Hosted key-issuance mode (business model moat):
    //   apiKey:       Platform API key from api.agentpayments.dev (ap_live_...)
    //   platformApiUrl: Override for self-hosted platform (default: PLATFORM_API_URL)
    //
    // When apiKey is set, agent keys are issued via the platform (metered, billed)
    // and carry the agp_ prefix. The SDK verifies them locally using the
    // verificationSecret fetched from the platform at first issuance.
    // challengeSecret is still required for browser challenge/cookie signing.
    // -----------------------------------------------------------------------
    apiKey = null,
    platformApiUrl = PLATFORM_API_URL,
  } = config;

  // Platform client (hosted issuance mode). Initialized once; verificationSecret
  // is fetched lazily on first key issuance and cached for the process lifetime.
  const platformClient = apiKey ? new PlatformClient(apiKey, platformApiUrl) : null;
  if (platformClient) {
    gateLog('info', 'Hosted key-issuance mode enabled. Agent keys will be issued via platform.', { platformApiUrl });
  }

  const secret = challengeSecret || 'default-secret-change-me';
  if (secret === 'default-secret-change-me') {
    if (debug) {
      gateLog('warn', 'Using default CHALLENGE_SECRET. Set a strong secret before deploying to production.');
    } else {
      throw new Error('[gate] CHALLENGE_SECRET is set to the insecure default. Set a strong, unique secret for production.');
    }
  }
  const walletAddress = homeWalletAddress || '';
  if (walletAddress && !BASE58_RE.test(walletAddress)) {
    throw new Error(`[gate] HOME_WALLET_ADDRESS "${walletAddress}" is not a valid Solana public key (expected 32-44 base58 characters).`);
  }
  // Normalize rpcUrl to an array so verifyPaymentOnChain can fall back across endpoints.
  const rpcUrls = (() => {
    const raw = solanaRpcUrl || (debug ? RPC_DEVNET : RPC_MAINNET);
    return Array.isArray(raw) ? raw : [raw];
  })();
  const requireHttps = requireHttpsOpt ?? !debug; // default: enforce HTTPS in production
  const mint = usdcMint || (debug ? USDC_MINT_DEVNET : USDC_MINT_MAINNET);
  const network = debug ? 'devnet' : 'mainnet-beta';
  const paymentCache = customPaymentCache || new PaymentCache();
  const rateLimiter = customRateLimiter || new RateLimiter();                                          // challenge verify: 20/min
  const agentKeyRateLimiter = customAgentKeyRateLimiter || new RateLimiter(RATE_LIMIT_WINDOW, AGENT_KEY_RATE_LIMIT_MAX); // agent key verify: 10/min
  const challengeIssueRateLimiter = customChallengeRateLimiter || new RateLimiter(RATE_LIMIT_WINDOW, CHALLENGE_ISSUE_RATE_LIMIT_MAX); // challenge issuance: 30/min
  const consumedNonces = new ConsumedNonces();
  setInterval(() => { rateLimiter.cleanup?.(); agentKeyRateLimiter.cleanup?.(); challengeIssueRateLimiter.cleanup?.(); consumedNonces.cleanup(); }, 60000).unref();

  return async function agentPaymentsGateMiddleware(req, res, next) {
    const pathname = req.path;

    if (isPublicPath(pathname)) return next();

    // Reject plaintext HTTP in production. Cookies and agent keys transmitted
    // over HTTP are visible to network observers. Behind a reverse proxy, set
    // app.set('trust proxy', 1) so req.secure reflects the upstream protocol.
    if (requireHttps && !isHttps(req)) {
      return json(res, 400, { error: 'https_required', message: 'This service requires a secure HTTPS connection.' });
    }

    // Verified search crawlers bypass the gate entirely (no challenge, no payment).
    if (verifyCrawlers) {
      const clientIpForCrawler = getClientIp(req);
      const ua = req.headers['user-agent'] || '';
      if (await isVerifiedCrawler(clientIpForCrawler, ua)) return next();
    }

    if (pathname === '/__challenge/verify' && req.method === 'POST') {
      const clientIp = getClientIp(req);
      if (!rateLimiter.check(clientIp)) {
        return json(res, 429, { error: 'rate_limited', message: 'Too many verification attempts. Please wait and try again.' });
      }
      const nonce = (req.body?.nonce || req.query?.nonce || '').slice(0, MAX_NONCE_LENGTH);
      const returnTo = (req.body?.return_to || req.query?.return_to || '/').slice(0, MAX_RETURN_TO_LENGTH);
      const fp = (req.body?.fp || req.query?.fp || '').slice(0, MAX_FP_LENGTH);
      const pow = (req.body?.pow || req.query?.pow || '').slice(0, MAX_POW_LENGTH);

      // Nonce format: <ts>.<rand>.<sig>
      const [nonceTs, nonceRand, nonceSig] = nonce.split('.');
      if (!nonceTs || !nonceRand || !nonceSig || !isPlausibleFingerprint(fp)) {
        return json(res, 403, { error: 'forbidden', message: 'Challenge verification failed.' });
      }

      const ts = Number.parseInt(nonceTs, 10);
      if (Number.isNaN(ts) || Date.now() - ts > NONCE_TTL_MS) {
        return json(res, 403, { error: 'forbidden', message: 'Challenge expired. Reload the page.' });
      }

      // Nonce is bound to the IP it was issued to.
      const clientId = clientIdForIp(clientIp, secret);
      const expectedSig = hmacSign(`nonce:${nonceTs}:${nonceRand}:${clientId}`, secret);
      if (nonceSig.length !== expectedSig.length || !crypto.timingSafeEqual(Buffer.from(nonceSig), Buffer.from(expectedSig))) {
        return json(res, 403, { error: 'forbidden', message: 'Invalid challenge.' });
      }

      if (!verifyPow(nonce, pow, powDifficulty)) {
        return json(res, 403, { error: 'forbidden', message: 'Challenge verification failed.' });
      }

      // Single use: a solved nonce cannot mint a second cookie.
      if (!consumedNonces.consume(nonceSig)) {
        return json(res, 403, { error: 'forbidden', message: 'Challenge expired. Reload the page.' });
      }

      const now = Date.now().toString();
      const cookieSig = hmacSign(`cookie:${now}:${clientId}`, secret);
      // Reject protocol-relative URLs (//attacker.com starts with '/' but is external).
      const safePath = (returnTo.startsWith('/') && !returnTo.startsWith('//')) ? returnTo : '/';

      res.cookie(COOKIE_NAME, `${now}.${cookieSig}`, {
        maxAge: COOKIE_MAX_AGE * 1000,
        path: '/',
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
      });
      return res.redirect(302, safePath);
    }

    if (!isBrowser(req)) {
      const agentKey = req.get('X-Agent-Key');

      // Resolve the on-chain platform fee requirement once (hosted-platform mode
      // only — always null for self-hosted vendors with no platformClient).
      let feeInfo = null;
      if (platformClient) {
        try {
          feeInfo = await platformClient.getPlatformFeeInfo();
        } catch (err) {
          gateLog('warn', 'Failed to fetch platform fee info, proceeding without fee enforcement', { error: err.message });
        }
      }

      if (!agentKey) {
        // Hosted mode: issue a metered platform key (agp_...).
        // Local mode: generate a self-signed key (ag_...).
        let newKey;
        if (platformClient) {
          try {
            const issued = await platformClient.issueKey();
            newKey = issued.key;
          } catch (err) {
            gateLog('warn', 'Platform key issuance failed, falling back to local key', { error: err.message });
            newKey = generateAgentKey(secret);
          }
        } else {
          newKey = generateAgentKey(secret);
        }
        const noKeyInstructions = feeInfo
          ? `Send ${minPayment} USDC on Solana ${debug ? 'devnet' : 'mainnet'} to ${walletAddress} with memo "${newKey}", AND in the SAME transaction send the platform fee (see platform_fee below) to ${feeInfo.wallet}. Then include the header X-Agent-Key: ${newKey} on all subsequent requests.`
          : `Send ${minPayment} USDC on Solana ${debug ? 'devnet' : 'mainnet'} to ${walletAddress} with memo "${newKey}". Then include the header X-Agent-Key: ${newKey} on all subsequent requests.`;
        return paymentRequiredJson(res, {
          error: 'payment_required',
          message: 'Access requires a paid API key. A key has been generated for you below. Send a USDC payment on Solana with this key as the memo to activate it, then retry your request with the X-Agent-Key header.',
          your_key: newKey,
          payment: buildPaymentField({ network, minPayment, walletAddress, memo: newKey, feeInfo, instructions: noKeyInstructions }),
        }, { walletAddress, mint, minPayment, debug, agentKey: newKey, resource: req.originalUrl || req.path });
      }

      // Validate the key. Platform-issued keys (agp_) are verified with the
      // verificationSecret fetched from the platform; local keys (ag_) with challengeSecret.
      const isHostedKey = agentKey.startsWith(HOSTED_KEY_PREFIX);
      if (isHostedKey) {
        if (!platformClient) {
          return json(res, 403, {
            error: 'forbidden',
            message: 'Platform-issued keys (agp_) require apiKey to be configured.',
          });
        }
        let verSec;
        try {
          verSec = await platformClient.getVerificationSecret();
        } catch (err) {
          gateLog('error', 'Failed to fetch verificationSecret from platform', { error: err.message });
          return json(res, 503, { error: 'service_unavailable', message: 'Key verification temporarily unavailable.' });
        }
        if (!isValidHostedKey(agentKey, verSec)) {
          return json(res, 403, { error: 'forbidden', message: 'Invalid API key.' });
        }
      } else if (!isValidAgentKey(agentKey, secret)) {
        return json(res, 403, {
          error: 'forbidden',
          message: 'Invalid API key. Keys must be issued by this server.',
          details: 'GET /.well-known/agent-access.json for access instructions.',
        });
      }

      // Rate-limit the verification path separately from the challenge endpoint.
      if (!agentKeyRateLimiter.check(getClientIp(req))) {
        return json(res, 429, { error: 'rate_limited', message: 'Too many payment verification requests. Please wait and try again.' });
      }

      if (!walletAddress) {
        return json(res, 500, { error: 'server_error', message: 'Payment verification unavailable.' });
      }

      // Grant store: durable check that survives the 100-tx wallet history window.
      if (grantStore && await grantStore.has(agentKey)) return next();

      const cached = paymentCache.get(agentKey);
      if (cached === true) return next();
      if (cached === false) {
        // Negative result cached — skip the RPC scan until the TTL expires.
        return paymentRequiredJson(res, {
          error: 'payment_required',
          message: 'Key is valid but payment has not been verified on-chain yet. Please send the USDC payment and allow a few moments for confirmation.',
          your_key: agentKey,
          payment: buildPaymentField({ network, minPayment, walletAddress, memo: agentKey, feeInfo }),
        }, { walletAddress, mint, minPayment, debug, agentKey, resource: req.originalUrl || req.path });
      }
      const paid = await verifyPaymentOnChain(agentKey, walletAddress, rpcUrls, mint, minPayment, feeInfo);
      paymentCache.set(agentKey, paid, paid ? PAYMENT_CACHE_TTL : NEGATIVE_CACHE_TTL_MS);
      if (paid && grantStore) await grantStore.add(agentKey);
      if (!paid) {
        return paymentRequiredJson(res, {
          error: 'payment_required',
          message: 'Key is valid but payment has not been verified on-chain yet. Please send the USDC payment and allow a few moments for confirmation.',
          your_key: agentKey,
          payment: buildPaymentField({ network, minPayment, walletAddress, memo: agentKey, feeInfo }),
        }, { walletAddress, mint, minPayment, debug, agentKey, resource: req.originalUrl || req.path });
      }

      return next();
    }

    if (isValidCookie(req, secret)) return next();

    // Rate-limit challenge page issuance. Without this, an attacker can request
    // unlimited nonces and mine PoW offline at native speed.
    if (!challengeIssueRateLimiter.check(getClientIp(req))) {
      return json(res, 429, { error: 'rate_limited', message: 'Too many requests. Please try again later.' });
    }

    const nonceTs = Date.now().toString();
    const nonceRand = crypto.randomBytes(8).toString('hex');
    const nonceClientId = clientIdForIp(getClientIp(req), secret);
    const nonceSig = hmacSign(`nonce:${nonceTs}:${nonceRand}:${nonceClientId}`, secret);
    return res
      .status(200)
      .set('Content-Type', 'text/html')
      .set('Cache-Control', 'no-store')
      .set('X-Frame-Options', 'DENY')
      .set('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'")
      .send(challengePage(req.originalUrl || req.url, `${nonceTs}.${nonceRand}.${nonceSig}`, powDifficulty));
  };
}

module.exports = { agentPaymentsGate, isValidHostedKey, PlatformClient, verifyPaymentOnChain };
