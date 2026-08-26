// Values sourced from sdk/constants.json (canonical). Inlined here because JSON
// import syntax differs across Deno (Netlify), Cloudflare Workers, and Vercel Edge.
const COOKIE_NAME = '__agp_verified';
const COOKIE_MAX_AGE = 86400;
const KEY_PREFIX = 'ag_';
const USDC_MINT_DEVNET = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const USDC_MINT_MAINNET = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const RPC_DEVNET = 'https://api.devnet.solana.com';
const RPC_MAINNET = 'https://api.mainnet-beta.solana.com';
const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const MIN_PAYMENT = 0.01;
const POW_DIFFICULTY = 4;
const MAX_POW_LENGTH = 20;
const NONCE_TTL_MS = 300000;
const MAX_KEY_LENGTH = 64;
const MAX_NONCE_LENGTH = 128;
const MAX_RETURN_TO_LENGTH = 2048;
const MAX_FP_LENGTH = 128;
const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const PAYMENT_CACHE_TTL = 10 * 60 * 1000; // 10 minutes
const PAYMENT_CACHE_MAX = 1000;
const NEGATIVE_CACHE_TTL_MS = 30000; // 30 seconds
const MAX_TRANSACTIONS_PER_VERIFY = 20;
const AGENT_KEY_RATE_LIMIT_MAX = 10;
const CHALLENGE_ISSUE_RATE_LIMIT_MAX = 30;
const USDC_DECIMALS = 6;
const X402_VERSION = 1;
const SOLANA_CHAIN_ID_MAINNET = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
const SOLANA_CHAIN_ID_DEVNET = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
const PLATFORM_API_URL = 'https://api.agentpayments.dev';
const HOSTED_KEY_PREFIX = 'agp_';

// ---------------------------------------------------------------------------
// Pluggable async store interface
//
// Any object implementing all four methods can be passed as the `store`
// option to createEdgeGate, or returned by the `getStore` factory.
//
// interface Store {
//   consumeNonce(sig: string, ttlMs: number): Promise<boolean>     // true = fresh
//   checkRateLimit(key: string, windowMs: number, max: number): Promise<boolean>
//   getCachedPayment(agentKey: string): Promise<boolean | undefined>
//   setCachedPayment(agentKey: string, value: boolean, ttlMs: number): Promise<void>
// }
// ---------------------------------------------------------------------------

export class InMemoryStore {
  constructor() {
    this._nonces   = new Map(); // sig -> expiryMs
    this._rateLimit = new Map(); // key -> {start, count}
    this._payments  = new Map(); // agentKey -> {value, ts}
  }

  async consumeNonce(sig, ttlMs) {
    const now = Date.now();
    const exp = this._nonces.get(sig);
    if (exp !== undefined && exp > now) return false; // already used
    if (this._nonces.size >= 10000) this._nonces.delete(this._nonces.keys().next().value);
    this._nonces.set(sig, now + ttlMs);
    return true;
  }

  async checkRateLimit(key, windowMs, max) {
    const now = Date.now();
    const entry = this._rateLimit.get(key);
    if (!entry || now - entry.start > windowMs) {
      this._rateLimit.set(key, { start: now, count: 1 });
      return true;
    }
    entry.count++;
    return entry.count <= max;
  }

  async getCachedPayment(agentKey) {
    const entry = this._payments.get(agentKey);
    if (!entry) return undefined;
    if (Date.now() - entry.ts > entry.ttl) { this._payments.delete(agentKey); return undefined; }
    return entry.value;
  }

  async setCachedPayment(agentKey, value, ttlMs) {
    if (this._payments.size >= PAYMENT_CACHE_MAX) this._payments.delete(this._payments.keys().next().value);
    this._payments.set(agentKey, { value, ts: Date.now(), ttl: ttlMs });
  }
}

function gateLog(level, message, data = {}) {
  const entry = JSON.stringify({ ts: new Date().toISOString(), level, component: 'agentpayments', message, ...data });
  if (level === 'error') console.error(entry);
  else if (level === 'warn') console.warn(entry);
  else console.log(entry);
}

const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 20;

// ---------------------------------------------------------------------------
// Verified crawler allowlist (DNS-over-HTTPS for edge environments)
// ---------------------------------------------------------------------------
const CRAWLER_PATTERNS = [
  { pattern: /googlebot/i,              suffix: '.googlebot.com' },
  { pattern: /google-inspectiontool/i,  suffix: '.google.com' },
  { pattern: /bingbot/i,                suffix: '.search.msn.com' },
  { pattern: /slurp/i,                  suffix: '.crawl.yahoo.net' },
  { pattern: /duckduckbot/i,            suffix: '.duckduckgo.com' },
  { pattern: /baiduspider/i,            suffix: '.crawl.baidu.com' },
  { pattern: /yandexbot/i,              suffix: '.yandex.com' },
  { pattern: /applebot/i,               suffix: '.applebot.apple.com' },
];
const CRAWLER_CACHE_TTL = 60 * 60 * 1000; // 1 hour, per-isolate
const _crawlerCache = new Map(); // ip -> { verified: boolean, exp: number }

async function isVerifiedCrawler(ip, userAgent) {
  if (!userAgent || !ip || ip === 'unknown') return false;
  const match = CRAWLER_PATTERNS.find((c) => c.pattern.test(userAgent));
  if (!match) return false;

  const cached = _crawlerCache.get(ip);
  if (cached && cached.exp > Date.now()) return cached.verified;

  let verified = false;
  try {
    // Reverse lookup: convert IP to PTR name (IPv4 only for now).
    const reversed = ip.split('.').reverse().join('.');
    const ptrResp = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${reversed}.in-addr.arpa&type=PTR`,
      { headers: { Accept: 'application/dns-json' } },
    );
    const ptrData = await ptrResp.json();
    const hostname = (ptrData.Answer?.[0]?.data || '').replace(/\.$/, '');
    if (hostname && hostname.endsWith(match.suffix)) {
      // Forward verify: hostname must resolve back to the original IP.
      const aResp = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`,
        { headers: { Accept: 'application/dns-json' } },
      );
      const aData = await aResp.json();
      verified = (aData.Answer || []).some((r) => r.data === ip);
    }
  } catch { /* DNS failure = not verified */ }

  _crawlerCache.set(ip, { verified, exp: Date.now() + CRAWLER_CACHE_TTL });
  return verified;
}

// Cache derived CryptoKey objects by secret so importKey isn't called on every
// hmacSign invocation. Edge isolates reuse module-level state between requests.
const _hmacKeyCache = new Map();

async function _getHmacKey(secret) {
  if (_hmacKeyCache.has(secret)) return _hmacKeyCache.get(secret);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  _hmacKeyCache.set(secret, key);
  return key;
}

export async function hmacSign(data, secret) {
  const key = await _getHmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Separate fixed key for timing-safe string comparison (never changes).
let _tscKey = null;
async function _getTimingSafeCmpKey() {
  if (_tscKey) return _tscKey;
  _tscKey = await crypto.subtle.importKey('raw', new TextEncoder().encode('timing-safe-cmp'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return _tscKey;
}

async function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  const enc = new TextEncoder();
  const key = await _getTimingSafeCmpKey();
  const [macA, macB] = await Promise.all([
    crypto.subtle.sign('HMAC', key, enc.encode(a)),
    crypto.subtle.sign('HMAC', key, enc.encode(b)),
  ]);
  const viewA = new Uint8Array(macA);
  const viewB = new Uint8Array(macB);
  let result = 0;
  for (let i = 0; i < viewA.length; i++) result |= viewA[i] ^ viewB[i];
  return result === 0;
}

async function sha256Hex(data) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Short HMAC of the client IP. Used to bind nonces and cookies to the client
// that solved the challenge, so a captured cookie is useless from another IP.
export async function clientIdForIp(ip, secret) {
  return (await hmacSign(`client:${ip}`, secret)).slice(0, 16);
}

// Canvas fingerprints are a base64 slice of a data URL. Reject anything that
// isn't base64 or is degenerate (e.g. a single repeated character).
const FP_RE = /^[A-Za-z0-9+/]{10,}$/;
function isPlausibleFingerprint(fp) {
  return FP_RE.test(fp) && new Set(fp).size >= 4;
}

// Proof-of-work: sha256(`${nonce}:${pow}`) must start with `difficulty` zero
// hex chars. Verification is a single hash; solving costs ~16^difficulty tries.
async function verifyPow(nonce, pow, difficulty) {
  if (!/^\d{1,20}$/.test(pow)) return false;
  return (await sha256Hex(`${nonce}:${pow}`)).startsWith('0'.repeat(difficulty));
}

export async function generateAgentKey(secret) {
  const random = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  const sig = await hmacSign(random, secret);
  return `${KEY_PREFIX}${random}_${sig.slice(0, 16)}`;
}

export async function isValidAgentKey(key, secret) {
  if (!key || key.length > MAX_KEY_LENGTH || !key.startsWith(KEY_PREFIX)) return false;
  const rest = key.slice(KEY_PREFIX.length);
  const underscoreIndex = rest.indexOf('_');
  if (underscoreIndex === -1) return false;
  const random = rest.slice(0, underscoreIndex);
  const sig = rest.slice(underscoreIndex + 1);
  const expected = await hmacSign(random, secret);
  return timingSafeEqual(sig, expected.slice(0, 16));
}

/**
 * Verify a platform-issued agent key (agp_ prefix) using the vendor's verificationSecret.
 * Key format: agp_${vendorId8}_${nonce16}_${sig16}
 * sig = hmac('agp:vendorId:nonce', verificationSecret).slice(0,16)
 */
async function isValidHostedKey(key, verificationSecret) {
  if (!key || !key.startsWith(HOSTED_KEY_PREFIX)) return false;
  const parts = key.split('_');
  if (parts.length !== 4) return false;
  const [, vendorId, nonce, sig] = parts;
  if (!vendorId || !nonce || !sig || sig.length !== 16) return false;
  const expected = (await hmacSign(`agp:${vendorId}:${nonce}`, verificationSecret)).slice(0, 16);
  return timingSafeEqual(sig, expected);
}

/**
 * Platform client for the Edge runtime. Cached by apiKey at module level so
 * the verificationSecret is fetched once per isolate/worker restart, not per request.
 */
const _edgePlatformClients = new Map();

class EdgePlatformClient {
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
        this._accountFetch = null;
        throw err;
      });
    return this._accountFetch;
  }

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

/** Get or create a cached EdgePlatformClient for the given apiKey. */
function getEdgePlatformClient(apiKey, platformUrl) {
  const cacheKey = `${apiKey}:${platformUrl || PLATFORM_API_URL}`;
  if (!_edgePlatformClients.has(cacheKey)) {
    _edgePlatformClients.set(cacheKey, new EdgePlatformClient(apiKey, platformUrl));
  }
  return _edgePlatformClients.get(cacheKey);
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
      if (err.message?.includes('failed:')) throw err; // re-throw permanent 4xx
      lastError = err;
    }
  }
  throw lastError;
}

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
export async function verifyPaymentOnChain(agentKey, walletAddress, rpcUrls, usdcMint, minPayment = MIN_PAYMENT, feeInfo = null) {
  try {
    // commitment: 'finalized' — confirmed blocks can be rolled back (rare but possible).
    const ataData = await rpcCallWithFallback(rpcUrls, 'getTokenAccountsByOwner', [walletAddress, { mint: usdcMint }, { encoding: 'jsonParsed', commitment: 'finalized' }]);
    const tokenAccounts = (ataData.result?.value || []).map((entry) => entry.pubkey);
    // Only transfers landing in one of the vendor's USDC token accounts count as
    // payment. Token accounts are mint-bound, so membership also guarantees the
    // token is USDC for plain `transfer` instructions (which carry no mint field).
    const vendorUsdcAccounts = new Set(tokenAccounts);
    if (vendorUsdcAccounts.size === 0) return false; // vendor has no USDC account yet — no payment possible

    let feeUsdcAccounts = null;
    let feeAmountMicro = 0;
    if (feeInfo) {
      const feeAtaData = await rpcCallWithFallback(rpcUrls, 'getTokenAccountsByOwner', [feeInfo.wallet, { mint: usdcMint }, { encoding: 'jsonParsed', commitment: 'finalized' }]);
      feeUsdcAccounts = new Set((feeAtaData.result?.value || []).map((entry) => entry.pubkey));
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

      const txData = await rpcCallWithFallback(rpcUrls, 'getTransaction', [sigInfo.signature, { encoding: 'jsonParsed', commitment: 'finalized', maxSupportedTransactionVersion: 0 }]);
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
            // Integer base-unit comparison — avoids float precision issues at threshold.
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

export function getCookie(request, name) {
  const cookies = request.headers.get('cookie') || '';
  const match = cookies.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export async function isValidCookie(request, secret, clientIp) {
  const cookie = getCookie(request, COOKIE_NAME);
  if (!cookie) return false;
  const dotIndex = cookie.indexOf('.');
  if (dotIndex === -1) return false;
  const timestamp = cookie.slice(0, dotIndex);
  const signature = cookie.slice(dotIndex + 1);
  const ts = Number.parseInt(timestamp, 10);
  if (Number.isNaN(ts) || Date.now() - ts > COOKIE_MAX_AGE * 1000) return false;
  // Cookie signature is bound to the client IP that solved the challenge.
  const clientId = await clientIdForIp(clientIp, secret);
  const expected = await hmacSign(`cookie:${timestamp}:${clientId}`, secret);
  return timingSafeEqual(signature, expected);
}

export function isPublicPath(pathname, allowlist = []) {
  if (pathname === '/robots.txt') return true;
  if (pathname.startsWith('/.well-known/')) return true;
  if (allowlist.includes(pathname)) return true;
  return false;
}

const BROWSER_UA_RE = /(Chrome|Chromium|Firefox|Safari|Edg|OPR|Opera|SamsungBrowser|UCBrowser|Mobile Safari)/i;
const BOT_UA_RE = /bot|crawl|spider|slurp|mediapartners|adsbot/i;

export function isBrowser(request) {
  if (request.headers.get('sec-fetch-mode') || request.headers.get('sec-fetch-dest')) return true;
  const ua = request.headers.get('user-agent') || '';
  return Boolean(ua && !BOT_UA_RE.test(ua) && BROWSER_UA_RE.test(ua));
}

export function jsonResponse(body, status) {
  return new Response(JSON.stringify(body, null, 2), { status, headers: { 'Content-Type': 'application/json' } });
}

/**
 * Build x402-standard PaymentRequirements for the Solana exact scheme.
 * Spec: https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_svm.md
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
 * Like jsonResponse(body, 402) but adds x402Version, accepts[], and
 * the X-PAYMENT-REQUIRED header (base64-encoded PaymentRequirements).
 */
function paymentRequiredResponse(body, x402Opts) {
  const payReq = buildX402PaymentRequirements(x402Opts);
  const enriched = { x402Version: X402_VERSION, accepts: [payReq], ...body };
  const encoded = btoa(JSON.stringify(payReq));
  return new Response(JSON.stringify(enriched, null, 2), {
    status: 402,
    headers: {
      'Content-Type': 'application/json',
      'X-PAYMENT-REQUIRED': encoded,
    },
  });
}

export function challengePage(returnTo, nonce, powDifficulty = POW_DIFFICULTY) {
  const safePath = (returnTo.startsWith('/') && !returnTo.startsWith('//')) ? returnTo : '/';
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Verifying your access...</title><style>body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#fafafa;color:#333}main{text-align:center;padding:2rem}.spinner{width:40px;height:40px;border:4px solid #e0e0e0;border-top-color:#333;border-radius:50%;animation:spin .8s linear infinite;margin:1rem auto}@keyframes spin{to{transform:rotate(360deg)}}</style></head><body><main role="status" aria-live="polite"><div class="spinner" aria-hidden="true"></div><p>Verifying your access&hellip;</p><noscript><p><strong>JavaScript is required to verify your access. Please enable JavaScript and reload this page.</strong></p></noscript></main><script>(function(){if(navigator.webdriver)return;if(!window.crypto||!window.crypto.subtle)return;var c=document.createElement("canvas");c.width=200;c.height=50;var ctx=c.getContext("2d");if(!ctx)return;ctx.font="18px Arial";ctx.fillStyle="#1a1a2e";ctx.fillText("verify",10,30);var data=c.toDataURL();if(!data||data.length<100)return;if(typeof window.innerWidth==="undefined"||window.innerWidth===0)return;var nonce=${JSON.stringify(nonce)};var target=${JSON.stringify('0'.repeat(powDifficulty))};var enc=new TextEncoder();var i=0;function submit(pow){var form=document.createElement("form");form.method="POST";form.action="/__challenge/verify";var fields={nonce:nonce,return_to:${JSON.stringify(safePath)},fp:data.slice(22,86),pow:pow};for(var key in fields){var input=document.createElement("input");input.type="hidden";input.name=key;input.value=fields[key];form.appendChild(input);}document.body.appendChild(form);form.submit();}function mine(){window.crypto.subtle.digest("SHA-256",enc.encode(nonce+":"+i)).then(function(buf){var b=new Uint8Array(buf);var h="";for(var j=0;j<4;j++)h+=(b[j]<16?"0":"")+b[j].toString(16);if(h.slice(0,target.length)===target)return submit(String(i));i++;mine();});}mine();})();</script></body></html>`;
  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html',
      'Cache-Control': 'no-store',
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'",
    },
  });
}

export function createEdgeGate(options = {}) {
  const {
    fetchUpstream,
    getClientIp = ({ request }) =>
      request.headers.get('cf-connecting-ip')
      || request.headers.get('x-real-ip')
      || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
      || 'unknown',
    publicPathAllowlist = [],
    minPayment = MIN_PAYMENT,
    powDifficulty = POW_DIFFICULTY,
    envResolver,
    // Pluggable state backend. Provide one of:
    //   store    — a static Store instance (shared across all requests)
    //   getStore — factory ({ request, env, context }) => Store (use for KV,
    //              where env holds the binding resolved per-request)
    store: staticStore,
    getStore,
    // When true (default), verified search crawlers bypass the gate entirely.
    verifyCrawlers = true,
    // When true (default in production), requests not over HTTPS get a 400.
    // Edge runtimes are always HTTPS in practice, but the check guards against
    // misconfigured local-dev tunnels forwarding HTTP traffic.
    requireHttps,
  } = options;

  if (typeof fetchUpstream !== 'function') {
    throw new Error('createEdgeGate requires fetchUpstream(request, env, context)');
  }

  // Default in-memory store shared across requests within this isolate.
  const _defaultStore = new InMemoryStore();

  return async function edgeGate(request, env = {}, context = {}) {
    const store = getStore ? getStore({ request, env, context }) : (staticStore || _defaultStore);
    const effectiveEnv = envResolver ? await envResolver({ request, env, context }) : env;
    const url = new URL(request.url);
    const secret = effectiveEnv.CHALLENGE_SECRET || 'default-secret-change-me';
    const walletAddress = effectiveEnv.HOME_WALLET_ADDRESS || '';
    const debug = effectiveEnv.DEBUG !== 'false';
    if (secret === 'default-secret-change-me') {
      if (debug) {
        gateLog('warn', 'Using default CHALLENGE_SECRET. Set a strong secret before deploying to production.');
      } else {
        return jsonResponse({ error: 'server_error', message: 'Server misconfiguration: insecure default secret.' }, 500);
      }
    }
    if (walletAddress && !BASE58_RE.test(walletAddress)) {
      gateLog('error', 'Invalid HOME_WALLET_ADDRESS', { walletAddress });
      return jsonResponse({ error: 'server_error', message: 'Server misconfiguration: invalid wallet address.' }, 500);
    }
    const rawRpc = effectiveEnv.SOLANA_RPC_URL || (debug ? RPC_DEVNET : RPC_MAINNET);
    const rpcUrls = Array.isArray(rawRpc) ? rawRpc : [rawRpc];
    const usdcMint = effectiveEnv.USDC_MINT || (debug ? USDC_MINT_DEVNET : USDC_MINT_MAINNET);
    const httpsRequired = requireHttps ?? !debug;
    // Hosted issuance mode: platform client is cached by apiKey across requests.
    const platformApiKey = effectiveEnv.AGENTPAYMENTS_API_KEY || null;
    const platformApiUrlEnv = effectiveEnv.AGENTPAYMENTS_PLATFORM_URL || PLATFORM_API_URL;
    const platformClient = platformApiKey ? getEdgePlatformClient(platformApiKey, platformApiUrlEnv) : null;

    if (isPublicPath(url.pathname, publicPathAllowlist)) {
      return fetchUpstream(request, effectiveEnv, context);
    }

    // Reject plaintext HTTP in production.
    if (httpsRequired && url.protocol !== 'https:') {
      return jsonResponse({ error: 'https_required', message: 'This service requires a secure HTTPS connection.' }, 400);
    }

    // Verified search crawlers bypass the gate (no challenge, no payment).
    if (verifyCrawlers) {
      const crawlerIp = getClientIp({ request, env: effectiveEnv, context });
      const ua = request.headers.get('user-agent') || '';
      if (await isVerifiedCrawler(crawlerIp, ua)) return fetchUpstream(request, effectiveEnv, context);
    }

    if (url.pathname === '/__challenge/verify' && request.method === 'POST') {
      const clientIp = getClientIp({ request, env: effectiveEnv, context });
      if (!(await store.checkRateLimit(clientIp, RATE_LIMIT_WINDOW, RATE_LIMIT_MAX))) {
        return jsonResponse({ error: 'rate_limited', message: 'Too many verification attempts. Please wait and try again.' }, 429);
      }
      const formData = await request.formData();
      const nonce = (formData.get('nonce')?.toString() || '').slice(0, MAX_NONCE_LENGTH);
      const returnTo = (formData.get('return_to')?.toString() || '/').slice(0, MAX_RETURN_TO_LENGTH);
      const fp = (formData.get('fp')?.toString() || '').slice(0, MAX_FP_LENGTH);
      const pow = (formData.get('pow')?.toString() || '').slice(0, MAX_POW_LENGTH);

      // Nonce format: <ts>.<rand>.<sig>
      const [nonceTs, nonceRand, nonceSig] = nonce.split('.');
      if (!nonceTs || !nonceRand || !nonceSig || !isPlausibleFingerprint(fp)) {
        return jsonResponse({ error: 'forbidden', message: 'Challenge verification failed.' }, 403);
      }

      const ts = Number.parseInt(nonceTs, 10);
      if (Number.isNaN(ts) || Date.now() - ts > NONCE_TTL_MS) {
        return jsonResponse({ error: 'forbidden', message: 'Challenge expired. Reload the page.' }, 403);
      }

      // Nonce is bound to the IP it was issued to.
      const clientId = await clientIdForIp(clientIp, secret);
      const expectedSig = await hmacSign(`nonce:${nonceTs}:${nonceRand}:${clientId}`, secret);
      if (!(await timingSafeEqual(nonceSig, expectedSig))) {
        return jsonResponse({ error: 'forbidden', message: 'Invalid challenge.' }, 403);
      }

      if (!(await verifyPow(nonce, pow, powDifficulty))) {
        return jsonResponse({ error: 'forbidden', message: 'Challenge verification failed.' }, 403);
      }

      // Single use: a solved nonce cannot mint a second cookie.
      if (!(await store.consumeNonce(nonceSig, NONCE_TTL_MS))) {
        return jsonResponse({ error: 'forbidden', message: 'Challenge expired. Reload the page.' }, 403);
      }

      const now = Date.now().toString();
      const cookieSig = await hmacSign(`cookie:${now}:${clientId}`, secret);
      const safePath = (returnTo.startsWith('/') && !returnTo.startsWith('//')) ? returnTo : '/';

      return new Response(null, {
        status: 302,
        headers: {
          Location: safePath,
          'Set-Cookie': `${COOKIE_NAME}=${encodeURIComponent(`${now}.${cookieSig}`)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`,
        },
      });
    }

    if (!isBrowser(request)) {
      const agentKey = request.headers.get('X-Agent-Key');
      const network = debug ? 'devnet' : 'mainnet-beta';

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
            newKey = await generateAgentKey(secret);
          }
        } else {
          newKey = await generateAgentKey(secret);
        }
        const noKeyInstructions = feeInfo
          ? `Send ${minPayment} USDC on Solana ${debug ? 'devnet' : 'mainnet'} to ${walletAddress} with memo "${newKey}", AND in the SAME transaction send the platform fee (see platform_fee below) to ${feeInfo.wallet}. Then include the header X-Agent-Key: ${newKey} on all subsequent requests.`
          : `Send ${minPayment} USDC on Solana ${debug ? 'devnet' : 'mainnet'} to ${walletAddress} with memo "${newKey}". Then include the header X-Agent-Key: ${newKey} on all subsequent requests.`;
        return paymentRequiredResponse({
          error: 'payment_required',
          message: 'Access requires a paid API key. A key has been generated for you below. Send a USDC payment on Solana with this key as the memo to activate it, then retry your request with the X-Agent-Key header.',
          your_key: newKey,
          payment: buildPaymentField({ network, minPayment, walletAddress, memo: newKey, feeInfo, instructions: noKeyInstructions }),
        }, { walletAddress, mint: usdcMint, minPayment, debug, agentKey: newKey, resource: url.pathname });
      }

      // Validate the key. Platform-issued (agp_) verified with verificationSecret;
      // local keys (ag_) verified with challengeSecret.
      const isHostedKey = agentKey.startsWith(HOSTED_KEY_PREFIX);
      if (isHostedKey) {
        if (!platformClient) {
          return jsonResponse({ error: 'forbidden', message: 'Platform-issued keys (agp_) require AGENTPAYMENTS_API_KEY to be configured.' }, 403);
        }
        let verSec;
        try {
          verSec = await platformClient.getVerificationSecret();
        } catch (err) {
          gateLog('error', 'Failed to fetch verificationSecret from platform', { error: err.message });
          return jsonResponse({ error: 'service_unavailable', message: 'Key verification temporarily unavailable.' }, 503);
        }
        if (!(await isValidHostedKey(agentKey, verSec))) {
          return jsonResponse({ error: 'forbidden', message: 'Invalid API key.' }, 403);
        }
      } else if (!(await isValidAgentKey(agentKey, secret))) {
        return jsonResponse({
          error: 'forbidden',
          message: 'Invalid API key. Keys must be issued by this server.',
          details: 'GET /.well-known/agent-access.json for access instructions.',
        }, 403);
      }

      // Rate-limit the verification path (stricter than the challenge endpoint).
      const agentKeyIp = getClientIp({ request, env: effectiveEnv, context });
      if (!(await store.checkRateLimit(`ak:${agentKeyIp}`, RATE_LIMIT_WINDOW, AGENT_KEY_RATE_LIMIT_MAX))) {
        return jsonResponse({ error: 'rate_limited', message: 'Too many payment verification requests. Please wait and try again.' }, 429);
      }

      if (!walletAddress) {
        return jsonResponse({ error: 'server_error', message: 'Payment verification unavailable.' }, 500);
      }

      const cachedPayment = await store.getCachedPayment(agentKey);
      if (cachedPayment === true) return fetchUpstream(request, effectiveEnv, context);
      if (cachedPayment === false) {
        // Negative result cached — skip the RPC scan until the TTL expires.
        return paymentRequiredResponse({
          error: 'payment_required',
          message: 'Key is valid but payment has not been verified on-chain yet. Please send the USDC payment and allow a few moments for confirmation.',
          your_key: agentKey,
          payment: buildPaymentField({ network, minPayment, walletAddress, memo: agentKey, feeInfo }),
        }, { walletAddress, mint: usdcMint, minPayment, debug, agentKey, resource: url.pathname });
      }
      const paid = await verifyPaymentOnChain(agentKey, walletAddress, rpcUrls, usdcMint, minPayment, feeInfo);
      await store.setCachedPayment(agentKey, paid, paid ? PAYMENT_CACHE_TTL : NEGATIVE_CACHE_TTL_MS);
      if (!paid) {
        return paymentRequiredResponse({
          error: 'payment_required',
          message: 'Key is valid but payment has not been verified on-chain yet. Please send the USDC payment and allow a few moments for confirmation.',
          your_key: agentKey,
          payment: buildPaymentField({ network, minPayment, walletAddress, memo: agentKey, feeInfo }),
        }, { walletAddress, mint: usdcMint, minPayment, debug, agentKey, resource: url.pathname });
      }

      const ua = request.headers.get('user-agent') || 'unknown';
      const ip = getClientIp({ request, env: effectiveEnv, context });
      gateLog('info', 'Payment verified - agent access granted', { network: debug ? 'devnet' : 'mainnet', key: agentKey.slice(0, 12) + '...', ua, ip, path: url.pathname });
      return fetchUpstream(request, effectiveEnv, context);
    }

    const browserIp = getClientIp({ request, env: effectiveEnv, context });
    if (await isValidCookie(request, secret, browserIp)) {
      return fetchUpstream(request, effectiveEnv, context);
    }

    // Rate-limit challenge page issuance to prevent unlimited nonce harvesting.
    if (!(await store.checkRateLimit(`ci:${browserIp}`, RATE_LIMIT_WINDOW, CHALLENGE_ISSUE_RATE_LIMIT_MAX))) {
      return jsonResponse({ error: 'rate_limited', message: 'Too many requests. Please try again later.' }, 429);
    }

    const nonceTs = Date.now().toString();
    const nonceRand = Array.from(crypto.getRandomValues(new Uint8Array(8))).map((b) => b.toString(16).padStart(2, '0')).join('');
    const nonceClientId = await clientIdForIp(browserIp, secret);
    const nonceSig = await hmacSign(`nonce:${nonceTs}:${nonceRand}:${nonceClientId}`, secret);
    return challengePage(url.pathname + url.search, `${nonceTs}.${nonceRand}.${nonceSig}`, powDifficulty);
  };
}
