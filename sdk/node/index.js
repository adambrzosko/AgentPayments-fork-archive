const crypto = require('node:crypto');
const {
  COOKIE_NAME, COOKIE_MAX_AGE, KEY_PREFIX,
  USDC_MINT_DEVNET, USDC_MINT_MAINNET,
  RPC_DEVNET, RPC_MAINNET,
  MEMO_PROGRAM, MIN_PAYMENT,
  MAX_KEY_LENGTH, MAX_NONCE_LENGTH, MAX_RETURN_TO_LENGTH, MAX_FP_LENGTH,
  POW_DIFFICULTY, MAX_POW_LENGTH, NONCE_TTL_MS,
} = require('../constants.json');
const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const PAYMENT_CACHE_TTL = 10 * 60 * 1000; // 10 minutes
const PAYMENT_CACHE_MAX = 1000;

class PaymentCache {
  constructor(ttl = PAYMENT_CACHE_TTL, maxSize = PAYMENT_CACHE_MAX) {
    this.ttl = ttl;
    this.maxSize = maxSize;
    this.cache = new Map();
  }
  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return undefined;
    if (Date.now() - entry.ts > this.ttl) { this.cache.delete(key); return undefined; }
    return entry.value;
  }
  set(key, value) {
    if (this.cache.size >= this.maxSize) {
      const oldest = this.cache.keys().next().value;
      this.cache.delete(oldest);
    }
    this.cache.set(key, { value, ts: Date.now() });
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

async function verifyPaymentOnChain(agentKey, walletAddress, rpcUrl, usdcMint, minPayment = MIN_PAYMENT) {
  try {
    const ataData = await rpcCall(rpcUrl, 'getTokenAccountsByOwner', [
      walletAddress,
      { mint: usdcMint },
      { encoding: 'jsonParsed' },
    ]);

    const tokenAccounts = (ataData.result?.value || []).map((a) => a.pubkey);
    // Only transfers landing in one of the vendor's USDC token accounts count as
    // payment. Token accounts are mint-bound, so membership also guarantees the
    // token is USDC for plain `transfer` instructions (which carry no mint field).
    const vendorUsdcAccounts = new Set(tokenAccounts);
    if (vendorUsdcAccounts.size === 0) return false; // vendor has no USDC account yet — no payment possible

    const addressesToScan = [walletAddress, ...tokenAccounts];
    const seen = new Set();
    const allSignatures = [];

    for (const addr of addressesToScan) {
      const sigsData = await rpcCall(rpcUrl, 'getSignaturesForAddress', [addr, { limit: 100 }]);
      for (const sig of sigsData.result || []) {
        if (!seen.has(sig.signature)) {
          seen.add(sig.signature);
          allSignatures.push(sig);
        }
      }
    }

    for (const sigInfo of allSignatures) {
      if (sigInfo.err) continue;

      const txData = await rpcCall(rpcUrl, 'getTransaction', [
        sigInfo.signature,
        { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 },
      ]);
      const tx = txData.result;
      if (!tx) continue;

      const instructions = tx.transaction?.message?.instructions || [];
      const innerInstructions = tx.meta?.innerInstructions || [];
      const allInstructions = [...instructions, ...innerInstructions.flatMap((inner) => inner.instructions || [])];

      let hasMemo = false;
      let hasPayment = false;

      for (const ix of allInstructions) {
        if (ix.program === 'spl-memo' || ix.programId === MEMO_PROGRAM) {
          const memo = typeof ix.parsed === 'string' ? ix.parsed : '';
          if (memo.includes(agentKey)) hasMemo = true;
        }

        if (ix.program === 'spl-token') {
          const parsed = ix.parsed || {};
          if (parsed.type === 'transfer' || parsed.type === 'transferChecked') {
            const info = parsed.info || {};
            // Payment must be delivered to one of the vendor's USDC token accounts.
            if (!vendorUsdcAccounts.has(info.destination)) continue;
            if (parsed.type === 'transferChecked' && info.mint !== usdcMint) continue;
            const uiAmount = info.tokenAmount?.uiAmount ?? Number.parseFloat(info.amount || '0') / 1e6;
            if (uiAmount >= minPayment) hasPayment = true;
          }
        }
      }

      if (hasMemo && hasPayment) return true;
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

function isPublicPath(pathname) {
  if (pathname === '/robots.txt') return true;
  if (pathname.startsWith('/.well-known/')) return true;
  return false;
}

function isBrowser(req) {
  return Boolean(req.headers['sec-fetch-mode'] || req.headers['sec-fetch-dest']);
}

function challengePage(returnTo, nonce, powDifficulty = POW_DIFFICULTY) {
  const safePath = returnTo.startsWith('/') ? returnTo : '/';
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

function agentPaymentsGate(config = {}) {
  const {
    challengeSecret,
    homeWalletAddress,
    solanaRpcUrl,
    usdcMint,
    minPayment = MIN_PAYMENT,
    powDifficulty = POW_DIFFICULTY,
    debug = process.env.DEBUG !== 'false',
  } = config;

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
  const rpcUrl = solanaRpcUrl || (debug ? RPC_DEVNET : RPC_MAINNET);
  const mint = usdcMint || (debug ? USDC_MINT_DEVNET : USDC_MINT_MAINNET);
  const network = debug ? 'devnet' : 'mainnet-beta';
  const paymentCache = new PaymentCache();
  const rateLimiter = new RateLimiter();
  const consumedNonces = new ConsumedNonces();
  setInterval(() => { rateLimiter.cleanup(); consumedNonces.cleanup(); }, 60000).unref();

  return async function agentPaymentsGateMiddleware(req, res, next) {
    const pathname = req.path;

    if (isPublicPath(pathname)) return next();

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
      const safePath = returnTo.startsWith('/') ? returnTo : '/';

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

      if (!agentKey) {
        const newKey = generateAgentKey(secret);
        return json(res, 402, {
          error: 'payment_required',
          message: 'Access requires a paid API key. A key has been generated for you below. Send a USDC payment on Solana with this key as the memo to activate it, then retry your request with the X-Agent-Key header.',
          your_key: newKey,
          payment: {
            chain: 'solana',
            network,
            token: 'USDC',
            amount: String(minPayment),
            wallet_address: walletAddress,
            memo: newKey,
            instructions: `Send ${minPayment} USDC on Solana ${debug ? 'devnet' : 'mainnet'} to ${walletAddress} with memo "${newKey}". Then include the header X-Agent-Key: ${newKey} on all subsequent requests.`,
          },
        });
      }

      if (!isValidAgentKey(agentKey, secret)) {
        return json(res, 403, {
          error: 'forbidden',
          message: 'Invalid API key. Keys must be issued by this server.',
          details: 'GET /.well-known/agent-access.json for access instructions.',
        });
      }

      if (!walletAddress) {
        return json(res, 500, { error: 'server_error', message: 'Payment verification unavailable.' });
      }

      const cached = paymentCache.get(agentKey);
      if (cached === true) return next();
      const paid = await verifyPaymentOnChain(agentKey, walletAddress, rpcUrl, mint, minPayment);
      if (paid) paymentCache.set(agentKey, true);
      if (!paid) {
        return json(res, 402, {
          error: 'payment_required',
          message: 'Key is valid but payment has not been verified on-chain yet. Please send the USDC payment and allow a few moments for confirmation.',
          your_key: agentKey,
          payment: {
            chain: 'solana',
            network,
            token: 'USDC',
            amount: String(minPayment),
            wallet_address: walletAddress,
            memo: agentKey,
          },
        });
      }

      return next();
    }

    if (isValidCookie(req, secret)) return next();

    const nonceTs = Date.now().toString();
    const nonceRand = crypto.randomBytes(8).toString('hex');
    const nonceClientId = clientIdForIp(getClientIp(req), secret);
    const nonceSig = hmacSign(`nonce:${nonceTs}:${nonceRand}:${nonceClientId}`, secret);
    return res.status(200).set('Cache-Control', 'no-store').set('Content-Type', 'text/html').send(challengePage(req.originalUrl || req.url, `${nonceTs}.${nonceRand}.${nonceSig}`, powDifficulty));
  };
}

module.exports = { agentPaymentsGate };
