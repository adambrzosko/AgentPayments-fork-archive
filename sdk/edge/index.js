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
const MAX_KEY_LENGTH = 64;
const MAX_NONCE_LENGTH = 128;
const MAX_RETURN_TO_LENGTH = 2048;
const MAX_FP_LENGTH = 128;
const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const PAYMENT_CACHE_TTL = 10 * 60 * 1000; // 10 minutes
const PAYMENT_CACHE_MAX = 1000;

const paymentCache = new Map();

function getCachedPayment(key) {
  const entry = paymentCache.get(key);
  if (!entry) return undefined;
  if (Date.now() - entry.ts > PAYMENT_CACHE_TTL) { paymentCache.delete(key); return undefined; }
  return entry.value;
}

function setCachedPayment(key, value) {
  if (paymentCache.size >= PAYMENT_CACHE_MAX) {
    const oldest = paymentCache.keys().next().value;
    paymentCache.delete(oldest);
  }
  paymentCache.set(key, { value, ts: Date.now() });
}

function gateLog(level, message, data = {}) {
  const entry = JSON.stringify({ ts: new Date().toISOString(), level, component: 'agentpayments', message, ...data });
  if (level === 'error') console.error(entry);
  else if (level === 'warn') console.warn(entry);
  else console.log(entry);
}

const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 20;
const rateLimitHits = new Map();

function rateLimitCheck(key) {
  const now = Date.now();
  const entry = rateLimitHits.get(key);
  if (!entry || now - entry.start > RATE_LIMIT_WINDOW) {
    rateLimitHits.set(key, { start: now, count: 1 });
    return true;
  }
  entry.count++;
  return entry.count <= RATE_LIMIT_MAX;
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

async function hmacSign(data, secret) {
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

async function generateAgentKey(secret) {
  const random = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
  const sig = await hmacSign(random, secret);
  return `${KEY_PREFIX}${random}_${sig.slice(0, 16)}`;
}

async function isValidAgentKey(key, secret) {
  if (!key || key.length > MAX_KEY_LENGTH || !key.startsWith(KEY_PREFIX)) return false;
  const rest = key.slice(KEY_PREFIX.length);
  const underscoreIndex = rest.indexOf('_');
  if (underscoreIndex === -1) return false;
  const random = rest.slice(0, underscoreIndex);
  const sig = rest.slice(underscoreIndex + 1);
  const expected = await hmacSign(random, secret);
  return timingSafeEqual(sig, expected.slice(0, 16));
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

async function verifyPaymentOnChain(agentKey, walletAddress, rpcUrl, usdcMint) {
  try {
    const ataData = await rpcCall(rpcUrl, 'getTokenAccountsByOwner', [walletAddress, { mint: usdcMint }, { encoding: 'jsonParsed' }]);
    const tokenAccounts = (ataData.result?.value || []).map((entry) => entry.pubkey);

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

      const txData = await rpcCall(rpcUrl, 'getTransaction', [sigInfo.signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }]);
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
            if (parsed.type === 'transferChecked' && info.mint !== usdcMint) continue;
            const uiAmount = info.tokenAmount?.uiAmount ?? Number.parseFloat(info.amount || '0') / 1e6;
            if (uiAmount >= MIN_PAYMENT) hasPayment = true;
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

function getCookie(request, name) {
  const cookies = request.headers.get('cookie') || '';
  const match = cookies.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function isValidCookie(request, secret) {
  const cookie = getCookie(request, COOKIE_NAME);
  if (!cookie) return false;
  const dotIndex = cookie.indexOf('.');
  if (dotIndex === -1) return false;
  const timestamp = cookie.slice(0, dotIndex);
  const signature = cookie.slice(dotIndex + 1);
  const ts = Number.parseInt(timestamp, 10);
  if (Number.isNaN(ts) || Date.now() - ts > COOKIE_MAX_AGE * 1000) return false;
  const expected = await hmacSign(timestamp, secret);
  return timingSafeEqual(signature, expected);
}

function isPublicPath(pathname, allowlist = []) {
  if (pathname === '/robots.txt') return true;
  if (pathname.startsWith('/.well-known/')) return true;
  if (allowlist.includes(pathname)) return true;
  return false;
}

function isBrowser(request) {
  return Boolean(request.headers.get('sec-fetch-mode') || request.headers.get('sec-fetch-dest'));
}

function jsonResponse(body, status) {
  return new Response(JSON.stringify(body, null, 2), { status, headers: { 'Content-Type': 'application/json' } });
}

function challengePage(returnTo, nonce) {
  const safePath = returnTo.startsWith('/') ? returnTo : '/';
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Verifying your access...</title><style>body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#fafafa;color:#333}main{text-align:center;padding:2rem}.spinner{width:40px;height:40px;border:4px solid #e0e0e0;border-top-color:#333;border-radius:50%;animation:spin .8s linear infinite;margin:1rem auto}@keyframes spin{to{transform:rotate(360deg)}}</style></head><body><main role="status" aria-live="polite"><div class="spinner" aria-hidden="true"></div><p>Verifying your access&hellip;</p><noscript><p><strong>JavaScript is required to verify your access. Please enable JavaScript and reload this page.</strong></p></noscript></main><script>(function(){if(navigator.webdriver)return;var c=document.createElement("canvas");c.width=200;c.height=50;var ctx=c.getContext("2d");if(!ctx)return;ctx.font="18px Arial";ctx.fillStyle="#1a1a2e";ctx.fillText("verify",10,30);var data=c.toDataURL();if(!data||data.length<100)return;if(typeof window.innerWidth==="undefined"||window.innerWidth===0)return;var form=document.createElement("form");form.method="POST";form.action="/__challenge/verify";var fields={nonce:${JSON.stringify(nonce)},return_to:${JSON.stringify(safePath)},fp:data.slice(22,86)};for(var key in fields){var input=document.createElement("input");input.type="hidden";input.name=key;input.value=fields[key];form.appendChild(input);}document.body.appendChild(form);form.submit();})();</script></body></html>`;
  return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' } });
}

export function createEdgeGate(options = {}) {
  const {
    fetchUpstream,
    getClientIp = () => 'unknown',
    publicPathAllowlist = [],
    minPayment = MIN_PAYMENT,
    envResolver,
  } = options;

  if (typeof fetchUpstream !== 'function') {
    throw new Error('createEdgeGate requires fetchUpstream(request, env, context)');
  }

  return async function edgeGate(request, env = {}, context = {}) {
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
    const rpcUrl = effectiveEnv.SOLANA_RPC_URL || (debug ? RPC_DEVNET : RPC_MAINNET);
    const usdcMint = effectiveEnv.USDC_MINT || (debug ? USDC_MINT_DEVNET : USDC_MINT_MAINNET);

    if (isPublicPath(url.pathname, publicPathAllowlist)) {
      return fetchUpstream(request, effectiveEnv, context);
    }

    if (url.pathname === '/__challenge/verify' && request.method === 'POST') {
      const clientIp = getClientIp({ request, env: effectiveEnv, context });
      if (!rateLimitCheck(clientIp)) {
        return jsonResponse({ error: 'rate_limited', message: 'Too many verification attempts. Please wait and try again.' }, 429);
      }
      const formData = await request.formData();
      const nonce = (formData.get('nonce')?.toString() || '').slice(0, MAX_NONCE_LENGTH);
      const returnTo = (formData.get('return_to')?.toString() || '/').slice(0, MAX_RETURN_TO_LENGTH);
      const fp = (formData.get('fp')?.toString() || '').slice(0, MAX_FP_LENGTH);

      const dotIndex = nonce.indexOf('.');
      if (dotIndex === -1 || !fp || fp.length < 10) {
        return jsonResponse({ error: 'forbidden', message: 'Challenge verification failed.' }, 403);
      }

      const nonceTs = nonce.slice(0, dotIndex);
      const nonceSig = nonce.slice(dotIndex + 1);
      const ts = Number.parseInt(nonceTs, 10);

      if (Number.isNaN(ts) || Date.now() - ts > 300000) {
        return jsonResponse({ error: 'forbidden', message: 'Challenge expired. Reload the page.' }, 403);
      }

      const expectedSig = await hmacSign(`nonce:${nonceTs}`, secret);
      if (!(await timingSafeEqual(nonceSig, expectedSig))) {
        return jsonResponse({ error: 'forbidden', message: 'Invalid challenge.' }, 403);
      }

      const now = Date.now().toString();
      const cookieSig = await hmacSign(now, secret);
      const safePath = returnTo.startsWith('/') ? returnTo : '/';

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

      if (!agentKey) {
        const newKey = await generateAgentKey(secret);
        return jsonResponse({
          error: 'payment_required',
          message: 'Access requires a paid API key. A key has been generated for you below. Send a USDC payment on Solana with this key as the memo to activate it, then retry your request with the X-Agent-Key header.',
          your_key: newKey,
          payment: {
            chain: 'solana',
            network: debug ? 'devnet' : 'mainnet-beta',
            token: 'USDC',
            amount: String(minPayment),
            wallet_address: walletAddress,
            memo: newKey,
            instructions: `Send ${minPayment} USDC on Solana ${debug ? 'devnet' : 'mainnet'} to ${walletAddress} with memo "${newKey}". Then include the header X-Agent-Key: ${newKey} on all subsequent requests.`,
          },
        }, 402);
      }

      if (!(await isValidAgentKey(agentKey, secret))) {
        return jsonResponse({
          error: 'forbidden',
          message: 'Invalid API key. Keys must be issued by this server.',
          details: 'GET /.well-known/agent-access.json for access instructions.',
        }, 403);
      }

      if (!walletAddress) {
        return jsonResponse({ error: 'server_error', message: 'Payment verification unavailable.' }, 500);
      }

      if (getCachedPayment(agentKey) === true) {
        return fetchUpstream(request, effectiveEnv, context);
      }
      const paid = await verifyPaymentOnChain(agentKey, walletAddress, rpcUrl, usdcMint);
      if (paid) setCachedPayment(agentKey, true);
      if (!paid) {
        return jsonResponse({
          error: 'payment_required',
          message: 'Key is valid but payment has not been verified on-chain yet. Please send the USDC payment and allow a few moments for confirmation.',
          your_key: agentKey,
          payment: {
            chain: 'solana',
            network: debug ? 'devnet' : 'mainnet-beta',
            token: 'USDC',
            amount: String(minPayment),
            wallet_address: walletAddress,
            memo: agentKey,
          },
        }, 402);
      }

      const ua = request.headers.get('user-agent') || 'unknown';
      const ip = getClientIp({ request, env: effectiveEnv, context });
      gateLog('info', 'Payment verified - agent access granted', { network: debug ? 'devnet' : 'mainnet', key: agentKey.slice(0, 12) + '...', ua, ip, path: url.pathname });
      return fetchUpstream(request, effectiveEnv, context);
    }

    if (await isValidCookie(request, secret)) {
      return fetchUpstream(request, effectiveEnv, context);
    }

    const nonceTs = Date.now().toString();
    const nonceSig = await hmacSign(`nonce:${nonceTs}`, secret);
    return challengePage(url.pathname + url.search, `${nonceTs}.${nonceSig}`);
  };
}
