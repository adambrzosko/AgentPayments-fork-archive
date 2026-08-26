/**
 * AgentPayments Platform API
 *
 * Metered, enforceable agent key issuance for the AgentPayments SDK.
 * Vendors register once, receive a platform API key + verificationSecret,
 * configure the SDK, and keys are issued/billed through this service.
 *
 * Endpoints:
 *   POST /v1/vendors/register              — create vendor account (rate-limited)
 *   GET  /v1/vendors/verify-email          — confirm email address
 *   GET  /v1/account                       — account info + verificationSecret (auth)
 *   POST /v1/keys/issue                    — issue a platform-signed key (auth, metered)
 *   GET  /v1/usage                         — usage stats (auth)
 *   POST /v1/keys/verify                   — public key validation (no auth)
 *   GET  /dashboard                        — vendor dashboard login page
 *   POST /dashboard/login                  — authenticate → session cookie
 *   GET  /dashboard/logout                 — clear session
 *
 * Environment:
 *   PLATFORM_MASTER_SECRET  required — long random string
 *   DATABASE_URL            optional — Postgres connection string (else JSON file)
 *   SMTP_HOST               optional — enables email verification
 *   SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
 *   PUBLIC_URL              optional — base URL for email links
 *   STRIPE_SECRET_KEY       optional — enables metered billing
 *   STRIPE_PRICE_ID         optional — Stripe metered price ID (see stripe-billing.js)
 *   STRIPE_METER_ID         optional — Stripe Billing Meter ID (see stripe-billing.js)
 *   STRIPE_METER_EVENT_NAME optional — Stripe Billing Meter event name
 *   PORT                    optional — default 3001
 *
 * Rotating PLATFORM_MASTER_SECRET invalidates all existing dashboard sessions and any
 * in-flight (unused) email-verification tokens immediately, but does NOT invalidate
 * already-issued vendor api_key/verification_secret values — those are generated once
 * at registration and stored verbatim, never re-derived from the current secret.
 */

'use strict';

const crypto = require('node:crypto');
const express = require('express');
const store = require('./store');
const { sendVerificationEmail } = require('./email');
const { createCustomerAndSubscription, recordKeyIssuance, getCurrentUsage } = require('./stripe-billing');
const { dashboardHtml, loginHtml } = require('./dashboard');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

if (!process.env.PLATFORM_MASTER_SECRET) {
  if (process.env.NODE_ENV === 'test') {
    process.env.PLATFORM_MASTER_SECRET = 'test-master-secret-do-not-use-in-prod';
  } else {
    throw new Error('PLATFORM_MASTER_SECRET env var is required. Set a long random string.');
  }
}
const masterSecret = process.env.PLATFORM_MASTER_SECRET;

// Email verification is enforced only when SMTP is configured.
const emailVerificationRequired = Boolean(process.env.SMTP_HOST);

// Dashboard session TTL: 8 hours
const DASHBOARD_SESSION_TTL = 8 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

function hmac(data, key) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

function timingSafeEqualStr(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// ---------------------------------------------------------------------------
// Key construction
// ---------------------------------------------------------------------------

function newVendorId() {
  return randomHex(4);
}

/** Format: ap_live_${vendorId8}_${rand16}_${sig24} */
function makeVendorApiKey(vendorId) {
  const rand = randomHex(8);
  const sig = hmac(`apikey:${vendorId}:${rand}`, masterSecret).slice(0, 24);
  return `ap_live_${vendorId}_${rand}_${sig}`;
}

/** Deterministic verificationSecret per vendor. */
function deriveVerificationSecret(vendorId) {
  return hmac(`verify:${vendorId}`, masterSecret).slice(0, 32);
}

/** Email verification token — scoped to vendor + email. */
function makeVerificationToken(vendorId, email) {
  return hmac(`email-verify:${vendorId}:${email}`, masterSecret).slice(0, 32);
}

/** Dashboard session cookie value. */
function makeDashboardSession(vendorId) {
  const ts = Date.now().toString();
  const sig = hmac(`dash:${vendorId}:${ts}`, masterSecret).slice(0, 32);
  return `${vendorId}.${ts}.${sig}`;
}

function parseDashboardSession(cookie) {
  if (!cookie) return null;
  const parts = cookie.split('.');
  if (parts.length !== 3) return null;
  const [vendorId, ts, sig] = parts;
  if (Date.now() - Number(ts) > DASHBOARD_SESSION_TTL) return null;
  const expected = hmac(`dash:${vendorId}:${ts}`, masterSecret).slice(0, 32);
  if (!timingSafeEqualStr(sig, expected)) return null;
  return vendorId;
}

/** Format: agp_${vendorId8}_${nonce16}_${sig16} */
function issueAgentKey(vendorId, verificationSecret) {
  const nonce = randomHex(8);
  const sig = hmac(`agp:${vendorId}:${nonce}`, verificationSecret).slice(0, 16);
  return `agp_${vendorId}_${nonce}_${sig}`;
}

// ---------------------------------------------------------------------------
// Rate limiting (in-memory, per IP)
// ---------------------------------------------------------------------------

class RateLimiter {
  constructor(windowMs, max) {
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
    return entry.count <= this.max;
  }
}

// Registration: 5 per hour per IP
const registrationLimiter = new RateLimiter(60 * 60 * 1000, 5);
// API endpoints: 120 per minute per IP
const apiLimiter = new RateLimiter(60 * 1000, 120);
// Dashboard login: 20 per minute per IP (credential-stuffing/DoS backstop)
const loginLimiter = new RateLimiter(60 * 1000, 20);
// Public key verification: high ceiling since this sees real vendor-server traffic,
// but still bounded as a DoS backstop against garbage-key floods.
const verifyLimiter = new RateLimiter(60 * 1000, 600);

// NOTE: all limiters above are in-memory (per-process) and only enforce correctly on
// a single instance. If this ever scales to multiple instances, each instance has its
// own counters and the effective limit multiplies — swap in a shared backend (see
// sdk/node/redis-store.js's RateLimiter for a reusable Redis-backed implementation)
// at that point.

function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = express();
// Railway (and most PaaS hosts) terminate TLS and forward over HTTP internally via a
// single reverse-proxy hop — trust proxy: 1 makes req.secure reflect X-Forwarded-Proto.
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: false })); // for dashboard login form + cookie parsing

// Reject plaintext HTTP outside test/dev, mirroring the requireHttps pattern already
// used in sdk/node/index.js.
const requireHttps = process.env.NODE_ENV !== 'test' && process.env.NODE_ENV !== 'development';
function isHttps(req) {
  return req.secure || (req.headers['x-forwarded-proto'] || '').startsWith('https');
}
app.use((req, res, next) => {
  if (requireHttps && !isHttps(req)) {
    return res.status(400).json({ error: 'https_required', message: 'This service requires a secure HTTPS connection.' });
  }
  next();
});

// Simple cookie parser (no dependency)
function getCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k.trim() === name) return decodeURIComponent(rest.join('='));
  }
  return null;
}

// ---------------------------------------------------------------------------
// Auth middleware (API)
// ---------------------------------------------------------------------------

async function authenticate(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', message: 'Missing Authorization: Bearer <apiKey> header.' });
  }
  const apiKey = auth.slice(7).trim();
  if (!apiKey.startsWith('ap_live_')) {
    return res.status(401).json({ error: 'unauthorized', message: 'Invalid API key format.' });
  }
  const vendor = await store.getVendorByApiKey(apiKey);
  if (!vendor) {
    return res.status(401).json({ error: 'unauthorized', message: 'API key not found.' });
  }
  // Block unverified accounts only when email verification is enforced.
  const verified = vendor.email_verified ?? vendor.emailVerified;
  if (emailVerificationRequired && !verified) {
    return res.status(403).json({
      error: 'email_not_verified',
      message: 'Please verify your email address before using the API. Check your inbox for the verification link.',
    });
  }
  req.vendor = vendor;
  next();
}

// ---------------------------------------------------------------------------
// POST /v1/vendors/register
// ---------------------------------------------------------------------------

app.post('/v1/vendors/register', async (req, res, next) => {
  try {
    const ip = clientIp(req);
    if (!registrationLimiter.check(ip)) {
      return res.status(429).json({ error: 'rate_limited', message: 'Too many registration attempts. Try again later.' });
    }

    const { email, name } = req.body || {};
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return res.status(400).json({ error: 'bad_request', message: 'email is required and must be a valid email address.' });
    }
    if (!name || typeof name !== 'string' || name.trim().length < 2) {
      return res.status(400).json({ error: 'bad_request', message: 'name is required (min 2 characters).' });
    }

    const vendorId = newVendorId();
    const apiKey = makeVendorApiKey(vendorId);
    const verificationSecret = deriveVerificationSecret(vendorId);
    const verificationToken = emailVerificationRequired ? makeVerificationToken(vendorId, email.toLowerCase().trim()) : null;

    let vendor;
    try {
      vendor = await store.createVendor({
        vendorId,
        email: email.toLowerCase().trim(),
        name: name.trim(),
        apiKey,
        verificationSecret,
        verificationToken,
      });
    } catch (err) {
      if (err.code === 'DUPLICATE_EMAIL') {
        return res.status(409).json({ error: 'conflict', message: 'A vendor account with that email already exists.' });
      }
      throw err;
    }

    // Stripe: create customer + subscription (fire-and-forget errors)
    createCustomerAndSubscription(vendor.email, vendor.name)
      .then(async (ids) => {
        if (ids) await store.setStripeIds(vendorId, ids.customerId);
      })
      .catch((err) => console.error(JSON.stringify({ level: 'error', component: 'stripe-setup', error: err.message })));

    // Email verification
    if (verificationToken) {
      await sendVerificationEmail({ email: vendor.email, name: vendor.name, vendorId, token: verificationToken });
    }

    const response = {
      vendorId: vendor.vendor_id || vendor.vendorId,
      apiKey,
      verificationSecret,
      emailVerificationRequired,
      message: emailVerificationRequired
        ? 'Check your email for a verification link. Your API key will be active once verified.'
        : 'Store these securely. Configure your SDK with apiKey.',
      docs: 'https://docs.agentpayments.dev/quickstart',
    };

    return res.status(201).json(response);
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// GET /v1/vendors/verify-email?token=...&vendorId=...
// ---------------------------------------------------------------------------

app.get('/v1/vendors/verify-email', async (req, res, next) => {
  try {
    const { token, vendorId } = req.query;
    if (!token || !vendorId) {
      return res.status(400).send('Missing token or vendorId parameter.');
    }
    const vendor = await store.verifyEmail(token);
    if (!vendor) {
      return res.status(400).send('Verification link is invalid or has already been used.');
    }
    // Redirect to dashboard after successful verification
    res.redirect(302, '/dashboard?verified=1');
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// GET /v1/account
// ---------------------------------------------------------------------------

app.get('/v1/account', authenticate, async (req, res, next) => {
  try {
    const v = req.vendor;
    res.json({
      vendorId: v.vendor_id || v.vendorId,
      email: v.email,
      name: v.name,
      plan: v.plan,
      verificationSecret: v.verification_secret || v.verificationSecret,
      emailVerified: v.email_verified ?? v.emailVerified,
      usage: {
        keysIssued: v.keys_issued ?? v.keysIssued,
        period: 'all_time',
      },
      createdAt: v.created_at || v.createdAt,
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /v1/keys/issue
// ---------------------------------------------------------------------------

app.post('/v1/keys/issue', authenticate, async (req, res, next) => {
  try {
    const ip = clientIp(req);
    if (!apiLimiter.check(ip)) {
      return res.status(429).json({ error: 'rate_limited', message: 'Too many requests.' });
    }
    const v = req.vendor;
    const verSec = v.verification_secret || v.verificationSecret;
    const vendorId = v.vendor_id || v.vendorId;
    const key = issueAgentKey(vendorId, verSec);

    // Increment counter (async, don't block response). Wrapped in Promise.resolve()
    // since store-json.js's implementation is synchronous while store-pg.js's is async.
    Promise.resolve(store.incrementKeysIssued(vendorId)).catch((err) =>
      console.error(JSON.stringify({ level: 'error', component: 'store', action: 'incrementKeysIssued', error: err.message })),
    );

    // Report to Stripe (fire-and-forget)
    const customerId = v.stripe_customer_id || v.stripeCustomerId;
    if (customerId) {
      recordKeyIssuance(customerId).catch(() => {});
    }

    res.json({ key, issuedAt: Date.now(), type: 'platform_issued' });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// GET /v1/usage
// ---------------------------------------------------------------------------

app.get('/v1/usage', authenticate, async (req, res, next) => {
  try {
    const v = req.vendor;
    const vendorId = v.vendor_id || v.vendorId;
    const customerId = v.stripe_customer_id || v.stripeCustomerId;
    const [thisMonth, stripeUsage] = await Promise.all([
      store.keysIssuedThisMonth(vendorId),
      getCurrentUsage(customerId),
    ]);
    res.json({
      vendorId,
      keysIssuedAllTime: v.keys_issued ?? v.keysIssued,
      keysIssuedThisMonth: thisMonth,
      billing: stripeUsage,
      period: 'all_time',
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// POST /v1/keys/verify  (public — no auth)
// ---------------------------------------------------------------------------

app.post('/v1/keys/verify', async (req, res, next) => {
  try {
    if (!verifyLimiter.check(clientIp(req))) {
      return res.status(429).json({ error: 'rate_limited', message: 'Too many requests.' });
    }
    const { key } = req.body || {};
    if (!key || typeof key !== 'string' || !key.startsWith('agp_')) {
      return res.status(400).json({ error: 'bad_request', message: 'key must be a platform-issued agp_ key.' });
    }
    const parts = key.split('_');
    if (parts.length !== 4) return res.json({ valid: false });
    const [, vendorId, nonce, sig] = parts;
    const vendor = await store.getVendor(vendorId);
    if (!vendor) return res.json({ valid: false });
    const verSec = vendor.verification_secret || vendor.verificationSecret;
    const expected = hmac(`agp:${vendorId}:${nonce}`, verSec).slice(0, 16);
    const valid = sig.length === expected.length && timingSafeEqualStr(sig, expected);
    res.json({ valid, vendorId: valid ? vendorId : undefined });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

app.get('/dashboard', async (req, res, next) => {
  try {
    const verified = req.query.verified === '1';
    const sessionCookie = getCookie(req, 'agp_dash');
    const vendorId = parseDashboardSession(sessionCookie);

    if (!vendorId) {
      const msg = verified ? null : null; // login page doesn't need a message
      return res.send(loginHtml(verified ? 'Email verified! Sign in to view your dashboard.' : null));
    }

    const vendor = await store.getVendor(vendorId);
    if (!vendor) {
      res.clearCookie('agp_dash');
      return res.send(loginHtml('Session expired. Please sign in again.'));
    }

    const [thisMonth, dailyUsage, stripeUsage] = await Promise.all([
      store.keysIssuedThisMonth(vendorId),
      store.getDailyUsage(vendorId, 30),
      getCurrentUsage(vendor.stripe_customer_id || vendor.stripeCustomerId),
    ]);

    res.send(dashboardHtml(vendor, thisMonth, dailyUsage, stripeUsage));
  } catch (err) {
    next(err);
  }
});

app.post('/dashboard/login', async (req, res, next) => {
  try {
    if (!loginLimiter.check(clientIp(req))) {
      return res.send(loginHtml('Too many attempts. Please wait a minute and try again.'));
    }
    const apiKey = (req.body?.key || '').trim();
    if (!apiKey) return res.send(loginHtml('Please enter your API key.'));

    const vendor = await store.getVendorByApiKey(apiKey);
    if (!vendor) return res.send(loginHtml('Invalid API key.'));

    const session = makeDashboardSession(vendor.vendor_id || vendor.vendorId);
    res.setHeader('Set-Cookie', `agp_dash=${encodeURIComponent(session)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${DASHBOARD_SESSION_TTL / 1000}`);
    res.redirect(302, '/dashboard');
  } catch (err) {
    next(err);
  }
});

app.get('/dashboard/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'agp_dash=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.redirect(302, '/dashboard');
});

// ---------------------------------------------------------------------------
// Error handler
// ---------------------------------------------------------------------------

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', component: 'platform-api', error: err.message, stack: err.stack }));
  res.status(500).json({ error: 'internal_server_error', message: 'An unexpected error occurred.' });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

if (require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(JSON.stringify({
      ts: new Date().toISOString(), level: 'info', component: 'platform-api',
      message: `AgentPayments Platform API listening on port ${PORT}`,
      store: process.env.DATABASE_URL ? 'postgres' : 'json-file',
      emailVerification: emailVerificationRequired,
      stripeBilling: Boolean(process.env.STRIPE_SECRET_KEY),
    }));
  });
}

module.exports = { app, issueAgentKey, deriveVerificationSecret };
