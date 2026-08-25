const test = require('node:test');
const assert = require('node:assert/strict');

process.env.NODE_ENV = 'test';

const { _internals } = require('../index.js');
const {
  hmacSign, generateAgentKey, isValidAgentKey, derivePaymentMemo,
  normalizeVerifyEndpoint, isPublicPath, isBrowser, getCookie, isValidCookie,
  challengePage, PaymentCache, RateLimiter,
  COOKIE_NAME, COOKIE_MAX_AGE,
} = _internals;

const SECRET = 'test-secret-1234';

test('hmacSign returns deterministic hex output', () => {
  const a = hmacSign('hello', SECRET);
  const b = hmacSign('hello', SECRET);
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(hmacSign('hello', 'other-secret'), a);
});

test('generateAgentKey produces valid format', () => {
  const key = generateAgentKey(SECRET);
  assert.match(key, /^ag_[0-9a-f]{16}_[0-9a-f]{16}$/);
});

test('isValidAgentKey accepts generated key', () => {
  const key = generateAgentKey(SECRET);
  assert.equal(isValidAgentKey(key, SECRET), true);
});

test('isValidAgentKey rejects tampered key', () => {
  const key = generateAgentKey(SECRET);
  const tampered = key.slice(0, -1) + (key.at(-1) === '0' ? '1' : '0');
  assert.equal(isValidAgentKey(tampered, SECRET), false);
});

test('isValidAgentKey rejects wrong secret', () => {
  const key = generateAgentKey(SECRET);
  assert.equal(isValidAgentKey(key, 'wrong-secret'), false);
});

test('isValidAgentKey rejects empty, null, and too-long inputs', () => {
  assert.equal(isValidAgentKey('', SECRET), false);
  assert.equal(isValidAgentKey(null, SECRET), false);
  assert.equal(isValidAgentKey(undefined, SECRET), false);
  assert.equal(isValidAgentKey('a'.repeat(200), SECRET), false);
});

test('derivePaymentMemo has correct format and is deterministic', () => {
  const key = generateAgentKey(SECRET);
  const memo = derivePaymentMemo(key, SECRET);
  assert.match(memo, /^gm_[0-9a-f]{16}$/);
  assert.equal(derivePaymentMemo(key, SECRET), memo);
});

test('normalizeVerifyEndpoint strips trailing slash and appends /verify', () => {
  assert.equal(normalizeVerifyEndpoint('https://example.com/'), 'https://example.com/verify');
  assert.equal(normalizeVerifyEndpoint('https://example.com///'), 'https://example.com/verify');
  assert.equal(normalizeVerifyEndpoint('https://example.com/verify'), 'https://example.com/verify');
  assert.equal(normalizeVerifyEndpoint(''), '');
  assert.equal(normalizeVerifyEndpoint(null), '');
});

test('isPublicPath matches public paths', () => {
  assert.equal(isPublicPath('/robots.txt'), true);
  assert.equal(isPublicPath('/.well-known/agent-access.json'), true);
  assert.equal(isPublicPath('/.well-known/foo'), true);
  assert.equal(isPublicPath('/api/data'), false);
  assert.equal(isPublicPath('/'), false);
});

test('isBrowser detects sec-fetch-mode header', () => {
  assert.equal(isBrowser({ headers: { 'sec-fetch-mode': 'navigate' } }), true);
  assert.equal(isBrowser({ headers: { 'sec-fetch-dest': 'document' } }), true);
  assert.equal(isBrowser({ headers: {} }), false);
  assert.equal(isBrowser({ headers: { 'user-agent': 'Mozilla' } }), false);
});

test('getCookie parses cookie from header string', () => {
  const req = { headers: { cookie: 'foo=bar; __agp_verified=abc123; baz=qux' } };
  assert.equal(getCookie(req, '__agp_verified'), 'abc123');
  assert.equal(getCookie(req, 'foo'), 'bar');
  assert.equal(getCookie(req, 'missing'), null);
  assert.equal(getCookie({ headers: {} }, 'foo'), null);
});

test('isValidCookie roundtrip: valid cookie passes', () => {
  const now = Date.now().toString();
  const sig = hmacSign(now, SECRET);
  const cookieVal = `${now}.${sig}`;
  const req = { headers: { cookie: `${COOKIE_NAME}=${cookieVal}` } };
  assert.equal(isValidCookie(req, SECRET), true);
});

test('isValidCookie rejects expired cookie', () => {
  const expired = (Date.now() - (COOKIE_MAX_AGE + 1) * 1000).toString();
  const sig = hmacSign(expired, SECRET);
  const cookieVal = `${expired}.${sig}`;
  const req = { headers: { cookie: `${COOKIE_NAME}=${cookieVal}` } };
  assert.equal(isValidCookie(req, SECRET), false);
});

test('isValidCookie rejects tampered cookie', () => {
  const now = Date.now().toString();
  const sig = hmacSign(now, SECRET);
  const tampered = sig.slice(0, -1) + (sig.at(-1) === '0' ? '1' : '0');
  const cookieVal = `${now}.${tampered}`;
  const req = { headers: { cookie: `${COOKIE_NAME}=${cookieVal}` } };
  assert.equal(isValidCookie(req, SECRET), false);
});

test('PaymentCache set/get works', () => {
  const cache = new PaymentCache();
  cache.set('k1', true);
  assert.equal(cache.get('k1'), true);
  assert.equal(cache.get('k2'), undefined);
});

test('PaymentCache TTL expiry', () => {
  const cache = new PaymentCache(1); // 1ms TTL
  cache.set('k1', true);
  // Busy-wait past TTL
  const start = Date.now();
  while (Date.now() - start < 5) { /* wait */ }
  assert.equal(cache.get('k1'), undefined);
});

test('PaymentCache max-size eviction', () => {
  const cache = new PaymentCache(60000, 2);
  cache.set('a', 1);
  cache.set('b', 2);
  cache.set('c', 3); // should evict 'a'
  assert.equal(cache.get('a'), undefined);
  assert.equal(cache.get('b'), 2);
  assert.equal(cache.get('c'), 3);
});

test('RateLimiter allows up to max', () => {
  const limiter = new RateLimiter(60000, 3);
  assert.equal(limiter.check('ip1'), true);
  assert.equal(limiter.check('ip1'), true);
  assert.equal(limiter.check('ip1'), true);
});

test('RateLimiter blocks after max', () => {
  const limiter = new RateLimiter(60000, 2);
  limiter.check('ip1');
  limiter.check('ip1');
  assert.equal(limiter.check('ip1'), false);
});

test('RateLimiter resets after window', () => {
  const limiter = new RateLimiter(1, 1); // 1ms window
  limiter.check('ip1');
  const start = Date.now();
  while (Date.now() - start < 5) { /* wait */ }
  assert.equal(limiter.check('ip1'), true);
});

test('challengePage returns HTML with nonce and return_to', () => {
  const html = challengePage('/foo', '12345.abcdef');
  assert.ok(html.includes('<!DOCTYPE html'));
  assert.ok(html.includes('12345.abcdef'));
  assert.ok(html.includes('/foo'));
});

test('challengePage sanitizes non-slash return_to', () => {
  const html = challengePage('https://evil.com', '12345.abcdef');
  assert.ok(html.includes('"/"'));
  assert.ok(!html.includes('evil.com'));
});
