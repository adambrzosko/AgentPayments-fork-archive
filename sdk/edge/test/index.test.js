import test from 'node:test';
import assert from 'node:assert/strict';
import {
  hmacSign, generateAgentKey, isValidAgentKey,
  isPublicPath, isBrowser, getCookie, isValidCookie,
  challengePage, jsonResponse, clientIdForIp,
} from '../index.js';

const SECRET = 'test-secret-edge';

test('hmacSign returns deterministic hex', async () => {
  const a = await hmacSign('hello', SECRET);
  const b = await hmacSign('hello', SECRET);
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(await hmacSign('hello', 'other'), a);
});

test('generateAgentKey produces valid format', async () => {
  const key = await generateAgentKey(SECRET);
  assert.match(key, /^ag_[0-9a-f]{16}_[0-9a-f]{16}$/);
});

test('isValidAgentKey roundtrip', async () => {
  const key = await generateAgentKey(SECRET);
  assert.equal(await isValidAgentKey(key, SECRET), true);
});

test('isValidAgentKey rejects tampered key', async () => {
  const key = await generateAgentKey(SECRET);
  const tampered = key.slice(0, -1) + (key.at(-1) === '0' ? '1' : '0');
  assert.equal(await isValidAgentKey(tampered, SECRET), false);
});

test('isValidAgentKey rejects wrong secret', async () => {
  const key = await generateAgentKey(SECRET);
  assert.equal(await isValidAgentKey(key, 'wrong'), false);
});

test('isValidAgentKey rejects empty/null/long', async () => {
  assert.equal(await isValidAgentKey('', SECRET), false);
  assert.equal(await isValidAgentKey(null, SECRET), false);
  assert.equal(await isValidAgentKey('a'.repeat(200), SECRET), false);
});

test('isPublicPath with default and custom allowlist', () => {
  assert.equal(isPublicPath('/robots.txt'), true);
  assert.equal(isPublicPath('/.well-known/foo'), true);
  assert.equal(isPublicPath('/api/data'), false);
  assert.equal(isPublicPath('/custom', ['/custom']), true);
  assert.equal(isPublicPath('/other', ['/custom']), false);
});

test('isBrowser detects sec-fetch headers on Request objects', () => {
  const browser = new Request('https://x.com', { headers: { 'sec-fetch-mode': 'navigate' } });
  assert.equal(isBrowser(browser), true);
  const agent = new Request('https://x.com', { headers: { 'user-agent': 'bot/1' } });
  assert.equal(isBrowser(agent), false);
});

test('getCookie parses from Web Request', () => {
  const req = new Request('https://x.com', { headers: { cookie: 'a=1; __agp_verified=abc; b=2' } });
  assert.equal(getCookie(req, '__agp_verified'), 'abc');
  assert.equal(getCookie(req, 'a'), '1');
  assert.equal(getCookie(req, 'missing'), null);
});

test('isValidCookie roundtrip', async () => {
  const clientIp = '1.2.3.4';
  const now = Date.now().toString();
  const clientId = await clientIdForIp(clientIp, SECRET);
  const sig = await hmacSign(`cookie:${now}:${clientId}`, SECRET);
  const req = new Request('https://x.com', { headers: { cookie: `__agp_verified=${now}.${sig}` } });
  assert.equal(await isValidCookie(req, SECRET, clientIp), true);
});

test('isValidCookie rejects missing cookie', async () => {
  const req = new Request('https://x.com');
  assert.equal(await isValidCookie(req, SECRET, '1.2.3.4'), false);
});

test('challengePage returns Response with HTML', async () => {
  const resp = challengePage('/test', '123.abc');
  assert.ok(resp instanceof Response);
  assert.equal(resp.status, 200);
  assert.equal(resp.headers.get('content-type'), 'text/html');
  const html = await resp.text();
  assert.ok(html.includes('<!DOCTYPE html'));
  assert.ok(html.includes('123.abc'));
  assert.ok(html.includes('/test'));
});

test('jsonResponse returns correct status and content-type', async () => {
  const resp = jsonResponse({ error: 'test' }, 402);
  assert.equal(resp.status, 402);
  assert.equal(resp.headers.get('content-type'), 'application/json');
  const body = await resp.json();
  assert.equal(body.error, 'test');
});
