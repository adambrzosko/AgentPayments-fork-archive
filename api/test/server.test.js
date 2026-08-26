'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

process.env.NODE_ENV = 'test';
process.env.PLATFORM_MASTER_SECRET = 'test-master-secret-do-not-use-in-prod';
process.env.DATA_FILE = path.join(__dirname, 'vendors.test.json');
// STRIPE_SECRET_KEY intentionally left unset — verifies the graceful no-op path.
delete process.env.STRIPE_SECRET_KEY;
delete process.env.SMTP_HOST;

const request = require('supertest');
const { app } = require('../server');

function resetStore() {
  fs.writeFileSync(process.env.DATA_FILE, JSON.stringify({ vendors: {}, apiKeys: {}, verificationTokens: {} }, null, 2));
}

// The registration rate limiter (5/hour) is a single in-memory Map shared by the
// whole test process. Give each test its own fake IP via X-Forwarded-For so tests
// don't consume each other's limiter budget.
let ipCounter = 0;
function register(body) {
  ipCounter += 1;
  return request(app)
    .post('/v1/vendors/register')
    .set('X-Forwarded-For', `10.0.0.${ipCounter}`)
    .send(body);
}

test.after(() => {
  fs.rmSync(process.env.DATA_FILE, { force: true });
});

test('/v1/account returns platformFeeWallet: null when PLATFORM_FEE_WALLET is unset', async () => {
  resetStore();
  const reg = await register({ email: 'no-fee-vendor@test.com', name: 'No Fee Vendor' });
  const account = await request(app).get('/v1/account').set('Authorization', `Bearer ${reg.body.apiKey}`);
  assert.equal(account.status, 200);
  assert.equal(account.body.platformFeeWallet, null);
  assert.equal(account.body.platformFeeRatePct, null);
});

test('register -> issue key -> verify key -> usage flow (no Stripe, no email)', async () => {
  resetStore();

  const reg = await register({ email: 'vendor@test.com', name: 'Test Vendor' });
  assert.equal(reg.status, 201);
  assert.ok(reg.body.apiKey.startsWith('ap_live_'));
  assert.equal(reg.body.emailVerificationRequired, false);

  const issue = await request(app).post('/v1/keys/issue').set('Authorization', `Bearer ${reg.body.apiKey}`);
  assert.equal(issue.status, 200);
  assert.ok(issue.body.key.startsWith('agp_'));

  const verify = await request(app).post('/v1/keys/verify').send({ key: issue.body.key });
  assert.equal(verify.status, 200);
  assert.equal(verify.body.valid, true);

  const usage = await request(app).get('/v1/usage').set('Authorization', `Bearer ${reg.body.apiKey}`);
  assert.equal(usage.status, 200);
  assert.equal(usage.body.keysIssuedAllTime, 1);
  assert.equal(usage.body.billing, null);
});

test('rejects unauthenticated /v1/keys/issue', async () => {
  resetStore();
  const res = await request(app).post('/v1/keys/issue');
  assert.equal(res.status, 401);
});

test('rejects a bad Authorization scheme on /v1/keys/issue', async () => {
  resetStore();
  const res = await request(app).post('/v1/keys/issue').set('Authorization', 'Basic dXNlcjpwYXNz');
  assert.equal(res.status, 401);
});

test('/v1/keys/verify rejects a forged/malformed key', async () => {
  resetStore();
  const malformed = await request(app).post('/v1/keys/verify').send({ key: 'not-a-real-key' });
  assert.equal(malformed.status, 400);

  const reg = await register({ email: 'forge@test.com', name: 'Forge Vendor' });
  const forged = await request(app).post('/v1/keys/verify').send({ key: `agp_${reg.body.vendorId}_deadbeef_0000000000000000` });
  assert.equal(forged.status, 200);
  assert.equal(forged.body.valid, false);
});

test('rejects duplicate email registration with 409', async () => {
  resetStore();
  await register({ email: 'dup@test.com', name: 'First' });
  const dup = await register({ email: 'dup@test.com', name: 'Second' });
  assert.equal(dup.status, 409);
});

test('rejects bad email/name on registration with 400', async () => {
  resetStore();
  const badEmail = await register({ email: 'not-an-email', name: 'Someone' });
  assert.equal(badEmail.status, 400);

  const badName = await register({ email: 'ok@test.com', name: 'x' });
  assert.equal(badName.status, 400);
});

test('dashboard login flow sets a session cookie and renders the dashboard', async () => {
  resetStore();
  const reg = await register({ email: 'dash@test.com', name: 'Dash Vendor' });

  const login = await request(app).post('/dashboard/login').type('form').send({ key: reg.body.apiKey });
  const setCookie = login.headers['set-cookie'];
  assert.ok(setCookie && setCookie.some((c) => c.startsWith('agp_dash=')));

  const cookie = setCookie.find((c) => c.startsWith('agp_dash=')).split(';')[0];
  const dash = await request(app).get('/dashboard').set('Cookie', cookie);
  assert.equal(dash.status, 200);
  assert.ok(dash.text.includes(reg.body.vendorId));
});

test('dashboard login rejects an invalid API key without setting a session cookie', async () => {
  resetStore();
  const login = await request(app).post('/dashboard/login').type('form').send({ key: 'ap_live_bogus' });
  assert.equal(login.status, 200);
  assert.ok(!login.headers['set-cookie']);
});

test('stripe-billing module no-ops all functions when STRIPE_SECRET_KEY is unset', async () => {
  const { createCustomerAndSubscription, recordKeyIssuance, getCurrentUsage } = require('../stripe-billing');
  assert.equal(await createCustomerAndSubscription('a@b.com', 'x'), null);
  await assert.doesNotReject(recordKeyIssuance('cus_123'));
  assert.equal(await getCurrentUsage('cus_123'), null);
});
