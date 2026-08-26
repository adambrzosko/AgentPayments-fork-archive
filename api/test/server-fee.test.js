'use strict';

// Separate process/file from server.test.js: PLATFORM_FEE_WALLET is read once at
// module-load time, so it must be set before the very first `require('../server')`.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

process.env.NODE_ENV = 'test';
process.env.PLATFORM_MASTER_SECRET = 'test-master-secret-do-not-use-in-prod';
process.env.DATA_FILE = path.join(__dirname, 'vendors.fee-test.json');
process.env.PLATFORM_FEE_WALLET = '11111111111111111111111111111111';
process.env.PLATFORM_FEE_RATE_PCT = '2';
delete process.env.STRIPE_SECRET_KEY;
delete process.env.SMTP_HOST;

const request = require('supertest');
const { app } = require('../server');

function resetStore() {
  fs.writeFileSync(process.env.DATA_FILE, JSON.stringify({ vendors: {}, apiKeys: {}, verificationTokens: {} }, null, 2));
}

let ipCounter = 0;
function register(body) {
  ipCounter += 1;
  return request(app)
    .post('/v1/vendors/register')
    .set('X-Forwarded-For', `10.0.1.${ipCounter}`)
    .send(body);
}

test.after(() => {
  fs.rmSync(process.env.DATA_FILE, { force: true });
});

test('/v1/account returns the configured platform fee wallet and rate', async () => {
  resetStore();
  const reg = await register({ email: 'fee-vendor@test.com', name: 'Fee Vendor' });
  assert.equal(reg.status, 201);

  const account = await request(app).get('/v1/account').set('Authorization', `Bearer ${reg.body.apiKey}`);
  assert.equal(account.status, 200);
  assert.equal(account.body.platformFeeWallet, '11111111111111111111111111111111');
  assert.equal(account.body.platformFeeRatePct, 2);
});
