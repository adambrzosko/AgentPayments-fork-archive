import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import request from 'supertest';

process.env.NODE_ENV = 'test';
process.env.MASTER_KEY = '0123456789012345678901234567890123456789';
process.env.PAYMENTS_DRY_RUN = 'true';

const { default: app } = await import('../app.js');

const DB_PATH = path.join(process.cwd(), 'data', 'db.json');

function resetDb() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  fs.writeFileSync(DB_PATH, JSON.stringify({ users: [], apiKeys: [], payments: [] }, null, 2));
}

test('signup + login flow', async () => {
  resetDb();
  const signup = await request(app).post('/api/signup').send({ email: 'a@test.com', password: 'verystrongpass' });
  assert.equal(signup.status, 200);
  assert.ok(signup.body.sessionToken);

  const me = await request(app).get('/api/me').set('x-session-token', signup.body.sessionToken);
  assert.equal(me.status, 200);
  assert.equal(me.body.email, 'a@test.com');

  const login = await request(app).post('/api/login').send({ email: 'a@test.com', password: 'verystrongpass' });
  assert.equal(login.status, 200);
  assert.ok(login.body.sessionToken);
});

test('tool pay enforces per-payment cap', async () => {
  resetDb();
  const signup = await request(app).post('/api/signup').send({ email: 'b@test.com', password: 'verystrongpass' });
  const sessionToken = signup.body.sessionToken;

  const key = await request(app)
    .post('/api/keys')
    .set('x-session-token', sessionToken)
    .send({ maxSolPerPayment: 0.01, dailySolCap: 0.1 });
  assert.equal(key.status, 200);

  const pay = await request(app)
    .post('/api/tool/pay')
    .set('x-wallet-tool-key', key.body.rawKey)
    .send({
      recipient: signup.body.user.walletAddress,
      amountSol: 0.02,
      reason: 'test',
      resourceUrl: 'https://example.com'
    });

  assert.equal(pay.status, 403);
  assert.match(pay.body.error, /per-payment limit/);
});

test('idempotency key replays same payment', async () => {
  resetDb();
  const signup = await request(app).post('/api/signup').send({ email: 'c@test.com', password: 'verystrongpass' });
  const sessionToken = signup.body.sessionToken;

  const key = await request(app)
    .post('/api/keys')
    .set('x-session-token', sessionToken)
    .send({ maxSolPerPayment: 0.05, dailySolCap: 0.2, allowlistedRecipients: [signup.body.user.walletAddress] });

  const idem = '11111111-1111-1111-1111-111111111111';
  const payload = { recipient: signup.body.user.walletAddress, amountSol: 0.01, reason: 't', resourceUrl: 'u' };

  const first = await request(app).post('/api/tool/pay').set('x-wallet-tool-key', key.body.rawKey).set('x-idempotency-key', idem).send(payload);
  assert.equal(first.status, 200);

  const second = await request(app).post('/api/tool/pay').set('x-wallet-tool-key', key.body.rawKey).set('x-idempotency-key', idem).send(payload);
  assert.equal(second.status, 200);
  assert.equal(second.body.replay, true);
  assert.equal(second.body.signature, first.body.signature);
});

test('GET /health returns 200', async () => {
  const res = await request(app).get('/health');
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
});

test('GET /api/me without session token returns 401', async () => {
  const res = await request(app).get('/api/me');
  assert.equal(res.status, 401);
});

test('POST /api/keys creates key and GET /api/keys lists it', async () => {
  resetDb();
  const signup = await request(app).post('/api/signup').send({ email: 'd@test.com', password: 'verystrongpass' });
  const sessionToken = signup.body.sessionToken;

  const create = await request(app)
    .post('/api/keys')
    .set('x-session-token', sessionToken)
    .send({ maxSolPerPayment: 0.05, dailySolCap: 0.2 });
  assert.equal(create.status, 200);
  assert.ok(create.body.rawKey);
  assert.ok(create.body.rawKey.startsWith('ak_'));

  const list = await request(app)
    .get('/api/keys')
    .set('x-session-token', sessionToken);
  assert.equal(list.status, 200);
  assert.ok(Array.isArray(list.body));
  assert.equal(list.body.length, 1);
  assert.equal(list.body[0].id, create.body.id);
});

test('GET /api/tool/balance returns balance with valid tool key', async () => {
  resetDb();
  const signup = await request(app).post('/api/signup').send({ email: 'e@test.com', password: 'verystrongpass' });
  const key = await request(app)
    .post('/api/keys')
    .set('x-session-token', signup.body.sessionToken)
    .send({ maxSolPerPayment: 0.05, dailySolCap: 0.2 });

  const balance = await request(app)
    .get('/api/tool/balance')
    .set('x-wallet-tool-key', key.body.rawKey);
  assert.equal(balance.status, 200);
  assert.ok('balanceSol' in balance.body);
  assert.ok('walletAddress' in balance.body);
});

test('POST /api/tool/pay rejects non-allowlisted recipient', async () => {
  resetDb();
  const signup = await request(app).post('/api/signup').send({ email: 'f@test.com', password: 'verystrongpass' });
  const key = await request(app)
    .post('/api/keys')
    .set('x-session-token', signup.body.sessionToken)
    .send({
      maxSolPerPayment: 0.05,
      dailySolCap: 0.2,
      allowlistedRecipients: [signup.body.user.walletAddress],
    });

  // Use a different valid-looking Solana address as recipient
  const otherAddr = '11111111111111111111111111111111';
  const pay = await request(app)
    .post('/api/tool/pay')
    .set('x-wallet-tool-key', key.body.rawKey)
    .send({ recipient: otherAddr, amountUsdc: 0.01, token: 'USDC', reason: 'test', resourceUrl: 'u' });
  assert.equal(pay.status, 403);
  assert.match(pay.body.error, /allowlist/);
});

test('POST /api/tool/pay enforces daily spending cap', async () => {
  resetDb();
  const signup = await request(app).post('/api/signup').send({ email: 'g@test.com', password: 'verystrongpass' });
  const key = await request(app)
    .post('/api/keys')
    .set('x-session-token', signup.body.sessionToken)
    .send({
      maxSolPerPayment: 0.05,
      dailySolCap: 0.02,
      allowlistedRecipients: [signup.body.user.walletAddress],
    });

  // First payment should succeed
  const pay1 = await request(app)
    .post('/api/tool/pay')
    .set('x-wallet-tool-key', key.body.rawKey)
    .send({ recipient: signup.body.user.walletAddress, amountUsdc: 0.01, token: 'USDC', reason: 'test', resourceUrl: 'u' });
  assert.equal(pay1.status, 200);

  // Second payment should exceed daily cap
  const pay2 = await request(app)
    .post('/api/tool/pay')
    .set('x-wallet-tool-key', key.body.rawKey)
    .send({ recipient: signup.body.user.walletAddress, amountUsdc: 0.02, token: 'USDC', reason: 'test2', resourceUrl: 'u' });
  assert.equal(pay2.status, 403);
  assert.match(pay2.body.error, /daily cap/);
});

test('GET /api/system-prompt returns non-empty string', async () => {
  resetDb();
  const signup = await request(app).post('/api/signup').send({ email: 'h@test.com', password: 'verystrongpass' });

  const res = await request(app)
    .get('/api/system-prompt?model=claude')
    .set('x-session-token', signup.body.sessionToken);
  assert.equal(res.status, 200);
  assert.equal(res.body.model, 'claude');
  assert.ok(res.body.prompt.length > 0);
});
