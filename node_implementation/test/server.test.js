const test = require('node:test');
const assert = require('node:assert/strict');

process.env.NODE_ENV = 'test';
process.env.CHALLENGE_SECRET = 'test-secret';

const request = require('supertest');
const app = require('../server');

test('/.well-known/agent-access.json returns valid JSON', async () => {
  const res = await request(app).get('/.well-known/agent-access.json');
  assert.equal(res.status, 200);
  assert.ok(res.headers['content-type'].includes('json'));
  assert.ok(res.body);
});

test('/robots.txt returns content', async () => {
  const res = await request(app).get('/robots.txt');
  assert.equal(res.status, 200);
  assert.ok(res.text.length > 0);
});

test('catch-all serves index.html', async () => {
  // Browser request (with sec-fetch-mode to bypass gate challenge)
  const res = await request(app)
    .get('/some-random-page')
    .set('sec-fetch-mode', 'navigate')
    .set('Cookie', '');
  // Should get either 200 (challenge page) since no valid cookie
  assert.equal(res.status, 200);
  assert.ok(res.headers['content-type'].includes('text/html'));
});

test('agent request without key gets 402 with a fresh agent key', async () => {
  const res = await request(app).get('/api/data');
  assert.equal(res.status, 402);
  assert.equal(res.body.error, 'payment_required');
  assert.ok(res.body.your_key);
});
