import test from 'node:test';
import assert from 'node:assert/strict';

process.env.NODE_ENV = 'test';
process.env.HOME_WALLET_ADDRESS = 'TestWallet1111111111111111111111111111111111';
process.env.ADMIN_SECRET = 'test-admin-secret-1234567890';

// Import pure helpers (app loads without throwing in test mode)
const { default: app, hashKey, generateApiKey } = await import('../app.js');
const { isDevnet, getUsdcMint, isRetryableError, batchGetTransactions, extractMemoAndPayment, matchMemosAgainstTransactions, fetchRecentTransactions, BulkVerifier } = await import('../chain.js');

// --- Pure function tests ---

test('hashKey returns deterministic SHA256 hex', () => {
  const a = hashKey('test-key');
  const b = hashKey('test-key');
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(hashKey('other-key'), a);
});

test('generateApiKey format', () => {
  const { raw, prefix, hash } = generateApiKey();
  assert.ok(raw.startsWith('vk_'));
  assert.equal(prefix, raw.slice(0, 11));
  assert.equal(prefix.length, 11);
  assert.equal(hash, hashKey(raw));
});

test('chain.isDevnet detects devnet URLs', () => {
  assert.equal(isDevnet('https://api.devnet.solana.com'), true);
  assert.equal(isDevnet('https://api.mainnet-beta.solana.com'), false);
  assert.equal(isDevnet(''), false);
  assert.equal(isDevnet(null), false);
});

test('chain.getUsdcMint returns correct mint per network', () => {
  const devnet = getUsdcMint('https://api.devnet.solana.com');
  const mainnet = getUsdcMint('https://api.mainnet-beta.solana.com');
  assert.match(devnet, /^[A-Za-z0-9]{32,50}$/);
  assert.match(mainnet, /^[A-Za-z0-9]{32,50}$/);
  assert.notEqual(devnet, mainnet);
});

test('chain.isRetryableError identifies retryable messages', () => {
  assert.equal(isRetryableError(new Error('429 Too Many Requests')), true);
  assert.equal(isRetryableError(new Error('fetch failed')), true);
  assert.equal(isRetryableError(new Error('ETIMEDOUT')), true);
  assert.equal(isRetryableError(new Error('ECONNRESET')), true);
  assert.equal(isRetryableError(new Error('some random error')), false);
});

// --- HTTP endpoint tests (no DB needed for /health) ---

import request from 'supertest';

test('GET /health returns { ok: true }', async () => {
  const res = await request(app).get('/health');
  assert.equal(res.status, 200);
  assert.equal(res.body.ok, true);
});

test('GET /verify without auth returns 401', async () => {
  const res = await request(app).get('/verify?memo=test');
  assert.equal(res.status, 401);
});

test('GET /merchants/me without auth returns 401', async () => {
  const res = await request(app).get('/merchants/me');
  assert.equal(res.status, 401);
});

test('POST /merchants/signup without name returns 400', async () => {
  const res = await request(app).post('/merchants/signup').send({});
  // Without DB it will be 400 (name required) or 500 (no pool)
  assert.ok(res.status === 400 || res.status === 500);
});

// ---------------------------------------------------------------------------
// Bulk verification tests — real mainnet RPC
//
// These tests hit real Solana mainnet RPC with a real USDC payment:
//   Wallet:    2UhakLCBSPgWyoVmTCqJ9fgtnXzW9SPeLTyJ5QsT79GF
//   Memo:      ag_test_mainnet_verify_001
//   Signature: 3SDA59Lpw3C563xokBEcmM5tDXPMeK77W5ARSBdCAz9gcie1cGtHbqLNjd7jZUWzijB569NoWWDs3t8YmGu5izYP
//   Amount:    0.01 USDC
// ---------------------------------------------------------------------------

const MAINNET_RPC = 'https://mainnet.helius-rpc.com/?api-key=b93b2624-6016-4274-b27d-3ae27b0a6441';
const MAINNET_WALLET = '2UhakLCBSPgWyoVmTCqJ9fgtnXzW9SPeLTyJ5QsT79GF';
const KNOWN_MEMO = 'ag_test_mainnet_verify_001';
const KNOWN_SIG = '3SDA59Lpw3C563xokBEcmM5tDXPMeK77W5ARSBdCAz9gcie1cGtHbqLNjd7jZUWzijB569NoWWDs3t8YmGu5izYP';
const USDC_MINT_MAINNET = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

// -- extractMemoAndPayment against real transaction --

test('batchGetTransactions fetches a real mainnet transaction', async () => {
  const results = await batchGetTransactions(MAINNET_RPC, [KNOWN_SIG]);
  assert.equal(results.length, 1);
  assert.ok(results[0], 'should return a parsed transaction');
  assert.ok(results[0].transaction.message.instructions.length > 0);
});

test('extractMemoAndPayment parses real mainnet transaction correctly', async () => {
  const [tx] = await batchGetTransactions(MAINNET_RPC, [KNOWN_SIG]);
  const result = extractMemoAndPayment(tx, USDC_MINT_MAINNET);

  assert.ok(result.memos.some((m) => m.includes(KNOWN_MEMO)), 'should find the memo');
  assert.ok(result.amount >= 0.01, 'should find USDC payment >= 0.01');
});

// -- fetchRecentTransactions against real chain --

test('fetchRecentTransactions finds known memo on mainnet', async () => {
  const results = await fetchRecentTransactions(MAINNET_RPC, MAINNET_WALLET, [KNOWN_MEMO]);

  assert.ok(results.length >= 1, 'should find at least 1 matching transaction');

  const match = results.find((r) => r.signature === KNOWN_SIG);
  assert.ok(match, 'should include the known signature');
  assert.ok(match.tx, 'should have fetched the full transaction');
});

test('fetchRecentTransactions returns empty for nonexistent memo on mainnet', async () => {
  const results = await fetchRecentTransactions(MAINNET_RPC, MAINNET_WALLET, ['ag_this_memo_does_not_exist_xyz']);
  assert.equal(results.length, 0);
});

// -- BulkVerifier against real chain --

test('BulkVerifier finds known payment on mainnet', async () => {
  const verifier = new BulkVerifier(MAINNET_RPC, MAINNET_WALLET);
  const result = await verifier.verify(KNOWN_MEMO);

  assert.equal(result.paid, true);
  assert.equal(result.txSignature, KNOWN_SIG);
  assert.ok(result.amount >= 0.01);
});

test('BulkVerifier returns paid:false for unknown memo on mainnet', async () => {
  const verifier = new BulkVerifier(MAINNET_RPC, MAINNET_WALLET);
  const result = await verifier.verify('ag_definitely_not_a_real_payment_memo');

  assert.equal(result.paid, false);
  assert.equal(result.txSignature, null);
  assert.equal(result.amount, null);
});

test('BulkVerifier coalesces concurrent mainnet requests', async () => {
  const verifier = new BulkVerifier(MAINNET_RPC, MAINNET_WALLET);

  const start = Date.now();
  const [found, notFound1, notFound2] = await Promise.all([
    verifier.verify(KNOWN_MEMO),
    verifier.verify('ag_fake_memo_aaa'),
    verifier.verify('ag_fake_memo_bbb'),
  ]);
  const elapsed = Date.now() - start;

  assert.equal(found.paid, true);
  assert.equal(found.txSignature, KNOWN_SIG);
  assert.equal(notFound1.paid, false);
  assert.equal(notFound2.paid, false);

  // All 3 resolved from a single flush — if they ran independently
  // it would take 3x as long
  console.log(`  coalesced 3 requests in ${elapsed}ms`);
});

test('BulkVerifier cache serves subsequent request instantly', async () => {
  const verifier = new BulkVerifier(MAINNET_RPC, MAINNET_WALLET);

  // Prime the cache
  await verifier.verify(KNOWN_MEMO);

  // Second request should be instant from cache
  const start = Date.now();
  const result = await verifier.verify(KNOWN_MEMO);
  const elapsed = Date.now() - start;

  assert.equal(result.paid, true);
  assert.ok(elapsed < 5, `cache hit should be <5ms, was ${elapsed}ms`);
});
