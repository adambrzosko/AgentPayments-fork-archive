/**
 * Test script to verify that the ATA derivation in sdk/node/index.js
 * produces the correct Associated Token Account address.
 *
 * Uses the same implementation copied from sdk/node/index.js since
 * those functions are not exported.
 */
const crypto = require('node:crypto');

// --- Copied from sdk/node/index.js ---

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ED25519_P = 2n ** 255n - 19n;
const ED25519_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const ASSOCIATED_TOKEN_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const TOKEN_PROGRAM_ADDR = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';

function b58decode(s) {
  let n = 0n;
  for (const c of s) n = n * 58n + BigInt(B58.indexOf(c));
  const out = [];
  while (n > 0n) { out.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const c of s) { if (c !== '1') break; out.unshift(0); }
  while (out.length < 32) out.unshift(0);
  return new Uint8Array(out);
}

function b58encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; s = '1' + s; }
  return s;
}

function modpow(b, e, m) {
  let r = 1n; b = ((b % m) + m) % m;
  while (e > 0n) { if (e & 1n) r = r * b % m; e >>= 1n; b = b * b % m; }
  return r;
}

function isOnCurve(bytes) {
  let y = 0n;
  for (let i = 0; i < 32; i++) y += BigInt(i === 31 ? bytes[i] & 0x7f : bytes[i]) << BigInt(8 * i);
  if (y >= ED25519_P) return false;
  const y2 = y * y % ED25519_P;
  const x2 = (y2 - 1n + ED25519_P) % ED25519_P * modpow((1n + ED25519_D * y2) % ED25519_P, ED25519_P - 2n, ED25519_P) % ED25519_P;
  if (x2 === 0n) return true;
  return modpow(x2, (ED25519_P - 1n) / 2n, ED25519_P) === 1n;
}

function deriveAta(owner, mint) {
  const seeds = [b58decode(owner), b58decode(TOKEN_PROGRAM_ADDR), b58decode(mint)];
  const programId = b58decode(ASSOCIATED_TOKEN_PROGRAM);
  const suffix = Buffer.from('ProgramDerivedAddress');
  for (let bump = 255; bump >= 0; bump--) {
    const buf = Buffer.concat([...seeds, Buffer.from([bump]), programId, suffix]);
    const hash = crypto.createHash('sha256').update(buf).digest();
    if (!isOnCurve(hash)) return b58encode(hash);
  }
  return null;
}

// --- End copied section ---

// Test parameters
const WALLET = '5rXZeAEbg13DQnSFijEno2hKEJLK2p14fAo3AmPtfBft';
const DEVNET_USDC_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const EXPECTED_ATA = 'Aj7cGsyxCRHp8U25CX8AFTCSa2XhKNp5s7ZELRmeT32Z';

console.log('=== ATA Derivation Test ===\n');
console.log('Wallet:         ', WALLET);
console.log('USDC Mint:      ', DEVNET_USDC_MINT);
console.log('Expected ATA:   ', EXPECTED_ATA);
console.log('');

// Test 1: b58decode roundtrip
console.log('--- Test 1: b58 encode/decode roundtrip ---');
const decoded = b58decode(WALLET);
console.log('Decoded wallet length:', decoded.length, '(expected 32)');
const reencoded = b58encode(decoded);
console.log('Re-encoded wallet:   ', reencoded);
console.log('Roundtrip match:     ', reencoded === WALLET ? 'PASS' : 'FAIL');
console.log('');

// Test 2: b58decode roundtrip for USDC mint
console.log('--- Test 2: b58 roundtrip for USDC mint ---');
const decodedMint = b58decode(DEVNET_USDC_MINT);
console.log('Decoded mint length: ', decodedMint.length, '(expected 32)');
const reencodedMint = b58encode(decodedMint);
console.log('Re-encoded mint:     ', reencodedMint);
console.log('Roundtrip match:     ', reencodedMint === DEVNET_USDC_MINT ? 'PASS' : 'FAIL');
console.log('');

// Test 3: isOnCurve sanity check (the wallet public key should be on curve)
console.log('--- Test 3: isOnCurve sanity ---');
console.log('Wallet on curve:     ', isOnCurve(decoded) ? 'yes (expected for a valid pubkey)' : 'no');
console.log('');

// Test 4: Derive ATA
console.log('--- Test 4: ATA Derivation ---');
const derived = deriveAta(WALLET, DEVNET_USDC_MINT);
console.log('Derived ATA:         ', derived);
console.log('Expected ATA:        ', EXPECTED_ATA);
console.log('Match:               ', derived === EXPECTED_ATA ? 'PASS' : 'FAIL');
console.log('');

// Also check with known mainnet USDC for completeness
const MAINNET_USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
console.log('--- Test 5: Mainnet USDC ATA derivation (no expected value, just no-error check) ---');
const mainnetAta = deriveAta(WALLET, MAINNET_USDC_MINT);
console.log('Mainnet USDC ATA:    ', mainnetAta);
console.log('Non-null:            ', mainnetAta !== null ? 'PASS' : 'FAIL');
console.log('');

// Summary
const allPassed =
  reencoded === WALLET &&
  reencodedMint === DEVNET_USDC_MINT &&
  derived === EXPECTED_ATA &&
  mainnetAta !== null;

if (allPassed) {
  console.log('=== ALL TESTS PASSED ===');
  process.exit(0);
} else {
  console.log('=== SOME TESTS FAILED ===');
  process.exit(1);
}
