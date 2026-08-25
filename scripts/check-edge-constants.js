#!/usr/bin/env node
/**
 * check-edge-constants.js
 *
 * Validates that sdk/edge/index.js inlined constants match sdk/constants.json.
 * Run this in CI or before publishing to catch drift between the two files.
 *
 * Usage:  node scripts/check-edge-constants.js
 * Exit 0 = all match, exit 1 = mismatch(es) found.
 */

'use strict';
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const canon = JSON.parse(fs.readFileSync(path.join(root, 'sdk/constants.json'), 'utf8'));
const edgeSrc = fs.readFileSync(path.join(root, 'sdk/edge/index.js'), 'utf8');

// Constants inlined in edge/index.js that must match constants.json.
// (type determines how to parse the value from source)
const CHECKS = [
  { key: 'COOKIE_NAME',               type: 'string' },
  { key: 'COOKIE_MAX_AGE',            type: 'number' },
  { key: 'KEY_PREFIX',                type: 'string' },
  { key: 'USDC_MINT_DEVNET',          type: 'string' },
  { key: 'USDC_MINT_MAINNET',         type: 'string' },
  { key: 'RPC_DEVNET',                type: 'string' },
  { key: 'RPC_MAINNET',               type: 'string' },
  { key: 'MEMO_PROGRAM',              type: 'string' },
  { key: 'MIN_PAYMENT',               type: 'number' },
  { key: 'POW_DIFFICULTY',            type: 'number' },
  { key: 'MAX_POW_LENGTH',            type: 'number' },
  { key: 'NONCE_TTL_MS',              type: 'number' },
  { key: 'MAX_KEY_LENGTH',            type: 'number' },
  { key: 'MAX_NONCE_LENGTH',          type: 'number' },
  { key: 'MAX_RETURN_TO_LENGTH',      type: 'number' },
  { key: 'MAX_FP_LENGTH',             type: 'number' },
  { key: 'MAX_TRANSACTIONS_PER_VERIFY', type: 'number' },
  { key: 'AGENT_KEY_RATE_LIMIT_MAX',  type: 'number' },
  { key: 'USDC_DECIMALS',             type: 'number' },
  { key: 'X402_VERSION',              type: 'number' },
  { key: 'SOLANA_CHAIN_ID_MAINNET',   type: 'string' },
  { key: 'SOLANA_CHAIN_ID_DEVNET',    type: 'string' },
  { key: 'PLATFORM_API_URL',          type: 'string' },
  { key: 'HOSTED_KEY_PREFIX',         type: 'string' },
];

let failures = 0;

for (const { key, type } of CHECKS) {
  const canonValue = canon[key];
  if (canonValue === undefined) {
    console.error(`MISSING in constants.json: ${key}`);
    failures++;
    continue;
  }

  let edgeValue;
  if (type === 'string') {
    // Match: const KEY = 'value'; or const KEY = "value";
    const m = edgeSrc.match(new RegExp(`const ${key}\\s*=\\s*['"]([^'"]+)['"]`));
    edgeValue = m ? m[1] : undefined;
  } else {
    // Match: const KEY = 123; or const KEY = 123.45;
    const m = edgeSrc.match(new RegExp(`const ${key}\\s*=\\s*([\\d.]+)`));
    edgeValue = m ? Number(m[1]) : undefined;
  }

  if (edgeValue === undefined) {
    console.error(`NOT FOUND in edge/index.js: ${key}`);
    failures++;
  } else if (edgeValue !== canonValue) {
    console.error(`MISMATCH: ${key}`);
    console.error(`  constants.json : ${JSON.stringify(canonValue)}`);
    console.error(`  edge/index.js  : ${JSON.stringify(edgeValue)}`);
    failures++;
  }
}

if (failures === 0) {
  console.log(`✓ All ${CHECKS.length} edge constants match constants.json`);
  process.exit(0);
} else {
  console.error(`\n${failures} mismatch(es) found. Update sdk/edge/index.js to match sdk/constants.json.`);
  process.exit(1);
}
