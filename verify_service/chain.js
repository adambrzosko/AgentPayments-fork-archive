/**
 * On-chain USDC payment verification for Solana.
 * Ported from scripts/verify_payment.py.
 *
 * Scans recent transactions on a wallet's USDC token accounts
 * looking for a transfer with a matching memo.
 */

import { Connection, PublicKey } from '@solana/web3.js';
import { TOKEN_PROGRAM_ID } from '@solana/spl-token';

const USDC_MINT_DEVNET = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const USDC_MINT_MAINNET = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const MIN_PAYMENT_USDC = 0.01;
const SIG_SCAN_LIMIT = 20;
const RPC_RETRIES = 3;
const TIME_BUDGET_MS = 8000;
const MAX_TX_TO_PARSE = 14;
const RETRYABLE_MESSAGES = ['429', 'Too Many Requests', 'fetch failed', 'ETIMEDOUT', 'ECONNRESET'];

function isDevnet(rpcUrl) {
  return String(rpcUrl || '').toLowerCase().includes('devnet');
}

function getUsdcMint(rpcUrl) {
  return isDevnet(rpcUrl) ? USDC_MINT_DEVNET : USDC_MINT_MAINNET;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableError(err) {
  const msg = String(err?.message || err || '');
  return RETRYABLE_MESSAGES.some((s) => msg.includes(s));
}

async function withRpcRetry(fn, label) {
  let lastErr;
  for (let i = 0; i < RPC_RETRIES; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (!isRetryableError(err) || i === RPC_RETRIES - 1) {
        throw err;
      }
      const waitMs = 250 * Math.pow(2, i);
      console.warn(`[verify-service] ${label} retry ${i + 1}/${RPC_RETRIES} after error: ${String(err?.message || err)}`);
      await sleep(waitMs);
    }
  }
  throw lastErr;
}

/**
 * Get all USDC token account addresses owned by a wallet.
 */
async function getTokenAccounts(connection, walletAddress, usdcMint) {
  const owner = new PublicKey(walletAddress);
  const mint = new PublicKey(usdcMint);
  const resp = await connection.getParsedTokenAccountsByOwner(owner, { mint }, 'confirmed');
  return resp.value.map((a) => a.pubkey.toBase58());
}

/**
 * Scan recent transactions on a wallet for a USDC payment with a matching memo.
 *
 * @param {string} rpcUrl - Solana RPC URL
 * @param {string} walletAddress - Recipient wallet to scan
 * @param {string} memo - Memo string to match (the agent key)
 * @returns {{ paid: boolean, txSignature: string|null, amount: number|null }}
 */
// ---------------------------------------------------------------------------
// Batch JSON-RPC helpers
// ---------------------------------------------------------------------------

const BATCH_CHUNK_SIZE = 100;

/**
 * Fetch multiple parsed transactions in parallel.
 * Returns an array of parsed transaction objects (null for failures).
 */
async function batchGetTransactions(rpcUrl, signatures) {
  if (signatures.length === 0) return [];

  const results = await Promise.all(
    signatures.map(async (sig) => {
      try {
        return await withRpcRetry(async () => {
          const r = await fetch(rpcUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              jsonrpc: '2.0', id: 1, method: 'getTransaction',
              params: [sig, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0, commitment: 'confirmed' }],
            }),
          });
          if (!r.ok) throw new Error(`RPC HTTP ${r.status}`);
          const json = await r.json();
          return json.result || null;
        }, 'getTransaction');
      } catch (err) {
        console.warn(`[verify-service] getTransaction failed for ${sig}: ${err.message}`);
        return null;
      }
    })
  );

  return results;
}

/**
 * Extract memo text and USDC payment amount from a parsed transaction.
 * Returns { memos: string[], amount: number|null }.
 */
function extractMemoAndPayment(tx, usdcMint) {
  if (!tx?.transaction?.message?.instructions) return { memos: [], amount: null };

  const instructions = tx.transaction.message.instructions || [];
  const innerGroups = tx.meta?.innerInstructions || [];
  const allIx = [...instructions];
  for (const group of innerGroups) {
    allIx.push(...(group.instructions || []));
  }

  const memos = [];
  let paymentAmount = null;

  for (const ix of allIx) {
    const program = ix.program || '';
    const programId = typeof ix.programId === 'string' ? ix.programId : ix.programId?.toBase58?.() || '';

    // Memo
    if (program === 'spl-memo' || programId === MEMO_PROGRAM_ID) {
      const parsed = ix.parsed || '';
      memos.push(typeof parsed === 'string' ? parsed : String(parsed));
    }

    // USDC transfer
    if (program === 'spl-token') {
      const parsed = ix.parsed || {};
      const txType = parsed.type || '';
      if (txType === 'transfer' || txType === 'transferChecked') {
        const info = parsed.info || {};
        if (txType === 'transferChecked' && info.mint !== usdcMint) continue;

        const tokenAmount = info.tokenAmount || {};
        let uiAmount = tokenAmount.uiAmount;
        if (uiAmount == null) {
          uiAmount = parseInt(info.amount || '0', 10) / 1e6;
        }
        if (uiAmount >= MIN_PAYMENT_USDC) {
          paymentAmount = uiAmount;
        }
      }
    }
  }

  return { memos, amount: paymentAmount };
}

/**
 * Fetch recent signatures for a wallet's USDC token accounts, filter by memo
 * match client-side, then batch-fetch only the matched transactions.
 *
 * getSignaturesForAddress returns a `memo` field on each signature, so we
 * can avoid fetching transactions that can't possibly match.
 *
 * @param {string} rpcUrl
 * @param {string} walletAddress
 * @param {string[]} memos - memos to match against (empty = fetch all)
 * @param {object} [opts]
 * @param {object} [opts.connection] - optional pre-built Connection (for testing)
 * @returns {Promise<Array<{ signature: string, tx: object|null }>>}
 */
async function fetchRecentTransactions(rpcUrl, walletAddress, memos = [], opts = {}) {
  const connection = opts.connection || new Connection(rpcUrl, 'confirmed');
  const usdcMint = getUsdcMint(rpcUrl);

  let tokenAccounts = [];
  try {
    tokenAccounts = await withRpcRetry(
      () => getTokenAccounts(connection, walletAddress, usdcMint),
      'getTokenAccountsByOwner'
    );
  } catch { /* fall through to main wallet */ }

  const addressesToScan = tokenAccounts.length > 0
    ? [...tokenAccounts, walletAddress]
    : [walletAddress];

  const seen = new Set();
  const matchedSigs = [];
  for (const addr of addressesToScan) {
    let sigs = [];
    try {
      sigs = await withRpcRetry(
        () => connection.getSignaturesForAddress(new PublicKey(addr), { limit: SIG_SCAN_LIMIT }, 'confirmed'),
        'getSignaturesForAddress'
      );
    } catch (err) {
      console.warn(`[verify-service] failed to fetch signatures for ${addr}: ${err.message}`);
      continue;
    }
    for (const s of sigs) {
      if (s.err || seen.has(s.signature)) continue;
      seen.add(s.signature);

      // Filter client-side: only fetch transactions whose memo matches
      if (memos.length > 0 && s.memo) {
        if (memos.some((m) => s.memo.includes(m))) {
          matchedSigs.push(s.signature);
        }
      } else if (memos.length === 0) {
        matchedSigs.push(s.signature);
      }
      // If s.memo is null and memos requested, skip — no memo means no match
    }
  }

  const txs = await batchGetTransactions(rpcUrl, matchedSigs);
  return matchedSigs.map((sig, i) => ({ signature: sig, tx: txs[i] }));
}

/**
 * Match a set of memos against a list of fetched transactions.
 * Returns a Map<memo, { paid, txSignature, amount }>.
 */
function matchMemosAgainstTransactions(memos, transactions, usdcMint) {
  const results = new Map();
  for (const memo of memos) {
    results.set(memo, { paid: false, txSignature: null, amount: null });
  }

  for (const { signature, tx } of transactions) {
    if (!tx) continue;
    const { memos: txMemos, amount } = extractMemoAndPayment(tx, usdcMint);
    if (!amount) continue;

    for (const memo of memos) {
      if (results.get(memo).paid) continue;
      if (txMemos.some((m) => m.includes(memo))) {
        results.set(memo, { paid: true, txSignature: signature, amount });
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// BulkVerifier — coalesces concurrent verify requests
// ---------------------------------------------------------------------------

const COALESCE_WINDOW_MS = 50;
const COALESCE_MAX_PENDING = 20;
const TX_CACHE_TTL_MS = 2000;

class BulkVerifier {
  /**
   * @param {string} rpcUrl
   * @param {string} walletAddress
   * @param {object} [opts]
   * @param {object} [opts.connection] - optional pre-built Connection (for testing)
   */
  constructor(rpcUrl, walletAddress, opts = {}) {
    this.rpcUrl = rpcUrl;
    this.walletAddress = walletAddress;
    this.usdcMint = getUsdcMint(rpcUrl);
    this._connection = opts.connection || null;

    // Pending requests waiting for the next bulk fetch
    this._pending = new Map(); // memo -> { resolve, reject }[]
    this._timer = null;

    // Short-lived transaction cache
    this._txCache = null;        // { transactions, fetchedAt }
  }

  /**
   * Verify a single memo. Coalesces with other concurrent calls.
   * @returns {Promise<{ paid: boolean, txSignature: string|null, amount: number|null }>}
   */
  verify(memo) {
    // Check if we have a fresh cache we can answer from immediately
    if (this._txCache && Date.now() - this._txCache.fetchedAt < TX_CACHE_TTL_MS) {
      const results = matchMemosAgainstTransactions(
        [memo], this._txCache.transactions, this.usdcMint
      );
      return Promise.resolve(results.get(memo));
    }

    return new Promise((resolve, reject) => {
      if (!this._pending.has(memo)) {
        this._pending.set(memo, []);
      }
      this._pending.get(memo).push({ resolve, reject });

      // Start coalescing timer on first pending request
      if (this._pending.size === 1) {
        this._timer = setTimeout(() => this._flush(), COALESCE_WINDOW_MS);
      }

      // Flush immediately if we hit the cap
      if (this._pending.size >= COALESCE_MAX_PENDING) {
        clearTimeout(this._timer);
        this._flush();
      }
    });
  }

  async _flush() {
    this._timer = null;
    const batch = this._pending;
    this._pending = new Map();

    const memos = [...batch.keys()];

    try {
      const fetchOpts = this._connection ? { connection: this._connection } : {};
      const transactions = await fetchRecentTransactions(this.rpcUrl, this.walletAddress, memos, fetchOpts);
      this._txCache = { transactions, fetchedAt: Date.now() };

      const results = matchMemosAgainstTransactions(memos, transactions, this.usdcMint);

      for (const [memo, waiters] of batch) {
        const result = results.get(memo) || { paid: false, txSignature: null, amount: null };
        for (const w of waiters) w.resolve(result);
      }
    } catch (err) {
      for (const [, waiters] of batch) {
        for (const w of waiters) w.reject(err);
      }
    }
  }
}

export { isDevnet, getUsdcMint, isRetryableError, batchGetTransactions, extractMemoAndPayment, matchMemosAgainstTransactions, fetchRecentTransactions, BulkVerifier };

export async function verifyPaymentOnChain(rpcUrl, walletAddress, memo) {
  const startedAt = Date.now();
  const isTimedOut = () => Date.now() - startedAt > TIME_BUDGET_MS;

  const connection = new Connection(rpcUrl, 'confirmed');
  const usdcMint = getUsdcMint(rpcUrl);

  // Collect addresses to scan. Prioritize USDC token accounts first because
  // payments land there; scanning the main wallet first can waste the time budget.
  let tokenAccounts = [];
  try {
    tokenAccounts = await withRpcRetry(
      () => getTokenAccounts(connection, walletAddress, usdcMint),
      'getTokenAccountsByOwner'
    );
  } catch {
    // If token account lookup fails, still try the main wallet
  }

  const addressesToScan = tokenAccounts.length > 0
    ? [...tokenAccounts, walletAddress]
    : [walletAddress];

  // Gather unique signatures across all addresses
  const seen = new Set();
  const allSigs = [];
  for (const addr of addressesToScan) {
    if (isTimedOut()) {
      console.warn('[verify-service] time budget exceeded while fetching signatures');
      break;
    }

    let sigs = [];
    try {
      sigs = await withRpcRetry(
        () => connection.getSignaturesForAddress(new PublicKey(addr), { limit: SIG_SCAN_LIMIT }, 'confirmed'),
        'getSignaturesForAddress'
      );
    } catch (err) {
      console.warn(`[verify-service] failed to fetch signatures for ${addr}: ${String(err?.message || err)}`);
      continue;
    }

    for (const s of sigs) {
      if (!seen.has(s.signature)) {
        seen.add(s.signature);
        allSigs.push(s);
      }
    }
  }

  // Check each transaction for memo + USDC transfer
  let parsedCount = 0;
  for (const sigInfo of allSigs) {
    if (parsedCount >= MAX_TX_TO_PARSE) {
      console.warn('[verify-service] tx parse cap reached');
      break;
    }
    if (isTimedOut()) {
      console.warn('[verify-service] time budget exceeded while scanning transactions');
      break;
    }

    if (sigInfo.err) continue;

    let tx;
    try {
      parsedCount += 1;
      tx = await withRpcRetry(
        () => connection.getParsedTransaction(sigInfo.signature, {
          maxSupportedTransactionVersion: 0,
          commitment: 'confirmed',
        }),
        'getParsedTransaction'
      );
    } catch (err) {
      console.warn(`[verify-service] failed to fetch transaction ${sigInfo.signature}: ${String(err?.message || err)}`);
      continue;
    }
    if (!tx) continue;

    const instructions = tx.transaction.message.instructions || [];
    const innerGroups = tx.meta?.innerInstructions || [];
    const allIx = [...instructions];
    for (const group of innerGroups) {
      allIx.push(...(group.instructions || []));
    }

    let hasMemo = false;
    let hasPayment = false;
    let paymentAmount = null;

    for (const ix of allIx) {
      // Check memo
      const program = ix.program || '';
      const programId = typeof ix.programId === 'string' ? ix.programId : ix.programId?.toBase58?.() || '';
      if (program === 'spl-memo' || programId === MEMO_PROGRAM_ID) {
        const parsed = ix.parsed || '';
        const memoText = typeof parsed === 'string' ? parsed : String(parsed);
        if (memoText.includes(memo)) {
          hasMemo = true;
        }
      }

      // Check USDC transfer
      if (program === 'spl-token') {
        const parsed = ix.parsed || {};
        const txType = parsed.type || '';
        if (txType === 'transfer' || txType === 'transferChecked') {
          const info = parsed.info || {};

          // For transferChecked, verify it's the right USDC mint
          if (txType === 'transferChecked' && info.mint !== usdcMint) continue;

          // Parse amount
          const tokenAmount = info.tokenAmount || {};
          let uiAmount = tokenAmount.uiAmount;
          if (uiAmount == null) {
            const raw = info.amount || '0';
            uiAmount = parseInt(raw, 10) / 1e6;
          }

          if (uiAmount >= MIN_PAYMENT_USDC) {
            hasPayment = true;
            paymentAmount = uiAmount;
          }
        }
      }
    }

    if (hasMemo && hasPayment) {
      return { paid: true, txSignature: sigInfo.signature, amount: paymentAmount };
    }
  }

  return { paid: false, txSignature: null, amount: null };
}
