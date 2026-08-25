import express from 'express';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import pg from 'pg';
import { verifyPaymentOnChain, BulkVerifier } from './chain.js';

const PORT = process.env.PORT || 3100;
const DATABASE_URL = process.env.DATABASE_URL || '';
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
const HOME_WALLET_ADDRESS = process.env.HOME_WALLET_ADDRESS || '';
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';

const IS_TEST = process.env.NODE_ENV === 'test';

const bulkVerifier = (HOME_WALLET_ADDRESS && SOLANA_RPC_URL)
  ? new BulkVerifier(SOLANA_RPC_URL, HOME_WALLET_ADDRESS)
  : null;

if (!IS_TEST) {
  if (!DATABASE_URL) throw new Error('DATABASE_URL is required');
  if (!HOME_WALLET_ADDRESS) throw new Error('HOME_WALLET_ADDRESS is required');
  if (!ADMIN_SECRET || ADMIN_SECRET.length < 16) throw new Error('ADMIN_SECRET must be at least 16 chars');
}

const { Pool } = pg;
const pool = DATABASE_URL ? new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
}) : null;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS merchants (
      id TEXT PRIMARY KEY,
      name TEXT,
      api_key_hash TEXT NOT NULL,
      api_key_prefix TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS verified_payments (
      id TEXT PRIMARY KEY,
      memo TEXT NOT NULL,
      recipient TEXT NOT NULL,
      amount_usdc DOUBLE PRECISION,
      tx_signature TEXT UNIQUE NOT NULL,
      discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_verified_payments_memo_recipient
      ON verified_payments(memo, recipient);
    CREATE INDEX IF NOT EXISTS idx_merchants_api_key_prefix
      ON merchants(api_key_prefix);
  `);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hashKey(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

function generateApiKey() {
  const raw = `vk_${crypto.randomBytes(24).toString('hex')}`;
  return { raw, prefix: raw.slice(0, 11), hash: hashKey(raw) };
}

async function lookupMerchant(apiKey) {
  const prefix = apiKey.slice(0, 11);
  const hash = hashKey(apiKey);
  const result = await pool.query(
    `SELECT * FROM merchants WHERE api_key_prefix = $1 AND api_key_hash = $2 LIMIT 1`,
    [prefix, hash],
  );
  return result.rows[0] || null;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(express.json({ limit: '16kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// GET /verify?memo=...
// Auth: Authorization: Bearer <per-merchant-api-key>
// ---------------------------------------------------------------------------

app.get('/verify', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing Authorization header' });
    }
    const apiKey = auth.slice(7);
    const merchant = await lookupMerchant(apiKey);
    if (!merchant) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    const memo = String(req.query.memo || '');
    if (!memo) return res.status(400).json({ error: 'memo query param required' });

    const wallet = HOME_WALLET_ADDRESS;

    // 1. Check DB cache first
    const cached = await pool.query(
      `SELECT 1 FROM verified_payments WHERE memo = $1 AND recipient = $2 LIMIT 1`,
      [memo, wallet],
    );
    if (cached.rows.length > 0) {
      return res.json({ paid: true });
    }

    // 2. On-demand chain check (bulk-coalesced when possible)
    const result = bulkVerifier
      ? await bulkVerifier.verify(memo)
      : await verifyPaymentOnChain(SOLANA_RPC_URL, wallet, memo);
    if (result.paid) {
      // Cache the result
      const id = crypto.randomUUID();
      await pool.query(
        `INSERT INTO verified_payments (id, memo, recipient, amount_usdc, tx_signature)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (tx_signature) DO NOTHING`,
        [id, memo, wallet, result.amount, result.txSignature],
      );
      return res.json({ paid: true });
    }

    return res.json({ paid: false });
  } catch (e) {
    console.error('verify error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ---------------------------------------------------------------------------
// POST /merchants/signup  (public)
// Body: { name }
// ---------------------------------------------------------------------------

app.post('/merchants/signup', async (req, res) => {
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    const name = String(body.name || '').trim().slice(0, 200);
    if (!name) return res.status(400).json({ error: 'name is required' });

    const id = crypto.randomUUID();
    const key = generateApiKey();

    await pool.query(
      `INSERT INTO merchants (id, name, api_key_hash, api_key_prefix, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [id, name, key.hash, key.prefix],
    );

    res.json({ id, name, apiKey: key.raw });
  } catch (e) {
    console.error('signup merchant error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ---------------------------------------------------------------------------
// POST /merchants  (admin-only)
// Auth: Authorization: Bearer <ADMIN_SECRET>
// Body: { name }
// ---------------------------------------------------------------------------

app.post('/merchants', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ') || auth.slice(7) !== ADMIN_SECRET) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const name = String(req.body.name || '').slice(0, 200);
    const id = crypto.randomUUID();
    const key = generateApiKey();

    await pool.query(
      `INSERT INTO merchants (id, name, api_key_hash, api_key_prefix, created_at)
       VALUES ($1, $2, $3, $4, NOW())`,
      [id, name, key.hash, key.prefix],
    );

    res.json({ id, name, apiKey: key.raw });
  } catch (e) {
    console.error('create merchant error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ---------------------------------------------------------------------------
// GET /merchants/me  (per-merchant key auth)
// Returns wallet address and network so SDKs can auto-configure.
// ---------------------------------------------------------------------------

app.get('/merchants/me', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing Authorization header' });
    }
    const apiKey = auth.slice(7);
    const merchant = await lookupMerchant(apiKey);
    if (!merchant) {
      return res.status(401).json({ error: 'Invalid API key' });
    }

    const network = SOLANA_RPC_URL.includes('devnet') ? 'devnet' : 'mainnet';
    res.json({ walletAddress: HOME_WALLET_ADDRESS, network });
  } catch (e) {
    console.error('merchants/me error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

app.get('/health', (_req, res) => res.json({ ok: true }));

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

if (IS_TEST) {
  // In test mode, skip DB init and server listen
} else if (process.env.VERCEL) {
  // On Vercel, just ensure schema exists; no listen needed
  initDb().catch((err) => console.error('Failed to initialize DB:', err));
} else {
  initDb()
    .then(() => app.listen(PORT, () => console.log(`verify-service listening on :${PORT}`)))
    .catch((err) => { console.error('Failed to initialize DB:', err); process.exit(1); });
}

export default app;
export { hashKey, generateApiKey, initDb };
