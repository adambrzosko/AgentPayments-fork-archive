import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import bs58 from 'bs58';
import { fileURLToPath } from 'url';
import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, SystemProgram, Transaction, TransactionInstruction } from '@solana/web3.js';
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountInstruction,
  createTransferCheckedInstruction,
  getAssociatedTokenAddressSync
} from '@solana/spl-token';
import pg from 'pg';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const APP_BASE_URL = process.env.APP_BASE_URL || '';
const MASTER_KEY = process.env.MASTER_KEY || '';
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
const PAYMENTS_DRY_RUN = process.env.PAYMENTS_DRY_RUN === 'true';
const BOT_WALLET_SECRET_KEY = process.env.BOT_WALLET_SECRET_KEY || '';
const BOT_WALLET_FILE = process.env.BOT_WALLET_FILE || path.resolve(__dirname, '..', 'jsons', 'bot-wallet.json');
const FAUCET_TOPUP_SOL = 0.5;
const DATABASE_URL = process.env.DATABASE_URL || '';
const USDC_MINT_DEVNET = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const USDC_MINT_MAINNET = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const USDC_DECIMALS = 6;
const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const USE_POSTGRES = Boolean(DATABASE_URL);
const { Pool } = pg;
const pool = USE_POSTGRES ? new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
}) : null;

if (!MASTER_KEY && process.env.NODE_ENV !== 'test') {
  throw new Error('MASTER_KEY is required');
}
if (MASTER_KEY && MASTER_KEY.length < 32) {
  throw new Error('MASTER_KEY must be at least 32 chars');
}

const DB_PATH = process.env.DB_PATH || (process.env.VERCEL ? '/tmp/llm-wallet-hub-db.json' : path.join(__dirname, 'data', 'db.json'));
const explorerCluster = isDevnetRpc(SOLANA_RPC_URL) ? 'devnet' : 'mainnet-beta';
const connection = new Connection(SOLANA_RPC_URL, 'confirmed');

const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: true, limit: '64kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

initPostgres().catch((err) => {
  console.error('Failed to initialize postgres schema:', err);
});

const rate = new Map();
function rateLimit(bucket, max, windowMs) {
  return (req, res, next) => {
    const key = `${bucket}:${req.ip}`;
    const now = Date.now();
    const arr = (rate.get(key) || []).filter((t) => now - t < windowMs);
    arr.push(now);
    rate.set(key, arr);
    if (arr.length > max) return res.status(429).json({ error: 'rate limited' });
    next();
  };
}

function ensureDb() {
  if (!fs.existsSync(DB_PATH)) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify({ users: [], apiKeys: [], payments: [] }, null, 2));
  }
}

function readDb() {
  ensureDb();
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

async function initPostgres() {
  if (!USE_POSTGRES) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      wallet_public_key TEXT NOT NULL,
      wallet_encrypted_secret JSONB NOT NULL,
      policy JSONB NOT NULL,
      session_token_hash TEXT,
      session_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT true,
      max_sol_per_payment DOUBLE PRECISION,
      daily_sol_cap DOUBLE PRECISION,
      allowlisted_recipients JSONB NOT NULL DEFAULT '[]'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS payments (
      id TEXT PRIMARY KEY,
      idempotency_key TEXT,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
      recipient TEXT NOT NULL,
      amount_sol DOUBLE PRECISION NOT NULL,
      reason TEXT NOT NULL,
      resource_url TEXT NOT NULL,
      memo TEXT,
      signature TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_users_session_token_hash ON users(session_token_hash);
    CREATE INDEX IF NOT EXISTS idx_api_keys_lookup ON api_keys(key_prefix, key_hash) WHERE active = true;
    CREATE INDEX IF NOT EXISTS idx_payments_user_created_at ON payments(user_id, created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_user_idem ON payments(user_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_payments_memo_recipient ON payments(memo, recipient) WHERE memo IS NOT NULL;

    -- Migration: add memo column to existing payments tables
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS memo TEXT;
  `);
}

function mapUserRow(row) {
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.password_hash,
    wallet: {
      publicKey: row.wallet_public_key,
      encryptedSecret: row.wallet_encrypted_secret
    },
    policy: row.policy,
    sessionTokenHash: row.session_token_hash,
    sessionExpiresAt: row.session_expires_at ? new Date(row.session_expires_at).toISOString() : null,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null
  };
}

function mapApiKeyRow(row) {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    keyPrefix: row.key_prefix,
    keyHash: row.key_hash,
    active: row.active,
    maxSolPerPayment: row.max_sol_per_payment,
    dailySolCap: row.daily_sol_cap,
    allowlistedRecipients: row.allowlisted_recipients || [],
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null
  };
}

function mapPaymentRow(row) {
  return {
    id: row.id,
    idempotencyKey: row.idempotency_key,
    userId: row.user_id,
    apiKeyId: row.api_key_id,
    recipient: row.recipient,
    amountSol: Number(row.amount_sol),
    reason: row.reason,
    resourceUrl: row.resource_url,
    signature: row.signature,
    createdAt: row.created_at ? new Date(row.created_at).toISOString() : null
  };
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password, encoded) {
  const [salt, hash] = encoded.split(':');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(derived, 'hex'));
}

function deriveKey() {
  return crypto.createHash('sha256').update(MASTER_KEY).digest();
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function encryptSecret(secretBase58) {
  const iv = crypto.randomBytes(12);
  const key = deriveKey();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(secretBase58, 'utf8'), cipher.final()]);
  return { iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), data: encrypted.toString('hex') };
}

function decryptSecret(enc) {
  const key = deriveKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(enc.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(enc.tag, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(enc.data, 'hex')), decipher.final()]).toString('utf8');
}

function issueToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString('hex');
}

function parseEmail(email) {
  const e = String(email || '').trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) ? e : null;
}

function parseSolanaAddress(value) {
  try {
    return new PublicKey(String(value)).toBase58();
  } catch {
    return null;
  }
}

async function authUser(req, res, next) {
  try {
    const token = String(req.headers['x-session-token'] || '');
    if (!token) return res.status(401).json({ error: 'Missing session token' });
    const tokenHash = hashToken(token);

    if (USE_POSTGRES) {
      const result = await pool.query(
        `SELECT * FROM users WHERE session_token_hash = $1 AND (session_expires_at IS NULL OR session_expires_at > NOW()) LIMIT 1`,
        [tokenHash]
      );
      if (!result.rows[0]) return res.status(401).json({ error: 'Invalid session token' });
      req.user = mapUserRow(result.rows[0]);
      req.db = null;
      return next();
    }

    const db = readDb();
    const user = db.users.find((u) => u.sessionTokenHash === tokenHash && (!u.sessionExpiresAt || Date.now() < new Date(u.sessionExpiresAt).getTime()));
    if (!user) return res.status(401).json({ error: 'Invalid session token' });
    req.user = user;
    req.db = db;
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

async function authTool(req, res, next) {
  try {
    const raw = String(req.headers['x-wallet-tool-key'] || '');
    if (!raw.startsWith('ak_')) return res.status(401).json({ error: 'Missing wallet tool key' });
    const keyPrefix = raw.slice(0, 12);
    const keyHash = hashToken(raw);

    if (USE_POSTGRES) {
      const keyResult = await pool.query(
        `SELECT * FROM api_keys WHERE key_prefix = $1 AND key_hash = $2 AND active = true LIMIT 1`,
        [keyPrefix, keyHash]
      );
      const apiKeyRow = keyResult.rows[0];
      if (!apiKeyRow) return res.status(401).json({ error: 'Invalid wallet tool key' });

      const userResult = await pool.query(`SELECT * FROM users WHERE id = $1 LIMIT 1`, [apiKeyRow.user_id]);
      const userRow = userResult.rows[0];
      if (!userRow) return res.status(401).json({ error: 'Key owner missing' });

      req.user = mapUserRow(userRow);
      req.apiKey = mapApiKeyRow(apiKeyRow);
      req.db = null;
      return next();
    }

    const db = readDb();
    const apiKey = db.apiKeys.find((k) => k.keyPrefix === keyPrefix && k.keyHash === keyHash && k.active);
    if (!apiKey) return res.status(401).json({ error: 'Invalid wallet tool key' });
    const user = db.users.find((u) => u.id === apiKey.userId);
    if (!user) return res.status(401).json({ error: 'Key owner missing' });
    req.user = user;
    req.apiKey = apiKey;
    req.db = db;
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

function getPolicy(user, apiKey) {
  return {
    maxSolPerPayment: apiKey.maxSolPerPayment ?? user.policy.maxSolPerPayment,
    dailySolCap: apiKey.dailySolCap ?? user.policy.dailySolCap,
    allowlistedRecipients: apiKey.allowlistedRecipients?.length ? apiKey.allowlistedRecipients : user.policy.allowlistedRecipients
  };
}

function getUsdcMintAddress() {
  return isDevnetRpc(SOLANA_RPC_URL) ? USDC_MINT_DEVNET : USDC_MINT_MAINNET;
}

async function getBalanceSol(publicKeyString) {
  if (PAYMENTS_DRY_RUN) return 0;
  const lamports = await connection.getBalance(new PublicKey(publicKeyString));
  return lamports / LAMPORTS_PER_SOL;
}

async function transferSol(fromSecretBase58, toAddress, amountSol) {
  if (PAYMENTS_DRY_RUN) return `dryrun_${crypto.randomUUID()}`;
  const fromKeypair = Keypair.fromSecretKey(bs58.decode(fromSecretBase58));
  const toPubkey = new PublicKey(toAddress);
  const lamports = Math.round(amountSol * LAMPORTS_PER_SOL);
  const tx = new Transaction().add(SystemProgram.transfer({ fromPubkey: fromKeypair.publicKey, toPubkey, lamports }));
  const signature = await connection.sendTransaction(tx, [fromKeypair]);
  await connection.confirmTransaction(signature, 'confirmed');
  return signature;
}

async function getUsdcBalance(publicKeyString, mintAddress = getUsdcMintAddress()) {
  if (PAYMENTS_DRY_RUN) return 0;
  const owner = new PublicKey(publicKeyString);
  const mint = new PublicKey(mintAddress);
  const ata = getAssociatedTokenAddressSync(mint, owner, false, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID);
  const info = await connection.getParsedAccountInfo(ata);
  if (!info.value) return 0;
  const parsed = info.value.data?.parsed;
  const uiAmount = parsed?.info?.tokenAmount?.uiAmount;
  return Number(uiAmount || 0);
}

async function transferUsdc(fromSecretBase58, toAddress, amountUsdc, mintAddress = getUsdcMintAddress(), memo = '') {
  if (PAYMENTS_DRY_RUN) return `dryrun_${crypto.randomUUID()}`;

  const fromKeypair = Keypair.fromSecretKey(bs58.decode(fromSecretBase58));
  const recipient = new PublicKey(toAddress);
  const mint = new PublicKey(mintAddress);

  const fromAta = getAssociatedTokenAddressSync(mint, fromKeypair.publicKey, false, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID);
  const toAta = getAssociatedTokenAddressSync(mint, recipient, false, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID);
  const amountAtomic = BigInt(Math.round(amountUsdc * 10 ** USDC_DECIMALS));

  const tx = new Transaction();
  const recipientAtaInfo = await connection.getAccountInfo(toAta);
  if (!recipientAtaInfo) {
    tx.add(
      createAssociatedTokenAccountInstruction(
        fromKeypair.publicKey,
        toAta,
        recipient,
        mint,
        TOKEN_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID
      )
    );
  }

  tx.add(
    createTransferCheckedInstruction(
      fromAta,
      mint,
      toAta,
      fromKeypair.publicKey,
      amountAtomic,
      USDC_DECIMALS,
      [],
      TOKEN_PROGRAM_ID
    )
  );

  if (memo) {
    tx.add(
      new TransactionInstruction({
        keys: [],
        programId: new PublicKey(MEMO_PROGRAM_ID),
        data: Buffer.from(memo, 'utf8')
      })
    );
  }

  const signature = await connection.sendTransaction(tx, [fromKeypair]);
  await connection.confirmTransaction(signature, 'confirmed');
  return signature;
}

function getBotWalletSecret() {
  if (BOT_WALLET_SECRET_KEY) return BOT_WALLET_SECRET_KEY;
  if (!fs.existsSync(BOT_WALLET_FILE)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(BOT_WALLET_FILE, 'utf8'));
    return typeof raw.secretKey === 'string' ? raw.secretKey : null;
  } catch {
    return null;
  }
}

function isDevnetRpc(url) {
  return String(url || '').toLowerCase().includes('devnet');
}

function getPublicBaseUrl(req) {
  if (APP_BASE_URL) return APP_BASE_URL;
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host = req.headers['x-forwarded-host'] || req.get('host');
  return `${proto}://${host}`;
}

app.post('/api/signup', rateLimit('signup', 20, 15 * 60 * 1000), async (req, res) => {
  try {
    const email = parseEmail(req.body.email);
    const password = String(req.body.password || '');
    if (!email || password.length < 10) return res.status(400).json({ error: 'Valid email + password (min 10 chars) required' });

    if (USE_POSTGRES) {
      const existing = await pool.query(`SELECT id FROM users WHERE email = $1 LIMIT 1`, [email]);
      if (existing.rows[0]) return res.status(409).json({ error: 'Email already exists' });
    } else {
      const db = readDb();
      if (db.users.some((u) => u.email === email)) return res.status(409).json({ error: 'Email already exists' });
    }

    const kp = Keypair.generate();
    const secret58 = bs58.encode(kp.secretKey);
    const sessionToken = issueToken(24);
    const user = {
      id: crypto.randomUUID(),
      email,
      passwordHash: hashPassword(password),
      wallet: { publicKey: kp.publicKey.toBase58(), encryptedSecret: encryptSecret(secret58) },
      policy: { maxSolPerPayment: 0.05, dailySolCap: 0.2, allowlistedRecipients: [] },
      sessionTokenHash: hashToken(sessionToken),
      sessionExpiresAt: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
      createdAt: new Date().toISOString()
    };

    if (USE_POSTGRES) {
      await pool.query(
        `INSERT INTO users (id, email, password_hash, wallet_public_key, wallet_encrypted_secret, policy, session_token_hash, session_expires_at, created_at)
         VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9)`,
        [
          user.id,
          user.email,
          user.passwordHash,
          user.wallet.publicKey,
          JSON.stringify(user.wallet.encryptedSecret),
          JSON.stringify(user.policy),
          user.sessionTokenHash,
          user.sessionExpiresAt,
          user.createdAt
        ]
      );
    } else {
      const db = readDb();
      db.users.push(user);
      writeDb(db);
    }

    res.json({ sessionToken, user: { id: user.id, email: user.email, walletAddress: user.wallet.publicKey, policy: user.policy } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', rateLimit('login', 30, 15 * 60 * 1000), async (req, res) => {
  const email = parseEmail(req.body.email);
  const password = String(req.body.password || '');
  if (!email) return res.status(401).json({ error: 'Invalid credentials' });

  let user;
  if (USE_POSTGRES) {
    const result = await pool.query(`SELECT * FROM users WHERE email = $1 LIMIT 1`, [email]);
    if (!result.rows[0]) return res.status(401).json({ error: 'Invalid credentials' });
    user = mapUserRow(result.rows[0]);
  } else {
    const db = readDb();
    user = db.users.find((u) => u.email === email);
  }

  if (!user || !verifyPassword(password, user.passwordHash)) return res.status(401).json({ error: 'Invalid credentials' });

  const sessionToken = issueToken(24);
  user.sessionTokenHash = hashToken(sessionToken);
  user.sessionExpiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();

  if (USE_POSTGRES) {
    await pool.query(`UPDATE users SET session_token_hash = $1, session_expires_at = $2 WHERE id = $3`, [user.sessionTokenHash, user.sessionExpiresAt, user.id]);
  } else {
    const db = readDb();
    const u = db.users.find((x) => x.id === user.id);
    if (u) {
      u.sessionTokenHash = user.sessionTokenHash;
      u.sessionExpiresAt = user.sessionExpiresAt;
      writeDb(db);
    }
  }

  res.json({ sessionToken, user: { id: user.id, email: user.email, walletAddress: user.wallet.publicKey, policy: user.policy } });
});

app.get('/api/me', authUser, async (req, res) => {
  const balanceSol = await getBalanceSol(req.user.wallet.publicKey);
  const balanceUsdc = await getUsdcBalance(req.user.wallet.publicKey);
  res.json({ id: req.user.id, email: req.user.email, walletAddress: req.user.wallet.publicKey, balanceSol, balanceUsdc, policy: req.user.policy });
});

app.post('/api/wallet/new', authUser, async (req, res) => {
  try {
    const kp = Keypair.generate();
    const secret58 = bs58.encode(kp.secretKey);
    const publicKey = kp.publicKey.toBase58();
    const encryptedSecret = encryptSecret(secret58);

    if (USE_POSTGRES) {
      await pool.query(
        `UPDATE users SET wallet_public_key = $1, wallet_encrypted_secret = $2::jsonb WHERE id = $3`,
        [publicKey, JSON.stringify(encryptedSecret), req.user.id]
      );
    } else {
      const user = req.db.users.find((u) => u.id === req.user.id);
      if (user) {
        user.wallet = { publicKey, encryptedSecret };
        writeDb(req.db);
      }
    }

    res.json({ walletAddress: publicKey, walletSecretKey: secret58 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/skill-template', (_req, res) => {
  const content = fs.readFileSync(path.join(__dirname, 'SKILL.md'), 'utf8');
  res.type('text/plain').send(content);
});

app.post('/api/faucet', authUser, async (req, res) => {
  try {
    if (!isDevnetRpc(SOLANA_RPC_URL)) {
      return res.status(400).json({ error: 'Faucet funding is devnet-only' });
    }

    const target = req.user.wallet.publicKey;
    const amountSol = Number.isFinite(Number(req.body?.amountSol)) ? Number(req.body.amountSol) : FAUCET_TOPUP_SOL;
    if (!Number.isFinite(amountSol) || amountSol <= 0 || amountSol > 2) {
      return res.status(400).json({ error: 'amountSol must be between 0 and 2' });
    }

    const amountLamports = Math.round(amountSol * LAMPORTS_PER_SOL);

    if (PAYMENTS_DRY_RUN) {
      return res.json({
        ok: true,
        dryRun: true,
        method: 'dry-run',
        amountSol,
        walletAddress: target,
        signature: `dryrun_${crypto.randomUUID()}`
      });
    }

    try {
      const airdropSig = await connection.requestAirdrop(new PublicKey(target), amountLamports);
      await connection.confirmTransaction(airdropSig, 'confirmed');
      const balanceSol = await getBalanceSol(target);
      return res.json({ ok: true, method: 'airdrop', amountSol, walletAddress: target, signature: airdropSig, balanceSol });
    } catch (airdropErr) {
      const botSecret = getBotWalletSecret();
      if (!botSecret) {
        return res.status(503).json({
          error: 'Airdrop failed and bot wallet fallback is not configured',
          details: String(airdropErr?.message || airdropErr)
        });
      }

      const fallbackSig = await transferSol(botSecret, target, amountSol);
      const balanceSol = await getBalanceSol(target);
      return res.json({
        ok: true,
        method: 'bot-wallet-fallback',
        amountSol,
        walletAddress: target,
        signature: fallbackSig,
        balanceSol,
        note: 'Airdrop failed, funded from bot wallet instead',
        airdropError: String(airdropErr?.message || airdropErr)
      });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/keys', authUser, async (req, res) => {
  const name = String(req.body.name || 'default').slice(0, 80);
  const maxSolPerPayment = req.body.maxSolPerPayment != null ? Number(req.body.maxSolPerPayment) : null;
  const dailySolCap = req.body.dailySolCap != null ? Number(req.body.dailySolCap) : null;
  const allowlistedRecipients = Array.isArray(req.body.allowlistedRecipients)
    ? req.body.allowlistedRecipients.map(parseSolanaAddress).filter(Boolean)
    : [];

  if (maxSolPerPayment != null && (!Number.isFinite(maxSolPerPayment) || maxSolPerPayment <= 0)) return res.status(400).json({ error: 'Invalid maxSolPerPayment' });
  if (dailySolCap != null && (!Number.isFinite(dailySolCap) || dailySolCap <= 0)) return res.status(400).json({ error: 'Invalid dailySolCap' });

  const rawKey = `ak_${issueToken(20)}`;
  const newKey = {
    id: crypto.randomUUID(),
    userId: req.user.id,
    name,
    keyPrefix: rawKey.slice(0, 12),
    keyHash: hashToken(rawKey),
    active: true,
    maxSolPerPayment,
    dailySolCap,
    allowlistedRecipients,
    createdAt: new Date().toISOString()
  };

  if (USE_POSTGRES) {
    await pool.query(
      `INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash, active, max_sol_per_payment, daily_sol_cap, allowlisted_recipients, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)`,
      [
        newKey.id,
        newKey.userId,
        newKey.name,
        newKey.keyPrefix,
        newKey.keyHash,
        true,
        newKey.maxSolPerPayment,
        newKey.dailySolCap,
        JSON.stringify(newKey.allowlistedRecipients),
        newKey.createdAt
      ]
    );
  } else {
    req.db.apiKeys.push(newKey);
    writeDb(req.db);
  }

  const effectivePolicy = getPolicy(req.user, newKey);
  const baseUrl = getPublicBaseUrl(req);
  const llmSetupInstructions = `Wallet payment tool setup (copy into your LLM):\n\nYou can make USDC (SPL token on Solana) payments ONLY through this tool.\n\nEndpoint:\nPOST ${baseUrl}/api/tool/pay\n\nHeaders:\nContent-Type: application/json\nx-wallet-tool-key: ${rawKey}\n(Optional) x-idempotency-key: <uuid>\n\nBody:\n{\n  \"recipient\": \"<solana address>\",\n  \"amountUsdc\": 0.01,\n  \"token\": \"USDC\",\n  \"memo\": \"<paywall key/challenge memo if provided>\",\n  \"reason\": \"<why payment is needed>\",\n  \"resourceUrl\": \"https://example.com\"\n}\n\nRules:\n- Pay only when required for the user's objective.\n- Keep payments as small as possible.\n- If a paywall provides a memo/key, include it exactly in \"memo\".\n- Explain each payment in one sentence.\n- Never ask for or use wallet private keys.\n- Respect limits: max ${effectivePolicy.maxSolPerPayment} USDC per payment, ${effectivePolicy.dailySolCap} USDC daily cap.${effectivePolicy.allowlistedRecipients.length ? ` Allowed recipients only: ${effectivePolicy.allowlistedRecipients.join(', ')}` : ''}`;

  res.json({ ...newKey, rawKey, llmSetupInstructions });
});

app.get('/api/keys', authUser, async (req, res) => {
  if (USE_POSTGRES) {
    const result = await pool.query(`SELECT * FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`, [req.user.id]);
    const keys = result.rows.map(mapApiKeyRow).map((k) => ({ ...k, keyHash: undefined }));
    return res.json(keys);
  }
  const keys = req.db.apiKeys.filter((k) => k.userId === req.user.id).map((k) => ({ ...k, keyHash: undefined }));
  res.json(keys);
});

app.patch('/api/keys/:id', authUser, async (req, res) => {
  try {
    const { dailySolCap, maxSolPerPayment, allowlistedRecipients } = req.body;

    if (dailySolCap != null && (!Number.isFinite(Number(dailySolCap)) || Number(dailySolCap) <= 0))
      return res.status(400).json({ error: 'Invalid dailySolCap' });
    if (maxSolPerPayment != null && (!Number.isFinite(Number(maxSolPerPayment)) || Number(maxSolPerPayment) <= 0))
      return res.status(400).json({ error: 'Invalid maxSolPerPayment' });

    if (USE_POSTGRES) {
      const result = await pool.query(`SELECT * FROM api_keys WHERE id = $1 AND user_id = $2 LIMIT 1`, [req.params.id, req.user.id]);
      if (!result.rows[0]) return res.status(404).json({ error: 'Key not found' });
      const key = mapApiKeyRow(result.rows[0]);

      const newCap = dailySolCap != null ? Number(dailySolCap) : key.dailySolCap;
      const newMax = maxSolPerPayment != null ? Number(maxSolPerPayment) : key.maxSolPerPayment;
      const newAllow = Array.isArray(allowlistedRecipients)
        ? allowlistedRecipients.map(parseSolanaAddress).filter(Boolean)
        : key.allowlistedRecipients;

      await pool.query(
        `UPDATE api_keys SET daily_sol_cap = $1, max_sol_per_payment = $2, allowlisted_recipients = $3::jsonb WHERE id = $4 AND user_id = $5`,
        [newCap, newMax, JSON.stringify(newAllow), req.params.id, req.user.id]
      );
      return res.json({ ...key, dailySolCap: newCap, maxSolPerPayment: newMax, allowlistedRecipients: newAllow, keyHash: undefined });
    }

    const key = req.db.apiKeys.find((k) => k.id === req.params.id && k.userId === req.user.id);
    if (!key) return res.status(404).json({ error: 'Key not found' });

    if (dailySolCap != null) key.dailySolCap = Number(dailySolCap);
    if (maxSolPerPayment != null) key.maxSolPerPayment = Number(maxSolPerPayment);
    if (Array.isArray(allowlistedRecipients)) key.allowlistedRecipients = allowlistedRecipients.map(parseSolanaAddress).filter(Boolean);
    writeDb(req.db);

    res.json({ ...key, keyHash: undefined });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/policy', authUser, async (req, res) => {
  const { maxSolPerPayment, dailySolCap, allowlistedRecipients } = req.body;
  if (maxSolPerPayment != null) {
    const n = Number(maxSolPerPayment);
    if (!Number.isFinite(n) || n <= 0) return res.status(400).json({ error: 'Invalid maxSolPerPayment' });
    req.user.policy.maxSolPerPayment = n;
  }
  if (dailySolCap != null) {
    const n = Number(dailySolCap);
    if (!Number.isFinite(n) || n <= 0) return res.status(400).json({ error: 'Invalid dailySolCap' });
    req.user.policy.dailySolCap = n;
  }
  if (Array.isArray(allowlistedRecipients)) {
    req.user.policy.allowlistedRecipients = allowlistedRecipients.map(parseSolanaAddress).filter(Boolean);
  }

  if (USE_POSTGRES) {
    await pool.query(`UPDATE users SET policy = $1::jsonb WHERE id = $2`, [JSON.stringify(req.user.policy), req.user.id]);
  } else {
    writeDb(req.db);
  }
  res.json(req.user.policy);
});

app.get('/api/system-prompt', authUser, (req, res) => {
  const { model = 'gpt' } = req.query;
  const baseUrl = getPublicBaseUrl(req);
  const prompt = `You can use a wallet payment tool for paywalled websites.\n\nRULES:\n1) Request quote/challenge first.\n2) Pay only if needed for user objective.\n3) Keep payments minimal.\n4) If paywall provides memo/key, include it exactly as memo.\n5) Give 1-line reason for each payment.\n\nTool name: wallet_pay\nInput:\n{\n  "recipient": "<solana address>",\n  "amountUsdc": 0.01,\n  "token": "USDC",\n  "memo": "<paywall memo or key>",\n  "reason": "<why needed>",\n  "resourceUrl": "https://example.com/article"\n}\n\nTool endpoint:\nPOST ${baseUrl}/api/tool/pay\nHeader: x-wallet-tool-key: <USER_TOOL_KEY>\nOptional Header: x-idempotency-key: <uuid>`;
  res.json({ model, prompt });
});

app.post('/api/tool/pay', rateLimit('pay', 120, 15 * 60 * 1000), authTool, async (req, res) => {
  try {
    const recipient = parseSolanaAddress(req.body.recipient);
    const amount = Number(req.body.amountUsdc ?? req.body.amountSol);
    const token = String(req.body.token || 'USDC').toUpperCase();
    const reason = String(req.body.reason || '').slice(0, 500);
    const resourceUrl = String(req.body.resourceUrl || '').slice(0, 1200);
    const memo = String(req.body.memo || '').slice(0, 256);
    const idem = String(req.headers['x-idempotency-key'] || '').trim();

    if (!recipient || !Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Valid recipient and amountUsdc required' });
    if (token !== 'USDC') return res.status(400).json({ error: 'Only USDC is currently supported by /api/tool/pay' });

    if (idem) {
      if (USE_POSTGRES) {
        const existingResult = await pool.query(
          `SELECT * FROM payments WHERE user_id = $1 AND idempotency_key = $2 LIMIT 1`,
          [req.user.id, idem]
        );
        if (existingResult.rows[0]) {
          const existing = mapPaymentRow(existingResult.rows[0]);
          return res.json({ ok: true, replay: true, signature: existing.signature, payment: existing, explorer: `https://explorer.solana.com/tx/${existing.signature}?cluster=${explorerCluster}` });
        }
      } else {
        const existing = req.db.payments.find((p) => p.userId === req.user.id && p.idempotencyKey === idem);
        if (existing) {
          return res.json({ ok: true, replay: true, signature: existing.signature, payment: existing, explorer: `https://explorer.solana.com/tx/${existing.signature}?cluster=${explorerCluster}` });
        }
      }
    }

    const policy = getPolicy(req.user, req.apiKey);
    if (amount > policy.maxSolPerPayment) return res.status(403).json({ error: `amount exceeds per-payment limit (${policy.maxSolPerPayment} USDC)` });
    if (policy.allowlistedRecipients.length > 0 && !policy.allowlistedRecipients.includes(recipient)) return res.status(403).json({ error: 'recipient not in allowlist' });

    let paidToday = 0;
    if (USE_POSTGRES) {
      const sumResult = await pool.query(
        `SELECT COALESCE(SUM(amount_sol), 0) AS paid_today FROM payments WHERE user_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'`,
        [req.user.id]
      );
      paidToday = Number(sumResult.rows[0]?.paid_today || 0);
    } else {
      const since = Date.now() - 24 * 3600 * 1000;
      paidToday = req.db.payments
        .filter((p) => p.userId === req.user.id && new Date(p.createdAt).getTime() >= since)
        .reduce((sum, p) => sum + p.amountSol, 0);
    }

    if (paidToday + amount > policy.dailySolCap) return res.status(403).json({ error: 'daily cap exceeded' });

    if (!PAYMENTS_DRY_RUN) {
      const usdcBalance = await getUsdcBalance(req.user.wallet.publicKey);
      if (usdcBalance < amount) return res.status(402).json({ error: 'insufficient USDC balance' });

      const feeSolBalance = await getBalanceSol(req.user.wallet.publicKey);
      if (feeSolBalance < 0.00001) return res.status(402).json({ error: 'insufficient SOL for transaction fees' });
    }

    const secret58 = decryptSecret(req.user.wallet.encryptedSecret);
    const signature = await transferUsdc(secret58, recipient, amount, getUsdcMintAddress(), memo);

    const payment = {
      id: crypto.randomUUID(),
      idempotencyKey: idem || null,
      userId: req.user.id,
      apiKeyId: req.apiKey.id,
      recipient,
      amountSol: amount,
      reason,
      resourceUrl,
      memo: memo || null,
      signature,
      createdAt: new Date().toISOString()
    };

    if (USE_POSTGRES) {
      await pool.query(
        `INSERT INTO payments (id, idempotency_key, user_id, api_key_id, recipient, amount_sol, reason, resource_url, memo, signature, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          payment.id,
          payment.idempotencyKey,
          payment.userId,
          payment.apiKeyId,
          payment.recipient,
          payment.amountSol,
          payment.reason,
          payment.resourceUrl,
          payment.memo,
          payment.signature,
          payment.createdAt
        ]
      );
    } else {
      req.db.payments.push(payment);
      writeDb(req.db);
    }

    res.json({ ok: true, token: 'USDC', amountUsdc: amount, signature, explorer: `https://explorer.solana.com/tx/${signature}?cluster=${explorerCluster}`, payment });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/tool/balance', authTool, async (req, res) => {
  const balanceSol = await getBalanceSol(req.user.wallet.publicKey);
  const balanceUsdc = await getUsdcBalance(req.user.wallet.publicKey);
  res.json({ walletAddress: req.user.wallet.publicKey, balanceSol, balanceUsdc, token: 'USDC', usdcMint: getUsdcMintAddress() });
});

app.get('/health', (_req, res) => res.json({ ok: true }));

export default app;
