/**
 * CloudflareKVStore — Store implementation backed by Cloudflare Workers KV.
 *
 * Pass an instance to createEdgeGate (or return one from getStore) to make
 * nonce replay prevention, rate limiting, and payment caching durable across
 * all Cloudflare isolates for a given worker deployment.
 *
 * Usage:
 *   import { CloudflareKVStore } from '@agentpayments/edge/cloudflare-kv-store.js';
 *   // or via the cloudflare.js createAgentPaymentsWorker({ kvBinding: 'KV_NAME' })
 *
 * KV namespace must be created and bound in wrangler.toml:
 *   [[kv_namespaces]]
 *   binding = "AGENTPAYMENTS_KV"
 *   id = "<id from `wrangler kv:namespace create AGENTPAYMENTS_KV`>"
 *
 * Trade-offs vs. InMemoryStore:
 *   consumeNonce  — KV put/get is NOT atomic; there is a small race window
 *                   (~ms) where two concurrent isolates could both accept the
 *                   same nonce. For a hard guarantee use Durable Objects.
 *                   KV is still vastly better than per-isolate in-memory
 *                   (where every isolate has a fresh empty set).
 *   checkRateLimit — fixed-window counter; same race applies, counts may be
 *                    slightly under the true value under high concurrency.
 *   getCachedPayment / setCachedPayment — reads/writes are eventually
 *                    consistent (KV replication lag ~60s in the worst case).
 *                    Paid keys may briefly re-scan the chain on a cold isolate
 *                    before the cache propagates.
 */

export class CloudflareKVStore {
  /**
   * @param {KVNamespace} kvNamespace  — the bound Cloudflare KV namespace
   */
  constructor(kvNamespace) {
    if (!kvNamespace || typeof kvNamespace.get !== 'function') {
      throw new Error('CloudflareKVStore: kvNamespace must be a Cloudflare KV binding');
    }
    this._kv = kvNamespace;
  }

  /**
   * Mark a nonce signature as consumed.
   * Returns true if this is the first use (fresh), false if it has been seen.
   *
   * Note: put/get is not atomic in KV — see file-level comment for the race caveat.
   */
  async consumeNonce(sig, ttlMs) {
    const key = `nonce:${sig}`;
    const existing = await this._kv.get(key);
    if (existing !== null) return false;
    await this._kv.put(key, '1', { expirationTtl: Math.max(1, Math.ceil(ttlMs / 1000)) });
    return true;
  }

  /**
   * Fixed-window rate limiter. Returns true if the caller is within the limit.
   */
  async checkRateLimit(ipKey, windowMs, max) {
    const key = `rl:${ipKey}`;
    const raw = await this._kv.get(key);
    const now = Date.now();
    let entry = raw ? JSON.parse(raw) : null;

    if (!entry || now - entry.start > windowMs) {
      entry = { start: now, count: 1 };
    } else {
      entry.count += 1;
    }

    const ttlSec = Math.max(1, Math.ceil(windowMs / 1000));
    await this._kv.put(key, JSON.stringify(entry), { expirationTtl: ttlSec });
    return entry.count <= max;
  }

  /**
   * Return the cached payment result for an agent key, or undefined if not cached.
   */
  async getCachedPayment(agentKey) {
    const val = await this._kv.get(`pay:${agentKey}`);
    if (val === null) return undefined;
    return val === 'true';
  }

  /**
   * Cache a payment verification result for ttlMs milliseconds.
   */
  async setCachedPayment(agentKey, value, ttlMs) {
    await this._kv.put(`pay:${agentKey}`, value ? 'true' : 'false', {
      expirationTtl: Math.max(1, Math.ceil(ttlMs / 1000)),
    });
  }
}
