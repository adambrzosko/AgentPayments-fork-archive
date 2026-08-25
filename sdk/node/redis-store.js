'use strict';
/**
 * RedisStore — pluggable state backend for the Node SDK using Redis.
 *
 * Designed for multi-process Node/Express deployments where the in-memory
 * RateLimiter and PaymentCache are per-process and therefore ineffective.
 *
 * Usage:
 *   const { createClient } = require('redis');
 *   const { RedisStore } = require('@agentpayments/node/redis-store');
 *
 *   const redis = createClient({ url: process.env.REDIS_URL });
 *   await redis.connect();
 *
 *   app.use(agentPaymentsGate({
 *     ...,
 *     rateLimiter:    new RedisStore.RateLimiter(redis),
 *     paymentCache:   new RedisStore.PaymentCache(redis),
 *   }));
 *
 * The RedisStore classes are intentionally drop-in replacements for the
 * built-in in-memory implementations (same method signatures, same TTL
 * semantics). The Node SDK gate accepts optional `rateLimiter` and
 * `paymentCache` options to substitute them.
 *
 * Atomicity note
 * ──────────────
 * RateLimiter uses a Lua INCR+EXPIRE script executed atomically server-side
 * so there is no read-modify-write race even under concurrent requests.
 * PaymentCache uses plain SET NX/EX — idempotent for the same key.
 *
 * Requires: redis@4+ (ioredis is also compatible — adjust the SET syntax
 * to use set(key, value, 'EX', ttlSec) for ioredis).
 */

const RATE_LIMIT_WINDOW_SEC = 60;
const RATE_LIMIT_MAX = 20;
const AGENT_KEY_RATE_LIMIT_MAX = 10;

// Lua script: atomically increment and set TTL only on the first hit.
// Returns current count after increment.
const INCR_SCRIPT = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
`.trim();

class RateLimiter {
  /**
   * @param {import('redis').RedisClientType} redisClient
   * @param {object} [opts]
   * @param {number} [opts.windowSec=60]    - sliding window in seconds
   * @param {number} [opts.max=20]          - max hits per window per key
   * @param {string} [opts.keyPrefix='agp:rl:']
   */
  constructor(redisClient, opts = {}) {
    this._redis = redisClient;
    this._window = opts.windowSec ?? RATE_LIMIT_WINDOW_SEC;
    this._max = opts.max ?? RATE_LIMIT_MAX;
    this._prefix = opts.keyPrefix ?? 'agp:rl:';
  }

  /**
   * Returns true if the request should be allowed, false if rate-limited.
   * @param {string} ip
   */
  async check(ip) {
    const key = `${this._prefix}${ip}`;
    try {
      const count = await this._redis.eval(INCR_SCRIPT, {
        keys: [key],
        arguments: [String(this._window)],
      });
      return Number(count) <= this._max;
    } catch (err) {
      // Fail open on Redis error — don't block legitimate traffic.
      console.error('[agentpayments] RedisStore.RateLimiter error', err?.message);
      return true;
    }
  }

  // No-op — Redis TTL handles eviction.
  cleanup() {}
}

class PaymentCache {
  /**
   * @param {import('redis').RedisClientType} redisClient
   * @param {object} [opts]
   * @param {string} [opts.keyPrefix='agp:pay:']
   */
  constructor(redisClient, opts = {}) {
    this._redis = redisClient;
    this._prefix = opts.keyPrefix ?? 'agp:pay:';
  }

  /**
   * @param {string} agentKey
   * @returns {Promise<true|false|undefined>}  true=paid, false=unpaid, undefined=miss
   */
  async get(agentKey) {
    try {
      const val = await this._redis.get(`${this._prefix}${agentKey}`);
      if (val === null) return undefined;
      return val === '1';
    } catch (err) {
      console.error('[agentpayments] RedisStore.PaymentCache.get error', err?.message);
      return undefined;
    }
  }

  /**
   * @param {string} agentKey
   * @param {boolean} paid
   * @param {number} ttlMs  - TTL in milliseconds
   */
  async set(agentKey, paid, ttlMs) {
    try {
      const ttlSec = Math.max(1, Math.round(ttlMs / 1000));
      await this._redis.set(`${this._prefix}${agentKey}`, paid ? '1' : '0', { EX: ttlSec });
    } catch (err) {
      console.error('[agentpayments] RedisStore.PaymentCache.set error', err?.message);
    }
  }
}

/**
 * Convenience factory: create pre-configured rate limiters matching the
 * built-in defaults (challenge verify at 20/min, agent-key at 10/min).
 *
 * @param {import('redis').RedisClientType} redisClient
 * @returns {{ challengeRateLimiter: RateLimiter, agentKeyRateLimiter: RateLimiter, paymentCache: PaymentCache }}
 */
function createRedisStore(redisClient) {
  return {
    challengeRateLimiter: new RateLimiter(redisClient, { max: RATE_LIMIT_MAX }),
    agentKeyRateLimiter:  new RateLimiter(redisClient, { max: AGENT_KEY_RATE_LIMIT_MAX }),
    paymentCache:         new PaymentCache(redisClient),
  };
}

module.exports = { RateLimiter, PaymentCache, createRedisStore };
