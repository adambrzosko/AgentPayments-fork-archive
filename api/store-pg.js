/**
 * Postgres-backed vendor store.
 *
 * Implements the same interface as store-json.js.
 * Activated automatically when DATABASE_URL is set.
 *
 * Run api/schema.sql once to create the tables.
 */

'use strict';

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', component: 'store-pg', error: err.message }));
});

// ---------------------------------------------------------------------------
// Core CRUD
// ---------------------------------------------------------------------------

module.exports = {
  async getVendorByApiKey(apiKey) {
    const { rows } = await pool.query(
      'SELECT * FROM vendors WHERE api_key = $1',
      [apiKey],
    );
    return rows[0] || null;
  },

  async createVendor({ vendorId, email, name, apiKey, verificationSecret, verificationToken }) {
    try {
      const { rows } = await pool.query(
        `INSERT INTO vendors
           (vendor_id, email, name, api_key, verification_secret, email_verified, verification_token, created_at)
         VALUES ($1, $2, $3, $4, $5, FALSE, $6, $7)
         RETURNING *`,
        [vendorId, email.toLowerCase().trim(), name.trim(), apiKey, verificationSecret, verificationToken || null, Date.now()],
      );
      return rows[0];
    } catch (err) {
      if (err.code === '23505') {
        // unique_violation on email
        const e = new Error('A vendor with that email already exists.');
        e.code = 'DUPLICATE_EMAIL';
        throw e;
      }
      throw err;
    }
  },

  async getVendor(vendorId) {
    const { rows } = await pool.query('SELECT * FROM vendors WHERE vendor_id = $1', [vendorId]);
    return rows[0] || null;
  },

  async listVendors() {
    const { rows } = await pool.query('SELECT * FROM vendors ORDER BY created_at DESC');
    return rows;
  },

  // ---------------------------------------------------------------------------
  // Key issuance — increments counter + upserts today's usage_daily row atomically
  // ---------------------------------------------------------------------------

  async incrementKeysIssued(vendorId) {
    await pool.query('UPDATE vendors SET keys_issued = keys_issued + 1 WHERE vendor_id = $1', [vendorId]);
    // Upsert today's daily count
    await pool.query(
      `INSERT INTO usage_daily (vendor_id, event_type, day, count)
       VALUES ($1, 'key_issued', CURRENT_DATE, 1)
       ON CONFLICT (vendor_id, event_type, day)
       DO UPDATE SET count = usage_daily.count + 1`,
      [vendorId],
    );
  },

  // ---------------------------------------------------------------------------
  // Email verification
  // ---------------------------------------------------------------------------

  async verifyEmail(token) {
    const { rows } = await pool.query(
      `UPDATE vendors SET email_verified = TRUE, verification_token = NULL
       WHERE verification_token = $1 AND email_verified = FALSE
       RETURNING *`,
      [token],
    );
    return rows[0] || null;
  },

  // ---------------------------------------------------------------------------
  // Stripe
  // ---------------------------------------------------------------------------

  async setStripeIds(vendorId, stripeCustomerId, stripeSubscriptionItemId) {
    await pool.query(
      `UPDATE vendors
       SET stripe_customer_id = $2, stripe_subscription_item_id = $3
       WHERE vendor_id = $1`,
      [vendorId, stripeCustomerId, stripeSubscriptionItemId],
    );
  },

  // ---------------------------------------------------------------------------
  // Usage analytics (for dashboard)
  // ---------------------------------------------------------------------------

  /**
   * Returns the last `days` days of daily key issuance counts.
   * Result: [{ day: 'YYYY-MM-DD', count: N }, ...]  ordered oldest → newest.
   */
  async getDailyUsage(vendorId, days = 30) {
    const { rows } = await pool.query(
      `SELECT to_char(day, 'YYYY-MM-DD') AS day, count
       FROM usage_daily
       WHERE vendor_id = $1
         AND event_type = 'key_issued'
         AND day >= CURRENT_DATE - ($2 - 1) * INTERVAL '1 day'
       ORDER BY day ASC`,
      [vendorId, days],
    );
    return rows;
  },

  /**
   * Keys issued in the current calendar month.
   */
  async keysIssuedThisMonth(vendorId) {
    const { rows } = await pool.query(
      `SELECT COALESCE(SUM(count), 0)::INTEGER AS total
       FROM usage_daily
       WHERE vendor_id = $1
         AND event_type = 'key_issued'
         AND date_trunc('month', day) = date_trunc('month', CURRENT_DATE)`,
      [vendorId],
    );
    return rows[0]?.total ?? 0;
  },
};
