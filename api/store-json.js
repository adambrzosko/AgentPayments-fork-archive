/**
 * Vendor store — JSON file backed, atomic writes.
 * Used in local dev when DATABASE_URL is not set.
 *
 * Schema:
 *   vendors.json {
 *     vendors: { [vendorId]: VendorRecord },
 *     apiKeys:  { [apiKey]:  vendorId },
 *     verificationTokens: { [token]: vendorId },
 *   }
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'vendors.json');

function read() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return { vendors: {}, apiKeys: {}, verificationTokens: {} };
  }
}

function write(data) {
  const tmp = `${DATA_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}

module.exports = {
  getVendorByApiKey(apiKey) {
    const data = read();
    const vendorId = data.apiKeys[apiKey];
    if (!vendorId) return null;
    return data.vendors[vendorId] || null;
  },

  createVendor({ vendorId, email, name, apiKey, verificationSecret, verificationToken }) {
    const data = read();
    if (Object.values(data.vendors).some((v) => v.email === email)) {
      const err = new Error('A vendor with that email already exists.');
      err.code = 'DUPLICATE_EMAIL';
      throw err;
    }
    const record = {
      vendorId, email, name, apiKey, verificationSecret,
      plan: 'free',
      keysIssued: 0,
      emailVerified: false,
      verificationToken: verificationToken || null,
      stripeCustomerId: null,
      stripeSubscriptionItemId: null,
      createdAt: Date.now(),
    };
    data.vendors[vendorId] = record;
    data.apiKeys[apiKey] = vendorId;
    if (verificationToken) data.verificationTokens[verificationToken] = vendorId;
    write(data);
    return record;
  },

  incrementKeysIssued(vendorId) {
    const data = read();
    if (data.vendors[vendorId]) {
      data.vendors[vendorId].keysIssued = (data.vendors[vendorId].keysIssued || 0) + 1;
      write(data);
    }
  },

  getVendor(vendorId) {
    return read().vendors[vendorId] || null;
  },

  listVendors() {
    return Object.values(read().vendors);
  },

  // Email verification
  verifyEmail(token) {
    const data = read();
    const vendorId = data.verificationTokens[token];
    if (!vendorId || !data.vendors[vendorId]) return null;
    data.vendors[vendorId].emailVerified = true;
    data.vendors[vendorId].verificationToken = null;
    delete data.verificationTokens[token];
    write(data);
    return data.vendors[vendorId];
  },

  // Stripe
  setStripeIds(vendorId, stripeCustomerId, stripeSubscriptionItemId) {
    const data = read();
    if (data.vendors[vendorId]) {
      data.vendors[vendorId].stripeCustomerId = stripeCustomerId;
      data.vendors[vendorId].stripeSubscriptionItemId = stripeSubscriptionItemId;
      write(data);
    }
  },

  // Usage analytics — JSON store has no daily breakdown; returns empty array
  getDailyUsage(_vendorId, _days = 30) {
    return [];
  },

  keysIssuedThisMonth(vendorId) {
    // JSON store doesn't track monthly — return all-time as fallback
    return read().vendors[vendorId]?.keysIssued ?? 0;
  },
};
