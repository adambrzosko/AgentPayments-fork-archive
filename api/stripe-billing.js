/**
 * Stripe metered billing integration.
 *
 * Gracefully no-ops when STRIPE_SECRET_KEY is not set (local dev / self-hosted).
 *
 * Required env vars (production):
 *   STRIPE_SECRET_KEY  — sk_live_... or sk_test_...
 *   STRIPE_PRICE_ID    — ID of a metered price in your Stripe dashboard.
 *                        Create it once:
 *                          Product: "AgentPayments Keys"
 *                          Pricing model: Usage-based (metered), per unit
 *                          Billing period: Monthly
 *                          Unit amount: e.g. $0.001 per key (= $1 per 1000 keys)
 *
 * Usage flow:
 *   1. vendor registers → createCustomerAndSubscription() → store IDs
 *   2. vendor issues a key → recordKeyIssuance(subscriptionItemId) → Stripe usage record
 *   3. Stripe invoices the vendor monthly based on reported usage
 */

'use strict';

function getStripe() {
  if (!process.env.STRIPE_SECRET_KEY) return null;
  // Lazy-load to avoid crashing when not installed
  try {
    return require('stripe')(process.env.STRIPE_SECRET_KEY);
  } catch {
    console.warn('stripe package not installed — Stripe billing disabled');
    return null;
  }
}

let _stripe = null;
function stripe() {
  if (_stripe === null) _stripe = getStripe();
  return _stripe;
}

/**
 * Create a Stripe customer and subscribe them to the metered price.
 * Returns { customerId, subscriptionItemId } or null if Stripe is disabled.
 */
async function createCustomerAndSubscription(email, name) {
  const s = stripe();
  if (!s) return null;

  const priceId = process.env.STRIPE_PRICE_ID;
  if (!priceId) {
    console.warn(JSON.stringify({ level: 'warn', component: 'stripe', message: 'STRIPE_PRICE_ID not set — skipping subscription creation' }));
    return null;
  }

  try {
    const customer = await s.customers.create({ email, name, metadata: { source: 'agentpayments' } });
    const subscription = await s.subscriptions.create({
      customer: customer.id,
      items: [{ price: priceId }],
      // No trial, starts immediately. Adjust as needed.
    });
    const subscriptionItemId = subscription.items.data[0]?.id;
    return { customerId: customer.id, subscriptionItemId };
  } catch (err) {
    console.error(JSON.stringify({ level: 'error', component: 'stripe', message: 'Failed to create customer/subscription', error: err.message }));
    return null;
  }
}

/**
 * Record one key issuance as a metered usage event on the vendor's subscription.
 * Fire-and-forget: errors are logged but do not block the key issuance response.
 */
async function recordKeyIssuance(subscriptionItemId) {
  const s = stripe();
  if (!s || !subscriptionItemId) return;

  try {
    await s.subscriptionItems.createUsageRecord(subscriptionItemId, {
      quantity: 1,
      action: 'increment',
      timestamp: Math.floor(Date.now() / 1000),
    });
  } catch (err) {
    // Non-fatal — log and continue
    console.error(JSON.stringify({ level: 'error', component: 'stripe', message: 'Usage record failed', error: err.message }));
  }
}

/**
 * Retrieve the current billing period's usage from Stripe.
 * Returns { totalUsage, periodStart, periodEnd } or null.
 */
async function getCurrentUsage(subscriptionItemId) {
  const s = stripe();
  if (!s || !subscriptionItemId) return null;

  try {
    const summary = await s.subscriptionItems.listUsageRecordSummaries(subscriptionItemId, { limit: 1 });
    const latest = summary.data[0];
    if (!latest) return null;
    return {
      totalUsage: latest.total_usage,
      periodStart: new Date(latest.period.start * 1000).toISOString(),
      periodEnd: new Date(latest.period.end * 1000).toISOString(),
    };
  } catch {
    return null;
  }
}

module.exports = { createCustomerAndSubscription, recordKeyIssuance, getCurrentUsage };
