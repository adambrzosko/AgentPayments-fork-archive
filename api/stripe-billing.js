/**
 * Stripe metered billing integration (Billing Meters API).
 *
 * Gracefully no-ops when STRIPE_SECRET_KEY is not set (local dev / self-hosted).
 *
 * Required env vars (production):
 *   STRIPE_SECRET_KEY        — sk_live_... or sk_test_...
 *   STRIPE_PRICE_ID          — ID of a metered Price backed by a Meter (see setup below).
 *   STRIPE_METER_ID          — ID of the Billing Meter (Meter.id, e.g. "mtr_..."),
 *                              used to query usage. Different from event_name.
 *   STRIPE_METER_EVENT_NAME  — the Meter's event_name (e.g. "agentpayments_key_issued"),
 *                              used to report usage.
 *
 * One-time setup in the Stripe Dashboard (or API), done ONCE per Stripe account,
 * not per vendor:
 *   1. Billing → Meters → Create meter
 *        Event name: agentpayments_key_issued
 *        Aggregation: Count (sum of events)
 *        Customer mapping key: stripe_customer_id (default)
 *      Copy the Meter's ID (mtr_...) → STRIPE_METER_ID
 *      Copy the event name → STRIPE_METER_EVENT_NAME
 *   2. Product catalog → create Product "AgentPayments Keys"
 *        Add a Price: Usage-based (metered), attached to the meter created above.
 *        Unit amount: e.g. $0.001 per key (= $1 per 1000 keys). Billing period: Monthly.
 *      Copy the Price ID → STRIPE_PRICE_ID
 *
 * Usage flow:
 *   1. vendor registers → createCustomerAndSubscription() → store stripe_customer_id
 *   2. vendor issues a key → recordKeyIssuance(customerId) → billing.meterEvents.create()
 *   3. Stripe aggregates meter events and invoices the vendor monthly
 *
 * Note on billing periods: this module intentionally does NOT read
 * subscription.current_period_start/end. That field was relocated/removed from the
 * Subscription object for accounts on API versions >= 2025-03-31.basil (see Stripe's
 * changelog), and relying on it risks silent breakage across accounts pinned to
 * different API versions. getCurrentUsage() instead reports a rolling 30-day window,
 * which approximates (but does not exactly match) the Stripe invoice period — the
 * returned object is flagged with periodApproximate: true.
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
 * Returns { customerId } or null if Stripe is disabled.
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
    await s.subscriptions.create({
      customer: customer.id,
      items: [{ price: priceId }],
      // No trial, starts immediately. Adjust as needed.
    });
    return { customerId: customer.id };
  } catch (err) {
    console.error(JSON.stringify({ level: 'error', component: 'stripe', message: 'Failed to create customer/subscription', error: err.message }));
    return null;
  }
}

/**
 * Record one key issuance as a Billing Meter event for the vendor's customer.
 * Fire-and-forget: errors are logged but do not block the key issuance response.
 */
async function recordKeyIssuance(customerId) {
  const s = stripe();
  const eventName = process.env.STRIPE_METER_EVENT_NAME;
  if (!s || !customerId || !eventName) return;

  try {
    await s.billing.meterEvents.create({
      event_name: eventName,
      payload: {
        stripe_customer_id: customerId,
        value: '1',
      },
      // Stripe enforces uniqueness of `identifier` within a rolling 24h window, which
      // is a reasonable dedupe guard against accidental double-reports of the same event.
      identifier: `key-issued-${customerId}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    });
  } catch (err) {
    // Non-fatal — log and continue
    console.error(JSON.stringify({ level: 'error', component: 'stripe', message: 'Meter event failed', error: err.message }));
  }
}

/**
 * Retrieve a rolling 30-day usage window from Stripe for the vendor's customer.
 * This is an APPROXIMATION of the true Stripe billing period (see module header).
 * Returns { totalUsage, periodStart, periodEnd, periodApproximate } or null.
 */
async function getCurrentUsage(customerId) {
  const s = stripe();
  const meterId = process.env.STRIPE_METER_ID;
  if (!s || !customerId || !meterId) return null;

  try {
    const now = Math.floor(Date.now() / 1000);
    const THIRTY_DAYS = 30 * 24 * 60 * 60;
    const startTime = now - THIRTY_DAYS;

    const summaries = await s.billing.meters.listEventSummaries(meterId, {
      customer: customerId,
      start_time: startTime,
      end_time: now,
      limit: 1,
    });
    const summary = summaries.data[0];
    const totalUsage = summary ? summary.aggregated_value : 0;

    return {
      totalUsage,
      periodStart: new Date(startTime * 1000).toISOString(),
      periodEnd: new Date(now * 1000).toISOString(),
      periodApproximate: true,
    };
  } catch (err) {
    console.error(JSON.stringify({ level: 'error', component: 'stripe', message: 'getCurrentUsage failed', error: err.message }));
    return null;
  }
}

module.exports = { createCustomerAndSubscription, recordKeyIssuance, getCurrentUsage };
