/**
 * Vendor dashboard HTML generator.
 *
 * Renders a self-contained HTML page with:
 *   - Key issuance stats (all-time + this month)
 *   - 30-day bar chart (inline SVG)
 *   - Billing status
 *   - Account details
 */

'use strict';

function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * @param {object} vendor        — vendor record from store
 * @param {number} thisMonth     — keys issued this billing period
 * @param {Array}  dailyUsage    — [{ day: 'YYYY-MM-DD', count: N }, ...]
 * @param {object|null} stripeUsage — { totalUsage, periodStart, periodEnd } | null
 */
function dashboardHtml(vendor, thisMonth, dailyUsage, stripeUsage) {
  const chart = buildChart(dailyUsage);
  const billingHtml = buildBillingSection(vendor, thisMonth, stripeUsage);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgentPayments — Dashboard</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #f5f5f5; color: #1a1a1a; min-height: 100vh; }
    header { background: #111; color: #fff; padding: 16px 32px; display: flex; align-items: center; justify-content: space-between; }
    header h1 { font-size: 18px; font-weight: 600; letter-spacing: -0.3px; }
    header .meta { font-size: 13px; color: #aaa; }
    header a.logout { color: #aaa; font-size: 13px; text-decoration: none; margin-left: 20px; }
    header a.logout:hover { color: #fff; }
    main { max-width: 960px; margin: 32px auto; padding: 0 24px; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .card { background: #fff; border-radius: 10px; padding: 20px 24px; border: 1px solid #e8e8e8; }
    .card .label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.6px; color: #888; margin-bottom: 8px; }
    .card .value { font-size: 32px; font-weight: 700; line-height: 1; }
    .card .sub { font-size: 12px; color: #999; margin-top: 6px; }
    .card.green .value { color: #16a34a; }
    .card.amber .value { color: #d97706; }
    .section { background: #fff; border-radius: 10px; border: 1px solid #e8e8e8; padding: 24px; margin-bottom: 24px; }
    .section h2 { font-size: 15px; font-weight: 600; margin-bottom: 20px; color: #111; }
    .chart-wrap { overflow-x: auto; }
    .chart-wrap svg { display: block; }
    .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px 32px; }
    .info-row { display: flex; flex-direction: column; gap: 2px; }
    .info-row .k { font-size: 11px; color: #999; text-transform: uppercase; letter-spacing: 0.5px; }
    .info-row .v { font-size: 14px; color: #222; font-family: monospace; word-break: break-all; }
    .badge { display: inline-block; padding: 3px 9px; border-radius: 99px; font-size: 11px; font-weight: 600; }
    .badge.verified { background: #dcfce7; color: #16a34a; }
    .badge.unverified { background: #fef9c3; color: #a16207; }
    .badge.free { background: #e0e7ff; color: #3730a3; }
    .billing-period { font-size: 13px; color: #666; margin-top: 8px; }
  </style>
</head>
<body>
  <header>
    <h1>AgentPayments</h1>
    <div style="display:flex;align-items:center;gap:4px">
      <span class="meta">${escapeHtml(vendor.name || vendor.email)}</span>
      <a class="logout" href="/dashboard/logout">Sign out</a>
    </div>
  </header>
  <main>
    <div class="cards">
      <div class="card">
        <div class="label">Keys issued — all time</div>
        <div class="value">${Number(vendor.keys_issued ?? vendor.keysIssued ?? 0).toLocaleString()}</div>
      </div>
      <div class="card">
        <div class="label">Keys issued — this month</div>
        <div class="value">${Number(thisMonth).toLocaleString()}</div>
      </div>
      <div class="card ${vendor.email_verified ?? vendor.emailVerified ? 'green' : 'amber'}">
        <div class="label">Account status</div>
        <div class="value" style="font-size:20px;padding-top:6px">
          ${vendor.email_verified ?? vendor.emailVerified
            ? '<span class="badge verified">Verified</span>'
            : '<span class="badge unverified">Pending verification</span>'}
        </div>
      </div>
      <div class="card">
        <div class="label">Plan</div>
        <div class="value" style="font-size:20px;padding-top:6px">
          <span class="badge free">${escapeHtml(vendor.plan || 'free')}</span>
        </div>
        ${stripeUsage ? `<div class="sub">${Number(stripeUsage.totalUsage).toLocaleString()} units this period</div>` : ''}
      </div>
    </div>

    <div class="section">
      <h2>Key issuance — last 30 days</h2>
      <div class="chart-wrap">
        ${chart}
      </div>
    </div>

    ${billingHtml}

    <div class="section">
      <h2>Account details</h2>
      <div class="info-grid">
        <div class="info-row"><span class="k">Vendor ID</span><span class="v">${escapeHtml(vendor.vendor_id || vendor.vendorId)}</span></div>
        <div class="info-row"><span class="k">Email</span><span class="v">${escapeHtml(vendor.email)}</span></div>
        <div class="info-row"><span class="k">Member since</span><span class="v">${new Date(Number(vendor.created_at || vendor.createdAt)).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}</span></div>
        ${vendor.stripe_customer_id || vendor.stripeCustomerId
          ? `<div class="info-row"><span class="k">Stripe Customer</span><span class="v">${escapeHtml(vendor.stripe_customer_id || vendor.stripeCustomerId)}</span></div>`
          : ''}
      </div>
    </div>
  </main>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// SVG bar chart (server-side, no JS required)
// ---------------------------------------------------------------------------

function buildChart(dailyUsage) {
  // Fill in zeros for missing days over the last 30 days
  const today = new Date();
  const days = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    days.push(d.toISOString().slice(0, 10));
  }

  const byDay = Object.fromEntries((dailyUsage || []).map((r) => [r.day, Number(r.count)]));
  const counts = days.map((d) => byDay[d] || 0);
  const max = Math.max(...counts, 1);

  const W = 900, H = 140, PAD = { top: 8, bottom: 28, left: 0, right: 0 };
  const barW = Math.floor((W - PAD.left - PAD.right) / 30) - 2;
  const chartH = H - PAD.top - PAD.bottom;

  const bars = counts.map((c, i) => {
    const barH = Math.max(c === 0 ? 2 : Math.round((c / max) * chartH), 2);
    const x = PAD.left + i * (barW + 2);
    const y = PAD.top + chartH - barH;
    const fill = c === 0 ? '#e5e7eb' : '#111';
    const label = days[i].slice(5); // MM-DD
    const showLabel = i === 0 || i === 14 || i === 29;
    return `
      <rect x="${x}" y="${y}" width="${barW}" height="${barH}" fill="${fill}" rx="2">
        <title>${days[i]}: ${c} key${c !== 1 ? 's' : ''}</title>
      </rect>
      ${showLabel ? `<text x="${x + barW / 2}" y="${H - 6}" text-anchor="middle" font-size="10" fill="#999">${label}</text>` : ''}`;
  }).join('');

  // Y-axis hint
  const yHint = `<text x="${W - 2}" y="${PAD.top + 4}" text-anchor="end" font-size="10" fill="#ccc">${max}</text>`;

  return `<svg viewBox="0 0 ${W} ${H}" width="100%" xmlns="http://www.w3.org/2000/svg"
    role="img" aria-label="30-day key issuance chart">
    ${yHint}
    ${bars}
  </svg>`;
}

function buildBillingSection(vendor, thisMonth, stripeUsage) {
  if (!stripeUsage) return '';
  return `
    <div class="section">
      <h2>Billing</h2>
      <div class="info-grid">
        <div class="info-row">
          <span class="k">Current period usage</span>
          <span class="v">${Number(stripeUsage.totalUsage).toLocaleString()} keys</span>
        </div>
        <div class="info-row">
          <span class="k">Billing period</span>
          <span class="v" style="font-size:12px">${new Date(stripeUsage.periodStart).toLocaleDateString()} – ${new Date(stripeUsage.periodEnd).toLocaleDateString()}</span>
        </div>
      </div>
    </div>`;
}

// ---------------------------------------------------------------------------
// Login page
// ---------------------------------------------------------------------------

function loginHtml(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgentPayments — Sign in</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .box { background: #fff; border: 1px solid #e8e8e8; border-radius: 12px; padding: 40px; width: 100%; max-width: 400px; }
    h1 { font-size: 20px; font-weight: 700; margin-bottom: 6px; }
    p { font-size: 14px; color: #666; margin-bottom: 24px; }
    label { font-size: 13px; font-weight: 500; display: block; margin-bottom: 6px; }
    input { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; font-family: monospace; margin-bottom: 16px; }
    input:focus { outline: none; border-color: #111; box-shadow: 0 0 0 2px rgba(0,0,0,0.08); }
    button { width: 100%; padding: 11px; background: #111; color: #fff; border: none; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; }
    button:hover { background: #333; }
    .error { background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; border-radius: 6px; padding: 10px 14px; font-size: 13px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="box">
    <h1>AgentPayments</h1>
    <p>Enter your platform API key to view your dashboard.</p>
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}
    <form method="POST" action="/dashboard/login">
      <label for="key">Platform API key</label>
      <input id="key" name="key" type="password" placeholder="ap_live_..." autocomplete="off" required>
      <button type="submit">Sign in</button>
    </form>
  </div>
</body>
</html>`;
}

module.exports = { dashboardHtml, loginHtml };
