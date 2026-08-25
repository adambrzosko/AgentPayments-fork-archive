/**
 * Email verification module.
 *
 * Uses nodemailer with SMTP. Gracefully no-ops in dev when SMTP_HOST is unset,
 * printing the verification link to the console instead.
 *
 * Required env vars (production):
 *   SMTP_HOST      — e.g. smtp.postmarkapp.com
 *   SMTP_PORT      — default 587
 *   SMTP_USER      — SMTP username / API token
 *   SMTP_PASS      — SMTP password / API token
 *   SMTP_FROM      — From address, e.g. "AgentPayments <noreply@agentpayments.dev>"
 *   PUBLIC_URL     — Base URL for verification links, e.g. https://api.agentpayments.dev
 */

'use strict';

const publicUrl = (process.env.PUBLIC_URL || 'http://localhost:3001').replace(/\/$/, '');

let _transporter = null;

function getTransporter() {
  if (_transporter) return _transporter;
  if (!process.env.SMTP_HOST) return null;

  const nodemailer = require('nodemailer');
  _transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_PORT === '465',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
  return _transporter;
}

/**
 * Send a verification email to a newly registered vendor.
 *
 * @param {object} opts
 * @param {string} opts.email
 * @param {string} opts.name
 * @param {string} opts.vendorId
 * @param {string} opts.token  — the verification token stored in the DB
 */
async function sendVerificationEmail({ email, name, vendorId, token }) {
  const link = `${publicUrl}/v1/vendors/verify-email?token=${token}&vendorId=${vendorId}`;

  const transporter = getTransporter();
  if (!transporter) {
    // Dev mode: print the link so you can verify manually
    console.log(JSON.stringify({
      ts: new Date().toISOString(),
      level: 'info',
      component: 'email',
      message: 'SMTP not configured — verification link (dev only):',
      link,
      email,
    }));
    return;
  }

  const from = process.env.SMTP_FROM || 'AgentPayments <noreply@agentpayments.dev>';

  await transporter.sendMail({
    from,
    to: email,
    subject: 'Verify your AgentPayments account',
    text: [
      `Hi ${name},`,
      '',
      'Welcome to AgentPayments. Click the link below to verify your email address and activate your account:',
      '',
      link,
      '',
      'This link expires in 24 hours.',
      '',
      'If you did not sign up, you can ignore this email.',
      '',
      '— The AgentPayments team',
    ].join('\n'),
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:system-ui,sans-serif;max-width:520px;margin:40px auto;color:#333;padding:0 20px">
  <h2 style="font-size:20px;margin-bottom:4px">Verify your AgentPayments account</h2>
  <p>Hi ${escapeHtml(name)},</p>
  <p>Welcome to AgentPayments. Click the button below to verify your email and activate your account.</p>
  <p style="margin:28px 0">
    <a href="${link}"
       style="background:#111;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;display:inline-block">
      Verify email address
    </a>
  </p>
  <p style="font-size:13px;color:#666">Or copy this link: <code style="word-break:break-all">${link}</code></p>
  <p style="font-size:13px;color:#666">This link expires in 24 hours. If you didn't sign up, you can ignore this email.</p>
</body>
</html>`,
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

module.exports = { sendVerificationEmail };
