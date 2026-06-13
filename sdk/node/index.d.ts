import type { RequestHandler } from 'express';

export interface AgentPaymentsGateConfig {
  /** HMAC secret for signing agent keys and cookies. Required for production. */
  challengeSecret?: string;
  /** URL of the AgentPayments verify service. */
  verifyUrl?: string;
  /** Per-merchant API key for the verify service. */
  apiKey?: string;
}

/**
 * Creates an Express middleware that gates access behind Solana USDC payments.
 *
 * Browser visitors see a JavaScript challenge page.
 * API clients (agents) must provide a valid, paid agent key via the X-Agent-Key header.
 *
 * Wallet address and network are fetched automatically from the verify service.
 *
 * @example
 * ```js
 * const { agentPaymentsGate } = require('@agentpayments/node');
 *
 * app.use(agentPaymentsGate({
 *   challengeSecret: process.env.CHALLENGE_SECRET,
 *   verifyUrl: process.env.AGENTPAYMENTS_VERIFY_URL,
 *   apiKey: process.env.AGENTPAYMENTS_API_KEY,
 * }));
 * ```
 */
export function agentPaymentsGate(config?: AgentPaymentsGateConfig): RequestHandler;
