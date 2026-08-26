import type { RequestHandler } from 'express';

export interface GrantStore {
  has(key: string): boolean | Promise<boolean>;
  add(key: string): void | Promise<void>;
}

export interface RateLimiter {
  check(ip: string): boolean | Promise<boolean>;
}

export interface PaymentCache {
  get(key: string): unknown;
  set(key: string, value: unknown, ttlMs: number): void;
}

export interface AgentPaymentsGateConfig {
  /** HMAC secret for signing agent keys and cookies. Required for production. */
  challengeSecret?: string;
  /** Solana wallet address to receive USDC payments. */
  homeWalletAddress?: string;
  /** Custom Solana RPC URL (string) or list of RPC URLs to fall back across. Defaults to devnet/mainnet based on debug flag. */
  solanaRpcUrl?: string | string[];
  /** Custom USDC mint address. Defaults to devnet/mainnet based on debug flag. */
  usdcMint?: string;
  /** Minimum payment amount required, in USDC. */
  minPayment?: number;
  /** Proof-of-work difficulty for the browser challenge page. */
  powDifficulty?: number;
  /** Enable debug mode (devnet). Defaults to process.env.DEBUG !== 'false'. */
  debug?: boolean;
  /** Allow verified search crawlers (Googlebot, Bingbot, etc.) through without a challenge or payment. Default: true. */
  verifyCrawlers?: boolean;
  /** Optional persistent grant store so paid keys don't need to be re-scanned on-chain. */
  grantStore?: GrantStore | null;
  /** Optional pluggable rate limiter for the challenge-verify endpoint. */
  rateLimiter?: RateLimiter | null;
  /** Optional pluggable rate limiter for agent-key payment verification. */
  agentKeyRateLimiter?: RateLimiter | null;
  /** Optional pluggable payment verification cache. */
  paymentCache?: PaymentCache | null;
  /** Optional pluggable rate limiter for challenge page issuance. */
  challengeRateLimiter?: RateLimiter | null;
  /** Reject requests that do not arrive over HTTPS. Defaults to true outside debug mode. */
  requireHttps?: boolean;
  /** Platform API key (ap_live_...) from api.agentpayments.dev. When set, agent keys are issued via the hosted platform (metered, billed) instead of locally. */
  apiKey?: string | null;
  /** Override the platform API URL for a self-hosted platform. */
  platformApiUrl?: string;
}

/**
 * Creates an Express middleware that gates access behind Solana USDC payments.
 *
 * Browser visitors see a JavaScript challenge page.
 * API clients (agents) must provide a valid, paid agent key via the X-Agent-Key header.
 *
 * @example
 * ```js
 * const { agentPaymentsGate } = require('@agentpayments/node');
 *
 * app.use(agentPaymentsGate({
 *   challengeSecret: process.env.CHALLENGE_SECRET,
 *   homeWalletAddress: process.env.HOME_WALLET_ADDRESS,
 *   solanaRpcUrl: process.env.SOLANA_RPC_URL,
 *   usdcMint: process.env.USDC_MINT,
 * }));
 * ```
 */
export function agentPaymentsGate(config?: AgentPaymentsGateConfig): RequestHandler;
