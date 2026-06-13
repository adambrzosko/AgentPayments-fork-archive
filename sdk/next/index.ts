import { NextResponse } from 'next/server';
import { createVercelEdgeGate } from '../edge/vercel.js';

type EnvConfig = {
  CHALLENGE_SECRET?: string;
  AGENTPAYMENTS_VERIFY_URL?: string;
  AGENTPAYMENTS_API_KEY?: string;
};

type Options = {
  env?: EnvConfig;
  publicPathAllowlist?: string[];
  minPayment?: number;
};

export function createNextMiddleware(options: Options = {}) {
  const env: EnvConfig = options.env || {
    CHALLENGE_SECRET: process.env.CHALLENGE_SECRET,
    AGENTPAYMENTS_VERIFY_URL: process.env.AGENTPAYMENTS_VERIFY_URL,
    AGENTPAYMENTS_API_KEY: process.env.AGENTPAYMENTS_API_KEY,
  };

  return createVercelEdgeGate({
    env,
    publicPathAllowlist: options.publicPathAllowlist || [],
    minPayment: options.minPayment,
    upstreamNext: () => NextResponse.next(),
    getClientIp: (request) =>
      request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown',
  });
}
