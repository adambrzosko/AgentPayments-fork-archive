import { createEdgeGate } from './index.js';

export function createNetlifyGate(options = {}) {
  const { publicPathAllowlist = [], minPayment, powDifficulty } = options;

  const gate = createEdgeGate({
    publicPathAllowlist,
    minPayment,
    powDifficulty,
    getClientIp: ({ context }) => context?.ip || 'unknown',
    envResolver: () => ({
      CHALLENGE_SECRET: Deno.env.get('CHALLENGE_SECRET') || 'default-secret-change-me',
      AGENTPAYMENTS_VERIFY_URL: Deno.env.get('AGENTPAYMENTS_VERIFY_URL') || '',
      AGENTPAYMENTS_API_KEY: Deno.env.get('AGENTPAYMENTS_API_KEY') || '',
    }),
    fetchUpstream: (request, _env, context) => context.next(request),
  });

  return (request, context) => gate(request, {}, context);
}
