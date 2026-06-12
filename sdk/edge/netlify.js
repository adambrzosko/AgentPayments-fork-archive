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
      HOME_WALLET_ADDRESS: Deno.env.get('HOME_WALLET_ADDRESS') || '',
      SOLANA_RPC_URL: Deno.env.get('SOLANA_RPC_URL') || '',
      USDC_MINT: Deno.env.get('USDC_MINT') || '',
      DEBUG: Deno.env.get('DEBUG') ?? 'true',
    }),
    fetchUpstream: (request, _env, context) => context.next(request),
  });

  return (request, context) => gate(request, {}, context);
}
