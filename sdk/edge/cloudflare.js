import { createEdgeGate } from './index.js';

export function createAgentPaymentsWorker(options = {}) {
  const { assetsBinding = 'ASSETS', publicPathAllowlist = [], minPayment, powDifficulty } = options;

  const gate = createEdgeGate({
    publicPathAllowlist,
    minPayment,
    powDifficulty,
    getClientIp: ({ request }) => request.headers.get('cf-connecting-ip') || 'unknown',
    fetchUpstream: (request, env) => {
      const binding = env[assetsBinding];
      if (!binding || typeof binding.fetch !== 'function') {
        return new Response(`${assetsBinding} binding is missing.`, { status: 500 });
      }
      return binding.fetch(request);
    },
  });

  return {
    fetch(request, env, context) {
      return gate(request, env, context);
    },
  };
}
