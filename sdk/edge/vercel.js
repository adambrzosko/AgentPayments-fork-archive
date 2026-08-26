import { createEdgeGate } from './index.js';

// Vercel adapter (Edge Middleware / Route Handler runtime).
// Caller provides upstreamNext() to return NextResponse.next() (or equivalent).
export function createVercelEdgeGate(options = {}) {
  const {
    publicPathAllowlist = [],
    minPayment,
    powDifficulty,
    env = {},
    upstreamNext,
    getClientIp,
  } = options;

  if (typeof upstreamNext !== 'function') {
    throw new Error('createVercelEdgeGate requires upstreamNext(request)');
  }

  const gate = createEdgeGate({
    publicPathAllowlist,
    minPayment,
    powDifficulty,
    getClientIp: ({ request }) =>
      (getClientIp ? getClientIp(request) : request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()) || 'unknown',
    fetchUpstream: (request) => upstreamNext(request),
  });

  return (request) => gate(request, env, {});
}
