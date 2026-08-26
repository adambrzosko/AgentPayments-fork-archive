import { createNetlifyGate } from './sdk/netlify.js';

// Stripe-style integration target:
// thin wrapper only, shared gate logic lives in sdk/
// SDK files are copied here at build time (see netlify.toml build command).
export default createNetlifyGate();
