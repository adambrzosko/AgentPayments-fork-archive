## TODO

### Completed
* ~~Get sites hosted~~ — Cloudflare, Django (Oracle VM), Next.js (Vercel), Netlify all deployed
* ~~Package bot blocking into a library~~ — `sdk/node`, `sdk/edge`, `sdk/python`, `sdk/next` all complete
* ~~Figure out how to implement into the three deployments~~ — demo wrappers in `node_implementation/`, `edge_implementation/`, `python_implementation/`, `next_implementation/`
* ~~Centralize constants~~ — `sdk/constants.json` is single source of truth
* ~~Add TypeScript types~~ — `index.d.ts` for Node and Edge SDKs
* ~~Add payment verification caching~~ — 10-min TTL, 1000 entries max
* ~~Add rate limiting~~ — 20 req/min/IP on challenge verify
* ~~Add input size limits~~ — all user inputs capped
* ~~Add timing-safe HMAC comparison~~ — all SDKs
* ~~Add wallet address validation~~ — base58, 32-44 chars
* ~~Add default secret detection~~ — warn in debug, throw in production
* ~~Add structured JSON logging~~ — Node/Edge SDKs
* ~~Add challenge page accessibility~~ — spinner, noscript fallback, ARIA

### In Progress
* Improve bot communication — ChatGPT and other LLM agents don't reliably read the 402 response instructions
* Flesh out backend — payment tracking, vendor dashboard

### Up Next
* Proxy adapter (Nginx/Envoy style enforcement)
* Write a comprehensive test script to hit all deployments
* Publish SDKs to npm / PyPI
* Fastify and Koa adapter wrappers (reuse Node SDK core)

## Ultimate Goals

#### Vendor Payment Rails
* A GitHub repo which a vendor simply pip installs / npm installs, drops a few lines of code, and it works.
  * Bots are blocked and told to pay
  * Payments are received to our wallet
    * For now, converting to cash and sending to vendors manually is fine
    * May even make sense to send them small amounts to improve word of mouth

#### Vendor UI
* A website where a vendor enters their bank details, verifies ownership of their resource

#### Agent Wallet
* A USDC/Solana wallet service for AI agents
* Demonstration to the ecosystem that agent-native payments work
* Likely harder technically than the core product for an MVP
