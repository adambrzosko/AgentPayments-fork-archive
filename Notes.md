## Thoughts
If an agent can't access a website, are they less likely to hit it in future?

## Competition

#### Cloudflare Pay-Per-Crawl
[Docs](https://blog.cloudflare.com/introducing-pay-per-crawl/?utm_source=chatgpt.com/)

Features
* Decides whether to charge based on origin of crawler

Advantages
* Simple add-on feature for existing Cloudflare clients (~20% of internet traffic)
* Can immediately charge crawlers with CF billing relationship

Disadvantages
* Can ONLY charge crawlers with an existing CF billing relationship
* Flat charge, not configurable beyond yes/no per crawler origin
* Vendor must already be a Cloudflare customer
* No support for arbitrary AI agents or custom payment flows

#### Skyfire AI
[Website](https://www.skyfire.xyz/)

Features
* Agent-to-agent payment network with a managed wallet infrastructure
* Agents get a "Skyfire wallet" funded by developers, used for API/data purchases

Advantages
* Purpose-built for AI agent commerce (agent wallets, usage metering)
* Backed by VC funding and partnerships

Disadvantages
* Closed ecosystem — both the agent and the vendor must be on Skyfire's network
* Centralized custody (Skyfire holds the wallets)
* No self-serve open-source SDK for vendors to drop in
* Limited to their marketplace of data/API providers

#### Our Differentiators
* **Open-source, self-hosted SDK** — vendor keeps full control, no platform lock-in
* **Any AI agent can pay** — uses Solana USDC on-chain, no pre-existing billing relationship needed
* **Multi-runtime support** — Node, Edge (Cloudflare/Netlify/Vercel), Next.js, Python (Django/FastAPI/Flask)
* **Stripe-style DX** — install package, add 2-3 lines, ship
* **On-chain verification** — payment proof is public and auditable
