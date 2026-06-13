# Next.js Deployment (Test Website)

Demo Next.js app wired the same way a customer app should be: importing `@agentpayments/next`.

## Run locally
```bash
cd next_implementation
cp .env.example .env.local
npm install
npm run dev
```

## Vercel
Set these env vars in project settings:
- CHALLENGE_SECRET
- AGENTPAYMENTS_VERIFY_URL
- AGENTPAYMENTS_API_KEY

For this monorepo setup, deploy with project root set to `next_implementation` from the repo root (so `file:../sdk/next` resolves during install).