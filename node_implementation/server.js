const path = require('node:path');

const express = require('express');
const dotenv = require('dotenv');
const { agentPaymentsGate } = require('./lib/agentpayments-middleware');

dotenv.config();

const app = express();
const staticDir = path.join(__dirname, 'static');
const parsedPort = Number.parseInt(process.env.PORT || '3000', 10);
const port = Number.isFinite(parsedPort) ? parsedPort : 3000;
const host = process.env.HOST || '127.0.0.1';

app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));

// In a real customer app this import would come from the published package, e.g.:
// const { agentPaymentsGate } = require('@agentpayments/node');
app.use(agentPaymentsGate({
  challengeSecret: process.env.CHALLENGE_SECRET,
  verifyUrl: process.env.AGENTPAYMENTS_VERIFY_URL,
  apiKey: process.env.AGENTPAYMENTS_API_KEY,
}));

app.get('/.well-known/agent-access.json', (_req, res) => {
  res.sendFile(path.join(staticDir, '.well-known', 'agent-access.json'));
});

app.get('/robots.txt', (_req, res) => {
  res.sendFile(path.join(staticDir, 'robots.txt'));
});

app.use(express.static(staticDir, { extensions: ['html'] }));

app.get('*', (_req, res) => {
  res.sendFile(path.join(staticDir, 'index.html'));
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(port, host, () => {
    console.log(`Node deployment listening on http://${host}:${port}`);
  });
}

module.exports = app;
