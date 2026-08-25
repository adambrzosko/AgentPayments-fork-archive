import app from './app.js';

const PORT = process.env.PORT || 8787;
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;

app.listen(PORT, () => {
  console.log(`LLM Wallet Hub running on ${APP_BASE_URL}`);
});
