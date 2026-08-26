/**
 * Runs schema.sql against DATABASE_URL using the `pg` package directly, rather than
 * shelling out to the `psql` binary — the deploy image isn't guaranteed to have it
 * installed. Safe to run on every deploy: schema.sql only uses CREATE TABLE/INDEX
 * IF NOT EXISTS.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('pg');

async function main() {
  if (!process.env.DATABASE_URL) {
    console.log('DATABASE_URL not set — skipping migration (JSON-file store in use).');
    return;
  }

  const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false },
  });

  await client.connect();
  try {
    await client.query(sql);
    console.log('Migration applied successfully.');
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('Migration failed:', err.message);
  process.exit(1);
});
