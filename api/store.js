/**
 * Store factory — selects Postgres or JSON-file backend based on environment.
 *
 *   DATABASE_URL set → store-pg.js  (production)
 *   DATABASE_URL absent → store-json.js  (local dev)
 */
'use strict';

module.exports = process.env.DATABASE_URL
  ? require('./store-pg')
  : require('./store-json');
