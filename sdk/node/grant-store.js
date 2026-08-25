/**
 * Grant stores for durable paid-key persistence (P0 #5).
 *
 * The 10-minute payment verification cache is NOT persistence — once a wallet
 * receives 100+ newer transactions the original payment can no longer be found
 * in the last-100-signatures scan. A grant store fixes this: once a key is
 * verified it is recorded permanently and never needs re-scanning.
 *
 * Usage — pass to agentPaymentsGate:
 *
 *   const { agentPaymentsGate } = require('@agentpayments/node');
 *   const { FileGrantStore } = require('@agentpayments/node/grant-store');
 *
 *   app.use(agentPaymentsGate({
 *     ...config,
 *     grantStore: new FileGrantStore('./data/grants.json'),
 *   }));
 *
 * Grant store interface (implement your own for Redis, Postgres, etc.):
 *
 *   interface GrantStore {
 *     has(agentKey: string): boolean | Promise<boolean>
 *     add(agentKey: string): void | Promise<void>
 *   }
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

/**
 * In-memory grant store. Survives restarts only if combined with a persistent
 * backing store. Useful as a default / for testing.
 */
class MemoryGrantStore {
  constructor() {
    this._grants = new Set();
  }
  has(key) { return this._grants.has(key); }
  add(key) { this._grants.add(key); }
}

/**
 * File-backed grant store. Persists grants to a JSON file on disk so they
 * survive server restarts. Write is atomic (temp-file + rename).
 *
 * Not suitable for multi-process deployments — use Redis or a database there.
 */
class FileGrantStore {
  /**
   * @param {string} filePath  Absolute or relative path to the JSON grants file.
   *                           The file is created if it does not exist.
   */
  constructor(filePath) {
    this._path = path.resolve(filePath);
    this._grants = new Set();
    this._load();
  }

  _load() {
    try {
      const raw = fs.readFileSync(this._path, 'utf8');
      const keys = JSON.parse(raw);
      if (Array.isArray(keys)) keys.forEach((k) => this._grants.add(k));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err; // only ignore missing file
    }
  }

  _save() {
    fs.mkdirSync(path.dirname(this._path), { recursive: true });
    const tmp = this._path + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify([...this._grants], null, 2), 'utf8');
    fs.renameSync(tmp, this._path);
  }

  has(key) { return this._grants.has(key); }

  add(key) {
    if (this._grants.has(key)) return;
    this._grants.add(key);
    this._save();
  }
}

module.exports = { MemoryGrantStore, FileGrantStore };
