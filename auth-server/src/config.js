'use strict';

const path = require('node:path');

function int(name, def) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) throw new Error(`${name} must be an integer`);
  return n;
}

const config = {
  host: process.env.HOST || '0.0.0.0',
  port: int('PORT', 8080),
  dataDir: path.resolve(process.env.DATA_DIR || path.join(__dirname, '..', 'data')),
  adminToken: process.env.ADMIN_TOKEN || '',
  keyPrefix: (process.env.KEY_PREFIX || 'PHX').toUpperCase(),
  // Loaders reporting a lower version get status "outdated". 0 disables the check.
  minLoaderVersion: int('MIN_LOADER_VERSION', 0),
  // Set to 1 only when running behind a reverse proxy (nginx/Caddy/Cloudflare).
  trustProxy: process.env.TRUST_PROXY === '1',
  authRatePerMinute: int('AUTH_RATE_PER_MINUTE', 20),
  adminRatePerMinute: int('ADMIN_RATE_PER_MINUTE', 60),
};

module.exports = config;
