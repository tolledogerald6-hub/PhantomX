'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const { openDb } = require('./db');
const { LicenseStore, now } = require('./license');
const { loadOrCreateSigningKey, rawPublicKey, signPayload } = require('./signing');

const MAX_BODY = 8 * 1024;

// ---------- helpers ----------

function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(Object.assign(new Error('Body too large'), { code: 413 }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (size === 0) return resolve({});
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(v && typeof v === 'object' && !Array.isArray(v) ? v : {});
      } catch {
        reject(Object.assign(new Error('Invalid JSON'), { code: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function clientIp(req, trustProxy) {
  if (trustProxy) {
    const fwd = req.headers['x-forwarded-for'];
    if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  }
  return req.socket.remoteAddress || '';
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

class RateLimiter {
  constructor(perMinute) {
    this.perMinute = perMinute;
    this.hits = new Map();
    this.timer = setInterval(() => this.hits.clear(), 60_000);
    this.timer.unref();
  }
  allow(id) {
    const n = (this.hits.get(id) || 0) + 1;
    this.hits.set(id, n);
    return n <= this.perMinute;
  }
  stop() { clearInterval(this.timer); }
}

const publicRow = (r) => r && {
  key: r.key,
  duration_days: r.duration_days,
  note: r.note,
  hwid_locked: r.hwid_hash !== null,
  created_at: r.created_at,
  activated_at: r.activated_at,
  expires_at: r.expires_at,
  last_seen_at: r.last_seen_at,
  last_ip: r.last_ip,
  banned: !!r.banned,
  ban_reason: r.ban_reason,
};

// ---------- app ----------

function createApp(cfg) {
  if (!cfg.adminToken || cfg.adminToken.length < 24) {
    throw new Error('ADMIN_TOKEN must be set and at least 24 characters long.');
  }
  const db = openDb(cfg.dataDir);
  const store = new LicenseStore(db, cfg);
  const { privateKey, publicKey } = loadOrCreateSigningKey(cfg.dataDir);
  const pubHex = rawPublicKey(publicKey).toString('hex');
  const authLimiter = new RateLimiter(cfg.authRatePerMinute);
  const adminLimiter = new RateLimiter(cfg.adminRatePerMinute);

  async function handleAuth(req, res, ip) {
    if (!authLimiter.allow(ip)) return send(res, 429, { error: 'Too many requests' });
    const body = await readJson(req);
    const nonce = typeof body.nonce === 'string' ? body.nonce : '';
    if (!/^[0-9a-f]{32,128}$/i.test(nonce)) return send(res, 400, { error: 'Invalid nonce' });

    const r = store.authenticate(
      { key: body.key, hwid: body.hwid, version: body.version },
      ip
    );
    // The loader must check that nonce / key / hwid echo back what it sent.
    const payload = {
      v: 1,
      ok: r.status === 'ok',
      status: r.status,
      message: r.message,
      key: typeof body.key === 'string' ? body.key.trim().toUpperCase().slice(0, 64) : '',
      hwid: typeof body.hwid === 'string' ? body.hwid.slice(0, 256) : '',
      nonce,
      expires_at: r.expires_at ?? 0, // 0 = lifetime (or not ok)
      server_time: now(),
    };
    send(res, 200, signPayload(privateKey, payload));
  }

  async function handleAdmin(req, res, ip, parts) {
    if (!adminLimiter.allow(ip)) return send(res, 429, { error: 'Too many requests' });
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (!safeEqual(token, cfg.adminToken)) return send(res, 401, { error: 'Unauthorized' });

    const m = req.method;
    // parts: ['keys'] | ['keys', KEY] | ['keys', KEY, action]
    if (parts[0] !== 'keys') return send(res, 404, { error: 'Not found' });

    if (parts.length === 1) {
      if (m === 'GET') {
        const url = new URL(req.url, 'http://x');
        const limit = Math.min(Number.parseInt(url.searchParams.get('limit') || '100', 10) || 100, 1000);
        const offset = Math.max(Number.parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);
        return send(res, 200, { keys: store.list(limit, offset).map(publicRow) });
      }
      if (m === 'POST') {
        const b = await readJson(req);
        try {
          const keys = store.createKeys(b.count ?? 1, b.days ?? 30, typeof b.note === 'string' ? b.note.slice(0, 200) : null);
          return send(res, 201, { keys });
        } catch (e) {
          return send(res, 400, { error: e.message });
        }
      }
      return send(res, 405, { error: 'Method not allowed' });
    }

    const key = decodeURIComponent(parts[1]);
    const action = parts[2];

    if (!action) {
      if (m === 'GET') {
        const row = store.get(key);
        return row ? send(res, 200, { key: publicRow(row), logs: store.logs(key, 50) }) : send(res, 404, { error: 'Key not found' });
      }
      if (m === 'DELETE') return store.delete(key) ? send(res, 200, { ok: true }) : send(res, 404, { error: 'Key not found' });
      return send(res, 405, { error: 'Method not allowed' });
    }

    if (m !== 'POST') return send(res, 405, { error: 'Method not allowed' });
    const b = await readJson(req);
    let ok;
    switch (action) {
      case 'reset-hwid': ok = store.resetHwid(key); break;
      case 'ban': ok = store.ban(key, typeof b.reason === 'string' ? b.reason.slice(0, 200) : null); break;
      case 'unban': ok = store.unban(key); break;
      case 'extend':
        try { ok = store.extend(key, b.days); } catch (e) { return send(res, 400, { error: e.message }); }
        break;
      default: return send(res, 404, { error: 'Not found' });
    }
    return ok ? send(res, 200, { ok: true, key: publicRow(store.get(key)) }) : send(res, 404, { error: 'Key not found' });
  }

  const server = http.createServer(async (req, res) => {
    const ip = clientIp(req, cfg.trustProxy);
    try {
      const pathname = new URL(req.url, 'http://x').pathname.replace(/\/+$/, '');
      const parts = pathname.split('/').filter(Boolean); // ['api','v1',...]
      if (parts[0] !== 'api' || parts[1] !== 'v1') return send(res, 404, { error: 'Not found' });
      const rest = parts.slice(2);

      if (rest[0] === 'health' && req.method === 'GET') return send(res, 200, { ok: true, time: now() });
      if (rest[0] === 'pubkey' && req.method === 'GET') return send(res, 200, { alg: 'ECDSA-P256-SHA256', public_key_hex: pubHex });
      if (rest[0] === 'auth' && rest.length === 1) {
        if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
        return await handleAuth(req, res, ip);
      }
      if (rest[0] === 'admin') return await handleAdmin(req, res, ip, rest.slice(1));
      return send(res, 404, { error: 'Not found' });
    } catch (e) {
      if (e.code === 400 || e.code === 413) return send(res, e.code, { error: e.message });
      console.error(e);
      if (!res.headersSent) send(res, 500, { error: 'Internal error' });
    }
  });

  server.on('close', () => {
    authLimiter.stop();
    adminLimiter.stop();
    db.close();
  });

  return { server, store };
}

if (require.main === module) {
  const cfg = require('./config');
  let app;
  try {
    app = createApp(cfg);
  } catch (e) {
    console.error(`[auth] ${e.message}`);
    process.exit(1);
  }
  app.server.listen(cfg.port, cfg.host, () => {
    console.log(`[auth] listening on http://${cfg.host}:${cfg.port}  (data: ${cfg.dataDir})`);
  });
  const shutdown = () => app.server.close(() => process.exit(0));
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

module.exports = { createApp };
