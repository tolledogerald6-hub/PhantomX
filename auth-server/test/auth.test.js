'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createApp } = require('../src/server');

const ADMIN = 'test-admin-token-0123456789abcdef';

// Verify exactly the way the C++ loader does: raw 64-byte pubkey, raw r||s sig.
function verifyLikeLoader(pubHex, { payload, sig }) {
  const raw = Buffer.from(pubHex, 'hex');
  const key = crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: raw.subarray(0, 32).toString('base64url'), y: raw.subarray(32).toString('base64url') },
    format: 'jwk',
  });
  const bytes = Buffer.from(payload, 'base64');
  const ok = crypto.verify('sha256', bytes, { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'base64'));
  return ok ? JSON.parse(bytes.toString('utf8')) : null;
}

test('auth flow', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phx-auth-'));
  const { server } = createApp({
    dataDir, adminToken: ADMIN, keyPrefix: 'PHX', minLoaderVersion: 2,
    trustProxy: false, authRatePerMinute: 1000, adminRatePerMinute: 1000,
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}/api/v1`;
  t.after(() => new Promise((r) => server.close(r)));

  const call = async (method, p, body, admin = false) => {
    const res = await fetch(base + p, {
      method,
      headers: { 'Content-Type': 'application/json', ...(admin ? { Authorization: `Bearer ${ADMIN}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { code: res.status, body: await res.json() };
  };

  const pubHex = (await call('GET', '/pubkey')).body.public_key_hex;
  const nonce = () => crypto.randomBytes(16).toString('hex');
  const auth = async (key, hwid, version = 2) => {
    const n = nonce();
    const r = await call('POST', '/auth', { key, hwid, nonce: n, version });
    assert.equal(r.code, 200);
    const p = verifyLikeLoader(pubHex, r.body);
    assert.ok(p, 'signature must verify');
    assert.equal(p.nonce, n);
    return p;
  };

  // admin auth required
  assert.equal((await call('GET', '/admin/keys')).code, 401);

  const { body } = await call('POST', '/admin/keys', { count: 2, days: 30, note: 't' }, true);
  assert.equal(body.keys.length, 2);
  const [key, key2] = body.keys;
  assert.match(key, /^PHX(-[A-Z2-9]{5}){4}$/);

  const hwidA = 'a'.repeat(64);
  const hwidB = 'b'.repeat(64);

  assert.equal((await auth('PHX-NOPE', hwidA)).status, 'invalid_key');
  assert.equal((await auth(key, hwidA, 1)).status, 'outdated');

  const first = await auth(key.toLowerCase(), hwidA);
  assert.equal(first.status, 'ok');
  assert.equal(first.ok, true);
  assert.ok(first.expires_at > first.server_time + 29 * 86400);

  assert.equal((await auth(key, hwidA)).status, 'ok');
  assert.equal((await auth(key, hwidB)).status, 'hwid_mismatch');

  // tampered payload must fail verification
  const r = await call('POST', '/auth', { key, hwid: hwidB, nonce: nonce(), version: 2 });
  const forged = Buffer.from(Buffer.from(r.body.payload, 'base64').toString().replace('"ok":false', '"ok":true '));
  assert.equal(verifyLikeLoader(pubHex, { payload: forged.toString('base64'), sig: r.body.sig }), null);

  // hwid reset keeps expiry
  assert.equal((await call('POST', `/admin/keys/${key}/reset-hwid`, {}, true)).code, 200);
  const moved = await auth(key, hwidB);
  assert.equal(moved.status, 'ok');
  assert.equal(moved.expires_at, first.expires_at);

  // extend
  await call('POST', `/admin/keys/${key}/extend`, { days: 5 }, true);
  assert.equal((await auth(key, hwidB)).expires_at, first.expires_at + 5 * 86400);

  // ban / unban
  await call('POST', `/admin/keys/${key}/ban`, { reason: 'x' }, true);
  assert.equal((await auth(key, hwidB)).status, 'banned');
  await call('POST', `/admin/keys/${key}/unban`, {}, true);
  assert.equal((await auth(key, hwidB)).status, 'ok');

  // info + delete
  const info = await call('GET', `/admin/keys/${key2}`, null, true);
  assert.equal(info.body.key.hwid_locked, false);
  assert.equal((await call('DELETE', `/admin/keys/${key2}`, null, true)).code, 200);
  assert.equal((await auth(key2, hwidA)).status, 'invalid_key');

  // bad nonce rejected
  assert.equal((await call('POST', '/auth', { key, hwid: hwidA, nonce: 'zz' })).code, 400);
});

test('expired key', async () => {
  const { openDb } = require('../src/db');
  const { LicenseStore } = require('../src/license');
  const db = openDb(fs.mkdtempSync(path.join(os.tmpdir(), 'phx-exp-')));
  const store = new LicenseStore(db);
  const [k] = store.createKeys(1, 1);
  assert.equal(store.authenticate({ key: k, hwid: 'h'.repeat(16) }).status, 'ok');
  db.prepare('UPDATE keys SET expires_at = 1 WHERE key = ?').run(k);
  assert.equal(store.authenticate({ key: k, hwid: 'h'.repeat(16) }).status, 'expired');
  const [life] = store.createKeys(1, 0);
  const r = store.authenticate({ key: life, hwid: 'h'.repeat(16) });
  assert.equal(r.status, 'ok');
  assert.equal(r.expires_at, null);
  db.close();
});
