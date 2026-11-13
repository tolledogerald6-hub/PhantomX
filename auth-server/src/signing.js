'use strict';

// Every auth response is signed with ECDSA P-256 / SHA-256. The loader holds
// only the public key, so a fake server (hosts-file redirect, MITM, etc.)
// cannot forge an "ok" answer. P-256 is used because Windows BCrypt can
// verify it natively — no extra libraries in the loader.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function loadOrCreateSigningKey(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const file = path.join(dataDir, 'signing_key.pem');
  if (!fs.existsSync(file)) {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    fs.writeFileSync(file, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  }
  const privateKey = crypto.createPrivateKey(fs.readFileSync(file));
  const publicKey = crypto.createPublicKey(privateKey);
  return { privateKey, publicKey };
}

// Raw 64-byte public key: X (32) || Y (32). This is what the loader embeds.
function rawPublicKey(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  return Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
}

// Returns { payload, sig } — both base64. The signature covers the exact
// payload bytes; signature format is raw r||s (64 bytes), as BCrypt expects.
function signPayload(privateKey, obj) {
  const bytes = Buffer.from(JSON.stringify(obj), 'utf8');
  const sig = crypto.sign('sha256', bytes, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return { payload: bytes.toString('base64'), sig: sig.toString('base64') };
}

function cppPublicKeyArray(publicKey) {
  const raw = rawPublicKey(publicKey);
  const hex = [...raw].map((b) => '0x' + b.toString(16).padStart(2, '0'));
  const lines = [];
  for (let i = 0; i < hex.length; i += 16) lines.push('    ' + hex.slice(i, i + 16).join(', '));
  return `static const unsigned char kServerPublicKey[64] = {\n${lines.join(',\n')}\n};`;
}

module.exports = { loadOrCreateSigningKey, rawPublicKey, signPayload, cppPublicKeyArray };
