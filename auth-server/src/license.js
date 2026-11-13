'use strict';

const crypto = require('node:crypto');

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
const DAY = 86400;

const now = () => Math.floor(Date.now() / 1000);
const hashHwid = (hwid) => crypto.createHash('sha256').update(String(hwid)).digest('hex');

function generateKeyString(prefix) {
  const groups = [];
  for (let g = 0; g < 4; g++) {
    let s = '';
    for (let i = 0; i < 5; i++) s += ALPHABET[crypto.randomInt(ALPHABET.length)];
    groups.push(s);
  }
  return `${prefix}-${groups.join('-')}`;
}

function normalizeKey(key) {
  return typeof key === 'string' ? key.trim().toUpperCase() : '';
}

class LicenseStore {
  constructor(db, { keyPrefix = 'PHX', minLoaderVersion = 0 } = {}) {
    this.db = db;
    this.keyPrefix = keyPrefix;
    this.minLoaderVersion = minLoaderVersion;
    this.q = {
      insert: db.prepare('INSERT INTO keys (key, duration_days, note, created_at) VALUES (?, ?, ?, ?)'),
      get: db.prepare('SELECT * FROM keys WHERE key = ?'),
      list: db.prepare('SELECT * FROM keys ORDER BY created_at DESC LIMIT ? OFFSET ?'),
      activate: db.prepare(
        'UPDATE keys SET hwid_hash = ?, activated_at = ?, expires_at = ? WHERE key = ? AND hwid_hash IS NULL'
      ),
      bindHwid: db.prepare('UPDATE keys SET hwid_hash = ? WHERE key = ? AND hwid_hash IS NULL'),
      seen: db.prepare('UPDATE keys SET last_seen_at = ?, last_ip = ? WHERE key = ?'),
      resetHwid: db.prepare('UPDATE keys SET hwid_hash = NULL WHERE key = ?'),
      ban: db.prepare('UPDATE keys SET banned = 1, ban_reason = ? WHERE key = ?'),
      unban: db.prepare('UPDATE keys SET banned = 0, ban_reason = NULL WHERE key = ?'),
      extend: db.prepare('UPDATE keys SET duration_days = duration_days + ?, expires_at = expires_at + ? WHERE key = ?'),
      del: db.prepare('DELETE FROM keys WHERE key = ?'),
      log: db.prepare('INSERT INTO auth_log (ts, key, ip, status) VALUES (?, ?, ?, ?)'),
      logs: db.prepare('SELECT ts, ip, status FROM auth_log WHERE key = ? ORDER BY id DESC LIMIT ?'),
    };
  }

  createKeys(count, durationDays, note = null) {
    if (!Number.isInteger(count) || count < 1 || count > 1000) throw new Error('count must be 1..1000');
    if (!Number.isInteger(durationDays) || durationDays < 0 || durationDays > 36500)
      throw new Error('days must be 0..36500 (0 = lifetime)');
    const keys = [];
    const t = now();
    this.db.exec('BEGIN');
    try {
      while (keys.length < count) {
        const k = generateKeyString(this.keyPrefix);
        try {
          this.q.insert.run(k, durationDays, note, t);
          keys.push(k);
        } catch (e) {
          if (!String(e.message).includes('UNIQUE')) throw e; // collision: retry
        }
      }
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
    return keys;
  }

  get(key) {
    const row = this.q.get.get(normalizeKey(key));
    return row ? { ...row } : null;
  }

  list(limit = 100, offset = 0) {
    return this.q.list.all(limit, offset).map((r) => ({ ...r }));
  }

  logs(key, limit = 50) {
    return this.q.logs.all(normalizeKey(key), limit).map((r) => ({ ...r }));
  }

  resetHwid(key) { return this.q.resetHwid.run(normalizeKey(key)).changes > 0; }
  ban(key, reason = null) { return this.q.ban.run(reason, normalizeKey(key)).changes > 0; }
  unban(key) { return this.q.unban.run(normalizeKey(key)).changes > 0; }
  delete(key) { return this.q.del.run(normalizeKey(key)).changes > 0; }

  extend(key, days) {
    if (!Number.isInteger(days) || days < 1) throw new Error('days must be a positive integer');
    const row = this.get(key);
    if (!row) return false;
    if (row.duration_days === 0) return true; // lifetime already
    this.q.extend.run(days, days * DAY, row.key);
    return true;
  }

  /**
   * Core check. Returns { status, message, expires_at }.
   * status: ok | bad_request | invalid_key | banned | expired | hwid_mismatch | outdated
   */
  authenticate({ key, hwid, version }, ip) {
    const k = normalizeKey(key);
    const t = now();
    const result = this._check(k, hwid, version, ip, t);
    this.q.log.run(t, k || null, ip || null, result.status);
    return result;
  }

  _check(k, hwid, version, ip, t) {
    if (!k || k.length > 64 || typeof hwid !== 'string' || hwid.length < 8 || hwid.length > 256) {
      return { status: 'bad_request', message: 'Invalid request.' };
    }
    if (this.minLoaderVersion > 0 && !(Number.isInteger(version) && version >= this.minLoaderVersion)) {
      return { status: 'outdated', message: 'Loader is outdated. Please download the latest version.' };
    }

    const row = this.q.get.get(k);
    if (!row) return { status: 'invalid_key', message: 'Invalid license key.' };
    if (row.banned) return { status: 'banned', message: 'This key has been banned.' };

    const h = hashHwid(hwid);
    let expiresAt = row.expires_at;

    if (row.hwid_hash === null) {
      if (row.activated_at === null) {
        // First use: start the clock and bind to this machine.
        expiresAt = row.duration_days === 0 ? null : t + row.duration_days * DAY;
        this.q.activate.run(h, t, expiresAt, k);
      } else {
        // Admin reset the HWID: bind to the new machine, keep original expiry.
        this.q.bindHwid.run(h, k);
      }
      // Re-read in case a concurrent request bound a different HWID first.
      const fresh = this.q.get.get(k);
      if (fresh.hwid_hash !== h) return { status: 'hwid_mismatch', message: 'Key is locked to another PC.' };
      expiresAt = fresh.expires_at;
    } else if (row.hwid_hash !== h) {
      return { status: 'hwid_mismatch', message: 'Key is locked to another PC. Ask an admin for an HWID reset.' };
    }

    if (expiresAt !== null && expiresAt <= t) return { status: 'expired', message: 'This key has expired.' };

    this.q.seen.run(t, ip || null, k);
    return { status: 'ok', message: 'Welcome.', expires_at: expiresAt };
  }
}

module.exports = { LicenseStore, generateKeyString, normalizeKey, hashHwid, now };
