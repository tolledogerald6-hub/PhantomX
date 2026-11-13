'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

function openDb(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, 'licenses.db'));
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS keys (
      key           TEXT PRIMARY KEY,
      duration_days INTEGER NOT NULL,          -- 0 = lifetime
      note          TEXT,
      hwid_hash     TEXT,                      -- bound on first successful auth
      created_at    INTEGER NOT NULL,
      activated_at  INTEGER,
      expires_at    INTEGER,                   -- NULL until activated, or lifetime
      last_seen_at  INTEGER,
      last_ip       TEXT,
      banned        INTEGER NOT NULL DEFAULT 0,
      ban_reason    TEXT
    );

    CREATE TABLE IF NOT EXISTS auth_log (
      id     INTEGER PRIMARY KEY AUTOINCREMENT,
      ts     INTEGER NOT NULL,
      key    TEXT,
      ip     TEXT,
      status TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS auth_log_key ON auth_log(key);
  `);
  return db;
}

module.exports = { openDb };
