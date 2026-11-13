'use strict';

// Local admin CLI — works directly on the database, no HTTP needed.
//   npm run admin -- gen 10 30 "batch for reseller A"
//   npm run admin -- list
//   npm run admin -- info PHX-XXXXX-XXXXX-XXXXX-XXXXX
//   npm run admin -- reset|ban|unban|delete <key> [reason]
//   npm run admin -- extend <key> <days>
//   npm run admin -- pubkey

const cfg = require('../src/config');
const { openDb } = require('../src/db');
const { LicenseStore } = require('../src/license');
const { loadOrCreateSigningKey, rawPublicKey, cppPublicKeyArray } = require('../src/signing');

const fmt = (t) => (t ? new Date(t * 1000).toISOString().replace('T', ' ').slice(0, 19) : '-');

function usage() {
  console.log(`Usage:
  gen <count> <days> [note]   create keys (days 0 = lifetime; clock starts on first login)
  list [limit]                list keys
  info <key>                  key details + recent auth log
  reset <key>                 clear HWID lock
  ban <key> [reason]          ban key
  unban <key>                 unban key
  extend <key> <days>         add days to a key
  delete <key>                delete key
  pubkey                      print the public key for the loader (C++ array)`);
}

function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (!cmd || cmd === 'help') return usage();

  if (cmd === 'pubkey') {
    const { publicKey } = loadOrCreateSigningKey(cfg.dataDir);
    console.log('// Paste into your loader (replaces kServerPublicKey):');
    console.log(cppPublicKeyArray(publicKey));
    console.log(`\n// hex: ${rawPublicKey(publicKey).toString('hex')}`);
    return;
  }

  const db = openDb(cfg.dataDir);
  const store = new LicenseStore(db, cfg);
  const need = (n) => { if (args.length < n) { usage(); process.exit(1); } };
  const done = (ok) => { console.log(ok ? 'OK' : 'Key not found'); process.exitCode = ok ? 0 : 1; };

  switch (cmd) {
    case 'gen': {
      need(2);
      const keys = store.createKeys(Number.parseInt(args[0], 10), Number.parseInt(args[1], 10), args[2] || null);
      keys.forEach((k) => console.log(k));
      break;
    }
    case 'list': {
      const rows = store.list(Number.parseInt(args[0] || '100', 10));
      console.table(rows.map((r) => ({
        key: r.key,
        days: r.duration_days || 'life',
        status: r.banned ? 'BANNED' : r.expires_at && r.expires_at < Date.now() / 1000 ? 'expired' : r.activated_at ? 'active' : 'unused',
        hwid: r.hwid_hash ? 'locked' : '-',
        expires: r.duration_days === 0 ? 'never' : fmt(r.expires_at),
        last_seen: fmt(r.last_seen_at),
        note: r.note || '',
      })));
      break;
    }
    case 'info': {
      need(1);
      const r = store.get(args[0]);
      if (!r) return done(false);
      console.log({ ...r, created_at: fmt(r.created_at), activated_at: fmt(r.activated_at), expires_at: fmt(r.expires_at), last_seen_at: fmt(r.last_seen_at) });
      console.table(store.logs(args[0], 20).map((l) => ({ ...l, ts: fmt(l.ts) })));
      break;
    }
    case 'reset': need(1); done(store.resetHwid(args[0])); break;
    case 'ban': need(1); done(store.ban(args[0], args.slice(1).join(' ') || null)); break;
    case 'unban': need(1); done(store.unban(args[0])); break;
    case 'delete': need(1); done(store.delete(args[0])); break;
    case 'extend': need(2); done(store.extend(args[0], Number.parseInt(args[1], 10))); break;
    default: usage(); process.exitCode = 1;
  }
  db.close();
}

main();
