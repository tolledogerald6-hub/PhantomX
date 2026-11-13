# PhantomX Auth Server

Server-side license key authentication for the PhantomX loader.
Zero npm dependencies — uses Node.js built-ins only (`http`, `sqlite`, `crypto`).

## Features
- License keys `PHX-XXXXX-XXXXX-XXXXX-XXXXX` with a duration (days) or lifetime
- Expiry clock starts on **first login**, not on creation
- **HWID lock** — key binds to the first PC that uses it; admin can reset
- Ban / unban, extend, delete, per-key auth log
- **Signed responses** (ECDSA P-256): the loader verifies every answer with an
  embedded public key, so a fake/cracked server (hosts redirect, MITM) can't return "ok"
- Nonce in every request — old responses can't be replayed
- Forced updates via `MIN_LOADER_VERSION`
- Per-IP rate limiting

## Setup
Requires Node.js **22.13+**.

```bash
cd auth-server
cp .env.example .env          # then set ADMIN_TOKEN (32+ random chars)
npm start                     # creates data/licenses.db and data/signing_key.pem
npm test
```

> **Back up `data/signing_key.pem`.** If it's lost, every shipped loader stops
> working (they hold the matching public key). Never commit or share it.

## Connect your loader
1. `npm run admin -- pubkey` → copy the `kServerPublicKey` array into your loader.
2. Include `loader-client/PhantomAuth.hpp` (see `loader-client/example_main.cpp`).
3. Set `cfg.host`, `cfg.port = 443`, `cfg.https = true` for production.

## Admin CLI (on the server)
```bash
npm run admin -- gen 10 30 "reseller A"   # 10 keys, 30 days
npm run admin -- gen 1 0                  # 1 lifetime key
npm run admin -- list
npm run admin -- info  <key>
npm run admin -- reset <key>              # clear HWID lock
npm run admin -- ban   <key> [reason]
npm run admin -- unban <key>
npm run admin -- extend <key> <days>
npm run admin -- delete <key>
```

## HTTP API
All admin routes need `Authorization: Bearer <ADMIN_TOKEN>`.

| Method | Path | Body | |
|---|---|---|---|
| POST | `/api/v1/auth` | `{key, hwid, nonce, version}` | Loader login → `{payload, sig}` |
| GET | `/api/v1/pubkey` | | Public key (hex) |
| GET | `/api/v1/health` | | Health check |
| GET | `/api/v1/admin/keys?limit=&offset=` | | List keys |
| POST | `/api/v1/admin/keys` | `{count, days, note}` | Create keys |
| GET | `/api/v1/admin/keys/:key` | | Details + log |
| DELETE | `/api/v1/admin/keys/:key` | | Delete |
| POST | `/api/v1/admin/keys/:key/reset-hwid` | | Reset HWID |
| POST | `/api/v1/admin/keys/:key/ban` | `{reason}` | Ban |
| POST | `/api/v1/admin/keys/:key/unban` | | Unban |
| POST | `/api/v1/admin/keys/:key/extend` | `{days}` | Add days |

Auth `status` values: `ok`, `invalid_key`, `banned`, `expired`, `hwid_mismatch`, `outdated`, `bad_request`.

## Production checklist
- Run behind **HTTPS** (Caddy is simplest: `auth.yourdomain.com { reverse_proxy 127.0.0.1:8080 }`) and set `TRUST_PROXY=1`, `HOST=127.0.0.1`.
- Keep the process alive with `pm2` or a systemd service.
- Back up the `data/` folder regularly.

## Note on security
The server is the source of truth for keys, but any check inside the loader
can still be patched by someone with a debugger. For stronger protection,
have the server deliver something the loader actually needs (e.g. a payload or
config) only after a successful auth, instead of a plain yes/no.
