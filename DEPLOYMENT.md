# Deploying Pulse Intelligence — new machine / new host

Short answer: **this project is deployment-ready as a directly-hosted Node app**
(what's actually running right now, on this RDP box). It is **not yet
container-ready** — `docker-compose.yml` has a `full` profile that expects a
`Dockerfile`, and none exists yet. Use the Node path below unless you want to
build a Dockerfile first (say so and it can be added).

This file is the "get it live on a brand new machine" checklist. For
day-to-day commands and architecture notes, see [`HANDOVER.md`](HANDOVER.md)
and [`README.md`](README.md) — this file only covers moving/redeploying.

---

## 0. What's in this folder vs. what isn't

If you received this as a zip, it deliberately **excludes**:

- `node_modules/` — reinstall with `npm install` on the target machine (native
  binaries in `sharp` and Prisma's query engine are platform-specific; copying
  a Windows `node_modules` to Linux, or vice versa, will not work).
- `.next/` — rebuild with `npm run build`.
- `.env` — **your real secrets are not in this zip.** Copy them across
  out-of-band (password manager, not email/chat/a file share you don't
  control) and recreate `.env` by hand on the new machine using
  `.env.example` as the template. See §2 for the full list of what needs to
  be in it.
- `*.tsbuildinfo`, `src/generated/prisma/` — build caches, regenerated
  automatically.

Everything else — source code, `prisma/migrations/`, `.claude/` skills,
scripts, git history — is included.

---

## 1. Prerequisites on the new machine

| Requirement | Notes |
|---|---|
| **Node.js 20.9+** | This project was built and run on Node 24. |
| **PostgreSQL 17** | Native install, or `docker compose up -d postgres` (see `docker-compose.yml` — the `postgres`/`redis` services work standalone without the missing Dockerfile). |
| **Redis-compatible server** | Memurai on Windows, real Redis on Linux/Mac, or `docker compose up -d redis`. |
| `npm` | Ships with Node. |

If you're moving to a real VPS/cloud host (not another Windows RDP box),
everything here works identically on Linux — the Windows-specific notes in
`HANDOVER.md` §7 (no `winget`, PATH prepending) won't apply.

---

## 2. Recreate `.env`

Copy `.env.example` to `.env` and fill in:

```
DATABASE_URL=              # postgres connection string
REDIS_URL=                 # redis connection string
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
ABUSEIPDB_API_KEYS=         # optional: comma-separated list for key rotation
OTX_API_KEY=
NVD_API_KEY=                # optional but strongly recommended, see HANDOVER §4.5
SESSION_SECRET=             # any random 32+ char string
SEED_PASSWORD=              # only used the first time you run db:seed
```

**Do not reuse the exact keys from a previous deployment if that deployment's
`.env` was ever shared over an insecure channel** (chat, email). Rotate them —
they're all free-tier and instant to regenerate (see the links in
`HANDOVER.md` §1.2).

---

## 3. First-time setup on the new machine

```bash
npm install

npx prisma generate                  # generates src/generated/prisma
npm run db:migrate                   # applies prisma/migrations/ — use this,
                                      # NOT `prisma migrate dev` (see HANDOVER §4.1/§4.2)
npm run db:seed                      # 3 base users (admin/analyst/viewer)
npm run db:seed:demo                 # optional: real APTs, campaigns, sample IOCs — idempotent
npm run attack:sync -- --all         # MITRE ATT&CK (~58MB download, ~1 min)
npm run feeds:install                # registers the 18-source feed catalogue
npm run cve:catchup -- --days 90     # backfill CVE data so it isn't stale on day one
```

Then recreate any accounts you need beyond the seed defaults (e.g. the admin
account this session created for `sukeshkumartkd@gmail.com` — that only
exists in this deployment's database; re-run the same
`hashPassword`/`db.user.upsert` pattern, or just log in with the seed admin
and use `/register` + a manual role bump).

---

## 4. Build and run

```bash
npm run build
npm run start          # production server, http://localhost:3000
```

In a **second** process/terminal, alongside it:

```bash
npm run worker         # feeds, enrichment, hunts, scheduled reports
```

Both need to run continuously. On a real host, use a process manager instead
of a bare terminal:

- **systemd** (most VPS/Linux hosts): two unit files, one for `npm run start`,
  one for `npm run worker`, both `Restart=always`.
- **pm2**: `pm2 start npm --name pulse-app -- start` and
  `pm2 start npm --name pulse-worker -- run worker`, then `pm2 save` +
  `pm2 startup` so they survive a reboot.
- Whatever the RDP-specific approach was (nohup + manual restart) works but
  does **not** survive a reboot — fine for iterating, not for a real deployment.

---

## 5. Expose it publicly

Two options, depending on what you're moving to:

**A. You control DNS for a domain (what this session set up: `pulseintel.online`
via Cloudflare)** — use a named Cloudflare Tunnel, not the quick/ephemeral one:

```bash
cloudflared tunnel login                              # once, authorizes your Cloudflare account
cloudflared tunnel create pulse-intel                 # once
cloudflared tunnel route dns pulse-intel <yourdomain>  # once
cloudflared tunnel run --url http://localhost:3000 pulse-intel   # every time you bring it up
```

This survives a `cloudflared` restart (unlike the quick-tunnel random URL) as
long as you keep reusing the same tunnel name/credentials file
(`~/.cloudflared/<tunnel-id>.json` — back this up if migrating hosts, or just
re-run `tunnel create` on the new machine and re-point the DNS route).

**B. A real VPS with a public IP** — you don't need `cloudflared` at all; put
a reverse proxy (nginx/Caddy) in front of port 3000 for TLS, point your
domain's A record at the VPS IP, and skip straight to a normal HTTPS setup.
This is generally the more "production" path than a tunnel — a tunnel is
convenient when you don't have a static IP or don't want to open inbound
ports, which is exactly the RDP-box situation this was built for.

---

## 6. Post-deploy checklist

```bash
npm run typecheck
npm run test                          # 143 tests, no DB/network needed
npm run verify:enrichment -- --live    # proves API keys + rate limiter work
npm run build
```

Sign in, change the seed passwords (`HANDOVER.md` §2.4 — there's no
self-service change-password UI yet), and confirm the worker log shows
`worker ready — enrichment + feeds + hunts + reports`.
