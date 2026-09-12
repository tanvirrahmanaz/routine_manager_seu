# routine_manager_seu

SEU Law class routine and faculty schedule manager — a single-page app deployed on **Vercel**, with every edit stored in **Upstash Redis** (from the Vercel Storage tab) so all users see the same routine.

Everything lives in one Vercel dashboard: no separate database account, no connection string, no npm dependencies.

- `public/index.html` — the whole app (grid view, faculty view, DOCX/HTML import, Word export, print).
- `api/storage.js` — a serverless key/value endpoint backed by Upstash Redis over its REST API.
- `api/auth.js` — sign-in, sessions, and the admin's editor accounts.
- `lib/shared.js` — the Redis client, password hashing and session lookup shared by both.

## How storage works

The app keeps a handful of string keys:

| Key | Holds |
| --- | --- |
| `weekly:<Day>` | permanent changes to that weekday (`{removed, added}`) |
| `override:<YYYY-MM-DD>` | one-off changes for a single date |
| `semesterInfo` | selected semester and year |
| `importedSchedule` | the routine imported from a `.docx` / `.html` file |
| `meta:seedApplied` | marker so bundled sample overrides are seeded only once |
| `auth:users` | accounts — `{ email: { hash, salt, role } }`, scrypt hashes |
| `auth:session:<token>` | a signed-in browser, expires after 30 days |
| `auth:fail:<ip>` | sign-in failure counter (10 in 15 minutes locks that IP out) |

All of them go through `appStorage` in `public/index.html`, which calls `/api/storage`. In Redis they are namespaced under `seuRoutine:`.

If the endpoint is unreachable — the file opened over `file://`, the browser offline, the store not configured — the app falls back to `localStorage` and shows an "Offline mode" line under the toolbar, so it still works but those edits stay on that one computer.

## API

```
GET    /api/storage?ping=1        -> { ok, auth }
GET    /api/storage?key=<key>     -> { key, value }   (404 if absent)
GET    /api/storage?prefix=<pfx>  -> { keys: [...] }
POST   /api/storage               { key, value }      upsert
DELETE /api/storage?key=<key>     -> { key, deleted }
```

Reads are always open. Writes require a signed-in user — the `seu_session` cookie set by `/api/auth`. The `auth:*` keys are never reachable through this endpoint.

```
GET    /api/auth                                        -> { user }   who the cookie belongs to, or null
POST   /api/auth { action: "login", email, password }   -> { user }   sets the cookie
POST   /api/auth { action: "logout" }
POST   /api/auth { action: "password", current, next }  own password, any signed-in user
POST   /api/auth { action: "listUsers" }                admin only
POST   /api/auth { action: "addUser", email, password } admin only, creates an editor
POST   /api/auth { action: "removeUser", email }        admin only
```

## Setup

### 1. Deploy

1. <https://vercel.com/new> → import this GitHub repository.
2. Framework preset: **Other**. Leave the build command empty — `vercel.json` already points the output at `public/`.
3. Deploy. The site will load in offline mode until step 2 is done.

### 2. Add the database

1. In the project, open the **Storage** tab → **Create Database** → **Upstash for Redis**.
2. Pick a region near your users, create it, and connect it to this project (all three environments).
3. Vercel injects `KV_REST_API_URL` and `KV_REST_API_TOKEN` automatically.
4. **Redeploy** — environment variables only reach new builds.

Open the site: the line under the toolbar should now read *"Connected to the shared database"*.

A Redis database created directly on [upstash.com](https://upstash.com) works too — it supplies `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`, and both variable pairs are supported.

### 3. Sign-in (needed to edit)

Viewing is open to everyone. Changing the routine needs an account.

1. In **Settings → Environment Variables** add `ADMIN_EMAIL` and `ADMIN_PASSWORD`, then redeploy.
2. Open the site and click **Sign in to edit** with those values. That first sign-in creates the admin account in Redis; from then on the database is the source of truth and the env values are ignored.
3. **Manage editors** (admin only) adds people by email + password and removes them — a removed editor is signed out at once.
4. **Change password** rotates your own password; editors can do the same for theirs.

Forgot the admin password? Delete the key `seuRoutine:auth:users` in the Upstash data browser and sign in again with the env values (no redeploy needed). That also drops every editor account.

## Free tier headroom

| | Included | This app uses |
| --- | --- | --- |
| Vercel Hobby | 1M function invocations, 100 GB bandwidth / month | a few API calls per page load |
| Upstash Redis free | 256 MB, 500K commands / month, 10 GB bandwidth | a few KB of JSON, ~5 commands per page load |

Vercel's Hobby plan is for personal, non-commercial use.

## Local development

```bash
npm i -g vercel        # once
vercel link
vercel env pull .env.local
vercel dev             # http://localhost:3000
```

There are no npm dependencies to install. `npm test` runs the API tests against an in-memory stand-in for Upstash, so it needs no database. Opening `public/index.html` directly from disk also works, but runs in offline mode against `localStorage`.
