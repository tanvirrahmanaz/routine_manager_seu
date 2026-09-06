# routine_manager_seu

SEU Law class routine and faculty schedule manager — a single-page app deployed on **Vercel**, with every edit stored in **MongoDB** so all users see the same routine.

- `public/index.html` — the whole app (grid view, faculty view, DOCX/HTML import, Word export, print).
- `api/storage.js` — a serverless key/value endpoint backed by MongoDB.

## How storage works

The app keeps a handful of string keys:

| Key | Holds |
| --- | --- |
| `weekly:<Day>` | permanent changes to that weekday (`{removed, added}`) |
| `override:<YYYY-MM-DD>` | one-off changes for a single date |
| `semesterInfo` | selected semester and year |
| `importedSchedule` | the routine imported from a `.docx` / `.html` file |
| `meta:seedApplied` | marker so bundled sample overrides are seeded only once |

All of them go through `appStorage` in `public/index.html`, which calls `/api/storage`. If that endpoint is unreachable — the file opened over `file://`, the browser offline, the database down — the app falls back to `localStorage` and shows an "Offline mode" line under the toolbar, so it still works but those edits stay on that one computer.

## API

```
GET    /api/storage?ping=1        -> { ok, auth }
GET    /api/storage?key=<key>     -> { key, value }   (404 if absent)
GET    /api/storage?prefix=<pfx>  -> { keys: [...] }
POST   /api/storage               { key, value }      upsert
DELETE /api/storage?key=<key>     -> { key, deleted }
```

Reads are always open. Writes require the `x-admin-key` header **only** if `ADMIN_KEY` is set (see below).

## Setup

### 1. MongoDB Atlas

1. Create a free cluster at <https://cloud.mongodb.com>.
2. **Database Access** → add a user with *Read and write to any database*.
3. **Network Access** → add `0.0.0.0/0` (Vercel functions do not have fixed IPs).
4. **Connect → Drivers** → copy the connection string, e.g.
   `mongodb+srv://user:password@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority`

The database (`seu_law_routine`) and collection (`routine_store`) are created automatically on the first write.

### 2. Vercel

1. <https://vercel.com/new> → import this GitHub repository.
2. Framework preset: **Other**. Leave the build command empty — `vercel.json` already points the output at `public/`.
3. **Settings → Environment Variables**, for Production, Preview and Development:

   | Name | Value |
   | --- | --- |
   | `MONGODB_URI` | your Atlas connection string (required) |
   | `MONGODB_DB` | `seu_law_routine` (optional) |
   | `MONGODB_COLLECTION` | `routine_store` (optional) |
   | `ADMIN_KEY` | a password, if editing should be restricted (optional) |

4. Deploy. Open the site: the line under the toolbar should read *"Connected to the shared database"*.

Re-deploy after changing an environment variable — Vercel only applies them to new builds.

### 3. Locking down editing (optional)

Without `ADMIN_KEY`, anyone who can open the URL can add, edit and delete classes. Set `ADMIN_KEY` to any password and the app asks for it the first time someone tries to save, then remembers it in that browser. Viewing stays open to everyone.

## Local development

```bash
npm install
npm i -g vercel        # once
cp .env.example .env.local   # then fill in MONGODB_URI
vercel dev             # http://localhost:3000
```

Opening `public/index.html` directly from disk also works, but runs in offline mode against `localStorage`.
