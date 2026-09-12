# Auth & login — design

Date: 2026-09-12. Status: approved in chat.

## Goal

Everyone can view the routine. Only signed-in users can change it. One
`admin` (bootstrapped from env) manages `editor` accounts and changes their
own password. Editors edit the routine and change their own password. The
shared `ADMIN_KEY` password is removed.

## Backend

Files: `lib/shared.js` (new), `api/auth.js` (new), `api/storage.js` (edited).

- `lib/shared.js` — `redis(cmd)`, `send(res, status, body)`, `readJsonBody(req)`
  moved here from `storage.js`, plus `currentUser(req)` which reads the
  `seu_session` cookie, loads `auth:session:<token>`, and confirms the user
  still exists in `auth:users`. Returns `{email, role}` or `null`.
- `api/auth.js`
  - `GET /api/auth` → `{ user }` (`null` when signed out).
  - `POST /api/auth` with `{action, ...}`:
    - `login {email, password}` → sets cookie, `{ user }`. 401 on bad
      credentials; 429 after 10 failures from one IP within 15 min.
    - `logout` → clears cookie.
    - `password {current, next}` → any signed-in user, own account.
    - `listUsers` → admin only → `{ users: [{email, role}] }`.
    - `addUser {email, password}` → admin only, creates an `editor`.
      409 if exists.
    - `removeUser {email}` → admin only, cannot remove an admin.
- `api/storage.js` — `authorized(req)` becomes `!!(await currentUser(req))`.
  `ADMIN_KEY` and `x-admin-key` are removed. `?ping=1` returns `{ ok }` only.

## Storage (Upstash Redis, `seuRoutine:` namespace)

| Key | Value |
| --- | --- |
| `auth:users` | JSON `{ "<email>": { hash, salt, role } }` — scrypt via `node:crypto` |
| `auth:session:<token>` | JSON `{ email, role }`, `EX` 30 days; token = 32 random bytes hex |
| `auth:fail:<ip>` | login failure counter, `EX` 900 |

Bootstrap: when `auth:users` is absent and the login matches `ADMIN_EMAIL` /
`ADMIN_PASSWORD` from env, the admin record is created. After that Redis is
the source of truth; the env vars are only consulted while the key is absent.
Reset = delete `seuRoutine:auth:users` in the Upstash console.

Cookie: `seu_session=<token>; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`,
plus `Secure` when the request arrived over https.

## Frontend (`public/index.html`)

- Masthead: **Sign in** button when signed out. When signed in: `email · role`,
  **Sign out**, **Change password**, and (admin) **Manage editors**.
- Modals, reusing existing modal/button styles: sign-in (email, password,
  error line); change password (current, new); manage editors (list with
  remove buttons + add form email/password).
- `body:not(.can-edit) .edit-only { display:none }`. `edit-only` goes on
  Import, Generate, Clear, Update and the semester bar.
- Grid cell click while signed out opens the sign-in modal instead of the
  add/delete dialog.
- `apiWrite`: on 401, open the sign-in modal and return the response (the
  existing "could not save" handling runs; user retries after signing in).
  The `window.prompt` / `x-admin-key` / localStorage admin-key code is deleted.
- `appStorage.set/delete` only mirror to localStorage after the API write
  succeeds when online, so a rejected write does not linger locally.
- Status line: "Signed in as `<email>`" or "Viewing only — sign in to edit".
- On load: `GET /api/auth` sets the signed-in state before rendering.

## Testing

`node --test test/` with `test/fake-upstash.js`, a tiny HTTP server that
answers Upstash REST command arrays (`PING GET SET DEL SCAN INCR EXPIRE`)
from a `Map`. Tests call the real handlers with stub `req`/`res`:

1. write without cookie → 401
2. admin bootstrap login → cookie → write → 200
3. addUser → editor login → write → 200
4. removeUser → same editor cookie → write → 401
5. 10 bad logins → 429
6. non-admin `addUser` → 403

Manual: serve `public/` + handlers against the fake store, open in the
Browser pane, walk sign-in / add editor / change password / sign out.

## Deploy

Vercel env: add `ADMIN_EMAIL`, `ADMIN_PASSWORD`; delete `ADMIN_KEY`. Redeploy.

## Out of scope

Multiple admins, email verification, password-reset emails, per-user audit
log. The `role` field makes multi-admin a one-line change later.
