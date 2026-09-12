# Auth & Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Anyone can view the routine; only a signed-in admin or editor can change it, and the admin manages editor accounts from the page.

**Architecture:** Session cookie backed by Redis (`auth:session:<token>`), users in one JSON blob (`auth:users`), scrypt password hashes via `node:crypto`. A new `api/auth.js` handles login/logout/users; `api/storage.js` gates writes on the session. The frontend adds a sign-in modal, an account bar in the masthead, and hides edit controls when signed out.

**Tech Stack:** Vercel serverless functions (Node 22, CommonJS), Upstash Redis REST, vanilla HTML/JS. Zero npm dependencies. Tests with `node:test` against a tiny fake Upstash HTTP server.

**Spec:** `docs/superpowers/specs/2026-09-12-auth-login-design.md`

## Global Constraints

- No npm dependencies. `package.json` stays dependency-free.
- Node `22.x` (from `package.json` engines). CommonJS (`require`/`module.exports`).
- All Redis keys live under the `seuRoutine:` namespace (`NS` in `lib/shared.js`).
- Cookie name is exactly `seu_session`.
- Emails are normalised with `.trim().toLowerCase()` before any lookup or store.
- Existing routine keys and their formats do not change.
- `public/index.html` uses CRLF line endings; keep them (edit in place, don't rewrite the file).

---

## File map

| File | Responsibility |
| --- | --- |
| `lib/shared.js` (new) | Redis REST client, JSON response/body helpers, password hash/verify, cookie parse, `currentUser(req)` |
| `api/auth.js` (new) | `/api/auth` — me, login, logout, password, listUsers, addUser, removeUser |
| `api/storage.js` (edit) | use `lib/shared.js`; writes require `currentUser(req)` |
| `test/fake-upstash.js` (new) | in-memory Upstash REST server for tests |
| `test/helpers.js` (new) | `call(handler, {method,url,headers,body})` → `{status, body, headers}` |
| `test/shared.test.js`, `test/auth.test.js` (new) | unit + end-to-end auth and storage gating tests |
| `public/index.html` (edit) | account bar, sign-in / password / editors modals, edit gating |
| `README.md`, `.env.example`, `package.json` (edit) | docs, env vars, `npm test` |

---

### Task 1: Shared library + fake Upstash

**Files:**
- Create: `lib/shared.js`
- Create: `test/fake-upstash.js`
- Create: `test/helpers.js`
- Create: `test/shared.test.js`
- Modify: `package.json` (add `"test": "node --test test/"`)

**Interfaces:**
- Produces (`lib/shared.js`):
  - `NS: string` — `'seuRoutine:'`; `SESSION_COOKIE = 'seu_session'`; `USERS_KEY = NS + 'auth:users'`
  - `redis(command: any[]): Promise<any>` — one Upstash REST command
  - `send(res, status: number, body: object): void`
  - `readJsonBody(req): Promise<object>`
  - `hashPassword(password: string): { salt: string, hash: string }`
  - `verifyPassword(password: string, rec: {salt, hash}): boolean`
  - `getCookie(req, name: string): string`
  - `sessionCookie(req, token: string, maxAge: number): string` — a `Set-Cookie` value
  - `loadUsers(): Promise<object|null>` — parsed `auth:users` or `null`
  - `currentUser(req): Promise<{email, role}|null>`
- Produces (`test/fake-upstash.js`): `start(): Promise<{ url: string, store: Map, close(): void }>`
- Produces (`test/helpers.js`): `call(handler, opts): Promise<{ status, body, headers }>`, `cookieFrom(result): string`

- [ ] **Step 1: Write the fake Upstash server** — `test/fake-upstash.js`

```js
// Minimal stand-in for the Upstash Redis REST API: POST a JSON command array,
// get back { result }. Only the commands this app sends are implemented.
const http = require('node:http');

function start(){
  const store = new Map();   // key -> { value, expiresAt }
  const get = (k) => {
    const rec = store.get(k);
    if(!rec) return null;
    if(rec.expiresAt && rec.expiresAt <= Date.now()){ store.delete(k); return null; }
    return rec.value;
  };
  const run = (cmd) => {
    const [name, ...args] = cmd;
    switch(String(name).toUpperCase()){
      case 'PING': return 'PONG';
      case 'GET': return get(args[0]);
      case 'SET': {
        let expiresAt = 0;
        const exIdx = args.findIndex((a) => String(a).toUpperCase() === 'EX');
        if(exIdx !== -1) expiresAt = Date.now() + Number(args[exIdx + 1]) * 1000;
        store.set(args[0], { value: String(args[1]), expiresAt });
        return 'OK';
      }
      case 'DEL': { let n = 0; for(const k of args){ if(store.delete(k)) n++; } return n; }
      case 'INCR': {
        const v = Number(get(args[0]) || 0) + 1;
        store.set(args[0], { value: String(v), expiresAt: (store.get(args[0]) || {}).expiresAt || 0 });
        return v;
      }
      case 'EXPIRE': { const rec = store.get(args[0]); if(!rec) return 0; rec.expiresAt = Date.now() + Number(args[1]) * 1000; return 1; }
      case 'SCAN': {
        const mIdx = args.findIndex((a) => String(a).toUpperCase() === 'MATCH');
        const pattern = mIdx === -1 ? '*' : String(args[mIdx + 1]);
        const re = new RegExp('^' + pattern.replace(/[.+^${}()|[\]]/g, '\\$&').replace(/\\\*/g, '.*').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
        const keys = [...store.keys()].filter((k) => get(k) !== null && re.test(k));
        return ['0', keys];
      }
      default: throw new Error('fake-upstash: unsupported command ' + name);
    }
  };
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      try{ res.end(JSON.stringify({ result: run(JSON.parse(raw)) })); }
      catch(err){ res.statusCode = 400; res.end(JSON.stringify({ error: err.message })); }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ url: 'http://127.0.0.1:' + server.address().port, store, close: () => server.close() });
    });
  });
}

module.exports = { start };
```

- [ ] **Step 2: Write the handler-call helper** — `test/helpers.js`

```js
// Invoke a Vercel-style (req, res) handler in-process and capture the reply.
async function call(handler, opts){
  const req = {
    method: opts.method || 'GET',
    url: opts.url || '/',
    headers: Object.assign({}, opts.headers || {}),
    body: opts.body,
  };
  const headers = {};
  let status = 200;
  let raw = '';
  const res = {
    get statusCode(){ return status; },
    set statusCode(v){ status = v; },
    setHeader(k, v){ headers[k.toLowerCase()] = v; },
    getHeader(k){ return headers[k.toLowerCase()]; },
    end(chunk){ raw = chunk == null ? '' : String(chunk); },
  };
  await handler(req, res);
  let body = null;
  try{ body = raw ? JSON.parse(raw) : null; }catch(e){ body = raw; }
  return { status, body, headers };
}

// Pull the cookie value out of a Set-Cookie header so tests can send it back.
function cookieFrom(result){
  const sc = result.headers['set-cookie'];
  if(!sc) return '';
  return String(sc).split(';')[0];
}

module.exports = { call, cookieFrom };
```

- [ ] **Step 3: Write the failing shared tests** — `test/shared.test.js`

```js
const test = require('node:test');
const assert = require('node:assert/strict');
const fake = require('./fake-upstash');
const { call } = require('./helpers');

let up, shared;
test.before(async () => {
  up = await fake.start();
  process.env.KV_REST_API_URL = up.url;
  process.env.KV_REST_API_TOKEN = 'test-token';
  shared = require('../lib/shared');
});
test.after(() => up.close());

test('hashPassword / verifyPassword round-trip', () => {
  const rec = shared.hashPassword('s3cret');
  assert.equal(typeof rec.salt, 'string');
  assert.equal(typeof rec.hash, 'string');
  assert.equal(shared.verifyPassword('s3cret', rec), true);
  assert.equal(shared.verifyPassword('wrong', rec), false);
  assert.notEqual(shared.hashPassword('s3cret').hash, rec.hash, 'salt differs per call');
});

test('getCookie reads one cookie among many', () => {
  const req = { headers: { cookie: 'a=1; seu_session=tok123; b=2' } };
  assert.equal(shared.getCookie(req, 'seu_session'), 'tok123');
  assert.equal(shared.getCookie({ headers: {} }, 'seu_session'), '');
});

test('sessionCookie is HttpOnly, SameSite=Lax, Secure only on https', () => {
  const plain = shared.sessionCookie({ headers: {} }, 'tok', 60);
  assert.match(plain, /^seu_session=tok; Path=\/; HttpOnly; SameSite=Lax; Max-Age=60$/);
  const https = shared.sessionCookie({ headers: { 'x-forwarded-proto': 'https' } }, 'tok', 60);
  assert.match(https, /; Secure$/);
});

test('currentUser: null without cookie, user with live session, null once user removed', async () => {
  const users = { 'a@x.com': Object.assign({ role: 'editor' }, shared.hashPassword('pw')) };
  await shared.redis(['SET', shared.USERS_KEY, JSON.stringify(users)]);
  await shared.redis(['SET', shared.NS + 'auth:session:T1', JSON.stringify({ email: 'a@x.com', role: 'editor' })]);

  assert.equal(await shared.currentUser({ headers: {} }), null);
  assert.deepEqual(await shared.currentUser({ headers: { cookie: 'seu_session=T1' } }), { email: 'a@x.com', role: 'editor' });
  assert.equal(await shared.currentUser({ headers: { cookie: 'seu_session=nope' } }), null);

  await shared.redis(['SET', shared.USERS_KEY, JSON.stringify({})]);
  assert.equal(await shared.currentUser({ headers: { cookie: 'seu_session=T1' } }), null);
});

test('send writes JSON with no-store', async () => {
  const r = await call((req, res) => shared.send(res, 418, { ok: 1 }), {});
  assert.equal(r.status, 418);
  assert.deepEqual(r.body, { ok: 1 });
  assert.equal(r.headers['cache-control'], 'no-store');
});
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `node --test test/shared.test.js`
Expected: FAIL — `Cannot find module '../lib/shared'`

- [ ] **Step 5: Write `lib/shared.js`**

```js
// Bits shared by the two API functions: the Upstash REST client, JSON
// helpers, password hashing and session lookup. No npm dependencies.
const crypto = require('node:crypto');

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';

// Everything this app owns lives under one namespace, so the database stays
// tidy if it is ever shared with something else.
const NS = 'seuRoutine:';
const SESSION_COOKIE = 'seu_session';
const USERS_KEY = NS + 'auth:users';

async function redis(command){
  if(!REDIS_URL || !REDIS_TOKEN){
    throw new Error('KV_REST_API_URL / KV_REST_API_TOKEN are not set on this deployment');
  }
  const res = await fetch(REDIS_URL.replace(/\/+$/, ''), {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + REDIS_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(command),
    cache: 'no-store',
  });
  const data = await res.json().catch(() => null);
  if(!res.ok || !data || data.error){
    throw new Error((data && data.error) || 'Redis request failed with status ' + res.status);
  }
  return data.result;
}

function send(res, status, body){
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

async function readJsonBody(req){
  if(req.body && typeof req.body === 'object') return req.body;
  if(typeof req.body === 'string' && req.body) return JSON.parse(req.body);
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

function hashPassword(password){
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, rec){
  if(!rec || typeof rec.salt !== 'string' || typeof rec.hash !== 'string') return false;
  const got = crypto.scryptSync(String(password), rec.salt, 64);
  const want = Buffer.from(rec.hash, 'hex');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

function getCookie(req, name){
  const header = (req.headers && req.headers.cookie) || '';
  for(const part of header.split(';')){
    const eq = part.indexOf('=');
    if(eq === -1) continue;
    if(part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return '';
}

function sessionCookie(req, token, maxAge){
  const secure = req.headers && req.headers['x-forwarded-proto'] === 'https';
  return SESSION_COOKIE + '=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + maxAge + (secure ? '; Secure' : '');
}

async function loadUsers(){
  const raw = await redis(['GET', USERS_KEY]);
  if(raw === null || raw === undefined) return null;
  try{ return JSON.parse(String(raw)); }catch(e){ return null; }
}

// Who is making this request, or null. The session must exist and the user
// must still be in auth:users — so removing an editor locks them out at once.
async function currentUser(req){
  const token = getCookie(req, SESSION_COOKIE);
  if(!/^[A-Za-z0-9]{1,64}$/.test(token)) return null;
  const raw = await redis(['GET', NS + 'auth:session:' + token]);
  if(!raw) return null;
  let session = null;
  try{ session = JSON.parse(String(raw)); }catch(e){ return null; }
  const users = await loadUsers();
  const rec = users && users[session.email];
  if(!rec) return null;
  return { email: session.email, role: rec.role };
}

module.exports = {
  NS, SESSION_COOKIE, USERS_KEY,
  redis, send, readJsonBody,
  hashPassword, verifyPassword,
  getCookie, sessionCookie,
  loadUsers, currentUser,
};
```

- [ ] **Step 6: Add the test script**

In `package.json` `scripts`, add `"test": "node --test test/"` and change `check` to `"node --check api/storage.js && node --check api/auth.js && node --check lib/shared.js"`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `node --test test/shared.test.js`
Expected: 5 passing.

- [ ] **Step 8: Commit**

```bash
git add lib/shared.js test/fake-upstash.js test/helpers.js test/shared.test.js package.json
git commit -m "Add shared lib (redis, password hashing, sessions) with fake Upstash tests"
```

---

### Task 2: `api/auth.js`

**Files:**
- Create: `api/auth.js`
- Create: `test/auth.test.js`

**Interfaces:**
- Consumes: everything exported by `lib/shared.js` (Task 1); `call`, `cookieFrom` from `test/helpers.js`.
- Produces: HTTP endpoint `/api/auth`
  - `GET` → `200 { user: {email, role} | null }`
  - `POST { action: 'login', email, password }` → `200 { user }` + `Set-Cookie`; `401 { error: 'bad-credentials' }`; `429 { error: 'too-many-attempts' }`; `503 { error: 'not-configured' }` when no users and env bootstrap unset
  - `POST { action: 'logout' }` → `200 { ok: true }` + expired cookie
  - `POST { action: 'password', current, next }` → `200 { ok: true }`; `401` if not signed in or current wrong; `400` if `next` shorter than 6
  - `POST { action: 'listUsers' }` → admin: `200 { users: [{email, role}] }`; else `403 { error: 'admin-only' }`
  - `POST { action: 'addUser', email, password }` → admin: `200 { users }`; `409 { error: 'exists' }`; `400` on bad email/short password
  - `POST { action: 'removeUser', email }` → admin: `200 { users }`; `400 { error: 'cannot-remove-admin' }`; `404 { error: 'not-found' }`

- [ ] **Step 1: Write the failing auth tests** — `test/auth.test.js`

```js
const test = require('node:test');
const assert = require('node:assert/strict');
const fake = require('./fake-upstash');
const { call, cookieFrom } = require('./helpers');

let up, auth, storage;
const post = (body, cookie, extra) => call(auth, { method: 'POST', body, headers: Object.assign(cookie ? { cookie } : {}, extra || {}) });
const write = (cookie) => call(storage, { method: 'POST', body: { key: 'semesterInfo', value: '{}' }, headers: cookie ? { cookie } : {} });
const adminLogin = async () => cookieFrom(await post({ action: 'login', email: 'admin@seu.edu', password: 'admin-pass' }));

test.before(async () => {
  up = await fake.start();
  process.env.KV_REST_API_URL = up.url;
  process.env.KV_REST_API_TOKEN = 'test-token';
  process.env.ADMIN_EMAIL = 'Admin@SEU.edu';
  process.env.ADMIN_PASSWORD = 'admin-pass';
  auth = require('../api/auth');
  storage = require('../api/storage');
});
test.after(() => up.close());
test.beforeEach(() => up.store.clear());

test('GET /api/auth without cookie → user null', async () => {
  const r = await call(auth, { method: 'GET' });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { user: null });
});

test('storage write without cookie → 401', async () => {
  assert.equal((await write('')).status, 401);
});

test('admin bootstrap login from env, then write succeeds; logout revokes', async () => {
  const bad = await post({ action: 'login', email: 'admin@seu.edu', password: 'nope' });
  assert.equal(bad.status, 401);
  const r = await post({ action: 'login', email: '  ADMIN@seu.edu ', password: 'admin-pass' });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.user, { email: 'admin@seu.edu', role: 'admin' });
  const cookie = cookieFrom(r);
  assert.match(cookie, /^seu_session=[a-f0-9]{64}$/);
  assert.match(String(r.headers['set-cookie']), /HttpOnly; SameSite=Lax/);

  const me = await call(auth, { method: 'GET', headers: { cookie } });
  assert.deepEqual(me.body.user, { email: 'admin@seu.edu', role: 'admin' });
  assert.equal((await write(cookie)).status, 200);

  const out = await post({ action: 'logout' }, cookie);
  assert.equal(out.status, 200);
  assert.match(String(out.headers['set-cookie']), /Max-Age=0/);
  assert.equal((await write(cookie)).status, 401);
});

test('env password stops working once users exist (Redis is the source of truth)', async () => {
  const admin = await adminLogin();
  const ch = await post({ action: 'password', current: 'admin-pass', next: 'new-pass-1' }, admin);
  assert.equal(ch.status, 200);
  assert.equal((await post({ action: 'login', email: 'admin@seu.edu', password: 'admin-pass' })).status, 401);
  assert.equal((await post({ action: 'login', email: 'admin@seu.edu', password: 'new-pass-1' })).status, 200);
});

test('password change rejects wrong current, short next, and signed-out callers', async () => {
  const admin = await adminLogin();
  assert.equal((await post({ action: 'password', current: 'x', next: 'new-pass-1' }, admin)).status, 401);
  assert.equal((await post({ action: 'password', current: 'admin-pass', next: '123' }, admin)).status, 400);
  assert.equal((await post({ action: 'password', current: 'admin-pass', next: 'new-pass-1' })).status, 401);
});

test('admin adds an editor; editor can write; removal locks them out', async () => {
  const admin = await adminLogin();
  const add = await post({ action: 'addUser', email: 'Ed@Gmail.com', password: 'editor-1' }, admin);
  assert.equal(add.status, 200);
  assert.deepEqual(add.body.users, [{ email: 'admin@seu.edu', role: 'admin' }, { email: 'ed@gmail.com', role: 'editor' }]);
  assert.equal((await post({ action: 'addUser', email: 'ed@gmail.com', password: 'editor-1' }, admin)).status, 409);
  assert.equal((await post({ action: 'addUser', email: 'not-an-email', password: 'editor-1' }, admin)).status, 400);
  assert.equal((await post({ action: 'addUser', email: 'x@y.com', password: '123' }, admin)).status, 400);

  const ed = await post({ action: 'login', email: 'ed@gmail.com', password: 'editor-1' });
  assert.equal(ed.status, 200);
  assert.deepEqual(ed.body.user, { email: 'ed@gmail.com', role: 'editor' });
  const edCookie = cookieFrom(ed);
  assert.equal((await write(edCookie)).status, 200);

  assert.equal((await post({ action: 'listUsers' }, edCookie)).status, 403);
  assert.equal((await post({ action: 'addUser', email: 'z@z.com', password: 'zzzzzz' }, edCookie)).status, 403);
  assert.equal((await post({ action: 'removeUser', email: 'admin@seu.edu' }, admin)).status, 400);
  assert.equal((await post({ action: 'removeUser', email: 'ghost@x.com' }, admin)).status, 404);

  const rm = await post({ action: 'removeUser', email: 'ed@gmail.com' }, admin);
  assert.equal(rm.status, 200);
  assert.deepEqual(rm.body.users, [{ email: 'admin@seu.edu', role: 'admin' }]);
  assert.equal((await write(edCookie)).status, 401);
  assert.equal((await post({ action: 'login', email: 'ed@gmail.com', password: 'editor-1' })).status, 401);
});

test('10 failed logins from one IP → 429; another IP is unaffected', async () => {
  const ip = { 'x-forwarded-for': '203.0.113.9, 10.0.0.1' };
  for(let i = 0; i < 10; i++){
    assert.equal((await post({ action: 'login', email: 'admin@seu.edu', password: 'bad' }, '', ip)).status, 401);
  }
  assert.equal((await post({ action: 'login', email: 'admin@seu.edu', password: 'admin-pass' }, '', ip)).status, 429);
  const other = await post({ action: 'login', email: 'admin@seu.edu', password: 'admin-pass' }, '', { 'x-forwarded-for': '198.51.100.2' });
  assert.equal(other.status, 200);
});

test('login when nothing is configured → 503', async () => {
  const saved = [process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD];
  delete process.env.ADMIN_EMAIL; delete process.env.ADMIN_PASSWORD;
  try{
    assert.equal((await post({ action: 'login', email: 'a@b.com', password: 'whatever' })).status, 503);
  } finally {
    process.env.ADMIN_EMAIL = saved[0]; process.env.ADMIN_PASSWORD = saved[1];
  }
});

test('unknown action → 400, wrong method → 405', async () => {
  const admin = await adminLogin();
  assert.equal((await post({ action: 'nope' }, admin)).status, 400);
  assert.equal((await call(auth, { method: 'DELETE' })).status, 405);
});

test('storage refuses auth:* keys even when signed in', async () => {
  const admin = await adminLogin();
  assert.equal((await call(storage, { method: 'POST', body: { key: 'auth:users', value: '{}' }, headers: { cookie: admin } })).status, 400);
  assert.equal((await call(storage, { method: 'GET', url: '/api/storage?key=auth:users' })).status, 400);
  assert.equal((await call(storage, { method: 'GET', url: '/api/storage?prefix=auth' })).status, 400);
  assert.equal((await call(storage, { method: 'DELETE', url: '/api/storage?key=auth:users', headers: { cookie: admin } })).status, 400);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/auth.test.js`
Expected: FAIL — `Cannot find module '../api/auth'`

- [ ] **Step 3: Write `api/auth.js`**

```js
// Sign-in and account management for the routine app.
//
//   GET  /api/auth                          -> { user }   who the cookie belongs to, or null
//   POST /api/auth { action: 'login', email, password }
//   POST /api/auth { action: 'logout' }
//   POST /api/auth { action: 'password', current, next }   own password, any signed-in user
//   POST /api/auth { action: 'listUsers' }                 admin only
//   POST /api/auth { action: 'addUser', email, password }  admin only, creates an editor
//   POST /api/auth { action: 'removeUser', email }         admin only
//
// Users live in one JSON blob at auth:users. The first successful login with
// ADMIN_EMAIL / ADMIN_PASSWORD from the environment creates the admin record;
// after that the database is the source of truth and the env values are
// ignored. To start over, delete seuRoutine:auth:users in the Upstash console.
const crypto = require('node:crypto');
const {
  NS, USERS_KEY, SESSION_COOKIE, redis, send, readJsonBody,
  hashPassword, verifyPassword, getCookie, sessionCookie, loadUsers, currentUser,
} = require('../lib/shared');

const SESSION_TTL = 60 * 60 * 24 * 30;   // 30 days
const MAX_FAILS = 10;                     // per IP ...
const FAIL_WINDOW = 15 * 60;              // ... per 15 minutes
const MIN_PASSWORD = 6;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const normEmail = (v) => String(v || '').trim().toLowerCase();
const clientIp = (req) => String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'local';
const saveUsers = (users) => redis(['SET', USERS_KEY, JSON.stringify(users)]);
const publicUsers = (users) => Object.keys(users).sort().map((email) => ({ email, role: users[email].role }));

function sameString(a, b){
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

async function login(req, res, body){
  const email = normEmail(body.email);
  const password = String(body.password || '');
  const failKey = NS + 'auth:fail:' + clientIp(req);
  if(Number(await redis(['GET', failKey]) || 0) >= MAX_FAILS) return send(res, 429, { error: 'too-many-attempts' });

  let users = await loadUsers();
  if(!users){
    const bootEmail = normEmail(process.env.ADMIN_EMAIL);
    const bootPass = process.env.ADMIN_PASSWORD || '';
    if(!bootEmail || !bootPass) return send(res, 503, { error: 'not-configured' });
    if(email === bootEmail && sameString(password, bootPass)){
      users = { [bootEmail]: Object.assign({ role: 'admin' }, hashPassword(bootPass)) };
      await saveUsers(users);
    }
  }
  const rec = users && users[email];
  if(!rec || !verifyPassword(password, rec)){
    const n = await redis(['INCR', failKey]);
    if(Number(n) === 1) await redis(['EXPIRE', failKey, FAIL_WINDOW]);
    return send(res, 401, { error: 'bad-credentials' });
  }
  await redis(['DEL', failKey]);
  const token = crypto.randomBytes(32).toString('hex');
  await redis(['SET', NS + 'auth:session:' + token, JSON.stringify({ email, role: rec.role }), 'EX', SESSION_TTL]);
  res.setHeader('Set-Cookie', sessionCookie(req, token, SESSION_TTL));
  return send(res, 200, { user: { email, role: rec.role } });
}

async function logout(req, res){
  const token = getCookie(req, SESSION_COOKIE);
  if(token) await redis(['DEL', NS + 'auth:session:' + token]);
  res.setHeader('Set-Cookie', sessionCookie(req, '', 0));
  return send(res, 200, { ok: true });
}

module.exports = async function handler(req, res){
  try{
    if(req.method === 'GET') return send(res, 200, { user: await currentUser(req) });
    if(req.method !== 'POST'){
      res.setHeader('Allow', 'GET, POST');
      return send(res, 405, { error: 'method-not-allowed' });
    }
    const body = await readJsonBody(req);
    const action = body && body.action;
    if(action === 'login') return login(req, res, body);
    if(action === 'logout') return logout(req, res);

    const user = await currentUser(req);
    if(!user) return send(res, 401, { error: 'auth-required' });

    if(action === 'password'){
      const users = await loadUsers();
      if(!verifyPassword(String(body.current || ''), users[user.email])) return send(res, 401, { error: 'bad-credentials' });
      const next = String(body.next || '');
      if(next.length < MIN_PASSWORD) return send(res, 400, { error: 'password-too-short' });
      users[user.email] = Object.assign({ role: users[user.email].role }, hashPassword(next));
      await saveUsers(users);
      return send(res, 200, { ok: true });
    }

    if(user.role !== 'admin') return send(res, 403, { error: 'admin-only' });
    const users = await loadUsers();

    if(action === 'listUsers') return send(res, 200, { users: publicUsers(users) });

    if(action === 'addUser'){
      const email = normEmail(body.email);
      const password = String(body.password || '');
      if(!EMAIL_RE.test(email)) return send(res, 400, { error: 'bad-email' });
      if(password.length < MIN_PASSWORD) return send(res, 400, { error: 'password-too-short' });
      if(users[email]) return send(res, 409, { error: 'exists' });
      users[email] = Object.assign({ role: 'editor' }, hashPassword(password));
      await saveUsers(users);
      return send(res, 200, { users: publicUsers(users) });
    }

    if(action === 'removeUser'){
      const email = normEmail(body.email);
      if(!users[email]) return send(res, 404, { error: 'not-found' });
      if(users[email].role === 'admin') return send(res, 400, { error: 'cannot-remove-admin' });
      delete users[email];
      await saveUsers(users);
      return send(res, 200, { users: publicUsers(users) });
    }

    return send(res, 400, { error: 'unknown-action' });
  }catch(err){
    return send(res, 500, { error: 'server-error', message: err && err.message });
  }
};
```

- [ ] **Step 4: Run the auth tests**

Run: `node --test test/auth.test.js`
Expected: the storage-gating tests still FAIL (storage.js is untouched until Task 3): `storage write without cookie → 401` fails with `200 !== 401`, and the `auth:*` test fails. Every other test PASSES.

- [ ] **Step 5: Commit**

```bash
git add api/auth.js test/auth.test.js
git commit -m "Add /api/auth: login, logout, password change, editor management"
```

---

### Task 3: Gate `api/storage.js` on the session

**Files:**
- Modify: `api/storage.js` (whole file — it shrinks)

**Interfaces:**
- Consumes: `redis`, `send`, `readJsonBody`, `currentUser`, `NS` from `lib/shared.js`.
- Produces: unchanged HTTP API except `?ping=1` now returns `{ ok: true }` (no `auth` field); writes return `401 { error: 'auth-required' }` without a valid session; any `auth:*` key or `auth` prefix returns `400 { error: 'reserved-key' }`.

- [ ] **Step 1: Rewrite `api/storage.js`**

```js
// Key/value storage for the routine app, backed by Upstash Redis over its REST
// API. No npm dependency — the REST API takes a plain JSON command array.
//
//   GET    /api/storage?ping=1          -> { ok }              health
//   GET    /api/storage?key=<key>       -> { key, value }      404 when the key does not exist
//   GET    /api/storage?prefix=<pfx>    -> { keys: [...] }
//   POST   /api/storage  {key, value}   -> { key, value }      upsert
//   DELETE /api/storage?key=<key>       -> { key, deleted }
//
// Reads are open. Writes need a signed-in user — the seu_session cookie set
// by /api/auth. The auth:* keys are never reachable through this endpoint.
// See lib/shared.js for the Redis client and session lookup.
const { NS, redis, send, readJsonBody, currentUser } = require('../lib/shared');

// SCAN patterns are globs, so a prefix carrying *, ?, [ or \ has to be escaped.
function globEscape(prefix) {
  let out = '';
  for (const ch of String(prefix)) {
    if (ch === '*' || ch === '?' || ch === '[' || ch === ']' || ch === '\\') out += '\\';
    out += ch;
  }
  return out;
}

async function scanKeys(prefix) {
  const pattern = NS + globEscape(prefix || '') + '*';
  const keys = [];
  let cursor = '0';
  let rounds = 0;
  do {
    const [next, batch] = await redis(['SCAN', cursor, 'MATCH', pattern, 'COUNT', 1000]);
    cursor = String(next);
    for (const k of batch || []) keys.push(k.slice(NS.length));
    rounds++;
  } while (cursor !== '0' && rounds < 50);
  return keys;
}

const reserved = (key) => typeof key === 'string' && key.startsWith('auth');

module.exports = async function handler(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const params = url.searchParams;

  try {
    if (params.has('ping')) {
      await redis(['PING']);
      return send(res, 200, { ok: true });
    }

    if (reserved(params.get('key')) || reserved(params.get('prefix'))) {
      return send(res, 400, { error: 'reserved-key' });
    }

    if (req.method === 'GET') {
      const key = params.get('key');
      if (key) {
        const value = await redis(['GET', NS + key]);
        if (value === null || value === undefined) return send(res, 404, { error: 'not-found', key });
        return send(res, 200, { key, value: String(value) });
      }
      if (params.has('prefix')) {
        const prefix = params.get('prefix') || '';
        return send(res, 200, { keys: await scanKeys(prefix), prefix });
      }
      return send(res, 400, { error: 'key or prefix is required' });
    }

    if (req.method === 'POST' || req.method === 'PUT') {
      if (!(await currentUser(req))) return send(res, 401, { error: 'auth-required' });
      const body = await readJsonBody(req);
      const key = body && body.key;
      if (typeof key !== 'string' || !key) return send(res, 400, { error: 'key is required' });
      if (reserved(key)) return send(res, 400, { error: 'reserved-key' });
      const value = body.value == null ? '' : String(body.value);
      await redis(['SET', NS + key, value]);
      return send(res, 200, { key, value });
    }

    if (req.method === 'DELETE') {
      if (!(await currentUser(req))) return send(res, 401, { error: 'auth-required' });
      const key = params.get('key');
      if (!key) return send(res, 400, { error: 'key is required' });
      const removed = await redis(['DEL', NS + key]);
      return send(res, 200, { key, deleted: Number(removed) > 0 });
    }

    res.setHeader('Allow', 'GET, POST, PUT, DELETE');
    return send(res, 405, { error: 'method-not-allowed' });
  } catch (err) {
    const status = params.has('ping') ? 503 : 500;
    return send(res, status, { ok: false, error: 'server-error', message: err && err.message });
  }
};
```

(Prefix check `startsWith('auth')` deliberately also blocks a `?prefix=auth` scan, and an empty prefix `''` still lists everything — including `auth:*` key names but never values. The seed logic only lists `override:`; nothing in the page lists with an empty prefix.)

- [ ] **Step 2: Run the full suite**

Run: `npm test` then `npm run check`.
Expected: every test in both files PASSES; `check` prints nothing.

- [ ] **Step 3: Commit**

```bash
git add api/storage.js
git commit -m "Gate storage writes on the session cookie; drop ADMIN_KEY"
```

---

### Task 4: Frontend — account bar, modals, edit gating

**Files:**
- Modify: `public/index.html`
  - CSS block: after `.btn-danger:hover` (≈line 392)
  - masthead-right: after the `#sourceLine` span (≈line 482)
  - semester bar `<div class="semester-bar">` (≈line 486)
  - control bar buttons `importBtn`, `genBtn`, `clearBtn` (≈518–523)
  - before the app `<script>`: three new overlays
  - JS: `ADMIN_KEY_KEY` / `getAdminKey` / `setAdminKey` / `apiFetch` / `apiWrite` / `probeApi` / `updateDbStatus` (≈728–813)
  - JS: `appStorage.set` / `appStorage.delete` (≈835–854)
  - JS: `seedDateOverridesIfNeeded` (≈871)
  - JS: `updateSourceLine` reset link (≈1444)
  - JS: `openAdd`, `openDelete`, `openEdit` first lines (≈1988, ≈2028, ≈2085)
  - JS: `init()` (≈2693)

**Interfaces:**
- Consumes: `/api/auth` and `/api/storage` as defined in Tasks 2–3.
- Produces (page-level JS): `authUser` (`{email, role}|null`), `canEdit(): boolean`, `requireSignIn(): boolean`, `openLogin()`, `applyAuthUi()`, `loadAuthUser(): Promise<void>`.

Keep CRLF endings. Do each edit as a targeted replacement (a script that reads the file, replaces exact substrings, writes back); never rewrite the whole file by hand.

- [ ] **Step 1: CSS** — after `  .btn-danger:hover{background:var(--navy-2);}` insert:

```css
  /* Editing controls only show for signed-in users (or offline, local-only mode). */
  body:not(.can-edit) .edit-only{display:none !important;}
  .auth-bar{margin-top:6px; display:flex; gap:8px; justify-content:flex-end; align-items:center; flex-wrap:wrap;}
  .auth-bar .who{color:var(--navy); font-weight:600;}
  .auth-bar .role, .user-list .role{font-size:11.5px; text-transform:uppercase; letter-spacing:.05em; background:var(--cream); border:1px solid var(--line); border-radius:999px; padding:1px 8px; color:var(--muted);}
  .auth-bar button{font:inherit; font-size:12.5px; padding:4px 10px; border-radius:6px; border:1.5px solid var(--navy); background:var(--navy); color:#fff; cursor:pointer;}
  .auth-bar button.ghost{background:transparent; color:var(--navy);}
  .auth-bar button:hover{background:var(--navy-2); color:#fff;}
  .form-error{color:var(--busy-bg); font-size:13px; min-height:18px; margin:-6px 0 8px;}
  .user-list{list-style:none; margin:0 0 14px; padding:0; border:1px solid var(--line); border-radius:8px; max-height:220px; overflow:auto;}
  .user-list li{display:flex; align-items:center; gap:10px; padding:8px 12px; border-bottom:1px solid var(--line); font-size:13.5px;}
  .user-list li:last-child{border-bottom:none;}
  .user-list li .email{flex:1; word-break:break-all;}
  .user-list li button{font:inherit; font-size:12px; padding:3px 9px; border-radius:6px; border:1px solid #cfd2d6; background:transparent; color:var(--busy-bg); cursor:pointer;}
  .user-list li button:hover{background:#fbeaea;}
```

- [ ] **Step 2: Masthead account bar** — inside `<div class="masthead-right">`, after the `#sourceLine` `</span>` line, add:

```html
      <div class="auth-bar" id="authBar"></div>
```

- [ ] **Step 3: Mark edit-only controls**

- `<div class="semester-bar">` → `<div class="semester-bar edit-only">`
- `<button class="print-btn" id="importBtn">` → `<button class="print-btn edit-only" id="importBtn">`
- `<button class="print-btn" id="genBtn">` → `<button class="print-btn edit-only" id="genBtn">`
- `<button class="print-btn" id="clearBtn"` → `<button class="print-btn edit-only" id="clearBtn"`
- Both occurrences of `<a href="#" id="resetSourceLink"` (initial HTML and inside `updateSourceLine`) → `<a href="#" id="resetSourceLink" class="edit-only"`.

- [ ] **Step 4: Three modals** — immediately before the app `<script>` tag (the one whose body starts with `const BASE_SCHEDULE`), add:

```html
<!-- Sign in -->
<div class="overlay" id="loginOverlay">
  <div class="modal">
    <h3>Sign in</h3>
    <div class="meta">Viewing is open to everyone. Sign in to change the routine.</div>
    <form id="loginForm" autocomplete="on">
      <div class="field">
        <label for="loginEmail">Email</label>
        <input type="email" id="loginEmail" autocomplete="username" required>
      </div>
      <div class="field">
        <label for="loginPassword">Password</label>
        <input type="password" id="loginPassword" autocomplete="current-password" required>
      </div>
      <div class="form-error" id="loginError"></div>
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" id="cancelLoginBtn">Cancel</button>
        <button type="submit" class="btn btn-primary" id="confirmLoginBtn">Sign in</button>
      </div>
    </form>
  </div>
</div>

<!-- Change password -->
<div class="overlay" id="passwordOverlay">
  <div class="modal">
    <h3>Change password</h3>
    <div class="meta" id="passwordMeta"></div>
    <form id="passwordForm">
      <div class="field">
        <label for="pwCurrent">Current password</label>
        <input type="password" id="pwCurrent" autocomplete="current-password" required>
      </div>
      <div class="field">
        <label for="pwNext">New password (6+ characters)</label>
        <input type="password" id="pwNext" autocomplete="new-password" minlength="6" required>
      </div>
      <div class="form-error" id="passwordError"></div>
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" id="cancelPasswordBtn">Cancel</button>
        <button type="submit" class="btn btn-primary" id="confirmPasswordBtn">Save</button>
      </div>
    </form>
  </div>
</div>

<!-- Manage editors (admin) -->
<div class="overlay" id="usersOverlay">
  <div class="modal" style="max-width:460px;">
    <h3>Editors</h3>
    <div class="meta">These accounts can change the routine. The admin account cannot be removed here.</div>
    <ul class="user-list" id="userList"></ul>
    <form id="addUserForm">
      <div class="field">
        <label for="newUserEmail">Add editor — email</label>
        <input type="email" id="newUserEmail" autocomplete="off" required>
      </div>
      <div class="field">
        <label for="newUserPassword">Password for them (6+ characters)</label>
        <input type="text" id="newUserPassword" autocomplete="off" minlength="6" required>
      </div>
      <div class="form-error" id="usersError"></div>
      <div class="modal-actions">
        <button type="button" class="btn btn-ghost" id="closeUsersBtn">Close</button>
        <button type="submit" class="btn btn-primary" id="addUserBtn">Add editor</button>
      </div>
    </form>
  </div>
</div>
```

- [ ] **Step 5: Replace the admin-key plumbing**

Delete from the JS: the `const ADMIN_KEY_KEY = ...` line, the `getAdminKey()` and `setAdminKey()` functions, `let apiNeedsAuth = false;`, and the `apiNeedsAuth = !!(data && data.auth);` line inside `probeApi`.

Replace `apiFetch` and `apiWrite` (and their comment) with:

```js
async function apiFetch(query, options){
  return fetch(API_BASE + (query || ''), Object.assign({ cache: 'no-store' }, options || {}));
}

// A 401 means nobody is signed in on this browser: show the sign-in dialog and
// let the caller report "could not save" — the user retries after signing in.
async function apiWrite(query, options){
  let res = null;
  try{ res = await apiFetch(query, options); }catch(e){ return null; }
  if(res.status === 401){ authUser = null; applyAuthUi(); openLogin(); }
  return res;
}
```

Replace `updateDbStatus` with:

```js
function updateDbStatus(){
  const el = document.getElementById('dbStatusLine');
  if(!el) return;
  if(apiOnline){
    el.textContent = authUser
      ? 'Connected to the shared database — signed in as ' + authUser.email + ', every change is saved for everyone.'
      : 'Connected to the shared database — viewing only. Sign in to make changes.';
    el.style.color = 'var(--green)';
  }else{
    el.textContent = 'Offline mode — changes are saved in this browser only and are not shared.';
    el.style.color = 'var(--busy-bg)';
  }
}
```

- [ ] **Step 6: Only mirror to localStorage after a successful online write**

`appStorage.set` becomes:

```js
  async set(key, value){
    if(apiOnline){
      const res = await apiWrite('', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ key: key, value: value })
      });
      if(!res || !res.ok) return null;
    }
    localSet(key, value);
    return { key, value };
  },
```

`appStorage.delete` becomes:

```js
  async delete(key){
    if(apiOnline){
      const res = await apiWrite('?key=' + encodeURIComponent(key), { method: 'DELETE' });
      if(!res || !res.ok) return null;
    }
    localDelete(key);
    return { key, deleted: true };
  },
```

- [ ] **Step 7: Don't seed while signed out** — in `seedDateOverridesIfNeeded`, right after the `if(!apiOnline){ ... return; }` block:

```js
  if(!authUser) return;   // seeding writes; it runs the first time an editor or admin signs in
```

- [ ] **Step 8: Auth state + UI code** — directly after the closing `};` of the `appStorage` object (before the `// One-off date changes baked into this file` comment), add:

```js
// ===== Sign-in state =====
// authUser is {email, role} when the seu_session cookie is valid, else null.
// Editing is allowed when signed in, or in offline (local-only) mode.
let authUser = null;
const AUTH_BASE = '/api/auth';

async function authPost(body){
  let res = null;
  try{
    res = await fetch(AUTH_BASE, { method: 'POST', cache: 'no-store', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  }catch(e){ return { ok: false, status: 0, data: null }; }
  let data = null;
  try{ data = await res.json(); }catch(e){ /* empty body */ }
  return { ok: res.ok, status: res.status, data };
}

async function loadAuthUser(){
  authUser = null;
  if(apiOnline){
    try{
      const res = await fetch(AUTH_BASE, { cache: 'no-store' });
      if(res.ok){ const data = await res.json(); authUser = (data && data.user) || null; }
    }catch(e){ /* treat as signed out */ }
  }
  applyAuthUi();
}

function canEdit(){ return !apiOnline || !!authUser; }

// Call at the top of any edit entry point. Returns false (and opens sign-in)
// when the site is online but nobody is signed in.
function requireSignIn(){
  if(canEdit()) return true;
  openLogin();
  return false;
}

function applyAuthUi(){
  document.body.classList.toggle('can-edit', canEdit());
  const bar = document.getElementById('authBar');
  if(bar){
    bar.innerHTML = '';
    if(!apiOnline){
      bar.innerHTML = '<span class="role">offline · local only</span>';
    }else if(authUser){
      bar.innerHTML = '<span class="who"></span><span class="role"></span>' +
        '<button type="button" class="ghost" id="passwordBtn">Change password</button>' +
        (authUser.role === 'admin' ? '<button type="button" id="usersBtn">Manage editors</button>' : '') +
        '<button type="button" class="ghost" id="logoutBtn">Sign out</button>';
      bar.querySelector('.who').textContent = authUser.email;
      bar.querySelector('.role').textContent = authUser.role;
      bar.querySelector('#passwordBtn').onclick = openPasswordModal;
      const ub = bar.querySelector('#usersBtn'); if(ub) ub.onclick = openUsersModal;
      bar.querySelector('#logoutBtn').onclick = async () => { await authPost({ action: 'logout' }); await loadAuthUser(); };
    }else{
      bar.innerHTML = '<button type="button" id="signInBtn">Sign in to edit</button>';
      bar.querySelector('#signInBtn').onclick = openLogin;
    }
  }
  updateDbStatus();
}

const loginOverlay = document.getElementById('loginOverlay');
const loginError = document.getElementById('loginError');
function openLogin(){
  loginError.textContent = '';
  document.getElementById('loginPassword').value = '';
  loginOverlay.classList.add('show');
  document.getElementById('loginEmail').focus();
}
document.getElementById('cancelLoginBtn').onclick = () => loginOverlay.classList.remove('show');
document.getElementById('loginForm').onsubmit = async (ev) => {
  ev.preventDefault();
  const btn = document.getElementById('confirmLoginBtn');
  btn.disabled = true; loginError.textContent = '';
  const r = await authPost({ action: 'login', email: document.getElementById('loginEmail').value, password: document.getElementById('loginPassword').value });
  btn.disabled = false;
  if(r.ok){
    authUser = r.data.user;
    loginOverlay.classList.remove('show');
    applyAuthUi();
    await seedDateOverridesIfNeeded();
    return;
  }
  loginError.textContent =
    r.status === 401 ? 'Wrong email or password.' :
    r.status === 429 ? 'Too many attempts — try again in 15 minutes.' :
    r.status === 503 ? 'Sign-in is not set up on this site yet (ADMIN_EMAIL / ADMIN_PASSWORD).' :
    'Could not sign in. Please try again.';
};

const passwordOverlay = document.getElementById('passwordOverlay');
const passwordError = document.getElementById('passwordError');
function openPasswordModal(){
  passwordError.textContent = '';
  document.getElementById('passwordMeta').textContent = authUser ? authUser.email : '';
  document.getElementById('pwCurrent').value = ''; document.getElementById('pwNext').value = '';
  passwordOverlay.classList.add('show');
  document.getElementById('pwCurrent').focus();
}
document.getElementById('cancelPasswordBtn').onclick = () => passwordOverlay.classList.remove('show');
document.getElementById('passwordForm').onsubmit = async (ev) => {
  ev.preventDefault();
  const r = await authPost({ action: 'password', current: document.getElementById('pwCurrent').value, next: document.getElementById('pwNext').value });
  if(r.ok){ passwordOverlay.classList.remove('show'); return; }
  passwordError.textContent =
    r.status === 401 ? 'Current password is wrong (or you were signed out).' :
    r.status === 400 ? 'New password must be at least 6 characters.' :
    'Could not change the password.';
};

const usersOverlay = document.getElementById('usersOverlay');
const usersError = document.getElementById('usersError');
function renderUserList(users){
  const ul = document.getElementById('userList');
  ul.innerHTML = '';
  (users || []).forEach((u) => {
    const li = document.createElement('li');
    const email = document.createElement('span'); email.className = 'email'; email.textContent = u.email;
    const role = document.createElement('span'); role.className = 'role'; role.textContent = u.role;
    li.appendChild(email); li.appendChild(role);
    if(u.role !== 'admin'){
      const rm = document.createElement('button'); rm.type = 'button'; rm.textContent = 'Remove';
      rm.onclick = async () => {
        if(!confirm('Remove ' + u.email + '? They will be signed out immediately.')) return;
        const r = await authPost({ action: 'removeUser', email: u.email });
        if(r.ok) renderUserList(r.data.users); else usersError.textContent = 'Could not remove that account.';
      };
      li.appendChild(rm);
    }
    ul.appendChild(li);
  });
}
async function openUsersModal(){
  usersError.textContent = '';
  document.getElementById('newUserEmail').value = ''; document.getElementById('newUserPassword').value = '';
  usersOverlay.classList.add('show');
  const r = await authPost({ action: 'listUsers' });
  if(r.ok) renderUserList(r.data.users); else usersError.textContent = 'Could not load the list.';
}
document.getElementById('closeUsersBtn').onclick = () => usersOverlay.classList.remove('show');
document.getElementById('addUserForm').onsubmit = async (ev) => {
  ev.preventDefault();
  usersError.textContent = '';
  const r = await authPost({ action: 'addUser', email: document.getElementById('newUserEmail').value, password: document.getElementById('newUserPassword').value });
  if(r.ok){
    renderUserList(r.data.users);
    document.getElementById('newUserEmail').value = ''; document.getElementById('newUserPassword').value = '';
    return;
  }
  usersError.textContent =
    r.status === 409 ? 'That email already has an account.' :
    r.status === 400 ? 'Enter a valid email and a password of 6+ characters.' :
    r.status === 403 ? 'Only the admin can add editors.' :
    'Could not add that account.';
};
```

- [ ] **Step 9: Guard the cell openers** — first line inside each of `function openAdd(time, room, dayKey){`, `function openDelete(time, room, entry, dayKey){`, `function openEdit(time, room, entry, dayKey){`:

```js
  if(!requireSignIn()) return;
```

- [ ] **Step 10: Load auth state on init** — in `init()`, replace

```js
  apiOnline = await probeApi();
  updateDbStatus();
  await seedDateOverridesIfNeeded();
```

with

```js
  apiOnline = await probeApi();
  await loadAuthUser();          // also calls updateDbStatus()
  await seedDateOverridesIfNeeded();
```

- [ ] **Step 11: Check the file still parses and the CRLFs survived**

```bash
node -e "const s=require('fs').readFileSync('public/index.html','utf8');const i=s.lastIndexOf('<script>');const j=s.lastIndexOf('</script>');new Function(s.slice(i+8,j));console.log('js ok;', (s.match(/\r\n/g)||[]).length, 'crlf of', s.split('\n').length, 'lines')"
```
Expected: `js ok; N crlf of N+1 lines`. A `SyntaxError` means a bad edit.

- [ ] **Step 12: Manual check in the browser**

Throwaway dev server in the scratchpad (not committed): start `test/fake-upstash.js`, set `KV_REST_API_URL`, `KV_REST_API_TOKEN`, `ADMIN_EMAIL=admin@seu.edu`, `ADMIN_PASSWORD=admin-pass`, serve `public/` statically and route `/api/auth` and `/api/storage` to the two handlers on `http://127.0.0.1:3000`. Open it in the Browser pane and check:

1. Signed out: grid visible; semester bar / Import / Generate / Clear hidden; status line says "viewing only"; clicking a `+ Add class` cell opens the Sign in modal.
2. Wrong password → "Wrong email or password." Correct → modal closes, account bar shows `admin@seu.edu ADMIN`, edit buttons appear.
3. Add a class on a cell → it renders; reload → still there.
4. Manage editors → add `ed@gmail.com` / `editor-1` → appears in list; Remove → gone.
5. Change password → works; Sign out → back to viewing only.

- [ ] **Step 13: Commit**

```bash
git add public/index.html
git commit -m "Sign-in, account bar, editor management and edit gating in the page"
```

---

### Task 5: Docs, env, push

**Files:**
- Modify: `README.md` (key table, API section, setup step 3, local dev)
- Modify: `.env.example`
- Modify: `docs/superpowers/specs/2026-09-12-auth-login-design.md` (the Update button only downloads an HTML copy — drop it from the edit-only list)

- [ ] **Step 1: `.env.example`** — replace the `ADMIN_KEY` block with:

```
# Bootstrap admin. Used only until the first successful sign-in creates the
# admin record in Redis; after that, change the password from the page.
# To start over, delete the key seuRoutine:auth:users in the Upstash console.
ADMIN_EMAIL="you@example.com"
ADMIN_PASSWORD="choose-a-strong-password"
```

- [ ] **Step 2: README**

- Intro bullet list: add `lib/shared.js` and `api/auth.js`.
- Key table: add `auth:users` (accounts, scrypt hashes), `auth:session:<token>` (30-day sessions), `auth:fail:<ip>` (sign-in rate limit).
- API section: add the `/api/auth` routes (copy the header comment from `api/auth.js`); change the storage note to "Reads are always open. Writes require a signed-in user (the `seu_session` cookie from `/api/auth`)."
- Replace "### 3. Locking down editing (optional)" with "### 3. Sign-in (needed to edit)": set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in Settings → Environment Variables, redeploy, click **Sign in to edit**; **Manage editors** adds people by email + password; **Change password** rotates. Forgot the admin password → delete `seuRoutine:auth:users` in the Upstash data browser and sign in again with the env values (no redeploy). Remove every mention of `ADMIN_KEY` / `x-admin-key`.
- Local development: mention `npm test`.

- [ ] **Step 3: Final checks**

Run: `npm test` and `npm run check`. Expected: all green; `check` prints nothing.

- [ ] **Step 4: Commit and push**

```bash
git add README.md .env.example docs/
git commit -m "Document sign-in setup and env vars"
git push -u origin feature/auth-login
gh pr create --title "Sign-in with admin-managed editors" --body "<summary; env vars ADMIN_EMAIL + ADMIN_PASSWORD to add before merging; ADMIN_KEY can be deleted; npm test>"
```

PR body ends with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.
