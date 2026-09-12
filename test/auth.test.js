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

test('GET /api/auth without cookie -> user null', async () => {
  const r = await call(auth, { method: 'GET' });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { user: null });
});

test('storage write without cookie -> 401', async () => {
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

test('10 failed logins from one IP -> 429; another IP is unaffected', async () => {
  const ip = { 'x-forwarded-for': '203.0.113.9, 10.0.0.1' };
  for(let i = 0; i < 10; i++){
    assert.equal((await post({ action: 'login', email: 'admin@seu.edu', password: 'bad' }, '', ip)).status, 401);
  }
  assert.equal((await post({ action: 'login', email: 'admin@seu.edu', password: 'admin-pass' }, '', ip)).status, 429);
  const other = await post({ action: 'login', email: 'admin@seu.edu', password: 'admin-pass' }, '', { 'x-forwarded-for': '198.51.100.2' });
  assert.equal(other.status, 200);
});

test('login when nothing is configured -> 503', async () => {
  const saved = [process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD];
  delete process.env.ADMIN_EMAIL; delete process.env.ADMIN_PASSWORD;
  try{
    assert.equal((await post({ action: 'login', email: 'a@b.com', password: 'whatever' })).status, 503);
  } finally {
    process.env.ADMIN_EMAIL = saved[0]; process.env.ADMIN_PASSWORD = saved[1];
  }
});

test('unknown action -> 400, wrong method -> 405', async () => {
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
