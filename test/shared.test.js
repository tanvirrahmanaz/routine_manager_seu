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
