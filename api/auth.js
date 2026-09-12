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
