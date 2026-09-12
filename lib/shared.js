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
