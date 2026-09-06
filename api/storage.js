// Key/value storage for the routine app, backed by Upstash Redis over its REST
// API. No npm dependency — the REST API takes a plain JSON command array.
//
//   GET    /api/storage?ping=1          -> { ok, auth }        health + whether writes need a password
//   GET    /api/storage?key=<key>       -> { key, value }      404 when the key does not exist
//   GET    /api/storage?prefix=<pfx>    -> { keys: [...] }
//   POST   /api/storage  {key, value}   -> { key, value }      upsert
//   DELETE /api/storage?key=<key>       -> { key, deleted }
//
// Connect an Upstash Redis store from the Vercel dashboard (Storage tab) and it
// injects KV_REST_API_URL / KV_REST_API_TOKEN automatically. The plain Upstash
// variable names work too, for a database created directly on upstash.com.
//
// Writes require the `x-admin-key` header only when ADMIN_KEY is set in the
// environment. Leave ADMIN_KEY unset and anyone who can open the page can edit.

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
const ADMIN_KEY = process.env.ADMIN_KEY || '';

// Everything this app owns lives under one namespace, so the database stays
// tidy if it is ever shared with something else.
const NS = 'seuRoutine:';

async function redis(command) {
  if (!REDIS_URL || !REDIS_TOKEN) {
    throw new Error('KV_REST_API_URL / KV_REST_API_TOKEN are not set on this deployment');
  }
  const res = await fetch(REDIS_URL.replace(/\/+$/, ''), {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + REDIS_TOKEN,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(command),
    cache: 'no-store',
  });
  const data = await res.json().catch(() => null);
  if (!res.ok || !data || data.error) {
    throw new Error((data && data.error) || 'Redis request failed with status ' + res.status);
  }
  return data.result;
}

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

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

function authorized(req) {
  if (!ADMIN_KEY) return true;
  const given = req.headers['x-admin-key'];
  return typeof given === 'string' && given === ADMIN_KEY;
}

async function readJsonBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string' && req.body) return JSON.parse(req.body);
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

module.exports = async function handler(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const params = url.searchParams;

  try {
    if (params.has('ping')) {
      await redis(['PING']);
      return send(res, 200, { ok: true, auth: !!ADMIN_KEY });
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
      if (!authorized(req)) return send(res, 401, { error: 'auth-required' });
      const body = await readJsonBody(req);
      const key = body && body.key;
      if (typeof key !== 'string' || !key) return send(res, 400, { error: 'key is required' });
      const value = body.value == null ? '' : String(body.value);
      await redis(['SET', NS + key, value]);
      return send(res, 200, { key, value });
    }

    if (req.method === 'DELETE') {
      if (!authorized(req)) return send(res, 401, { error: 'auth-required' });
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
