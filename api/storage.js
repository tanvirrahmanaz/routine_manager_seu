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
