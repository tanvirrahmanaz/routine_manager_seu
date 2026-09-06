// Key/value storage for the routine app, backed by MongoDB.
//
//   GET    /api/storage?ping=1          -> { ok, auth }        health + whether writes need a password
//   GET    /api/storage?key=<key>       -> { key, value }      404 when the key does not exist
//   GET    /api/storage?prefix=<pfx>    -> { keys: [...] }
//   POST   /api/storage  {key, value}   -> { key, value }      upsert
//   DELETE /api/storage?key=<key>       -> { key, deleted }
//
// Writes require the `x-admin-key` header only when ADMIN_KEY is set in the
// environment. Leave ADMIN_KEY unset and anyone who can open the page can edit.

const { MongoClient } = require('mongodb');

const URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || 'seu_law_routine';
const COLLECTION = process.env.MONGODB_COLLECTION || 'routine_store';
const ADMIN_KEY = process.env.ADMIN_KEY || '';

// Serverless functions are re-used between invocations, so hang the client off
// the global object to avoid opening a new connection pool on every request.
const cache = global.__seuRoutineMongo || (global.__seuRoutineMongo = { promise: null });

async function getCollection(){
  if(!URI) throw new Error('MONGODB_URI is not set on this deployment');
  if(!cache.promise){
    cache.promise = new MongoClient(URI, { maxPoolSize: 5 }).connect().catch(err => {
      cache.promise = null; // let the next request retry a failed connection
      throw err;
    });
  }
  const client = await cache.promise;
  return client.db(DB_NAME).collection(COLLECTION);
}

function send(res, status, body){
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

// Prefix match as an index-friendly range scan on _id, so no regex escaping
// is needed for keys that contain ":" or "-".
function prefixQuery(prefix){
  if(!prefix) return {};
  return { _id: { $gte: prefix, $lt: prefix + String.fromCharCode(0xFFFF) } };
}

function authorized(req){
  if(!ADMIN_KEY) return true;
  const given = req.headers['x-admin-key'];
  return typeof given === 'string' && given === ADMIN_KEY;
}

async function readJsonBody(req){
  if(req.body && typeof req.body === 'object') return req.body;
  if(typeof req.body === 'string' && req.body) return JSON.parse(req.body);
  const chunks = [];
  for await (const chunk of req){ chunks.push(chunk); }
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

module.exports = async function handler(req, res){
  const url = new URL(req.url, 'http://localhost');
  const params = url.searchParams;

  try{
    if(params.has('ping')){
      const col = await getCollection();
      await col.estimatedDocumentCount();
      return send(res, 200, { ok: true, auth: !!ADMIN_KEY });
    }

    if(req.method === 'GET'){
      const key = params.get('key');
      if(key){
        const col = await getCollection();
        const doc = await col.findOne({ _id: key });
        if(!doc) return send(res, 404, { error: 'not-found', key });
        return send(res, 200, { key, value: doc.value });
      }
      if(params.has('prefix')){
        const prefix = params.get('prefix') || '';
        const col = await getCollection();
        const docs = await col.find(prefixQuery(prefix)).project({ _id: 1 }).limit(5000).toArray();
        return send(res, 200, { keys: docs.map(d => d._id), prefix });
      }
      return send(res, 400, { error: 'key or prefix is required' });
    }

    if(req.method === 'POST' || req.method === 'PUT'){
      if(!authorized(req)) return send(res, 401, { error: 'auth-required' });
      const body = await readJsonBody(req);
      const key = body && body.key;
      if(typeof key !== 'string' || !key) return send(res, 400, { error: 'key is required' });
      const value = body.value == null ? '' : String(body.value);
      const col = await getCollection();
      await col.updateOne(
        { _id: key },
        { $set: { value, updatedAt: new Date() } },
        { upsert: true }
      );
      return send(res, 200, { key, value });
    }

    if(req.method === 'DELETE'){
      if(!authorized(req)) return send(res, 401, { error: 'auth-required' });
      const key = params.get('key');
      if(!key) return send(res, 400, { error: 'key is required' });
      const col = await getCollection();
      const result = await col.deleteOne({ _id: key });
      return send(res, 200, { key, deleted: result.deletedCount > 0 });
    }

    res.setHeader('Allow', 'GET, POST, PUT, DELETE');
    return send(res, 405, { error: 'method-not-allowed' });
  }catch(err){
    return send(res, 500, { error: 'server-error', message: err && err.message });
  }
};
