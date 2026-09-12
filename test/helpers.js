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
