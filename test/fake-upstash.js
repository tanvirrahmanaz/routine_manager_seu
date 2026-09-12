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
        const re = new RegExp('^' + pattern.replace(/[.+^${}()|[\]]/g, '\$&').replace(/\\*/g, '.*').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
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
