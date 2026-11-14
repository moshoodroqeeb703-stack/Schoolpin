// School PIN checker — Cloudflare Worker (free plan).
// Secrets to add in Cloudflare: FB_PROJECT, FB_EMAIL, FB_KEY.  Optional variable: ALLOW_ORIGIN
const MAX_WRONG = 10, WINDOW = 15 * 60e3;
const enc = new TextEncoder();
const sha = async s => [...new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('');
const rid = (s, t) => s + '_' + t.toLowerCase().replace(/[^a-z0-9]+/g, '-');

async function check(st, q) {
  const exam = String(q.exam || '').toUpperCase().replace(/\s+/g, '');
  const serial = String(q.serial || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  const pin = String(q.pin || '').replace(/\D/g, '');
  if (!/^[A-Z0-9\/._-]{2,40}$/.test(exam) || serial.length !== 8 || pin.length !== 12)
    return { s: 400, e: 'Enter your exam number, the PIN serial number and the 12-digit PIN.' };
  const now = Date.now(), ih = await sha('ip:' + (q.ip || 'x')), g = await st.getGuard(ih);
  const live = g && now - g.t < WINDOW;
  if (live && g.n >= MAX_WRONG) return { s: 429, e: 'Too many wrong tries. Wait 15 minutes and try again.' };
  const p = await st.getPin(serial);
  if (!p || p.h !== await sha(serial + ':' + pin)) {
    await st.setGuard(ih, live ? { n: g.n + 1, t: g.t } : { n: 1, t: now });
    return { s: 401, e: 'Wrong PIN or serial number.' };
  }
  if (p.status === 'disabled') return { s: 403, e: 'This PIN has been disabled. Contact the school.' };
  if (p.exp) { const c = await st.getCurrent(); if (c && c.session + ' ' + c.term !== p.term) return { s: 403, e: 'This PIN has expired because the term is closed.' }; }
  if (p.exam && p.exam !== exam) return { s: 403, e: 'This PIN is already tied to another exam number.' };
  if (p.uses >= p.max) return { s: 403, e: 'This PIN has no checks left.' };
  const u = await st.getStudent(exam);
  const r = u && await st.getResult(rid(u.uid, p.term));
  if (!r || r.published !== true) return { s: 404, e: 'No published result for this exam number in ' + p.term + ' yet. This check was not counted.' };
  if (!await st.usePin(serial, p, exam, now)) return { s: 409, e: 'Please try again.' };
  return { s: 200, d: { name: u.name, cls: r.cls || '', term: p.term, session: r.session, tn: r.tn, rows: r.rows || [], remark: r.remark || '', pos: r.pos || 0, outOf: r.outOf || 0, left: p.max - p.uses - 1 } };
}

/* ---- Firestore REST ---- */
const fv = v => typeof v === 'string' ? { stringValue: v } : typeof v === 'boolean' ? { booleanValue: v } : Number.isInteger(v) ? { integerValue: String(v) } : typeof v === 'number' ? { doubleValue: v } : Array.isArray(v) ? { arrayValue: { values: v.map(fv) } } : { mapValue: { fields: Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fv(x)])) } };
const uv = v => 'stringValue' in v ? v.stringValue : 'booleanValue' in v ? v.booleanValue : 'integerValue' in v ? +v.integerValue : 'doubleValue' in v ? v.doubleValue : 'arrayValue' in v ? (v.arrayValue.values || []).map(uv) : 'mapValue' in v ? ff(v.mapValue.fields) : null;
const ff = f => Object.fromEntries(Object.entries(f || {}).map(([k, v]) => [k, uv(v)]));
const b64 = s => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
let tok = { t: '', x: 0 };
async function token(env) {
  if (tok.x > Date.now() + 60e3) return tok.t;
  const n = Math.floor(Date.now() / 1000);
  const head = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const body = b64(JSON.stringify({ iss: env.FB_EMAIL, scope: 'https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: n, exp: n + 3600 }));
  const pem = env.FB_KEY.replace(/\\n/g, '\n').replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), c => c.charCodeAt(0)), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(head + '.' + body)));
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=' + head + '.' + body + '.' + b64(String.fromCharCode(...sig)) });
  const j = await r.json();
  if (!j.access_token) throw new Error('auth');
  tok = { t: j.access_token, x: Date.now() + 3500e3 };
  return tok.t;
}
function fsStore(env) {
  const root = 'projects/' + env.FB_PROJECT + '/databases/(default)/documents', base = 'https://firestore.googleapis.com/v1/' + root;
  const call = async (url, method, body) => {
    const r = await fetch(url, { method, headers: { authorization: 'Bearer ' + await token(env), 'content-type': 'application/json' }, body: body && JSON.stringify(body) });
    return r;
  };
  const get = async path => { const r = await call(base + '/' + path, 'GET'); if (r.status === 404) return null; if (!r.ok) throw new Error('db'); const d = await r.json(); return { f: ff(d.fields), ut: d.updateTime }; };
  return {
    async getGuard(id) { const d = await get('guard/' + id); return d && d.f; },
    async setGuard(id, v) { await call(base + ':commit', 'POST', { writes: [{ update: { name: root + '/guard/' + id, fields: { n: fv(v.n), t: fv(v.t) } } }] }); },
    async getPin(id) { const d = await get('pins/' + id); if (!d) return null; d.f.__ut = d.ut; return d.f; },
    async getCurrent() { const d = await get('meta/current'); return d && d.f; },
    async getStudent(exam) {
      const r = await call(base + ':runQuery', 'POST', { structuredQuery: { from: [{ collectionId: 'users' }], where: { fieldFilter: { field: { fieldPath: 'exam' }, op: 'EQUAL', value: { stringValue: exam } } }, limit: 5 } });
      if (!r.ok) throw new Error('db');
      for (const x of await r.json()) if (x.document) { const f = ff(x.document.fields); if (f.role === 'student') return { uid: x.document.name.split('/').pop(), name: f.name }; }
      return null;
    },
    async getResult(id) { const d = await get('results/' + id); return d && d.f; },
    async usePin(serial, p, exam, now) {
      const first = p.first || now;
      const r = await call(base + ':commit', 'POST', { writes: [{ update: { name: root + '/pins/' + serial, fields: { exam: fv(exam), uses: fv(p.uses + 1), first: fv(first), last: fv(now) } }, updateMask: { fieldPaths: ['exam', 'uses', 'first', 'last'] }, currentDocument: { updateTime: p.__ut } }] });
      return r.ok;
    }
  };
}

export default {
  async fetch(req, env) {
    const H = { 'access-control-allow-origin': env.ALLOW_ORIGIN || '*', 'access-control-allow-headers': 'content-type', 'access-control-allow-methods': 'POST,OPTIONS', 'content-type': 'application/json' };
    const out = (s, b) => new Response(JSON.stringify(b), { status: s, headers: H });
    if (req.method === 'OPTIONS') return new Response(null, { headers: H });
    if (req.method !== 'POST' || new URL(req.url).pathname !== '/check') return out(404, { e: 'Not found' });
    let b; try { b = await req.json(); } catch (e) { return out(400, { e: 'Bad request' }); }
    try {
      const r = await check(fsStore(env), { ...b, ip: req.headers.get('cf-connecting-ip') || 'x' });
      return r.e ? out(r.s, { e: r.e }) : out(200, r.d);
    } catch (e) { return out(500, { e: 'Service error. Try again later.' }); }
  }
};
