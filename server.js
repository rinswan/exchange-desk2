'use strict';
/* Exchange Desk server: Express + SQLite. Server-side login, roles, shared data. */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

/* ---------- config (.env is read without extra packages) ---------- */
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(l);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
} catch (e) { /* no .env file: fine */ }
const PORT = +process.env.PORT || 3000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const COOKIE_SECURE = String(process.env.COOKIE_SECURE).toLowerCase() === 'true';
const ALLOW_SIGNUP = String(process.env.ALLOW_SIGNUP).toLowerCase() === 'true';
const AI_KEY = process.env.ANTHROPIC_API_KEY || '';
const AI_MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6';
const MIN_PW = 8;
fs.mkdirSync(DATA_DIR, { recursive: true });

/* ---------- database ---------- */
const db = new Database(path.join(DATA_DIR, 'desk.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, pw TEXT NOT NULL,
  role TEXT NOT NULL, off INTEGER NOT NULL DEFAULT 0, owner TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '', perm TEXT, last TEXT, hist TEXT NOT NULL DEFAULT '[]', created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, uid TEXT NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT NOT NULL, ver INTEGER NOT NULL, by TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS docs(col TEXT NOT NULL, id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY(col, id));
CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, name TEXT, mime TEXT, size INTEGER, owner TEXT, data BLOB, at TEXT);
`);

const ROLES = ['admin', 'user', 'tpladmin', 'tpluser'];
const ID_RE = /^[A-Za-z0-9._-]{3,40}$/;
const EM_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const now = () => new Date().toISOString();
const isTpl = r => String(r).startsWith('tpl');
const stable = v => JSON.stringify(v, (k, x) => (x && typeof x === 'object' && !Array.isArray(x))
  ? Object.keys(x).sort().reduce((o, key) => (o[key] = x[key], o), {}) : x);
const eq = (a, b) => stable(a) === stable(b);
const isObj = v => !!v && typeof v === 'object' && !Array.isArray(v);
const fail = (status, error) => { const e = new Error(error); e.status = status; throw e; };

const pub = u => {
  const o = { id: u.id, name: u.name, email: u.email, role: u.role, off: !!u.off, owner: u.owner || '', phone: u.phone || '', last: u.last || null, hist: JSON.parse(u.hist || '[]') };
  if (u.perm) o.perm = JSON.parse(u.perm);
  return o;
};
function listFor(actor) {
  let rows;
  if (actor.role === 'admin') rows = db.prepare('SELECT * FROM users ORDER BY created, id').all();
  else if (actor.role === 'tpladmin') rows = db.prepare('SELECT * FROM users WHERE id = ? OR owner = ? ORDER BY created, id').all(actor.id, actor.id);
  else rows = db.prepare('SELECT * FROM users WHERE id = ?').all(actor.id);
  return rows.map(pub);
}
const countUsers = () => db.prepare('SELECT COUNT(*) n FROM users').get().n;
const activeAdmins = exceptId => db.prepare("SELECT COUNT(*) n FROM users WHERE role='admin' AND off=0 AND id<>?").get(exceptId || '').n;
const hashPw = pw => bcrypt.hash(pw, 12);
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 12);

async function createUser({ id, name, email, pw, role, owner, phone, off, perm }) {
  id = String(id || '').trim().toLowerCase(); email = String(email || '').trim().toLowerCase();
  if (!ID_RE.test(id)) fail(400, 'User ID needs 3 or more characters: letters, numbers . _ - only.');
  if (!EM_RE.test(email)) fail(400, 'Enter a valid Email ID.');
  if (String(pw || '').length < MIN_PW) fail(400, 'Password needs at least ' + MIN_PW + ' characters.');
  if (!ROLES.includes(role)) fail(400, 'Unknown role.');
  if (db.prepare('SELECT 1 FROM users WHERE id = ?').get(id)) fail(409, 'That User ID is taken.');
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) fail(409, 'That Email ID is already used.');
  if (owner) { const o = db.prepare("SELECT role FROM users WHERE id = ?").get(owner); if (!o || o.role !== 'tpladmin') fail(400, 'Owner must be a 3PL Admin.'); }
  const h = await hashPw(pw);
  db.prepare('INSERT INTO users(id,name,email,pw,role,off,owner,phone,perm,created) VALUES(?,?,?,?,?,?,?,?,?,?)')
    .run(id, String(name || id).trim().slice(0, 80) || id, email, h, role, off ? 1 : 0, owner || '', String(phone || '').slice(0, 40), perm ? JSON.stringify(cleanPerm(perm)) : null, now());
  return id;
}
function cleanPerm(p) {
  const o = {};
  if (isObj(p)) Object.keys(p).slice(0, 40).forEach(k => { if (/^[A-Za-z0-9_]{1,30}$/.test(k)) o[k] = p[k] ? 1 : 0; });
  return o;
}

/* first Super Admin from environment, only when there are no users */
(async () => {
  if (countUsers() === 0 && process.env.ADMIN_ID && process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    try { await createUser({ id: process.env.ADMIN_ID, name: process.env.ADMIN_ID, email: process.env.ADMIN_EMAIL, pw: process.env.ADMIN_PASSWORD, role: 'admin' }); console.log('Created first Super Admin:', process.env.ADMIN_ID); }
    catch (e) { console.error('Could not create the first Super Admin:', e.message); }
  }
})();

/* ---------- sessions ---------- */
const SESSION_MS = 7 * 24 * 3600 * 1000;
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
function parseCookies(h) { const o = {}; String(h || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); }); return o; }
function setCookie(res, token, maxAgeMs) {
  res.append('Set-Cookie', 'ed_sid=' + encodeURIComponent(token) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + Math.floor(maxAgeMs / 1000) + (COOKIE_SECURE ? '; Secure' : ''));
}
function startSession(res, uid) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions(token,uid,exp) VALUES(?,?,?)').run(sha256(token), uid, Date.now() + SESSION_MS);
  setCookie(res, token, SESSION_MS);
}
function dropSessions(uid, exceptHash) { db.prepare('DELETE FROM sessions WHERE uid = ? AND token <> ?').run(uid, exceptHash || ''); }
setInterval(() => db.prepare('DELETE FROM sessions WHERE exp < ?').run(Date.now()), 3600e3).unref();

/* ---------- login throttling ---------- */
const attempts = new Map();
const blocked = k => { const r = attempts.get(k); if (!r) return false; if (Date.now() > r.until) { attempts.delete(k); return false; } return r.n >= 10; };
const strike = k => { const r = attempts.get(k) || { n: 0, until: 0 }; r.n++; r.until = Date.now() + 15 * 60e3; attempts.set(k, r); };

/* ---------- app ---------- */
const app = express();
if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY === 'true' ? 1 : process.env.TRUST_PROXY);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  });
  if (COOKIE_SECURE) res.set('Strict-Transport-Security', 'max-age=31536000');
  next();
});
app.get('/healthz', (req, res) => res.json({ ok: true }));
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    if (req.get('X-Requested-With') !== 'ed') return res.status(403).json({ error: 'Blocked request.' });
    const o = req.get('Origin');
    if (o) { try { if (new URL(o).host !== req.get('Host')) return res.status(403).json({ error: 'Blocked request.' }); } catch (e) { return res.status(403).json({ error: 'Blocked request.' }); } }
  }
  next();
});
app.post('/api/assets', express.raw({ type: () => true, limit: '11mb' }));
app.use('/api', express.json({ limit: '12mb' }));

const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
function auth(req, res, next) {
  const tok = parseCookies(req.headers.cookie).ed_sid;
  if (!tok) return res.status(401).json({ error: 'Please sign in.' });
  const h = sha256(tok);
  const s = db.prepare('SELECT * FROM sessions WHERE token = ?').get(h);
  if (!s || s.exp < Date.now()) return res.status(401).json({ error: 'Please sign in.' });
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(s.uid);
  if (!u || u.off) return res.status(401).json({ error: 'Please sign in.' });
  if (s.exp - Date.now() < SESSION_MS - 24 * 3600e3) { db.prepare('UPDATE sessions SET exp = ? WHERE token = ?').run(Date.now() + SESSION_MS, h); setCookie(res, tok, SESSION_MS); }
  req.user = u; req.sh = h; next();
}
const needAdmin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Super Admin only.' });

/* ---------- auth routes ---------- */
app.get('/api/status', (req, res) => {
  const has = countUsers() > 0;
  res.json({ hasUsers: has, signup: !has || ALLOW_SIGNUP, ai: !!AI_KEY });
});
const session = u => ({ user: pub(u), accounts: listFor(u), ai: !!AI_KEY });
app.post('/api/login', wrap(async (req, res) => {
  const id = String(req.body.id || '').trim().toLowerCase(), pw = String(req.body.pw || ''), group = req.body.group === 'tpl' ? 'tpl' : 'staff';
  const key = req.ip + ':' + id;
  if (blocked(key)) fail(429, 'Too many attempts. Try again in 15 minutes.');
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  const ok = await bcrypt.compare(pw, u ? u.pw : DUMMY_HASH);
  const hist = (okv) => { if (!u) return; const h = [{ at: now(), ok: okv }, ...JSON.parse(u.hist || '[]')].slice(0, 15); db.prepare('UPDATE users SET hist = ?, last = CASE WHEN ? THEN ? ELSE last END WHERE id = ?').run(JSON.stringify(h), okv ? 1 : 0, now(), u.id); };
  if (!u || !ok) { strike(key); hist(0); fail(401, 'User ID or password is not correct.'); }
  if (u.off) fail(403, 'This account is deactivated. Contact the Super Admin.');
  if (isTpl(u.role) !== (group === 'tpl')) fail(400, 'This account belongs to the other login type. Change "Login as" and try again.');
  attempts.delete(key); hist(1);
  startSession(res, u.id);
  res.json(session(db.prepare('SELECT * FROM users WHERE id = ?').get(u.id)));
}));
app.post('/api/logout', (req, res) => {
  const tok = parseCookies(req.headers.cookie).ed_sid;
  if (tok) db.prepare('DELETE FROM sessions WHERE token = ?').run(sha256(tok));
  setCookie(res, '', 0); res.json({ ok: true });
});
app.post('/api/signup', wrap(async (req, res) => {
  const first = countUsers() === 0;
  if (!first && !ALLOW_SIGNUP) fail(403, 'Sign-up is closed. Ask the Super Admin to create your account.');
  const key = 'signup:' + req.ip;
  if (blocked(key)) fail(429, 'Too many attempts. Try again later.');
  strike(key);
  await createUser({ id: req.body.id, name: req.body.id, email: req.body.email, pw: req.body.pw, role: first ? 'admin' : 'user' });
  res.json({ ok: true });
}));
app.get('/api/me', auth, (req, res) => res.json(session(req.user)));

/* ---------- accounts: patch-based, permission-checked ---------- */
app.get('/api/accounts', auth, (req, res) => res.json({ accounts: listFor(req.user) }));
app.put('/api/accounts', auth, wrap(async (req, res) => {
  const actor = req.user, isAdmin = actor.role === 'admin';
  const patches = Array.isArray(req.body.patches) ? req.body.patches.slice(0, 200) : [];
  const dels = Array.isArray(req.body.del) ? req.body.del.slice(0, 200).map(String) : [];
  const visible = new Set(listFor(actor).map(a => a.id));
  const mayManage = e => isAdmin || (actor.role === 'tpladmin' && isTpl(e.role) && (e.id === actor.id || e.owner === actor.id));
  const pwUpdates = [];
  const apply = db.transaction(() => {
    for (const p of patches) {
      const id = String(p.id || '').toLowerCase();
      if (p.create) continue; // creation is async (bcrypt): handled below
      const e = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
      if (!e || !visible.has(id)) fail(403, 'You cannot change that account.');
      const self = e.id === actor.id, manage = mayManage(e), prof = self || manage;
      const set = {};
      if ('name' in p && p.name !== e.name) { if (!prof) fail(403, 'You cannot change that account.'); const n = String(p.name || '').trim().slice(0, 80); if (!n) fail(400, 'Enter your name.'); set.name = n; }
      if ('email' in p && String(p.email).toLowerCase() !== e.email) {
        if (!prof) fail(403, 'You cannot change that account.');
        const em = String(p.email || '').trim().toLowerCase();
        if (!EM_RE.test(em)) fail(400, 'Enter a valid, unused Email ID.');
        if (db.prepare('SELECT 1 FROM users WHERE email = ? AND id <> ?').get(em, e.id)) fail(409, 'That Email ID is already used.');
        set.email = em;
      }
      if ('phone' in p && (p.phone || '') !== (e.phone || '')) { if (!prof) fail(403, 'You cannot change that account.'); set.phone = String(p.phone || '').trim().slice(0, 40); }
      if ('role' in p && p.role !== e.role) {
        if (!isAdmin || self) fail(403, 'Only the Super Admin can change roles, and not their own.');
        if (!ROLES.includes(p.role)) fail(400, 'Unknown role.');
        if (e.role === 'admin' && activeAdmins(e.id) < 1) fail(400, 'Keep at least one Admin.');
        set.role = p.role;
      }
      if ('off' in p && !!p.off !== !!e.off) {
        if (!isAdmin || self) fail(403, 'Only the Super Admin can do that, and not for themselves.');
        if (p.off && e.role === 'admin' && activeAdmins(e.id) < 1) fail(400, 'Keep at least one active Super Admin.');
        set.off = p.off ? 1 : 0;
      }
      if ('owner' in p && (p.owner || '') !== (e.owner || '')) {
        if (!isAdmin) fail(403, 'Only the Super Admin can do that.');
        const ow = String(p.owner || '');
        if (ow && !(db.prepare("SELECT 1 FROM users WHERE id = ? AND role='tpladmin'").get(ow))) fail(400, 'Owner must be a 3PL Admin.');
        set.owner = ow;
      }
      if ('perm' in p) {
        const np = p.perm ? JSON.stringify(cleanPerm(p.perm)) : null;
        if (np !== (e.perm || null)) { if (!isAdmin || self) fail(403, 'Only the Super Admin can change access, and not their own.'); set.perm = np; }
      }
      if (p.newpw) {
        if (!prof) fail(403, 'You cannot change that account.');
        if (String(p.newpw).length < MIN_PW) fail(400, 'New password needs at least ' + MIN_PW + ' characters.');
        pwUpdates.push({ id: e.id, pw: String(p.newpw), self });
      }
      const cols = Object.keys(set);
      if (cols.length) db.prepare('UPDATE users SET ' + cols.map(c => c + ' = ?').join(', ') + ' WHERE id = ?').run(...cols.map(c => set[c]), e.id);
      if (set.off || set.role) dropSessions(e.id);
    }
    for (const id0 of dels) {
      const id = id0.toLowerCase();
      const e = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
      if (!e) continue;
      const ok = e.id !== actor.id && e.role !== 'admin' && (isAdmin || (actor.role === 'tpladmin' && e.role === 'tpluser' && e.owner === actor.id));
      if (!ok) fail(403, 'You cannot remove that account.');
      db.prepare('DELETE FROM sessions WHERE uid = ?').run(e.id);
      db.prepare('DELETE FROM users WHERE id = ?').run(e.id);
    }
  });
  apply();
  for (const u of pwUpdates) {
    db.prepare('UPDATE users SET pw = ? WHERE id = ?').run(await hashPw(u.pw), u.id);
    dropSessions(u.id, u.self ? req.sh : '');
  }
  for (const p of patches) {
    if (!p.create) continue;
    const role = String(p.role || '');
    const allowed = isAdmin || (actor.role === 'tpladmin' && role === 'tpluser');
    if (!allowed) fail(403, 'You cannot add that kind of account.');
    await createUser({ id: p.id, name: p.name, email: p.email, pw: p.newpw, role, owner: actor.role === 'tpladmin' ? actor.id : (p.owner || ''), phone: p.phone, off: isAdmin ? p.off : 0, perm: isAdmin ? p.perm : null });
  }
  res.json({ accounts: listFor(db.prepare('SELECT * FROM users WHERE id = ?').get(actor.id)) });
}));

/* ---------- shared data (key/value with three-way merge) ---------- */
const KEY_RE = /^desk:(v3|v3:tpl(?::([A-Za-z0-9._-]*))?|lbl|lbl:tpl|perm|perm3)$/;
function keyAccess(u, key) {
  const m = KEY_RE.exec(key);
  if (!m) return { r: false, w: false };
  const k = m[1];
  if (k === 'v3') { const ok = u.role === 'admin' || u.role === 'user'; return { r: ok, w: ok }; }
  if (k.startsWith('v3:tpl')) {
    const g = m[2] || '';
    if (u.role === 'admin') return { r: true, w: true };
    if (u.role === 'tpladmin') { const ok = g === u.id; return { r: ok, w: ok }; }
    if (u.role === 'tpluser') { const ok = g === (u.owner || ''); return { r: ok, w: ok }; }
    return { r: false, w: false };
  }
  if (k === 'perm3') return { r: true, w: u.role === 'admin' || u.role === 'tpladmin' };
  return { r: true, w: u.role === 'admin' }; // lbl, lbl:tpl, perm
}
const byId = a => Array.isArray(a) && a.every(x => isObj(x) && x.id !== undefined && x.id !== null);
function merge3(base, cur, mine) {
  if (eq(mine, base)) return cur;
  if (eq(cur, base)) return mine;
  if (eq(mine, cur)) return mine;
  if (isObj(base) && isObj(cur) && isObj(mine)) {
    const out = {};
    for (const k of new Set([...Object.keys(base), ...Object.keys(cur), ...Object.keys(mine)])) {
      const hb = k in base, hc = k in cur, hm = k in mine;
      if (!hm) { if (hb) { if (hc && !eq(cur[k], base[k])) out[k] = cur[k]; } else if (hc) out[k] = cur[k]; continue; }
      if (!hc) { if (hb) { if (!eq(mine[k], base[k])) out[k] = mine[k]; } else out[k] = mine[k]; continue; }
      out[k] = hb ? merge3(base[k], cur[k], mine[k]) : (isObj(cur[k]) && isObj(mine[k]) ? merge3({}, cur[k], mine[k]) : mine[k]);
    }
    return out;
  }
  if (Array.isArray(base) && Array.isArray(cur) && Array.isArray(mine)) {
    if (byId(base) && byId(cur) && byId(mine)) {
      const B = new Map(base.map(x => [String(x.id), x])), M = new Map(mine.map(x => [String(x.id), x])), seen = new Set(), out = [];
      for (const x of cur) {
        const id = String(x.id); seen.add(id);
        if (M.has(id)) out.push(B.has(id) ? merge3(B.get(id), x, M.get(id)) : (isObj(x) ? merge3({}, x, M.get(id)) : M.get(id)));
        else if (!B.has(id) || !eq(B.get(id), x)) out.push(x);
      }
      for (const x of mine) { const id = String(x.id); if (!seen.has(id) && (!B.has(id) || !eq(B.get(id), x))) out.push(x); }
      return out;
    }
    if (base.length === cur.length && cur.length === mine.length) return base.map((b, i) => merge3(b, cur[i], mine[i]));
  }
  return mine;
}
function visibleKeys(u) { return db.prepare('SELECT key, ver FROM kv').all().filter(r => keyAccess(u, r.key).r); }
app.get('/api/kv/vers', auth, (req, res) => {
  const vers = {}; visibleKeys(req.user).forEach(r => { vers[r.key] = r.ver; }); res.json({ vers });
});
app.get('/api/kv', auth, (req, res) => {
  const want = req.query.keys ? new Set(String(req.query.keys).split(',')) : null;
  const kv = {};
  db.prepare('SELECT key, value, ver FROM kv').all().forEach(r => { if ((!want || want.has(r.key)) && keyAccess(req.user, r.key).r) kv[r.key] = { v: r.value, ver: r.ver }; });
  res.json({ kv });
});
app.put('/api/kv', auth, (req, res) => {
  const { key, value, base, baseVer } = req.body || {};
  if (typeof key !== 'string' || typeof value !== 'string') fail(400, 'Bad request.');
  if (!keyAccess(req.user, key).w) fail(403, 'You cannot change that data.');
  let mine; try { mine = JSON.parse(value); } catch (e) { fail(400, 'Bad data.'); }
  const out = db.transaction(() => {
    const cur = db.prepare('SELECT * FROM kv WHERE key = ?').get(key);
    if (!cur) { db.prepare('INSERT INTO kv(key,value,ver,by,at) VALUES(?,?,?,?,?)').run(key, value, 1, req.user.id, now()); return { value, ver: 1 }; }
    let next = value;
    if (+baseVer !== cur.ver) {
      let b = null; try { b = typeof base === 'string' ? JSON.parse(base) : null; } catch (e) { b = null; }
      if (b !== null) { const merged = merge3(b, JSON.parse(cur.value), mine); next = eq(merged, mine) ? value : JSON.stringify(merged); }
    }
    if (next === cur.value) return { value: next, ver: cur.ver };
    db.prepare('UPDATE kv SET value = ?, ver = ?, by = ?, at = ? WHERE key = ?').run(next, cur.ver + 1, req.user.id, now(), key);
    return { value: next, ver: cur.ver + 1 };
  })();
  res.json(out);
});

/* ---------- document collections (tickets, labels) ---------- */
const COLS = new Set(['tickets', 'tmeta', 'treplies', 'tlog', 'resolutions', 'settings']);
const DOC_ID = /^[A-Za-z0-9._-]{1,80}$/;
const myTicketIds = u => new Set(db.prepare("SELECT id, json FROM docs WHERE col='tickets'").all().filter(r => { try { return JSON.parse(r.json).by === u.id; } catch (e) { return false; } }).map(r => r.id));
app.get('/api/db/:col', auth, (req, res) => {
  const c = req.params.col; if (!COLS.has(c)) fail(404, 'Unknown collection.');
  let rows = db.prepare('SELECT id, json FROM docs WHERE col = ?').all(c).map(r => ({ id: r.id, data: JSON.parse(r.json) }));
  if (req.user.role !== 'admin' && c !== 'settings') {
    const mine = myTicketIds(req.user);
    rows = rows.filter(r => c === 'tickets' ? r.data.by === req.user.id : (c === 'tmeta' || c === 'resolutions') ? mine.has(r.id) : mine.has(r.data.tid));
  }
  res.json({ docs: rows });
});
app.put('/api/db/:col/:id', auth, (req, res) => {
  const { col, id } = req.params, u = req.user, admin = u.role === 'admin';
  if (!COLS.has(col) || !DOC_ID.test(id)) fail(404, 'Unknown document.');
  const data = req.body; if (!isObj(data)) fail(400, 'Bad data.');
  if (JSON.stringify(data).length > 400000) fail(413, 'Too large.');
  const existing = db.prepare('SELECT json FROM docs WHERE col = ? AND id = ?').get(col, id);
  if (!admin) {
    const mine = myTicketIds(u);
    if (col === 'tickets') { if (existing || data.by !== u.id) fail(403, 'Not allowed.'); data.role = u.role; data.id = id; }
    else if (col === 'tmeta') { if (!mine.has(id)) fail(403, 'Not allowed.'); if (existing) { const o = JSON.parse(existing.json); data.asg = o.asg; data.status = (data.status === 'Closed' || data.status === 'Open' || data.status === o.status) ? data.status : o.status; } else { data.asg = ''; data.status = 'Open'; } }
    else if (col === 'treplies' || col === 'tlog') { if (!mine.has(data.tid) || existing) fail(403, 'Not allowed.'); }
    else fail(403, 'Not allowed.');
  }
  db.prepare('INSERT INTO docs(col,id,json) VALUES(?,?,?) ON CONFLICT(col,id) DO UPDATE SET json = excluded.json').run(col, id, JSON.stringify(data));
  res.json({ ok: true });
});
app.delete('/api/db/:col/:id', auth, needAdmin, (req, res) => {
  const { col, id } = req.params; if (!COLS.has(col)) fail(404, 'Unknown collection.');
  db.prepare('DELETE FROM docs WHERE col = ? AND id = ?').run(col, id); res.json({ ok: true });
});

/* ---------- file attachments ---------- */
const MIMES = { 'image/png': 'inline', 'image/jpeg': 'inline', 'image/webp': 'inline', 'image/gif': 'inline', 'application/pdf': 'inline', 'text/plain': 'attachment', 'text/csv': 'attachment' };
app.post('/api/assets', auth, (req, res) => {
  const mime = String(req.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  if (!(mime in MIMES)) fail(415, 'Only PNG, JPG, WebP, GIF, PDF, TXT or CSV files are allowed.');
  if (!Buffer.isBuffer(req.body) || !req.body.length) fail(400, 'Empty file.');
  if (req.body.length > 10 * 1024 * 1024) fail(413, 'File too large.');
  const id = crypto.randomBytes(16).toString('hex');
  let name = 'file'; try { name = decodeURIComponent(req.get('X-Filename') || 'file'); } catch (e) { /* keep */ }
  name = name.replace(/[\r\n"\\\/]/g, '_').slice(0, 120);
  db.prepare('INSERT INTO files(id,name,mime,size,owner,data,at) VALUES(?,?,?,?,?,?,?)').run(id, name, mime, req.body.length, req.user.id, req.body, now());
  res.json({ url: '/_blob/' + id });
});
app.delete('/api/assets/:id', auth, (req, res) => {
  const f = db.prepare('SELECT owner FROM files WHERE id = ?').get(req.params.id);
  if (f && (f.owner === req.user.id || req.user.role === 'admin')) db.prepare('DELETE FROM files WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});
app.get('/_blob/:id', auth, (req, res) => {
  const f = /^[0-9a-f]{32}$/.test(req.params.id) && db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!f || (f.owner !== req.user.id && req.user.role !== 'admin')) return res.status(404).end();
  res.set({ 'Content-Type': f.mime, 'Content-Disposition': MIMES[f.mime] + '; filename="' + f.name.replace(/[^\x20-\x7e]/g, '_') + '"', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; sandbox", 'Cache-Control': 'private, max-age=3600' });
  res.send(f.data);
});

/* ---------- AI assistant (Super Admin, optional) ---------- */
app.post('/api/ai', auth, needAdmin, wrap(async (req, res) => {
  if (!AI_KEY) fail(501, 'AI is not set up on the server.');
  const content = String(req.body.content || '').slice(0, 60000);
  if (!content) fail(400, 'Empty question.');
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': AI_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: AI_MODEL, max_tokens: 1000, messages: [{ role: 'user', content }] })
  });
  if (r.status === 429) fail(429, 'Too many requests.');
  if (!r.ok) fail(502, 'The AI request failed.');
  const j = await r.json();
  res.json({ text: (j.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n') });
}));

/* ---------- static site + errors ---------- */
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: 0 }));
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Too large.' });
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status >= 500 ? 'Server error.' : err.message });
});
app.listen(PORT, () => console.log('Exchange Desk running on http://localhost:' + PORT));
