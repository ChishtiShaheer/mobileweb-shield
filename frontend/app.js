'use strict';
const $ = s => document.querySelector(s);
const enc = new TextEncoder(), dec = new TextDecoder();
let csrf = null, user = null;
const uid = () => crypto.randomUUID();
const store = (k, v) => v === undefined ? JSON.parse(localStorage.getItem(k + user) || '[]') : localStorage.setItem(k + user, JSON.stringify(v));

function say(msg, bad) { const s = $('#status'); s.textContent = msg; s.className = bad ? 'bad' : 'ok'; }
function li(parent, text, ...btns) { const e = document.createElement('li'); e.append(text + ' '); btns.forEach(b => e.append(b)); parent.append(e); }
function btn(label, fn) { const b = document.createElement('button'); b.textContent = label; b.onclick = fn; return b; }

async function api(path, method = 'GET', body) {
  const h = {'Content-Type': 'application/json'}; if (csrf) h['X-CSRF-Token'] = csrf;
  const r = await fetch('/api' + path, {method, headers: h, body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin'});
  const t = (r.headers.get('content-type') || '').includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw Object.assign(new Error(t.error ? t.error.message : 'Request failed'), {code: t.error && t.error.code, status: r.status});
  return t;
}
const guard = fn => async (...a) => { try { await fn(...a); } catch (e) { say(e.code ? `${e.code}: ${e.message}` : 'Network unavailable (changes stay queued)', true); if (e.status === 401 && user) setUser(null); } };

// ----- Web Crypto: PBKDF2 -> AES-GCM-256 -----
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function deriveKey(pass, salt) {
  const m = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256'}, m, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']);
}
async function encrypt(pass, text) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, await deriveKey(pass, salt), enc.encode(text));
  return {iv: b64(iv) + '.' + b64(salt), ct: b64(ct)};   // "iv" field holds "iv.salt"
}
async function decrypt(pass, ivs, ct) {
  const [iv, salt] = ivs.split('.').map(unb64);
  return dec.decode(await crypto.subtle.decrypt({name: 'AES-GCM', iv}, await deriveKey(pass, salt), unb64(ct)));
}

// ----- UI state -----
function setUser(u) {
  user = u && u.username; csrf = u && u.csrf;
  $('#who').textContent = u ? `${u.username} (${u.role})` : 'Signed out';
  $('#logout').hidden = !u; $('#p-login').hidden = !!u;
  const role = u && u.role;
  $('#p-notes').hidden = !['admin', 'analyst'].includes(role); $('#p-tools').hidden = $('#p-notes').hidden;
  $('#p-sess').hidden = !u; $('#p-report').hidden = !u; $('#p-admin').hidden = role !== 'admin';
  if (u) renderNotes();
}
function net() { const o = navigator.onLine; $('#net').textContent = o ? 'online' : 'offline'; if (o && user) flush(); }
addEventListener('online', net); addEventListener('offline', net);

// ----- Login -----
$('#login').onclick = guard(async () => {
  const r = await api('/auth/login', 'POST', {username: $('#u').value, password: $('#p').value});
  $('#p').value = ''; setUser({...r.user, csrf: r.csrf}); say('Logged in'); flush();
});
$('#logout').onclick = guard(async () => { await api('/auth/logout', 'POST'); setUser(null); say('Logged out'); });

// ----- Notes + offline queue -----
function renderNotes() {
  const ul = $('#notes'); ul.replaceChildren(); $('#qlen').textContent = store('queue').length;
  for (const n of store('notes')) {
    const status = n.conflict ? `CONFLICT (server v${n.conflict})` : n.error ? `REJECTED ${n.error}` : n.pending ? 'pending' : 'synced';
    const items = [btn('Decrypt', guard(async () => { $('#opened').textContent = await decrypt($('#pass').value, n.iv, n.ct); }))];
    if (n.conflict) items.push(btn('Overwrite server with mine', () => { queueOp(n, n.conflict); flush(); }));
    li(ul, `[${n.tag || 'no tag'}] v${n.version} - ${status}`, ...items);
  }
}
function queueOp(n, base) {
  const q = store('queue').filter(o => o.lid !== n.lid);
  q.push({op_id: uid(), lid: n.lid, note_id: n.id, base_version: base, iv: n.iv, ct: n.ct, tag: n.tag || null});
  n.pending = true; n.conflict = null; n.error = null; store('queue', q); persist(n);
}
function persist(n) { const l = store('notes').filter(x => x.lid !== n.lid); l.unshift(n); store('notes', l); renderNotes(); }
$('#save').onclick = guard(async () => {
  if (!$('#pass').value || !$('#body').value) throw Object.assign(new Error('Passphrase and note text required'), {code: 'LOCAL'});
  const e = await encrypt($('#pass').value, $('#body').value);
  queueOp({lid: uid(), id: null, version: 0, iv: e.iv, ct: e.ct, tag: $('#tag').value}, 0);
  $('#body').value = ''; say('Saved locally (encrypted) and queued'); await flush();
});
async function flush() {
  const q = store('queue'); if (!q.length || !navigator.onLine) { renderNotes(); return; }
  const {results} = await api('/notes/sync', 'POST', {ops: q.slice(0, 50).map(({lid, ...o}) => o)});
  const notes = store('notes');
  results.forEach((r, i) => {
    const n = notes.find(x => x.lid === q[i].lid); if (!n) return;
    n.pending = false;
    if (r.status === 'applied' || r.status === 'duplicate') { n.id = r.note_id; n.version = r.version; }
    else if (r.status === 'conflict') n.conflict = r.version; else n.error = r.code;
  });
  store('notes', notes); store('queue', q.slice(results.length));
  say(results.map(r => r.status).join(', ') || 'Nothing to sync'); renderNotes();
}
$('#sync').onclick = guard(flush);

// ----- Sessions -----
const loadSessions = guard(async () => {
  const r = await api('/sessions'); const ul = $('#sessions'); ul.replaceChildren();
  for (const s of r.sessions) {
    const st = s.revoked_at ? `revoked (${s.revoke_reason})` : 'active';
    li(ul, `${s.username} | ${s.ip} | ${(s.ua || '').slice(0, 40)} | ${st}${s.id === r.current ? ' | THIS SESSION' : ''}`,
      ...(s.revoked_at ? [] : [btn('Revoke', guard(async () => { await api(`/sessions/${s.id}/revoke`, 'POST'); say('Session revoked'); loadSessions(); }))]));
  }
});
$('#rsess').onclick = loadSessions;
$('#lost').onclick = guard(async () => { const r = await api('/device-loss', 'POST', {}); say(`${r.sessions_revoked} session(s) revoked`); setUser(null); });

// ----- Tools -----
const show = (id, o) => { $(id).textContent = JSON.stringify(o, null, 2); };
$('#rsim').onclick = guard(async () => { const me = await api('/auth/me'); show('#toolout', await api('/risk/simulate', 'POST', {session_id: me.session_id, user_agent: $('#rua').value, ip: $('#rip').value})); });
$('#cver').onclick = guard(async () => show('#toolout', await api('/cache-policy/verify', 'POST', {path: $('#cp').value, sha256: $('#ch').value})));

// ----- Admin -----
$('#setthr').onclick = guard(async () => { show('#adminout', await api('/admin/settings', 'PUT', {risk_threshold: +$('#thr').value})); say('Threshold updated (audited)'); });
$('#raudit').onclick = guard(async () => {
  const r = await api('/audit?limit=100'); const tb = $('#audit'); tb.replaceChildren();
  for (const e of r.events) {
    const tr = document.createElement('tr');
    [e.id, e.actor, e.action, e.outcome, e.detail].forEach(v => { const td = document.createElement('td'); td.textContent = v; tr.append(td); });
    const td = document.createElement('td'); td.append(btn('Explain', guard(async () => { const x = await api('/explain', 'POST', {event_id: e.id}); $('#adminout').textContent = `[${x.source}] ${x.text}`; })));
    tr.append(td); tb.append(tr);
  }
});
$('#vaudit').onclick = guard(async () => show('#adminout', await api('/audit/verify')));
$('#rrep').onclick = guard(async () => show('#repout', await api('/report')));

// ----- Boot -----
(async () => {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => say('Service worker not installed (integrity check or no network)', true));
  try { const m = await api('/auth/me'); setUser({...m.user, csrf: m.csrf}); const s = await api('/admin/settings').catch(() => null); if (s) $('#thr').value = s.risk_threshold; } catch (e) { /* signed out */ }
  net();
})();
