// Update policy: cache only allowlisted assets whose SHA-256 matches the server manifest. /api is never cached.
const PREFIX = 'mws-';
self.addEventListener('install', e => e.waitUntil((async () => {
  const m = await (await fetch('/api/cache-policy', {cache: 'no-store'})).json();
  const cache = await caches.open(PREFIX + m.version);
  for (const [path, expected] of Object.entries(m.assets)) {
    const r = await fetch(path, {cache: 'reload'});
    const d = await crypto.subtle.digest('SHA-256', await r.clone().arrayBuffer());
    const hex = [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
    if (!r.ok || hex !== expected) throw new Error('Integrity check failed: ' + path);
    await cache.put(path, r);
  }
  await self.skipWaiting();
})()));
self.addEventListener('activate', e => e.waitUntil((async () => {
  for (const k of await caches.keys()) {
    if (k.startsWith(PREFIX)) { const m = await (await fetch('/api/cache-policy', {cache: 'no-store'}).catch(() => null))?.json?.(); if (m && k !== PREFIX + m.version) await caches.delete(k); }
  }
  await self.clients.claim();
})()));
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api')) return;
  e.respondWith(caches.match(u.pathname).then(hit => hit || fetch(e.request)));
});
