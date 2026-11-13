const CACHE = 'archangel-pwa-v6.7';
const SHELL = ['/manifest.webmanifest','/icons/icon.svg'];
self.addEventListener('install', event => { event.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL))); self.skipWaiting(); });
self.addEventListener('activate', event => { event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
// Never cache chat/API traffic, HTML containing session state, or user data.
self.addEventListener('fetch', event => {
  const u = new URL(event.request.url);
  if (u.origin !== self.location.origin || u.pathname.startsWith('/api/') || event.request.method !== 'GET') return;
  if (SHELL.includes(u.pathname)) event.respondWith(caches.match(event.request).then(hit => hit || fetch(event.request)));
});