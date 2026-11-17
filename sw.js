// ================================================================
// SAFEREACH SERVICE WORKER
// Makes the member app open and work without a connection:
//  - the app page, manifest and icons are stored on install
//  - Leaflet (map library) and fonts are stored the first time they load
//  - map tiles you have viewed are kept so the map still shows offline
//  - the page itself is fetched fresh whenever there is a connection,
//    so new deploys show up straight away
// API calls (SafeReach server, place search, weather) are never cached.
// ================================================================
'use strict';

// Change this string on every deploy that should replace the stored files.
const VERSION   = 'sr-2026-11-17e';
const APP_CACHE = VERSION + '-app';
const LIB_CACHE = 'sr-libs-v1';     // Leaflet + fonts (versioned URLs, safe to keep)
const TILE_CACHE = 'sr-tiles-v1';   // map tiles
const TILE_LIMIT = 600;

const APP_FILES = [
  './',
  './index.html',
  './manifest.json',
  './icon-96.png',
  './icon-192.png',
  './icon-512.png',
  './apple-touch-icon.png',
  './favicon.ico',
];
const LIB_FILES = [
  'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css',
  'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js',
];

// Never intercept these: live data must come from the network or fail visibly.
const NETWORK_ONLY = [
  'overpass-api.de', 'nominatim.openstreetmap.org', 'open-meteo.com',
  'api.anthropic.com', 'onrender.com', 'railway.app', 'app.github.dev',
];

self.addEventListener('install', e => {
  e.waitUntil((async () => {
    const app = await caches.open(APP_CACHE);
    await Promise.allSettled(APP_FILES.map(u =>
      fetch(u, { cache: 'reload' }).then(r => r.ok && app.put(u, r))));
    const libs = await caches.open(LIB_CACHE);
    await Promise.allSettled(LIB_FILES.map(async u => {
      if (await libs.match(u)) return;
      const r = await fetch(u, { mode: 'cors' });
      if (r.ok) await libs.put(u, r);
    }));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    const keep = [APP_CACHE, LIB_CACHE, TILE_CACHE];
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => !keep.includes(k)).map(k => caches.delete(k)));
    await self.clients.claim();
    const list = await self.clients.matchAll({ type: 'window' });
    list.forEach(c => { try { c.postMessage({ type: 'SW_UPDATED', deploy: VERSION }); } catch {} });
  })());
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (NETWORK_ONLY.some(h => url.hostname.endsWith(h))) return;

  // Map tiles: stored copy first, then network
  if (url.hostname === 'tile.openstreetmap.org') {
    e.respondWith(tile(req));
    return;
  }
  // Leaflet and Google Fonts: stored copy first, refreshed in the background
  if (url.hostname === 'unpkg.com' || url.hostname.endsWith('googleapis.com') || url.hostname.endsWith('gstatic.com')) {
    e.respondWith(staleWhileRevalidate(req, LIB_CACHE));
    return;
  }
  if (url.origin !== self.location.origin) return;

  // Same-origin: network first (fresh deploys), stored copy when offline
  e.respondWith(networkFirst(req));
});

async function networkFirst(req) {
  const isDoc = req.mode === 'navigate' || req.destination === 'document';
  const cache = await caches.open(APP_CACHE);
  try {
    const res = await fetch(req, isDoc ? { cache: 'no-store' } : {});
    if (res && res.ok) cache.put(req, res.clone());
    return res;
  } catch {
    const hit = await cache.match(req, { ignoreSearch: true });
    if (hit) return hit;
    if (isDoc) {
      // Opening the app offline (e.g. "./?action=sos") falls back to the app page
      const page = await cache.match('./index.html') || await cache.match('./');
      if (page) return page;
    }
    return new Response('Offline and this file was not saved yet.', {
      status: 503, headers: { 'Content-Type': 'text/plain' },
    });
  }
}

async function staleWhileRevalidate(req, name) {
  const cache = await caches.open(name);
  const hit = await cache.match(req);
  const net = fetch(req).then(res => {
    if (res && (res.ok || res.type === 'opaque')) cache.put(req, res.clone());
    return res;
  }).catch(() => null);
  return hit || (await net) || new Response('', { status: 503 });
}

async function tile(req) {
  const cache = await caches.open(TILE_CACHE);
  const hit = await cache.match(req);
  if (hit) return hit;
  try {
    const res = await fetch(req);
    if (res && (res.ok || res.type === 'opaque')) {
      await cache.put(req, res.clone());
      trimTiles(cache);
    }
    return res;
  } catch {
    return new Response('', { status: 503 });
  }
}

async function trimTiles(cache) {
  const keys = await cache.keys();
  if (keys.length <= TILE_LIMIT) return;
  await Promise.all(keys.slice(0, keys.length - TILE_LIMIT).map(k => cache.delete(k)));
}

// ── Background sync ────────────────────────────────────────────
self.addEventListener('sync', e => {
  if (e.tag === 'retry-search') {
    e.waitUntil(self.clients.matchAll({ type: 'window' })
      .then(list => list.forEach(c => c.postMessage({ type: 'BACK_ONLINE' }))));
  }
});

// ── Push notifications ─────────────────────────────────────────
self.addEventListener('push', e => {
  if (!e.data) return;
  let d = {};
  try { d = e.data.json(); } catch { d = { body: e.data.text() }; }
  e.waitUntil(self.registration.showNotification(d.title || 'SafeReach', {
    body: d.body || 'Emergency alert',
    icon: './icon-192.png',
    tag: 'safereach-alert',
    requireInteraction: !!d.urgent,
  }));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) {
      if (c.url.includes('index.html') || c.url.endsWith('/')) return c.focus();
    }
    return self.clients.openWindow('./index.html');
  }));
});

// ── Messages from the page ─────────────────────────────────────
self.addEventListener('message', e => {
  const type = e.data && e.data.type;
  if (type === 'SKIP_WAITING') self.skipWaiting();
  if (type === 'CLEAR_CACHES') {
    // Clears saved search results and tiles; the app files stay so it still opens offline
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== APP_CACHE && k !== LIB_CACHE).map(k => caches.delete(k))))
      .then(() => e.source && e.source.postMessage({ type: 'CACHES_CLEARED' }));
  }
  if (type === 'GET_VERSION') {
    e.source && e.source.postMessage({ type: 'VERSION_INFO', deploy: VERSION, hash: APP_CACHE });
  }
});
