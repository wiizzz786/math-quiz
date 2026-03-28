/* void-sw.js — Void Proxy Service Worker
   Intercepts network requests (import(), CSS @import, fonts, etc.)
   that client-side overrides can't catch, and routes them through
   the CORS proxy. */

var CFG = { proxy: '', origin: '', cookies: {} };

var VOID_PATHS = new Set([
  '/', '/void.html', '/void-admin.html', '/void-sw.js',
  '/server.js', '/worker.js', '/favicon.ico', '/index.html',
  '/package.json', '/wrangler.toml', '/package-lock.json'
]);

self.addEventListener('install', function() { self.skipWaiting(); });
self.addEventListener('activate', function(e) { e.waitUntil(self.clients.claim()); });

self.addEventListener('message', function(e) {
  if (!e.data) return;
  if (e.data.type === 'void-sw-config') {
    CFG.proxy = (e.data.proxy || '').replace(/\/+$/, '');
    CFG.origin = (e.data.origin || '').replace(/\/+$/, '');
    if (e.data.cookies) CFG.cookies = e.data.cookies;
    if (e.ports && e.ports[0]) e.ports[0].postMessage('ack');
  }
  if (e.data.type === 'void-sw-cookies') {
    CFG.cookies = e.data.cookies || {};
  }
});

function makeProxyUrl(target) {
  var p = CFG.proxy;
  if (p.indexOf('?') >= 0) return p + encodeURIComponent(target);
  return p + '?url=' + encodeURIComponent(target);
}

function getCookies(url) {
  try {
    var h = new URL(url).hostname, parts = [];
    for (var d in CFG.cookies) {
      if (h === d || h.endsWith('.' + d)) {
        for (var n in CFG.cookies[d]) parts.push(n + '=' + CFG.cookies[d][n]);
      }
    }
    return parts.join('; ');
  } catch(e) { return ''; }
}

self.addEventListener('fetch', function(e) {
  if (!CFG.proxy || !CFG.origin) return;

  var u;
  try { u = new URL(e.request.url); } catch(x) { return; }

  if (e.request.url.indexOf(CFG.proxy) === 0) return;

  if (u.origin === self.location.origin) {
    if (VOID_PATHS.has(u.pathname)) return;
    if (u.pathname.startsWith('/node_modules/')) return;
    if (u.pathname.startsWith('/public/')) return;
    if (/^\/(void|admin|cards)/.test(u.pathname)) return;
  }

  var targetUrl;
  if (u.origin === self.location.origin) {
    targetUrl = CFG.origin + u.pathname + u.search;
  } else if (/^https?:$/.test(u.protocol)) {
    targetUrl = e.request.url;
  } else {
    return;
  }

  e.respondWith((async function() {
    try {
      var pxyUrl = makeProxyUrl(targetUrl);
      var h = new Headers();
      for (var pair of e.request.headers) {
        var k = pair[0].toLowerCase();
        if (k !== 'host' && k !== 'origin' && k !== 'referer') h.set(pair[0], pair[1]);
      }
      var ck = getCookies(targetUrl);
      if (ck) h.set('X-Void-Cookie', ck);

      var init = { method: e.request.method, headers: h, mode: 'cors' };
      if (e.request.method !== 'GET' && e.request.method !== 'HEAD') {
        try { init.body = await e.request.clone().arrayBuffer(); } catch(x) {}
      }

      var r = await fetch(pxyUrl, init);

      var rh = new Headers(r.headers);
      ['content-security-policy','content-security-policy-report-only','x-frame-options',
       'strict-transport-security','cross-origin-opener-policy','cross-origin-embedder-policy',
       'cross-origin-resource-policy','x-content-type-options'].forEach(function(k){ rh.delete(k); });

      var sc = r.headers.get('x-void-set-cookie');
      if (sc) {
        var cls = await self.clients.matchAll();
        cls.forEach(function(c) {
          c.postMessage({ type: 'void-sw-set-cookie', raw: sc, url: targetUrl });
        });
      }

      return new Response(r.body, { status: r.status, statusText: r.statusText, headers: rh });
    } catch(err) {
      return new Response('SW proxy error: ' + err.message, { status: 502 });
    }
  })());
});
