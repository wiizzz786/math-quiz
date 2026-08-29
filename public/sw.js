const SKIP = /^(data:|blob:|javascript:|#|mailto:)/i;

let customTld = '.securly.com';
const urlParams = new URLSearchParams(self.location.search);
if (urlParams.has('tld')) {
  customTld = urlParams.get('tld');
}

function E(url) {
  try {
    let u = new URL(url).href;
    const key = "NoodalMathKey2026";
    const out = [];
    for (let i = 0; i < u.length; i++) {
      let k = key.charCodeAt(i % key.length);
      let code = u.charCodeAt(i) ^ k ^ ((i * 13 + 7) & 0xFF);
      out.push(String.fromCharCode(code));
    }
    return self.location.origin + '/p/' + btoa(out.join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '') + customTld;
  } catch(e) {
    return url;
  }
}

self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
  const req = event.request;
  const url = new URL(req.url);

  // If it's a same-origin request, let it pass natively
  if (url.origin === self.location.origin) {
    return; 
  }

  // Cross-origin request intercepted!
  event.respondWith((async () => {
    try {
      const encodedUrl = E(req.url);
      
      const headers = new Headers(req.headers);
      headers.set('x-void-dest', req.headers.get('sec-fetch-dest') || '');
      headers.set('x-void-mode', req.headers.get('sec-fetch-mode') || '');
      headers.set('x-void-site', req.headers.get('sec-fetch-site') || '');

      const reqOpts = {
        method: req.method,
        headers: headers,
        redirect: 'manual'
      };

      if (!['GET', 'HEAD'].includes(req.method)) {
        reqOpts.body = await req.blob();
      }

      return await fetch(encodedUrl, reqOpts);
    } catch (err) {
      console.error("[SW] Fetch interception error:", err);
      return new Response("Service Worker Proxy Error", { status: 500 });
    }
  })());
});
