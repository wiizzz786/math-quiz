const SKIP = /^(data:|blob:|javascript:|#|mailto:)/i;

let customTld = '.securly.com';
const urlParams = new URLSearchParams(self.location.search);
if (urlParams.has('tld')) {
  customTld = urlParams.get('tld');
}

function E(url) {
  try {
    let u = new URL(url).href;
    const salt = Math.random().toString(36).substring(2, 6).padEnd(4, "x");
    u = salt + "||" + u;
    const key = "Void2026";
    let chars = [];
    for (let i = 0; i < u.length; i++) {
      let code = u.charCodeAt(i) ^ key.charCodeAt(i % key.length);
      chars.push(String.fromCharCode(code));
    }
    const tld = ".www.securly.com";
    return self.location.origin + "/pe/" + btoa(chars.join("")).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"") + tld;
  } catch(e) { return url; }
}

function D(encoded) {
  try {
    let b64 = encoded;
    const tldIndex = b64.lastIndexOf(".");
    if (tldIndex > 0) b64 = b64.substring(0, tldIndex);
    b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const raw = atob(b64);
    const key = "Void2026";
    let dec = [];
    for (let i = 0; i < raw.length; i++) {
      let code = raw.charCodeAt(i) ^ key.charCodeAt(i % key.length);
      dec.push(String.fromCharCode(code));
    }
    const parts = dec.join('').split('||');
    return parts.length === 2 ? parts[1] : parts[0];
  } catch(e) {
    return '';
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

  // If it's a same-origin request
  if (url.origin === self.location.origin) {
    const isAsset = /^\/(p|pe|api|public|sw\.js|favicon)/.test(url.pathname) || url.pathname === '/';
    if (isAsset) return;

    // Relative request inside iframe
    const referrer = req.referrer;
    if (referrer && referrer.startsWith(self.location.origin)) {
      const refUrl = new URL(referrer);
      const match = refUrl.pathname.match(/^\/(p|pe)\/([^/]+)/);
      if (match) {
        const encodedRef = match[2];
        const baseTarget = D(encodedRef);
        if (baseTarget) {
          const targetUrl = new URL(url.pathname + url.search, baseTarget).href;
          event.respondWith((async () => {
            try {
              const encodedUrl = E(targetUrl);
              const headers = new Headers(req.headers);
              headers.set('x-void-dest', req.destination || '');
              headers.set('x-void-mode', req.mode || '');
              headers.set('x-void-site', req.mode === 'navigate' ? 'none' : 'cross-site');

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
              return new Response("Service Worker Proxy Error", { status: 500 });
            }
          })());
          return;
        }
      }
    }
    return;
  }

  // Cross-origin request intercepted!
  event.respondWith((async () => {
    try {
      const encodedUrl = E(req.url);
      
      const headers = new Headers(req.headers);
      headers.set('x-void-dest', req.destination || '');
      headers.set('x-void-mode', req.mode || '');
      headers.set('x-void-site', req.mode === 'navigate' ? 'none' : 'cross-site');

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
