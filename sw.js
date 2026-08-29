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
      
      const reqOpts = {
        method: req.method,
        headers: req.headers,
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
