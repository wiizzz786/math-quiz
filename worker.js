

const BLOCKED_HOSTS = /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|metadata\.google\.internal)$/i;
const BLOCKED_SCHEMES = /^(file|ftp|data|javascript|vbscript):/i;
const MAX_REDIRECTS = 8;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Expose-Headers': '*',
  'Access-Control-Max-Age': '86400'
};

const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

function validateUrl(target) {
  if (!target) throw new Error('Missing target URL');
  const decoded = decodeURIComponent(target);
  if (BLOCKED_SCHEMES.test(decoded)) throw new Error('Blocked scheme');
  
  const parsed = new URL(decoded);
  if (BLOCKED_HOSTS.test(parsed.hostname)) throw new Error('Blocked host');
  return parsed.href;
}

function buildHeaders(request, targetUrl) {
  const fwd = new Headers();
  const targetParsed = new URL(targetUrl);

  const STRIP = new Set([
    'host', 'origin', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor',
    'x-forwarded-for', 'x-real-ip', 'x-forwarded-proto', 'x-client-data',
    'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'sec-fetch-user'
  ]);

  for (const [key, val] of request.headers) {
    const k = key.toLowerCase();
    if (!STRIP.has(k) && !k.startsWith('x-void-') && !k.startsWith('x-goog-')) {
      fwd.set(key, val);
    }
  }

  // Handle client void cookies
  const voidCookie = request.headers.get('x-void-cookie');
  if (voidCookie) {
    fwd.set('Cookie', voidCookie);
  }

  // Real browser headers setup to prevent anti-bot detection (Google, Cloudflare, etc.)
  fwd.set('User-Agent', fwd.get('User-Agent') || DEFAULT_UA);
  fwd.set('Accept-Language', fwd.get('Accept-Language') || 'en-US,en;q=0.9');
  fwd.set('Accept-Encoding', 'gzip, deflate, br');
  fwd.set('Referer', targetParsed.origin + '/');
  fwd.set('Origin', targetParsed.origin);

  // Chrome Client Hints to pass Google bot checks
  if (!fwd.has('sec-ch-ua')) {
    fwd.set('sec-ch-ua', '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"');
  }
  if (!fwd.has('sec-ch-ua-mobile')) fwd.set('sec-ch-ua-mobile', '?0');
  if (!fwd.has('sec-ch-ua-platform')) fwd.set('sec-ch-ua-platform', '"Windows"');

  const dest = request.headers.get('x-void-dest') || 'empty';

  if (dest === 'document') {
    fwd.set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8');
    fwd.set('Sec-Fetch-Dest', 'document');
    fwd.set('Sec-Fetch-Mode', 'navigate');
    fwd.set('Sec-Fetch-Site', 'none');
    fwd.set('Sec-Fetch-User', '?1');
    fwd.set('Upgrade-Insecure-Requests', '1');
  } else if (dest === 'script') {
    fwd.set('Accept', '*/*');
    fwd.set('Sec-Fetch-Dest', 'script');
    fwd.set('Sec-Fetch-Mode', 'no-cors');
    fwd.set('Sec-Fetch-Site', 'cross-site');
  } else if (dest === 'style') {
    fwd.set('Accept', 'text/css,*/*;q=0.1');
    fwd.set('Sec-Fetch-Dest', 'style');
    fwd.set('Sec-Fetch-Mode', 'no-cors');
    fwd.set('Sec-Fetch-Site', 'cross-site');
  } else if (dest === 'image') {
    fwd.set('Accept', 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8');
    fwd.set('Sec-Fetch-Dest', 'image');
    fwd.set('Sec-Fetch-Mode', 'no-cors');
    fwd.set('Sec-Fetch-Site', 'cross-site');
  } else {
    fwd.set('Accept', '*/*');
    fwd.set('Sec-Fetch-Dest', 'empty');
    fwd.set('Sec-Fetch-Mode', 'cors');
    fwd.set('Sec-Fetch-Site', 'cross-site');
  }

  return fwd;
}

function cleanResponseHeaders(headers, finalUrl, ct) {
  const resp = new Headers();
  for (const [key, val] of headers) {
    if (key.toLowerCase() === 'set-cookie') continue;
    resp.set(key, val);
  }

  for (const [k, v] of Object.entries(CORS_HEADERS)) {
    resp.set(k, v);
  }

  const REMOVE_SECURITY_HEADERS = [
    'content-security-policy',
    'content-security-policy-report-only',
    'x-frame-options',
    'strict-transport-security',
    'x-content-type-options',
    'x-xss-protection',
    'permissions-policy',
    'cross-origin-opener-policy',
    'cross-origin-embedder-policy',
    'cross-origin-resource-policy'
  ];
  for (const h of REMOVE_SECURITY_HEADERS) resp.delete(h);

  const cookies = headers.getAll ? headers.getAll('set-cookie') : [];
  if (!cookies.length) {
    const sc = headers.get('set-cookie');
    if (sc) cookies.push(sc);
  }
  if (cookies.length) {
    resp.set('X-Void-Set-Cookie', JSON.stringify(cookies));
  }

  resp.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  resp.set('X-Void-Final-URL', finalUrl);
  resp.set('Timing-Allow-Origin', '*');
  return resp;
}

function rewriteCss(css, baseUrl, proxyBase) {
  return css
    .replace(/@import\s+url\(\s*(['"]?)((?!data:)[^)'"]+)\1\s*\)/gi, (m, q, rawUrl) => {
      try {
        const abs = new URL(rawUrl.trim(), baseUrl).href;
        return `@import url(${q}${proxyBase}?url=${encodeURIComponent(abs)}${q})`;
      } catch { return m; }
    })
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (m, q, rawUrl) => {
      try {
        const abs = new URL(rawUrl.trim(), baseUrl).href;
        return `@import ${q}${proxyBase}?url=${encodeURIComponent(abs)}${q}`;
      } catch { return m; }
    })
    .replace(/url\(\s*(['"]?)((?!data:|blob:|#)[^)'"]+)\1\s*\)/gi, (m, q, rawUrl) => {
      const clean = rawUrl.trim();
      if (/^(data:|blob:|#)/i.test(clean)) return m;
      try {
        const abs = new URL(clean, baseUrl).href;
        return `url(${q}${proxyBase}?url=${encodeURIComponent(abs)}${q})`;
      } catch { return m; }
    });
}

function rewriteHtmlStream(response, baseUrl, proxyBase) {
  const makeProxyUrl = (rawUrl) => {
    if (!rawUrl || /^(data:|javascript:|blob:|about:|#)/i.test(rawUrl.trim())) return rawUrl;
    try {
      const abs = new URL(rawUrl, baseUrl).href;
      return `${proxyBase}?url=${encodeURIComponent(abs)}`;
    } catch { return rawUrl; }
  };

  const rewriter = new HTMLRewriter()
    .on('head', {
      element(el) {
        el.prepend(`<base href="${baseUrl}">`, { html: true });
      }
    })
    .on('a', {
      element(el) {
        const href = el.getAttribute('href');
        if (href) el.setAttribute('href', makeProxyUrl(href));
      }
    })
    .on('form', {
      element(el) {
        const action = el.getAttribute('action');
        if (action) el.setAttribute('action', makeProxyUrl(action));
      }
    })
    .on('img', {
      element(el) {
        const src = el.getAttribute('src');
        if (src) el.setAttribute('src', makeProxyUrl(src));
      }
    })
    .on('script', {
      element(el) {
        const src = el.getAttribute('src');
        if (src) el.setAttribute('src', makeProxyUrl(src));
      }
    })
    .on('link', {
      element(el) {
        const href = el.getAttribute('href');
        if (href) el.setAttribute('href', makeProxyUrl(href));
      }
    })
    .on('iframe', {
      element(el) {
        const src = el.getAttribute('src');
        if (src) el.setAttribute('src', makeProxyUrl(src));
      }
    });

  return rewriter.transform(response);
}

export default {
  async fetch(request, env, ctx) {
    const workerUrl = new URL(request.url);
    const target = workerUrl.searchParams.get('url');

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    if (!target) {
      return new Response('Void CORS Proxy Operational\nUsage: ?url=https://example.com', {
        headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'text/plain' }
      });
    }

    let validUrl;
    try {
      validUrl = validateUrl(target);
    } catch (e) {
      return new Response('Blocked: ' + (e.message || 'Invalid target URL'), {
        status: 403,
        headers: { 'Access-Control-Allow-Origin': '*' }
      });
    }

    const fwdHeaders = buildHeaders(request, validUrl);
    let finalUrl = validUrl;
    let upstream;
    let hops = 0;
    const collectedCookies = [];
    let curMethod = request.method;
    let curBody = (curMethod !== 'GET' && curMethod !== 'HEAD') ? request.body : undefined;

    try {
      while (hops < MAX_REDIRECTS) {
        upstream = await fetch(finalUrl, {
          method: curMethod,
          headers: fwdHeaders,
          body: curBody,
          redirect: 'manual'
        });

        const scAll = upstream.headers.getAll ? upstream.headers.getAll('set-cookie') : [];
        if (scAll.length) {
          collectedCookies.push(...scAll);
        } else {
          const sc = upstream.headers.get('set-cookie');
          if (sc) collectedCookies.push(sc);
        }

        if (upstream.status >= 300 && upstream.status < 400) {
          const loc = upstream.headers.get('location');
          if (!loc) break;
          try {
            finalUrl = new URL(loc, finalUrl).href;
          } catch { break; }

          const newOrigin = new URL(finalUrl).origin;
          fwdHeaders.set('Referer', newOrigin + '/');
          fwdHeaders.set('Origin', newOrigin);

          if (upstream.status !== 307 && upstream.status !== 308) {
            curMethod = 'GET';
            curBody = undefined;
            fwdHeaders.delete('Content-Type');
            fwdHeaders.delete('Content-Length');
          }

          if (collectedCookies.length) {
            const cookieStr = collectedCookies.map(c => c.split(';')[0]).join('; ');
            const existing = fwdHeaders.get('Cookie');
            fwdHeaders.set('Cookie', existing ? `${existing}; ${cookieStr}` : cookieStr);
          }

          hops++;
          continue;
        }
        break;
      }

      const ct = (upstream.headers.get('content-type') || '').toLowerCase();
      const respHeaders = cleanResponseHeaders(upstream.headers, finalUrl, ct);

      if (collectedCookies.length) {
        const existing = respHeaders.get('X-Void-Set-Cookie');
        const arr = existing ? JSON.parse(existing) : [];
        arr.push(...collectedCookies);
        respHeaders.set('X-Void-Set-Cookie', JSON.stringify(arr));
      }

      if (hops > 0) {
        respHeaders.set('X-Void-Redirects', String(hops));
      }

      const proxyBase = `${workerUrl.origin}${workerUrl.pathname}`;

      // HTML Rewriting at Edge Speed
      if (ct.includes('text/html')) {
        const rawResponse = new Response(upstream.body, {
          status: upstream.status,
          statusText: upstream.statusText,
          headers: respHeaders
        });
        return rewriteHtmlStream(rawResponse, finalUrl, proxyBase);
      }

      // CSS Rewriting
      if (ct.includes('text/css')) {
        const cssText = await upstream.text();
        const rewrittenCss = rewriteCss(cssText, finalUrl, proxyBase);
        return new Response(rewrittenCss, {
          status: upstream.status,
          statusText: upstream.statusText,
          headers: respHeaders
        });
      }

      // Passthrough for images, fonts, binaries, etc.
      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: respHeaders
      });

    } catch (e) {
      return new Response(JSON.stringify({ error: e.message, url: validUrl }), {
        status: 502,
        headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' }
      });
    }
  }
};