/**
 * Void CORS Proxy — Cloudflare Worker (optimized)
 * Deploy:  npx wrangler deploy
 */

var BLOCKED_HOSTS = /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|metadata\.google\.internal)$/i;
var BLOCKED_SCHEMES = /^(file|ftp|data|javascript|vbscript):/i;
var MAX_REDIRECTS = 8;

var CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': '*',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Expose-Headers': '*',
  'Access-Control-Max-Age': '86400'
};

var STATIC_RE = /\/(javascript|css|font|woff|woff2|ttf|otf|eot|png|jpg|jpeg|gif|webp|avif|svg|ico|mp4|webm|mp3|ogg|wav|flac)/i;
var IMMUTABLE_RE = /\.(woff2?|ttf|otf|eot)(\?|$)/i;

function cachePolicy(ct, finalUrl) {
  if (IMMUTABLE_RE.test(finalUrl)) return 'public, max-age=31536000, immutable';
  if (STATIC_RE.test(ct)) return 'public, max-age=86400, stale-while-revalidate=3600';
  return 'public, max-age=300, stale-while-revalidate=60';
}

function validate(target) {
  var decoded = decodeURIComponent(target);
  var parsed = new URL(decoded);
  if (BLOCKED_SCHEMES.test(decoded)) throw new Error('blocked scheme');
  if (BLOCKED_HOSTS.test(parsed.hostname)) throw new Error('blocked host');
  return decoded;
}

function buildHeaders(request) {
  var fwd = new Headers();
  var STRIP = new Set(['host','origin','cf-connecting-ip','cf-ipcountry','cf-ray','cf-visitor',
    'x-forwarded-for','x-real-ip','x-forwarded-proto',
    'sec-fetch-site','sec-fetch-mode','sec-fetch-dest','sec-fetch-user']);
  for (var pair of request.headers) {
    var k = pair[0].toLowerCase();
    if (!STRIP.has(k) && !k.startsWith('x-void-')) fwd.set(pair[0], pair[1]);
  }

  var voidCookie = request.headers.get('x-void-cookie');
  if (voidCookie) {
    fwd.set('Cookie', voidCookie);
  }

  if (!fwd.has('user-agent')) {
    fwd.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
  }

  var dest = request.headers.get('x-void-dest') || 'empty';
  fwd.delete('x-void-dest');

  if (dest === 'document') {
    if (!fwd.has('accept')) fwd.set('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8');
    fwd.set('Sec-Fetch-Dest', 'document');
    fwd.set('Sec-Fetch-Mode', 'navigate');
    fwd.set('Sec-Fetch-Site', 'none');
    fwd.set('Sec-Fetch-User', '?1');
    fwd.set('Upgrade-Insecure-Requests', '1');
  } else if (dest === 'script') {
    if (!fwd.has('accept')) fwd.set('Accept', '*/*');
    fwd.set('Sec-Fetch-Dest', 'script');
    fwd.set('Sec-Fetch-Mode', 'no-cors');
    fwd.set('Sec-Fetch-Site', 'same-origin');
  } else if (dest === 'style') {
    if (!fwd.has('accept')) fwd.set('Accept', 'text/css,*/*;q=0.1');
    fwd.set('Sec-Fetch-Dest', 'style');
    fwd.set('Sec-Fetch-Mode', 'no-cors');
    fwd.set('Sec-Fetch-Site', 'same-origin');
  } else if (dest === 'image') {
    if (!fwd.has('accept')) fwd.set('Accept', 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8');
    fwd.set('Sec-Fetch-Dest', 'image');
    fwd.set('Sec-Fetch-Mode', 'no-cors');
    fwd.set('Sec-Fetch-Site', 'same-origin');
  } else {
    if (!fwd.has('accept')) fwd.set('Accept', '*/*');
    fwd.set('Sec-Fetch-Dest', 'empty');
    fwd.set('Sec-Fetch-Mode', 'cors');
    fwd.set('Sec-Fetch-Site', 'same-origin');
  }

  if (!fwd.has('accept-language')) fwd.set('Accept-Language', 'en-US,en;q=0.9');
  fwd.set('Accept-Encoding', 'gzip, deflate, br');
  return fwd;
}

function cleanResponseHeaders(headers, finalUrl, ct) {
  var resp = new Headers();
  for (var pair of headers) {
    var key = pair[0].toLowerCase();
    if (key === 'set-cookie') continue;
    resp.set(pair[0], pair[1]);
  }

  for (var k of Object.keys(CORS_HEADERS)) resp.set(k, CORS_HEADERS[k]);

  var remove = ['content-security-policy','content-security-policy-report-only',
    'x-frame-options','strict-transport-security','x-content-type-options',
    'x-xss-protection','permissions-policy','cross-origin-opener-policy',
    'cross-origin-embedder-policy','cross-origin-resource-policy'];
  for (var h of remove) resp.delete(h);

  var cookies = headers.getAll ? headers.getAll('set-cookie') : [];
  if (!cookies.length) {
    var sc = headers.get('set-cookie');
    if (sc) cookies = [sc];
  }
  if (cookies.length) {
    resp.set('X-Void-Set-Cookie', JSON.stringify(cookies));
  }

  resp.set('Cache-Control', cachePolicy(ct, finalUrl));
  resp.set('X-Void-Final-URL', finalUrl);
  resp.set('Timing-Allow-Origin', '*');
  return resp;
}

var _cookieJar = {};

function rewriteCss(css, baseUrl, proxyBase) {
  css = css.replace(/@import\s+url\(\s*(['"]?)((?!data:)[^)'"]+)\1\s*\)/gi, function(m, q, rawUrl) {
    try {
      var abs = new URL(rawUrl.trim(), baseUrl).href;
      if (!/^https?:\/\//i.test(abs)) return m;
      return '@import url(' + q + proxyBase + '?url=' + encodeURIComponent(abs) + q + ')';
    } catch(e) { return m; }
  });
  css = css.replace(/@import\s+(['"])([^'"]+)\1/gi, function(m, q, rawUrl) {
    try {
      var abs = new URL(rawUrl.trim(), baseUrl).href;
      if (!/^https?:\/\//i.test(abs)) return m;
      return '@import ' + q + proxyBase + '?url=' + encodeURIComponent(abs) + q;
    } catch(e) { return m; }
  });
  css = css.replace(/url\(\s*(['"]?)((?!data:|blob:|#)[^)'"]+)\1\s*\)/gi, function(m, q, rawUrl) {
    rawUrl = rawUrl.trim();
    if (/^(data:|blob:|#)/i.test(rawUrl)) return m;
    try {
      var abs = new URL(rawUrl, baseUrl).href;
      if (!/^https?:\/\//i.test(abs)) return m;
      return 'url(' + q + proxyBase + '?url=' + encodeURIComponent(abs) + q + ')';
    } catch(e) { return m; }
  });
  return css;
}

export default {
  async fetch(request, env, ctx) {
    var url = new URL(request.url);
    var target = url.searchParams.get('url');

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    if (!target) {
      return new Response('Void CORS Proxy OK\n\nUsage: ?url=https://example.com', {
        headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'text/plain' }
      });
    }

    var decoded;
    try {
      decoded = validate(target);
    } catch (e) {
      return new Response('Blocked: ' + (e.message || 'invalid URL'), {
        status: 403, headers: { 'Access-Control-Allow-Origin': '*' }
      });
    }

    var fwdHeaders = buildHeaders(request);
    var targetOrigin = new URL(decoded).origin;
    fwdHeaders.set('Referer', targetOrigin + '/');
    fwdHeaders.set('Origin', targetOrigin);
    fwdHeaders.delete('x-void-cookie');
    fwdHeaders.delete('x-void-set-cookie');

    try {
      var finalUrl = decoded;
      var upstream;
      var hops = 0;
      var collectedCookies = [];
      var curMethod = request.method;
      var curBody = (curMethod !== 'GET' && curMethod !== 'HEAD') ? request.body : undefined;

      while (hops < MAX_REDIRECTS) {
        upstream = await fetch(finalUrl, {
          method: curMethod,
          headers: fwdHeaders,
          body: curBody,
          redirect: 'manual'
        });

        var scAll = upstream.headers.getAll ? upstream.headers.getAll('set-cookie') : [];
        if (scAll.length) {
          collectedCookies.push(...scAll);
        } else {
          var sc = upstream.headers.get('set-cookie');
          if (sc) collectedCookies.push(sc);
        }

        if (upstream.status >= 300 && upstream.status < 400) {
          var loc = upstream.headers.get('location');
          if (!loc) break;
          try { finalUrl = new URL(loc, finalUrl).href; } catch { break; }
          var newOrigin = new URL(finalUrl).origin;
          fwdHeaders.set('Referer', newOrigin + '/');
          fwdHeaders.set('Origin', newOrigin);

          if (upstream.status !== 307 && upstream.status !== 308) {
            curMethod = 'GET';
            curBody = undefined;
            fwdHeaders.delete('Content-Type');
            fwdHeaders.delete('Content-Length');
          }

          if (collectedCookies.length) {
            var cookieStr = collectedCookies.map(function(c) {
              return c.split(';')[0];
            }).join('; ');
            var existing = fwdHeaders.get('Cookie');
            fwdHeaders.set('Cookie', existing ? existing + '; ' + cookieStr : cookieStr);
          }

          hops++;
          continue;
        }
        break;
      }

      var ct = (upstream.headers.get('content-type') || '').toLowerCase();
      var respHeaders = cleanResponseHeaders(upstream.headers, finalUrl, ct);

      if (collectedCookies.length) {
        var existing = respHeaders.get('X-Void-Set-Cookie');
        var arr = existing ? JSON.parse(existing) : [];
        arr.push(...collectedCookies);
        respHeaders.set('X-Void-Set-Cookie', JSON.stringify(arr));
      }

      if (hops > 0) {
        respHeaders.set('X-Void-Redirects', String(hops));
      }

      if (ct.indexOf('text/css') >= 0) {
        var cssText = await upstream.text();
        var proxyBase = url.origin + url.pathname;
        cssText = rewriteCss(cssText, finalUrl, proxyBase);
        return new Response(cssText, {
          status: upstream.status,
          statusText: upstream.statusText,
          headers: respHeaders
        });
      }

      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: respHeaders
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message, url: decoded }), {
        status: 502,
        headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' }
      });
    }
  }
};
