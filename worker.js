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
  var STRIP = new Set(['host','origin','cf-connecting-ip','cf-ipcountry','cf-ray','cf-visitor','x-forwarded-for','x-real-ip','cookie','x-forwarded-proto']);
  for (var pair of request.headers) {
    if (!STRIP.has(pair[0].toLowerCase())) fwd.set(pair[0], pair[1]);
  }
  if (!fwd.has('user-agent')) {
    fwd.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
  }
  fwd.set('Accept-Encoding', 'gzip, deflate, br');
  return fwd;
}

function cleanResponseHeaders(headers, finalUrl, ct) {
  var resp = new Headers(headers);
  for (var k of Object.keys(CORS_HEADERS)) resp.set(k, CORS_HEADERS[k]);

  var remove = ['content-security-policy','content-security-policy-report-only',
    'x-frame-options','strict-transport-security','x-content-type-options',
    'x-xss-protection','permissions-policy','cross-origin-opener-policy',
    'cross-origin-embedder-policy','cross-origin-resource-policy'];
  for (var h of remove) resp.delete(h);

  resp.set('Cache-Control', cachePolicy(ct, finalUrl));
  resp.set('X-Void-Final-URL', finalUrl);
  resp.set('Timing-Allow-Origin', '*');
  return resp;
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
    fwdHeaders.set('Referer', new URL(decoded).origin + '/');

    try {
      var finalUrl = decoded;
      var upstream;
      var hops = 0;

      while (hops < MAX_REDIRECTS) {
        upstream = await fetch(finalUrl, {
          method: request.method,
          headers: fwdHeaders,
          body: (request.method !== 'GET' && request.method !== 'HEAD') ? request.body : undefined,
          redirect: 'manual'
        });

        if (upstream.status >= 300 && upstream.status < 400) {
          var loc = upstream.headers.get('location');
          if (!loc) break;
          try { finalUrl = new URL(loc, finalUrl).href; } catch { break; }
          fwdHeaders.set('Referer', new URL(finalUrl).origin + '/');
          hops++;
          continue;
        }
        break;
      }

      var ct = (upstream.headers.get('content-type') || '').toLowerCase();
      var respHeaders = cleanResponseHeaders(upstream.headers, finalUrl, ct);

      if (hops > 0) {
        respHeaders.set('X-Void-Redirects', String(hops));
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
