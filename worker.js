/**
 * Void CORS Proxy — Cloudflare Worker
 * Deploy:  npx wrangler deploy
 */

var BLOCKED_HOSTS = /^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|metadata\.google\.internal)$/i;
var BLOCKED_SCHEMES = /^(file|ftp|data|javascript|vbscript):/i;

export default {
  async fetch(request, env) {
    var url = new URL(request.url);
    var target = url.searchParams.get('url');

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': '*',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    if (!target) {
      return new Response('Void CORS Proxy OK\n\nUsage: ?url=https://example.com', {
        headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'text/plain' }
      });
    }

    var decoded;
    try {
      decoded = decodeURIComponent(target);
      var parsed = new URL(decoded);
      if (BLOCKED_SCHEMES.test(decoded)) throw new Error('blocked scheme');
      if (BLOCKED_HOSTS.test(parsed.hostname)) throw new Error('blocked host');
    } catch (e) {
      return new Response('Blocked: ' + (e.message || 'invalid URL'), {
        status: 403,
        headers: { 'Access-Control-Allow-Origin': '*' }
      });
    }

    var STRIP_REQ = ['host', 'origin', 'cf-connecting-ip', 'cf-ipcountry',
      'cf-ray', 'cf-visitor', 'x-forwarded-for', 'x-real-ip', 'cookie'];

    var fwdHeaders = new Headers();
    for (var pair of request.headers) {
      if (STRIP_REQ.indexOf(pair[0].toLowerCase()) === -1) {
        fwdHeaders.set(pair[0], pair[1]);
      }
    }
    if (!fwdHeaders.has('referer')) fwdHeaders.set('Referer', decoded);
    if (!fwdHeaders.has('user-agent')) {
      fwdHeaders.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
    }

    try {
      var upstream = await fetch(decoded, {
        method: request.method,
        headers: fwdHeaders,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
        redirect: 'follow'
      });

      var respHeaders = new Headers(upstream.headers);
      respHeaders.set('Access-Control-Allow-Origin', '*');
      respHeaders.set('Access-Control-Expose-Headers', '*');
      respHeaders.delete('content-security-policy');
      respHeaders.delete('content-security-policy-report-only');
      respHeaders.delete('x-frame-options');
      respHeaders.delete('strict-transport-security');
      respHeaders.delete('x-content-type-options');

      var ct = (respHeaders.get('content-type') || '').toLowerCase();
      var cacheCtl = 'no-store';
      if (ct.match(/\/(javascript|css|font|image|png|jpg|jpeg|gif|webp|svg|woff|woff2|ttf|otf|ico)/)) {
        cacheCtl = 'public, max-age=3600';
      }
      respHeaders.set('Cache-Control', cacheCtl);

      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: respHeaders
      });
    } catch (e) {
      return new Response('Upstream fetch failed: ' + e.message, {
        status: 502,
        headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'text/plain' }
      });
    }
  }
};
