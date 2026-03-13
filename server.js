import express from "express";
import { createServer } from "node:http";
import https from "node:https";
import http from "node:http";
import { createGunzip, createInflate, createBrotliDecompress } from "node:zlib";
import { Transform } from "node:stream";
import { createHash } from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import * as cheerio from "cheerio";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static(join(__dirname, "public")));

/* ═══════════════════════════════════════════
   URL encoding / decoding helpers
   ═══════════════════════════════════════════ */

function enc(url) {
  return "/p/" + Buffer.from(url).toString("base64url");
}

function dec(encoded) {
  const normalized = String(encoded).replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4;
  const padded = padding ? normalized + "=".repeat(4 - padding) : normalized;
  return Buffer.from(padded, "base64").toString("utf8");
}

function rewriteUrl(raw, base) {
  if (
    !raw ||
    raw.startsWith("data:") ||
    raw.startsWith("blob:") ||
    raw.startsWith("javascript:") ||
    raw.startsWith("#") ||
    raw.startsWith("mailto:")
  )
    return raw;
  try {
    return enc(new URL(raw, base).href);
  } catch {
    return raw;
  }
}

/* ═══════════════════════════════════════════
   CSS url() rewriter
   ═══════════════════════════════════════════ */

function rewriteCss(css, base) {
  return css
    .replace(
      /url\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi,
      (match, q, url) => {
        const r = rewriteUrl(url, base);
        return r !== url ? `url(${q}${r}${q})` : match;
      }
    )
    .replace(
      /@import\s+(['"])([^'"]+)\1/gi,
      (match, q, url) => {
        const r = rewriteUrl(url, base);
        return r !== url ? `@import ${q}${r}${q}` : match;
      }
    );
}

/* ═══════════════════════════════════════════
   Injection: JS overrides for dynamic reqs
   ═══════════════════════════════════════════ */

function injectionScript(base) {
  const safeBase = (base || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  return `<script data-void="1">
(function(){
  var B='${safeBase}';
  function E(u){
    try{
      if(!u||typeof u!=='string')return u;
      if(u.startsWith('/p/'))return u;
      var a=new URL(u,B).href;
      if(a.startsWith('http'))return'/p/'+btoa(a).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'');
      return u;
    }catch(e){return u;}
  }
  var _f=window.fetch;
  window.fetch=function(u,o){
    if(typeof u==='string')u=E(u);
    else if(u&&u.url)u=new Request(E(u.url),u);
    return _f.call(this,u,o);
  };
  var _xo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){
    arguments[1]=E(u);
    return _xo.apply(this,arguments);
  };
  var _wo=window.open;
  window.open=function(u,w){
    if(u&&typeof u==='string'){
      var eu=E(u);
      if(eu!==u){
        if(w==='_blank')return _wo(eu,'_blank');
        window.location.href=eu;return null;
      }
    }
    return _wo.apply(this,arguments);
  };
  var _ps=History.prototype.pushState;
  History.prototype.pushState=function(s,t,u){
    if(u)arguments[2]=E(u);
    return _ps.apply(this,arguments);
  };
  var _rs=History.prototype.replaceState;
  History.prototype.replaceState=function(s,t,u){
    if(u)arguments[2]=E(u);
    return _rs.apply(this,arguments);
  };
  var _la=Location.prototype.assign||function(){};
  if(Location.prototype.assign){
    Location.prototype.assign=function(u){return _la.call(this,E(u));};
  }
  var _lr=Location.prototype.replace;
  if(Location.prototype.replace){
    Location.prototype.replace=function(u){return _lr.call(this,E(u));};
  }

  // Intercept all link clicks — force everything through the proxy in the same tab
  // Use getAttribute('href') so we get the raw href; t.href is resolved against
  // the proxy URL (wrong) and would turn /url?q=... into our origin, sending user home
  document.addEventListener('click',function(e){
    var t=e.target;
    while(t&&t.tagName!=='A')t=t.parentElement;
    if(!t)return;
    var raw=t.getAttribute('href');
    if(!raw)return;
    if(raw==='/'||raw==='')return;
    t.removeAttribute('target');
    if(raw.startsWith('/p/')){
      e.preventDefault();window.location.href=raw;
      return;
    }
    if(raw.startsWith('javascript:')||raw.startsWith('#')||raw.startsWith('data:')||raw.startsWith('mailto:'))return;
    try{
      var abs=new URL(raw,B).href;
      if(abs.startsWith('http://')||abs.startsWith('https://')){
        if(abs.startsWith(location.origin))return;
        e.preventDefault();
        e.stopPropagation();
        window.location.href=E(abs);
      }
    }catch(err){}
  },true);

  // Intercept form submissions (use getAttribute to avoid wrong resolution)
  document.addEventListener('submit',function(e){
    var f=e.target;
    if(!f||f.tagName!=='FORM')return;
    var a=f.getAttribute('action')||f.action||'';
    if(!a)return;
    if(a.startsWith('/p/'))return;
    if(a.startsWith('javascript:')||a.startsWith('#'))return;
    try{
      var abs=new URL(a,B).href;
      if((abs.startsWith('http://')||abs.startsWith('https://'))&&!abs.startsWith(location.origin)){
        f.action=E(abs);
      }
    }catch(err){}
  },true);

  // MutationObserver: rewrite href/src on dynamically added elements
  var obs=new MutationObserver(function(muts){
    muts.forEach(function(m){
      m.addedNodes.forEach(function(n){
        if(n.nodeType!==1)return;
        rewriteEl(n);
        if(n.querySelectorAll){
          n.querySelectorAll('a[href],form[action],img[src],link[href],script[src]').forEach(rewriteEl);
        }
      });
    });
  });
  function rewriteEl(el){
    if(el.tagName==='A'){
      el.removeAttribute('target');
      var h=el.getAttribute('href');
      if(h==='/'||h==='')return;
      if(h&&!h.startsWith('/p/')&&!h.startsWith('#')&&!h.startsWith('javascript:')&&!h.startsWith('data:')){
        try{var abs=new URL(h,B).href;if(abs.startsWith('http'))el.setAttribute('href',E(abs));}catch(e){}
      }
    }
    if(el.tagName==='FORM'){
      el.removeAttribute('target');
      var a=el.getAttribute('action');
      if(a&&!a.startsWith('/p/')){
        try{var abs2=new URL(a,B).href;if(abs2.startsWith('http'))el.setAttribute('action',E(abs2));}catch(e){}
      }
    }
    if((el.tagName==='IMG'||el.tagName==='SCRIPT'||el.tagName==='LINK')&&(el.src||el.href)){
      var s=el.getAttribute('src')||el.getAttribute('href');
      if(s&&!s.startsWith('/p/')&&!s.startsWith('data:')&&!s.startsWith('blob:')){
        try{
          var abs3=new URL(s,B).href;
          if(abs3.startsWith('http')){
            var attr=el.getAttribute('src')?'src':'href';
            el.setAttribute(attr,E(abs3));
          }
        }catch(e){}
      }
    }
  }
  obs.observe(document.documentElement,{childList:true,subtree:true});
})();
</script>`;
}

/* ═══════════════════════════════════════════
   Proxy top-bar injected into pages
   ═══════════════════════════════════════════ */

function proxyBar(displayUrl) {
  const safe = displayUrl.replace(/'/g, "&#39;").replace(/"/g, "&quot;");
  let domain = "";
  try { domain = new URL(displayUrl).hostname; } catch {}
  const favicon = domain ? `https://www.google.com/s2/favicons?domain=${domain}&sz=32` : "";
  const faviconHtml = favicon
    ? `<img src="${favicon}" style="width:14px;height:14px;border-radius:2px;flex-shrink:0;" onerror="this.style.display='none'"/>`
    : "";
  return `<div id="__vbar" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;height:42px;display:flex;align-items:center;gap:8px;padding:0 12px;background:rgba(6,6,11,.94);backdrop-filter:blur(16px) saturate(1.2);border-bottom:1px solid rgba(255,255,255,.06);font-family:-apple-system,system-ui,sans-serif;font-size:12px;color:#9a9bb8;box-shadow:0 4px 24px rgba(0,0,0,.3);">
<a href="/" target="_top" style="background:linear-gradient(135deg,#7c6aff,#ff5f8f);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;font-weight:900;text-decoration:none;letter-spacing:-.04em;font-size:16px;">void</a>
<span style="width:1px;height:18px;background:rgba(255,255,255,.08);flex-shrink:0;"></span>
<button onclick="history.back()" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);color:#9a9bb8;border-radius:6px;width:28px;height:28px;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;" title="Back">&#8592;</button>
<button onclick="history.forward()" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);color:#9a9bb8;border-radius:6px;width:28px;height:28px;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;" title="Forward">&#8594;</button>
<button onclick="location.reload()" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);color:#9a9bb8;border-radius:6px;width:28px;height:28px;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;" title="Reload">&#8635;</button>
<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:rgba(0,0,0,.35);padding:5px 12px;border-radius:8px;border:1px solid rgba(255,255,255,.05);font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:11px;color:#646478;display:flex;align-items:center;gap:6px;">${faviconHtml}${safe}</span>
<a href="/" target="_top" style="padding:5px 14px;border-radius:8px;background:rgba(255,255,255,.05);color:#ccc;text-decoration:none;font-weight:600;font-size:11px;border:1px solid rgba(255,255,255,.06);transition:background .15s;">Home</a>
<button onclick="document.getElementById('__vbar').style.display='none';document.getElementById('__vsp').style.display='none'" style="padding:5px 9px;border-radius:8px;background:rgba(255,255,255,.04);color:#ff5f8f;border:1px solid rgba(255,255,255,.06);cursor:pointer;font-weight:700;font-size:13px;">&#x2715;</button>
</div><div id="__vsp" style="height:42px;"></div>`;
}

/* ═══════════════════════════════════════════
   HTML rewriter (cheerio)
   ═══════════════════════════════════════════ */

const URL_ATTRS = {
  a: ["href"],
  area: ["href"],
  link: ["href"],
  img: ["src", "srcset"],
  script: ["src"],
  source: ["src", "srcset"],
  video: ["src", "poster"],
  audio: ["src"],
  embed: ["src"],
  object: ["data"],
  form: ["action"],
  input: ["src"],
  track: ["src"],
};

function rewriteHtml(html, base, opts) {
  const $ = cheerio.load(html, { decodeEntities: false });

  // Determine base URL (<base href> overrides)
  const baseTag = $("base[href]").first();
  let resolveBase = base;
  if (baseTag.length) {
    try {
      resolveBase = new URL(baseTag.attr("href"), base).href;
    } catch {}
    baseTag.remove();
  }

  // Remove CSP so our injected scripts work
  $('meta[http-equiv="Content-Security-Policy"]').remove();
  $('meta[http-equiv="content-security-policy"]').remove();

  // Rewrite URL attributes
  for (const [tag, attrs] of Object.entries(URL_ATTRS)) {
    $(tag).each((_, el) => {
      for (const attr of attrs) {
        const val = $(el).attr(attr);
        if (!val) continue;

        if (attr === "srcset") {
          const rewritten = val.replace(
            /([^\s,]+)(\s+[^,]*)?/g,
            (m, url, desc) => rewriteUrl(url, resolveBase) + (desc || "")
          );
          $(el).attr(attr, rewritten);
        } else {
          $(el).attr(attr, rewriteUrl(val, resolveBase));
        }
      }
    });
  }

  // Rewrite inline styles
  $("[style]").each((_, el) => {
    $(el).attr("style", rewriteCss($(el).attr("style"), resolveBase));
  });

  // Rewrite <style> blocks
  $("style").each((_, el) => {
    $(el).html(rewriteCss($(el).html() || "", resolveBase));
  });

  // Rewrite meta refresh
  $('meta[http-equiv="refresh"]').each((_, el) => {
    const content = $(el).attr("content") || "";
    const m = content.match(/^(\d+)\s*;\s*url\s*=\s*['"]?(.+?)['"]?$/i);
    if (m) {
      $(el).attr("content", m[1] + ";url=" + rewriteUrl(m[2], resolveBase));
    }
  });

  // Options
  if (opts.nojs) {
    $("script:not([data-void])").remove();
    $(
      "[onclick],[onload],[onerror],[onsubmit],[onchange],[onmouseover],[onfocus],[onblur]"
    ).each((_, el) => {
      for (const a of [
        "onclick",
        "onload",
        "onerror",
        "onsubmit",
        "onchange",
        "onmouseover",
        "onfocus",
        "onblur",
      ]) {
        $(el).removeAttr(a);
      }
    });
  }

  if (opts.noimg) {
    $("img").remove();
    $("picture").remove();
    $('[style*="background-image"]').css("background-image", "none");
  }

  // Inject our bar + JS overrides at start of <body>
  const barHtml = proxyBar(base);
  const scriptHtml = opts.nojs ? "" : injectionScript(resolveBase);
  $("body").prepend(barHtml);
  $("head").prepend(scriptHtml);

  return $.html();
}

/* ═══════════════════════════════════════════
   Build request headers for target
   ═══════════════════════════════════════════ */

const HOP_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "upgrade",
  "proxy-authorization",
  "proxy-connection",
]);

function buildHeaders(req, targetUrl) {
  const h = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (HOP_HEADERS.has(k.toLowerCase())) continue;
    if (k.toLowerCase() === "referer") continue;
    if (k.toLowerCase() === "origin") continue;
    h[k] = v;
  }
  try {
    const u = new URL(targetUrl);
    h["host"] = u.host;
    h["referer"] = u.origin + "/";
    h["origin"] = u.origin;
  } catch {}
  return h;
}

/* ═══════════════════════════════════════════
   Proxy handler
   ═══════════════════════════════════════════ */

async function handleProxy(req, res) {
  let targetUrl;
  try {
    targetUrl = dec(req.params.encoded);
  } catch {
    return res.status(400).send("Invalid URL encoding");
  }

  if (!/^https?:\/\//i.test(targetUrl)) {
    return res.status(400).send("Invalid URL");
  }

  const opts = {
    nojs: req.query.nojs === "1",
    noimg: req.query.noimg === "1",
  };

  // Build query string to preserve options across navigation
  const optQs = [];
  if (opts.nojs) optQs.push("nojs=1");
  if (opts.noimg) optQs.push("noimg=1");
  const optSuffix = optQs.length ? "?" + optQs.join("&") : "";

  // Temporarily override enc() to append options
  const _enc = (url) => enc(url) + optSuffix;
  const origRewriteUrl = rewriteUrl;

  try {
    const headers = buildHeaders(req, targetUrl);

    const fetchOpts = {
      method: req.method,
      headers,
      redirect: "manual",
    };

    if (req.method === "POST" && req.body) {
      if (typeof req.body === "object") {
        fetchOpts.body = new URLSearchParams(req.body).toString();
        fetchOpts.headers["content-type"] =
          "application/x-www-form-urlencoded";
      } else {
        fetchOpts.body = req.body;
      }
    }

    const response = await fetch(targetUrl, fetchOpts);

    // Handle redirects
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const loc = response.headers.get("location");
      if (loc) {
        const abs = new URL(loc, targetUrl).href;
        return res.redirect(response.status, enc(abs) + optSuffix);
      }
    }

    const ct = response.headers.get("content-type") || "";

    // Forward safe headers
    for (const [k, v] of response.headers.entries()) {
      const kl = k.toLowerCase();
      if (
        kl === "content-security-policy" ||
        kl === "content-security-policy-report-only" ||
        kl === "x-frame-options" ||
        kl === "strict-transport-security" ||
        kl === "transfer-encoding" ||
        kl === "content-encoding" ||
        kl === "content-length"
      )
        continue;

      if (kl === "set-cookie") {
        const cleaned = v
          .replace(/;\s*domain=[^;]*/gi, "")
          .replace(/;\s*secure/gi, "")
          .replace(/;\s*samesite=[^;]*/gi, "")
          .replace(/;\s*path=[^;]*/gi, "; path=/");
        res.append("set-cookie", cleaned);
        continue;
      }

      if (kl === "location") continue;
      try {
        res.set(k, v);
      } catch {}
    }

    // HTML → rewrite
    if (ct.includes("text/html")) {
      const text = await response.text();

      // Temporarily patch rewriteUrl to include options
      const patched = text ? rewriteHtmlWithOpts(text, targetUrl, opts, optSuffix) : text;
      res.type("text/html; charset=utf-8").send(patched);
      return;
    }

    // CSS → rewrite url()
    if (ct.includes("text/css")) {
      const text = await response.text();
      res.type("text/css; charset=utf-8").send(rewriteCss(text, targetUrl));
      return;
    }

    // Everything else → passthrough
    res.set("content-type", ct);
    const buf = Buffer.from(await response.arrayBuffer());
    res.send(buf);
  } catch (err) {
    const isLogOrAnalytics = /\.(google|googleapis|gstatic)\.com\/(log|analytics|collect|gen_204)/i.test(targetUrl) || /\/(log|analytics|collect|beacon|ping)(\?|&|$)/i.test(targetUrl);
    if (!isLogOrAnalytics) console.error("[proxy error]", targetUrl, err.message);
    const safeTarget = targetUrl.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const safeErr = (err.message || "Unknown error").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    res.status(502).send(`<!DOCTYPE html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Void - Connection Failed</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&family=JetBrains+Mono:wght@400&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{background:#06060b;color:#9a9bb8;font-family:'Inter',system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem;-webkit-font-smoothing:antialiased}
.wrap{max-width:480px;text-align:center}
.code{font-size:6rem;font-weight:900;letter-spacing:-.06em;line-height:1;background:linear-gradient(135deg,#7c6aff,#ff5f8f);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;filter:drop-shadow(0 0 40px rgba(124,106,255,.15))}
h1{font-size:1.4rem;font-weight:700;color:#eef0f8;margin:.8rem 0 .5rem}
p{font-size:.85rem;line-height:1.6;margin:.6rem 0}
.url{display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);padding:6px 14px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:#646478;margin:.6rem 0}
.err{font-size:.78rem;color:#ff5f8f;background:rgba(255,95,143,.06);border:1px solid rgba(255,95,143,.12);padding:8px 14px;border-radius:8px;margin:.8rem 0;font-family:'JetBrains Mono',monospace}
.btn{display:inline-flex;align-items:center;gap:6px;padding:10px 24px;border-radius:10px;background:linear-gradient(135deg,#7c6aff,#ff5f8f);color:#fff;text-decoration:none;font-weight:700;font-size:.82rem;letter-spacing:.02em;margin-top:1.2rem;box-shadow:0 4px 20px rgba(124,106,255,.3);transition:transform .15s,box-shadow .2s}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(124,106,255,.4)}
</style></head><body>
<div class="wrap">
<div class="code">502</div>
<h1>Connection Failed</h1>
<p>Void couldn't reach the requested page.</p>
<div class="url">${safeTarget}</div>
<div class="err">${safeErr}</div>
<p style="font-size:.78rem;color:#464660">The site may be down, blocking proxy requests, or the URL may be invalid.</p>
<a class="btn" href="/">&#8592; Back to Void</a>
</div></body></html>`);
  }
}

function rewriteHtmlWithOpts(html, base, opts, optSuffix) {
  const $ = cheerio.load(html, { decodeEntities: false });

  const baseTag = $("base[href]").first();
  let resolveBase = base;
  if (baseTag.length) {
    try {
      resolveBase = new URL(baseTag.attr("href"), base).href;
    } catch {}
    baseTag.remove();
  }

  $('meta[http-equiv="Content-Security-Policy"]').remove();
  $('meta[http-equiv="content-security-policy"]').remove();

  function rw(raw) {
    if (
      !raw ||
      raw.startsWith("data:") ||
      raw.startsWith("blob:") ||
      raw.startsWith("javascript:") ||
      raw.startsWith("#") ||
      raw.startsWith("mailto:")
    )
      return raw;
    try {
      return enc(new URL(raw, resolveBase).href) + optSuffix;
    } catch {
      return raw;
    }
  }

  function rwNoOpts(raw) {
    if (
      !raw ||
      raw.startsWith("data:") ||
      raw.startsWith("blob:") ||
      raw.startsWith("javascript:") ||
      raw.startsWith("#") ||
      raw.startsWith("mailto:")
    )
      return raw;
    try {
      return enc(new URL(raw, resolveBase).href);
    } catch {
      return raw;
    }
  }

  function rwCssBlock(css) {
    return css
      .replace(/url\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi, (match, q, url) => {
        const r = rwNoOpts(url);
        return r !== url ? `url(${q}${r}${q})` : match;
      })
      .replace(/@import\s+(['"])([^'"]+)\1/gi, (match, q, url) => {
        const r = rwNoOpts(url);
        return r !== url ? `@import ${q}${r}${q}` : match;
      });
  }

  // Strip target=_blank from all links so they stay in the proxy
  $("a[target]").removeAttr("target");
  $("form[target]").removeAttr("target");
  $("base[target]").removeAttr("target");

  for (const [tag, attrs] of Object.entries(URL_ATTRS)) {
    $(tag).each((_, el) => {
      for (const attr of attrs) {
        const val = $(el).attr(attr);
        if (!val) continue;
        if (attr === "srcset") {
          $(el).attr(
            attr,
            val.replace(
              /([^\s,]+)(\s+[^,]*)?/g,
              (m, url, desc) => rwNoOpts(url) + (desc || "")
            )
          );
        } else {
          $(el).attr(attr, rw(val));
        }
      }
    });
  }

  $("[style]").each((_, el) => {
    $(el).attr("style", rwCssBlock($(el).attr("style") || ""));
  });
  $("style").each((_, el) => {
    $(el).html(rwCssBlock($(el).html() || ""));
  });

  $('meta[http-equiv="refresh"]').each((_, el) => {
    const content = $(el).attr("content") || "";
    const m = content.match(/^(\d+)\s*;\s*url\s*=\s*['"]?(.+?)['"]?$/i);
    if (m) {
      $(el).attr("content", m[1] + ";url=" + rw(m[2]));
    }
  });

  if (opts.nojs) {
    $("script:not([data-void])").remove();
    const evts =
      "onclick,onload,onerror,onsubmit,onchange,onmouseover,onfocus,onblur,onkeydown,onkeyup,onmousedown,onmouseup".split(
        ","
      );
    $("*").each((_, el) => {
      for (const e of evts) $(el).removeAttr(e);
    });
  }

  if (opts.noimg) {
    $("img").remove();
    $("picture").remove();
  }

  $("body").prepend(proxyBar(base));
  if (!opts.nojs) $("head").prepend(injectionScript(resolveBase));

  return $.html();
}

/* ═══════════════════════════════════════════
   EXPERIMENTAL PROXY ENGINE (bare-metal, no UV/Scramjet)
   Node core only: http, https, zlib, stream, crypto, net, tls
   ═══════════════════════════════════════════ */

function encPe(url) {
  return "/pe/" + Buffer.from(url).toString("base64url");
}

function decPe(encoded) {
  const normalized = String(encoded).replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4;
  const padded = padding ? normalized + "=".repeat(4 - padding) : normalized;
  return Buffer.from(padded, "base64").toString("utf8");
}

const STEALTH_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15";
const STEALTH_ACCEPT =
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
const STEALTH_ACCEPT_LANG = "en-US,en;q=0.9";

function buildStealthHeaders(targetUrl, req) {
  const u = new URL(targetUrl);
  const host = u.host;
  const origin = u.origin;
  return {
    host,
    "user-agent": STEALTH_UA,
    accept: STEALTH_ACCEPT,
    "accept-language": STEALTH_ACCEPT_LANG,
    "accept-encoding": "gzip, deflate, br",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
    referer: origin + "/",
    origin,
    "cache-control": "max-age=0",
    dnt: "1",
    connection: "keep-alive",
    pragma: "no-cache",
    "sec-ch-ua": '"Safari";v="17.2", "Chromium";v="", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    ...(req.method === "POST" && req.headers["content-type"]
      ? { "content-type": req.headers["content-type"] }
      : {}),
  };
}

const STRIP_RESPONSE_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-content-type-options",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "strict-transport-security",
  "transfer-encoding",
  "content-encoding",
  "content-length",
  "set-cookie",
]);

function remapSetCookie(rawCookie, _proxyHost) {
  return rawCookie
    .replace(/;\s*domain=[^;]*/gi, "")
    .replace(/;\s*secure/gi, "")
    .replace(/;\s*samesite=[^;]*/gi, "")
    .replace(/;\s*path=[^;]*/gi, "; path=/")
    .trim();
}

function rewriteUrlPe(raw, base, optSuffix = "") {
  if (
    !raw ||
    raw.startsWith("data:") ||
    raw.startsWith("blob:") ||
    raw.startsWith("javascript:") ||
    raw.startsWith("#") ||
    raw.startsWith("mailto:")
  )
    return raw;
  try {
    const abs = new URL(raw, base).href;
    if (!/^https?:/.test(abs)) return raw;
    return encPe(abs) + optSuffix;
  } catch {
    return raw;
  }
}

function experimentalRewriteHtml(html, base, optSuffix) {
  const baseRegex = /<base\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let resolveBase = base;
  let m;
  if ((m = baseRegex.exec(html))) {
    try {
      resolveBase = new URL(m[1], base).href;
    } catch {}
  }
  html = html.replace(baseRegex, "");

  const rw = (url) => rewriteUrlPe(url, resolveBase, optSuffix);
  const rwNoOpts = (url) => rewriteUrlPe(url, resolveBase, "");

  const attrPatterns = [
    [/<a\s+([^>]*?)href\s*=\s*["']([^"']*)["']/gi, "href"],
    [/<link\s+([^>]*?)href\s*=\s*["']([^"']*)["']/gi, "href"],
    [/<img\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<script\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<form\s+([^>]*?)action\s*=\s*["']([^"']*)["']/gi, "action"],
    [/<iframe\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<source\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<embed\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<object\s+([^>]*?)data\s*=\s*["']([^"']*)["']/gi, "data"],
  ];
  for (const [re, attr] of attrPatterns) {
    html = html.replace(re, (full, _rest, url) => {
      const rewritten = rw(url);
      if (rewritten === url) return full;
      const q = full.indexOf(url);
      return q === -1 ? full : full.slice(0, q) + rewritten + full.slice(q + url.length);
    });
  }

  html = html.replace(/url\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi, (match, q, url) => {
    const r = rwNoOpts(url);
    return r !== url ? `url(${q}${r}${q})` : match;
  });
  html = html.replace(/@import\s+(['"])([^'"]+)\1/gi, (match, q, url) => {
    const r = rwNoOpts(url);
    return r !== url ? `@import ${q}${r}${q}` : match;
  });

  html = html.replace(/<meta\s+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, "");
  html = html.replace(/\s+target\s*=\s*["']?[^"'\s>]+["']?/gi, "");
  return html;
}

function experimentalRewriteCss(css, base, optSuffix = "") {
  const rw = (url) => rewriteUrlPe(url, base, optSuffix);
  return css
    .replace(/url\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi, (match, q, url) => {
      const r = rw(url);
      return r !== url ? `url(${q}${r}${q})` : match;
    })
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (match, q, url) => {
      const r = rw(url);
      return r !== url ? `@import ${q}${r}${q}` : match;
    });
}

function experimentalRewriteJs(js, base, optSuffix) {
  const safeBase = (base || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  const encPeJs = `function E(u){try{if(!u||typeof u!=='string')return u;if(u.startsWith('/pe/'))return u;var a=new URL(u,'${safeBase}').href;if(/^https?:/.test(a))return'/pe/'+btoa(a).replace(/\\\\+/g,'-').replace(/\\\\//g,'_').replace(/=+$/g,'');return u;}catch(e){return u;}}`;
  const wsEnc = (url) => {
    try {
      if (!url || typeof url !== "string") return url;
      const u = url.trim();
      if (u.startsWith("/pe-ws/")) return u;
      const abs = new URL(u, base).href;
      if (/^wss?:/.test(abs))
        return "/pe-ws/" + btoa(abs).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      return url;
    } catch {
      return url;
    }
  };

  let out = js
    .replace(/\bfetch\s*\(\s*["']([^"']+)["']/gi, (_, url) => `fetch(E("${rewriteUrlPe(url, base, optSuffix).replace(/"/g, '\\"')}")`)
    .replace(/\b(src|href)\s*=\s*["']([^"']+)["']/gi, (_, attr, url) => {
      const r = rewriteUrlPe(url, base, optSuffix);
      return r !== url ? `${attr}="${r}"` : _;
    });
  return out;
}

function injectionScriptExperimental(base, optSuffix, proxyHost) {
  const safeBase = (base || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  const suffix = (optSuffix || "").replace(/'/g, "\\'");
  return `<script data-void="1">
(function(){
  var B='${safeBase}', S='${suffix}';
  function E(u){
    try{
      if(!u||typeof u!=='string')return u;
      if(u.startsWith('/pe/'))return u;
      var a=new URL(u,B).href;
      if(a.startsWith('http'))return'/pe/'+btoa(a).replace(/\\\\+/g,'-').replace(/\\\\//g,'_').replace(/=+$/g,'')+S;
      return u;
    }catch(e){return u;}
  }
  function Ws(u){
    try{
      if(!u||typeof u!=='string')return u;
      if(u.startsWith('/pe-ws/'))return u;
      var a=new URL(u,B).href;
      if(/^wss?:/.test(a))return'/pe-ws/'+btoa(a).replace(/\\\\+/g,'-').replace(/\\\\//g,'_').replace(/=+$/g,'');
      return u;
    }catch(e){return u;}
  }
  var _f=window.fetch;
  window.fetch=function(u,o){
    if(typeof u==='string')u=E(u);
    else if(u&&u.url)u=new Request(E(u.url),u);
    return _f.call(this,u,o);
  };
  var _xo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){
    arguments[1]=E(u);
    return _xo.apply(this,arguments);
  };
  var _Ws=window.WebSocket;
  window.WebSocket=function(u){
    return new _Ws(Ws(u));
  };
  var _wo=window.open;
  window.open=function(u,w){
    if(u&&typeof u==='string'){
      var eu=E(u);
      if(eu!==u){
        if(w==='_blank')return _wo(eu,'_blank');
        window.location.href=eu;return null;
      }
    }
    return _wo.apply(this,arguments);
  };
  var _ps=History.prototype.pushState;
  History.prototype.pushState=function(s,t,u){if(u)arguments[2]=E(u);return _ps.apply(this,arguments);};
  var _rs=History.prototype.replaceState;
  History.prototype.replaceState=function(s,t,u){if(u)arguments[2]=E(u);return _rs.apply(this,arguments);};
  document.addEventListener('click',function(e){
    var t=e.target;
    while(t&&t.tagName!=='A')t=t.parentElement;
    if(!t)return;
    var raw=t.getAttribute('href');
    if(!raw||raw==='/'||raw===''||raw.startsWith('/pe/')||raw.startsWith('javascript:')||raw.startsWith('#')||raw.startsWith('data:')||raw.startsWith('mailto:'))return;
    t.removeAttribute('target');
    try{
      var abs=new URL(raw,B).href;
      if((abs.startsWith('http://')||abs.startsWith('https://'))&&!abs.startsWith(location.origin)){e.preventDefault();window.location.href=E(abs);}
    }catch(err){}
  },true);
  document.addEventListener('submit',function(e){
    var f=e.target;
    if(!f||f.tagName!=='FORM')return;
    var a=f.getAttribute('action')||'';
    if(!a||a.startsWith('/pe/'))return;
    try{
      var abs=new URL(a,B).href;
      if((abs.startsWith('http')||abs.startsWith('https'))&&!abs.startsWith(location.origin))f.action=E(abs);
    }catch(err){}
  },true);
})();
</script>`;
}

function requestWithNode(targetUrl, opts) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const isHttps = u.protocol === "https:";
    const lib = isHttps ? https : http;
    const reqOpts = {
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      method: opts.method || "GET",
      headers: opts.headers || {},
      rejectUnauthorized: true,
    };
    const req = lib.request(reqOpts, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ res, body: Buffer.concat(chunks), chunks }));
      res.on("error", reject);
    });
    req.on("error", reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function decompressBody(body, encoding) {
  const enc = (encoding || "").toLowerCase();
  if (enc === "gzip") return new Promise((res, rej) => {
    const gunzip = createGunzip();
    const out = [];
    gunzip.on("data", (c) => out.push(c));
    gunzip.on("end", () => res(Buffer.concat(out)));
    gunzip.on("error", rej);
    gunzip.write(body);
    gunzip.end();
  });
  if (enc === "deflate") return new Promise((res, rej) => {
    const inflate = createInflate();
    const out = [];
    inflate.on("data", (c) => out.push(c));
    inflate.on("end", () => res(Buffer.concat(out)));
    inflate.on("error", rej);
    inflate.write(body);
    inflate.end();
  });
  if (enc === "br") return new Promise((res, rej) => {
    const br = createBrotliDecompress();
    const out = [];
    br.on("data", (c) => out.push(c));
    br.on("end", () => res(Buffer.concat(out)));
    br.on("error", rej);
    br.write(body);
    br.end();
  });
  return Promise.resolve(body);
}

async function handleExperimentalProxy(req, res) {
  let targetUrl;
  try {
    targetUrl = decPe(req.params.encoded);
  } catch {
    return res.status(400).send("Invalid URL encoding");
  }
  if (!/^https?:\/\//i.test(targetUrl)) {
    return res.status(400).send("Invalid URL");
  }

  const opts = { nojs: req.query.nojs === "1", noimg: req.query.noimg === "1" };
  const optQs = [];
  if (opts.nojs) optQs.push("nojs=1");
  if (opts.noimg) optQs.push("noimg=1");
  const optSuffix = optQs.length ? "?" + optQs.join("&") : "";

  const proxyHost = req.headers.host || "localhost";

  try {
    const headers = buildStealthHeaders(targetUrl, req);
    let body;
    if (req.method === "POST" && req.body) {
      body = typeof req.body === "object" ? new URLSearchParams(req.body).toString() : req.body;
      headers["content-length"] = Buffer.byteLength(body);
    }

    const { res: upstream, body: rawBody } = await requestWithNode(targetUrl, {
      method: req.method,
      headers,
      body,
    });

    if ([301, 302, 303, 307, 308].includes(upstream.statusCode)) {
      const loc = upstream.headers.location;
      if (loc) {
        const abs = new URL(loc, targetUrl).href;
        return res.redirect(upstream.statusCode, encPe(abs) + optSuffix);
      }
    }

    const contentType = (upstream.headers["content-type"] || "").toLowerCase();
    const contentEncoding = (upstream.headers["content-encoding"] || "").toLowerCase();

    let bodyBuffer = rawBody;
    let decompressed = true;
    if (contentEncoding && bodyBuffer.length) {
      try {
        bodyBuffer = await decompressBody(bodyBuffer, contentEncoding);
      } catch (_) {
        decompressed = false;
      }
    }

    for (const [k, v] of Object.entries(upstream.headers)) {
      const kl = k.toLowerCase();
      if (STRIP_RESPONSE_HEADERS.has(kl)) continue;
      if (!decompressed && (kl === "content-encoding" || kl === "content-length")) continue;
      if (kl === "set-cookie") {
        const remapped = remapSetCookie(v, proxyHost);
        res.append("set-cookie", remapped);
        continue;
      }
      try {
        res.set(k, v);
      } catch {}
    }

    if (contentType.includes("text/html")) {
      if (!decompressed) {
        res.set("content-type", upstream.headers["content-type"] || "text/html; charset=utf-8");
        if (contentEncoding) res.set("content-encoding", contentEncoding);
        res.set("content-length", rawBody.length);
        return res.send(rawBody);
      }
      let html = bodyBuffer.toString("utf8");
      html = experimentalRewriteHtml(html, targetUrl, optSuffix);
      const barHtml = proxyBar(targetUrl);
      const scriptHtml = opts.nojs ? "" : injectionScriptExperimental(targetUrl, optSuffix, proxyHost);
      html = html.replace(/<body\s*/i, `<body>${barHtml}${scriptHtml}`);
      res.type("text/html; charset=utf-8").send(html);
      return;
    }
    if (contentType.includes("text/css")) {
      if (!decompressed) {
        res.set("content-type", upstream.headers["content-type"] || "text/css; charset=utf-8");
        if (contentEncoding) res.set("content-encoding", contentEncoding);
        res.set("content-length", rawBody.length);
        return res.send(rawBody);
      }
      const css = experimentalRewriteCss(bodyBuffer.toString("utf8"), targetUrl, optSuffix);
      res.type("text/css; charset=utf-8").send(css);
      return;
    }
    if (contentType.includes("javascript")) {
      res.type(upstream.headers["content-type"] || "application/javascript");
      res.send(bodyBuffer);
      return;
    }

    res.set("content-type", upstream.headers["content-type"] || "application/octet-stream");
    res.send(bodyBuffer);
  } catch (err) {
    const isLogOrAnalytics = /\.(google|googleapis|gstatic)\.com\/(log|analytics|collect|gen_204)/i.test(targetUrl || "") || /\/(log|analytics|collect|beacon|ping)(\?|&|$)/i.test(targetUrl || "");
    if (!isLogOrAnalytics) console.error("[experimental proxy error]", targetUrl, err.message);
    const safeTarget = (targetUrl || "").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const safeErr = (err.message || "Unknown error").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    res.status(502).send(`<!DOCTYPE html><html><head><meta charset="utf-8"/><title>Void Experimental - Error</title></head><body><h1>502</h1><p>${safeTarget}</p><p>${safeErr}</p><a href="/">Back</a></body></html>`);
  }
}

function handlePeWsUpgrade(req, socket, head) {
  const path = req.url || "";
  const match = path.match(/^\/pe-ws\/([A-Za-z0-9_-]+)/);
  if (!match) {
    socket.destroy();
    return;
  }
  let targetWsUrl;
  try {
    targetWsUrl = decPe(match[1]);
  } catch {
    socket.destroy();
    return;
  }
  if (!/^wss?:\/\//i.test(targetWsUrl)) {
    socket.destroy();
    return;
  }
  const u = new URL(targetWsUrl);
  const isWss = u.protocol === "wss:";
  const port = parseInt(u.port, 10) || (isWss ? 443 : 80);
  const key = req.headers["sec-websocket-key"] || "";
  const accept = createHash("sha1").update(key + "258EAFA5-E907-79C0-96EC-E2C3F2E2612D").digest("base64");

  socket.write(
    `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`
  );

  const pathQuery = u.pathname + u.search;
  const wsKey = Buffer.from(u.hostname + Date.now() + Math.random()).toString("base64").replace(/=+$/, "");
  const targetReq =
    `GET ${pathQuery} HTTP/1.1\r\nHost: ${u.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${wsKey}\r\nSec-WebSocket-Version: 13\r\nOrigin: ${u.origin}\r\n\r\n`;

  const conn = isWss
    ? tls.connect(port, u.hostname, { servername: u.hostname }, () => {})
    : net.connect(port, u.hostname, () => {});

  let targetHandshakeDone = false;
  let handshakeBuf = Buffer.alloc(0);
  const clientBuf = [];

  conn.on("data", (chunk) => {
    if (!targetHandshakeDone) {
      handshakeBuf = Buffer.concat([handshakeBuf, chunk]);
      if (handshakeBuf.indexOf("\r\n\r\n") !== -1) {
        targetHandshakeDone = true;
        const bodyStart = handshakeBuf.indexOf("\r\n\r\n") + 4;
        if (bodyStart < handshakeBuf.length) socket.write(handshakeBuf.subarray(bodyStart));
        while (clientBuf.length) conn.write(clientBuf.shift());
      }
      return;
    }
    socket.write(chunk);
  });

  conn.on("error", () => {
    socket.destroy();
    conn.destroy();
  });
  socket.on("error", () => {
    socket.destroy();
    conn.destroy();
  });

  socket.on("data", (data) => {
    if (targetHandshakeDone) conn.write(data);
    else clientBuf.push(data);
  });

  conn.write(targetReq);
  if (head && head.length) conn.write(head);
}

/* ═══════════════════════════════════════════
   Routes
   ═══════════════════════════════════════════ */

const SEARCH_ENGINES = {
  brave:   q => "https://search.brave.com/search?q=" + encodeURIComponent(q),
  google:  q => "https://www.google.com/search?q=" + encodeURIComponent(q),
  ddg:     q => "https://duckduckgo.com/?q=" + encodeURIComponent(q),
  bing:    q => "https://www.bing.com/search?q=" + encodeURIComponent(q),
  yahoo:   q => "https://search.yahoo.com/search?p=" + encodeURIComponent(q),
};

app.get("/go", (req, res) => {
  let url = (req.query.url || "").trim();
  if (!url) return res.redirect("/");

  const engine = req.query.engine || "brave";

  if (!/^https?:\/\//i.test(url)) {
    if (url.includes(".") && !url.includes(" ")) {
      url = "https://" + url;
    } else {
      const searchFn = SEARCH_ENGINES[engine] || SEARCH_ENGINES.ddg;
      url = searchFn(url);
    }
  }

  const qs = [];
  if (req.query.nojs === "1") qs.push("nojs=1");
  if (req.query.noimg === "1") qs.push("noimg=1");
  const qsStr = qs.length ? "?" + qs.join("&") : "";

  const mode = (req.query.mode || "server").toLowerCase().trim();
  if (mode === "experimental") {
    return res.redirect(encPe(url) + qsStr);
  }
  res.redirect(enc(url) + qsStr);
});

app.get("/p/:encoded", handleProxy);
app.post("/p/:encoded", handleProxy);

app.get("/pe/:encoded", handleExperimentalProxy);
app.post("/pe/:encoded", handleExperimentalProxy);

app.get("/{*path}", (_req, res) => {
  res.sendFile(join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 8080;
const server = createServer(app);

server.on("upgrade", (req, socket, head) => {
  if ((req.url || "").startsWith("/pe-ws/")) {
    handlePeWsUpgrade(req, socket, head);
  } else {
    socket.destroy();
  }
});

server.listen(PORT, () => console.log(`Void proxy running on http://localhost:${PORT}`));
