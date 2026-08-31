import express from "express";
import axios from "axios";
import http, { createServer } from "node:http";
import https from "node:https";
import dns from "node:dns";
import net from "node:net";
import tls from "node:tls";
import { createHash } from "node:crypto";
import { createUnzip, createInflateRaw, createBrotliDecompress } from "node:zlib";
import * as cheerio from "cheerio";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import * as wisp from "@mercuryworkshop/wisp-js/server";
import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";

// Load .env manually
try {
  const envPath = join(dirname(fileURLToPath(import.meta.url)), ".env");
  const envLines = readFileSync(envPath, "utf8").split("\n");
  for (const line of envLines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
    if (key && !(key in process.env)) process.env[key] = val;
  }
} catch { /* .env optional */ }

const SERPER_API_KEY = process.env.SERPER_API_KEY || "b0bc542c982089c356327a42e18db7fe42815dfc";
const SERPAPI_KEY = process.env.SERPAPI_KEY || "707a83bd5fcf248d7e6b242a8f458677fa5e1c6e34c618bc596103d59c87665e";

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
app.set("json spaces", 2);

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 512, maxFreeSockets: 64, timeout: 25000 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 512, maxFreeSockets: 64, timeout: 25000 });

/* ═══════════════════════════════════════════
   IP / SSRF Security Validation
   ═══════════════════════════════════════════ */

const isPrivateV4 = (ip) => {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return true;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
};

const isPrivateV6 = (ip) => {
  const v = ip.toLowerCase();
  if (v === "::" || v === "::1") return true;
  if (v.startsWith("::ffff:")) return isPrivateV4(v.slice(7));
  return /^f[cd]/i.test(v) || /^fe[89ab]/i.test(v);
};

async function assertSafeUrl(rawUrl) {
  const u = new URL(rawUrl);
  if (!["http:", "https:"].includes(u.protocol)) {
    throw new Error("Unsupported protocol");
  }
  const host = u.hostname.replace(/^\[(.*)\]$/, "$1");
  if (
    host === "metadata.google.internal" ||
    host === "localhost" ||
    /\.(local|internal|localhost)$/i.test(host)
  ) {
    throw new Error("Access to internal/private domains is blocked.");
  }

  if (net.isIP(host)) {
    if (net.isIPv4(host) ? isPrivateV4(host) : isPrivateV6(host)) {
      throw new Error("Access to private IP space is blocked.");
    }
    return;
  }

  const addrs = await dns.promises.lookup(host, { all: true });
  if (!addrs || addrs.length === 0) {
    throw new Error("DNS resolution failed");
  }
  for (const a of addrs) {
    if (net.isIPv4(a.address) ? isPrivateV4(a.address) : isPrivateV6(a.address)) {
      throw new Error("Domain points to forbidden private network.");
    }
  }
}

/* ═══════════════════════════════════════════
   LRU Cache & Fast In-Memory Storage
   ═══════════════════════════════════════════ */

const CACHE_MAX_SIZE = 2000;
const CACHE_TTL = 30 * 60 * 1000;
const _resourceCache = new Map();

function cacheGet(key) {
  const entry = _resourceCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) {
    _resourceCache.delete(key);
    return null;
  }
  _resourceCache.delete(key);
  _resourceCache.set(key, entry);
  return entry;
}

function cacheSet(key, ct, body) {
  if (!body) return;
  const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  if (bodyBuf.length > 2 * 1024 * 1024) return;

  if (_resourceCache.size >= CACHE_MAX_SIZE) {
    const oldest = _resourceCache.keys().next().value;
    _resourceCache.delete(oldest);
  }
  _resourceCache.set(key, { ct, body: bodyBuf, ts: Date.now() });
}

/* ═══════════════════════════════════════════
   Express Configuration
   ═══════════════════════════════════════════ */

app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.json({ limit: "10mb" }));
app.use(express.raw({ type: "*/*", limit: "10mb" }));

app.use(express.static(join(__dirname, "public"), {
  maxAge: "1d",
  etag: true,
  lastModified: true,
  setHeaders: (res, path) => {
    if (path.endsWith("sw.js")) {
      res.setHeader("Service-Worker-Allowed", "/");
    }
  }
}));

app.use("/scramjet/", express.static(scramjetPath));
app.use("/baremux/", express.static(baremuxPath));
app.use("/epoxy/", express.static(join(__dirname, "node_modules", "@mercuryworkshop", "epoxy-transport", "dist")));

/* ═══════════════════════════════════════════
   Encoding Helpers
   ═══════════════════════════════════════════ */

function enc(url) {
  const key = "Void2026";
  let chars = [];
  for (let i = 0; i < url.length; i++) {
    chars.push(String.fromCharCode(url.charCodeAt(i) ^ key.charCodeAt(i % key.length)));
  }
  return "/p/" + Buffer.from(chars.join(""), "binary").toString("base64url") + ".www.securly.com";
}

function dec(encoded) {
  try {
    let str = String(encoded).trim();
    if (!str) return "";
    if (/^https?:\/\//i.test(str) || str.includes(" ")) return str;

    const dotIdx = str.indexOf(".");
    if (dotIdx > 0) str = str.substring(0, dotIdx);

    const normalized = str.replace(/-/g, "+").replace(/_/g, "/");
    const padding = normalized.length % 4;
    const padded = padding ? normalized + "=".repeat(4 - padding) : normalized;
    const rawBinary = Buffer.from(padded, "base64").toString("binary");

    const key = "Void2026";
    let decChars = [];
    for (let i = 0; i < rawBinary.length; i++) {
      decChars.push(String.fromCharCode(rawBinary.charCodeAt(i) ^ key.charCodeAt(i % key.length)));
    }
    const multiDecoded = decChars.join("");
    if (multiDecoded && /^[\x20-\x7E\s]+$/.test(multiDecoded)) {
      if (multiDecoded.substring(4, 6) === "||") return multiDecoded.substring(6);
      return multiDecoded;
    }

    const decodedUtf8 = Buffer.from(padded, "base64").toString("utf8");
    if (decodedUtf8 && /^[\x20-\x7E\s]+$/.test(decodedUtf8)) return decodedUtf8;

    return str;
  } catch {
    return String(encoded || "");
  }
}

function encPe(url) {
  return "/pe/" + Buffer.from(url, "utf8").toString("base64url");
}

function decPe(encoded) {
  try {
    let str = String(encoded).trim();
    const dotIdx = str.indexOf(".");
    if (dotIdx > 0) str = str.substring(0, dotIdx);
    const url = Buffer.from(str, "base64url").toString("utf8");
    if (!/^https?:\/\//i.test(url)) throw new Error("Not a valid URL");
    return url;
  } catch (e) {
    throw new Error(`URL decode failed: ${e.message}`);
  }
}

function normalizeAbsoluteUrl(raw, base) {
  if (!raw || typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (/^(data:|blob:|javascript:|#|mailto:|about:)/i.test(trimmed)) return null;
  try {
    if (trimmed.startsWith("//")) return new URL("https:" + trimmed).href;
    return new URL(trimmed, base).href;
  } catch {
    return null;
  }
}

function rewriteUrl(raw, base) {
  const abs = normalizeAbsoluteUrl(raw, base);
  return abs ? enc(abs) : raw;
}

function rewriteUrlPe(raw, base, optSuffix = "") {
  const abs = normalizeAbsoluteUrl(raw, base);
  return abs ? encPe(abs) + optSuffix : raw;
}

function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi, (match, q, url) => {
      const r = rewriteUrl(url, base);
      return r !== url ? `url(${q}${r}${q})` : match;
    })
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (match, q, url) => {
      const r = rewriteUrl(url, base);
      return r !== url ? `@import ${q}${r}${q}` : match;
    });
}

function rewriteCssPe(css, base, optSuffix = "") {
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

function rewriteEmbeddedUrls(text, base, encodeFn = enc) {
  if (!text) return text;
  function rw(url) {
    try {
      return encodeFn(new URL(url, base).href);
    } catch {
      return url;
    }
  }
  text = text.replace(/(["'`])(\/\/[^"'`\s\\]+)\1/g, (m, q, url) => {
    if (url.startsWith("/p/") || url.startsWith("/pe/")) return m;
    try {
      return q + rw(new URL("https:" + url).href) + q;
    } catch {
      return m;
    }
  });
  text = text.replace(/(["'`])(https?:\/\/[^"'`\s\\]+)\1/g, (m, q, url) =>
    url.startsWith("/p/") || url.startsWith("/pe/") ? m : q + rw(url) + q
  );
  if (base) {
    text = text.replace(/(["'])(\/((?!\/)[^"'\s\\]*\.[a-zA-Z0-9]{2,6}[^"']*))(\1)/g, (m, q1, url, _inner, q2) => {
      if (url.startsWith("/p/") || url.startsWith("/pe/")) return m;
      try {
        const abs = new URL(url, base).href;
        if (!abs.startsWith("http")) return m;
        return q1 + rw(abs) + q2;
      } catch {
        return m;
      }
    });
  }
  return text;
}

function rewriteJsUrls(code, base, prefix) {
  if (!code) return code;
  const encodeFn = prefix === "/pe/" ? encPe : enc;
  function rw(url) {
    try {
      return encodeFn(new URL(url, base).href);
    } catch {
      return url;
    }
  }
  code = code.replace(/((?:import|export)\s+[\s\S]*?\bfrom\s+)(["'])(https?:\/\/[^"'\s]+)\2/g, (m, pre, q, url) => pre + q + rw(url) + q);
  code = code.replace(/\bimport\s*\(\s*(["'`])(https?:\/\/[^"'`\s]+)\1/g, (m, q, url) => `import(${q}${rw(url)}${q}`);
  code = code.replace(/\bimportScripts\s*\(([^)]*)\)/g, (m, args) => {
    const rArgs = args.replace(/(["'])(https?:\/\/[^"'\s]+)\1/g, (_, q, url) => q + rw(url) + q);
    return `importScripts(${rArgs})`;
  });
  code = code.replace(/\bnew\s+Worker\s*\(\s*(["'])(https?:\/\/[^"'\s]+)\1/g, (m, q, url) => `new Worker(${q}${rw(url)}${q}`);
  code = code.replace(/\bnew\s+SharedWorker\s*\(\s*(["'])(https?:\/\/[^"'\s]+)\1/g, (m, q, url) => `new SharedWorker(${q}${rw(url)}${q}`);

  if (code.length < 1000000) {
    return rewriteEmbeddedUrls(code, base, encodeFn);
  }
  return code;
}

/* ═══════════════════════════════════════════
   DOM Injection & Client Runtime
   ═══════════════════════════════════════════ */

function injectionScript(base) {
  return `<script data-void="1">
(function(){
  var B=${JSON.stringify(base)};
  var SKIP=/^(data:|blob:|javascript:|#|mailto:|about:)/i;

  function toAbs(u){
    if(!u||typeof u!=="string")return null;
    var t=u.trim();
    if(t.startsWith("/p/")||t.startsWith("/pe/")||t.startsWith("/v")||t.startsWith("/s")||t.startsWith("/go"))return null;
    if(SKIP.test(t))return null;
    try{
      if(t.startsWith("//"))return "https:"+t;
      return new URL(t,B).href;
    }catch(e){return null;}
  }

  function E(u){
    var abs=toAbs(u);
    if(!abs||!abs.startsWith("http"))return u;
    var key="Void2026",chars=[];
    for(var i=0;i<abs.length;i++)chars.push(String.fromCharCode(abs.charCodeAt(i)^key.charCodeAt(i%key.length)));
    var tld="";try{tld=localStorage.getItem("void_tld")||".www.securly.com";}catch(e){tld=".www.securly.com";}
    return "/p/"+btoa(chars.join("")).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"")+tld;
  }

  function Esrcset(v){if(!v)return v;return v.replace(/([^\\s,]+)(\\s+[^,]*)?/g,function(_,u,d){return E(u)+(d||'');});}

  var _f=window.fetch;
  window.fetch=function(u,o){
    if(typeof u==='string')u=E(u);
    else if(u&&u.url)return _f.call(this,E(u.url),u);
    return _f.call(this,u,o);
  };
  var _xo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){arguments[1]=E(u);return _xo.apply(this,arguments);};
  var _wo=window.open;
  window.open=function(u){if(u&&typeof u==='string')arguments[0]=E(u);return _wo.apply(this,arguments);};
  var _ps=History.prototype.pushState;
  History.prototype.pushState=function(s,t,u){if(u)arguments[2]=E(u);return _ps.apply(this,arguments);};
  var _rs=History.prototype.replaceState;
  History.prototype.replaceState=function(s,t,u){if(u)arguments[2]=E(u);return _rs.apply(this,arguments);};

  if(navigator.serviceWorker){
    var _swr=navigator.serviceWorker.register.bind(navigator.serviceWorker);
    navigator.serviceWorker.register=function(u,o){return _swr(E(u),o);};
  }

  var desc=Object.getOwnPropertyDescriptor(HTMLImageElement.prototype,'src');
  if(desc&&desc.set){
    Object.defineProperty(HTMLImageElement.prototype,'src',{
      get:desc.get,
      set:function(v){desc.set.call(this,E(v));},
      configurable:true,
      enumerable:true
    });
  }

  var _sa=Element.prototype.setAttribute;
  var LAZY_TAGS={'src':1,'data-src':1,'data-lazy-src':1,'data-thumb':1,'data-original':1,'data-hero':1,'href':1,'action':1,'poster':1};
  Element.prototype.setAttribute=function(name,val){
    var n=name.toLowerCase();
    if(val&&typeof val==='string'&&LAZY_TAGS[n]){
      if(n==='srcset'||n==='data-srcset')val=Esrcset(val);
      else val=E(val);
    }
    return _sa.call(this,name,val);
  };

  document.addEventListener('click',function(e){
    var t=e.target;while(t&&t.tagName!=='A')t=t.parentElement;if(!t)return;
    if(t.closest('#__vbar'))return;
    var raw=t.getAttribute('href');if(!raw||raw==='/'||raw==='')return;
    t.removeAttribute('target');
    var abs=toAbs(raw);
    if(abs&&abs.startsWith('http')){
      e.preventDefault();
      location.href=E(abs);
    }
  },true);

  document.addEventListener('submit',function(e){
    var f=e.target;if(!f||f.tagName!=='FORM')return;
    if(f.closest('#__vbar'))return;
    var a=f.getAttribute('action')||'';
    var abs=toAbs(a);
    if(abs&&abs.startsWith('http'))f.action=E(abs);
  },true);
})();
</script>`;
}

function injectionScriptExperimental(base, optSuffix) {
  return `<script data-void="1">
(function(){
  var B=${JSON.stringify(base)};
  var S=${JSON.stringify(optSuffix || "")};
  var SKIP=/^(data:|blob:|javascript:|#|mailto:|about:)/i;

  function toAbs(u){
    if(!u||typeof u!=="string")return null;
    var t=u.trim();
    if(t.startsWith("/pe/")||t.startsWith("/v")||t.startsWith("/s")||t.startsWith("/go"))return null;
    if(SKIP.test(t))return null;
    try{
      if(t.startsWith("//"))return "https:"+t;
      return new URL(t,B).href;
    }catch(e){return null;}
  }

  function E(u){
    var abs=toAbs(u);
    if(!abs||!abs.startsWith("http"))return u;
    var tld="";try{tld=localStorage.getItem("void_tld")||".www.securly.com";}catch(e){tld=".www.securly.com";}
    return "/pe/"+btoa(abs).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"")+tld+S;
  }

  var _f=window.fetch;
  window.fetch=function(u,o){
    if(typeof u==='string')u=E(u);
    else if(u&&u.url)return _f.call(this,E(u.url),u);
    return _f.call(this,u,o);
  };
  var _xo=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u){arguments[1]=E(u);return _xo.apply(this,arguments);};

  var _sa=Element.prototype.setAttribute;
  var LAZY_TAGS={'src':1,'data-src':1,'data-lazy-src':1,'data-thumb':1,'data-original':1,'data-hero':1,'href':1,'action':1};
  Element.prototype.setAttribute=function(name,val){
    var n=name.toLowerCase();
    if(val&&typeof val==='string'&&LAZY_TAGS[n]) val=E(val);
    return _sa.call(this,name,val);
  };
})();
</script>`;
}

function proxyBar(displayUrl) {
  const safe = displayUrl.replace(/&/g, "&amp;").replace(/'/g, "&#39;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  let domain = "";
  try { domain = new URL(displayUrl).hostname; } catch {}
  const favicon = domain ? `https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=32` : "";
  const faviconHtml = favicon
    ? `<img src="${favicon}" style="width:14px;height:14px;border-radius:2px;flex-shrink:0;" onerror="this.style.display='none'" alt=""/>`
    : "";
  return `<div id="__vbar" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;height:42px;display:flex;align-items:center;gap:8px;padding:0 12px;background:#ffffff;border-bottom:1px solid #000000;font-family:'Times New Roman',Times,serif;font-size:14px;color:#000000;box-sizing:border-box;">
<a href="/" style="color:#000000;font-weight:bold;text-decoration:none;font-size:18px;text-transform:uppercase;">void</a>
<span style="color:#555555;font-size:14px;margin-left:4px;white-space:nowrap;">Go Anywhere</span>
<button onclick="history.back()" style="background:#eeeeee;border:1px solid #000000;color:#000000;padding:2px 8px;cursor:pointer;font-family:'Times New Roman',Times,serif;" title="Back">&larr;</button>
<button onclick="history.forward()" style="background:#eeeeee;border:1px solid #000000;color:#000000;padding:2px 8px;cursor:pointer;font-family:'Times New Roman',Times,serif;" title="Forward">&rarr;</button>
<button onclick="location.reload()" style="background:#eeeeee;border:1px solid #000000;color:#000000;padding:2px 8px;cursor:pointer;font-family:'Times New Roman',Times,serif;" title="Reload">&#8635;</button>
<form action="/v" method="GET" style="flex:1;display:flex;align-items:center;background:#ffffff;border:1px solid #000000;padding:2px 8px;gap:6px;margin:0;">
  <input type="hidden" name="mode" value="server" />
  ${faviconHtml}
  <input type="text" name="q" value="${safe}" style="flex:1;border:none;outline:none;background:transparent;font-family:'Times New Roman',Times,serif;font-size:13px;color:#000000;min-width:0;" autocomplete="off" spellcheck="false" />
</form>
<a href="/" style="padding:2px 10px;background:#eeeeee;color:#000000;text-decoration:none;border:1px solid #000000;">Home</a>
<button onclick="document.getElementById('__vbar').style.display='none';document.getElementById('__vsp').style.display='none';" style="padding:2px 8px;background:#eeeeee;color:#000000;border:1px solid #000000;cursor:pointer;font-family:'Times New Roman',Times,serif;" aria-label="Close toolbar">&#x2715;</button>
</div>
<div id="__vsp" style="height:42px;"></div>`;
}

/* ═══════════════════════════════════════════
   Headers Management & Fast Passthrough
   ═══════════════════════════════════════════ */

const HOP_HEADERS = new Set([
  "host", "connection", "keep-alive", "transfer-encoding",
  "te", "upgrade", "proxy-authorization", "proxy-connection",
]);

const STRIP_HEADERS = new Set([
  "content-security-policy", "content-security-policy-report-only",
  "x-frame-options", "strict-transport-security", "transfer-encoding",
  "cross-origin-opener-policy", "cross-origin-embedder-policy",
  "cross-origin-resource-policy", "permissions-policy",
  "x-content-type-options", "report-to", "link", "alt-svc", "clear-site-data", "nel",
]);

const URL_ATTRS = {
  a: ["href", "ping"], area: ["href"], link: ["href"],
  img: ["src", "srcset", "data-src", "data-srcset", "data-lazy-src", "data-original", "data-thumb", "data-hero"],
  script: ["src"], source: ["src", "srcset"], video: ["src", "poster", "data-src"],
  audio: ["src"], embed: ["src"], object: ["data"], form: ["action"],
  input: ["src", "formaction"], track: ["src"], iframe: ["src"],
  button: ["formaction"], body: ["background"], table: ["background"],
  td: ["background"], th: ["background"],
};

const BINARY_TYPE_PREFIXES = [
  "video/", "audio/", "image/", "application/wasm",
  "application/octet-stream", "font/", "application/font-woff", "application/x-font-ttf",
];

function cookiePrefix(hostname) {
  return "__v_" + Buffer.from(hostname).toString("base64url").slice(0, 8) + "_";
}

function scopeCookiesForTarget(rawCookieHeader, targetUrl) {
  if (!rawCookieHeader) return "";
  try {
    const prefix = cookiePrefix(new URL(targetUrl).hostname);
    return rawCookieHeader
      .split(";")
      .map((c) => c.trim())
      .filter((c) => c.startsWith(prefix))
      .map((c) => c.slice(prefix.length))
      .join("; ");
  } catch {
    return rawCookieHeader;
  }
}

function prefixSetCookie(rawSetCookie, targetUrl) {
  try {
    const prefix = cookiePrefix(new URL(targetUrl).hostname);
    const eqIdx = rawSetCookie.indexOf("=");
    if (eqIdx === -1) return rawSetCookie;
    const name = rawSetCookie.slice(0, eqIdx);
    const rest = rawSetCookie.slice(eqIdx);
    return (prefix + name + rest)
      .replace(/;\s*domain=[^;]*/gi, "")
      .replace(/;\s*secure/gi, "")
      .replace(/;\s*samesite=[^;]*/gi, "; samesite=lax")
      .replace(/;\s*path=[^;]*/gi, "; path=/");
  } catch {
    return rawSetCookie;
  }
}

function buildHeaders(req, targetUrl) {
  const h = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const kl = k.toLowerCase();
    if (HOP_HEADERS.has(kl)) continue;
    if (kl === "referer" || kl === "origin" || kl === "host" || kl === "cookie") continue;
    if (kl.startsWith("x-vercel-") || kl.startsWith("x-forwarded-") || kl === "forwarded" || kl === "via" || kl === "x-real-ip" || kl.startsWith("x-void-")) continue;
    h[k] = v;
  }
  try {
    const u = new URL(targetUrl);
    h["host"] = u.host;
    h["referer"] = u.origin + "/";
    h["origin"] = u.origin;
  } catch (e) {
    console.error("[proxy] buildHeaders invalid targetUrl:", e.message);
  }
  const scoped = scopeCookiesForTarget(req.headers.cookie, targetUrl);
  if (scoped) h["cookie"] = scoped;
  if (!h["user-agent"]) {
    h["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
  }
  if (req.headers.range) h["range"] = req.headers.range;
  h["accept-encoding"] = "gzip, deflate, br";
  return h;
}

function decompressStream(stream, encoding) {
  const encType = (encoding || "").toLowerCase().trim();
  if (encType === "gzip" || encType === "deflate") {
    const unzip = createUnzip();
    unzip.on("error", () => stream.pipe(createInflateRaw()));
    return stream.pipe(unzip);
  }
  if (encType === "br") return stream.pipe(createBrotliDecompress());
  return stream;
}

/* ═══════════════════════════════════════════
   High-Speed Proxy Request Handler (/p/)
   ═══════════════════════════════════════════ */

async function handleProxy(req, res) {
  let targetUrl;
  try {
    targetUrl = dec(req.params.encoded);
  } catch {
    return res.status(400).send("Invalid URL encoding");
  }

  try {
    await assertSafeUrl(targetUrl);
  } catch (err) {
    return res.status(403).send("Forbidden URL destination: " + err.message);
  }

  if (/(\/fd\/ls\/|bat\.bing\.com\/action\/|clarity\.ms\/collect)/i.test(targetUrl)) {
    return res.status(204).end();
  }

  if (req.method === "GET" && req.query && Object.keys(req.query).length > 0) {
    try {
      const u = new URL(targetUrl);
      for (const [k, v] of Object.entries(req.query)) {
        if (["nojs", "noimg", "eruda", "mode", "engine"].includes(k)) continue;
        if (Array.isArray(v)) v.forEach((item) => u.searchParams.append(k, item));
        else if (!u.searchParams.has(k)) u.searchParams.append(k, v);
      }
      targetUrl = u.href;
    } catch (e) {
      console.error("[proxy] Query parameter merge failed:", e.message);
    }
  }

  const opts = { nojs: req.query.nojs === "1", noimg: req.query.noimg === "1", eruda: req.query.eruda === "1" };
  const optQs = [];
  if (opts.nojs) optQs.push("nojs=1");
  if (opts.noimg) optQs.push("noimg=1");
  if (opts.eruda) optQs.push("eruda=1");
  const optSuffix = optQs.length ? "?" + optQs.join("&") : "";

  if (req.method === "GET") {
    const cached = cacheGet("p:" + targetUrl + optSuffix);
    if (cached) {
      res.type(cached.ct);
      res.setHeader("X-Void-Cache", "HIT");
      return res.send(cached.body);
    }
  }

  let axiosRes;
  try {
    const headers = buildHeaders(req, targetUrl);
    axiosRes = await axios({
      url: targetUrl,
      method: req.method,
      headers,
      data: ["POST", "PUT", "PATCH", "DELETE"].includes(req.method) ? req.body : undefined,
      responseType: "stream",
      maxRedirects: 0,
      decompress: false,
      validateStatus: () => true,
      timeout: 25000,
      httpAgent,
      httpsAgent,
    });
  } catch (axiosErr) {
    return res.status(502).send("Upstream Request Failed: " + axiosErr.message);
  }

  if ([301, 302, 303, 307, 308].includes(axiosRes.status) && axiosRes.headers.location) {
    try {
      const nextUrl = new URL(axiosRes.headers.location, targetUrl).href;
      await assertSafeUrl(nextUrl);
      res.setHeader("Location", enc(nextUrl) + optSuffix);
      return res.status(axiosRes.status).end();
    } catch (e) {
      return res.status(403).send("Blocked unsafe redirect: " + e.message);
    }
  }

  if ([204, 304].includes(axiosRes.status)) return res.status(axiosRes.status).end();

  for (const [k, v] of Object.entries(axiosRes.headers)) {
    const kl = k.toLowerCase();
    if (STRIP_HEADERS.has(kl) || kl === "set-cookie") continue;
    try { res.setHeader(k, v); } catch {}
  }

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  res.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");

  const rawSetCookies = axiosRes.headers["set-cookie"];
  if (rawSetCookies) {
    const cookies = Array.isArray(rawSetCookies) ? rawSetCookies : [rawSetCookies];
    for (const c of cookies) res.append("set-cookie", prefixSetCookie(c, targetUrl));
  }

  const rawCt = String(axiosRes.headers["content-type"] || "");
  const ct = rawCt.split(";")[0].trim().toLowerCase();
  const isBinary = BINARY_TYPE_PREFIXES.some((prefix) => ct.startsWith(prefix));

  if (isBinary || axiosRes.status === 206) {
    res.status(axiosRes.status);
    const passthroughHeaders = [
      "content-type", "content-length", "content-disposition",
      "accept-ranges", "content-range", "cache-control", "etag", "last-modified",
    ];
    for (const h of passthroughHeaders) {
      if (axiosRes.headers[h] !== undefined) res.set(h, axiosRes.headers[h]);
    }
    axiosRes.data.on("error", () => {
      if (!res.headersSent) res.status(502);
      res.end();
    });
    req.on("close", () => axiosRes.data.destroy());
    return axiosRes.data.pipe(res);
  }

  try {
    const contentEncoding = String(axiosRes.headers["content-encoding"] || "").toLowerCase();
    const decompStream = decompressStream(axiosRes.data, contentEncoding);
    const chunks = [];
    for await (const chunk of decompStream) chunks.push(chunk);
    const bodyBuf = Buffer.concat(chunks);
    const text = bodyBuf.toString("utf8");

    res.removeHeader("content-encoding");
    res.removeHeader("content-length");

    if (ct.includes("text/html")) {
      const patched = text ? rewriteHtmlWithOpts(text, targetUrl, opts, optSuffix) : text;
      res.type("text/html; charset=utf-8").status(axiosRes.status).send(patched);
      cacheSet("p:" + targetUrl + optSuffix, "text/html; charset=utf-8", patched);
      return;
    }

    if (ct.includes("text/css")) {
      const rewritten = rewriteCss(text, targetUrl);
      cacheSet("p:" + targetUrl + optSuffix, "text/css; charset=utf-8", rewritten);
      res.type("text/css; charset=utf-8").send(rewritten);
      return;
    }

    if (ct.includes("javascript") || ct.includes("ecmascript")) {
      const rewritten = rewriteJsUrls(text, targetUrl, "/p/");
      cacheSet("p:" + targetUrl + optSuffix, ct, rewritten);
      res.type(rawCt || "application/javascript").status(axiosRes.status).send(rewritten);
      return;
    }

    if (ct.includes("json")) {
      const rewritten = rewriteEmbeddedUrls(text, targetUrl);
      cacheSet("p:" + targetUrl + optSuffix, ct, rewritten);
      res.type(rawCt || "application/json").status(axiosRes.status).send(rewritten);
      return;
    }

    res.type(rawCt || "application/octet-stream").status(axiosRes.status).send(bodyBuf);
  } catch (err) {
    if (!res.headersSent) res.status(502).send("Buffer error: " + err.message);
  }
}

function rewriteHtmlWithOpts(html, base, opts, optSuffix) {
  const $ = cheerio.load(html);

  const baseTag = $("base[href]").first();
  let resolveBase = base;
  if (baseTag.length) {
    try { resolveBase = new URL(baseTag.attr("href"), base).href; } catch {}
    baseTag.remove();
  }

  $('meta[http-equiv="Content-Security-Policy"]').remove();
  $('meta[http-equiv="content-security-policy"]').remove();

  function rw(raw) {
    return rewriteUrl(raw, resolveBase) + optSuffix;
  }

  function rwNoOpts(raw) {
    return rewriteUrl(raw, resolveBase);
  }

  function rwCssBlock(css) {
    return rewriteCss(css, resolveBase);
  }

  $("a[target]").removeAttr("target");
  $("form[target]").removeAttr("target");
  $("base[target]").removeAttr("target");
  $("[integrity]").removeAttr("integrity");
  $("[nonce]").removeAttr("nonce");
  $("[crossorigin]").removeAttr("crossorigin");

  $('link[rel*="icon"], link[rel*="shortcut"], link[rel*="apple-touch-icon"]').each((_, el) => {
    const href = $(el).attr("href");
    if (href) $(el).attr("href", rwNoOpts(href));
  });

  for (const [tag, attrs] of Object.entries(URL_ATTRS)) {
    $(tag).each((_, el) => {
      for (const attr of attrs) {
        const val = $(el).attr(attr);
        if (!val) continue;
        if (attr === "srcset" || attr === "data-srcset") {
          $(el).attr(
            attr,
            val.replace(/([^\s,]+)(\s+[^,]*)?/g, (m, url, desc) => rwNoOpts(url) + (desc || ""))
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
    if (m) $(el).attr("content", m[1] + ";url=" + rw(m[2]));
  });

  $("script:not([src]):not([data-void])").each((_, el) => {
    let code = $(el).html();
    if (!code || !code.trim()) return;
    code = rewriteJsUrls(code, resolveBase, "/p/");
    $(el).html(code);
  });

  if (opts.nojs) {
    $("script:not([data-void])").remove();
    const evts = "onclick,onload,onerror,onsubmit,onchange,onmouseover,onfocus,onblur,onkeydown,onkeyup,onmousedown,onmouseup".split(",");
    $("*").each((_, el) => {
      for (const e of evts) $(el).removeAttr(e);
    });
  }

  if (opts.noimg) $("img, picture").remove();

  $("body").prepend(proxyBar(base));
  if (!opts.nojs) $("head").prepend(injectionScript(resolveBase));
  if (opts.eruda) {
    $("head").append('<script src="https://cdn.jsdelivr.net/npm/eruda"></script><script>eruda.init();</script>');
  }

  return $.html();
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
      agent: isHttps ? httpsAgent : httpAgent,
    };
    const req = lib.request(reqOpts, (res) => {
      res.on("error", reject);
      resolve(res);
    });
    req.on("error", reject);
    req.setTimeout(25000, () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function experimentalRewriteHtml(html, base, optSuffix) {
  const baseRegex = /<base\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let resolveBase = base;
  let m;
  if ((m = baseRegex.exec(html))) {
    try { resolveBase = new URL(m[1], base).href; } catch {}
  }
  html = html.replace(baseRegex, "");

  const rw = (url) => rewriteUrlPe(url, resolveBase, optSuffix);
  const rwNoOpts = (url) => rewriteUrlPe(url, resolveBase, "");

  const attrPatterns = [
    [/<a\s+([^>]*?)href\s*=\s*["']([^"']*)["']/gi, "href"],
    [/<link\s+([^>]*?)href\s*=\s*["']([^"']*)["']/gi, "href"],
    [/<img\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<img\s+([^>]*?)srcset\s*=\s*["']([^"']*)["']/gi, "srcset"],
    [/<script\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<form\s+([^>]*?)action\s*=\s*["']([^"']*)["']/gi, "action"],
    [/<iframe\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<source\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
  ];

  for (const [re, attr] of attrPatterns) {
    html = html.replace(re, (full, _rest, url) => {
      const rewritten = attr === "srcset" ? url.replace(/([^\s,]+)(\s+[^,]*)?/g, (_, u, d) => rwNoOpts(u) + (d || "")) : rw(url);
      if (rewritten === url) return full;
      const cut = full.length - url.length - 1;
      return full.slice(0, cut) + rewritten + full.slice(cut + url.length);
    });
  }

  html = html.replace(/<script(\s[^>]*)?>(?!<\/script>)([\s\S]*?)<\/script>/gi, (match, attrs, code) => {
    if (!code || !code.trim() || (attrs && /\bsrc\s*=/i.test(attrs)) || (attrs && /data-void/i.test(attrs))) return match;
    const rewritten = rewriteJsUrls(code, resolveBase, "/pe/");
    return rewritten !== code ? match.replace(code, rewritten) : match;
  });

  html = html.replace(/<meta\s+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, "");
  html = html.replace(/\starget\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "");
  html = html.replace(/\sintegrity\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "");
  html = html.replace(/\snonce\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "");
  return html;
}

async function handleExperimentalProxy(req, res) {
  let targetUrl;
  try {
    targetUrl = decPe(req.params.encoded);
  } catch {
    return res.status(400).send("Invalid URL encoding");
  }

  try {
    await assertSafeUrl(targetUrl);
  } catch (err) {
    return res.status(403).send("Forbidden URL destination: " + err.message);
  }

  if (/(\/fd\/ls\/|bat\.bing\.com\/action\/|clarity\.ms\/collect)/i.test(targetUrl)) {
    return res.status(204).end();
  }

  const opts = { nojs: req.query.nojs === "1", noimg: req.query.noimg === "1", eruda: req.query.eruda === "1" };
  const optQs = [];
  if (opts.nojs) optQs.push("nojs=1");
  if (opts.noimg) optQs.push("noimg=1");
  if (opts.eruda) optQs.push("eruda=1");
  const optSuffix = optQs.length ? "?" + optQs.join("&") : "";

  try {
    const u = new URL(targetUrl);
    const headers = {
      host: u.host,
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      accept: req.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "accept-language": req.headers["accept-language"] || "en-US,en;q=0.9",
      "accept-encoding": "gzip, deflate, br",
      referer: u.origin + "/",
      origin: u.origin,
      connection: "keep-alive",
    };

    if (req.headers.range) headers.range = req.headers.range;
    if (req.method === "POST" && req.headers["content-type"]) headers["content-type"] = req.headers["content-type"];
    const scoped = scopeCookiesForTarget(req.headers.cookie, targetUrl);
    if (scoped) headers.cookie = scoped;

    let body;
    if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && req.body) {
      if (Buffer.isBuffer(req.body)) body = req.body;
      else if (typeof req.body === "object") {
        body = JSON.stringify(req.body);
        headers["content-type"] = "application/json";
      } else body = req.body;
      headers["content-length"] = Buffer.byteLength(body);
    }

    const upstream = await requestWithNode(targetUrl, { method: req.method, headers, body });

    if ([301, 302, 303, 307, 308].includes(upstream.statusCode) && upstream.headers.location) {
      const nextUrl = new URL(upstream.headers.location, targetUrl).href;
      await assertSafeUrl(nextUrl);
      res.setHeader("Location", encPe(nextUrl) + optSuffix);
      return res.status(upstream.statusCode).end();
    }

    if ([204, 304].includes(upstream.statusCode)) return res.status(upstream.statusCode).end();

    const rawCt = upstream.headers["content-type"] || "";
    const contentType = rawCt.split(";")[0].trim().toLowerCase();
    const contentEncoding = (upstream.headers["content-encoding"] || "").toLowerCase();

    for (const [k, v] of Object.entries(upstream.headers)) {
      const kl = k.toLowerCase();
      if (STRIP_HEADERS.has(kl) || kl === "set-cookie") continue;
      try { if (!Array.isArray(v)) res.set(k, v); } catch {}
    }

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    res.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");

    const rawSetCookies = upstream.headers["set-cookie"];
    if (rawSetCookies) {
      const cookies = Array.isArray(rawSetCookies) ? rawSetCookies : [rawSetCookies];
      for (const c of cookies) res.append("set-cookie", prefixSetCookie(c, targetUrl));
    }

    const isBinary = BINARY_TYPE_PREFIXES.some((prefix) => contentType.startsWith(prefix));
    if (isBinary || upstream.statusCode === 206) {
      res.status(upstream.statusCode);
      return upstream.pipe(res);
    }

    const decompressed = decompressStream(upstream, contentEncoding);
    const chunks = [];
    for await (const c of decompressed) chunks.push(c);
    const bodyBuffer = Buffer.concat(chunks);

    res.removeHeader("content-encoding");
    res.removeHeader("content-length");

    if (contentType.includes("text/html")) {
      let html = bodyBuffer.toString("utf8");
      html = experimentalRewriteHtml(html, targetUrl, optSuffix);
      const barHtml = proxyBar(targetUrl);
      const scriptHtml = opts.nojs ? "" : injectionScriptExperimental(targetUrl, optSuffix);
      html = html.replace(/<body\s*/i, `<body>${barHtml}${scriptHtml}`);
      res.type("text/html; charset=utf-8").send(html);
      return;
    }
    if (contentType.includes("text/css")) {
      const css = rewriteCssPe(bodyBuffer.toString("utf8"), targetUrl, optSuffix);
      res.type("text/css; charset=utf-8").send(css);
      return;
    }
    if (contentType.includes("javascript") || contentType.includes("ecmascript")) {
      const js = rewriteJsUrls(bodyBuffer.toString("utf8"), targetUrl, "/pe/");
      res.type(rawCt || "application/javascript").send(js);
      return;
    }
    if (contentType.includes("json")) {
      const json = rewriteEmbeddedUrls(bodyBuffer.toString("utf8"), targetUrl, encPe);
      res.type(rawCt || "application/json").send(json);
      return;
    }

    res.set("content-type", rawCt || "application/octet-stream");
    res.send(bodyBuffer);
  } catch (err) {
    res.status(502).send(`<!DOCTYPE html><html><body>502 Error: ${err.message}</body></html>`);
  }
}

function handlePeWsUpgrade(req, socket, head) {
  const path = req.url || "";
  const match = path.match(/^\/pe-ws\/([A-Za-z0-9_-]+)/);
  if (!match) return socket.destroy();

  let targetWsUrl;
  try {
    targetWsUrl = Buffer.from(match[1], "base64url").toString("utf8");
  } catch {
    return socket.destroy();
  }

  if (!/^wss?:\/\//i.test(targetWsUrl)) return socket.destroy();

  assertSafeUrl(targetWsUrl).then(() => {
    const u = new URL(targetWsUrl);
    const isWss = u.protocol === "wss:";
    const port = parseInt(u.port, 10) || (isWss ? 443 : 80);
    const key = req.headers["sec-websocket-key"] || "";
    const accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");

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

    conn.on("error", () => { socket.destroy(); conn.destroy(); });
    socket.on("error", () => { socket.destroy(); conn.destroy(); });
    socket.on("data", (data) => {
      if (targetHandshakeDone) conn.write(data);
      else clientBuf.push(data);
    });

    conn.write(targetReq);
    if (head && head.length) conn.write(head);
  }).catch(() => socket.destroy());
}

/* ═══════════════════════════════════════════
   Search & API Endpoints (Serper, SerpApi, DDG)
   ═══════════════════════════════════════════ */

const SEARCH_ENGINES = {
  brave:  q => "https://search.brave.com/search?q=" + encodeURIComponent(q),
  google: q => "https://www.google.com/search?q=" + encodeURIComponent(q),
  ddg:    q => "https://duckduckgo.com/?q=" + encodeURIComponent(q),
  bing:   q => "https://www.bing.com/search?q=" + encodeURIComponent(q),
};

async function fetchDdgFallback(q, num = 10) {
  try {
    const ddgRes = await axios.get(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(q)}`, {
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
      timeout: 6000
    });
    const $ = cheerio.load(ddgRes.data);
    const fallbackResults = [];
    $(".result").each((_, el) => {
      const a = $(el).find(".result__title a").first();
      const snippet = $(el).find(".result__snippet").text().trim();
      const title = a.text().trim();
      let href = a.attr("href") || "";
      if (href.includes("uddg=")) {
        try {
          const match = href.match(/uddg=([^&]+)/);
          if (match) href = decodeURIComponent(match[1]);
        } catch {}
      }
      if (href && /^https?:\/\//i.test(href)) {
        fallbackResults.push({ title: title || href, url: href, snippet, type: "web" });
      }
      if (fallbackResults.length >= num) return false;
    });
    return fallbackResults;
  } catch {
    return [];
  }
}

async function fetchYouTubeDirect(q) {
  try {
    const r = await axios.get(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(q + " site:youtube.com/watch")}`, {
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
      timeout: 6000
    });
    const $ = cheerio.load(r.data);
    const videos = [];
    $(".result").each((_, el) => {
      const a = $(el).find(".result__title a").first();
      const title = a.text().trim();
      let href = a.attr("href") || "";
      if (href.includes("uddg=")) {
        try {
          const match = href.match(/uddg=([^&]+)/);
          if (match) href = decodeURIComponent(match[1]);
        } catch {}
      }
      if (/youtube\.com\/watch\?v=/i.test(href)) {
        const vId = (href.match(/v=([^&]+)/) || [])[1];
        videos.push({
          title,
          link: href,
          videoId: vId,
          thumbnail: vId ? `https://i.ytimg.com/vi/${vId}/hqdefault.jpg` : "",
          channel: "YouTube",
          views: "YouTube Video"
        });
      }
      if (videos.length >= 12) return false;
    });
    return videos;
  } catch {
    return [];
  }
}

app.get("/api/search", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.status(400).json({ error: "Missing query parameter q" });
  const num = Math.min(10, Math.max(1, parseInt(req.query.num, 10) || 8));

  // 1. Serper POST Request
  if (SERPER_API_KEY) {
    try {
      const payload = JSON.stringify({ q, num });
      const serperRes = await axios({
        method: "post",
        maxBodyLength: Infinity,
        url: "https://google.serper.dev/search",
        headers: {
          "X-API-KEY": SERPER_API_KEY,
          "Content-Type": "application/json",
        },
        data: payload,
        timeout: 5000,
      });

      if (Array.isArray(serperRes.data?.organic) && serperRes.data.organic.length > 0) {
        const results = serperRes.data.organic.map((item) => ({
          title: item.title || item.link,
          url: item.link,
          snippet: item.snippet || "",
        }));
        return res.json({ cached: false, results });
      }
    } catch (e) {}
  }

  // 2. SerpApi GET Request (https://serpapi.com/search?engine=google)
  if (SERPAPI_KEY) {
    try {
      const serpUrl = `https://serpapi.com/search?engine=google&q=${encodeURIComponent(q)}&num=${num}&api_key=${SERPAPI_KEY}`;
      const serpRes = await axios.get(serpUrl, { timeout: 5000 });
      if (Array.isArray(serpRes.data?.organic_results) && serpRes.data.organic_results.length > 0) {
        const results = serpRes.data.organic_results.map((item) => ({
          title: item.title || item.link,
          url: item.link,
          snippet: item.snippet || "",
        }));
        return res.json({ cached: false, results });
      }
    } catch (e) {}
  }

  // 3. Fallback Zero-Key DDG Scraper
  const ddgResults = await fetchDdgFallback(q, num);
  return res.json({ cached: false, results: ddgResults });
});

app.get("/api/images", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.json({ images: [] });
  if (SERPAPI_KEY) {
    try {
      const url = `https://serpapi.com/search?engine=google_images&q=${encodeURIComponent(q)}&api_key=${SERPAPI_KEY}`;
      const r = await axios.get(url, { timeout: 6000 });
      const images = (r.data.images_results || []).map(img => ({
        title: img.title || "",
        original: img.original || img.link,
        thumbnail: img.thumbnail,
        source: img.source || img.domain
      })).slice(0, 20);
      return res.json({ images });
    } catch {}
  }
  return res.json({ images: [] });
});

app.get("/api/serp", async (req, res) => {
  const q = (req.query.q || "").trim();
  const engine = (req.query.engine || "google").trim();
  if (!q) return res.json({ error: "Empty query" });
  if (SERPAPI_KEY) {
    try {
      const url = `https://serpapi.com/search?engine=${encodeURIComponent(engine)}&q=${encodeURIComponent(q)}&api_key=${SERPAPI_KEY}`;
      const r = await axios.get(url, { timeout: 8000 });
      return res.json(r.data);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }
  return res.json({ error: "SerpApi Key not set" });
});

app.get("/api/youtube", async (req, res) => {
  const q = (req.query.q || "").trim();
  const v = (req.query.v || "").trim();
  if (v) {
    return res.json({ video: { title: "YouTube Video", video_id: v } });
  }
  if (!q) return res.json({ videos: [] });

  if (SERPAPI_KEY) {
    try {
      const url = `https://serpapi.com/search?engine=youtube&search_query=${encodeURIComponent(q)}&api_key=${SERPAPI_KEY}`;
      const r = await axios.get(url, { timeout: 5000 });
      const videos = (r.data.video_results || []).map(vid => ({
        title: vid.title,
        link: vid.link,
        videoId: vid.link ? (vid.link.match(/v=([^&]+)/) || [])[1] : null,
        thumbnail: vid.thumbnail?.static || vid.thumbnail,
        channel: vid.channel?.name || "YouTube",
        views: vid.views || ""
      })).slice(0, 15);
      if (videos.length > 0) return res.json({ videos });
    } catch {}
  }

  const fallbackVideos = await fetchYouTubeDirect(q);
  return res.json({ videos: fallbackVideos });
});

app.get("/api/autocomplete", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.json({ suggestions: [] });
  try {
    const url = `https://suggestqueries.google.com/complete/search?client=chrome&q=${encodeURIComponent(q)}`;
    const r = await axios.get(url, { timeout: 3000 });
    if (Array.isArray(r.data) && Array.isArray(r.data[1])) {
      return res.json({ suggestions: r.data[1].slice(0, 8) });
    }
  } catch {}
  return res.json({ suggestions: [] });
});

/* ═══════════════════════════════════════════
   Search Results UI Routes (/s, /sr, /serper-results)
   ═══════════════════════════════════════════ */

app.get(["/serper-results", "/sr", "/serpapi-results", "/s"], (req, res) => {
  let rawQ = (req.query.q || "").trim();
  if (!rawQ) return res.redirect("/");

  let q = rawQ;
  try { q = dec(rawQ); } catch {}
  const safeQ = q.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

  res.type("text/html; charset=utf-8").send(`
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${safeQ} — Void Search</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{background:#ffffff;color:#000000;font-family:'Times New Roman',Times,serif;min-height:100vh;}
a{text-decoration:none;color:inherit;}
.topbar{display:flex;align-items:center;gap:12px;padding:14px 20px;background:#ffffff;border-bottom:1px solid #000000;position:sticky;top:0;z-index:100;}
.topbar .logo{font-size:1.2rem;font-weight:bold;color:#000000;text-transform:uppercase;}
.topbar form{flex:1;display:flex;gap:8px;max-width:640px;}
.topbar input{flex:1;background:#ffffff;border:1px solid #000000;color:#000000;font-family:'Times New Roman',Times,serif;font-size:1rem;padding:6px 10px;outline:none;}
.topbar button{padding:6px 14px;background:#eeeeee;border:1px solid #000000;color:#000000;font-weight:bold;font-size:.9rem;cursor:pointer;}
.topbar .back{padding:6px 12px;background:#eeeeee;border:1px solid #000000;color:#000000;font-size:.9rem;text-decoration:none;display:inline-flex;}
.tabs{display:flex;gap:16px;padding:12px 20px 0;border-bottom:1px solid #000000;max-width:760px;margin:0 auto 20px;overflow-x:auto;}
.tab{font-size:.95rem;color:#555555;cursor:pointer;padding-bottom:6px;text-transform:uppercase;letter-spacing:0.05em;white-space:nowrap;}
.tab.active{color:#000000;font-weight:bold;border-bottom:3px solid #000000;}
.main{max-width:760px;margin:0 auto;padding:0 20px 60px;}
.meta{font-size:.9rem;color:#555555;margin-bottom:20px;display:flex;align-items:center;gap:8px;}
.result{display:block;padding:16px 0;border-bottom:1px solid #dddddd;margin-bottom:12px;}
.result:hover{background:#f9f9f9;}
.result-head{display:flex;align-items:center;gap:7px;margin-bottom:4px;}
.fav{width:14px;height:14px;}
.domain{font-size:.8rem;color:#555555;}
.result-title{font-size:1.1rem;font-weight:bold;color:#0000cc;margin-bottom:4px;}
.result:hover .result-title{text-decoration:underline;}
.result-snippet{font-size:.9rem;color:#333333;line-height:1.4;}
.img-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:16px;}
.img-card{display:flex;flex-direction:column;border:1px solid #dddddd;padding:8px;text-align:center;}
.img-card img{width:100%;height:120px;object-fit:cover;margin-bottom:8px;}
.spinner{display:flex;align-items:center;justify-content:center;padding:60px;gap:12px;}
.spin{width:18px;height:18px;border-radius:50%;border:2px solid #000;border-top-color:transparent;animation:sp .8s linear infinite;}
@keyframes sp{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="topbar">
  <a class="logo" href="/">void</a>
  <a class="back" href="javascript:history.back()">← Back</a>
  <form id="sf" action="/s" method="get">
    <input name="q" type="text" value="${safeQ}" autocomplete="off" spellcheck="false"/>
    <button type="submit">SEARCH</button>
  </form>
</div>
<div class="tabs" id="tabs">
  <div class="tab active" data-engine="all">All</div>
  <div class="tab" data-engine="images">Images</div>
  <div class="tab" data-engine="youtube">Videos</div>
</div>
<div class="main">
  <div class="meta" id="meta"></div>
  <div id="results"><div class="spinner"><div class="spin"></div>Searching…</div></div>
</div>
<script>
(function(){
  var Q = ${JSON.stringify(safeQ)};
  var currentEngine = "all";
  var resDiv = document.getElementById("results");
  var metaDiv = document.getElementById("meta");

  function esc(s){ return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
  
  function getProxyUrl(raw) {
    if(!raw) return "";
    var customTld = localStorage.getItem("void_tld") || ".www.securly.com";
    var key = "Void2026", chars = [];
    for (var i = 0; i < raw.length; i++) chars.push(String.fromCharCode(raw.charCodeAt(i) ^ key.charCodeAt(i % key.length)));
    return "/p/" + btoa(chars.join("")).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"") + customTld;
  }

  function fetchAndRender() {
    resDiv.innerHTML = "<div class=\"spinner\"><div class=\"spin\"></div>Searching…</div>";
    var endpoint = "/api/search?q=" + encodeURIComponent(Q);
    if (currentEngine === "images") endpoint = "/api/images?q=" + encodeURIComponent(Q);
    if (currentEngine === "youtube") endpoint = "/api/youtube?q=" + encodeURIComponent(Q);

    fetch(endpoint).then(function(r){ return r.json(); }).then(function(data){
      var arr = data.results || data.images || data.videos || [];
      if(!arr || arr.length === 0) {
        resDiv.innerHTML = "<div style='text-align:center;padding:40px;color:#666;'>No results found. Try another search query.</div>";
        metaDiv.innerHTML = "";
        return;
      }
      metaDiv.innerHTML = "<span>" + arr.length + " results for <strong>\"" + esc(Q) + "\"</strong></span>";

      if(currentEngine === "images") {
        resDiv.innerHTML = "<div class=\"img-grid\">" + arr.map(function(img){
          return "<a class=\"img-card\" href=\""+getProxyUrl(img.original||img.link)+"\"><img src=\""+getProxyUrl(img.thumbnail)+"\"/><div class=\"domain\">"+esc(img.source)+"</div></a>";
        }).join("") + "</div>";
      } else if(currentEngine === "youtube") {
        resDiv.innerHTML = arr.map(function(vid){
          return "<a class=\"result\" href=\""+getProxyUrl(vid.link)+"\"><div class=\"result-title\">"+esc(vid.title)+"</div><div class=\"result-head\"><span class=\"domain\">"+esc(vid.channel)+" • "+esc(vid.views)+"</span></div></a>";
        }).join("");
      } else {
        resDiv.innerHTML = arr.map(function(r){
          var domain = ""; try { domain = new URL(r.url||r.link).hostname; } catch(e){}
          var fav = domain ? "<img class=\"fav\" src=\"https://www.google.com/s2/favicons?domain="+encodeURIComponent(domain)+"&sz=32\"/>" : "";
          return "<a class=\"result\" href=\""+getProxyUrl(r.url||r.link)+"\"><div class=\"result-head\">"+fav+"<span class=\"domain\">"+esc(domain)+"</span></div><div class=\"result-title\">"+esc(r.title)+"</div><div class=\"result-snippet\">"+esc(r.snippet)+"</div></a>";
        }).join("");
      }
    }).catch(function(err){
      resDiv.innerHTML = "<div style='text-align:center;padding:40px;color:#c00;'>Error retrieving search results. Please try again.</div>";
    });
  }

  document.querySelectorAll(".tab").forEach(function(t){
    t.addEventListener("click", function(){
      document.querySelectorAll(".tab").forEach(function(x){ x.classList.remove("active"); });
      t.classList.add("active");
      currentEngine = t.getAttribute("data-engine");
      fetchAndRender();
    });
  });

  fetchAndRender();
})();
</script>
</body>
</html>
  `);
});

/* ═══════════════════════════════════════════
   Direct URL & Search Router (/go and /v)
   ═══════════════════════════════════════════ */

app.get(["/go", "/v"], (req, res) => {
  let rawInput = (req.query.q || req.query.url || "").trim();
  if (!rawInput) return res.redirect("/");

  let url = rawInput;
  try {
    url = dec(rawInput);
  } catch (e) {
    url = rawInput;
  }

  const domainPattern = /^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$/i;
  const ipPattern = /^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/.*)?$/;

  if (!/^https?:\/\//i.test(url)) {
    if (domainPattern.test(url) || ipPattern.test(url)) {
      url = "https://" + url;
    } else {
      const engine = req.query.engine || "brave";
      const searchFn = SEARCH_ENGINES[engine] || SEARCH_ENGINES.ddg;
      url = searchFn(url);
    }
  }

  const qs = [];
  if (req.query.nojs === "1") qs.push("nojs=1");
  if (req.query.noimg === "1") qs.push("noimg=1");
  if (req.query.eruda === "1") qs.push("eruda=1");
  const qsStr = qs.length ? "?" + qs.join("&") : "";

  const mode = (req.query.mode || "server").toLowerCase().trim();
  if (mode === "experimental") return res.redirect(encPe(url) + qsStr);
  return res.redirect(enc(url) + qsStr);
});

app.all("/p/:encoded", handleProxy);
app.all("/pe/:encoded", handleExperimentalProxy);

app.get("/", (_req, res) => {
  res.sendFile(join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 8080;
const server = createServer(app);

server.on("upgrade", (req, socket, head) => {
  if ((req.url || "").startsWith("/wisp/")) {
    wisp.server.routeRequest(req, socket, head);
  } else if ((req.url || "").startsWith("/pe-ws/")) {
    handlePeWsUpgrade(req, socket, head);
  } else {
    socket.destroy();
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running at http://0.0.0.0:${PORT}`);
});

export default app;