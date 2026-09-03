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

const __dirname = dirname(fileURLToPath(import.meta.url));

// 1. Initialize Express App first
const app = express();
app.set("json spaces", 2);

// 2. Load .env manually if present
try {
  const envPath = join(__dirname, ".env");
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
} catch { /* .env is optional */ }

// Keys read strictly from environment variables
const KEYS = {
  serper: process.env.SERPER_API_KEY || "",
  serpapi: process.env.SERPAPI_KEY || ""
};

// High-concurrency Keep-Alive agents to cut latency
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 1024, maxFreeSockets: 128, timeout: 15000 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 1024, maxFreeSockets: 128, timeout: 15000 });

/* ═══════════════════════════════════════════
   DNS Cache & Fast SSRF Security Validation
   ═══════════════════════════════════════════ */

const dnsCache = new Map();
const DNS_CACHE_TTL = 10 * 60 * 1000;

const isPrivateV4 = (ip) => {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return true;
  const [a, b] = parts;
  return (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
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
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("Unsupported protocol");

  const host = u.hostname.replace(/^\[(.*)\]$/, "$1");
  if (host === "metadata.google.internal" || host === "localhost" || /\.(local|internal|localhost)$/i.test(host)) {
    throw new Error("Access to internal/private domains is blocked.");
  }

  if (net.isIP(host)) {
    if (net.isIPv4(host) ? isPrivateV4(host) : isPrivateV6(host)) {
      throw new Error("Access to private IP space is blocked.");
    }
    return;
  }

  const cachedDns = dnsCache.get(host);
  if (cachedDns && (Date.now() - cachedDns.ts < DNS_CACHE_TTL)) {
    if (cachedDns.blocked) throw new Error("Domain points to forbidden network.");
    return;
  }

  const addrs = await dns.promises.lookup(host, { all: true });
  if (!addrs || addrs.length === 0) throw new Error("DNS resolution failed");

  for (const a of addrs) {
    if (net.isIPv4(a.address) ? isPrivateV4(a.address) : isPrivateV6(a.address)) {
      dnsCache.set(host, { blocked: true, ts: Date.now() });
      throw new Error("Domain points to forbidden network.");
    }
  }

  dnsCache.set(host, { blocked: false, ts: Date.now() });
}

/* ═══════════════════════════════════════════
   Express Configuration
   ═══════════════════════════════════════════ */

app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.json({ limit: "10mb" }));
app.use(express.raw({ type: "*/*", limit: "10mb" }));

app.use(express.static(join(__dirname, "public"), {
  maxAge: 0,
  etag: false,
  lastModified: false,
  setHeaders: (res, path) => {
    if (path.endsWith("sw.js")) res.setHeader("Service-Worker-Allowed", "/");
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
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

function rewriteEmbeddedUrls(text, base) {
  if (!text) return text;
  return text.replace(/(["'`])(https?:\/\/[^"'`\s\\]+)\1/g, (m, q, url) => {
    if (url.startsWith("/p/")) return m;
    try { return q + enc(new URL(url, base).href) + q; } catch { return m; }
  });
}

function rewriteJsUrls(code, base) {
  if (!code) return code;
  code = code.replace(/((?:import|export)\s+[\s\S]*?\bfrom\s+)(["'])(https?:\/\/[^"'\s]+)\2/g, (m, pre, q, url) => pre + q + enc(url) + q);
  code = code.replace(/\bimport\s*\(\s*(["'`])(https?:\/\/[^"'`\s]+)\1/g, (m, q, url) => `import(${q}${enc(url)}${q}`);
  if (code.length < 1000000) return rewriteEmbeddedUrls(code, base);
  return code;
}

/* ── DOM Injection ── */
function injectionScript(base) {
  return `<script data-void="1">
(function(){
  var B = ${JSON.stringify(base)};
  var SKIP = /^(data:|blob:|javascript:|#|mailto:|about:)/i;

  function toAbs(u){
    if(!u || typeof u !== "string") return null;
    var t = u.trim();
    if(t.startsWith("/p/") || t.startsWith("/v") || t.startsWith("/s") || t.startsWith("/go")) return null;
    if(SKIP.test(t)) return null;
    try {
      if(t.startsWith("//")) return "https:" + t;
      return new URL(t, B).href;
    } catch(e) { return null; }
  }

  function E(u){
    var abs = toAbs(u);
    if(!abs || !abs.startsWith("http")) return u;
    var key = "Void2026", chars = [];
    for(var i=0; i<abs.length; i++) chars.push(String.fromCharCode(abs.charCodeAt(i) ^ key.charCodeAt(i % key.length)));
    var tld = ""; try { tld = localStorage.getItem("void_tld") || ".www.securly.com"; } catch(e) { tld = ".www.securly.com"; }
    return "/p/" + btoa(chars.join("")).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"") + tld;
  }

  function Esrcset(v){
    if(!v) return v;
    return v.replace(/([^\\s,]+)(\\s+[^,]*)?/g, function(_, u, d){ return E(u) + (d || ''); });
  }

  var _f = window.fetch;
  window.fetch = function(u, o){
    if(typeof u === 'string') u = E(u);
    else if(u && u.url) return _f.call(this, E(u.url), u);
    return _f.call(this, u, o);
  };

  var _xo = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m, u){
    arguments[1] = E(u);
    return _xo.apply(this, arguments);
  };

  var _sa = Element.prototype.setAttribute;
  var LAZY_TAGS = {'src':1,'data-src':1,'data-src-hq':1,'data-lazy-src':1,'data-thumb':1,'data-original':1,'data-hero':1,'href':1,'action':1};
  Element.prototype.setAttribute = function(name, val){
    var n = name.toLowerCase();
    if(val && typeof val === 'string' && LAZY_TAGS[n]){
      if(n === 'srcset' || n === 'data-srcset') val = Esrcset(val);
      else {
        val = E(val);
        if(n.startsWith('data-src') && this.tagName === 'IMG') _sa.call(this, 'src', val);
      }
    }
    return _sa.call(this, name, val);
  };

  document.addEventListener('click', function(e){
    var t = e.target; while(t && t.tagName !== 'A') t = t.parentElement; if(!t) return;
    if(t.closest('#__vbar')) return;
    var raw = t.getAttribute('href'); if(!raw || raw === '/' || raw === '') return;
    t.removeAttribute('target');
    var abs = toAbs(raw);
    if(abs && abs.startsWith('http')){
      e.preventDefault();
      location.href = E(abs);
    }
  }, true);
})();
</script>`;
}

function proxyBar(displayUrl) {
  const safe = displayUrl.replace(/&/g, "&amp;").replace(/'/g, "&#39;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return `
<style>
  #__vbar {
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    height: 40px; display: flex; align-items: center; gap: 8px; padding: 0 12px;
    background: #ffffff; border-bottom: 1px solid #dfe1e5;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; font-size: 13px; color: #202124;
  }
</style>
<div id="__vbar">
  <a href="/" style="font-weight:bold;color:#4285f4;text-decoration:none;">Google</a>
  <button onclick="history.back()" style="padding:2px 8px;cursor:pointer;">&larr;</button>
  <button onclick="location.reload()" style="padding:2px 8px;cursor:pointer;">&#8635;</button>
  <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#5f6368;">${safe}</span>
  <a href="/" style="text-decoration:none;color:#1a73e8;">Home</a>
</div>`;
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
  a: ["href"], link: ["href"], img: ["src", "srcset", "data-src", "data-src-hq", "data-lazy-src", "data-original"],
  script: ["src"], source: ["src", "srcset"], video: ["src", "poster"], audio: ["src"], form: ["action"], iframe: ["src"]
};

const BINARY_PREFIXES = [
  "image/", "video/", "audio/", "font/", "application/font-woff", "application/x-font-ttf",
  "application/octet-stream", "application/wasm", "application/pdf"
];

function buildHeaders(req, targetUrl) {
  const h = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const kl = k.toLowerCase();
    if (HOP_HEADERS.has(kl)) continue;
    if (
      kl === "referer" || kl === "origin" || kl === "host" || kl === "cookie" ||
      kl.startsWith("x-vercel-") || kl.startsWith("x-forwarded-") ||
      kl === "forwarded" || kl === "via" || kl === "x-real-ip" ||
      kl.startsWith("x-void-") || kl.startsWith("sec-ch-ua")
    ) continue;
    h[k] = v;
  }

  try {
    const u = new URL(targetUrl);
    h["host"] = u.host;
    h["referer"] = u.origin + "/";
  } catch {}

  h["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
  h["accept"] = req.headers["accept"] || "*/*";
  h["accept-language"] = "en-US,en;q=0.9";
  h["accept-encoding"] = "gzip, deflate, br";

  if (req.headers.range) h["range"] = req.headers.range;
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

  const isImageExt = /\.(png|jpe?g|gif|webp|svg|ico|bmp|tiff)(\?.*)?$/i.test(targetUrl);

  let axiosRes;
  try {
    axiosRes = await axios({
      url: targetUrl,
      method: req.method,
      headers: buildHeaders(req, targetUrl),
      data: ["POST", "PUT", "PATCH", "DELETE"].includes(req.method) ? req.body : undefined,
      responseType: "stream",
      maxRedirects: 5,
      decompress: false,
      validateStatus: () => true,
      timeout: 15000,
      httpAgent,
      httpsAgent,
    });
  } catch (axiosErr) {
    return res.status(502).send("Upstream Request Failed: " + axiosErr.message);
  }

  if ([204, 304].includes(axiosRes.status)) return res.status(axiosRes.status).end();

  for (const [k, v] of Object.entries(axiosRes.headers)) {
    const kl = k.toLowerCase();
    if (STRIP_HEADERS.has(kl) || kl === "set-cookie") continue;
    try { res.setHeader(k, v); } catch {}
  }

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Timing-Allow-Origin", "*");

  const rawCt = String(axiosRes.headers["content-type"] || "");
  const ct = rawCt.split(";")[0].trim().toLowerCase();
  const isBinary = isImageExt || BINARY_PREFIXES.some((prefix) => ct.startsWith(prefix));

  if (isBinary || axiosRes.status === 206) {
    res.status(axiosRes.status);
    if (!res.getHeader("content-type") && rawCt) res.setHeader("content-type", rawCt);

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
      const patched = rewriteHtml(text, targetUrl);
      return res.type("text/html; charset=utf-8").status(axiosRes.status).send(patched);
    }

    if (ct.includes("text/css")) {
      const rewritten = rewriteCss(text, targetUrl);
      return res.type("text/css; charset=utf-8").send(rewritten);
    }

    if (ct.includes("javascript") || ct.includes("ecmascript")) {
      const rewritten = rewriteJsUrls(text, targetUrl);
      return res.type(rawCt || "application/javascript").status(axiosRes.status).send(rewritten);
    }

    res.type(rawCt || "application/octet-stream").status(axiosRes.status).send(bodyBuf);
  } catch (err) {
    if (!res.headersSent) res.status(502).send("Buffer error: " + err.message);
  }
}

function rewriteHtml(html, base) {
  const $ = cheerio.load(html);

  const baseTag = $("base[href]").first();
  let resolveBase = base;
  if (baseTag.length) {
    try { resolveBase = new URL(baseTag.attr("href"), base).href; } catch {}
    baseTag.remove();
  }

  $('meta[http-equiv="Content-Security-Policy"]').remove();
  $('meta[http-equiv="content-security-policy"]').remove();
  $('head').prepend('<meta name="referrer" content="no-referrer">');

  $("a[target]").removeAttr("target");
  $("[integrity]").removeAttr("integrity");
  $("[nonce]").removeAttr("nonce");

  for (const [tag, attrs] of Object.entries(URL_ATTRS)) {
    $(tag).each((_, el) => {
      for (const attr of attrs) {
        const val = $(el).attr(attr);
        if (!val) continue;
        if (attr === "srcset" || attr === "data-srcset") {
          $(el).attr(attr, val.replace(/([^\s,]+)(\s+[^,]*)?/g, (m, url, desc) => rewriteUrl(url, resolveBase) + (desc || "")));
        } else {
          const rewritten = rewriteUrl(val, resolveBase);
          $(el).attr(attr, rewritten);
          if (tag === "img" && (attr === "data-src" || attr === "data-original")) {
            $(el).attr("src", rewritten);
          }
        }
      }
    });
  }

  $("[style]").each((_, el) => { $(el).attr("style", rewriteCss($(el).attr("style") || "", resolveBase)); });
  $("style").each((_, el) => { $(el).html(rewriteCss($(el).html() || "", resolveBase)); });

  $("body").prepend(proxyBar(base));
  $("head").prepend(injectionScript(resolveBase));

  return $.html();
}

/* ═══════════════════════════════════════════
   Load-Balanced Search Engine Implementations
   ═══════════════════════════════════════════ */

async function fetchFromSerper(query, type = "web", num = 10) {
  if (!KEYS.serper) throw new Error("Missing SERPER_API_KEY");
  const endpoint = `https://google.serper.dev/${type === "images" ? "images" : "search"}`;
  const response = await axios({
    method: "post",
    url: endpoint,
    headers: { "X-API-KEY": KEYS.serper, "Content-Type": "application/json" },
    data: JSON.stringify({ q: query, num, gl: "us", hl: "en" }),
    timeout: 5000,
  });

  const data = response.data;
  if (type === "images") {
    return (data.images || []).map((img) => ({
      title: img.title || "",
      imageUrl: img.imageUrl || img.link,
      thumbnail: img.imageUrl,
      source: img.domain || "google",
    }));
  }

  return (data.organic || []).map((item) => ({
    title: item.title,
    link: item.link,
    snippet: item.snippet,
  }));
}

async function fetchFromSerpApi(query, type = "web", num = 10) {
  if (!KEYS.serpapi) throw new Error("Missing SERPAPI_KEY");
  const engine = type === "images" ? "google_images" : "google";
  const url = `https://serpapi.com/search.json?engine=${engine}&q=${encodeURIComponent(query)}&num=${num}&api_key=${KEYS.serpapi}&gl=us&hl=en`;

  const response = await axios.get(url, { timeout: 5000 });
  const data = response.data;

  if (type === "images") {
    return (data.images_results || []).map((img) => ({
      title: img.title || "",
      imageUrl: img.original || img.link,
      thumbnail: img.thumbnail,
      source: img.source || "google",
    }));
  }

  return (data.organic_results || []).map((item) => ({
    title: item.title,
    link: item.link,
    snippet: item.snippet,
  }));
}

async function fetchFromDuckDuckGo(query, num = 10) {
  try {
    const ddgRes = await axios.get(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`, {
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
      timeout: 5000,
    });
    const $ = cheerio.load(ddgRes.data);
    const results = [];
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
        results.push({ title: title || href, link: href, snippet });
      }
      if (results.length >= num) return false;
    });
    return results;
  } catch {
    return [];
  }
}

async function searchGoogle(query, type = "web", num = 10) {
  const availablePaid = [];
  if (KEYS.serper) availablePaid.push("serper");
  if (KEYS.serpapi) availablePaid.push("serpapi");

  if (availablePaid.length === 0) return await fetchFromDuckDuckGo(query, num);

  const primary = availablePaid[Math.floor(Math.random() * availablePaid.length)];
  try {
    return primary === "serper" ? await fetchFromSerper(query, type, num) : await fetchFromSerpApi(query, type, num);
  } catch {
    const secondary = availablePaid.find((p) => p !== primary);
    if (secondary) {
      try {
        return secondary === "serper" ? await fetchFromSerper(query, type, num) : await fetchFromSerpApi(query, type, num);
      } catch {}
    }
    return await fetchFromDuckDuckGo(query, num);
  }
}

/* ═══════════════════════════════════════════
   Endpoints
   ═══════════════════════════════════════════ */

app.get("/api/search", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.status(400).json({ error: "Missing query parameter q" });
  const num = Math.min(15, Math.max(1, parseInt(req.query.num, 10) || 10));

  const results = await searchGoogle(q, "web", num);
  return res.json({
    cached: false,
    results: results.map((item) => ({
      title: item.title,
      url: item.link || item.url,
      snippet: item.snippet || "",
    })),
  });
});

app.get("/api/images", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.json({ images: [] });
  const images = await searchGoogle(q, "images", 20);
  return res.json({ images });
});

app.get("/api/autocomplete", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.json({ suggestions: [] });
  try {
    const ddgRes = await axios.get(`https://duckduckgo.com/ac/?q=${encodeURIComponent(q)}&type=list`, { timeout: 2000 });
    return res.json({ suggestions: ddgRes.data[1]?.slice(0, 8) || [] });
  } catch {
    return res.json({ suggestions: [] });
  }
});

/* ── Results UI ── */
app.get(["/serper-results", "/sr", "/serpapi-results", "/s"], (req, res) => {
  let rawQ = (req.query.q || "").trim();
  if (!rawQ) return res.redirect("/");

  let q = rawQ;
  try {
    let decoded = dec(rawQ);
    if (decoded.includes("||")) decoded = decoded.split("||")[1] || decoded;
    q = decoded;
  } catch {}

  const safeQ = q.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

  res.type("text/html; charset=utf-8").send(`
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="referrer" content="no-referrer">
<title>${safeQ} — Void Search</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{background:#ffffff;color:#202124;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh;}
a{text-decoration:none;color:inherit;}
.topbar{display:flex;align-items:center;gap:12px;padding:12px 20px;background:#ffffff;border-bottom:1px solid #dfe1e5;position:sticky;top:0;z-index:100;}
.topbar .logo{font-size:1.4rem;font-weight:bold;color:#4285f4;text-transform:lowercase;letter-spacing:-1px;}
.topbar form{flex:1;display:flex;gap:8px;max-width:640px;}
.topbar input{flex:1;background:#ffffff;border:1px solid #dfe1e5;color:#202124;border-radius:24px;font-size:.95rem;padding:8px 16px;outline:none;}
.topbar button{padding:8px 18px;background:#f8f9fa;border:1px solid #f8f9fa;color:#3c4043;font-weight:600;font-size:.85rem;border-radius:4px;cursor:pointer;}
.tabs{display:flex;gap:16px;padding:10px 20px 0;border-bottom:1px solid #ebebeb;max-width:760px;margin:0 auto 16px;}
.tab{font-size:.9rem;color:#5f6368;cursor:pointer;padding-bottom:8px;}
.tab.active{color:#1a73e8;font-weight:500;border-bottom:3px solid #1a73e8;}
.main{max-width:760px;margin:0 auto;padding:0 20px 60px;}
.meta{font-size:.85rem;color:#70757a;margin-bottom:16px;}
.result{display:block;padding:12px 0;margin-bottom:12px;}
.domain{font-size:.8rem;color:#202124;}
.result-title{font-size:1.15rem;font-weight:400;color:#1a0dab;line-height:1.3;margin-bottom:3px;}
.result-snippet{font-size:.88rem;color:#4d5156;line-height:1.5;}
.img-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;}
.img-card{display:flex;flex-direction:column;border:1px solid #dadce0;border-radius:8px;overflow:hidden;padding:6px;text-align:center;background:#fff;}
.img-card img{width:100%;height:110px;object-fit:cover;border-radius:4px;margin-bottom:6px;background:#f1f3f4;}
</style>
</head>
<body>
<div class="topbar">
  <a class="logo" href="/">void</a>
  <form action="/s" method="get">
    <input name="q" type="text" value="${safeQ}" autocomplete="off" spellcheck="false"/>
    <button type="submit">Search</button>
  </form>
</div>
<div class="tabs" id="tabs">
  <div class="tab active" data-engine="all">All</div>
  <div class="tab" data-engine="images">Images</div>
</div>
<div class="main">
  <div class="meta" id="meta"></div>
  <div id="results">Searching...</div>
</div>
<script>
(function(){
  var Q = ${JSON.stringify(q)};
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
    resDiv.innerHTML = "Searching...";
    var endpoint = (currentEngine === "images") ? "/api/images?q=" + encodeURIComponent(Q) : "/api/search?q=" + encodeURIComponent(Q);

    fetch(endpoint).then(function(r){ return r.json(); }).then(function(data){
      var arr = data.results || data.images || [];
      if(!arr.length) { resDiv.innerHTML = "No results found."; metaDiv.innerHTML = ""; return; }
      metaDiv.innerHTML = "About " + arr.length + " results for <strong>" + esc(Q) + "</strong>";

      if(currentEngine === "images") {
        resDiv.innerHTML = "<div class='img-grid'>" + arr.map(function(img){
          return "<a class='img-card' href='" + getProxyUrl(img.imageUrl) + "'><img src='" + (img.thumbnail || img.imageUrl) + "' loading='lazy'/><div class='domain'>" + esc(img.source) + "</div></a>";
        }).join("") + "</div>";
      } else {
        resDiv.innerHTML = arr.map(function(r){
          return "<a class='result' href='" + getProxyUrl(r.url) + "'><div class='domain'>" + esc(r.url) + "</div><div class='result-title'>" + esc(r.title) + "</div><div class='result-snippet'>" + esc(r.snippet) + "</div></a>";
        }).join("");
      }
    }).catch(function(){ resDiv.innerHTML = "Error loading results."; });
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

app.get(["/go", "/v"], (req, res) => {
  let rawInput = (req.query.q || req.query.url || "").trim();
  if (!rawInput) return res.redirect("/");

  let url = rawInput;
  try { url = dec(rawInput); } catch {}

  const isUrl = /^https?:\/\//i.test(url) || /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}/.test(url);
  if (!isUrl) return res.redirect("/s?q=" + encodeURIComponent(url));
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  return res.redirect(enc(url));
});

app.all("/p/:encoded", handleProxy);

app.get("/", (_req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.sendFile(join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 8080;
const server = createServer(app);

server.on("upgrade", (req, socket, head) => {
  if ((req.url || "").startsWith("/wisp/")) {
    wisp.server.routeRequest(req, socket, head);
  } else {
    socket.destroy();
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running at http://0.0.0.0:${PORT}`);
});

export default app;