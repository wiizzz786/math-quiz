import express from "express";
import axios from "axios";
import { createServer } from "node:http";
import https from "node:https";
import http from "node:http";
import { createGunzip, createInflate, createBrotliDecompress } from "node:zlib";
import { Readable } from "node:stream";
import { createHash } from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import * as cheerio from "cheerio";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import * as wisp from "@mercuryworkshop/wisp-js/server";
import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";

// Load .env manually (no external dep needed)
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
} catch { /* .env is optional */ }

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
app.set("json spaces", 2);

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64, maxFreeSockets: 16, timeout: 30000 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64, maxFreeSockets: 16, timeout: 30000 });

const CACHE_MAX_SIZE = 10000;
let _resourceCache = new Map();

async function cacheGet(key) {
  return _resourceCache.get(key) || null;
}

async function cacheSet(key, ct, body) {
  if (!body) return;
  const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  if (bodyBuf.length > 5 * 1024 * 1024) return;

  if (_resourceCache.size >= CACHE_MAX_SIZE) {
    const oldest = _resourceCache.keys().next().value;
    _resourceCache.delete(oldest);
  }

  _resourceCache.set(key, { ct, body: bodyBuf, ts: Date.now() });
}

/* ═══════════════════════════════════════════
   Serper search result cache (server-side)
   Smart fuzzy caching: normalizes queries and
   matches near-typos within edit distance 2.
   Results expire after SERPER_CACHE_TTL ms.
   ═══════════════════════════════════════════ */

const SERPER_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
const SERPER_CACHE_MAX = 500;
const _serperCache = new Map();

// Normalize: lowercase, collapse whitespace, strip punctuation noise
function normalizeQuery(q) {
  return q.toLowerCase().trim().replace(/\s+/g, " ").replace(/[^\w\s]/g, "");
}

// Levenshtein distance — O(n*m) but queries are short so fine
function levenshtein(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

// Max edit distance allowed to consider two queries "the same"
// Scales with query length: 1 for short (≤5 chars), 2 for medium, 3 for long
function maxEditDistance(q) {
  if (q.length <= 5) return 1;
  if (q.length <= 12) return 2;
  return 3;
}

// Find a cached key that fuzzy-matches the normalized query
function fuzzyFindCacheKey(normQ, suffix) {
  const exact = normQ + suffix;
  if (_serperCache.has(exact)) return exact;
  const maxDist = maxEditDistance(normQ);
  for (const key of _serperCache.keys()) {
    if (!key.endsWith(suffix)) continue;
    const keyQ = key.slice(0, key.length - suffix.length);
    if (levenshtein(normQ, keyQ) <= maxDist) return key;
  }
  return null;
}

function serperCacheGet(query, suffix = "") {
  const normQ = normalizeQuery(query);
  const key = fuzzyFindCacheKey(normQ, suffix);
  if (!key) return null;
  const entry = _serperCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > SERPER_CACHE_TTL) {
    _serperCache.delete(key);
    return null;
  }
  return entry.data;
}

function serperCacheSet(query, data, suffix = "") {
  if (_serperCache.size >= SERPER_CACHE_MAX) {
    const oldest = _serperCache.keys().next().value;
    _serperCache.delete(oldest);
  }
  const key = normalizeQuery(query) + suffix;
  _serperCache.set(key, { data, ts: Date.now() });
}

app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(express.json({ limit: "50mb" }));
app.use(express.raw({ type: "*/*", limit: "50mb" }));
app.use(express.static(join(__dirname, "public"), {
  maxAge: "1h",
  etag: true,
  lastModified: true,
  setHeaders: (res, path) => {
    if (path.endsWith('sw.js')) {
      res.setHeader('Service-Worker-Allowed', '/');
    }
  }
}));
app.use("/scramjet/", express.static(scramjetPath));
app.use("/baremux/", express.static(baremuxPath));
app.use("/epoxy/", express.static(join(__dirname, "node_modules", "@mercuryworkshop", "epoxy-transport", "dist")));

/* ═══════════════════════════════════════════
   URL encoding / decoding helpers
   ═══════════════════════════════════════════ */

function enc(url) {
  return "/p/" + Buffer.from(url).toString("base64url") + ".securly.com";
}

function dec(encoded) {
  try {
    let str = String(encoded).trim();
    if (!str) return "";

    if (str.endsWith(".securly.com")) {
      str = str.slice(0, -12);
    }

    // Check if str is already a plain URL or plain text with spaces
    if (/^https?:\/\//i.test(str) || str.includes(" ")) {
      return str;
    }

    // Standardize base64url (- _) to base64 (+ /)
    const normalized = str.replace(/-/g, "+").replace(/_/g, "/");
    const padding = normalized.length % 4;
    const padded = padding ? normalized + "=".repeat(4 - padding) : normalized;
    const rawBinary = Buffer.from(padded, "base64").toString("binary");

    // 1. Try salted multi-key cipher decryption
    const key = "NoodalMathKey2026";
    const decChars = [];
    for (let i = 0; i < rawBinary.length; i++) {
      const k = key.charCodeAt(i % key.length);
      const code = rawBinary.charCodeAt(i) ^ k ^ ((i * 13 + 7) & 0xFF);
      decChars.push(String.fromCharCode(code));
    }
    const multiDecoded = decChars.join("");
    if (multiDecoded && /^[\x20-\x7E\s]+$/.test(multiDecoded)) {
      return multiDecoded;
    }

    // 2. Try legacy XOR 0x3F cipher decryption
    const xorDecoded = rawBinary.split("").map(c => String.fromCharCode(c.charCodeAt(0) ^ 0x3f)).join("");
    if (xorDecoded && /^[\x20-\x7E\s]+$/.test(xorDecoded)) {
      return xorDecoded;
    }

    // 3. Try standard UTF-8 Base64 decode
    const decodedUtf8 = Buffer.from(padded, "base64").toString("utf8");
    if (decodedUtf8 && /^[\x20-\x7E\s]+$/.test(decodedUtf8)) {
      return decodedUtf8;
    }

    return str;
  } catch (e) {
    return String(encoded || "");
  }
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

function rewriteJsUrls(code, base, prefix) {
  if (!code) return code;
  const pfx = prefix || "/p/";
  function rw(url) {
    try {
      return pfx + Buffer.from(new URL(url, base).href).toString("base64url");
    } catch {
      return url;
    }
  }
  code = code.replace(
    /((?:import|export)\s+[\s\S]*?\bfrom\s+)(["'])(https?:\/\/[^"'\s]+)\2/g,
    (m, pre, q, url) => pre + q + rw(url) + q
  );
  code = code.replace(
    /\bimport\s*\(\s*(["'`])(https?:\/\/[^"'`\s]+)\1/g,
    (m, q, url) => `import(${q}${rw(url)}${q}`
  );
  code = code.replace(
    /\bimportScripts\s*\(([^)]*)\)/g,
    (m, args) => {
      const rArgs = args.replace(/(["'])(https?:\/\/[^"'\s]+)\1/g, (_, q, url) => q + rw(url) + q);
      return `importScripts(${rArgs})`;
    }
  );
  code = code.replace(
    /\bnew\s+Worker\s*\(\s*(["'])(https?:\/\/[^"'\s]+)\1/g,
    (m, q, url) => `new Worker(${q}${rw(url)}${q}`
  );
  code = code.replace(
    /\bnew\s+SharedWorker\s*\(\s*(["'])(https?:\/\/[^"'\s]+)\1/g,
    (m, q, url) => `new SharedWorker(${q}${rw(url)}${q}`
  );
  return code;
}

/* ═══════════════════════════════════════════
   Injection: JS overrides for dynamic reqs
   ═══════════════════════════════════════════ */

function injectionScript(base) {
  const safeBase = (base || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  return `<script data-void="1">
(function(){
  var B='${safeBase}';
  var SKIP=/^(data:|blob:|javascript:|#|mailto:|about:)/;
  function E(u){
    try{
      if(!u||typeof u!=='string')return u;
      if(u.startsWith('/p/'))return u;
      if(SKIP.test(u))return u;
      var a=new URL(u,B).href;
      if(a.startsWith('http'))return'/p/'+btoa(a).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'')+'.securly.com';
      return u;
    }catch(e){return u;}
  }
  function Esrcset(v){if(!v)return v;return v.replace(/([^\\s,]+)(\\s+[^,]*)?/g,function(_,u,d){return E(u)+(d||'');});}
  var _f=window.fetch;
  window.fetch=function(u,o){
    if(typeof u==='string')u=E(u);
    else if(u&&u.url)u=new Request(E(u.url),u);
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
  if(Location.prototype.assign){var _la=Location.prototype.assign;Location.prototype.assign=function(u){return _la.call(this,E(u));};}
  if(Location.prototype.replace){var _lr=Location.prototype.replace;Location.prototype.replace=function(u){return _lr.call(this,E(u));};}
  if(navigator.sendBeacon){var _sb=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=function(u,d){return _sb(E(u),d);};}
  if(window.EventSource){var _ES=window.EventSource;window.EventSource=function(u,o){return new _ES(E(u),o);};window.EventSource.prototype=_ES.prototype;}
  try{Object.defineProperty(navigator,'serviceWorker',{get:function(){return{register:function(){return Promise.reject(new DOMException('blocked','SecurityError'))},ready:new Promise(function(){}),controller:null,getRegistrations:function(){return Promise.resolve([])},addEventListener:function(){}}}});}catch(e){}
  if(window.Worker){var _Wk=window.Worker;window.Worker=function(u,o){return new _Wk(E(u),o);};window.Worker.prototype=_Wk.prototype;}
  if(window.SharedWorker){var _SWk=window.SharedWorker;window.SharedWorker=function(u,o){return new _SWk(E(u),o);};window.SharedWorker.prototype=_SWk.prototype;}
  var _LD={};['href','protocol','host','hostname','port','pathname','search','hash','origin'].forEach(function(p){try{_LD[p]=Object.getOwnPropertyDescriptor(Location.prototype,p);}catch(e){}});
  function _rawLoc(p){return _LD[p]&&_LD[p].get?_LD[p].get.call(location):'';}
  function _realUrl(){var path=_rawLoc('pathname')||'';var url=B;if(path.startsWith('/p/')){try{var e=path.slice(3).replace(/-/g,'+').replace(/_/g,'/');var r=e.length%4;if(r)e+='='.repeat(4-r);url=atob(e);}catch(x){}}try{return new URL(url);}catch(x){try{return new URL(B);}catch(x2){return null;}}}
  ['href','protocol','host','hostname','port','pathname','search','hash','origin'].forEach(function(prop){try{var desc={configurable:true,enumerable:true};desc.get=function(){try{var u=_realUrl();return u?u[prop]:'';}catch(e){return '';}};if(prop==='href')desc.set=function(v){if(_LD.href&&_LD.href.set)_LD.href.set.call(location,E(v));};else if(prop==='pathname')desc.set=function(v){try{var u=_realUrl();if(u){u.pathname=v;if(_LD.href&&_LD.href.set)_LD.href.set.call(location,E(u.href));}}catch(e){}};else if(prop==='search')desc.set=function(v){try{var u=_realUrl();if(u){u.search=v;if(_LD.href&&_LD.href.set)_LD.href.set.call(location,E(u.href));}}catch(e){}};else if(prop==='hash')desc.set=function(v){try{var u=_realUrl();if(u){u.hash=v;if(_LD.href&&_LD.href.set)_LD.href.set.call(location,E(u.href));}}catch(e){}};Object.defineProperty(Location.prototype,prop,desc);}catch(e){}});
  try{Location.prototype.toString=function(){try{var u=_realUrl();return u?u.href:'';}catch(e){return '';}};Location.prototype.valueOf=function(){return this;};}catch(e){}
  try{Object.defineProperty(document,'URL',{get:function(){try{var u=_realUrl();return u?u.href:B;}catch(e){return B;}},configurable:true});}catch(e){}
  try{Object.defineProperty(document,'documentURI',{get:function(){try{var u=_realUrl();return u?u.href:B;}catch(e){return B;}},configurable:true});}catch(e){}
  try{Object.defineProperty(document,'referrer',{get:function(){try{return new URL(B).origin+'/';}catch(e){return '';}},configurable:true});}catch(e){}
  try{Object.defineProperty(document,'domain',{get:function(){try{return new URL(B).hostname;}catch(e){return '';}},set:function(){},configurable:true});}catch(e){}
  var _cP='__v_'+btoa(new URL(B).hostname).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'').slice(0,8)+'_';
  var _cD=Object.getOwnPropertyDescriptor(Document.prototype,'cookie');
  if(_cD&&_cD.get&&_cD.set){try{Object.defineProperty(document,'cookie',{get:function(){var all=_cD.get.call(document);if(!all)return '';return all.split(';').map(function(c){return c.trim();}).filter(function(c){return c.startsWith(_cP);}).map(function(c){return c.slice(_cP.length);}).join('; ');},set:function(v){if(!v)return;var eq=v.indexOf('=');if(eq===-1){_cD.set.call(document,v);return;}var name=v.slice(0,eq);var rest=v.slice(eq);_cD.set.call(document,_cP+name+rest);},configurable:true});}catch(e){}}
  var _sa=Element.prototype.setAttribute;
  var URL_A={'href':1,'src':1,'action':1,'data':1,'formaction':1,'poster':1,'background':1,'ping':1,'data-src':1,'data-href':1,'data-url':1,'data-lazy-src':1,'data-original':1,'data-poster':1,'data-bg':1};
  Element.prototype.setAttribute=function(name,val){
    var n=name.toLowerCase();
    if(val&&typeof val==='string'){
      if(URL_A[n])val=E(val);
      else if(n==='srcset'||n==='data-srcset')val=Esrcset(val);
      else if(n==='style')val=val.replace(/url\\(\\s*(['"]?)([^'")\\s]+)\\1\\s*\\)/gi,function(m,q,u){if(SKIP.test(u))return m;return 'url('+q+E(u)+q+')';});
    }
    return _sa.call(this,name,val);
  };
  [['HTMLImageElement','src'],['HTMLScriptElement','src'],['HTMLIFrameElement','src'],['HTMLSourceElement','src'],['HTMLVideoElement','src'],['HTMLAudioElement','src'],['HTMLEmbedElement','src'],['HTMLTrackElement','src'],['HTMLVideoElement','poster'],['HTMLInputElement','src'],['HTMLInputElement','formAction'],['HTMLButtonElement','formAction']].forEach(function(p){
    var P=window[p[0]]&&window[p[0]].prototype;if(!P)return;
    var d=Object.getOwnPropertyDescriptor(P,p[1]);if(!d||!d.set)return;
    Object.defineProperty(P,p[1],{get:d.get,set:function(v){d.set.call(this,E(v));},configurable:true,enumerable:true});
  });
  [['HTMLAnchorElement','href'],['HTMLAreaElement','href'],['HTMLLinkElement','href']].forEach(function(p){
    var P=window[p[0]]&&window[p[0]].prototype;if(!P)return;
    var d=Object.getOwnPropertyDescriptor(P,p[1]);if(!d||!d.set)return;
    Object.defineProperty(P,p[1],{get:d.get,set:function(v){d.set.call(this,E(v));},configurable:true,enumerable:true});
  });
  (function(){var P=HTMLFormElement.prototype,d=Object.getOwnPropertyDescriptor(P,'action');if(d&&d.set)Object.defineProperty(P,'action',{get:d.get,set:function(v){d.set.call(this,E(v));},configurable:true,enumerable:true});})();
  (function(){var P=HTMLObjectElement.prototype,d=Object.getOwnPropertyDescriptor(P,'data');if(d&&d.set)Object.defineProperty(P,'data',{get:d.get,set:function(v){d.set.call(this,E(v));},configurable:true,enumerable:true});})();
  document.addEventListener('click',function(e){
    var t=e.target;while(t&&t.tagName!=='A')t=t.parentElement;if(!t)return;
    var raw=t.getAttribute('href');if(!raw||raw==='/'||raw==='')return;
    t.removeAttribute('target');
    if(raw.startsWith('/p/'))return;
    if(SKIP.test(raw))return;
    try{var abs=new URL(raw,B).href;if((abs.startsWith('http://')||abs.startsWith('https://'))&&!abs.startsWith(_rawLoc('origin'))){e.preventDefault();e.stopPropagation();if(_LD.href&&_LD.href.set)_LD.href.set.call(location,E(abs));}}catch(err){}
  },true);
  document.addEventListener('submit',function(e){
    var f=e.target;if(!f||f.tagName!=='FORM')return;
    var a=f.getAttribute('action')||f.action||'';if(!a||a.startsWith('/p/')||SKIP.test(a))return;
    try{var abs=new URL(a,B).href;if((abs.startsWith('http://')||abs.startsWith('https://'))&&!abs.startsWith(_rawLoc('origin')))f.action=E(abs);}catch(err){}
  },true);
  var DUA=['data-src','data-srcset','data-lazy-src','data-original','data-bg','data-href','data-url','data-poster'];
  function rwEl(el){
    if(el.tagName==='A'||el.tagName==='AREA'){
      el.removeAttribute('target');var h=el.getAttribute('href');
      if(h&&h!=='/'&&h!==''&&!h.startsWith('/p/')&&!SKIP.test(h)){
        try{var a=new URL(h,B).href;if(a.startsWith('http'))_sa.call(el,'href',E(a));}catch(e){}
      }
    }
    if(el.tagName==='FORM'){
      el.removeAttribute('target');var ac=el.getAttribute('action');
      if(ac&&!ac.startsWith('/p/')){try{var a2=new URL(ac,B).href;if(a2.startsWith('http'))_sa.call(el,'action',E(a2));}catch(e){}}
    }
    var tag=el.tagName;
    if(tag==='IMG'||tag==='SCRIPT'||tag==='LINK'||tag==='IFRAME'||tag==='VIDEO'||tag==='AUDIO'||tag==='SOURCE'||tag==='EMBED'||tag==='TRACK'||tag==='INPUT'){
      var s=el.getAttribute('src')||el.getAttribute('href');
      if(s&&!s.startsWith('/p/')&&!s.startsWith('data:')&&!s.startsWith('blob:')){
        try{var a3=new URL(s,B).href;if(a3.startsWith('http'))_sa.call(el,el.hasAttribute('src')?'src':'href',E(a3));}catch(e){}
      }
      var ss=el.getAttribute('srcset');if(ss)_sa.call(el,'srcset',Esrcset(ss));
      DUA.forEach(function(da){var v=el.getAttribute(da);if(v&&!v.startsWith('/p/')&&!v.startsWith('data:')){try{var a4=new URL(v,B).href;if(a4.startsWith('http'))_sa.call(el,da,E(a4));}catch(e){}}});
    }
    if(el.hasAttribute('integrity'))el.removeAttribute('integrity');
    if(el.hasAttribute('nonce'))el.removeAttribute('nonce');
    if(el.hasAttribute('crossorigin'))el.removeAttribute('crossorigin');
  }
  var obs=new MutationObserver(function(muts){
    muts.forEach(function(m){
      m.addedNodes.forEach(function(n){
        if(n.nodeType!==1)return;rwEl(n);
        if(n.querySelectorAll)n.querySelectorAll('a[href],area[href],form[action],img[src],img[data-src],link[href],script[src],iframe[src],video[src],audio[src],source[src],embed[src],track[src],input[src],[integrity],[nonce],[crossorigin],[srcset]').forEach(rwEl);
      });
    });
  });
  var _dw=document.write;var _dwl=document.writeln;
  function _rwHtml(h){if(!h||typeof h!=='string')return h;return h.replace(/(href|src|action|data|poster|background)\\s*=\\s*(["'])([^"']*)\\2/gi,function(m,attr,q,url){if(!url||SKIP.test(url))return m;return attr+'='+q+E(url)+q;});}
  document.write=function(){var a=[];for(var i=0;i<arguments.length;i++)a.push(typeof arguments[i]==='string'?_rwHtml(arguments[i]):arguments[i]);return _dw.apply(document,a);};
  document.writeln=function(){var a=[];for(var i=0;i<arguments.length;i++)a.push(typeof arguments[i]==='string'?_rwHtml(arguments[i]):arguments[i]);return _dwl.apply(document,a);};
  if(CSSStyleSheet.prototype.insertRule){var _csIR=CSSStyleSheet.prototype.insertRule;CSSStyleSheet.prototype.insertRule=function(r,i){if(typeof r==='string')r=r.replace(/url\\(\\s*(['"]?)([^'")\\s]+)\\1\\s*\\)/gi,function(m,q,u){if(SKIP.test(u))return m;return 'url('+q+E(u)+q+')';});return _csIR.call(this,r,i);};}
  if(window.Blob){var _Blb=window.Blob;window.Blob=function(p,o){if(o&&o.type&&/javascript|ecmascript/i.test(o.type)&&Array.isArray(p)){p=p.map(function(s){if(typeof s==='string')return s.replace(/importScripts\\s*\\(\\s*(["'])(https?:\\/\\/[^"'\\s]+)\\1/g,function(m,q,u){return 'importScripts('+q+E(u)+q;});return s;});}return new _Blb(p,o);};window.Blob.prototype=_Blb.prototype;}
  if(CSSStyleDeclaration.prototype.setProperty){var _csSP=CSSStyleDeclaration.prototype.setProperty;CSSStyleDeclaration.prototype.setProperty=function(p,v,p2){if(typeof v==='string'&&(p==='background-image'||p==='background')){v=v.replace(/url\\(\\s*(['"]?)([^'")\\s]+)\\1\\s*\\)/gi,function(m,q,u){if(SKIP.test(u))return m;return 'url('+q+E(u)+q+')';});}return _csSP.call(this,p,v,p2);};}
  ['backgroundImage','background','cssText'].forEach(function(prop){try{var d=Object.getOwnPropertyDescriptor(CSSStyleDeclaration.prototype,prop);if(d&&d.set){Object.defineProperty(CSSStyleDeclaration.prototype,prop,{get:d.get,set:function(v){if(typeof v==='string'){v=v.replace(/url\\(\\s*(['"]?)([^'")\\s]+)\\1\\s*\\)/gi,function(m,q,u){if(SKIP.test(u))return m;return 'url('+q+E(u)+q+')';});}d.set.call(this,v);},enumerable:true,configurable:true});}}catch(e){}});
  obs.observe(document.documentElement,{childList:true,subtree:true});
})();
</script>`;
}

/* ═══════════════════════════════════════════
   Proxy top-bar injected into pages
   ═══════════════════════════════════════════ */

function proxyBar(displayUrl) {
  const safe = displayUrl.replace(/&/g, "&amp;").replace(/'/g, "&#39;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  let domain = "";
  try { domain = new URL(displayUrl).hostname; } catch {}
  const favicon = domain ? `https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=32` : "";
  const faviconHtml = favicon
    ? `<img src="${favicon}" style="width:14px;height:14px;border-radius:2px;flex-shrink:0;" onerror="this.style.display='none'" alt=""/>`
    : "";
  return `<div id="__vbar" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;height:42px;display:flex;align-items:center;gap:8px;padding:0 12px;background:#ffffff;border-bottom:1px solid #000000;font-family:'Times New Roman',Times,serif;font-size:14px;color:#000000;">
<a href="/" target="_top" style="color:#000000;font-weight:bold;text-decoration:none;font-size:18px;text-transform:uppercase;">void</a>
<span style="color:#555555;font-size:14px;margin-left:4px;">Go Anywhere</span>
<button onclick="history.back()" style="background:#eeeeee;border:1px solid #000000;color:#000000;padding:2px 8px;cursor:pointer;font-family:'Times New Roman',Times,serif;" title="Back">&larr;</button>
<button onclick="history.forward()" style="background:#eeeeee;border:1px solid #000000;color:#000000;padding:2px 8px;cursor:pointer;font-family:'Times New Roman',Times,serif;" title="Forward">&rarr;</button>
<button onclick="location.reload()" style="background:#eeeeee;border:1px solid #000000;color:#000000;padding:2px 8px;cursor:pointer;font-family:'Times New Roman',Times,serif;" title="Reload">&#8635;</button>
<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:#ffffff;padding:2px 8px;border:1px solid #000000;font-family:'Times New Roman',Times,serif;font-size:13px;color:#000000;display:flex;align-items:center;gap:6px;">${faviconHtml}${safe}</span>
<a href="/" target="_top" style="padding:2px 10px;background:#eeeeee;color:#000000;text-decoration:none;border:1px solid #000000;">Home</a>
<button onclick="document.getElementById('__vbar').style.display='none';document.getElementById('__vsp').style.display='none';" style="padding:2px 8px;background:#eeeeee;color:#000000;border:1px solid #000000;cursor:pointer;font-family:'Times New Roman',Times,serif;" aria-label="Close toolbar">&#x2715;</button>
</div>
<div id="__vsp" style="height:42px;"></div>`;
}

/* ═══════════════════════════════════════════
   HTML rewriter (cheerio)
   ═══════════════════════════════════════════ */

const URL_ATTRS = {
  a: ["href", "ping"],
  area: ["href"],
  link: ["href"],
  img: ["src", "srcset", "data-src", "data-srcset", "data-lazy-src", "data-original"],
  script: ["src"],
  source: ["src", "srcset"],
  video: ["src", "poster"],
  audio: ["src"],
  embed: ["src"],
  object: ["data"],
  form: ["action"],
  input: ["src", "formaction"],
  track: ["src"],
  iframe: ["src"],
  button: ["formaction"],
  body: ["background"],
  table: ["background"],
  td: ["background"],
  th: ["background"],
};

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

function isBlockedUrl(url) {
  try {
    const u = new URL(url);
    const h = u.hostname;
    if (h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "0.0.0.0" || h === "[::1]") return true;
    if (/^10\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || /^192\.168\./.test(h)) return true;
    if (/^169\.254\./.test(h)) return true;
    if (h === "metadata.google.internal") return true;
    if (h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".localhost")) return true;
    if (/^0\./.test(h) || /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(h)) return true;
    if (/^fc[0-9a-f]{2}:/i.test(h) || /^fd[0-9a-f]{2}:/i.test(h) || /^fe80:/i.test(h)) return true;
    return false;
  } catch {
    return true;
  }
}

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
    h[k] = v;
  }
  try {
    const u = new URL(targetUrl);
    h["host"] = u.host;
    h["referer"] = u.origin + "/";
    h["origin"] = u.origin;
  } catch (e) {
    console.error("[proxy] buildHeaders: invalid targetUrl:", e.message);
  }
  const scoped = scopeCookiesForTarget(req.headers.cookie, targetUrl);
  if (scoped) h["cookie"] = scoped;
  if (!h["user-agent"]) {
    h["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
  }
  h["accept-encoding"] = "gzip, deflate, br";
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
  if (isBlockedUrl(targetUrl)) {
    return res.status(403).send("Access to internal/private addresses is blocked.");
  }

  // Merge GET query params (e.g. form ?q=...) into targetUrl so searches work
  if (req.method === "GET" && req.query && Object.keys(req.query).length > 0) {
    try {
      const u = new URL(targetUrl);
      for (const [k, v] of Object.entries(req.query)) {
        if (k === "nojs" || k === "noimg" || k === "eruda" || k === "offline") continue;
        u.searchParams.set(k, v);
      }
      targetUrl = u.href;
    } catch (e) {
      console.error("[proxy] Failed to merge query params:", e.message);
    }
  }

  const opts = {
    nojs: req.query.nojs === "1",
    noimg: req.query.noimg === "1",
    eruda: req.query.eruda === "1",
    offline: req.query.offline === "1",
  };

  // Build query string to preserve options across navigation
  const optQs = [];
  if (opts.nojs) optQs.push("nojs=1");
  if (opts.noimg) optQs.push("noimg=1");
  if (opts.eruda) optQs.push("eruda=1");
  const optSuffix = optQs.length ? "?" + optQs.join("&") : "";

  try {
    const headers = buildHeaders(req, targetUrl);

    let axiosRes;
    try {
      axiosRes = await axios({
        url: targetUrl,
        method: req.method,
        headers,
        data: ["POST", "PUT", "PATCH", "DELETE"].includes(req.method) ? req.body : undefined,
        responseType: "arraybuffer",
        maxRedirects: 5,
        validateStatus: () => true,
        timeout: 25000,
        decompress: true
      });
    } catch (axiosErr) {
      console.error("[axios proxy error]:", axiosErr.message);
      return res.status(502).send("Upstream Proxy Fetch Failed: " + axiosErr.message);
    }

    const STRIP_RES = new Set([
      "content-security-policy", "content-security-policy-report-only",
      "x-frame-options", "strict-transport-security", "transfer-encoding",
      "content-encoding", "content-length", "set-cookie", "location",
      "cross-origin-opener-policy", "cross-origin-embedder-policy",
      "cross-origin-resource-policy", "permissions-policy",
      "x-content-type-options", "report-to",
    ]);

    for (const [k, v] of Object.entries(axiosRes.headers)) {
      if (STRIP_RES.has(k.toLowerCase())) continue;
      try { res.setHeader(k, v); } catch (e) {}
    }

    const ct = String(axiosRes.headers["content-type"] || "");

    // HTML → rewrite
    if (ct.includes("text/html")) {
      const text = Buffer.from(axiosRes.data).toString("utf8");
      const patched = text ? rewriteHtmlWithOpts(text, targetUrl, opts, optSuffix) : text;
      res.type("text/html; charset=utf-8").status(axiosRes.status).send(patched);
      cacheSet("p:" + targetUrl, "text/html; charset=utf-8", text || "");
      return;
    }

    if (ct.includes("text/css")) {
      const text = Buffer.from(axiosRes.data).toString("utf8");
      const rewritten = rewriteCss(text, targetUrl);
      cacheSet("p:" + targetUrl, "text/css; charset=utf-8", rewritten);
      res.type("text/css; charset=utf-8").status(axiosRes.status).send(rewritten);
      return;
    }

    if (ct.includes("javascript") || ct.includes("ecmascript")) {
      const text = Buffer.from(axiosRes.data).toString("utf8");
      const rewritten = rewriteJsUrls(text, targetUrl, "/p/");
      cacheSet("p:" + targetUrl, ct, rewritten);
      res.type(ct).status(axiosRes.status).send(rewritten);
      return;
    }

    const rawBuf = Buffer.from(axiosRes.data);
    cacheSet("p:" + targetUrl, ct, rawBuf);
    return res.status(axiosRes.status).send(rawBuf);
  } catch (err) {
    if (req.method === "GET") {
      const fallback = await cacheGet("p:" + targetUrl);
      if (fallback) {
        res.set("content-type", fallback.ct);
        res.set("X-Void-Cache", "HIT-OFFLINE");
        return res.send(fallback.body);
      }
    }
    const isLogOrAnalytics = /\.(google|googleapis|gstatic)\.com\/(log|analytics|collect|gen_204)/i.test(targetUrl) || /\/(log|analytics|collect|beacon|ping)(\?|&|$)/i.test(targetUrl);
    if (!isLogOrAnalytics) console.error("[proxy error]", targetUrl, err.message);
    const safeTarget = targetUrl.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const safeErr = (err.message || "Unknown error").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    res.status(502).send(`<!DOCTYPE html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Void — Connection Failed</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;900&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000000;color:#ffffff;font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem;-webkit-font-smoothing:antialiased}
.wrap{max-width:500px;text-align:center;background:#050508;border:2px solid #ffffff;border-radius:12px;padding:32px;box-shadow:0 0 30px rgba(255,255,255,0.15)}
.code{font-size:5rem;font-weight:900;letter-spacing:-.06em;line-height:1;color:#ffffff;margin-bottom:10px;}
h1{font-size:1.3rem;font-weight:700;color:#ffffff;margin:.8rem 0 .5rem;text-transform:uppercase;}
p{font-size:.85rem;line-height:1.6;margin:.6rem 0;color:#cccccc}
.url{display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:#000000;border:1px solid #ffffff;padding:8px 14px;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:#ffffff;margin:.6rem 0}
.err{font-size:.78rem;color:#ffffff;background:rgba(255,255,255,0.08);border:1px solid #ffffff;padding:8px 14px;border-radius:6px;margin:.8rem 0;font-family:'JetBrains Mono',monospace}
.btn{display:inline-flex;align-items:center;gap:6px;padding:10px 24px;border-radius:6px;background:#ffffff;color:#000000;text-decoration:none;font-weight:900;font-size:.85rem;letter-spacing:.02em;margin-top:1.2rem;transition:background .15s}
.btn:hover{background:#cccccc}
</style></head><body>
<div class="wrap">
<div class="code">502</div>
<h1>Connection Failed</h1>
<p>Void couldn't reach the requested page.</p>
<div class="url">${safeTarget}</div>
<div class="err">${safeErr}</div>
<p style="font-size:.78rem;color:#888888">The site may be down, blocking proxy requests, or the URL may be invalid.</p>
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
    } catch (e) {
      console.error("[rewrite] Invalid <base href>:", e.message);
    }
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

  $("a[target]").removeAttr("target");
  $("form[target]").removeAttr("target");
  $("base[target]").removeAttr("target");

  $("[integrity]").removeAttr("integrity");
  $("[nonce]").removeAttr("nonce");
  $("[crossorigin]").removeAttr("crossorigin");

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

  $("script:not([src]):not([data-void])").each((_, el) => {
    let code = $(el).html();
    if (!code || !code.trim()) return;
    code = rewriteJsUrls(code, resolveBase, "/p/");
    $(el).html(code);
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
  if (opts.eruda) {
    $("head").append(
      '<script src="https://cdn.jsdelivr.net/npm/eruda"></script><script>eruda.init();</script>'
    );
  }

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
  try {
    const str = String(encoded);
    const normalized = str.replace(/-/g, "+").replace(/_/g, "/");
    const padding = normalized.length % 4;
    const padded = padding ? normalized + "=".repeat(4 - padding) : normalized;
    const decoded = Buffer.from(padded, "base64").toString("utf8");
    if (!/^https?:\/\//i.test(decoded)) throw new Error("Decoded value is not an http/https URL");
    return decoded;
  } catch (e) {
    throw new Error(`URL decode failed: ${e.message}`);
  }
}

// Browser-matched constants
const STEALTH_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";
const STEALTH_ACCEPT =
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
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
    "accept-encoding": "gzip, deflate, br, zstd",
    "sec-ch-ua": '"Not=A?Brand";v="99", "Google Chrome";v="151", "Chromium";v="151"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
    priority: "u=0, i",
    referer: origin + "/",
    origin,
    connection: "keep-alive",
    ...(req.method === "POST" && req.headers["content-type"]
      ? { "content-type": req.headers["content-type"] }
      : {}),
    ...(req.headers.cookie
      ? { cookie: scopeCookiesForTarget(req.headers.cookie, targetUrl) || undefined }
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
  "permissions-policy",
  "x-permitted-cross-domain-policies",
  "x-xss-protection",
  "strict-transport-security",
  "transfer-encoding",
  "content-encoding",
  "content-length",
  "report-to",
]);

function remapSetCookie(rawCookie, _proxyHost, targetUrl) {
  return prefixSetCookie(rawCookie, targetUrl);
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
    } catch (e) {
      console.error("[experimental rewrite] Invalid <base href>:", e.message);
    }
  }
  html = html.replace(baseRegex, "");

  const rw = (url) => rewriteUrlPe(url, resolveBase, optSuffix);
  const rwNoOpts = (url) => rewriteUrlPe(url, resolveBase, "");

  const attrPatterns = [
    [/<a\s+([^>]*?)href\s*=\s*["']([^"']*)["']/gi, "href"],
    [/<link\s+([^>]*?)href\s*=\s*["']([^"']*)["']/gi, "href"],
    [/<img\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<img\s+([^>]*?)srcset\s*=\s*["']([^"']*)["']/gi, "srcset"],
    [/<img\s+([^>]*?)data-src\s*=\s*["']([^"']*)["']/gi, "data-src"],
    [/<script\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<form\s+([^>]*?)action\s*=\s*["']([^"']*)["']/gi, "action"],
    [/<iframe\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<source\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<source\s+([^>]*?)srcset\s*=\s*["']([^"']*)["']/gi, "srcset"],
    [/<embed\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<object\s+([^>]*?)data\s*=\s*["']([^"']*)["']/gi, "data"],
    [/<video\s+([^>]*?)poster\s*=\s*["']([^"']*)["']/gi, "poster"],
    [/<video\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
    [/<track\s+([^>]*?)src\s*=\s*["']([^"']*)["']/gi, "src"],
  ];
  for (const [re, attr] of attrPatterns) {
    html = html.replace(re, (full, _rest, url) => {
      const rewritten = attr === "srcset" ? url.replace(/([^\s,]+)(\s+[^,]*)?/g, (_, u, d) => rwNoOpts(u) + (d || "")) : rw(url);
      if (rewritten === url) return full;
      const q = full.indexOf(url);
      return q === -1 ? full : full.slice(0, q) + rewritten + full.slice(q + url.length);
    });
  }

  html = html.replace(/<meta\s+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?(\d+)\s*;\s*url\s*=\s*([^"'>\s]+)/gi, (match, _n, url) => {
    const r = rw(url.trim());
    return r !== url ? match.replace(url, r) : match;
  });

  html = html.replace(/url\(\s*(['"]?)([^'")\s]+)\1\s*\)/gi, (match, q, url) => {
    const r = rwNoOpts(url);
    return r !== url ? `url(${q}${r}${q})` : match;
  });
  html = html.replace(/@import\s+(['"])([^'"]+)\1/gi, (match, q, url) => {
    const r = rwNoOpts(url);
    return r !== url ? `@import ${q}${r}${q}` : match;
  });

  html = html.replace(/<script(\s[^>]*)?>(?!<\/script>)([\s\S]*?)<\/script>/gi, (match, attrs, code) => {
    if (!code || !code.trim()) return match;
    if (attrs && /\bsrc\s*=/i.test(attrs)) return match;
    if (attrs && /data-void/i.test(attrs)) return match;
    const rewritten = rewriteJsUrls(code, resolveBase, "/pe/");
    return rewritten !== code ? match.replace(code, rewritten) : match;
  });

  html = html.replace(/<meta\s+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, "");
  html = html.replace(/<meta\s+http-equiv\s*=\s*["']?content-security-policy-report-only["']?[^>]*>/gi, "");
  html = html.replace(/\s+target\s*=\s*["']?[^"'\s>]+["']?/gi, "");
  html = html.replace(/\s+integrity\s*=\s*["'][^"']*["']/gi, "");
  html = html.replace(/\s+nonce\s*=\s*["'][^"']*["']/gi, "");
  html = html.replace(/\s+crossorigin(?:\s*=\s*["']?[^"'\s>]*["']?)?/gi, "");
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

function injectionScriptExperimental(base, optSuffix, proxyHost) {
  const safeBase = (base || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  const suffix = (optSuffix || "").replace(/'/g, "\\'");
  return `<script data-void="1">
(function(){
  var B='${safeBase}', S='${suffix}';
  var SKIP=/^(data:|blob:|javascript:|#|mailto:|about:)/;
  function E(u){
    try{
      if(!u||typeof u!=='string')return u;
      if(u.startsWith('/pe/'))return u;
      if(SKIP.test(u))return u;
      var a=new URL(u,B).href;
      if(a.startsWith('http'))return'/pe/'+btoa(a).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'')+S;
      return u;
    }catch(e){return u;}
  }
  function Esrcset(v){if(!v)return v;return v.replace(/([^\\s,]+)(\\s+[^,]*)?/g,function(_,u,d){return E(u)+(d||'');});}
  function Ws(u){
    try{
      if(!u||typeof u!=='string')return u;
      if(u.startsWith('/pe-ws/'))return u;
      var a=new URL(u,B).href;
      if(/^wss?:/.test(a))return'/pe-ws/'+btoa(a).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'');
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
  XMLHttpRequest.prototype.open=function(m,u){arguments[1]=E(u);return _xo.apply(this,arguments);};
  var _Ws=window.WebSocket;
  window.WebSocket=function(u,p){return p?new _Ws(Ws(u),p):new _Ws(Ws(u));};
  window.WebSocket.prototype=_Ws.prototype;
  window.WebSocket.CONNECTING=_Ws.CONNECTING;window.WebSocket.OPEN=_Ws.OPEN;window.WebSocket.CLOSING=_Ws.CLOSING;window.WebSocket.CLOSED=_Ws.CLOSED;
  var _wo=window.open;
  window.open=function(u){if(u&&typeof u==='string')arguments[0]=E(u);return _wo.apply(this,arguments);};
  var _ps=History.prototype.pushState;
  History.prototype.pushState=function(s,t,u){if(u)arguments[2]=E(u);return _ps.apply(this,arguments);};
  var _rs=History.prototype.replaceState;
  History.prototype.replaceState=function(s,t,u){if(u)arguments[2]=E(u);return _rs.apply(this,arguments);};
  if(Location.prototype.assign){var _la=Location.prototype.assign;Location.prototype.assign=function(u){return _la.call(this,E(u));};}
  if(Location.prototype.replace){var _lr=Location.prototype.replace;Location.prototype.replace=function(u){return _lr.call(this,E(u));};}
  if(navigator.sendBeacon){var _sb=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=function(u,d){return _sb(E(u),d);};}
  if(window.EventSource){var _ES=window.EventSource;window.EventSource=function(u,o){return new _ES(E(u),o);};window.EventSource.prototype=_ES.prototype;}
  try{Object.defineProperty(navigator,'serviceWorker',{get:function(){return{register:function(){return Promise.reject(new DOMException('blocked','SecurityError'))},ready:new Promise(function(){}),controller:null,getRegistrations:function(){return Promise.resolve([])},addEventListener:function(){}}}});}catch(e){}
  if(window.Worker){var _Wk=window.Worker;window.Worker=function(u,o){return new _Wk(E(u),o);};window.Worker.prototype=_Wk.prototype;}
  if(window.SharedWorker){var _SWk=window.SharedWorker;window.SharedWorker=function(u,o){return new _SWk(E(u),o);};window.SharedWorker.prototype=_SWk.prototype;}
  var _LD={};['href','protocol','host','hostname','port','pathname','search','hash','origin'].forEach(function(p){try{_LD[p]=Object.getOwnPropertyDescriptor(Location.prototype,p);}catch(e){}});
  function _rawLoc(p){return _LD[p]&&_LD[p].get?_LD[p].get.call(location):'';}
  function _realUrl(){var path=_rawLoc('pathname')||'';var url=B;if(path.startsWith('/pe/')){try{var e=path.slice(4).replace(/-/g,'+').replace(/_/g,'/');var r=e.length%4;if(r)e+='='.repeat(4-r);url=atob(e);}catch(x){}}try{return new URL(url);}catch(x){try{return new URL(B);}catch(x2){return null;}}}
  ['href','protocol','host','hostname','port','pathname','search','hash','origin'].forEach(function(prop){try{var desc={configurable:true,enumerable:true};desc.get=function(){try{var u=_realUrl();return u?u[prop]:'';}catch(e){return '';}};if(prop==='href')desc.set=function(v){if(_LD.href&&_LD.href.set)_LD.href.set.call(location,E(v));};else if(prop==='pathname')desc.set=function(v){try{var u=_realUrl();if(u){u.pathname=v;if(_LD.href&&_LD.href.set)_LD.href.set.call(location,E(u.href));}}catch(e){}};else if(prop==='search')desc.set=function(v){try{var u=_realUrl();if(u){u.search=v;if(_LD.href&&_LD.href.set)_LD.href.set.call(location,E(u.href));}}catch(e){}};else if(prop==='hash')desc.set=function(v){try{var u=_realUrl();if(u){u.hash=v;if(_LD.href&&_LD.href.set)_LD.href.set.call(location,E(u.href));}}catch(e){}};Object.defineProperty(Location.prototype,prop,desc);}catch(e){}});
  try{Location.prototype.toString=function(){try{var u=_realUrl();return u?u.href:'';}catch(e){return '';}};Location.prototype.valueOf=function(){return this;};}catch(e){}
  try{Object.defineProperty(document,'URL',{get:function(){try{var u=_realUrl();return u?u.href:B;}catch(e){return B;}},configurable:true});}catch(e){}
  try{Object.defineProperty(document,'documentURI',{get:function(){try{var u=_realUrl();return u?u.href:B;}catch(e){return B;}},configurable:true});}catch(e){}
  try{Object.defineProperty(document,'referrer',{get:function(){try{return new URL(B).origin+'/';}catch(e){return '';}},configurable:true});}catch(e){}
  try{Object.defineProperty(document,'domain',{get:function(){try{return new URL(B).hostname;}catch(e){return '';}},set:function(){},configurable:true});}catch(e){}
  var _cP='__v_'+btoa(new URL(B).hostname).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'').slice(0,8)+'_';
  var _cD=Object.getOwnPropertyDescriptor(Document.prototype,'cookie');
  if(_cD&&_cD.get&&_cD.set){try{Object.defineProperty(document,'cookie',{get:function(){var all=_cD.get.call(document);if(!all)return '';return all.split(';').map(function(c){return c.trim();}).filter(function(c){return c.startsWith(_cP);}).map(function(c){return c.slice(_cP.length);}).join('; ');},set:function(v){if(!v)return;var eq=v.indexOf('=');if(eq===-1){_cD.set.call(document,v);return;}var name=v.slice(0,eq);var rest=v.slice(eq);_cD.set.call(document,_cP+name+rest);},configurable:true});}catch(e){}}
  var _sa=Element.prototype.setAttribute;
  var URL_A={'href':1,'src':1,'action':1,'data':1,'formaction':1,'poster':1,'background':1,'ping':1,'data-src':1,'data-href':1,'data-url':1,'data-lazy-src':1,'data-original':1,'data-poster':1,'data-bg':1};
  Element.prototype.setAttribute=function(name,val){
    var n=name.toLowerCase();
    if(val&&typeof val==='string'){
      if(URL_A[n])val=E(val);
      else if(n==='srcset'||n==='data-srcset')val=Esrcset(val);
    }
    return _sa.call(this,name,val);
  };
  [['HTMLImageElement','src'],['HTMLScriptElement','src'],['HTMLIFrameElement','src'],['HTMLSourceElement','src'],['HTMLVideoElement','src'],['HTMLAudioElement','src'],['HTMLEmbedElement','src'],['HTMLTrackElement','src'],['HTMLVideoElement','poster'],['HTMLInputElement','src'],['HTMLInputElement','formAction'],['HTMLButtonElement','formAction']].forEach(function(p){
    var P=window[p[0]]&&window[p[0]].prototype;if(!P)return;
    var d=Object.getOwnPropertyDescriptor(P,p[1]);if(!d||!d.set)return;
    Object.defineProperty(P,p[1],{get:d.get,set:function(v){d.set.call(this,E(v));},configurable:true,enumerable:true});
  });
  [['HTMLAnchorElement','href'],['HTMLAreaElement','href'],['HTMLLinkElement','href']].forEach(function(p){
    var P=window[p[0]]&&window[p[0]].prototype;if(!P)return;
    var d=Object.getOwnPropertyDescriptor(P,p[1]);if(!d||!d.set)return;
    Object.defineProperty(P,p[1],{get:d.get,set:function(v){d.set.call(this,E(v));},configurable:true,enumerable:true});
  });
  (function(){var P=HTMLFormElement.prototype,d=Object.getOwnPropertyDescriptor(P,'action');if(d&&d.set)Object.defineProperty(P,'action',{get:d.get,set:function(v){d.set.call(this,E(v));},configurable:true,enumerable:true});})();
  (function(){var P=HTMLObjectElement.prototype,d=Object.getOwnPropertyDescriptor(P,'data');if(d&&d.set)Object.defineProperty(P,'data',{get:d.get,set:function(v){d.set.call(this,E(v));},configurable:true,enumerable:true});})();
  document.addEventListener('click',function(e){
    var t=e.target;while(t&&t.tagName!=='A')t=t.parentElement;if(!t)return;
    var raw=t.getAttribute('href');if(!raw||raw==='/'||raw==='')return;
    t.removeAttribute('target');
    if(raw.startsWith('/pe/'))return;
    if(SKIP.test(raw))return;
    try{var abs=new URL(raw,B).href;if((abs.startsWith('http://')||abs.startsWith('https://'))&&!abs.startsWith(_rawLoc('origin'))){e.preventDefault();e.stopPropagation();if(_LD.href&&_LD.href.set)_LD.href.set.call(location,E(abs));}}catch(err){}
  },true);
  document.addEventListener('submit',function(e){
    var f=e.target;if(!f||f.tagName!=='FORM')return;
    var a=f.getAttribute('action')||'';if(!a||a.startsWith('/pe/')||SKIP.test(a))return;
    try{var abs=new URL(a,B).href;if((abs.startsWith('http://')||abs.startsWith('https://'))&&!abs.startsWith(_rawLoc('origin')))f.action=E(abs);}catch(err){}
  },true);
  var DUA=['data-src','data-srcset','data-lazy-src','data-original','data-bg','data-href','data-url','data-poster'];
  function rwEl(el){
    if(el.tagName==='A'||el.tagName==='AREA'){
      el.removeAttribute('target');var h=el.getAttribute('href');
      if(h&&h!=='/'&&h!==''&&!h.startsWith('/pe/')&&!SKIP.test(h)){
        try{var a=new URL(h,B).href;if(a.startsWith('http'))_sa.call(el,'href',E(a));}catch(e){}
      }
    }
    if(el.tagName==='FORM'){
      el.removeAttribute('target');var ac=el.getAttribute('action');
      if(ac&&!ac.startsWith('/pe/')){try{var a2=new URL(ac,B).href;if(a2.startsWith('http'))_sa.call(el,'action',E(a2));}catch(e){}}
    }
    var tag=el.tagName;
    if(tag==='IMG'||tag==='SCRIPT'||tag==='LINK'||tag==='IFRAME'||tag==='VIDEO'||tag==='AUDIO'||tag==='SOURCE'||tag==='EMBED'||tag==='TRACK'||tag==='INPUT'){
      var s=el.getAttribute('src')||el.getAttribute('href');
      if(s&&!s.startsWith('/pe/')&&!s.startsWith('data:')&&!s.startsWith('blob:')){
        try{var a3=new URL(s,B).href;if(a3.startsWith('http'))_sa.call(el,el.hasAttribute('src')?'src':'href',E(a3));}catch(e){}
      }
      var ss=el.getAttribute('srcset');if(ss)_sa.call(el,'srcset',Esrcset(ss));
      DUA.forEach(function(da){var v=el.getAttribute(da);if(v&&!v.startsWith('/pe/')&&!v.startsWith('data:')){try{var a4=new URL(v,B).href;if(a4.startsWith('http'))_sa.call(el,da,E(a4));}catch(e){}}});
    }
    if(el.hasAttribute('integrity'))el.removeAttribute('integrity');
    if(el.hasAttribute('nonce'))el.removeAttribute('nonce');
    if(el.hasAttribute('crossorigin'))el.removeAttribute('crossorigin');
  }
  var obs=new MutationObserver(function(muts){
    muts.forEach(function(m){
      m.addedNodes.forEach(function(n){
        if(n.nodeType!==1)return;rwEl(n);
        if(n.querySelectorAll)n.querySelectorAll('a[href],area[href],form[action],img[src],img[data-src],link[href],script[src],iframe[src],video[src],audio[src],source[src],embed[src],track[src],input[src],[integrity],[nonce],[crossorigin],[srcset]').forEach(rwEl);
      });
    });
  });
  var _dw=document.write;var _dwl=document.writeln;
  function _rwHtml(h){if(!h||typeof h!=='string')return h;return h.replace(/(href|src|action|data|poster|background)\\s*=\\s*(["'])([^"']*)\\2/gi,function(m,attr,q,url){if(!url||SKIP.test(url))return m;return attr+'='+q+E(url)+q;});}
  document.write=function(){var a=[];for(var i=0;i<arguments.length;i++)a.push(typeof arguments[i]==='string'?_rwHtml(arguments[i]):arguments[i]);return _dw.apply(document,a);};
  document.writeln=function(){var a=[];for(var i=0;i<arguments.length;i++)a.push(typeof arguments[i]==='string'?_rwHtml(arguments[i]):arguments[i]);return _dwl.apply(document,a);};
  if(CSSStyleSheet.prototype.insertRule){var _csIR=CSSStyleSheet.prototype.insertRule;CSSStyleSheet.prototype.insertRule=function(r,i){if(typeof r==='string')r=r.replace(/url\\(\\s*(['"]?)([^'")\\s]+)\\1\\s*\\)/gi,function(m,q,u){if(SKIP.test(u))return m;return 'url('+q+E(u)+q+')';});return _csIR.call(this,r,i);};}
  if(window.Blob){var _Blb=window.Blob;window.Blob=function(p,o){if(o&&o.type&&/javascript|ecmascript/i.test(o.type)&&Array.isArray(p)){p=p.map(function(s){if(typeof s==='string')return s.replace(/importScripts\\s*\\(\\s*(["'])(https?:\\/\\/[^"'\\s]+)\\1/g,function(m,q,u){return 'importScripts('+q+E(u)+q;});return s;});}return new _Blb(p,o);};window.Blob.prototype=_Blb.prototype;}
  obs.observe(document.documentElement,{childList:true,subtree:true});
})();
</script>`;
}

const EXPERIMENTAL_REQUEST_TIMEOUT_MS = 25000;
const EXPERIMENTAL_MAX_REDIRECTS = 5;

function requestWithNode(targetUrl, opts, redirectCount = 0) {
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
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && redirectCount < EXPERIMENTAL_MAX_REDIRECTS) {
        const loc = res.headers.location;
        if (loc) {
          try {
            const nextUrl = new URL(loc, targetUrl).href;
            if (/^https?:/.test(nextUrl)) {
              res.resume();
              requestWithNode(nextUrl, { ...opts, headers: { ...opts.headers, host: new URL(nextUrl).host } }, redirectCount + 1)
                .then(resolve).catch(reject);
              return;
            }
          } catch (_) {}
        }
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ res, body: Buffer.concat(chunks), chunks }));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(EXPERIMENTAL_REQUEST_TIMEOUT_MS, () => {
      req.destroy();
      reject(new Error("Request timeout"));
    });
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
  if (isBlockedUrl(targetUrl)) {
    return res.status(403).send("Access to internal/private addresses is blocked.");
  }
  if (req.method === "GET" && req.query && Object.keys(req.query).length > 0) {
    try {
      const u = new URL(targetUrl);
      for (const [k, v] of Object.entries(req.query)) {
        if (k === "nojs" || k === "noimg" || k === "eruda") continue;
        u.searchParams.set(k, v);
      }
      targetUrl = u.href;
    } catch (e) {
      console.error("[experimental proxy] Failed to merge query params:", e.message);
    }
  }

  const opts = { nojs: req.query.nojs === "1", noimg: req.query.noimg === "1", eruda: req.query.eruda === "1" };
  const optQs = [];
  if (opts.nojs) optQs.push("nojs=1");
  if (opts.noimg) optQs.push("noimg=1");
  if (opts.eruda) optQs.push("eruda=1");
  const optSuffix = optQs.length ? "?" + optQs.join("&") : "";

  const proxyHost = req.headers.host || "localhost";

  try {
    const headers = buildStealthHeaders(targetUrl, req);
    let body;
    if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && req.body) {
      const ct = req.headers["content-type"] || "";
      if (Buffer.isBuffer(req.body)) {
        body = req.body;
      } else if (typeof req.body === "object" && ct.includes("json")) {
        body = JSON.stringify(req.body);
        headers["content-type"] = "application/json";
      } else if (typeof req.body === "object") {
        body = new URLSearchParams(req.body).toString();
        headers["content-type"] = "application/x-www-form-urlencoded";
      } else {
        body = req.body;
      }
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
        try {
          const abs = new URL(loc, targetUrl).href;
          if (/^https?:/.test(abs)) return res.redirect(upstream.statusCode, encPe(abs) + optSuffix);
        } catch (_) {}
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

    const rawSetCookies = upstream.headers["set-cookie"];
    if (rawSetCookies) {
      const cookies = Array.isArray(rawSetCookies) ? rawSetCookies : [rawSetCookies];
      for (const c of cookies) {
        res.append("set-cookie", remapSetCookie(c, proxyHost, targetUrl));
      }
    }
    for (const [k, v] of Object.entries(upstream.headers)) {
      const kl = k.toLowerCase();
      if (STRIP_RESPONSE_HEADERS.has(kl)) continue;
      if (kl === "set-cookie") continue;
      if (!decompressed && (kl === "content-encoding" || kl === "content-length")) continue;
      try {
        if (!Array.isArray(v)) res.set(k, v);
      } catch (e) { /* skip headers that Express rejects */ }
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
      if (opts.eruda) {
        html = html.replace(/<\/head>/i, '<script src="https://cdn.jsdelivr.net/npm/eruda"></script><script>eruda.init();</script></head>');
      }
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
    if (contentType.includes("javascript") || contentType.includes("ecmascript")) {
      if (!decompressed) {
        res.set("content-type", upstream.headers["content-type"] || "application/javascript");
        if (contentEncoding) res.set("content-encoding", contentEncoding);
        res.set("content-length", rawBody.length);
        return res.send(rawBody);
      }
      const js = rewriteJsUrls(bodyBuffer.toString("utf8"), targetUrl, "/pe/");
      res.type(upstream.headers["content-type"] || "application/javascript").send(js);
      return;
    }

    res.set("content-type", upstream.headers["content-type"] || "application/octet-stream");
    res.send(bodyBuffer);
  } catch (err) {
    const isLogOrAnalytics = /\.(google|googleapis|gstatic)\.com\/(log|analytics|collect|gen_204)/i.test(targetUrl || "") || /\/(log|analytics|collect|beacon|ping)(\?|&|$)/i.test(targetUrl || "");
    if (!isLogOrAnalytics) console.error("[experimental proxy error]", targetUrl, err.message);
    const safeTarget = (targetUrl || "").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const safeErr = (err.message || "Unknown error").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    res.status(502).send(`<!DOCTYPE html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Void Experimental - Connection Failed</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&family=JetBrains+Mono:wght@400&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{background:#06060b;color:#9a9bb8;font-family:'Inter',system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem;-webkit-font-smoothing:antialiased}
.wrap{max-width:480px;text-align:center}
.code{font-size:6rem;font-weight:900;letter-spacing:-.06em;line-height:1;background:linear-gradient(135deg,#ff5f8f,#7c6aff);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;filter:drop-shadow(0 0 40px rgba(255,95,143,.15))}
h1{font-size:1.4rem;font-weight:700;color:#eef0f8;margin:.8rem 0 .5rem}
p{font-size:.85rem;line-height:1.6;margin:.6rem 0}
.badge{display:inline-block;font-size:.55rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:3px 8px;border-radius:5px;background:rgba(255,95,143,.1);color:#ff5f8f;border:1px solid rgba(255,95,143,.15);margin-bottom:.8rem}
.url{display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);padding:6px 14px;border-radius:8px;font-family:'JetBrains Mono',monospace;font-size:.78rem;color:#646478;margin:.6rem 0}
.err{font-size:.78rem;color:#ff5f8f;background:rgba(255,95,143,.06);border:1px solid rgba(255,95,143,.12);padding:8px 14px;border-radius:8px;margin:.8rem 0;font-family:'JetBrains Mono',monospace}
.btn{display:inline-flex;align-items:center;gap:6px;padding:10px 24px;border-radius:10px;background:linear-gradient(135deg,#7c6aff,#ff5f8f);color:#fff;text-decoration:none;font-weight:700;font-size:.82rem;letter-spacing:.02em;margin-top:1.2rem;box-shadow:0 4px 20px rgba(124,106,255,.3);transition:transform .15s,box-shadow .2s}
.btn:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(124,106,255,.4)}
</style></head><body>
<div class="wrap">
<div class="code">502</div>
<span class="badge">Experimental Engine</span>
<h1>Connection Failed</h1>
<p>Void's experimental engine couldn't reach the requested page.</p>
<div class="url">${safeTarget}</div>
<div class="err">${safeErr}</div>
<p style="font-size:.78rem;color:#464660">The site may be down, blocking requests, or requires features not yet supported by the experimental engine.</p>
<a class="btn" href="/">&#8592; Back to Void</a>
</div></body></html>`);
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

  conn.on("error", (err) => {
    console.error("[ws-proxy] Target connection error:", err.message);
    socket.destroy();
    conn.destroy();
  });
  socket.on("error", (err) => {
    console.error("[ws-proxy] Client socket error:", err.message);
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

/* ═══════════════════════════════════════════
/* -------------------------------------------
   Shared Serper fetch  single call path for
   both /api/search and /serper-results
   ------------------------------------------- */

let searchCallCount = 0;

async function fetchSerperResults(q, num = 8) {
  const suffix = "|serper|" + num;
  const cached = serperCacheGet(q, suffix);
  if (cached) return { results: cached, fromCache: true };

  const apiKey = process.env.SERPER_API_KEY || "1729c383021935c483b8b324b106c3fbd6d09ff3";
  try {
    const res = await axios.post("https://google.serper.dev/search", { q, num }, {
      headers: { "X-API-KEY": apiKey, "Content-Type": "application/json" },
      timeout: 8000
    });
    const data = res.data;
    const results = [];
    if (data.knowledgeGraph?.website) {
      const kg = data.knowledgeGraph;
      results.push({ title: kg.title || kg.website, url: kg.website, snippet: kg.description || kg.type || "", type: "kg" });
    }
    if (Array.isArray(data.organic)) {
      for (const item of data.organic) {
        if (item.link) results.push({ title: item.title || item.link, url: item.link, snippet: item.snippet || "", type: "web" });
        if (results.length >= num) break;
      }
    }
    if (results.length > 0) {
      serperCacheSet(q, results, suffix);
      return { results, fromCache: false };
    }
  } catch (err) {
    console.error("[serper] fetch failed:", err.message);
  }
  return { results: null, fromCache: false };
}

async function fetchSerpApiResults(q, num = 8) {
  const suffix = "|serpapi|" + num;
  const cached = serperCacheGet(q, suffix);
  if (cached) return { results: cached, fromCache: true };

  const apiKey = process.env.SERPAPI_KEY || "cb26624d508f0419e7524a4cc13b0b0495849fad9da5c910af58648b1456ab85";
  try {
    const url = `https://serpapi.com/search.json?q=${encodeURIComponent(q)}&num=${num}&engine=google&api_key=${apiKey}`;
    const res = await axios.get(url, { timeout: 10000 });
    const data = res.data;
    const results = [];
    if (data.knowledge_graph?.website) {
      const kg = data.knowledge_graph;
      results.push({ title: kg.title || kg.website, url: kg.website, snippet: kg.description || "", type: "kg" });
    }
    if (Array.isArray(data.organic_results)) {
      for (const item of data.organic_results) {
        if (item.link) results.push({ title: item.title || item.link, url: item.link, snippet: item.snippet || "", type: "web" });
        if (results.length >= num) break;
      }
    }
    if (results.length > 0) {
      serperCacheSet(q, results, suffix);
      return { results, fromCache: false };
    }
  } catch (err) {
    console.error("[serpapi] fetch failed:", err.message);
  }
  return { results: null, fromCache: false };
}

async function fetchDdgFallback(q, num = 8) {
  try {
    const ddgRes = await axios.get(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(q)}`, {
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" },
      timeout: 8000
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
        } catch (e) {}
      }
      if (href && /^https?:\/\//i.test(href)) {
        fallbackResults.push({ title: title || href, url: href, snippet, type: "web" });
      }
      if (fallbackResults.length >= num) return false;
    });
    return { results: fallbackResults, fromCache: false };
  } catch (e) {
    console.error("[serpapi] DDG fallback error:", e.message);
  }
  return { results: [], fromCache: false, error: "Search failed" };
}

async function fetchUnifiedAlternatingSearch(q, num = 8) {
  // Random choice preferring SerpApi (75% SerpApi, 25% Serper)
  const preferSerpApi = Math.random() < 0.75;
  if (preferSerpApi) {
    const res1 = await fetchSerpApiResults(q, num);
    if (res1.results && res1.results.length > 0) return res1;
    const res2 = await fetchSerperResults(q, num);
    if (res2.results && res2.results.length > 0) return res2;
  } else {
    const res1 = await fetchSerperResults(q, num);
    if (res1.results && res1.results.length > 0) return res1;
    const res2 = await fetchSerpApiResults(q, num);
    if (res2.results && res2.results.length > 0) return res2;
  }
  return fetchDdgFallback(q, num);
}

app.get("/api/serpapi-search", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.status(400).json({ error: "Missing query parameter q" });
  const num = Math.min(10, Math.max(1, parseInt(req.query.num, 10) || 8));
  const { results, fromCache } = await fetchUnifiedAlternatingSearch(q, num);
  return res.json({ cached: fromCache, results: results || [] });
});

app.get("/api/search", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.status(400).json({ error: "Missing query parameter q" });
  const num = Math.min(10, Math.max(1, parseInt(req.query.num, 10) || 8));
  const { results, fromCache } = await fetchUnifiedAlternatingSearch(q, num);
  return res.json({ cached: fromCache, results: results || [] });
});

app.get("/api/autocomplete", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.json({ suggestions: [] });

  const apiKey = process.env.SERPAPI_KEY || "cb26624d508f0419e7524a4cc13b0b0495849fad9da5c910af58648b1456ab85";
  try {
    const url = `https://serpapi.com/search.json?engine=google_autocomplete&q=${encodeURIComponent(q)}&api_key=${apiKey}`;
    const r = await axios.get(url, { timeout: 5000 });
    const suggestions = (r.data.suggestions || []).map(s => s.value || s.suggestion || s).filter(Boolean);
    if (suggestions.length > 0) {
      return res.json({ suggestions });
    }
  } catch (e) {}

  try {
    const url = `https://suggestqueries.google.com/complete/search?client=chrome&q=${encodeURIComponent(q)}`;
    const r = await axios.get(url, { timeout: 4000 });
    if (Array.isArray(r.data) && Array.isArray(r.data[1])) {
      return res.json({ suggestions: r.data[1].slice(0, 8) });
    }
  } catch (e) {}

  return res.json({ suggestions: [] });
});

app.get("/api/images", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.json({ images: [] });

  try {
    const url = `https://serpapi.com/search.json?engine=google_images&q=${encodeURIComponent(q)}&api_key=${apiKey}`;
    const r = await axios.get(url, { timeout: 10000 });
    const images = (r.data.images_results || []).map(img => ({
      title: img.title || "",
      original: img.original || img.link,
      thumbnail: img.thumbnail,
      source: img.source || img.domain
    })).slice(0, 20);
    return res.json({ images });
  } catch (e) {
    return res.status(500).json({ error: e.message, images: [] });
  }
});

app.get("/api/youtube", async (req, res) => {
  const q = (req.query.q || "").trim();
  const v = (req.query.v || "").trim();
  const apiKey = process.env.SERPAPI_KEY || "cb26624d508f0419e7524a4cc13b0b0495849fad9da5c910af58648b1456ab85";

  if (v) {
    try {
      const videoUrl = `https://serpapi.com/search.json?engine=youtube_video&v=${encodeURIComponent(v)}&api_key=${apiKey}`;
      const transcriptUrl = `https://serpapi.com/search.json?engine=youtube_video_transcript&v=${encodeURIComponent(v)}&api_key=${apiKey}`;
      const [vRes, tRes] = await Promise.allSettled([
        axios.get(videoUrl, { timeout: 8000 }),
        axios.get(transcriptUrl, { timeout: 8000 })
      ]);
      const video = vRes.status === "fulfilled" ? vRes.value.data : {};
      const transcript = tRes.status === "fulfilled" ? tRes.value.data : {};
      return res.json({ video, transcript });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  if (!q) return res.json({ videos: [] });

  try {
    const url = `https://serpapi.com/search.json?engine=youtube&search_query=${encodeURIComponent(q)}&api_key=${apiKey}`;
    const r = await axios.get(url, { timeout: 10000 });
    const videos = (r.data.video_results || []).map(vid => ({
      title: vid.title,
      link: vid.link,
      videoId: vid.link ? (vid.link.match(/v=([^&]+)/) || [])[1] : null,
      thumbnail: vid.thumbnail?.static || vid.thumbnail,
      channel: vid.channel?.name,
      views: vid.views,
      published: vid.published_date
    })).slice(0, 15);
    return res.json({ videos });
  } catch (e) {
    return res.status(500).json({ error: e.message, videos: [] });
  }
});

app.get(["/serper-results", "/sr", "/serpapi-results", "/s"], async (req, res) => {
  let rawQ = (req.query.q || "").trim();
  if (!rawQ) return res.redirect("/");

  let q = rawQ;
  try { q = dec(rawQ); } catch (e) {}

  const safeQ = q.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

  res.type("text/html; charset=utf-8").send(`<!DOCTYPE html>
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
.topbar input{flex:1;background:#ffffff;border:1px solid #000000;border-radius:0;color:#000000;font-family:'Times New Roman',Times,serif;font-size:1rem;padding:6px 10px;outline:none;}
.topbar input:focus{border-color:#000000;}
.topbar button{padding:6px 14px;border-radius:0;background:#eeeeee;border:1px solid #000000;color:#000000;font-weight:bold;font-size:.9rem;cursor:pointer;white-space:nowrap;}
.topbar .back{padding:6px 12px;border-radius:0;background:#eeeeee;border:1px solid #000000;color:#000000;font-size:.9rem;text-decoration:none;display:inline-flex;}
.topbar .back:hover{background:#dddddd;}
.main{max-width:760px;margin:0 auto;padding:24px 20px 60px;}
.meta{font-size:.9rem;color:#555555;margin-bottom:20px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.meta .dot{width:4px;height:4px;border-radius:50%;background:#000000;}
.cache-tag{font-size:.7rem;padding:2px 5px;border:1px solid #000000;text-transform:uppercase;}
.cache-tag.live{background:#ffffff;color:#000000;}
.cache-tag.cached{background:#eeeeee;color:#000000;}
.result{display:block;padding:16px 0;border-bottom:1px solid #dddddd;margin-bottom:12px;}
.result:hover{background:#f9f9f9;}
.result-head{display:flex;align-items:center;gap:7px;margin-bottom:4px;}
.fav{width:14px;height:14px;}
.domain{font-size:.8rem;color:#555555;font-family:'Times New Roman',Times,serif;}
.badge{font-size:.6rem;padding:1px 4px;border:1px solid #000;margin-left:4px;background:#fff;color:#000;}
.result-title{font-size:1.1rem;font-weight:bold;color:#0000cc;margin-bottom:4px;}
.result:hover .result-title{text-decoration:underline;}
.result-snippet{font-size:.9rem;color:#333333;line-height:1.4;}
.no-results{text-align:center;padding:60px;color:#555555;font-size:1rem;}
.spinner{display:flex;align-items:center;justify-content:center;padding:60px;gap:12px;color:#000;font-size:1rem;}
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
<div class="main">
  <div class="meta" id="meta"></div>
  <div id="results"><div class="spinner"><div class="spin"></div>Searching…</div></div>
</div>
<script>
(function(){
  var Q = ${JSON.stringify(safeQ)};
  var CACHE_TTL = 24 * 60 * 60 * 1000;
  var CACHE_PREFIX = 'void_search_';

  function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  function levenshtein(a,b){
    if(a===b)return 0;
    var dp=[];
    for(var i=0;i<=a.length;i++){dp[i]=[i];}
    for(var j=1;j<=b.length;j++)dp[0][j]=j;
    for(var i=1;i<=a.length;i++)for(var j=1;j<=b.length;j++)
      dp[i][j]=a[i-1]===b[j-1]?dp[i-1][j-1]:1+Math.min(dp[i-1][j],dp[i][j-1],dp[i-1][j-1]);
    return dp[a.length][b.length];
  }

  function maxDist(q){ return q.length<=5?1:q.length<=12?2:3; }

  function normQ(q){ return q.toLowerCase().trim().replace(/\s+/g,' ').replace(/[^\w\s]/g,''); }

  function findCache(qNorm){
    try{
      for(var i=0;i<sessionStorage.length;i++){
        var k=sessionStorage.key(i);
        if(!k||!k.startsWith(CACHE_PREFIX))continue;
        var kq=k.slice(CACHE_PREFIX.length);
        if(levenshtein(qNorm,kq)<=maxDist(qNorm)){
          var entry=JSON.parse(sessionStorage.getItem(k)||'null');
          if(entry&&Array.isArray(entry.results)&&Date.now()-entry.ts<CACHE_TTL)
            return{results:entry.results,cached:true};
        }
      }
    }catch(e){}
    return null;
  }

  function saveCache(qNorm,results){
    try{ sessionStorage.setItem(CACHE_PREFIX+qNorm,JSON.stringify({results:results,ts:Date.now()})); }catch(e){}
  }

  function renderResult(r){
    var domain='';try{domain=new URL(r.url).hostname;}catch(e){}
    var fav=domain?'<img class="fav" src="https://www.google.com/s2/favicons?domain='+encodeURIComponent(domain)+'&sz=32" alt="" onerror="this.style.display=\'none\'"/>':'';
    var badge=r.type==='kg'?'<span class="badge">Info</span>':'';
    var snippet=r.snippet?'<div class="result-snippet">'+esc(r.snippet.slice(0,180))+'</div>':'';
    var proxyUrl='/p/'+btoa(r.url).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
    return '<a class="result" href="'+proxyUrl+'">'
      +'<div class="result-head">'+fav+'<span class="domain">'+esc(domain)+'</span>'+badge+'</div>'
      +'<div class="result-title">'+esc(r.title||domain||r.url)+'</div>'
      +snippet+'</a>';
  }

  function render(results, fromCache){
    var meta=document.getElementById('meta');
    var res=document.getElementById('results');
    if(meta){
      meta.innerHTML='<span>'+results.length+' results for <strong>"'+esc(Q)+'"</strong></span>'
        +'<span class="dot"></span><span>via Mega Engine</span>'
        +(fromCache
          ?'<span class="dot"></span><span class="cache-tag cached">cached</span>'
          :'<span class="dot"></span><span class="cache-tag live">live</span>');
    }
    if(res){
      res.innerHTML=results.length
        ?results.map(renderResult).join('')
        :'<div class="no-results">No results found — try a different query.</div>';
    }
  }

  var qNorm=normQ(Q);
  var hit=findCache(qNorm);
  if(hit){
    render(hit.results,true);
    return;
  }

  fetch('/api/search?q='+encodeURIComponent(Q)+'&num=10')
    .then(function(r){return r.ok?r.json():null;})
    .then(function(data){
      if(!data||!Array.isArray(data.results)||!data.results.length){
        render([], false);
        return;
      }
      saveCache(qNorm,data.results);
      render(data.results,data.cached||false);
    })
    .catch(function(){
      render([], false);
    });
})();
</script>
</body>
</html>`);
});

app.get("/api/health", (_req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.json({ status: "ok", version: "4.5.2", isVercel: !!process.env.VERCEL, uptime: Math.floor(process.uptime()) });
});

app.get("/api/raw", async (req, res) => {
  const targetUrl = (req.query.url || "").trim();
  if (!targetUrl) return res.status(400).send("Missing url parameter");
  try {
    const parsed = new URL(targetUrl);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).send("Only http and https protocols are supported");
    }
    const host = parsed.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host.startsWith("169.254.")) {
      return res.status(403).send("Forbidden host");
    }
    const r = await fetch(targetUrl, {
      headers: { "User-Agent": "Void-Proxy/4.5.2" }
    });
    if (!r.ok) return res.status(r.status).send("Upstream HTTP " + r.status);
    const content = await r.text();
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Cache-Control", "public, max-age=60");
    res.send(content);
  } catch (err) {
    res.status(500).send("Fetch error: " + err.message);
  }
});

app.get(["/go", "/v"], (req, res) => {
  let rawInput = (req.query.q || req.query.url || "").trim();
  if (!rawInput) return res.redirect("/");

  let url = rawInput;
  try {
    url = dec(rawInput);
  } catch (e) {
    url = rawInput;
  }

  if (!/^https?:\/\//i.test(url)) {
    if (url.includes(".") && !url.includes(" ")) {
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
  if (mode === "experimental") {
    return res.redirect(encPe(url) + qsStr);
  }
  res.redirect(enc(url) + qsStr);
});

app.all("/p/:encoded", handleProxy);
app.all("/pe/:encoded", handleExperimentalProxy);

app.get("/void-minimal.html", (_req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.sendFile(join(__dirname, "void.html"));
});

app.get("/void.html", (_req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.sendFile(join(__dirname, "void.html"));
});

app.get("/", (_req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.sendFile(join(__dirname, "public", "index.html"));
});

app.get("/index.html", (_req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.sendFile(join(__dirname, "public", "index.html"));
});

app.get("/{*path}", (_req, res) => {
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

server.listen(PORT, "0.0.0.0", () => console.log(`Void proxy running on http://0.0.0.0:${PORT}`));

function gracefulShutdown(signal) {
  console.log(`Received ${signal}. Shutting down Void proxy server gracefully...`);
  server.close(() => {
    console.log("HTTP server closed.");
    process.exit(0);
  });
  setTimeout(() => {
    console.error("Forced shutdown after timeout.");
    process.exit(1);
  }, 10000).unref();
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

export default app;