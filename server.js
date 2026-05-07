import express from "express";
import { createServer } from "node:http";
import https from "node:https";
import http from "node:http";
import { createGunzip, createInflate, createBrotliDecompress } from "node:zlib";
import { Transform, Readable } from "node:stream";
import { createHash, randomUUID } from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import * as cheerio from "cheerio";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { promises as fs } from "node:fs";
import fsSync from "node:fs";
import { spawn } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
app.set("json spaces", 2);

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64, maxFreeSockets: 16, timeout: 30000 });
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 64, maxFreeSockets: 16, timeout: 30000 });

const CACHE_MAX_SIZE = 10000;
const CACHE_FILE = join(__dirname, ".void_cache.warc");

let _resourceCache = new Map();

function loadWarc() {
  if (!fsSync.existsSync(CACHE_FILE)) return;
  try {
    const buf = fsSync.readFileSync(CACHE_FILE);
    const delim = Buffer.from('\r\n\r\n');
    let offset = 0;
    while (offset < buf.length) {
      const headerEnd = buf.indexOf(delim, offset);
      if (headerEnd === -1) break;
      const headerStr = buf.toString('utf8', offset, headerEnd);

      const clMatch = headerStr.match(/Content-Length:\s*(\d+)/i);
      if (!clMatch) break;
      const cl = parseInt(clMatch[1], 10);
      if (!Number.isFinite(cl) || cl < 0 || cl > 50 * 1024 * 1024) break;

      const uriMatch = headerStr.match(/WARC-Target-URI:\s*([^\r\n]+)/i);
      const dateMatch = headerStr.match(/WARC-Date:\s*([^\r\n]+)/i);

      const httpOffset = headerEnd + 4;
      const httpEnd = httpOffset + cl;
      if (httpEnd > buf.length) break;

      const rawHttp = buf.subarray(httpOffset, httpEnd);
      const httpHdrEnd = rawHttp.indexOf(delim);
      if (httpHdrEnd !== -1) {
        const httpHdrs = rawHttp.toString('utf8', 0, httpHdrEnd);
        const ctMatch = httpHdrs.match(/Content-Type:\s*([^\r\n]+)/i);
        const ct = ctMatch ? ctMatch[1] : '';
        const body = rawHttp.subarray(httpHdrEnd + 4);

        if (uriMatch && uriMatch[1] && _resourceCache.size < CACHE_MAX_SIZE) {
          // Only cache http/https URIs
          const uri = uriMatch[1].trim();
          if (/^https?:\/\//i.test(uri)) {
            _resourceCache.set(uri, { ct, body, ts: dateMatch ? new Date(dateMatch[1]).getTime() : Date.now() });
          }
        }
      }
      offset = httpEnd + 4;
    }
    console.log(`[cache] Loaded ${_resourceCache.size} entries from WARC`);
  } catch (e) {
    console.error("[cache] Failed to load WARC:", e.message);
  }
}
loadWarc();

async function appendWarc(key, ct, bodyBuf, ts) {
  try {
    const httpHeaders = `HTTP/1.1 200 OK\r\nContent-Type: ${ct}\r\nContent-Length: ${bodyBuf.length}\r\n\r\n`;
    const httpBlock = Buffer.concat([Buffer.from(httpHeaders), bodyBuf]);
    const warcHeaders = `WARC/1.0\r\nWARC-Type: response\r\nWARC-Record-ID: <urn:uuid:${randomUUID()}>\r\nWARC-Date: ${new Date(ts).toISOString()}\r\nWARC-Target-URI: ${key}\r\nContent-Type: application/http; msgtype=response\r\nContent-Length: ${httpBlock.length}\r\n\r\n`;
    const fullRecord = Buffer.concat([Buffer.from(warcHeaders), httpBlock, Buffer.from('\r\n\r\n')]);
    await fs.appendFile(CACHE_FILE, fullRecord);
  } catch (e) {
    console.error("[cache] Failed to append WARC record:", e.message);
  }
}

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
  
  const ts = Date.now();
  _resourceCache.set(key, { ct, body: bodyBuf, ts });
  appendWarc(key, ct, bodyBuf, ts);
}

app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(express.json({ limit: "50mb" }));
app.use(express.raw({ type: "*/*", limit: "50mb" }));
app.use(express.static(join(__dirname, "public"), {
  maxAge: "1h",
  etag: true,
  lastModified: true,
}));

app.post("/api/cache-site", (req, res) => {
  const { url, urls } = req.body;
  const list = urls || (url ? [url] : []);
  if (!list.length) return res.status(400).json({ error: "Missing URL(s)" });

  // Validate each URL before spawning — prevents command injection via malformed input
  const validList = [];
  for (const u of list) {
    if (typeof u !== "string") continue;
    try {
      const parsed = new URL(u);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") continue;
      if (isBlockedUrl(u)) continue;
      validList.push(u);
    } catch {
      // skip invalid URLs
    }
  }
  if (!validList.length) return res.status(400).json({ error: "No valid URL(s) provided" });

  try {
    for (const u of validList) {
      const child = spawn("node", ["scripts/cache.mjs", u], {
        cwd: __dirname,
        stdio: "ignore",
        detached: true,
      });
      child.unref();
    }
    res.json({ success: true, message: `Caching job started for ${validList.length} URL(s)!` });
  } catch (e) {
    console.error("[cache-site] Failed to start caching job:", e.message);
    res.status(500).json({ error: "Failed to start caching job" });
  }
});

app.get("/api/cache-links", (req, res) => {
  const links = [];
  for (const [key, val] of _resourceCache.entries()) {
    if (key.startsWith("p:") && val.ct && val.ct.includes("text/html")) {
      // Decode URL if it was rewritten, mostly it's stored exactly as passing proxy
      const urlStr = key.substring(2);
      if (!urlStr.includes("uv.html") && !urlStr.includes("scramjet") && urlStr.includes("http")) {
        // Strip off base proxy path if accidentally appended, otherwise just the raw url
        links.push(urlStr);
      }
    }
  }
  res.json([...new Set(links)]);
});


/* ═══════════════════════════════════════════
   URL encoding / decoding helpers
   ═══════════════════════════════════════════ */

function enc(url) {
  return "/p/" + Buffer.from(url).toString("base64url");
}

function dec(encoded) {
  try {
    const str = String(encoded);
    // Accept both base64url (- _) and standard base64 (+ /)
    const normalized = str.replace(/-/g, "+").replace(/_/g, "/");
    const padding = normalized.length % 4;
    const padded = padding ? normalized + "=".repeat(4 - padding) : normalized;
    const decoded = Buffer.from(padded, "base64").toString("utf8");
    // Must decode to a valid http/https URL
    if (!/^https?:\/\//i.test(decoded)) throw new Error("Decoded value is not an http/https URL");
    return decoded;
  } catch (e) {
    throw new Error(`URL decode failed: ${e.message}`);
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
      if(a.startsWith('http'))return'/p/'+btoa(a).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/g,'');
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
  return `<div id="__vbar" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;height:42px;display:flex;align-items:center;gap:8px;padding:0 12px;background:rgba(6,6,11,.94);backdrop-filter:blur(16px) saturate(1.2);border-bottom:1px solid rgba(255,255,255,.06);font-family:-apple-system,system-ui,sans-serif;font-size:12px;color:#9a9bb8;box-shadow:0 4px 24px rgba(0,0,0,.3);">
<a href="/" target="_top" style="background:linear-gradient(135deg,#7c6aff,#ff5f8f);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;font-weight:900;text-decoration:none;letter-spacing:-.04em;font-size:16px;">void</a><span style="color:rgba(255,255,255,.4);font-size:12px;font-weight:500;margin-left:2px;">Go Anywhere</span>
<span style="width:1px;height:18px;background:rgba(255,255,255,.08);flex-shrink:0;"></span>
<button onclick="history.back()" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);color:#9a9bb8;border-radius:6px;width:28px;height:28px;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;" title="Back">&#8592;</button>
<button onclick="history.forward()" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);color:#9a9bb8;border-radius:6px;width:28px;height:28px;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;" title="Forward">&#8594;</button>
<button onclick="location.reload()" style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);color:#9a9bb8;border-radius:6px;width:28px;height:28px;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;" title="Reload">&#8635;</button>
<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:rgba(0,0,0,.35);padding:5px 12px;border-radius:8px;border:1px solid rgba(255,255,255,.05);font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace;font-size:11px;color:#646478;display:flex;align-items:center;gap:6px;">${faviconHtml}${safe}</span>
<a href="/" target="_top" style="padding:5px 14px;border-radius:8px;background:rgba(255,255,255,.05);color:#ccc;text-decoration:none;font-weight:600;font-size:11px;border:1px solid rgba(255,255,255,.06);transition:background .15s;">Home</a>
<button onclick="document.getElementById('__vbar').style.display='none';document.getElementById('__vsp').style.display='none';" style="padding:5px 9px;border-radius:8px;background:rgba(255,255,255,.04);color:#ff5f8f;border:1px solid rgba(255,255,255,.06);cursor:pointer;font-weight:700;font-size:13px;" aria-label="Close toolbar">&#x2715;</button>
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

    const fetchOpts = {
      method: req.method,
      headers,
      redirect: "manual",
      signal: AbortSignal.timeout(25000),
    };

    if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method) && req.body) {
      const ct = req.headers["content-type"] || "";
      if (Buffer.isBuffer(req.body)) {
        fetchOpts.body = req.body;
        if (ct) fetchOpts.headers["content-type"] = ct;
      } else if (typeof req.body === "object" && ct.includes("json")) {
        fetchOpts.body = JSON.stringify(req.body);
        fetchOpts.headers["content-type"] = "application/json";
      } else if (typeof req.body === "object") {
        fetchOpts.body = new URLSearchParams(req.body).toString();
        fetchOpts.headers["content-type"] = "application/x-www-form-urlencoded";
      } else {
        fetchOpts.body = req.body;
        if (ct) fetchOpts.headers["content-type"] = ct;
      }
    }

    if (req.method === "GET") {
      const cached = await cacheGet("p:" + targetUrl);
      if (cached) {
        res.set("X-Void-Cache", "HIT");
        if (cached.ct && cached.ct.includes("text/html")) {
          // Re-rewrite cached HTML with current options
          const rawHtml = cached.body.toString("utf8");
          const patched = rewriteHtmlWithOpts(rawHtml, targetUrl, opts, optSuffix);
          return res.type("text/html; charset=utf-8").send(patched);
        }
        res.set("content-type", cached.ct);
        return res.send(cached.body);
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

    const STRIP_RES = new Set([
      "content-security-policy", "content-security-policy-report-only",
      "x-frame-options", "strict-transport-security", "transfer-encoding",
      "content-encoding", "content-length", "set-cookie", "location",
      "cross-origin-opener-policy", "cross-origin-embedder-policy",
      "cross-origin-resource-policy", "permissions-policy",
      "x-content-type-options", "report-to",
    ]);
    for (const [k, v] of response.headers.entries()) {
      if (STRIP_RES.has(k.toLowerCase())) continue;
      try { res.set(k, v); } catch (e) { /* skip headers that Express rejects (e.g. invalid chars) */ }
    }
    const setCookies = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
    for (const raw of setCookies) {
      res.append("set-cookie", prefixSetCookie(raw, targetUrl));
    }

    // HTML → rewrite
    if (ct.includes("text/html")) {
      const text = await response.text();

      // Temporarily patch rewriteUrl to include options
      const patched = text ? rewriteHtmlWithOpts(text, targetUrl, opts, optSuffix) : text;
      res.type("text/html; charset=utf-8").send(patched);
      // Cache the raw (pre-rewrite) HTML so it can be re-rewritten on cache hit with fresh options
      cacheSet("p:" + targetUrl, "text/html; charset=utf-8", text || "");
      return;
    }

    if (ct.includes("text/css")) {
      const text = await response.text();
      const rewritten = rewriteCss(text, targetUrl);
      cacheSet("p:" + targetUrl, "text/css; charset=utf-8", rewritten);
      res.type("text/css; charset=utf-8").send(rewritten);
      return;
    }

    if (ct.includes("javascript") || ct.includes("ecmascript")) {
      const text = await response.text();
      const rewritten = rewriteJsUrls(text, targetUrl, "/p/");
      cacheSet("p:" + targetUrl, ct, rewritten);
      res.type(ct).send(rewritten);
      return;
    }

    res.set("content-type", ct);
    const cl = response.headers.get("content-length");
    if (cl) res.set("content-length", cl);

    if (/\/(image|font|woff|ttf|otf|png|jpg|jpeg|gif|webp|avif|svg|ico|mp4|webm|mp3)/i.test(ct)) {
      res.set("Cache-Control", "public, max-age=86400");
    }

    if (response.body && typeof Readable.fromWeb === "function") {
      try {
        Readable.fromWeb(response.body).pipe(res);
        return;
      } catch (streamErr) {
        console.error("[proxy] Stream pipe failed, falling back to buffer:", streamErr.message);
      }
    }
    const buf = Buffer.from(await response.arrayBuffer());
    if (buf.length < 2 * 1024 * 1024) cacheSet("p:" + targetUrl, ct, buf);
    res.send(buf);
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
    "sec-ch-ua-full-version-list": '"Safari";v="17.2.0", "Chromium";v="", "Not_A Brand";v="24.0.0"',
    "priority": "u=1",
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
  if ((req.url || "").startsWith("/pe-ws/")) {
    handlePeWsUpgrade(req, socket, head);
  } else {
    socket.destroy();
  }
});

server.listen(PORT, () => console.log(`Void proxy running on http://localhost:${PORT}`));
