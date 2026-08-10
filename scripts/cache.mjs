import * as cheerio from "cheerio";

const TARGET_URL = process.argv[2];

if (!TARGET_URL) {
  console.error("Usage: node scripts/cache.mjs <URL>");
  console.error("Example: node scripts/cache.mjs https://example.com");
  process.exit(1);
}

const PROXY_BASE = "http://localhost:8080/go?mode=server&engine=brave&offline=0&url=";

const visited = new Set();
// We queue PROXY urls, not raw URLs
const proxyQueue = [PROXY_BASE + encodeURIComponent(TARGET_URL)];

async function crawl() {
  console.log(`Starting proxy cache scraper for ${TARGET_URL}...`);
  let count = 0;
  
  while (proxyQueue.length > 0 && count < 4000) {
    const currentProxyUrl = proxyQueue.shift();
    if (visited.has(currentProxyUrl)) continue;
    visited.add(currentProxyUrl);
    count++;
    
    console.log(`[${count}] Caching: ${currentProxyUrl}`);
    
    try {
      const res = await fetch(currentProxyUrl);
      const ct = res.headers.get("content-type") || "";
      
      if (ct.includes("text/html") || ct.includes("text/css") || ct.includes("javascript")) {
        const text = await res.text();
        
        // Find rewritten proxy URLs
        let match;
        const proxyRegex = /(?:\/p\/[A-Za-z0-9_=-]+|\/go\?[^"'\s>\\]+)/g;
        while ((match = proxyRegex.exec(text)) !== null) {
          const foundPath = match[0].replace(/&amp;/g, '&');
          const fullProxyUrl = "http://localhost:8080" + foundPath;
          if (!visited.has(fullProxyUrl) && !proxyQueue.includes(fullProxyUrl)) {
            proxyQueue.push(fullProxyUrl);
          }
        }
        
        // Find raw external HTTP/HTTPS URLs (for lazy loaded images/data-src strings)
        const rawUrlRegex = /(?:https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\/[^"'\s\)\\;]*)?)/g;
        while ((match = rawUrlRegex.exec(text)) !== null) {
          const rawUrl = match[0].replace(/&amp;/g, '&');
          // Skip tracking /p/ inside raw URLs or local host itself backwards
          if (rawUrl.includes("localhost:")) continue;
          
          const fullProxyUrl = PROXY_BASE + encodeURIComponent(rawUrl);
          // Only add if it's from the same domain or a CDN to prevent internet explosion
          if (rawUrl.includes("gn-math") || rawUrl.includes("cdn") || rawUrl.includes("googleapis") || rawUrl.includes("gstatic")) {
             if (!visited.has(fullProxyUrl) && !proxyQueue.includes(fullProxyUrl)) {
               proxyQueue.push(fullProxyUrl);
             }
          }
        }
      } else {
        await res.arrayBuffer(); // drain body
      }
    } catch (err) {
      console.error(`Error:`, err.message);
    }
  }
  console.log(`Successfully cached ${count} files for offline viewing! Everything is saved in your .void_cache.warc format.`);
  process.exit(0);
}

crawl();
