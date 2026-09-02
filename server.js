/* ═══════════════════════════════════════════
   Search & Free Public Autocomplete Endpoints
   ═══════════════════════════════════════════ */

// Default search routing now maps google -> bing
const SEARCH_ENGINES = {
  brave:  q => "https://search.brave.com/search?q=" + encodeURIComponent(q),
  bing:   q => "https://www.bing.com/search?q=" + encodeURIComponent(q),
  google: q => "https://www.bing.com/search?q=" + encodeURIComponent(q), // Replaced with Bing
  ddg:    q => "https://html.duckduckgo.com/html/?q=" + encodeURIComponent(q),
};

// Bing Web Scraper Fallback (Zero-Key)
async function fetchBingFallback(q, num = 10) {
  try {
    const res = await axios.get(`https://www.bing.com/search?q=${encodeURIComponent(q)}`, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.bing.com/"
      },
      timeout: 6000
    });
    const $ = cheerio.load(res.data);
    const results = [];
    $("#b_results .b_algo").each((_, el) => {
      const a = $(el).find("h2 a").first();
      const title = a.text().trim();
      const url = a.attr("href");
      const snippet = $(el).find(".b_caption p").text().trim();
      if (url && /^https?:\/\//i.test(url)) {
        results.push({ title: title || url, url, snippet });
      }
      if (results.length >= num) return false;
    });
    return results;
  } catch (err) {
    return [];
  }
}

app.get("/api/search", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.status(400).json({ error: "Missing query parameter q" });
  const num = Math.min(10, Math.max(1, parseInt(req.query.num, 10) || 8));

  // 1. SerpApi Bing Request (Uses Bing directly)
  if (SERPAPI_KEY) {
    try {
      const serpUrl = `https://serpapi.com/search.json?engine=bing&q=${encodeURIComponent(q)}&count=${num}&api_key=${SERPAPI_KEY}`;
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

  // 2. Serper Fallback
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

  // 3. Fallback to Native Bing Scraper
  const bingResults = await fetchBingFallback(q, num);
  if (bingResults.length > 0) {
    return res.json({ cached: false, results: bingResults });
  }

  // 4. Fallback to DDG Scraper
  const ddgResults = await fetchDdgFallback(q, num);
  return res.json({ cached: false, results: ddgResults });
});

app.get("/api/images", async (req, res) => {
  const q = (req.query.q || "").trim();
  if (!q) return res.json({ images: [] });
  if (SERPAPI_KEY) {
    try {
      // Switched engine to bing_images
      const url = `https://serpapi.com/search.json?engine=bing_images&q=${encodeURIComponent(q)}&api_key=${SERPAPI_KEY}`;
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