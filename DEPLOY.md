# How to deploy Void (completely free, no credit card)

**Glitch is ending hosting (July 2025).** Use the option below — **free, no credit card** required. Push your project to **GitHub** first.

---

## Replit

1. Go to [replit.com](https://replit.com) → **Sign up** or **Log in** (GitHub or email; no card).
2. **Create Repl** → **Import from GitHub** → paste your repo URL: `https://github.com/YOUR_USERNAME/proxy-site`.
3. Replit clones the repo. It should detect Node. Set **Run** to `npm start` if it doesn’t auto-run.
4. Click **Run**. Your app URL appears at the top (e.g. `https://proxy-site.YOUR_USERNAME.repl.co`). Open it in a new tab or use the **Webview** panel.

**Note:** The Repl sleeps when idle; first load after sleep can be slow. **No credit card required.**  
⚠️ Replit sometimes blocks proxy-style apps (Terms of Service). If your Repl is disabled, use one of the options below.

---

## Other hosting options

### Render
- [render.com](https://render.com) → **New** → **Web Service** → connect GitHub repo.
- **Build:** `npm install` | **Start:** `npm start` | **Instance:** Free.
- Free tier: no card required. App sleeps after ~15 min idle.
- Some proxy apps may be restricted; worth trying.

### Doprax
- [doprax.com](https://www.doprax.com) → Sign up → create app from **GitHub**.
- Supports Node; use a **Dockerfile** or their Node template. Set start to `npm start`.
- Free tier available; check current limits on the site.

### Run on your computer + tunnel (no host can block it)
Run the app locally and expose it with a free tunnel so you get a public URL:

1. **Terminal 1:** `cd proxy-site && npm install && npm start`
2. **Terminal 2:** `npx localtunnel --port 8080`  
   Use the `https://....loca.lt` URL it prints.

Or use **Cloudflare Tunnel**: install [cloudflared](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/), then:
```bash
cloudflared tunnel --url http://localhost:8080
```
You get a `*.trycloudflare.com` URL. No signup, no card, no host ToS.

---

## After deploy

- Open your live URL. You should see the Void UI.
- To use **UV** or **Scramjet**, deploy them separately and set **UV backend URL** and **Scramjet backend URL** in Void’s Advanced section. See **docs/UV-SCRAMJET-KOYEB.md** for that.

---

## Port note

This app already uses `process.env.PORT || 8080`, so the host can set the port. No change needed.
