# Void Proxy

A web proxy with a clean UI. Browse the web through the proxy with **Server-side** or **Experimental** mode.

## Features

- **Server-side proxy** – Fetches and rewrites pages on the server (HTML, CSS, links). No service worker.
- **Experimental proxy** – Custom engine: stealth headers, stream rewriting, cookie remap, WebSocket support.
- Search (Brave, Google, DuckDuckGo, Bing, Yahoo) or enter any URL.
- Optional: **Use iframe** (double iframe), **Tab cloak**, **Remove scripts/images**.
- **Shift+Esc** → show **Update** button (fetch latest from GitHub when repo is set).

## Run locally

```bash
npm install
npm start
```

Open http://localhost:8080

## Deploy (e.g. Render)

1. Push this repo to GitHub.
2. On [Render](https://render.com): **New** → **Web Service** → connect repo.
3. **Build command:** `npm install`  
   **Start command:** `npm start`
4. Create. Render sets `PORT`; the app uses it automatically.

## Project layout

- `server.js` – Node server (Express): `/go`, `/p/:encoded` (server-side), `/pe/:encoded` (experimental), WebSocket at `/pe-ws/`.
- `public/index.html` – Main UI (search, quick links, advanced options).
- `void.html` – Standalone alternate UI.

## License

MIT
