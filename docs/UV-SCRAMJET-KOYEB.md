# Use Void HTML with UV and Scramjet on Koyeb

You can use **Void** (your proxy HTML) as the front-end and run **UV** and **Scramjet** as separate backends on Koyeb. When you pick UV or Scramjet in Void, it will open the site through your Koyeb-hosted instance.

## Overview

1. **Void (HTML)** = your UI. Host it anywhere:
   - Your current Node app (e.g. on Render) that serves `public/index.html`
   - Or the **single-file** `void.html` (e.g. on GitHub Pages, or open from file)
2. **UV** = one Koyeb app (from Ultraviolet-App)
3. **Scramjet** = another Koyeb app (from Scramjet-App)
4. In Void, set **UV backend URL** and **Scramjet backend URL** to the two Koyeb URLs.

---

## Step 1: Deploy UV on Koyeb

1. Go to [koyeb.com](https://www.koyeb.com) and sign in (or create an account).
2. Click **Create App** → **Web Service**.
3. **Source**: choose **GitHub**.
   - Connect GitHub if needed.
   - Repository: `titaniumnetwork-dev/Ultraviolet-App`
   - Branch: `main`
4. **Build**:
   - Builder: **Dockerfile** (Ultraviolet-App has a Dockerfile)  
     **OR** if you use “Buildpack”: Build command `pnpm install`, Start command `pnpm start`.
   - If using Dockerfile, leave build/run as default.
5. **Port**: set to `8080` (or whatever the app expects; check the repo’s README/Dockerfile).
6. Click **Deploy**.
7. After deploy, copy your service URL, e.g. `https://your-uv-app-xxx.koyeb.app`.

**Quick deploy link** (deploys your fork; fork the repo first):  
`https://app.koyeb.com/deploy?type=git&repository=github.com/YOUR_USERNAME/Ultraviolet-App&branch=main&name=uv-proxy`

---

## Step 2: Deploy Scramjet on Koyeb

1. In Koyeb, **Create App** → **Web Service** again.
2. **Source**: **GitHub**
   - Repository: `MercuryWorkshop/Scramjet-App`
   - Branch: `main`
3. **Build**:
   - Use **Dockerfile** if available, or  
   - Build command: `pnpm install`  
   - Start command: `pnpm start`
4. **Port**: usually `8080` (see Scramjet-App README).
5. **Deploy** and copy the service URL, e.g. `https://your-scramjet-app-xxx.koyeb.app`.

---

## Step 3: Point Void at UV and Scramjet

1. Open your **Void** UI (from your main site or `void.html`).
2. Open **Advanced** (main app) or scroll to **UV / Scramjet backends** (single-file).
3. Set:
   - **UV backend URL** = your UV Koyeb URL, e.g. `https://your-uv-app-xxx.koyeb.app`
   - **Scramjet backend URL** = your Scramjet Koyeb URL, e.g. `https://your-scramjet-app-xxx.koyeb.app`
4. Save (values are stored in `localStorage`).

When you choose **UV** or **Scramjet** and enter a URL, Void will open:

- UV mode → `https://your-uv-app-xxx.koyeb.app?url=<encoded-target>`
- Scramjet mode → `https://your-scramjet-app-xxx.koyeb.app?url=<encoded-target>`

If the official app doesn’t support `?url=` and only shows a search box, you’ll land on their page and can type the URL there. Many proxy apps do support `?url=` on the index.

---

## Hosting the Void HTML

- **Option A**: Keep your current **Node server** (e.g. on Render). It already serves `public/index.html` and the backend URL fields; just set the two Koyeb URLs in the UI.
- **Option B**: Use the **single-file** `void.html`:
  - Put it on **GitHub Pages**, **Netlify**, or **Vercel** (static), and open that URL. Set the two backend URLs once; they’re saved in the browser.
  - Or open `void.html` from your computer; same backend URL fields and behavior.

You don’t need to host UV or Scramjet on the same server as Void; they only need to be reachable at the URLs you paste.

---

## Summary

| What        | Where to host | URL you use in Void        |
|------------|----------------|----------------------------|
| Void (HTML)| Your choice    | — (this is the page you use) |
| UV         | Koyeb          | UV backend URL             |
| Scramjet   | Koyeb          | Scramjet backend URL       |

After this, use Void as normal and pick UV or Scramjet when you want to route traffic through those backends on Koyeb.
