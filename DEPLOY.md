# How to deploy Void

Deploy your **Void proxy** (this repo) so it’s live on the internet. Pick one option below.

---

## Option 1: Render (recommended, free tier)

1. Push this project to **GitHub** (create a repo and push your code).
2. Go to [render.com](https://render.com) → **Sign up** / Log in.
3. **New** → **Web Service**.
4. Connect GitHub and select your **proxy-site** repo.
5. Set:
   - **Name:** `void-proxy` (or any name)
   - **Region:** pick one
   - **Branch:** `main`
   - **Runtime:** **Node**
   - **Build command:** `npm install`
   - **Start command:** `npm start`
   - **Instance type:** Free
6. Click **Create Web Service**.
7. Wait for the first deploy. Your app will be at `https://void-proxy.onrender.com` (or the name you chose).

**Note:** On the free tier the app may sleep after inactivity; the first load can be slow.

---

## Option 2: Koyeb

1. Push this project to **GitHub**.
2. Go to [koyeb.com](https://www.koyeb.com) → **Sign up** / Log in.
3. **Create App** → **Web Service**.
4. **Source:** GitHub → select your **proxy-site** repo, branch **main**.
5. **Build:**
   - Build command: `npm install`
   - Run command: `npm start`
6. **Port:** `8080` (this app uses `process.env.PORT || 8080`; Koyeb will set PORT automatically).
7. **Deploy** and copy your URL (e.g. `https://your-app-xxx.koyeb.app`).

---

## Option 3: Railway

1. Push this project to **GitHub**.
2. Go to [railway.app](https://railway.app) → **Login** (with GitHub).
3. **New Project** → **Deploy from GitHub repo** → pick **proxy-site**.
4. Railway will detect Node and run `npm start`. If it doesn’t:
   - **Settings** → Build: `npm install` → Start: `npm start`.
5. **Settings** → **Generate Domain** to get a public URL.

---

## After deploy

- Open your live URL. You should see the Void UI.
- To use **UV** or **Scramjet**, deploy them separately (e.g. on Koyeb) and set **UV backend URL** and **Scramjet backend URL** in Void’s Advanced section. See **docs/UV-SCRAMJET-KOYEB.md** for that.

---

## Port note

This app already uses `process.env.PORT || 8080`, so Render/Koyeb/Railway can set the port for you. No change needed.
