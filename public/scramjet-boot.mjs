/**
 * Initializes BareMux (Epoxy + Wisp), ScramjetController, then navigates to ?url= via encodeUrl.
 * Wisp URL: query ?wisp=wss://... or window.__WISP_URL__ or public Mercury relay.
 */
const params = new URLSearchParams(location.search);
const targetUrl = params.get("url");
const wispFromQuery = params.get("wisp");
const WISP =
  wispFromQuery ||
  (typeof window !== "undefined" && window.__WISP_URL__) ||
  "wss://wisp.mercurywork.shop/";
/* Epoxy (default) or patched libcurl-transport — see ?transport=libcurl and server /libcurl */
const useLibcurlTransport =
  params.get("transport") === "libcurl" ||
  (typeof window !== "undefined" && window.__VOID_LIBCURL_TRANSPORT__);
const bareTransportModule = useLibcurlTransport
  ? new URL("/libcurl/index.mjs", location.origin).href
  : new URL("/epoxy/index.mjs", location.origin).href;

if (navigator.userAgent.includes("Firefox")) {
  Object.defineProperty(globalThis, "crossOriginIsolated", {
    value: true,
    writable: false,
  });
}

const { ScramjetController } = $scramjetLoadController();
const scramjet = new ScramjetController({
  prefix: "/scramjet/",
  files: {
    wasm: "/scram/scramjet.wasm.wasm",
    all: "/scram/scramjet.all.js",
    sync: "/scram/scramjet.sync.js",
  },
});

async function waitForControllingSw() {
  await navigator.serviceWorker.register("/scram-sw.js", { scope: "/" });
  await navigator.serviceWorker.ready;
  if (!navigator.serviceWorker.controller) {
    await new Promise((resolve) => {
      navigator.serviceWorker.addEventListener("controllerchange", resolve, { once: true });
    });
  }
}

const statusEl = () => document.getElementById("status");

try {
  try {
    await waitForControllingSw();
  } catch (e) {
    throw new Error("Service worker (/scram-sw.js): " + (e && e.message ? e.message : e));
  }
  try {
    await scramjet.init();
  } catch (e) {
    throw new Error("Scramjet init: " + (e && e.message ? e.message : e));
  }

  let conn;
  try {
    const { BareMuxConnection } = await import("/baremux/index.mjs");
    conn = new BareMuxConnection("/baremux/worker.js");
    await conn.setTransport(bareTransportModule, [{ wisp: WISP }]);
  } catch (e) {
    throw new Error(
      "BareMux transport / Wisp (is " +
        WISP +
        " reachable?): " +
        (e && e.message ? e.message : e)
    );
  }

  const el = statusEl();
  if (targetUrl) {
    if (el) el.textContent = "Loading…";
    location.replace(scramjet.encodeUrl(targetUrl));
  } else {
    if (el) {
      el.textContent =
        "Scramjet ready. Open Void with Scramjet mode and an empty backend, or add ?url=https://example.com";
    }
  }
} catch (e) {
  const el = statusEl();
  const msg = e instanceof Error ? e.message : String(e);
  if (el) {
    el.textContent = "Scramjet error: " + msg;
    el.style.whiteSpace = "pre-wrap";
    el.style.textAlign = "left";
    el.style.maxWidth = "42rem";
  }
  console.error("[scramjet-boot]", e);
}
