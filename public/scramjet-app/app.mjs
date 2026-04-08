/**
 * Full Scramjet shell (Mercury Workshop pattern): SW + ScramjetController + BareMux + Epoxy/Wisp + createFrame/go.
 * Same stack as /scramjet.html but with the official demo UI.
 */
import { BareMuxConnection } from "/baremux/index.mjs";
import { search } from "/scramjet-app/search.mjs";

const params = new URLSearchParams(location.search);
const WISP =
  params.get("wisp") ||
  (typeof globalThis !== "undefined" && globalThis.__WISP_URL__) ||
  "wss://wisp.mercurywork.shop/";
const useLibcurl =
  params.get("transport") === "libcurl" ||
  (typeof globalThis !== "undefined" && globalThis.__VOID_LIBCURL_TRANSPORT__);
const transportMod = useLibcurl
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

const form = document.getElementById("sj-form");
const address = document.getElementById("sj-address");
const searchEngine = document.getElementById("sj-search-engine");
const errorEl = document.getElementById("sj-error");
const errorCode = document.getElementById("sj-error-code");

async function waitForControllingSw() {
  await navigator.serviceWorker.register("/scram-sw.js", { scope: "/" });
  await navigator.serviceWorker.ready;
  if (!navigator.serviceWorker.controller) {
    await new Promise((resolve) => {
      navigator.serviceWorker.addEventListener("controllerchange", resolve, { once: true });
    });
  }
}

let muxReady = false;

async function ensureMux() {
  if (muxReady) return;
  const conn = new BareMuxConnection("/baremux/worker.js");
  await conn.setTransport(transportMod, [{ wisp: WISP }]);
  muxReady = true;
}

async function boot() {
  await waitForControllingSw();
  await scramjet.init();
  await ensureMux();
}

function showErr(msg, detail) {
  if (errorEl) errorEl.textContent = msg || "";
  if (errorCode) errorCode.textContent = detail || "";
}

boot()
  .then(() => {
    showErr("", "");
  })
  .catch((e) => {
    const msg = e instanceof Error ? e.message : String(e);
    showErr("Scramjet failed to start.", msg);
    console.error("[scramjet-app]", e);
  });

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorEl.textContent = "";
  errorCode.textContent = "";

  try {
    await boot();
  } catch (err) {
    showErr("Failed to initialize proxy.", err instanceof Error ? err.message : String(err));
    return;
  }

  try {
    const url = search(address.value, searchEngine.value);
    const prev = document.getElementById("sj-frame");
    if (prev) prev.remove();

    const frame = scramjet.createFrame();
    frame.frame.id = "sj-frame";
    document.body.appendChild(frame.frame);
    frame.go(url);
  } catch (err) {
    showErr("Navigation error.", err instanceof Error ? err.message : String(err));
  }
});
