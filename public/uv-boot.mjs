/**
 * Registers Ultraviolet SW, then navigates to /uv/service/… for ?url=.
 * Expects /uv/uv.bundle.js + /uv/uv.config.js (server overrides config for /uv/service/).
 */
const params = new URLSearchParams(location.search);
const targetUrl = params.get("url");
const wantEruda = params.get("eruda") === "1";

if (navigator.userAgent.includes("Firefox")) {
  Object.defineProperty(globalThis, "crossOriginIsolated", {
    value: true,
    writable: false,
  });
}

const statusEl = () => document.getElementById("status");

try {
  await navigator.serviceWorker.register("/uv/sw.js", { scope: "/" });
  await navigator.serviceWorker.ready;
  if (!navigator.serviceWorker.controller) {
    await new Promise((resolve) => {
      navigator.serviceWorker.addEventListener("controllerchange", resolve, { once: true });
    });
  }

  if (wantEruda) {
    const s = document.createElement("script");
    s.src = "https://cdn.jsdelivr.net/npm/eruda";
    s.crossOrigin = "anonymous";
    s.onload = () => {
      try {
        if (globalThis.eruda) globalThis.eruda.init();
      } catch (_) {}
    };
    document.head.appendChild(s);
  }

  const config = self.__uv$config;
  if (!config || typeof config.encodeUrl !== "function") {
    throw new Error("Ultraviolet config missing (load /uv/uv.bundle.js before /uv/uv.config.js)");
  }

  if (targetUrl) {
    if (statusEl()) statusEl().textContent = "Loading…";
    const enc = config.encodeUrl(targetUrl);
    location.replace(location.origin + config.prefix + enc);
  } else if (statusEl()) {
    statusEl().textContent =
      "Ultraviolet ready. Open Void in UV mode with a URL, or add ?url=https://example.com";
  }
} catch (e) {
  const el = statusEl();
  const msg = e instanceof Error ? e.message : String(e);
  if (el) {
    el.textContent = "Ultraviolet error: " + msg;
    el.style.whiteSpace = "pre-wrap";
    el.style.textAlign = "left";
    el.style.maxWidth = "42rem";
  }
  console.error("[uv-boot]", e);
}
