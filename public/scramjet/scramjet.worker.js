importScripts('/scramjet/scramjet.config.js');
importScripts('/scramjet/scramjet.all.js');

const { ScramjetServiceWorker } = $scramjetLoadWorker();
const scramjet = new ScramjetServiceWorker();

self.addEventListener("fetch", (event) => {
  if (scramjet.route(event)) {
    event.respondWith((async () => {
      await scramjet.loadConfig();
      return scramjet.fetch(event);
    })());
  }
});
