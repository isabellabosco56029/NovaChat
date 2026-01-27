const CACHE_NAME = "novachat-v2";

const ASSETS = [
  "/",
  "/index.html",
  "/login.html",
  "/register.html",
  "/style.css",
  "/socket.io/socket.io.js"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;

  // Кэшируем только GET-запросы (чтобы не ломать POST /login, /register и т.п.)
  if (req.method !== "GET") return;

  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req);
    })
  );
});
