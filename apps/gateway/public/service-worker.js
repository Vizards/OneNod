const CACHE_PREFIX = "onenod-shell-";
const CACHE_NAME = "onenod-shell-dev";
const PRECACHE_URLS = [
  "/requests",
  "/manifest.webmanifest",
  "/icon.svg",
  "/icon-192.png",
  "/icon-512.png",
  "/apple-touch-icon.png",
];
const PRECACHE_PATHS = new Set(PRECACHE_URLS);

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE_URLS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then(async (keys) => {
      const olderShellCaches = keys.filter(
        (key) => key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME,
      );
      const previousCache = olderShellCaches.at(-1);
      await Promise.all(
        olderShellCaches
          .filter((key) => key !== previousCache)
          .map((key) => caches.delete(key)),
      );
      await self.clients.claim();
    }),
  );
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith("/v1/")) return;
  if (event.request.mode === "navigate") {
    event.respondWith(networkFirstNavigation(event.request));
    return;
  }
  if (url.pathname.startsWith("/assets/") || PRECACHE_PATHS.has(url.pathname)) {
    event.respondWith(cacheFirstStatic(event.request, url.pathname));
  }
});

async function networkFirstNavigation(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      await cache.put("/requests", response.clone());
    }
    return response;
  } catch {
    const cached = await caches.match("/requests");
    return cached ?? Response.error();
  }
}

async function cacheFirstStatic(request, pathname) {
  const cached = await caches.match(pathname);
  if (cached) return cached;
  return fetch(request);
}

self.addEventListener("push", (event) => {
  let message = {};
  try {
    message = event.data?.json() ?? {};
  } catch {
    message = {};
  }
  const title = typeof message.title === "string" ? message.title : "New approval request";
  const url = typeof message.url === "string" && message.url.startsWith("/")
    ? message.url
    : "/requests";
  const notification = self.registration.showNotification(title, {
    body: typeof message.body === "string" ? message.body : "Open the approval app to review details.",
    data: { url },
    icon: "/icon-192.png",
    badge: "/icon-192.png",
    tag: typeof message.tag === "string" ? message.tag : "approval-request",
    renotify: true,
  });
  let badge = Promise.resolve();
  try {
    if (typeof self.navigator.setAppBadge === "function") {
      // Badging is optional. Chrome treats a rejected push waitUntil promise as
      // a silent push and may add its own generic background-update notice,
      // even after showNotification succeeded.
      badge = Promise.resolve(self.navigator.setAppBadge(1)).catch(() => undefined);
    }
  } catch {
    badge = Promise.resolve();
  }
  event.waitUntil(Promise.all([notification, badge]).then(() => undefined));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = new URL(event.notification.data?.url ?? "/requests", self.location.origin).href;
  event.waitUntil(clearAppBadge().then(() => focusOrOpenApp(url)));
});

async function clearAppBadge() {
  try {
    if (typeof self.navigator.clearAppBadge === "function") {
      await self.navigator.clearAppBadge();
      return;
    }
    if (typeof self.navigator.setAppBadge === "function") {
      await self.navigator.setAppBadge(0);
    }
  } catch {
    // Badge support is optional and must never block notification navigation.
  }
}

async function focusOrOpenApp(url) {
  const clients = await self.clients.matchAll({ includeUncontrolled: true, type: "window" });
  const sameOrigin = clients.filter(
    (client) => new URL(client.url).origin === self.location.origin,
  );
  const target =
    sameOrigin.find((client) => client.url === url) ??
    sameOrigin.find((client) => client.focused) ??
    sameOrigin.find((client) => client.visibilityState === "visible") ??
    sameOrigin[0];
  if (!target) return self.clients.openWindow(url);

  let active = target;
  try {
    active = await target.focus();
  } catch {
    // macOS/Chrome may decline to switch Spaces. Navigation is still useful.
  }
  let navigated;
  try {
    navigated = await active.navigate(url);
  } catch {
    return active;
  }
  if (!navigated) return active;
  try {
    return await navigated.focus();
  } catch {
    return navigated;
  }
}
