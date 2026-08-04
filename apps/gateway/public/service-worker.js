const CACHE_NAME = "onenod-shell-v4";
const SHELL = [
  "/requests",
  "/manifest.webmanifest",
  "/icon.svg",
  "/icon-192.png",
  "/apple-touch-icon.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    Promise.all([
      self.clients.claim(),
      caches.keys().then((keys) =>
        Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))),
      ),
    ]),
  );
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith("/v1/")) return;
  event.respondWith(
    fetch(event.request).catch(() =>
      caches.match(event.request).then((cached) => cached ?? caches.match("/requests")),
    ),
  );
});

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
