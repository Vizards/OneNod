import { createHash } from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, relative, resolve, sep } from "node:path";

const scriptPath = fileURLToPath(import.meta.url);
const defaultDistRoot = resolve(dirname(scriptPath), "../dist/web");
const CACHE_DECLARATION = 'const CACHE_NAME = "onenod-shell-dev";';
const PRECACHE_DECLARATION = `const PRECACHE_URLS = [
  "/requests",
  "/manifest.webmanifest",
  "/icon.svg",
  "/icon-192.png",
  "/icon-512.png",
  "/apple-touch-icon.png",
];`;

export async function finalizeServiceWorker(distRoot = defaultDistRoot) {
  const serviceWorkerPath = join(distRoot, "service-worker.js");
  const indexPath = join(distRoot, "index.html");
  const source = await readFile(serviceWorkerPath, "utf8");
  if (!source.includes(CACHE_DECLARATION) || !source.includes(PRECACHE_DECLARATION)) {
    throw new Error("service worker build markers are missing");
  }

  const entries = [
    { path: indexPath, url: "/requests" },
    ...[
      "manifest.webmanifest",
      "icon.svg",
      "icon-192.png",
      "icon-512.png",
      "apple-touch-icon.png",
    ].map((name) => ({ path: join(distRoot, name), url: `/${name}` })),
    ...(await regularFiles(join(distRoot, "assets"))).map((path) => ({
      path,
      url: `/${relative(distRoot, path).split(sep).join("/")}`,
    })),
  ].sort((left, right) => left.url.localeCompare(right.url));

  const urls = entries.map((entry) => entry.url);
  if (new Set(urls).size !== urls.length) {
    throw new Error("service worker precache contains duplicate URLs");
  }
  if (!urls.some((url) => url.endsWith(".js"))) {
    throw new Error("service worker precache contains no JavaScript asset");
  }
  if (!urls.some((url) => url.endsWith(".css"))) {
    throw new Error("service worker precache contains no CSS asset");
  }

  const digest = createHash("sha256").update(source);
  for (const entry of entries) {
    digest.update("\0").update(entry.url).update("\0");
    digest.update(await readFile(entry.path));
  }
  const cacheName = `onenod-shell-${digest.digest("hex").slice(0, 20)}`;
  const finalized = source
    .replace(CACHE_DECLARATION, `const CACHE_NAME = ${JSON.stringify(cacheName)};`)
    .replace(
      PRECACHE_DECLARATION,
      `const PRECACHE_URLS = ${JSON.stringify(urls, undefined, 2)};`,
    );
  await writeFile(serviceWorkerPath, finalized, "utf8");
  return { cacheName, urls };
}

async function regularFiles(root) {
  const entries = await readdir(root, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...await regularFiles(path));
      continue;
    }
    if (!entry.isFile()) {
      throw new Error(`service worker precache input is not a regular file: ${path}`);
    }
    files.push(path);
  }
  return files.sort();
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  await finalizeServiceWorker();
}
