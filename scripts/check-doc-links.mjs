import { existsSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { dirname, extname, resolve } from "node:path";
import { markdownLinks } from "./lib/markdown-links.mjs";

const repositoryRoot = resolve(import.meta.dirname, "..");
const roots = [
  resolve(repositoryRoot, "AGENTS.md"),
  resolve(repositoryRoot, "README.md"),
  resolve(repositoryRoot, "CONTRIBUTING.md"),
  resolve(repositoryRoot, "SECURITY.md"),
  resolve(repositoryRoot, "skills/onenod"),
];

const markdownFiles = [];
for (const root of roots) {
  if (!existsSync(root)) throw new Error(`documentation root is missing: ${root}`);
  if (extname(root) === ".md") markdownFiles.push(root);
  else await collectMarkdown(root, markdownFiles);
}

const failures = [];
for (const file of markdownFiles) {
  const source = await readFile(file, "utf8");
  for (const target of markdownLinks(source, { includeImages: true })) {
    if (
      target.startsWith("#") ||
      /^[a-z][a-z\d+.-]*:/iu.test(target)
    ) {
      continue;
    }
    const path = decodeURIComponent(target.split("#", 1)[0]);
    if (!existsSync(resolve(dirname(file), path))) {
      failures.push(`${file}: ${target}`);
    }
  }
}

if (failures.length > 0) {
  throw new Error(`broken local documentation links:\n${failures.join("\n")}`);
}

console.log(
  JSON.stringify({ event: "documentation_links_verified", files: markdownFiles.length }),
);

async function collectMarkdown(directory, output) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) await collectMarkdown(path, output);
    else if (entry.isFile() && entry.name.endsWith(".md")) output.push(path);
  }
}
