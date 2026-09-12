import { readdir, readFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, relative, resolve, sep } from "node:path";
import { markdownLinks } from "./markdown-links.mjs";

// A leaf may be linked by a task router instead of by SKILL.md itself.
export async function unreachableSkillReferences(directory) {
  const root = resolve(directory);
  const references = [];
  await collect(resolve(root, "references"), references);
  const visited = new Set();
  const pending = [resolve(root, "SKILL.md")];
  while (pending.length > 0) {
    const file = pending.pop();
    if (visited.has(file)) continue;
    visited.add(file);
    const source = await readFile(file, "utf8");
    for (const target of markdownLinks(source)) {
      if (target.startsWith("#") || /^[a-z][a-z\d+.-]*:/iu.test(target)) continue;
      const path = resolve(dirname(file), decodeURIComponent(target.split("#", 1)[0]));
      const inside = relative(root, path);
      if (inside === ".." || inside.startsWith(`..${sep}`) || isAbsolute(inside)) continue;
      if (extname(path) === ".md") pending.push(path);
    }
  }
  return references.filter((file) => !visited.has(file)).map((file) => relative(root, file)).sort();
}

async function collect(directory, files) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) await collect(path, files);
    else if (entry.isFile() && extname(path) === ".md") files.push(path);
  }
}
