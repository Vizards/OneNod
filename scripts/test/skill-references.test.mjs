import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { unreachableSkillReferences } from "../lib/skill-references.mjs";

async function fixture(t, files) {
  const root = await mkdtemp(join(tmpdir(), "onenod-skill-routes-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "references"));
  for (const [name, content] of Object.entries(files)) {
    await mkdir(dirname(join(root, name)), { recursive: true });
    await writeFile(join(root, name), content);
  }
  return root;
}

test("follows a router to nested leaves and terminates on backlinks", async (t) => {
  const root = await fixture(t, {
    "SKILL.md": "[Setup](references/setup.md)",
    "references/setup.md": "[Leaf](nested/leaf.md#details)",
    "references/nested/leaf.md": "[Back](../setup.md)\n[Remote](https://example.com/guide.md)",
  });
  assert.deepEqual(await unreachableSkillReferences(root), []);
});

test("reports orphaned leaves and an unreachable reference cycle", async (t) => {
  const root = await fixture(t, {
    "SKILL.md": "[Setup](references/setup.md)",
    "references/setup.md": "Use the installed product.",
    "references/orphan.md": "No incoming link.",
    "references/a.md": "[B](b.md)",
    "references/b.md": "[A](a.md)",
  });
  assert.deepEqual(await unreachableSkillReferences(root), [
    "references/a.md", "references/b.md", "references/orphan.md",
  ]);
});

test("a filename mention is not a navigable reference", async (t) => {
  const root = await fixture(t, {
    "SKILL.md": "references/leaf.md",
    "references/leaf.md": "Contract.",
  });
  assert.deepEqual(await unreachableSkillReferences(root), ["references/leaf.md"]);
});

test("does not follow a checkout-external route", async (t) => {
  const root = await fixture(t, {
    "SKILL.md": "[External](../unavailable.md)",
    "references/leaf.md": "Contract.",
  });
  assert.deepEqual(await unreachableSkillReferences(root), ["references/leaf.md"]);
});
