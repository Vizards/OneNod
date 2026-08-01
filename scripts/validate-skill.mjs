import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const skillRoot = resolve(import.meta.dirname, "../skills/onenod");
const skill = await readFile(resolve(skillRoot, "SKILL.md"), "utf8");
const openAI = await readFile(resolve(skillRoot, "agents/openai.yaml"), "utf8");

const frontmatter = /^---\n(?<body>[\s\S]*?)\n---(?:\n|$)/u.exec(skill)?.groups
  ?.body;
if (frontmatter === undefined) fail("SKILL.md has no closed frontmatter");

const skillFields = parseFields(frontmatter, "", "SKILL.md frontmatter");
if (
  skillFields.size !== 2 ||
  [...skillFields.keys()].some((key) => !["name", "description"].includes(key))
) {
  fail("SKILL.md frontmatter must contain only name and description");
}
if (required(skillFields, "name") !== "onenod") {
  fail("the published Skill name must be onenod");
}
const description = required(skillFields, "description");
if (description.length > 1024 || /[<>]/u.test(description)) {
  fail("the Skill description violates the public metadata contract");
}

const openAILines = openAI.trimEnd().split("\n");
if (openAILines.shift() !== "interface:") {
  fail("agents/openai.yaml has no interface mapping");
}
const interfaceFields = parseFields(
  openAILines.join("\n"),
  "  ",
  "agents/openai.yaml",
);
const expectedInterfaceFields = [
  "default_prompt",
  "display_name",
  "short_description",
];
if (
  interfaceFields.size !== expectedInterfaceFields.length ||
  [...interfaceFields.keys()].some(
    (key) => !expectedInterfaceFields.includes(key),
  )
) {
  fail("agents/openai.yaml contains an unexpected interface field");
}
if (required(interfaceFields, "display_name") !== "OneNod") {
  fail("the OpenAI display name must be OneNod");
}
const shortDescription = required(interfaceFields, "short_description");
if (shortDescription.length < 25 || shortDescription.length > 64) {
  fail("the OpenAI short description must contain 25 to 64 characters");
}
if (!required(interfaceFields, "default_prompt").includes("$onenod")) {
  fail("the OpenAI default prompt must invoke $onenod");
}

const references = await readdir(resolve(skillRoot, "references"), {
  withFileTypes: true,
});
for (const entry of references) {
  if (
    entry.isFile() &&
    entry.name.endsWith(".md") &&
    !skill.includes(`references/${entry.name}`)
  ) {
    fail(`SKILL.md does not route reference ${entry.name}`);
  }
}

process.stdout.write('{"event":"skill_metadata_verified","name":"onenod"}\n');

function parseFields(source, indentation, label) {
  const fields = new Map();
  for (const rawLine of source.split("\n")) {
    if (rawLine.trim() === "") continue;
    const match = new RegExp(
      `^${indentation}(?<key>[a-z][a-z0-9_-]*): (?<value>.+)$`,
      "u",
    ).exec(rawLine);
    if (match?.groups === undefined) fail(`${label} must use scalar fields`);
    const { key, value: rawValue } = match.groups;
    if (fields.has(key)) fail(`${label} contains duplicate key ${key}`);
    let value = rawValue;
    if (rawValue.startsWith('"')) {
      try {
        value = JSON.parse(rawValue);
      } catch {
        fail(`${label} contains invalid quoting for ${key}`);
      }
    }
    if (typeof value !== "string" || value.trim() === "") {
      fail(`${label} contains an invalid value for ${key}`);
    }
    fields.set(key, value.trim());
  }
  return fields;
}

function required(fields, key) {
  const value = fields.get(key);
  if (value === undefined) fail(`missing required field ${key}`);
  return value;
}

function fail(message) {
  throw new Error(`skill_validation_failed:${message}`);
}
