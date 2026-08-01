import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { delimiter, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const noticesScript = resolve(repositoryRoot, "scripts/release/generate-notices.mjs");
const commit = "a".repeat(40);

test("binary notices bind exact Go runtime LICENSE and PATENTS and fail closed", async () => {
  const root = await mkdtemp(join(tmpdir(), "onenod-notices-test-"));
  const bin = join(root, "bin");
  const goRoot = join(root, "goroot");
  const moduleRoot = join(root, "module");
  const binary = join(root, "may");
  await Promise.all([
    mkdir(bin),
    mkdir(goRoot),
    mkdir(moduleRoot),
    writeFile(binary, "fixture"),
  ]);
  const bsd = [
    "Copyright 2009 The Go Authors. All rights reserved.",
    "",
    "Redistribution and use in source and binary forms, with or without",
    "modification, are permitted provided that the following conditions are met:",
    "Neither the name of Google Inc. nor the names of its contributors may be used.",
    "",
  ].join("\n");
  const mit = [
    "MIT License",
    "Copyright (c) Fixture",
    "Permission is hereby granted, free of charge, to any person obtaining a copy",
    "of this software and associated documentation files (the Software), to deal",
    "in the Software without restriction.",
    "",
  ].join("\n");
  await Promise.all([
    writeFile(join(goRoot, "VERSION"), "go1.25.8\ntime 2026-07-01T00:00:00Z\n"),
    writeFile(join(goRoot, "LICENSE"), bsd),
    writeFile(join(goRoot, "PATENTS"), "Additional Go patent grant.\n"),
    writeFile(join(moduleRoot, "LICENSE"), mit),
    writeFile(
      join(bin, "go"),
      `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args[0] === "version" && args[1] === "-m") {
  process.stdout.write(args[2] + ": go1.25.8\\n\\tpath\\tfixture\\n\\tmod\\tfixture\\t(devel)\\t\\n\\tdep\\texample.com/library\\tv1.2.3\\th1:fixture=\\n");
} else if (args[0] === "env" && args[1] === "GOROOT") {
  process.stdout.write(process.env.FIXTURE_GOROOT + "\\n");
} else if (args[0] === "version") {
  process.stdout.write("go version go1.25.8 linux/amd64\\n");
} else if (args[0] === "mod" && args[1] === "download") {
  process.stdout.write(JSON.stringify({ Dir: process.env.FIXTURE_MODULE_ROOT }) + "\\n");
} else {
  process.exitCode = 2;
}
`,
      { mode: 0o755 },
    ),
  ]);

  const environment = {
    ...process.env,
    FIXTURE_GOROOT: goRoot,
    FIXTURE_MODULE_ROOT: moduleRoot,
    PATH: `${bin}${delimiter}${process.env.PATH}`,
  };
  const notices = join(root, "notices.txt");
  const inventory = join(root, "components.json");
  try {
    run(
      [
        "--scope",
        "binary",
        "--binary",
        binary,
        "--version",
        "0.0.1",
        "--commit",
        commit,
        "--output",
        notices,
        "--inventory-output",
        inventory,
      ],
      environment,
    );
    const text = await readFile(notices, "utf8");
    const components = JSON.parse(await readFile(inventory, "utf8")).components;
    assert.match(text, /Go standard library and runtime@go1\.25\.8/u);
    assert.match(text, /Toolchain VERSION: go1\.25\.8; time 2026-07-01/u);
    assert.match(text, /BEGIN PATENTS/u);
    assert.match(text, /example\.com\/library@v1\.2\.3/u);
    assert.equal(components.length, 2);
    assert.deepEqual(
      components.find(({ ecosystem }) => ecosystem === "go-toolchain"),
      {
        ecosystem: "go-toolchain",
        license: "BSD-3-Clause",
        name: "Go standard library and runtime",
        purl: "pkg:generic/golang@1.25.8",
        source: "https://go.dev/dl/#go1.25.8",
        version: "go1.25.8",
      },
    );

    await writeFile(join(moduleRoot, "LICENSE"), "proprietary\n");
    assert.throws(
      () =>
        run(
          [
            "--scope",
            "binary",
            "--binary",
            binary,
            "--version",
            "0.0.1",
            "--commit",
            commit,
            "--output",
            join(root, "invalid-notices.txt"),
          ],
          environment,
        ),
      /release_notices_failed:Go module example\.com\/library@v1\.2\.3 has an unreviewed license/u,
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("Node license inventory rejects UNLICENSED before packaging", async () => {
  const root = await mkdtemp(join(tmpdir(), "onenod-node-license-test-"));
  const bin = join(root, "bin");
  await mkdir(bin);
  await writeFile(
    join(bin, "pnpm"),
    `#!/usr/bin/env node
process.stdout.write(JSON.stringify({ UNLICENSED: [{ name: "forbidden", versions: ["1.0.0"], paths: ["/unused"] }] }));
`,
    { mode: 0o755 },
  );
  try {
    assert.throws(
      () =>
        run(
          [
            "--scope",
            "deployment",
            "--version",
            "0.0.1",
            "--commit",
            commit,
            "--output",
            join(root, "notices.txt"),
          ],
          { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}` },
        ),
      /not in the reviewed SPDX allowlist: UNLICENSED/u,
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

function run(args, environment) {
  return execFileSync(process.execPath, [noticesScript, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: environment,
    maxBuffer: 10 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}
