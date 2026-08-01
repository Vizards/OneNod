import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const packageScript = resolve(repositoryRoot, "scripts/release/package-artifact.mjs");
const manifestScript = resolve(repositoryRoot, "scripts/release/generate-manifest.mjs");
const verifyScript = resolve(repositoryRoot, "scripts/release/verify-release-set.mjs");
const finalizeSbomScript = resolve(
  repositoryRoot,
  "scripts/release/finalize-artifact-sbom.mjs",
);
const mergeNoticesScript = resolve(
  repositoryRoot,
  "scripts/release/merge-artifact-notices.mjs",
);
const version = "0.0.1";
const helperVersion = "1.0.0";
const releaseContract = JSON.parse(
  await readFile(resolve(repositoryRoot, "scripts/release/release-contract.json"), "utf8"),
);
const helperSourceDigest = releaseContract.components.keychain_helper.source_digest;
const commit = "a".repeat(40);
const helperCommit = "d".repeat(40);

test("release packager is deterministic and the verifier enforces the exact set", async () => {
  const temporaryRoot = await mkdtemp(join(tmpdir(), "onenod-release-test-"));
  const releaseDirectory = join(temporaryRoot, "release");
  const dummyBinary = join(temporaryRoot, "dummy-binary");
  const noticesPath = join(temporaryRoot, "artifact-notices.txt");
  const componentsPath = join(temporaryRoot, "artifact-components.json");
  const helperNoticesPath = join(temporaryRoot, "helper-notices.txt");
  const helperComponentsPath = join(temporaryRoot, "helper-components.json");
  await writeFile(dummyBinary, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  await writeFile(
    noticesPath,
    [
      "OneNod Third-Party Notices",
      "Format: 2",
      `Release: ${version}`,
      `Source commit: ${commit}`,
      "Scope: binary",
      "Components: 0",
      `Component inventory SHA-256: ${createHash("sha256").update("[]").digest("hex")}`,
      "Go standard library and runtime",
      "Copyright (c) 2024 1Password",
      "Original SHA-256: 23d115f4ac7519b48172df3e8615945572dbda7033d51b44c9490fd533ae0f23",
      "Processed SHA-256: 803c7752dd41abc3911a75ac2df9b83197d000265d42d6412760458ba07858f6",
      "",
    ].join("\n"),
  );
  await writeFile(
    helperNoticesPath,
    [
      "OneNod Third-Party Notices",
      "Format: 2",
      `Release: ${helperVersion}`,
      `Source commit: ${helperCommit}`,
      "Scope: binary",
      "Components: 0",
      `Component inventory SHA-256: ${createHash("sha256").update("[]").digest("hex")}`,
      "Go standard library and runtime",
      "",
    ].join("\n"),
  );
  await writeFile(
    helperComponentsPath,
    `${JSON.stringify({
      schema_version: 1,
      scope: "binary",
      release_version: helperVersion,
      source_commit: helperCommit,
      components: [],
    })}\n`,
  );
  await writeFile(
    componentsPath,
    `${JSON.stringify({
      schema_version: 1,
      scope: "binary",
      release_version: version,
      source_commit: commit,
      components: [],
    })}\n`,
  );

  try {
    const first = join(temporaryRoot, "first.tar.gz");
    const second = join(temporaryRoot, "second.tar.gz");
    packageArtifact("local", [
      "--binary",
      dummyBinary,
      "--arch",
      "arm64",
      "--version",
      version,
      "--commit",
      commit,
      "--notices",
      noticesPath,
      "--components",
      componentsPath,
      "--output",
      first,
    ]);
    packageArtifact("local", [
      "--binary",
      dummyBinary,
      "--arch",
      "arm64",
      "--version",
      version,
      "--commit",
      commit,
      "--notices",
      noticesPath,
      "--components",
      componentsPath,
      "--output",
      second,
    ]);
    assert.equal(await digest(first), await digest(second));

    for (const arch of ["arm64", "amd64"]) {
      packageArtifact("local", [
        "--binary",
        dummyBinary,
        "--arch",
        arch,
        "--version",
        version,
        "--commit",
        commit,
        "--notices",
        noticesPath,
        "--components",
        componentsPath,
        "--output",
        join(releaseDirectory, `onenod-darwin-${arch}.tar.gz`),
      ]);
      packageArtifact("helper", [
        "--binary",
        dummyBinary,
        "--arch",
        arch,
        "--helper-version",
        helperVersion,
        "--helper-source-digest",
        helperSourceDigest,
        "--commit",
        helperCommit,
        "--notices",
        helperNoticesPath,
        "--components",
        helperComponentsPath,
        "--output",
        join(
          releaseDirectory,
          `onenod-keychain-helper-${helperVersion}-darwin-${arch}.tar.gz`,
        ),
      ]);
      const helperDescriptor = JSON.parse(
        execFileSync(
          "tar",
          [
            "-xOzf",
            join(
              releaseDirectory,
              `onenod-keychain-helper-${helperVersion}-darwin-${arch}.tar.gz`,
            ),
            "onenod-keychain-helper/RELEASE.json",
          ],
          { encoding: "utf8" },
        ),
      );
      assert.equal(helperDescriptor.helper_source_digest, helperSourceDigest);
    }
    packageArtifact("deployment", [
      "--version",
      version,
      "--commit",
      commit,
      "--notices",
      noticesPath,
      "--components",
      componentsPath,
      "--output",
      join(releaseDirectory, `onenod-deployment-${version}.tar.gz`),
    ]);
    const deploymentDescriptor = JSON.parse(
      execFileSync(
        "tar",
        [
          "-xOzf",
          join(releaseDirectory, `onenod-deployment-${version}.tar.gz`),
          "onenod-deployment/deployment.json",
        ],
        { encoding: "utf8" },
      ),
    );
    assert.equal(deploymentDescriptor.gateway.config, "gateway/wrangler.jsonc");
    assert.equal(
      deploymentDescriptor.executor.config,
      "executor/wrangler.jsonc",
    );
    assert.equal(deploymentDescriptor.gateway.template, undefined);
    assert.equal(deploymentDescriptor.executor.template, undefined);
    packageArtifact("skill", [
      "--version",
      version,
      "--commit",
      commit,
      "--output",
      join(releaseDirectory, `onenod-skill-${version}.tar.gz`),
    ]);
    const archives = [
      "onenod-darwin-arm64.tar.gz",
      "onenod-darwin-amd64.tar.gz",
      `onenod-deployment-${version}.tar.gz`,
      `onenod-keychain-helper-${helperVersion}-darwin-arm64.tar.gz`,
      `onenod-keychain-helper-${helperVersion}-darwin-amd64.tar.gz`,
      `onenod-skill-${version}.tar.gz`,
    ];
    const reusedHelperArchive = join(
      releaseDirectory,
      `onenod-keychain-helper-${helperVersion}-darwin-arm64.tar.gz`,
    );
    const reusedHelperDigest = await digest(reusedHelperArchive);
    for (const archive of archives) {
      finalizeFixtureSbom(temporaryRoot, releaseDirectory, archive);
    }
    const helperSbom = JSON.parse(
      await readFile(
        join(
          releaseDirectory,
          `onenod-keychain-helper-${helperVersion}-darwin-arm64.spdx.json`,
        ),
        "utf8",
      ),
    );
    assert.equal(
      helperSbom.packages.find(
        ({ SPDXID }) => SPDXID === helperSbom.documentDescribes[0],
      ).versionInfo,
      helperVersion,
    );
    run(mergeNoticesScript, [
      "--directory",
      releaseDirectory,
      "--output",
      join(releaseDirectory, "THIRD_PARTY_NOTICES.txt"),
      "--version",
      version,
      "--commit",
      commit,
    ]);

    run(manifestScript, [
      "--directory",
      releaseDirectory,
      "--version",
      version,
      "--previous-version",
      "",
      "--commit",
      commit,
      "--published-at",
      "2026-08-01T00:00:00.000Z",
    ]);
    verify(releaseDirectory, "assembled");

    const manifestPath = join(releaseDirectory, "release-manifest.json");
    const checksumsPath = join(releaseDirectory, "SHA256SUMS");
    const originalManifest = await readFile(manifestPath);
    const originalChecksums = await readFile(checksumsPath);
    const mismatchedManifest = JSON.parse(originalManifest.toString("utf8"));
    mismatchedManifest.components.keychain_helper.source_digest =
      `sha256:${"b".repeat(64)}`;
    const mismatchedManifestBytes = Buffer.from(
      `${JSON.stringify(mismatchedManifest, null, 2)}\n`,
    );
    await writeFile(manifestPath, mismatchedManifestBytes);
    await writeFile(
      checksumsPath,
      originalChecksums
        .toString("utf8")
        .replace(
          /^[0-9a-f]{64}  release-manifest\.json$/mu,
          `${createHash("sha256").update(mismatchedManifestBytes).digest("hex")}  release-manifest.json`,
        ),
    );
    assert.throws(
      () => verify(releaseDirectory, "assembled"),
      /Keychain helper identity differs from the release manifest/u,
    );
    await writeFile(manifestPath, originalManifest);
    await writeFile(checksumsPath, originalChecksums);
    verify(releaseDirectory, "assembled");

    await writeFile(
      join(releaseDirectory, "onenod-provenance.intoto.jsonl"),
      "{}\n",
    );
    verify(releaseDirectory, "complete");
    assert.equal(await digest(reusedHelperArchive), reusedHelperDigest);

    await writeFile(
      join(releaseDirectory, "onenod-darwin-arm64.tar.gz"),
      "tampered",
    );
    assert.throws(
      () => verify(releaseDirectory, "complete"),
      /release_set_verification_failed/u,
    );
  } finally {
    await rm(temporaryRoot, { force: true, recursive: true });
  }
});

function packageArtifact(kind, args) {
  run(packageScript, [kind, ...args]);
}

function finalizeFixtureSbom(temporaryRoot, releaseDirectory, archive) {
  const raw = join(temporaryRoot, `${archive}.raw.spdx.json`);
  const rootID = `SPDXRef-Package-${archive.replaceAll(/[^A-Za-z0-9.-]/gu, "-")}`;
  const document = {
    SPDXID: "SPDXRef-DOCUMENT",
    creationInfo: { created: "2026-08-01T00:00:00Z", creators: ["Tool: fixture"] },
    dataLicense: "CC0-1.0",
    documentDescribes: [rootID],
    documentNamespace: `https://github.com/Vizards/OneNod/test/${archive}`,
    name: archive,
    packages: [
      {
        SPDXID: rootID,
        copyrightText: "NOASSERTION",
        downloadLocation: "NOASSERTION",
        filesAnalyzed: false,
        licenseConcluded: "NOASSERTION",
        licenseDeclared: "NOASSERTION",
        name: archive,
        versionInfo: version,
      },
    ],
    relationships: [],
    spdxVersion: "SPDX-2.3",
  };
  execFileSync(process.execPath, [
    "-e",
    "require('node:fs').writeFileSync(process.argv[1], process.argv[2])",
    raw,
    `${JSON.stringify(document)}\n`,
  ]);
  run(finalizeSbomScript, [
    "--archive",
    join(releaseDirectory, archive),
    "--sbom",
    raw,
    "--output",
    join(releaseDirectory, `${archive.slice(0, -7)}.spdx.json`),
    "--version",
    version,
    "--commit",
    commit,
  ]);
}

function verify(directory, phase) {
  run(verifyScript, [
    "--directory",
    directory,
    "--phase",
    phase,
    "--version",
    version,
    "--commit",
    commit,
  ]);
}

function run(script, args) {
  return execFileSync(process.execPath, [script, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function digest(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}
