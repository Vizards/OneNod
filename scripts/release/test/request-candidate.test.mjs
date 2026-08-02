import assert from "node:assert/strict";
import test from "node:test";

import { requestCandidate } from "../request-candidate.mjs";

const alphaCommit = "a".repeat(40);
const mainCommit = "b".repeat(40);
const repository = JSON.stringify({
  defaultBranchRef: { name: "main" },
  nameWithOwner: "Vizards/OneNod",
});

test("alpha dispatches the pushed current branch through the main workflow", () => {
  const fixture = runner({
    branch: "prepare/candidate",
    dirty: true,
    head: alphaCommit,
    remoteBranches: { "prepare/candidate": alphaCommit },
  });
  const output = writer();

  const result = requestCandidate({
    args: ["alpha"],
    cwd: "/workspace/OneNod",
    run: fixture.run,
    stdout: output,
  });

  assert.equal(result.channel, "alpha");
  assert.equal(result.sourceSha, alphaCommit);
  assert.match(output.value, /uncommitted changes; they are excluded/u);
  assert.match(output.value, /actions\/workflows\/release\.yml/u);
  const dispatch = fixture.calls.find(
    ({ executable, args }) => executable === "gh" && args[0] === "workflow",
  );
  assert.deepEqual(dispatch?.args, [
    "workflow",
    "run",
    "release.yml",
    "--repo",
    "Vizards/OneNod",
    "--ref",
    "main",
    "-f",
    "intent=alpha",
    "-f",
    `source_sha=${alphaCommit}`,
  ]);
  assert.equal(dispatch?.args.some((value) => value.includes("version")), false);
});

test("alpha rejects a local HEAD that is not the canonical remote branch tip", () => {
  const fixture = runner({
    branch: "prepare/candidate",
    head: alphaCommit,
    remoteBranches: { "prepare/candidate": mainCommit },
  });

  assert.throws(
    () =>
      requestCandidate({
        args: ["alpha"],
        cwd: "/workspace/OneNod",
        run: fixture.run,
        stdout: writer(),
      }),
    /origin\/prepare\/candidate must exist and point to local HEAD/u,
  );
  assert.equal(
    fixture.calls.some(
      ({ executable, args }) => executable === "gh" && args[0] === "workflow",
    ),
    false,
  );
});

test("alpha may publish the exactly pushed main HEAD for controller bootstrap", () => {
  const fixture = runner({
    branch: "main",
    head: mainCommit,
    remoteBranches: { main: mainCommit },
  });

  const result = requestCandidate({
    args: ["alpha"],
    cwd: "/workspace/OneNod",
    run: fixture.run,
    stdout: writer(),
  });

  assert.equal(result.sourceLabel, "origin/main");
  assert.equal(result.sourceSha, mainCommit);
});

test("beta lets the main controller bind its own canonical commit", () => {
  const fixture = runner({
    detached: true,
    dirty: true,
    head: alphaCommit,
    remoteBranches: { main: mainCommit },
  });
  const output = writer();

  const result = requestCandidate({
    args: ["beta"],
    cwd: "/workspace/OneNod",
    run: fixture.run,
    stdout: output,
  });

  assert.equal(result.sourceLabel, "origin/main");
  assert.equal(result.sourceSha, mainCommit);
  const dispatch = fixture.calls.find(
    ({ executable, args }) => executable === "gh" && args[0] === "workflow",
  );
  assert.equal(
    dispatch?.args.some((value) => value.startsWith("source_sha=")),
    false,
  );
});

test("candidate requests reject a differently owned origin", () => {
  const fixture = runner({ origin: "git@github.com:someone/OneNod.git" });
  assert.throws(
    () =>
      requestCandidate({
        args: ["alpha"],
        cwd: "/workspace/OneNod",
        run: fixture.run,
        stdout: writer(),
      }),
    /origin must identify the canonical Vizards\/OneNod repository/u,
  );
});

function runner({
  branch = "prepare/candidate",
  detached = false,
  dirty = false,
  head = alphaCommit,
  origin = "ssh://git@github.com:22/Vizards/OneNod.git",
  remoteBranches = { "prepare/candidate": alphaCommit, main: mainCommit },
} = {}) {
  const calls = [];
  return {
    calls,
    run(executable, args) {
      calls.push({ args: [...args], executable });
      const key = `${executable} ${args.join(" ")}`;
      if (key === "git --version") return success("git version 2.50.1\n");
      if (key === "gh --version") return success("gh version 2.76.2\n");
      if (key === "git rev-parse --show-toplevel") {
        return success("/workspace/OneNod\n");
      }
      if (key === "git remote get-url origin") return success(`${origin}\n`);
      if (key === "gh auth status --hostname github.com") return success("");
      if (
        key ===
        "gh repo view Vizards/OneNod --json nameWithOwner,defaultBranchRef"
      ) {
        return success(repository);
      }
      if (key === "git symbolic-ref --quiet --short HEAD") {
        return detached ? failure("detached HEAD") : success(`${branch}\n`);
      }
      if (key === "git rev-parse --verify HEAD^{commit}") {
        return success(`${head}\n`);
      }
      if (key === "git status --porcelain=v1") {
        return success(dirty ? " M local-only\n" : "");
      }
      if (
        executable === "git" &&
        args[0] === "ls-remote" &&
        args[1] === "--exit-code"
      ) {
        const reference = args[3];
        const remoteBranch = reference.replace(/^refs\/heads\//u, "");
        const commit = remoteBranches[remoteBranch];
        return commit === undefined
          ? failure("remote branch missing")
          : success(`${commit}\t${reference}\n`);
      }
      if (executable === "gh" && args[0] === "workflow") return success("");
      return failure(`unexpected command: ${key}`);
    },
  };
}

function success(stdout) {
  return { status: 0, stderr: "", stdout };
}

function failure(stderr) {
  return { status: 1, stderr, stdout: "" };
}

function writer() {
  return {
    value: "",
    write(value) {
      this.value += value;
    },
  };
}
