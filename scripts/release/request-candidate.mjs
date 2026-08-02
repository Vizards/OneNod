import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const officialRepository = "Vizards/OneNod";
const officialRemote = "https://github.com/Vizards/OneNod.git";
const releaseWorkflow = "release.yml";
const releaseWorkflowURL =
  "https://github.com/Vizards/OneNod/actions/workflows/release.yml";

export function requestCandidate({
  args = process.argv.slice(2),
  cwd = resolve(import.meta.dirname, "../.."),
  run = runCommand,
  stdout = process.stdout,
} = {}) {
  const channel = parseChannel(args);
  command(run, cwd, "git", ["--version"], "Git is unavailable");
  command(run, cwd, "gh", ["--version"], "GitHub CLI is unavailable");

  const repositoryRoot = command(
    run,
    cwd,
    "git",
    ["rev-parse", "--show-toplevel"],
    "this command must run from the OneNod source repository",
  ).trim();
  if (resolve(repositoryRoot) !== resolve(cwd)) {
    fail("the script is not running from the repository root that contains it");
  }

  const origin = command(
    run,
    cwd,
    "git",
    ["remote", "get-url", "origin"],
    "Git remote origin is unavailable",
  ).trim();
  if (githubRepository(origin)?.toLowerCase() !== officialRepository.toLowerCase()) {
    fail(`origin must identify the canonical ${officialRepository} repository`);
  }

  command(
    run,
    cwd,
    "gh",
    ["auth", "status", "--hostname", "github.com"],
    "GitHub CLI is not authenticated for github.com",
  );
  const repository = parseJSON(
    command(
      run,
      cwd,
      "gh",
      [
        "repo",
        "view",
        officialRepository,
        "--json",
        "nameWithOwner,defaultBranchRef",
      ],
      `GitHub CLI cannot inspect ${officialRepository}`,
    ),
    "GitHub repository metadata",
  );
  if (
    repository.nameWithOwner?.toLowerCase() !== officialRepository.toLowerCase() ||
    repository.defaultBranchRef?.name !== "main"
  ) {
    fail("GitHub repository identity or default branch is unexpected");
  }

  let sourceLabel;
  let sourceSha;
  if (channel === "alpha") {
    const currentBranch = command(
      run,
      cwd,
      "git",
      ["symbolic-ref", "--quiet", "--short", "HEAD"],
      "alpha candidates require a named local branch",
    ).trim();
    if (currentBranch === "") fail("alpha candidates require a named local branch");
    const localSha = strictCommit(
      command(
        run,
        cwd,
        "git",
        ["rev-parse", "--verify", "HEAD^{commit}"],
        "the local branch HEAD is not a commit",
      ).trim(),
      "local branch HEAD",
    );
    const remoteSha = remoteBranchCommit(run, cwd, currentBranch);
    if (remoteSha !== localSha) {
      fail(
        `origin/${currentBranch} must exist and point to local HEAD before requesting an alpha`,
      );
    }
    sourceLabel = `origin/${currentBranch}`;
    sourceSha = localSha;
  } else {
    sourceLabel = "origin/main";
    sourceSha = remoteBranchCommit(run, cwd, "main");
  }

  const worktree = command(
    run,
    cwd,
    "git",
    ["status", "--porcelain=v1"],
    "cannot inspect the local worktree",
  );
  stdout.write(
    [
      "OneNod public candidate request",
      `  Channel: ${channel}`,
      `  Source: ${sourceLabel}`,
      `  Commit: ${sourceSha}`,
      `  Controller: ${officialRepository}/.github/workflows/release.yml@main`,
      "  Version: assigned by the trusted release controller",
      worktree.trim() === ""
        ? "  Local worktree: clean"
        : "  Local worktree: has uncommitted changes; they are excluded from this candidate",
      "",
    ].join("\n"),
  );

  const dispatchArguments = [
    "workflow",
    "run",
    releaseWorkflow,
    "--repo",
    officialRepository,
    "--ref",
    "main",
    "-f",
    `intent=${channel}`,
  ];
  if (channel === "alpha") {
    dispatchArguments.push("-f", `source_sha=${sourceSha}`);
  }
  command(
    run,
    cwd,
    "gh",
    dispatchArguments,
    "GitHub rejected the candidate workflow dispatch",
  );
  stdout.write(`Candidate request submitted: ${releaseWorkflowURL}\n`);
  return { channel, sourceLabel, sourceSha, workflowURL: releaseWorkflowURL };
}

function parseChannel(args) {
  if (args.length !== 1 || (args[0] !== "alpha" && args[0] !== "beta")) {
    fail("usage: node scripts/release/request-candidate.mjs <alpha|beta>");
  }
  return args[0];
}

function remoteBranchCommit(run, cwd, branch) {
  const reference = `refs/heads/${branch}`;
  const output = command(
    run,
    cwd,
    "git",
    ["ls-remote", "--exit-code", officialRemote, reference],
    `cannot resolve ${officialRepository} ${reference}`,
  );
  const lines = output.trim().split("\n").filter(Boolean);
  if (lines.length !== 1) fail(`remote branch ${reference} did not resolve exactly once`);
  const [commit, returnedReference, ...extra] = lines[0].split("\t");
  if (returnedReference !== reference || extra.length !== 0) {
    fail(`remote branch ${reference} returned an unexpected Git reference`);
  }
  return strictCommit(commit, `remote branch ${reference}`);
}

function githubRepository(remote) {
  if (typeof remote !== "string" || remote === "") return null;
  if (!remote.includes("://")) {
    const scp = /^(?:[^@]+@)?github\.com:(.+)$/u.exec(remote);
    if (scp !== null) return repositoryPath(scp[1]);
  }
  let parsed;
  try {
    parsed = new URL(remote);
  } catch {
    return null;
  }
  if (parsed.hostname.toLowerCase() !== "github.com") return null;
  return repositoryPath(parsed.pathname);
}

function repositoryPath(value) {
  const path = value.replace(/^\/+|\/+$/gu, "").replace(/\.git$/u, "");
  return /^[^/]+\/[^/]+$/u.test(path) ? path : null;
}

function command(run, cwd, executable, args, errorMessage) {
  const result = run(executable, args, { cwd });
  if (
    result === null ||
    typeof result !== "object" ||
    result.status !== 0 ||
    typeof result.stdout !== "string"
  ) {
    fail(errorMessage);
  }
  return result.stdout;
}

function runCommand(executable, args, { cwd }) {
  return spawnSync(executable, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function parseJSON(value, label) {
  try {
    const parsed = JSON.parse(value);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      fail(`${label} is not a JSON object`);
    }
    return parsed;
  } catch (error) {
    if (error instanceof SyntaxError) fail(`${label} is not valid JSON`);
    throw error;
  }
}

function strictCommit(value, label) {
  if (!/^[0-9a-f]{40}$/u.test(value)) {
    fail(`${label} is not a full lowercase Git commit`);
  }
  return value;
}

function fail(message) {
  throw new Error(`candidate_request_failed:${message}`);
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    requestCandidate();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
