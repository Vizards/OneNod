import { parse } from "yaml";

export function validateReleaseWorkflow(value) {
  const workflow = parseWorkflow(value);
  for (const jobName of [
    "local-artifacts",
    "deployment-artifacts",
    "sbom",
    "publish",
  ]) {
    const job = workflowJob(workflow, jobName);
    const steps = workflowSteps(job, jobName);
    const pnpmSetup = pinnedActionStep(steps, "pnpm/action-setup");
    const nodeSetup = pinnedActionStep(steps, "actions/setup-node");
    if (
      pnpmSetup === undefined ||
      nodeSetup?.with?.cache !== "pnpm" ||
      !steps.some(({ run }) => run === "pnpm install --frozen-lockfile")
    ) {
      fail(`release job ${jobName} does not install the frozen Node dependency set`);
    }
  }

  const prepareJob = workflowJob(workflow, "prepare");
  const prepareSteps = workflowSteps(prepareJob, "prepare");
  const prepareCheckout = namedStep(
    prepareSteps,
    "Check out the reviewed release controller",
  );
  const alphaSource = namedStep(
    prepareSteps,
    "Fetch the exact same-repository alpha source",
  );
  const publishedLineage = namedStep(
    prepareSteps,
    "Fetch published release lineage",
  );
  const deriveRelease = namedStep(
    prepareSteps,
    "Derive the release from the manifest transition",
  );
  const predecessorLineage = namedStep(
    prepareSteps,
    "Require a published immutable predecessor",
  );
  const selectedSourceContract = namedStep(
    prepareSteps,
    "Verify the exact selected source contract",
  );
  if (
    !isPinnedAction(prepareCheckout?.uses, "actions/checkout") ||
    !stepRun(alphaSource).includes("branches-where-head") ||
    !stepRun(publishedLineage).includes("gh api --paginate --slurp") ||
    !stepRun(publishedLineage).includes(
      "X-GitHub-Api-Version: 2026-03-10",
    ) ||
    !stepRun(publishedLineage).includes("releases?per_page=100") ||
    !stepRun(publishedLineage).includes(".draft == false") ||
    !stepRun(publishedLineage).includes(".immutable == true") ||
    !stepRun(publishedLineage).includes(
      '> "$RUNNER_TEMP/published-release-tags.json"',
    ) ||
    !stepRun(deriveRelease).includes(
      '--published-release-tags "$RUNNER_TEMP/published-release-tags.json"',
    ) ||
    !stepRun(deriveRelease).includes('--source-sha "$SOURCE_SHA_INPUT"') ||
    stepRun(selectedSourceContract) !==
      'node scripts/release/verify-source-contract.mjs --source-sha "$SOURCE_SHA"' ||
    selectedSourceContract?.env?.SOURCE_SHA !==
      "${{ steps.release.outputs.source_sha }}" ||
    selectedSourceContract?.if !==
      "steps.release.outputs.should_release == 'true'" ||
    !jobCondition(prepareJob).includes("github.ref == 'refs/heads/main'") ||
    namedStep(prepareSteps, "Require a GitHub-verified source commit signature") ===
      undefined ||
    !prepareSteps.some(
      ({ run }) => typeof run === "string" && run.includes("GITHUB_STEP_SUMMARY"),
    ) ||
    prepareJob.permissions?.contents !== "read" ||
    prepareJob.permissions?.attestations !== "read" ||
    !stepRun(predecessorLineage).includes(
      "--pattern onenod-provenance.intoto.jsonl",
    ) ||
    !stepRun(predecessorLineage).includes("gh attestation verify") ||
    !stepRun(predecessorLineage).includes(
      "--bundle \"$lineage_dir/onenod-provenance.intoto.jsonl\"",
    ) ||
    !stepRun(predecessorLineage).includes(
      "--predicate-type https://slsa.dev/provenance/v1",
    ) ||
    !stepRun(predecessorLineage).includes(
      "--signer-workflow github.com/Vizards/OneNod/.github/workflows/release.yml",
    ) ||
    !stepRun(predecessorLineage).includes("--source-ref refs/heads/main") ||
    !stepRun(predecessorLineage).includes("--deny-self-hosted-runners") ||
    namedStep(prepareSteps, "Create or verify the exact lightweight tag") !== undefined
  ) {
    fail(
      "prepare job must produce a read-only, signed-source plan through the reviewed main controller",
    );
  }

  const authorizeJob = workflowJob(workflow, "authorize");
  const authorizeSteps = workflowSteps(authorizeJob, "authorize");
  const authorizeEnvironment = recordValue(authorizeJob.environment);
  const tagStep = namedStep(
    authorizeSteps,
    "Create or verify the exact lightweight tag",
  );
  if (
    !jobNeeds(authorizeJob, "prepare") ||
    !jobCondition(authorizeJob).includes("github.ref == 'refs/heads/main'") ||
    authorizeEnvironment?.name !==
      "release-${{ needs.prepare.outputs.channel }}" ||
    authorizeJob.permissions?.contents !== "write" ||
    !stepRun(tagStep).includes('ref="refs/tags/$RELEASE_TAG"')
  ) {
    fail("authorize job must gate and bind the exact reviewed release plan");
  }

  for (const jobName of ["local-artifacts", "deployment-artifacts"]) {
    if (!jobNeeds(workflowJob(workflow, jobName), "authorize")) {
      fail(`release build job ${jobName} must wait for release authorization`);
    }
  }
  const localSteps = workflowSteps(
    workflowJob(workflow, "local-artifacts"),
    "local-artifacts",
  );
  const exactBuildSigning = stepRun(
    namedStep(localSteps, "Bind deterministic exact-build macOS identities"),
  );
  const exactBuildVerification = stepRun(
    namedStep(localSteps, "Verify exact-build identities and Hardened Runtime"),
  );
  if (
    !exactBuildSigning.includes("--sign -") ||
    !exactBuildSigning.includes("--options runtime") ||
    !exactBuildSigning.includes("--timestamp=none") ||
    !exactBuildSigning.includes("com.github.vizards.onenod.may-ssh-sign") ||
    !exactBuildVerification.includes("codesign --verify --strict") ||
    !exactBuildVerification.includes("com.apple.security.get-task-allow") ||
    !exactBuildVerification.includes("com.apple.security.debugger") ||
    !exactBuildVerification.includes("com.apple.security.cs.disable-library-validation") ||
    !exactBuildVerification.includes("com.apple.security.cs.disable-executable-page-protection") ||
    !exactBuildVerification.includes("com.apple.security.cs.allow-jit") ||
    !exactBuildVerification.includes("com.apple.security.cs.allow-unsigned-executable-memory")
  ) {
    fail("native release jobs must bind and verify deterministic ad-hoc Hardened Runtime exact builds");
  }
  const publishJob = workflowJob(workflow, "publish");
  const publishSteps = workflowSteps(publishJob, "publish");
  const publishCheckout = namedStep(
    publishSteps,
    "Check out the reviewed release controller",
  );
  const controllerIdentity = namedStep(
    publishSteps,
    "Verify the release controller identity",
  );
  const publishRuns = publishSteps
    .map(({ run }) => (typeof run === "string" ? run : ""))
    .join("\n");
  if (
    !isPinnedAction(publishCheckout?.uses, "actions/checkout") ||
    publishCheckout?.with?.ref !== "${{ github.sha }}" ||
    !jobNeeds(publishJob, "authorize") ||
    !jobCondition(publishJob).includes("needs.authorize.result == 'success'") ||
    !jobCondition(publishJob).includes("github.ref == 'refs/heads/main'") ||
    stepRun(controllerIdentity) !==
      'test "$(git rev-parse HEAD)" = "$WORKFLOW_SHA"' ||
    !publishRuns.includes(
      'gh release view "$RELEASE_TAG" --json databaseId --jq .databaseId',
    ) ||
    publishRuns.includes('releases/tags/$RELEASE_TAG" --jq .id') ||
    publishRuns.includes("refs/tags/${{ needs.prepare.outputs.tag }}") ||
    publishRuns.includes(".release-controller") ||
    (publishRuns.match(
      /node scripts\/release\/verify-github-release\.mjs/gu,
    )?.length ?? 0) !== 2
  ) {
    fail(
      "publish job must execute only the reviewed main controller while handling candidate artifacts",
    );
  }
}

function parseWorkflow(value) {
  let parsed;
  try {
    parsed = parse(value, { maxAliasCount: 0, uniqueKeys: true });
  } catch {
    fail("release workflow is not valid YAML");
  }
  if (recordValue(parsed)?.jobs === undefined) {
    fail("release workflow does not contain a jobs map");
  }
  return parsed;
}

function workflowJob(workflow, name) {
  const jobs = recordValue(workflow.jobs);
  const job = recordValue(jobs?.[name]);
  if (job === undefined) fail(`release workflow job ${name} is missing`);
  return job;
}

function workflowSteps(job, name) {
  if (
    !Array.isArray(job.steps) ||
    job.steps.some((step) => recordValue(step) === undefined)
  ) {
    fail(`release workflow job ${name} has invalid steps`);
  }
  return job.steps;
}

function recordValue(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value
    : undefined;
}

function namedStep(steps, name) {
  return steps.find((step) => step.name === name);
}

function pinnedActionStep(steps, action) {
  return steps.find(({ uses }) => isPinnedAction(uses, action));
}

function isPinnedAction(value, action) {
  if (typeof value !== "string") return false;
  const prefix = `${action}@`;
  return (
    value.startsWith(prefix) &&
    /^[0-9a-f]{40}$/u.test(value.slice(prefix.length))
  );
}

function stepRun(step) {
  return typeof step?.run === "string" ? step.run : "";
}

function jobCondition(job) {
  return typeof job.if === "string" ? job.if : "";
}

function jobNeeds(job, dependency) {
  const needs = typeof job.needs === "string" ? [job.needs] : job.needs;
  return Array.isArray(needs) && needs.includes(dependency);
}

function fail(message) {
  throw new Error(message);
}
