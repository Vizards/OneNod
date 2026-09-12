# Bootstrap the first `may`

Read [Setup](setup.md) for scope and release provenance.

When `may` is not installed, obtain the macOS archive, `release-manifest.json`,
and `onenod-provenance.intoto.jsonl` from the canonical GitHub Release selected
by the human. Stable is the default; use an exact prerelease only when the human
deliberately requests that channel or version. Do not execute the downloaded
binary yet.

The first executable cannot authenticate itself. The Agent uses an independent GitHub
attestation verifier (normally `gh
attestation verify release-manifest.json --repo Vizards/OneNod --bundle
onenod-provenance.intoto.jsonl --signer-workflow
Vizards/OneNod/.github/workflows/release.yml --source-ref refs/heads/main
--deny-self-hosted-runners`) to
verify the manifest's GitHub build provenance. Then locate the exact
architecture-specific archive entry in that
verified manifest and compare its declared SHA-256 and byte size with the
downloaded archive. Reject a repository, workflow, source commit, artifact
name, digest, architecture, or version mismatch. After these read-only checks,
the Agent must output only the authenticated temporary `may` path, the attested
source digest and Release tag, and one exact `may install ...` or `may operator
init ...` command. It then exits without executing `may`. The human inspects
that non-secret summary, stops every same-user Agent harness, and runs the exact
command from a human-controlled terminal. Do not treat `may version`, a
filename, a Release page, or the archive's own `RELEASE.json` as independent
provenance.

Only after those checks, treat the downloaded bytes as one authenticated,
bounded artifact snapshot and extract it in a private temporary directory. The
CLI repeats a default-no first-execution ceremony summary before it can install
an initializer, helper, Skill, or local runtime. That prompt is a human gate,
not permission for the Agent that verified the artifact to remain running. Do
not require Go, a repository clone, private project documents, or another
Skill. Once the one-time Keychain
ceremony has pinned the exact official build, later updates are authenticated
by the installed `may` and stable helper; never replace that path with a locally
built binary or an unverified third-party package.

The first preview is not Developer ID signed or notarized. macOS may therefore
require the human to allow the first verified binary through Gatekeeper. Never
remove quarantine metadata, ad-hoc sign the downloaded binary, disable
Gatekeeper, or otherwise bypass that decision for the human.

Stable is the default release channel. A human who is deliberately testing a
candidate may select `beta` or `alpha` through the CLI's `--channel` option.
This is a release-discovery preference, not a code-execution trust boundary:
all official alpha, beta, and stable artifacts must pass the same provenance,
digest, and exact-build checks. `beta` may discover beta or stable Releases;
`alpha` may discover alpha, beta, or stable Releases. Broadening discovery to
include a prerelease requires an explicit default-no anti-accident confirmation
and is persisted in the applicable local or operator receipt. Do not infer
prerelease consent from the fact that the task is a test.

A stable binary released before channel support cannot discover the first
candidate. In that one bootstrap case, obtain `may` from the exact GitHub
prerelease selected by the human, then pass its canonical version with
`--version X.Y.Z-alpha.N` to setup. Exact version selection and `--channel` are
mutually exclusive. Once installed, the receipt carries the inferred channel
and normal update discovery applies.

