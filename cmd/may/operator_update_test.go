package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoverOperatorUpdateReusesExactGatewayUploadTransaction(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	receipt := &operatorDeploymentReceipt{
		AccountID:      "0123456789abcdef0123456789abcdef",
		ReleaseVersion: "0.0.2-alpha.10",
	}
	release := &verifiedRelease{Manifest: releaseManifest{ReleaseVersion: "0.0.2-alpha.11"}}
	artifact := releaseArtifact{Name: "onenod-deployment.tar.gz", SHA256: strings.Repeat("a", 64)}

	transaction, path, err := newOperatorUpdateTransaction(
		receipt, release, artifact, testPriorWorkerVersion, testTargetWorkerVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	transaction.ExecutorAfter = "33333333-3333-4333-8333-333333333333"
	transaction.Outcome = "remote_needs_attention"
	transaction.Phase = "gateway_upload_unknown"
	if err := writeAtomicPrivateJSON(path, transaction); err != nil {
		t.Fatal(err)
	}

	recovered, recoveredPath, resuming, err := recoverOrCreateOperatorUpdateTransaction(
		receipt, release, artifact, testPriorWorkerVersion, testTargetWorkerVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !resuming || recoveredPath != path || recovered.ID != transaction.ID ||
		recovered.ExecutorAfter != transaction.ExecutorAfter {
		t.Fatalf("unexpected recovered transaction: resuming=%t path=%q transaction=%+v", resuming, recoveredPath, recovered)
	}

	if _, _, _, err := recoverOrCreateOperatorUpdateTransaction(
		receipt, release, artifact, "44444444-4444-4444-8444-444444444444", testTargetWorkerVersion,
	); err == nil || !strings.Contains(err.Error(), "Cloudflare traffic changed") {
		t.Fatalf("changed production baseline was accepted: %v", err)
	}
}

func TestRecoverOperatorUpdateReusesExactExecutorUploadTransaction(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	receipt := &operatorDeploymentReceipt{
		AccountID:      "0123456789abcdef0123456789abcdef",
		ReleaseVersion: "0.0.2-alpha.10",
	}
	release := &verifiedRelease{Manifest: releaseManifest{ReleaseVersion: "0.0.2-alpha.11"}}
	artifact := releaseArtifact{Name: "onenod-deployment.tar.gz", SHA256: strings.Repeat("a", 64)}

	transaction, path, err := newOperatorUpdateTransaction(
		receipt, release, artifact, testPriorWorkerVersion, testTargetWorkerVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	transaction.ExecutorAfter = "33333333-3333-4333-8333-333333333333"
	transaction.Outcome = "remote_needs_attention"
	transaction.Phase = "executor_upload_unknown"
	if err := writeAtomicPrivateJSON(path, transaction); err != nil {
		t.Fatal(err)
	}

	recovered, recoveredPath, resuming, err := recoverOrCreateOperatorUpdateTransaction(
		receipt, release, artifact, testPriorWorkerVersion, testTargetWorkerVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !resuming || recoveredPath != path || recovered.ID != transaction.ID ||
		recovered.ExecutorAfter != transaction.ExecutorAfter {
		t.Fatalf("unexpected recovered transaction: resuming=%t path=%q transaction=%+v", resuming, recoveredPath, recovered)
	}
}

func TestRecoverOperatorUpdateRejectsExecutorUploadWithoutKnownVersion(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	receipt := &operatorDeploymentReceipt{
		AccountID:      "0123456789abcdef0123456789abcdef",
		ReleaseVersion: "0.0.2-alpha.10",
	}
	release := &verifiedRelease{Manifest: releaseManifest{ReleaseVersion: "0.0.2-alpha.11"}}
	artifact := releaseArtifact{Name: "onenod-deployment.tar.gz", SHA256: strings.Repeat("a", 64)}
	transaction, path, err := newOperatorUpdateTransaction(
		receipt, release, artifact, testPriorWorkerVersion, testTargetWorkerVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	transaction.Outcome = "remote_needs_attention"
	transaction.Phase = "executor_upload_unknown"
	if err := writeAtomicPrivateJSON(path, transaction); err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := recoverOrCreateOperatorUpdateTransaction(
		receipt, release, artifact, testPriorWorkerVersion, testTargetWorkerVersion,
	); err == nil || !strings.Contains(err.Error(), "invalid uploaded versions") {
		t.Fatalf("executor upload without a known version was accepted: %v", err)
	}
}

func TestUploadOrReuseWorkerVersionNeverUploadsKnownVersion(t *testing.T) {
	callLog := filepath.Join(t.TempDir(), "calls")
	wrangler := writeWranglerFixture(t, `
printf '%s\n' "$*" >> "`+callLog+`"
if [ "$1 $2" = "versions view" ]; then
  printf '%s\n' '{"id":"`+testTargetWorkerVersion+`","resources":{"bindings":[{"name":"EXECUTOR_AUTH_TOKEN","type":"secret_text"}]}}'
  exit 0
fi
exit 2
`)
	var output strings.Builder
	version, err := uploadOrReuseWorkerVersion(
		wrangler, "temporary", t.TempDir(), "worker.jsonc", "gateway",
		testTargetWorkerVersion, "test", &operatorConsole{stdout: &output, stderr: io.Discard},
		[]string{"EXECUTOR_AUTH_TOKEN"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if version != testTargetWorkerVersion || !strings.Contains(output.String(), "Reusing previously uploaded") {
		t.Fatalf("known version was not reused: version=%q output=%q", version, output.String())
	}
	calls, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "versions upload") || strings.Count(string(calls), "versions view") != 1 {
		t.Fatalf("known version caused a mutation or duplicate inspection: %s", calls)
	}
}

func TestUploadOrReuseWorkerVersionPreservesUploadedVersionOnInspectionFailure(t *testing.T) {
	wrangler := writeWranglerFixture(t, `
if [ "$1 $2" = "versions upload" ]; then
  printf '%s\n' 'Worker Version ID: `+testTargetWorkerVersion+`'
  exit 0
fi
if [ "$1 $2" = "versions view" ]; then
  printf '%s\n' '{"id":"`+testTargetWorkerVersion+`","resources":{"bindings":[]}}'
  exit 0
fi
exit 2
`)
	version, err := uploadOrReuseWorkerVersion(
		wrangler, "temporary", t.TempDir(), "worker.jsonc", "gateway",
		"", "test", &operatorConsole{stdout: io.Discard, stderr: io.Discard},
		[]string{"EXECUTOR_AUTH_TOKEN"},
	)
	if err == nil || !strings.Contains(err.Error(), "missing secret binding") {
		t.Fatalf("invalid uploaded binding set was accepted: %v", err)
	}
	if version != testTargetWorkerVersion {
		t.Fatalf("known uploaded version was discarded: %q", version)
	}
}

func TestUploadOrReuseWorkerVersionPreservesObservedVersionOnUploadError(t *testing.T) {
	wrangler := writeWranglerFixture(t, `
if [ "$1 $2" = "versions upload" ]; then
  printf '%s\n' 'Worker Version ID: `+testTargetWorkerVersion+`'
  exit 1
fi
exit 2
`)
	version, err := uploadOrReuseWorkerVersion(
		wrangler, "temporary", t.TempDir(), "worker.jsonc", "gateway",
		"", "test", &operatorConsole{stdout: io.Discard, stderr: io.Discard}, nil,
	)
	var unknown *remoteOutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("upload error was not preserved as an unknown outcome: %v", err)
	}
	if version != testTargetWorkerVersion {
		t.Fatalf("observed uploaded version was discarded: %q", version)
	}
}
