package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/Vizards/OneNod/cmd/beholder-gatekeeper/internal/retrieval"
)

const (
	maximumRetrievalSnapshotBytes = 0 // File-backed snapshots have no total-size admission gate.
	maximumModelRequestBytes      = 16 * 1024 * 1024
	maximumRetrievalRounds        = 24
	maximumRoundToolCalls         = 32
	retrievalSnapshotName         = "07-session-snapshot.jsonl"
	retrievalRequestName          = "08-retrieval-request.json"
)

//go:embed retrieval-policy.txt
var retrievalSystemPrompt string

type retrievalInput struct {
	store    *retrieval.Store
	initial  []byte
	deadline time.Time
	request  []byte
}

type retrievalSourceEvidence struct {
	SchemaVersion     int             `json:"schema_version"`
	SnapshotID        string          `json:"snapshot_id"`
	SessionFile       string          `json:"session_file"`
	RequestFile       string          `json:"request_file"`
	ToolsSHA256       string          `json:"tools_sha256"`
	InitialInput      json.RawMessage `json:"initial_input"`
	PrefetchedHistory bool            `json:"prefetched_history"`
	GeneratedSummary  bool            `json:"generated_summary"`
	Selection         string          `json:"selection"`
	StorageFormat     string          `json:"storage_format,omitempty"`
}

func buildRetrievalDecisionInput(request localDecisionRequest, aliases map[string]string, capture *transcriptCapture) (externalDecisionInput, contextMetrics, sourceContextEvidence, error) {
	var output externalDecisionInput
	metrics := contextMetrics{}
	at := time.Now().UTC()
	if capture != nil {
		at = capture.capturedAt
	}
	source := sourceContextEvidence{SchemaVersion: 1, RecordType: "beholder_source_context", EvidenceID: request.RequestID, CapturedAt: at,
		TargetAlias: externalizeTarget(request.ActualRequest, aliases).TargetAlias, OperationTargetSHA256: localOperationTargetSHA256(request.ActualRequest),
		LocalRequest: localRequestForEvidence(request), Candidates: []contextCandidate{}, CandidateSummary: []contextCandidateSummary{},
		RequesterContext: rawJSONCopy(request.ActualRequest.RequesterContext), GatekeeperProcess: collectEvidenceProcessContext(), ProcessEnvironment: collectEvidenceEnvironment()}
	fail := func(code string) (externalDecisionInput, contextMetrics, sourceContextEvidence, error) {
		source.CollectorError = stringPointer(code)
		return output, metrics, source, errors.New(code)
	}
	if _, err := validateLocalDecisionEnvelope(request); err != nil {
		return fail(err.Error())
	}
	if capture == nil {
		var err error
		capture, err = openTranscriptCapture(request.TranscriptPath)
		if err != nil {
			return fail("related-context-unavailable")
		}
		defer capture.close()
	}
	if capture.path != request.TranscriptPath || capture.file == nil {
		return fail("retrieval-snapshot-identity-mismatch")
	}
	source.TranscriptSnapshot = transcriptSnapshot{Source: "codex-session-jsonl", CaptureBoundary: "file-prefix-at-request-admission", FileBytesAtOpen: capture.info.Size(), FileModifiedAtOpen: capture.info.ModTime().UTC()}
	if match := codexTaskIDPattern.FindStringSubmatch(request.TranscriptPath); len(match) == 2 {
		source.TranscriptSnapshot.TaskID = match[1]
	}
	ctx := context.Background()
	cancel := func() {}
	if !request.decisionDeadline.IsZero() {
		ctx, cancel = context.WithDeadline(ctx, request.decisionDeadline)
	}
	defer cancel()
	if ctx.Err() != nil {
		return fail("gatekeeper-decision-budget-exhausted")
	}
	local := localRequestForEvidence(request)
	// The source evidence stores this parsed at its root to support redaction.
	// read_request must still include the original executable/arguments/env.
	local.ActualRequest.RequesterContext = request.ActualRequest.RequesterContext
	// A local filesystem path is not needed for any model query. Tools cannot
	// open a path supplied by the model; they only navigate this captured source.
	local.TranscriptPath = ""
	requestBytes, err := json.MarshalIndent(local, "", "  ")
	if err != nil {
		return fail("model-request-build-failed")
	}
	store, err := retrieval.Freeze(ctx, io.NewSectionReader(capture.file, 0, capture.info.Size()), string(requestBytes), request.RequestID)
	if err != nil {
		clear(requestBytes)
		if ctx.Err() != nil {
			return fail("gatekeeper-decision-budget-exhausted")
		}
		return fail("retrieval-snapshot-invalid")
	}
	if store.SourceBytes() != capture.info.Size() {
		_ = store.Close()
		clear(requestBytes)
		return fail("retrieval-snapshot-read-failed")
	}
	target := externalizeTarget(request.ActualRequest, aliases)
	initial, err := json.Marshal(struct {
		Pending verifiedExternalTarget `json:"pending_request"`
	}{verifiedExternalTarget{
		VerificationScope: actualRequestVerification, Surface: target.Surface, Operation: target.Operation, TargetKind: target.TargetKind,
		TargetID: target.TargetID, TargetAlias: target.TargetAlias, KeyFingerprint: target.KeyFingerprint, RemoteUser: target.RemoteUser, HostKeyFingerprint: target.HostKeyFingerprint}})
	if err != nil {
		_ = store.Close()
		clear(requestBytes)
		return fail("model-request-build-failed")
	}
	source.TranscriptSnapshot.ScannedBytes = store.SourceBytes()
	source.TranscriptSnapshot.ScannedEvents = store.Count()
	source.TranscriptSnapshot.ScannedContentSHA256 = store.SourceDigest()

	source.Retrieval = &retrievalSourceEvidence{SchemaVersion: 2, StorageFormat: retrieval.IndexedFormat, SnapshotID: store.ID(), SessionFile: retrievalSnapshotName, RequestFile: retrievalRequestName,
		ToolsSHA256: digestValue(retrieval.Tools()), InitialInput: append(json.RawMessage(nil), initial...), Selection: "model-selected exact original records; no prefetch, history summary or relevance ranking"}
	metrics.InputBytes = len(initial)
	source.SelectionMetrics = metrics
	output.retrieval = &retrievalInput{store: store, initial: initial, deadline: request.decisionDeadline, request: requestBytes}
	return output, metrics, source, nil
}

func attachRetrievalInput(bundle *evidenceBundle, input *externalDecisionInput) error {
	if input.retrieval == nil {
		return nil
	}
	if bundle == nil {
		return errors.New("evidence-bundle-unavailable")
	}
	r := input.retrieval
	ctx := context.Background()
	cancel := func() {}
	if !r.deadline.IsZero() {
		ctx, cancel = context.WithDeadline(ctx, r.deadline)
	}
	defer cancel()
	if err := r.store.Persist(ctx, filepath.Join(bundle.path, retrievalSnapshotName)); err != nil {
		return errors.New("evidence-retrieval-source-write-failed")
	}
	bundle.store.mu.Lock()
	manifest, err := readManifest(bundle.path)
	if err == nil && manifest.Files[retrievalSnapshotName] == nil {
		digest := r.store.SourceDigest()
		manifest.Files[retrievalSnapshotName] = &digest
		err = writeManifest(bundle.path, manifest)
	} else if err == nil {
		err = errors.New("retrieval evidence manifest conflict")
	}
	bundle.store.mu.Unlock()
	if err != nil {
		return err
	}
	if err := bundle.writeRetrievalFile(retrievalRequestName, r.request); err != nil {
		return errors.New("evidence-retrieval-source-write-failed")
	}
	bundle.retrieval = r
	return nil
}

func (bundle *evidenceBundle) writeRetrievalFile(name string, body []byte) error {
	if bundle == nil || bundle.store == nil || name != retrievalRequestName || len(body) > maximumModelRequestBytes {
		return errors.New("invalid retrieval evidence source")
	}
	bundle.store.mu.Lock()
	defer bundle.store.mu.Unlock()
	manifest, err := readManifest(bundle.path)
	if err != nil || manifest.Files[name] != nil {
		return errors.New("retrieval evidence manifest conflict")
	}
	if err := writeNewEvidenceFile(bundle.path, name, body); err != nil {
		return err
	}
	manifest.Files[name] = digestPointer(body)
	return writeManifest(bundle.path, manifest)
}

func retrievalPolicySHA256() string {
	// Policy identity covers the API contract as well as instructions.
	return digestValue(append(append([]byte(strings.TrimSuffix(retrievalSystemPrompt, "\n")), '\n'), retrieval.Tools()...))
}
