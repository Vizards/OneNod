package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	evidenceManifestSchemaVersion  = 2
	evidenceManifestName           = "manifest.json"
	evidenceSourceName             = "01-source-context.json"
	evidenceRequestName            = "02-model-request.json"
	evidenceResponseName           = "03-model-response.json"
	evidenceOutcomeName            = "04-human-outcome.json"
	evidenceComparisonRequestName  = "05-model-request-thinking-enabled.json"
	evidenceComparisonResponseName = "06-model-response-thinking-enabled.json"
	evidenceRedactionName          = "redactions.json"
	evidenceOutcomeEventsName      = "outcome-delivery.jsonl"
	maximumEvidenceSourceBytes     = 16 * 1024 * 1024
)

type redactionEvent struct {
	Source           string `json:"source"`
	JSONPath         string `json:"json_path"`
	Rule             string `json:"rule"`
	OriginalBytes    int    `json:"original_bytes"`
	ReplacementBytes int    `json:"replacement_bytes"`
}

type evidenceManifest struct {
	SchemaVersion          int                `json:"schema_version"`
	RecordType             string             `json:"record_type"`
	EvidenceID             string             `json:"evidence_id"`
	State                  string             `json:"state"`
	CreatedAt              time.Time          `json:"created_at"`
	ModelFinalizedAt       *time.Time         `json:"model_finalized_at"`
	HumanFinalizedAt       *time.Time         `json:"human_finalized_at"`
	GatekeeperVersion      string             `json:"gatekeeper_version"`
	PolicySHA256           string             `json:"policy_sha256"`
	ConfigSHA256           string             `json:"config_sha256"`
	CoreBinarySHA256       string             `json:"core_binary_sha256,omitempty"`
	OneNodBinarySHA256     string             `json:"onenod_binary_sha256,omitempty"`
	GatekeeperBinarySHA256 string             `json:"gatekeeper_binary_sha256"`
	Surface                string             `json:"surface,omitempty"`
	Operation              string             `json:"operation,omitempty"`
	TargetAlias            string             `json:"target_alias,omitempty"`
	Files                  map[string]*string `json:"files"`
	SecretMaterialStored   bool               `json:"secret_material_stored"`
}

type modelRequestEvidence struct {
	SchemaVersion int             `json:"schema_version"`
	RecordType    string          `json:"record_type"`
	EvidenceID    string          `json:"evidence_id"`
	Variant       string          `json:"variant"`
	Method        string          `json:"method"`
	Endpoint      string          `json:"endpoint"`
	ContentType   string          `json:"content_type"`
	StartedAt     time.Time       `json:"started_at"`
	RequestSent   bool            `json:"request_sent"`
	BodyBytes     int             `json:"body_bytes"`
	BodySHA256    string          `json:"body_sha256,omitempty"`
	RawBodyBase64 string          `json:"raw_body_base64,omitempty"`
	Body          json.RawMessage `json:"body,omitempty"`
	BuildError    *string         `json:"build_error"`
}

type modelResponseEvidence struct {
	SchemaVersion    int               `json:"schema_version"`
	RecordType       string            `json:"record_type"`
	EvidenceID       string            `json:"evidence_id"`
	Variant          string            `json:"variant"`
	ReceivedAt       time.Time         `json:"received_at"`
	HTTPStatus       int               `json:"http_status"`
	Headers          map[string]string `json:"headers"`
	BodyBytes        int               `json:"body_bytes"`
	BodySHA256       string            `json:"body_sha256,omitempty"`
	RawBodyBase64    string            `json:"raw_body_base64,omitempty"`
	Body             json.RawMessage   `json:"body,omitempty"`
	BodyTruncated    bool              `json:"body_truncated"`
	TransportError   *string           `json:"transport_error"`
	TransportDetail  *string           `json:"transport_error_detail,omitempty"`
	ParserError      *string           `json:"parser_error"`
	Decision         string            `json:"decision"`
	Reason           string            `json:"reason"`
	ScopeResolution  string            `json:"scope_resolution,omitempty"`
	EvidenceRefs     []string          `json:"evidence_refs"`
	ResponseShape    string            `json:"response_shape"`
	ModelUsed        bool              `json:"model_used"`
	ModelCalled      bool              `json:"model_called"`
	ModelTransport   string            `json:"model_transport,omitempty"`
	ReasoningPresent bool              `json:"reasoning_present"`
	ReasoningBytes   int               `json:"reasoning_bytes"`
	ReasoningTokens  int               `json:"reasoning_tokens"`
	FinishReason     string            `json:"finish_reason"`
	LatencyMS        int64             `json:"latency_ms"`
}

type evidenceIndexRecord struct {
	SchemaVersion       int       `json:"schema_version"`
	RecordType          string    `json:"record_type"`
	ObservedAt          time.Time `json:"observed_at"`
	EvidenceID          string    `json:"evidence_id"`
	Phase               string    `json:"phase"`
	Variant             string    `json:"variant,omitempty"`
	Surface             string    `json:"surface,omitempty"`
	Operation           string    `json:"operation,omitempty"`
	TargetAlias         string    `json:"target_alias,omitempty"`
	Decision            string    `json:"decision,omitempty"`
	Reason              string    `json:"reason,omitempty"`
	ErrorCode           *string   `json:"error_code,omitempty"`
	ModelCalled         *bool     `json:"model_called,omitempty"`
	ModelUsed           *bool     `json:"model_used,omitempty"`
	ResponseShape       string    `json:"response_shape,omitempty"`
	HTTPStatus          *int      `json:"http_status,omitempty"`
	LatencyMS           *int64    `json:"latency_ms,omitempty"`
	AuthorizationSource string    `json:"authorization_source,omitempty"`
	HumanDecision       string    `json:"human_decision,omitempty"`
	BundlePath          string    `json:"bundle_path"`
	State               string    `json:"state"`
	ManifestSHA256      string    `json:"manifest_sha256"`
}

type outcomeDeliveryEvent struct {
	SchemaVersion int       `json:"schema_version"`
	RecordType    string    `json:"record_type"`
	ObservedAt    time.Time `json:"observed_at"`
	EvidenceID    string    `json:"evidence_id"`
	Result        string    `json:"result"`
	ErrorCode     *string   `json:"error_code"`
}

type evidenceStore struct {
	mu                sync.Mutex
	root              string
	indexPath         string
	outcomeEventsPath string
	bundles           map[string]string
}

type evidenceBundle struct {
	store       *evidenceStore
	evidenceID  string
	path        string
	capturedAt  time.Time
	surface     string
	operation   string
	targetAlias string
}

type evidencePresence struct {
	state              string
	source             bool
	request            bool
	response           bool
	comparisonRequest  bool
	comparisonResponse bool
	outcome            bool
}

type humanOutcomeWriteError struct {
	code string
}

func (failure humanOutcomeWriteError) Error() string {
	return failure.code
}

func humanOutcomeWriteFailure(code string) error {
	return humanOutcomeWriteError{code: code}
}

func humanOutcomeWriteErrorCode(err error) string {
	var failure humanOutcomeWriteError
	if errors.As(err, &failure) && safeReasonCode(failure.code) {
		return failure.code
	}
	return "human-outcome-write-failed"
}

func newEvidenceStore(root string) (*evidenceStore, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("evidence root must be an absolute canonical path")
	}
	if err := os.MkdirAll(root, 0o700); err != nil || os.Chmod(root, 0o700) != nil {
		return nil, errors.New("create private evidence root failed")
	}
	if err := verifyPrivateDirectory(root); err != nil {
		return nil, err
	}
	store := &evidenceStore{
		root: root, indexPath: filepath.Join(root, "index.jsonl"),
		outcomeEventsPath: filepath.Join(root, evidenceOutcomeEventsName),
		bundles:           map[string]string{},
	}
	if err := store.recoverInterruptedBundles(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *evidenceStore) recoverInterruptedBundles() error {
	months, err := os.ReadDir(store.root)
	if err != nil {
		return err
	}
	for _, month := range months {
		if !month.IsDir() {
			continue
		}
		monthPath := filepath.Join(store.root, month.Name())
		if verifyPrivateDirectory(monthPath) != nil {
			return errors.New("existing evidence month identity mismatch")
		}
		bundles, err := os.ReadDir(monthPath)
		if err != nil {
			return err
		}
		for _, entry := range bundles {
			if !entry.IsDir() {
				return errors.New("unexpected file in evidence month")
			}
			bundlePath := filepath.Join(monthPath, entry.Name())
			if verifyPrivateDirectory(bundlePath) != nil {
				return errors.New("existing evidence bundle identity mismatch")
			}
			manifest, err := readManifest(bundlePath)
			if err != nil || manifest.EvidenceID != entry.Name() {
				return errors.New("existing evidence manifest mismatch")
			}
			store.bundles[manifest.EvidenceID] = bundlePath
			if manifest.State == "reserved" || manifest.State == "collecting" {
				manifest.State = "partial"
				if err := writeManifest(bundlePath, manifest); err != nil {
					return errors.New("recover interrupted evidence bundle failed")
				}
			}
		}
	}
	return nil
}

func verifyPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("evidence directory identity mismatch")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("evidence directory owner mismatch")
	}
	return nil
}

func (store *evidenceStore) begin(
	source sourceContextEvidence,
	gatekeeperBinarySHA256, policySHA256, configSHA256 string,
) (*evidenceBundle, error) {
	bundle, err := store.reserve(
		source, gatekeeperBinarySHA256, policySHA256, configSHA256,
	)
	if err != nil {
		clearSourceContextEvidence(&source)
		return nil, err
	}
	if err := bundle.writeSource(source); err != nil {
		// The reservation is itself durable and remains the only valid bundle
		// identity for this request. Return it so the caller can write a minimal
		// fallback source and the not-called decision stages without trying to
		// reserve the same evidence ID a second time.
		return bundle, err
	}
	return bundle, nil
}

// reserve establishes the durable evidence identity before any potentially
// expensive transcript scan. That lets the Core receive an evidence handle in
// time to correlate a fast human outcome while the immutable transcript
// snapshot is processed asynchronously.
func (store *evidenceStore) reserve(
	source sourceContextEvidence,
	gatekeeperBinarySHA256, policySHA256, configSHA256 string,
) (*evidenceBundle, error) {
	if store == nil || !safeRecordLabel(source.EvidenceID) || len(source.EvidenceID) > 96 ||
		source.CapturedAt.IsZero() || source.LocalRequest.RequestID != source.EvidenceID ||
		!validSHA256(source.LocalRequest.CoreBinarySHA256) || !validSHA256(gatekeeperBinarySHA256) ||
		!validSHA256(policySHA256) || !validSHA256(configSHA256) {
		return nil, errors.New("invalid evidence identity")
	}
	evidenceID := source.EvidenceID
	capturedAt := source.CapturedAt.UTC()
	coreBinarySHA256 := source.LocalRequest.CoreBinarySHA256
	onenodBinarySHA256 := requesterExecutableSHA256(source.RequesterContext)
	surface := source.LocalRequest.ActualRequest.Surface
	operation := source.LocalRequest.ActualRequest.Operation
	targetAlias := source.TargetAlias
	store.mu.Lock()
	defer store.mu.Unlock()
	monthPath := filepath.Join(store.root, capturedAt.Format("2006-01"))
	if err := os.MkdirAll(monthPath, 0o700); err != nil || os.Chmod(monthPath, 0o700) != nil || verifyPrivateDirectory(monthPath) != nil {
		return nil, errors.New("create evidence month failed")
	}
	bundlePath := filepath.Join(monthPath, evidenceID)
	if err := os.Mkdir(bundlePath, 0o700); err != nil || verifyPrivateDirectory(bundlePath) != nil {
		return nil, errors.New("create unique evidence bundle failed")
	}
	bundle := &evidenceBundle{
		store: store, evidenceID: evidenceID, path: bundlePath,
		capturedAt: capturedAt, surface: surface, operation: operation, targetAlias: targetAlias,
	}
	manifest := evidenceManifest{
		SchemaVersion: evidenceManifestSchemaVersion, RecordType: "beholder_decision_evidence_manifest",
		EvidenceID: evidenceID, State: "reserved", CreatedAt: capturedAt,
		GatekeeperVersion: gatekeeperVersion, PolicySHA256: policySHA256,
		ConfigSHA256: configSHA256, CoreBinarySHA256: coreBinarySHA256,
		OneNodBinarySHA256:     onenodBinarySHA256,
		GatekeeperBinarySHA256: gatekeeperBinarySHA256,
		Surface:                surface, Operation: operation, TargetAlias: targetAlias,
		Files: map[string]*string{
			evidenceSourceName: nil, evidenceRequestName: nil,
			evidenceResponseName: nil, evidenceOutcomeName: nil,
			evidenceComparisonRequestName: nil, evidenceComparisonResponseName: nil,
			evidenceRedactionName: nil,
		},
		SecretMaterialStored: false,
	}
	if err := writeManifest(bundlePath, manifest); err != nil {
		return nil, err
	}
	store.bundles[evidenceID] = bundlePath
	return bundle, nil
}

func (bundle *evidenceBundle) writeSource(source sourceContextEvidence) error {
	if bundle == nil || bundle.store == nil || source.EvidenceID != bundle.evidenceID ||
		source.LocalRequest.RequestID != bundle.evidenceID || source.CapturedAt.IsZero() ||
		!source.CapturedAt.UTC().Equal(bundle.capturedAt.UTC()) {
		clearSourceContextEvidence(&source)
		return errors.New("invalid evidence identity")
	}
	sourceBytes, redactions, err := marshalEvidenceJSON(evidenceSourceName, source)
	clearSourceContextEvidence(&source)
	if err != nil {
		return errors.New("evidence-source-encode-failed")
	}
	if len(sourceBytes) > maximumEvidenceSourceBytes {
		clear(sourceBytes)
		return errors.New("evidence-source-too-large")
	}
	defer clear(sourceBytes)
	redactionBytes, err := json.MarshalIndent(struct {
		SchemaVersion int              `json:"schema_version"`
		RecordType    string           `json:"record_type"`
		EvidenceID    string           `json:"evidence_id"`
		Events        []redactionEvent `json:"events"`
	}{1, "beholder_evidence_redactions", bundle.evidenceID, redactions}, "", "  ")
	if err != nil {
		return errors.New("evidence-redaction-encode-failed")
	}
	redactionBytes = append(redactionBytes, '\n')
	defer clear(redactionBytes)

	bundle.store.mu.Lock()
	defer bundle.store.mu.Unlock()
	manifest, err := readManifest(bundle.path)
	if err != nil || manifest.EvidenceID != bundle.evidenceID ||
		manifest.Files[evidenceSourceName] != nil || manifest.Files[evidenceRedactionName] != nil {
		return errors.New("evidence-source-manifest-conflict")
	}
	if err := writeNewEvidenceFile(bundle.path, evidenceSourceName, sourceBytes); err != nil {
		manifest.State = "partial"
		_ = writeManifest(bundle.path, manifest)
		return errors.New("evidence-source-file-write-failed")
	}
	manifest.Files[evidenceSourceName] = digestPointer(sourceBytes)
	manifest.State = "collecting"
	if manifest.Files[evidenceOutcomeName] != nil {
		manifest.State = "partial"
	}
	if err := writeManifest(bundle.path, manifest); err != nil {
		return errors.New("evidence-source-manifest-write-failed")
	}
	if err := writeNewEvidenceFile(bundle.path, evidenceRedactionName, redactionBytes); err != nil {
		manifest.State = "partial"
		_ = writeManifest(bundle.path, manifest)
		return errors.New("evidence-redaction-file-write-failed")
	}
	manifest.Files[evidenceRedactionName] = digestPointer(redactionBytes)
	if err := writeManifest(bundle.path, manifest); err != nil {
		return errors.New("evidence-redaction-manifest-write-failed")
	}
	return nil
}

func requesterExecutableSHA256(context json.RawMessage) string {
	var value struct {
		ExecutableSHA256 string `json:"executable_sha256"`
	}
	if json.Unmarshal(context, &value) != nil || !validSHA256(value.ExecutableSHA256) {
		return ""
	}
	return value.ExecutableSHA256
}

func clearSourceContextEvidence(source *sourceContextEvidence) {
	if source == nil {
		return
	}
	source.LocalRequest.Prompt = ""
	source.LocalRequest.ToolInput = ""
	source.LocalRequest.Evidence = ""
	source.OperationTargetSHA256 = ""
	if source.SelectedModelInput != nil {
		clearExternalInput(source.SelectedModelInput)
	}
	clear(source.RequesterContext)
	source.RequesterContext = nil
	source.GatekeeperProcess.Executable = ""
	source.GatekeeperProcess.ExecutableSHA256 = ""
	for index := range source.GatekeeperProcess.Arguments {
		source.GatekeeperProcess.Arguments[index] = ""
	}
	source.GatekeeperProcess.Arguments = nil
	source.GatekeeperProcess.CWD = ""
	for index := range source.Candidates {
		source.Candidates[index].Content = ""
		source.Candidates[index].Input = ""
		source.Candidates[index].Output = ""
		clear(source.Candidates[index].RawEvent)
		source.Candidates[index].RawEvent = nil
		source.Candidates[index].RawEventText = ""
	}
	for index := range source.ProcessEnvironment {
		source.ProcessEnvironment[index].Value = ""
	}
}

func (bundle *evidenceBundle) writeModelRequest(record modelRequestEvidence) error {
	primary := record
	primary.Variant = primaryVariantName
	if err := bundle.writeStage(evidenceRequestName, primary, "collecting", nil, nil); err != nil {
		return err
	}
	comparison := record
	comparison.Variant = comparisonVariantName
	return bundle.writeStage(evidenceComparisonRequestName, comparison, "collecting", nil, nil)
}

func (bundle *evidenceBundle) writeModelRequestVariant(name string, record modelRequestEvidence) error {
	if name != evidenceRequestName && name != evidenceComparisonRequestName {
		return errors.New("invalid model request evidence stage")
	}
	return bundle.writeStage(name, record, "collecting", nil, nil)
}

func (bundle *evidenceBundle) writeModelResponse(record modelResponseEvidence, redactions ...redactionEvent) error {
	now := time.Now().UTC()
	primary := record
	primary.Variant = primaryVariantName
	if err := bundle.writeStage(evidenceResponseName, primary, "model-finalized", &now, redactions); err != nil {
		return err
	}
	comparison := record
	comparison.Variant = comparisonVariantName
	return bundle.writeStage(evidenceComparisonResponseName, comparison, "model-finalized", &now, redactions)
}

func (bundle *evidenceBundle) writeModelResponseVariant(name string, record modelResponseEvidence, redactions ...redactionEvent) error {
	if name != evidenceResponseName && name != evidenceComparisonResponseName {
		return errors.New("invalid model response evidence stage")
	}
	now := time.Now().UTC()
	return bundle.writeStage(name, record, "model-finalized", &now, redactions)
}

func (bundle *evidenceBundle) appendRedactionEvents(events []redactionEvent) error {
	if bundle == nil || bundle.store == nil || len(events) == 0 {
		return nil
	}
	bundle.store.mu.Lock()
	defer bundle.store.mu.Unlock()
	return appendRedactions(bundle.path, bundle.evidenceID, events)
}

func (store *evidenceStore) writeHumanOutcome(outcome humanOutcome) error {
	if store == nil || !validHumanOutcome(outcome) {
		return humanOutcomeWriteFailure("human-outcome-invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	bundlePath, err := store.findBundleLocked(outcome.EvidenceID)
	if err != nil {
		return humanOutcomeWriteFailure("human-outcome-bundle-not-found")
	}
	manifest, err := readManifest(bundlePath)
	if err != nil || manifest.EvidenceID != outcome.EvidenceID {
		return humanOutcomeWriteFailure("human-outcome-manifest-conflict")
	}
	bytesValue, _, err := marshalEvidenceJSON(evidenceOutcomeName, outcome)
	if err != nil {
		return humanOutcomeWriteFailure("human-outcome-encode-failed")
	}
	defer clear(bytesValue)
	outcomePath := filepath.Join(bundlePath, evidenceOutcomeName)
	desiredDigest := digestValue(bytesValue)
	if existing := manifest.Files[evidenceOutcomeName]; existing != nil {
		// The Core and requester deliberately retry until they receive a durable
		// acknowledgement. Treat an exact replay as success while rejecting a
		// conflicting second human account of the same decision.
		if digest := fileSHA256(outcomePath); digest != "" && digest == *existing && digest == desiredDigest {
			if err := store.ensureHumanOutcomeIndexLocked(bundlePath, manifest, outcome); err != nil {
				return humanOutcomeWriteFailure("human-outcome-index-write-failed")
			}
			return nil
		}
		return humanOutcomeWriteFailure("human-outcome-conflict")
	}
	// Recover the narrow crash window after the immutable outcome file was
	// created but before the manifest replacement completed. Only the exact
	// expected bytes can repair that partial stage.
	if _, inspectErr := os.Lstat(outcomePath); inspectErr == nil {
		if fileSHA256(outcomePath) != desiredDigest {
			return humanOutcomeWriteFailure("human-outcome-file-conflict")
		}
	} else if !errors.Is(inspectErr, os.ErrNotExist) {
		return humanOutcomeWriteFailure("human-outcome-file-inspect-failed")
	} else if err := writeNewEvidenceFile(bundlePath, evidenceOutcomeName, bytesValue); err != nil {
		return humanOutcomeWriteFailure("human-outcome-file-write-failed")
	}
	manifest.Files[evidenceOutcomeName] = &desiredDigest
	now := outcome.ObservedAt.UTC()
	manifest.HumanFinalizedAt = &now
	manifest.State = "human-finalized"
	if !modelEvidenceComplete(manifest) {
		manifest.State = "partial"
	}
	if err := writeManifest(bundlePath, manifest); err != nil {
		return humanOutcomeWriteFailure("human-outcome-manifest-write-failed")
	}
	if err := store.ensureHumanOutcomeIndexLocked(bundlePath, manifest, outcome); err != nil {
		return humanOutcomeWriteFailure("human-outcome-index-write-failed")
	}
	return nil
}

func (store *evidenceStore) ensureHumanOutcomeIndexLocked(
	bundlePath string,
	manifest evidenceManifest,
	outcome humanOutcome,
) error {
	contents, err := readPrivateEvidenceFile(store.indexPath, 64*1024*1024)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	matching := 0
	for _, line := range bytes.Split(contents, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var record evidenceIndexRecord
		if json.Unmarshal(line, &record) != nil {
			clear(contents)
			return errors.New("evidence index contains invalid records")
		}
		if record.EvidenceID != outcome.EvidenceID || record.Phase != "human-outcome" {
			continue
		}
		matching++
		if record.AuthorizationSource != outcome.AuthorizationSource || record.HumanDecision != outcome.Decision ||
			record.BundlePath != bundlePath {
			clear(contents)
			return errors.New("human outcome index conflict")
		}
	}
	clear(contents)
	if matching == 1 {
		return nil
	}
	if matching > 1 {
		return errors.New("duplicate human outcome index records")
	}
	surface, operation, targetAlias := bundleIndexMetadata(bundlePath)
	return store.appendIndexLocked(evidenceIndexRecord{
		SchemaVersion: 1, RecordType: "beholder_evidence_index_event", ObservedAt: outcome.ObservedAt.UTC(),
		EvidenceID: outcome.EvidenceID, Phase: "human-outcome",
		Surface: surface, Operation: operation, TargetAlias: targetAlias,
		AuthorizationSource: outcome.AuthorizationSource, HumanDecision: outcome.Decision,
		BundlePath: bundlePath, State: manifest.State,
		ManifestSHA256: fileSHA256(filepath.Join(bundlePath, evidenceManifestName)),
	})
}

func digestValue(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func bundleIndexMetadata(bundlePath string) (string, string, string) {
	contents, err := readPrivateEvidenceFile(filepath.Join(bundlePath, evidenceSourceName), 64*1024*1024)
	if err != nil {
		manifest, manifestErr := readManifest(bundlePath)
		if manifestErr != nil {
			return "", "", ""
		}
		return manifest.Surface, manifest.Operation, manifest.TargetAlias
	}
	defer clear(contents)
	var source sourceContextEvidence
	if json.Unmarshal(contents, &source) != nil {
		return "", "", ""
	}
	return source.LocalRequest.ActualRequest.Surface,
		source.LocalRequest.ActualRequest.Operation,
		source.TargetAlias
}

func (store *evidenceStore) presence(evidenceID string) evidencePresence {
	if store == nil || !safeRecordLabel(evidenceID) {
		return evidencePresence{state: "unavailable"}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	bundlePath, err := store.findBundleLocked(evidenceID)
	if err != nil {
		return evidencePresence{state: "unavailable"}
	}
	manifest, err := readManifest(bundlePath)
	if err != nil || manifest.EvidenceID != evidenceID {
		return evidencePresence{state: "unavailable"}
	}
	return evidencePresence{
		state:              manifest.State,
		source:             manifest.Files[evidenceSourceName] != nil,
		request:            manifest.Files[evidenceRequestName] != nil,
		response:           manifest.Files[evidenceResponseName] != nil,
		comparisonRequest:  manifest.Files[evidenceComparisonRequestName] != nil,
		comparisonResponse: manifest.Files[evidenceComparisonResponseName] != nil,
		outcome:            manifest.Files[evidenceOutcomeName] != nil,
	}
}

func (bundle *evidenceBundle) writeStage(
	name string,
	value any,
	state string,
	finalizedAt *time.Time,
	extraRedactions []redactionEvent,
) error {
	if bundle == nil || bundle.store == nil {
		return errors.New("evidence bundle unavailable")
	}
	bundle.store.mu.Lock()
	defer bundle.store.mu.Unlock()
	encoded, redactions, err := marshalEvidenceJSON(name, value)
	if err != nil {
		return err
	}
	defer clear(encoded)
	manifest, err := readManifest(bundle.path)
	if err != nil || manifest.EvidenceID != bundle.evidenceID || manifest.Files[name] != nil {
		return errors.New("evidence manifest conflict")
	}
	if err := writeNewEvidenceFile(bundle.path, name, encoded); err != nil {
		return err
	}
	redactions = append(redactions, extraRedactions...)
	if len(redactions) > 0 {
		if err := appendRedactions(bundle.path, bundle.evidenceID, redactions); err != nil {
			return err
		}
	}
	manifest, err = readManifest(bundle.path)
	if err != nil || manifest.EvidenceID != bundle.evidenceID || manifest.Files[name] != nil {
		return errors.New("evidence manifest conflict")
	}
	manifest.Files[name] = digestPointer(encoded)
	manifest.State = state
	// A human outcome may arrive while the asynchronous model call is still
	// running. Preserve that earlier stage and mark the bundle fully correlated
	// once the model response lands, regardless of completion order.
	if manifest.Files[evidenceOutcomeName] != nil {
		if modelEvidenceComplete(manifest) {
			manifest.State = "human-finalized"
		} else {
			manifest.State = "partial"
		}
	} else if (name == evidenceResponseName || name == evidenceComparisonResponseName) && !modelEvidenceComplete(manifest) {
		manifest.State = "collecting"
	}
	if finalizedAt != nil && modelEvidenceComplete(manifest) {
		when := finalizedAt.UTC()
		manifest.ModelFinalizedAt = &when
	}
	if err := writeManifest(bundle.path, manifest); err != nil {
		return err
	}
	if name == evidenceResponseName || name == evidenceComparisonResponseName {
		response, _ := value.(modelResponseEvidence)
		errorCode := response.ParserError
		if errorCode == nil {
			errorCode = response.TransportError
		}
		modelCalled, modelUsed := response.ModelCalled, response.ModelUsed
		httpStatus, latencyMS := response.HTTPStatus, response.LatencyMS
		return bundle.store.appendIndexLocked(evidenceIndexRecord{
			SchemaVersion: 1, RecordType: "beholder_evidence_index_event", ObservedAt: time.Now().UTC(),
			EvidenceID: bundle.evidenceID, Phase: map[bool]string{true: "model-comparison", false: "model-decision"}[name == evidenceComparisonResponseName],
			Variant: response.Variant,
			Surface: bundle.surface, Operation: bundle.operation, TargetAlias: bundle.targetAlias,
			Decision: response.Decision, Reason: response.Reason, ErrorCode: errorCode,
			ModelCalled: &modelCalled, ModelUsed: &modelUsed, ResponseShape: response.ResponseShape,
			HTTPStatus: &httpStatus, LatencyMS: &latencyMS,
			BundlePath: bundle.path, State: manifest.State,
			ManifestSHA256: fileSHA256(filepath.Join(bundle.path, evidenceManifestName)),
		})
	}
	return nil
}

func modelEvidenceComplete(manifest evidenceManifest) bool {
	if manifest.Files[evidenceResponseName] == nil {
		return false
	}
	_, hasComparison := manifest.Files[evidenceComparisonResponseName]
	return !hasComparison || manifest.Files[evidenceComparisonResponseName] != nil
}

func marshalEvidenceJSON(source string, value any) ([]byte, []redactionEvent, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, nil, err
	}
	defer clear(raw)
	var generic any
	if json.Unmarshal(raw, &generic) != nil {
		return nil, nil, errors.New("evidence JSON build failed")
	}
	redactions := []redactionEvent{}
	preserveUpstreamRedactions(source, "$", "", &generic, &redactions)
	encoded, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	encoded = append(encoded, '\n')

	return encoded, redactions, nil
}

// preserveUpstreamRedactions records explicit redactions made at credential sources.
// It does not classify or rewrite the content of strings, object keys, or JSON.
func preserveUpstreamRedactions(source, path, key string, value *any, events *[]redactionEvent) {
	switch typed := (*value).(type) {
	case map[string]any:
		if redacted, _ := typed["redacted"].(bool); redacted {
			if text, ok := typed["value"].(string); ok {
				rule, _ := typed["redaction_rule"].(string)
				if rule == "" {
					rule = "source-redaction"
				}
				*events = append(*events, redactionEvent{Source: source, JSONPath: path + ".value", Rule: rule, ReplacementBytes: len(text)})
			}
		}
		keys := make([]string, 0, len(typed))
		for childKey := range typed {
			keys = append(keys, childKey)
		}
		sort.Strings(keys)
		for _, childKey := range keys {
			child := typed[childKey]
			preserveUpstreamRedactions(source, path+"."+childKey, childKey, &child, events)
		}
	case []any:
		for index, child := range typed {
			preserveUpstreamRedactions(source, fmt.Sprintf("%s[%d]", path, index), key, &child, events)
		}
	}
}

func appendRedactions(bundlePath, evidenceID string, additional []redactionEvent) error {
	path := filepath.Join(bundlePath, evidenceRedactionName)
	bytesValue, err := readPrivateEvidenceFile(path, 64*1024*1024)
	if err != nil {
		return err
	}
	defer clear(bytesValue)
	var record struct {
		SchemaVersion int              `json:"schema_version"`
		RecordType    string           `json:"record_type"`
		EvidenceID    string           `json:"evidence_id"`
		Events        []redactionEvent `json:"events"`
	}
	if json.Unmarshal(bytesValue, &record) != nil || record.EvidenceID != evidenceID {
		return errors.New("redaction record invalid")
	}
	record.Events = append(record.Events, additional...)
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	if err := atomicReplaceEvidenceFile(path, encoded); err != nil {
		return err
	}
	manifest, err := readManifest(bundlePath)
	if err != nil {
		return err
	}
	manifest.Files[evidenceRedactionName] = digestPointer(encoded)
	return writeManifest(bundlePath, manifest)
}

func validHumanOutcome(outcome humanOutcome) bool {
	if outcome.SchemaVersion != 1 || outcome.RecordType != "beholder_human_outcome" ||
		!safeRecordLabel(outcome.EvidenceID) || outcome.ObservedAt.IsZero() ||
		!validSHA256(outcome.OperationTargetSHA256) ||
		!oneOf(outcome.AuthorizationSource, "beholder-authoritative", "pwa-interactive", "remembered-grant", "local-fallback", "not-requested", "unknown") ||
		!oneOf(outcome.Decision, "approved", "rejected", "timed_out", "expired", "error", "not_requested", "unknown") ||
		(outcome.OneNodRequestID != nil && !safeOutcomeValue(*outcome.OneNodRequestID, 256)) ||
		!safeOutcomeValue(outcome.FailureStage, 96) || len(outcome.StatusTimeline) > 256 {
		return false
	}
	for _, entry := range outcome.StatusTimeline {
		if !safeOutcomeValue(entry.Status, 96) || entry.ObservedAt.IsZero() {
			return false
		}
	}
	encoded, err := json.Marshal(outcome)
	if err != nil {
		return false
	}
	defer clear(encoded)
	return true
}

func safeOutcomeValue(value string, maximum int) bool {
	if value == "" {
		return true
	}
	return len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")

}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func (store *evidenceStore) findBundleLocked(evidenceID string) (string, error) {
	if path := store.bundles[evidenceID]; path != "" {
		return path, nil
	}
	months, err := os.ReadDir(store.root)
	if err != nil {
		return "", err
	}
	for _, month := range months {
		if !month.IsDir() {
			continue
		}
		candidate := filepath.Join(store.root, month.Name(), evidenceID)
		if verifyPrivateDirectory(candidate) == nil {
			store.bundles[evidenceID] = candidate
			return candidate, nil
		}
	}
	return "", errors.New("evidence bundle not found")
}

func writeNewEvidenceFile(directory, name string, contents []byte) error {
	path := filepath.Join(directory, name)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("evidence stage already exists")
	}
	return atomicReplaceEvidenceFile(path, contents)
}

func atomicReplaceEvidenceFile(path string, contents []byte) error {
	directory := filepath.Dir(path)
	if verifyPrivateDirectory(directory) != nil {
		return errors.New("evidence parent invalid")
	}
	temporary, err := os.CreateTemp(directory, ".evidence-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o600) != nil {
		temporary.Close()
		return errors.New("set evidence file mode failed")
	}
	if _, err := temporary.Write(contents); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("write evidence file failed")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	return nil
}

func writeManifest(bundlePath string, manifest evidenceManifest) error {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	return atomicReplaceEvidenceFile(filepath.Join(bundlePath, evidenceManifestName), encoded)
}

func readManifest(bundlePath string) (evidenceManifest, error) {
	var manifest evidenceManifest
	contents, err := readPrivateEvidenceFile(filepath.Join(bundlePath, evidenceManifestName), 4*1024*1024)
	if err != nil {
		return manifest, err
	}
	defer clear(contents)
	if json.Unmarshal(contents, &manifest) != nil ||
		(manifest.SchemaVersion != 1 && manifest.SchemaVersion != evidenceManifestSchemaVersion) ||
		manifest.Files == nil {
		return evidenceManifest{}, errors.New("evidence manifest invalid")
	}
	return manifest, nil
}

func digestPointer(contents []byte) *string {
	digest := sha256.Sum256(contents)
	value := hex.EncodeToString(digest[:])
	return &value
}

func fileSHA256(path string) string {
	contents, err := readPrivateEvidenceFile(path, 64*1024*1024)
	if err != nil {
		return ""
	}
	defer clear(contents)
	return *digestPointer(contents)
}

func readPrivateEvidenceFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() < 0 || info.Size() > maximum {
		return nil, errors.New("evidence file identity mismatch")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("evidence file owner mismatch")
	}
	return os.ReadFile(path)
}

func rawBodyFields(body []byte) (int, string, string, json.RawMessage) {
	if len(body) == 0 {
		return 0, "", "", nil
	}
	digest := sha256.Sum256(body)
	encoded := base64.StdEncoding.EncodeToString(body)
	var parsed json.RawMessage
	if json.Valid(body) {
		parsed = append(json.RawMessage(nil), body...)
	}
	return len(body), hex.EncodeToString(digest[:]), encoded, parsed
}

func (store *evidenceStore) appendIndexLocked(record evidenceIndexRecord) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		clear(encoded)
		return errors.New("evidence index encoding failed")
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	return appendPrivateEvidenceLine(store.indexPath, encoded)
}

func (store *evidenceStore) recordOutcomeDelivery(evidenceID, result string, errorCode *string) error {
	if store == nil || !safeRecordLabel(evidenceID) || (result != "recorded" && result != "failed") ||
		(errorCode != nil && !safeReasonCode(*errorCode)) || (result == "recorded" && errorCode != nil) ||
		(result == "failed" && errorCode == nil) {
		return errors.New("invalid outcome delivery event")
	}
	encoded, err := json.Marshal(outcomeDeliveryEvent{
		SchemaVersion: 1, RecordType: "beholder_outcome_delivery_event",
		ObservedAt: time.Now().UTC(), EvidenceID: evidenceID, Result: result, ErrorCode: errorCode,
	})
	if err != nil {
		clear(encoded)
		return errors.New("outcome delivery event encoding failed")
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	store.mu.Lock()
	defer store.mu.Unlock()
	return appendPrivateEvidenceLine(store.outcomeEventsPath, encoded)
}

func appendPrivateEvidenceLine(path string, encoded []byte) error {
	flags := os.O_APPEND | os.O_WRONLY
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		flags |= os.O_CREATE | os.O_EXCL
	} else if err != nil {
		return err
	} else {
		info, inspectErr := os.Lstat(path)
		if inspectErr != nil {
			return inspectErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o600 || !ok || stat.Uid != uint32(os.Geteuid()) {
			return errors.New("evidence index identity mismatch")
		}
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	if file.Chmod(0o600) != nil {
		file.Close()
		return errors.New("set evidence index mode failed")
	}
	_, writeErr := file.Write(encoded)
	if syncErr := file.Sync(); writeErr == nil {
		writeErr = syncErr
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	return writeErr
}
