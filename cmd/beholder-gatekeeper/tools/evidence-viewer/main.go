package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"time"
)

var (
	defaultEvidenceRoot       = defaultUserPath("Library", "Application Support", "Beholder", "evidence", "v1")
	defaultDecisionRecordRoot = defaultUserPath("Library", "Application Support", "Beholder", "records")
)

var evidenceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{7,95}$`)

var productVersion = "development"
var sourceCommit = "unknown"
var releaseTag = ""

type manifest struct {
	SchemaVersion        int                `json:"schema_version"`
	RecordType           string             `json:"record_type"`
	EvidenceID           string             `json:"evidence_id"`
	State                string             `json:"state"`
	CreatedAt            time.Time          `json:"created_at"`
	GatekeeperVersion    string             `json:"gatekeeper_version"`
	PolicySHA256         string             `json:"policy_sha256"`
	Files                map[string]*string `json:"files"`
	SecretMaterialStored bool               `json:"secret_material_stored"`
}

var evidenceStageNames = []string{
	"01-source-context.json",
	"02-model-request.json",
	"03-model-response.json",
	"04-human-outcome.json",
	"redactions.json",
}

var dualShadowEvidenceStageNames = []string{
	"01-source-context.json",
	"02-model-request.json",
	"03-model-response.json",
	"04-human-outcome.json",
	"05-model-request-thinking-disabled.json",
	"06-model-response-thinking-disabled.json",
	"redactions.json",
}

var authoritativeDogfoodEvidenceStageNames = []string{
	"01-source-context.json",
	"02-model-request.json",
	"03-model-response.json",
	"04-human-outcome.json",
	"05-model-request-thinking-enabled.json",
	"06-model-response-thinking-enabled.json",
	"redactions.json",
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--identity" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schema_version": 1, "component": "beholder-evidence", "product_version": productVersion,
			"source_commit": sourceCommit, "release_tag": releaseTag,
		})
		return
	}
	root := flag.String("root", defaultEvidenceRoot, "absolute E2-OBS-2 evidence root")
	recordRoot := flag.String("record-root", defaultDecisionRecordRoot, "private Gatekeeper decision-record directory used by audit")
	flag.Parse()
	if !filepath.IsAbs(*root) || filepath.Clean(*root) != *root || verifyDirectory(*root) != nil {
		fatal("invalid evidence root")
	}
	arguments := flag.Args()
	if len(arguments) == 0 {
		fatal("usage: beholder-evidence [--root path] list|show|diff|verify|audit [evidence-id ...]")
	}
	var err error
	switch arguments[0] {
	case "list":
		if len(arguments) != 1 {
			fatal("list takes no evidence id")
		}
		err = listEvidence(*root, os.Stdout)
	case "show":
		if len(arguments) != 2 {
			fatal("show requires one evidence id")
		}
		err = showEvidence(*root, arguments[1], os.Stdout)
	case "verify":
		if len(arguments) != 2 {
			fatal("verify requires one evidence id")
		}
		err = verifyEvidence(*root, arguments[1], os.Stdout)
	case "diff":
		if len(arguments) != 3 {
			fatal("diff requires two evidence ids")
		}
		err = diffEvidence(*root, arguments[1], arguments[2], os.Stdout)
	case "audit":
		if len(arguments) != 1 {
			fatal("audit takes no evidence id")
		}
		err = auditEvidenceWithRecordRoot(*root, *recordRoot, os.Stdout)
	default:
		fatal("unknown evidence command")
	}
	if err != nil {
		fatal(err.Error())
	}
}

func listEvidence(root string, output io.Writer) error {
	path := filepath.Join(root, "index.jsonl")
	contents, err := readPrivateFile(path, 64*1024*1024)
	if errors.Is(err, os.ErrNotExist) {
		_, err = fmt.Fprintln(output, "[]")
		return err
	}
	if err != nil {
		return err
	}
	defer clear(contents)
	lines := make([]json.RawMessage, 0)
	for _, line := range splitLines(contents) {
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return errors.New("evidence index contains invalid JSON")
		}
		lines = append(lines, append(json.RawMessage(nil), line...))
	}
	return writeJSON(output, lines)
}

func showEvidence(root, evidenceID string, output io.Writer) error {
	bundle, manifestValue, err := loadManifest(root, evidenceID)
	if err != nil {
		return err
	}
	files := map[string]json.RawMessage{}
	names := make([]string, 0, len(manifestValue.Files)+1)
	names = append(names, "manifest.json")
	for name, digest := range manifestValue.Files {
		if digest != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		contents, err := readPrivateFile(filepath.Join(bundle, name), 64*1024*1024)
		if err != nil {
			return err
		}
		if !json.Valid(contents) {
			clear(contents)
			return fmt.Errorf("%s is not valid JSON", name)
		}
		files[name] = append(json.RawMessage(nil), contents...)
		clear(contents)
	}
	return writeJSON(output, map[string]any{
		"schema_version": 1, "record_type": "beholder_evidence_view",
		"evidence_id": evidenceID, "bundle_path": bundle, "files": files,
	})
}

func verifyEvidence(root, evidenceID string, output io.Writer) error {
	index, err := loadIndex(root)
	if err != nil {
		return err
	}
	inspection := inspectBundle(root, evidenceID, index)
	if err := writeJSON(output, inspection); err != nil {
		return err
	}
	if !inspection.Valid {
		return errors.New("evidence verification failed")
	}
	return nil
}

func diffEvidence(root, leftID, rightID string, output io.Writer) error {
	_, left, err := loadManifest(root, leftID)
	if err != nil {
		return err
	}
	_, right, err := loadManifest(root, rightID)
	if err != nil {
		return err
	}
	namesMap := map[string]bool{}
	for name := range left.Files {
		namesMap[name] = true
	}
	for name := range right.Files {
		namesMap[name] = true
	}
	names := make([]string, 0, len(namesMap))
	for name := range namesMap {
		names = append(names, name)
	}
	sort.Strings(names)
	type comparison struct {
		Name        string  `json:"name"`
		LeftSHA256  *string `json:"left_sha256"`
		RightSHA256 *string `json:"right_sha256"`
		Equal       bool    `json:"equal"`
	}
	comparisons := make([]comparison, 0, len(names))
	for _, name := range names {
		leftDigest := left.Files[name]
		rightDigest := right.Files[name]
		comparisons = append(comparisons, comparison{
			Name: name, LeftSHA256: leftDigest, RightSHA256: rightDigest,
			Equal: leftDigest != nil && rightDigest != nil && *leftDigest == *rightDigest,
		})
	}
	leftFacts, err := semanticFacts(root, leftID)
	if err != nil {
		return err
	}
	rightFacts, err := semanticFacts(root, rightID)
	if err != nil {
		return err
	}
	return writeJSON(output, map[string]any{
		"schema_version": 1, "record_type": "beholder_evidence_diff",
		"left_evidence_id": leftID, "right_evidence_id": rightID, "files": comparisons,
		"semantic": semanticComparisons(leftFacts, rightFacts),
	})
}

func loadManifest(root, evidenceID string) (string, manifest, error) {
	var result manifest
	if !evidenceIDPattern.MatchString(evidenceID) {
		return "", result, errors.New("invalid evidence id")
	}
	months, err := os.ReadDir(root)
	if err != nil {
		return "", result, err
	}
	found := ""
	for _, month := range months {
		if !month.IsDir() {
			continue
		}
		candidate := filepath.Join(root, month.Name(), evidenceID)
		if verifyDirectory(candidate) == nil {
			if found != "" {
				return "", result, errors.New("evidence id is not unique")
			}
			found = candidate
		}
	}
	if found == "" {
		return "", result, errors.New("evidence id not found")
	}
	contents, err := readPrivateFile(filepath.Join(found, "manifest.json"), 4*1024*1024)
	if err != nil {
		return "", result, err
	}
	defer clear(contents)
	if json.Unmarshal(contents, &result) != nil || !validManifest(result, evidenceID) {
		return "", manifest{}, errors.New("invalid evidence manifest")
	}
	return found, result, nil
}

func validManifest(value manifest, evidenceID string) bool {
	stageNames := evidenceStageNames
	dualShadow := dualShadowVersion(value.GatekeeperVersion)
	if authoritativeDogfoodVersion(value.GatekeeperVersion) {
		stageNames = authoritativeDogfoodEvidenceStageNames
	} else if dualShadow {
		stageNames = dualShadowEvidenceStageNames
	}
	validSchema := (!dualShadow && value.SchemaVersion == 1) || (dualShadow && value.SchemaVersion == 2)
	if !validSchema || value.RecordType != "beholder_decision_evidence_manifest" ||
		value.EvidenceID != evidenceID || value.SecretMaterialStored || len(value.Files) != len(stageNames) {
		return false
	}
	if value.State != "reserved" && value.State != "collecting" && value.State != "model-finalized" &&
		value.State != "human-finalized" && value.State != "partial" {
		return false
	}
	for _, name := range stageNames {
		digest, found := value.Files[name]
		if !found || (digest != nil && !validSHA256(*digest)) {
			return false
		}
	}
	if value.State != "partial" && value.State != "reserved" &&
		(value.Files["01-source-context.json"] == nil || value.Files["redactions.json"] == nil) {
		return false
	}
	if value.State == "reserved" {
		for _, digest := range value.Files {
			if digest != nil {
				return false
			}
		}
	}
	if value.State == "model-finalized" &&
		(value.Files["02-model-request.json"] == nil || value.Files["03-model-response.json"] == nil) {
		return false
	}
	if dualShadow && (value.State == "model-finalized" || value.State == "human-finalized") {
		comparisonRequestName, comparisonResponseName := comparisonStageNames(value.GatekeeperVersion)
		if value.Files[comparisonRequestName] == nil || value.Files[comparisonResponseName] == nil {
			return false
		}
	}
	if value.State == "human-finalized" &&
		(value.Files["02-model-request.json"] == nil || value.Files["03-model-response.json"] == nil ||
			value.Files["04-human-outcome.json"] == nil) {
		return false
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func verifyDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("private directory identity mismatch")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("private directory owner mismatch")
	}
	return nil
}

func readPrivateFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() < 0 || info.Size() > maximum {
		return nil, errors.New("private evidence file identity mismatch")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("private evidence file owner mismatch")
	}
	return os.ReadFile(path)
}

func digestPrivateFile(path string) (string, error) {
	contents, err := readPrivateFile(path, 64*1024*1024)
	if err != nil {
		return "", err
	}
	defer clear(contents)
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:]), nil
}

func splitLines(contents []byte) [][]byte {
	result := make([][]byte, 0)
	start := 0
	for index, value := range contents {
		if value == '\n' {
			result = append(result, contents[start:index])
			start = index + 1
		}
	}
	if start < len(contents) {
		result = append(result, contents[start:])
	}
	return result
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}

func defaultUserPath(parts ...string) string {
	homeDirectory, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(homeDirectory) {
		return ""
	}
	return filepath.Join(append([]string{homeDirectory}, parts...)...)
}
