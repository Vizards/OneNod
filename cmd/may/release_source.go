package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

func defaultReleaseSource(client *http.Client) releaseSource {
	if client == nil {
		client = &http.Client{Timeout: releaseRequestTimeout}
	}
	safe := *client
	if safe.Timeout == 0 || safe.Timeout > releaseRequestTimeout {
		safe.Timeout = releaseRequestTimeout
	}
	safe.CheckRedirect = func(request *http.Request, _ []*http.Request) error {
		parsed := request.URL
		host := strings.ToLower(parsed.Hostname())
		if parsed.Scheme != "https" || parsed.User != nil ||
			(host != "api.github.com" && host != "github.com" &&
				!strings.HasSuffix(host, ".githubusercontent.com")) {
			return errors.New("GitHub release redirect left the trusted HTTPS hosts")
		}
		return nil
	}
	return &githubReleaseSource{
		client: &safe, latestURL: officialLatestReleaseAPI,
		official: true, releaseByTagURL: officialReleaseByTagAPI,
		releasesURL: officialReleasesAPI,
	}
}

func releaseSourceFor(deps dependencies) releaseSource {
	if deps.releases != nil {
		return deps.releases
	}
	return defaultReleaseSource(deps.httpClient)
}

func (source *githubReleaseSource) Latest(
	ctx context.Context,
	channel releaseChannel,
) (*verifiedRelease, error) {
	if source == nil || source.client == nil || source.latestURL == "" {
		return nil, errors.New("release source is unavailable")
	}
	if !validReleaseChannel(channel) {
		return nil, errors.New("release channel is invalid")
	}
	release, err := source.discoverLatestReleaseMetadata(ctx, channel)
	if err != nil {
		return nil, err
	}
	return source.verifyReleaseMetadata(ctx, release, channel, "")
}

func (source *githubReleaseSource) discoverLatestReleaseMetadata(
	ctx context.Context,
	channel releaseChannel,
) (githubReleaseMetadata, error) {
	if channel == releaseChannelStable {
		var release githubReleaseMetadata
		if err := source.readJSON(ctx, source.latestURL, maxManifestBytes, "application/vnd.github+json", &release); err != nil {
			return githubReleaseMetadata{}, fmt.Errorf("discover latest stable OneNod release: %w", err)
		}
		return release, nil
	}
	if source.releasesURL == "" {
		return githubReleaseMetadata{}, errors.New("release source cannot discover prerelease channels")
	}

	for page := 1; page <= maxReleaseDiscoveryPages; page++ {
		address, err := releaseDiscoveryPageURL(source.releasesURL, page)
		if err != nil {
			return githubReleaseMetadata{}, err
		}
		var releases []githubReleaseMetadata
		if err := source.readJSON(ctx, address, maxReleaseListBytes, "application/vnd.github+json", &releases); err != nil {
			return githubReleaseMetadata{}, fmt.Errorf("discover OneNod %s channel: %w", channel, err)
		}
		if len(releases) > 100 {
			return githubReleaseMetadata{}, errors.New("GitHub release discovery returned an oversized page")
		}
		candidate, candidateVersion := latestAcceptedReleaseMetadata(releases, channel)
		if candidateVersion != "" {
			return candidate, nil
		}
		if len(releases) < 100 {
			return githubReleaseMetadata{}, fmt.Errorf(
				"no published immutable OneNod release is available for the %s channel",
				channel,
			)
		}
	}
	return githubReleaseMetadata{}, errors.New("GitHub release discovery exceeded its page limit")
}

func releaseDiscoveryPageURL(address string, page int) (string, error) {
	parsed, err := url.Parse(address)
	if err != nil || page <= 0 {
		return "", errors.New("release discovery address is invalid")
	}
	query := parsed.Query()
	query.Set("page", strconv.Itoa(page))
	query.Set("per_page", "100")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (source *githubReleaseSource) Exact(
	ctx context.Context,
	version string,
) (*verifiedRelease, error) {
	if source == nil || source.client == nil || source.releaseByTagURL == "" {
		return nil, errors.New("release source cannot resolve an exact version")
	}
	if !validProductVersion(version) {
		return nil, errors.New("exact release version is invalid")
	}
	tag := "v" + version
	address := strings.TrimRight(source.releaseByTagURL, "/") + "/" + url.PathEscape(tag)
	var release githubReleaseMetadata
	if err := source.readJSON(
		ctx, address, maxManifestBytes, "application/vnd.github+json", &release,
	); err != nil {
		return nil, fmt.Errorf("resolve exact OneNod release %s: %w", version, err)
	}
	if release.Tag != tag {
		return nil, errors.New("exact OneNod release endpoint returned a different tag")
	}
	return source.verifyReleaseMetadata(
		ctx, release, releaseChannelForVersion(version), version,
	)
}

func (source *githubReleaseSource) verifyReleaseMetadata(
	ctx context.Context,
	release githubReleaseMetadata,
	channel releaseChannel,
	requestedVersion string,
) (*verifiedRelease, error) {
	if release.Draft || !release.Immutable {
		return nil, errors.New("selected OneNod release is not published and immutable")
	}
	if !validReleaseTag(release.Tag) {
		return nil, errors.New("selected OneNod release has an invalid product tag")
	}
	actualChannel := releaseChannelForVersion(strings.TrimPrefix(release.Tag, "v"))
	if release.Prerelease != (actualChannel != releaseChannelStable) ||
		!releaseChannelAccepts(channel, actualChannel) {
		return nil, errors.New("selected OneNod release channel metadata is inconsistent")
	}
	assets := make(map[string]releaseAsset, len(release.Assets))
	for _, asset := range release.Assets {
		if asset.Name == "" || asset.URL == "" || asset.Size <= 0 {
			return nil, errors.New("selected OneNod release contains invalid asset metadata")
		}
		if _, exists := assets[asset.Name]; exists {
			return nil, errors.New("selected OneNod release contains duplicate asset names")
		}
		assets[asset.Name] = releaseAsset{Name: asset.Name, Size: asset.Size, APIURL: asset.URL}
	}
	manifestAsset, ok := assets[releaseManifestAssetName]
	if !ok || manifestAsset.Size > maxManifestBytes {
		return nil, errors.New("immutable OneNod release is missing a bounded release manifest")
	}
	manifestBytes, err := source.readBytes(
		ctx, manifestAsset.APIURL, maxManifestBytes, "application/octet-stream",
	)
	if err != nil {
		return nil, fmt.Errorf("download OneNod release manifest: %w", err)
	}
	if int64(len(manifestBytes)) != manifestAsset.Size {
		return nil, errors.New("OneNod release manifest size does not match immutable asset metadata")
	}
	var manifest releaseManifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, errors.New("OneNod release manifest is invalid")
	}
	if err := ensureDecoderEOF(decoder); err != nil {
		return nil, errors.New("OneNod release manifest contains trailing data")
	}
	if err := validateReleaseManifest(manifest, release.Tag, assets); err != nil {
		return nil, err
	}
	if releaseChannel(manifest.Channel) != actualChannel {
		return nil, errors.New("OneNod release manifest channel differs from GitHub release metadata")
	}
	verified := &verifiedRelease{
		Assets: assets, Manifest: manifest, SelectedChannel: channel,
		RequestedVersion: requestedVersion, Tag: release.Tag, Source: source,
	}
	if source.official {
		if err := requireOfficialRepositoryID(); err != nil {
			return nil, err
		}
		if err := source.verifyOfficialRepositoryIdentity(ctx); err != nil {
			return nil, err
		}
		verified.RepositoryID = officialRepositoryID
		if err := source.verifyOfficialTagRef(ctx, release.Tag, manifest.Source.Commit); err != nil {
			return nil, err
		}
	}
	if source.official {
		provenanceAsset, ok := assets[provenanceBundleAssetName]
		if !ok || provenanceAsset.Size <= 0 || provenanceAsset.Size > maxAttestationBytes {
			return nil, errors.New("immutable OneNod release is missing its bounded provenance bundle")
		}
		encoded, err := source.readBytes(ctx, provenanceAsset.APIURL, maxAttestationBytes, "application/octet-stream")
		if err != nil {
			return nil, fmt.Errorf("download OneNod provenance bundle: %w", err)
		}
		if int64(len(encoded)) != provenanceAsset.Size {
			return nil, errors.New("OneNod provenance bundle size does not match immutable asset metadata")
		}
		verified.ProvenanceBundles, err = parseProvenanceBundles(encoded)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(manifestBytes)
		if err := source.verifyArtifactAttestation(
			ctx, verified, releaseManifestAssetName, digest[:], manifest.Source.Commit,
		); err != nil {
			return nil, fmt.Errorf("verify OneNod release manifest provenance: %w", err)
		}
	}
	return verified, nil
}

func selectLatestReleaseMetadata(
	releases []githubReleaseMetadata,
	channel releaseChannel,
) (githubReleaseMetadata, error) {
	if !validReleaseChannel(channel) {
		return githubReleaseMetadata{}, errors.New("release channel is invalid")
	}
	selected, selectedVersion := latestAcceptedReleaseMetadata(releases, channel)
	if selectedVersion == "" {
		return githubReleaseMetadata{}, fmt.Errorf(
			"no published immutable OneNod release is available for the %s channel",
			channel,
		)
	}
	return selected, nil
}

func latestAcceptedReleaseMetadata(
	releases []githubReleaseMetadata,
	channel releaseChannel,
) (githubReleaseMetadata, string) {
	var selected githubReleaseMetadata
	selectedVersion := ""
	for _, candidate := range releases {
		version := strings.TrimPrefix(candidate.Tag, "v")
		candidateChannel := releaseChannelForVersion(version)
		if candidate.Draft || !candidate.Immutable || !validProductVersion(version) ||
			candidate.Prerelease != (candidateChannel != releaseChannelStable) ||
			!releaseChannelAccepts(channel, candidateChannel) {
			continue
		}
		if selectedVersion == "" || compareProductVersions(version, selectedVersion) > 0 {
			selected = candidate
			selectedVersion = version
		}
	}
	return selected, selectedVersion
}

func requireOfficialRepositoryID() error {
	if officialRepositoryID == "" {
		return errors.New("official_repository_id_unset: pin the numeric Vizards/OneNod repository ID before publishing or consuming releases")
	}
	if parsePositiveInt64(officialRepositoryID) <= 0 {
		return errors.New("official_repository_id_invalid: pinned Vizards/OneNod repository ID is not a positive integer")
	}
	return nil
}

func (source *githubReleaseSource) verifyOfficialRepositoryIdentity(ctx context.Context) error {
	var repository struct {
		FullName string `json:"full_name"`
		ID       int64  `json:"id"`
		Owner    struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
		} `json:"owner"`
		Visibility string `json:"visibility"`
	}
	address := "https://api.github.com/repos/" + officialRepository
	if err := source.readJSON(ctx, address, maxManifestBytes, "application/vnd.github+json", &repository); err != nil {
		return fmt.Errorf("resolve official OneNod repository identity: %w", err)
	}
	if repository.FullName != officialRepository || repository.ID <= 0 ||
		strconv.FormatInt(repository.ID, 10) != officialRepositoryID ||
		repository.Owner.Login != "Vizards" || repository.Owner.ID != officialRepositoryOwnerID ||
		repository.Visibility != "public" {
		return errors.New("official OneNod repository identity is unexpected, recreated, or not public")
	}
	return nil
}

func (source *githubReleaseSource) verifyOfficialTagRef(
	ctx context.Context,
	tag string,
	commit string,
) error {
	var reference struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
		Ref string `json:"ref"`
	}
	address := "https://api.github.com/repos/" + officialRepository + "/git/ref/tags/" + url.PathEscape(tag)
	if err := source.readJSON(ctx, address, maxManifestBytes, "application/vnd.github+json", &reference); err != nil {
		return fmt.Errorf("resolve official OneNod release tag: %w", err)
	}
	if reference.Ref != "refs/tags/"+tag || reference.Object.Type != "commit" ||
		reference.Object.SHA != commit {
		return errors.New("official OneNod release tag is not bound to the attested source commit")
	}
	return nil
}

func parseProvenanceBundles(encoded []byte) ([]*bundle.Bundle, error) {
	if len(encoded) == 0 || len(encoded) > maxAttestationBytes {
		return nil, errors.New("OneNod provenance bundle is empty or oversized")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(encoded)))
	scanner.Buffer(make([]byte, 64*1024), maxAttestationBytes)
	var bundles []*bundle.Bundle
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var parsed bundle.Bundle
		if err := parsed.UnmarshalJSON([]byte(line)); err != nil {
			return nil, errors.New("OneNod provenance bundle contains invalid Sigstore JSON")
		}
		bundles = append(bundles, &parsed)
	}
	if err := scanner.Err(); err != nil || len(bundles) != 1 {
		return nil, errors.New("OneNod provenance bundle set is invalid")
	}
	return bundles, nil
}

func (source *githubReleaseSource) artifactVerifier() (*verify.Verifier, error) {
	source.verifierOnce.Do(func() {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		// Release verification must not inherit an untrusted proxy from the
		// invoking Agent's environment.
		transport.Proxy = nil
		client := &http.Client{
			Timeout: releaseRequestTimeout,
			Transport: exactHostTransport{
				base: transport,
				host: "tuf-repo-cdn.sigstore.dev",
			},
			CheckRedirect: func(request *http.Request, previous []*http.Request) error {
				if len(previous) >= 3 || request.URL.Scheme != "https" ||
					strings.ToLower(request.URL.Hostname()) != "tuf-repo-cdn.sigstore.dev" ||
					request.URL.User != nil {
					return errors.New("Sigstore TUF redirect left the pinned HTTPS origin")
				}
				return nil
			},
		}
		rootFetcher := fetcher.NewDefaultFetcher()
		rootFetcher.SetHTTPClient(client)
		options := tuf.DefaultOptions()
		// DefaultOptions supplies sigstore-go's embedded Public Good bootstrap
		// root. Release-controlled data cannot replace it.
		options.RepositoryBaseURL = sigstoreTUFRepository
		options.Fetcher = rootFetcher
		options.WithDisableLocalCache()
		trustedRoot, err := root.FetchTrustedRootWithOptions(options)
		if err != nil {
			source.verifierErr = fmt.Errorf("load Sigstore Public Good trusted root: %w", err)
			return
		}
		source.verifier, source.verifierErr = verify.NewVerifier(
			trustedRoot,
			verify.WithSignedCertificateTimestamps(1),
			verify.WithObserverTimestamps(1),
			verify.WithTransparencyLog(1),
		)
	})
	return source.verifier, source.verifierErr
}

type exactHostTransport struct {
	base http.RoundTripper
	host string
}

func (transport exactHostTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.URL.Scheme != "https" ||
		request.URL.User != nil || strings.ToLower(request.URL.Hostname()) != transport.host {
		return nil, errors.New("request left its pinned HTTPS origin")
	}
	return transport.base.RoundTrip(request)
}

func (source *githubReleaseSource) verifyArtifactAttestation(
	_ context.Context,
	release *verifiedRelease,
	artifactName string,
	digest []byte,
	releaseCommit string,
) error {
	if len(digest) != sha256.Size || release == nil || len(release.ProvenanceBundles) != 1 {
		return errors.New("verified provenance material is unavailable")
	}
	verifier, err := source.artifactVerifier()
	if err != nil {
		return err
	}
	if release.RepositoryID == "" || !commitPattern.MatchString(releaseCommit) {
		return errors.New("official repository identity is unavailable for provenance verification")
	}
	// The signed subject is the manifest itself, so its release source commit is
	// already covered by the artifact digest and is separately bound to the
	// immutable tag. A trusted manual retry intentionally has a newer workflow
	// commit, which the Fulcio certificate and SLSA predicate must agree on.
	digestHex := hex.EncodeToString(digest)
	for _, sourceRef := range []string{"refs/heads/main", "refs/tags/" + release.Tag} {
		expectedSAN := "https://github.com/" + officialRepository + "/" +
			officialReleaseWorkflow + "@" + sourceRef
		identity, identityErr := verify.NewShortCertificateIdentity(
			"https://token.actions.githubusercontent.com", "", expectedSAN, "",
		)
		if identityErr != nil {
			return errors.New("construct official OneNod attestation identity failed")
		}
		for _, candidate := range release.ProvenanceBundles {
			result, verifyErr := verifier.Verify(
				candidate,
				verify.NewPolicy(
					verify.WithArtifactDigest("sha256", digest),
					verify.WithCertificateIdentity(identity),
				),
			)
			if verifyErr != nil || result.Statement == nil || result.Signature == nil ||
				result.Signature.Certificate == nil {
				continue
			}
			workflowCommit, ok := officialWorkflowCommit(
				result.Signature.Certificate, release.RepositoryID, sourceRef, expectedSAN,
			)
			if !ok {
				continue
			}
			if result.Statement.GetPredicate() == nil ||
				result.Statement.GetType() != "https://in-toto.io/Statement/v1" ||
				result.Statement.GetPredicateType() != "https://slsa.dev/provenance/v1" ||
				!statementHasExactSubject(result.Statement.GetSubject(), artifactName, digestHex) ||
				!releaseProvenancePredicateMatches(
					result.Statement.GetPredicate().AsMap(), release.RepositoryID, workflowCommit, sourceRef,
				) {
				continue
			}
			return nil
		}
	}
	return errors.New("no cryptographically valid official provenance attestation matched the artifact")
}

func officialWorkflowCommit(
	summary *certificate.Summary,
	repositoryID string,
	sourceRef string,
	expectedSAN string,
) (string, bool) {
	if summary == nil {
		return "", false
	}
	workflowCommit := summary.SourceRepositoryDigest
	if !commitPattern.MatchString(workflowCommit) ||
		summary.SourceRepositoryURI != "https://github.com/"+officialRepository ||
		summary.SourceRepositoryRef != sourceRef ||
		summary.SourceRepositoryIdentifier != repositoryID ||
		summary.SourceRepositoryOwnerURI != "https://github.com/Vizards" ||
		summary.SourceRepositoryOwnerIdentifier != strconv.FormatInt(officialRepositoryOwnerID, 10) ||
		summary.SourceRepositoryVisibilityAtSigning != "public" ||
		summary.BuildConfigURI != expectedSAN ||
		summary.BuildConfigDigest != workflowCommit ||
		summary.BuildSignerURI != expectedSAN ||
		summary.BuildSignerDigest != workflowCommit ||
		summary.RunnerEnvironment != "github-hosted" ||
		!validReleaseAttestationTrigger(summary.BuildTrigger, sourceRef) {
		return "", false
	}
	return workflowCommit, true
}

func validReleaseAttestationTrigger(trigger, sourceRef string) bool {
	if sourceRef == "refs/heads/main" {
		return trigger == "push" || trigger == "workflow_dispatch"
	}
	return trigger == "workflow_dispatch"
}

func statementHasExactSubject(subjects []*in_toto.ResourceDescriptor, name, digest string) bool {
	return len(subjects) == 1 && subjects[0] != nil &&
		subjects[0].GetName() == name && len(subjects[0].GetDigest()) == 1 &&
		subjects[0].GetDigest()["sha256"] == digest
}

func releaseProvenancePredicateMatches(
	predicate map[string]any,
	repositoryID string,
	commit string,
	sourceRef string,
) bool {
	buildDefinition, ok := recordValue(predicate["buildDefinition"])
	if !ok || stringValue(buildDefinition["buildType"]) !=
		"https://actions.github.io/buildtypes/workflow/v1" {
		return false
	}
	external, ok := recordValue(buildDefinition["externalParameters"])
	if !ok {
		return false
	}
	workflow, ok := recordValue(external["workflow"])
	if !ok || stringValue(workflow["repository"]) != "https://github.com/"+officialRepository ||
		stringValue(workflow["path"]) != officialReleaseWorkflow ||
		stringValue(workflow["ref"]) != sourceRef {
		return false
	}
	internal, ok := recordValue(buildDefinition["internalParameters"])
	if !ok {
		return false
	}
	github, ok := recordValue(internal["github"])
	if !ok || !identifierMatches(github["repository_id"], repositoryID) ||
		!identifierMatches(github["repository_owner_id"], strconv.FormatInt(officialRepositoryOwnerID, 10)) ||
		stringValue(github["runner_environment"]) != "github-hosted" ||
		!validReleaseAttestationTrigger(stringValue(github["event_name"]), sourceRef) {
		return false
	}
	resolved, ok := buildDefinition["resolvedDependencies"].([]any)
	if !ok || len(resolved) != 1 {
		return false
	}
	expectedDependencyURI := "git+https://github.com/" + officialRepository + "@" + sourceRef
	dependency, ok := recordValue(resolved[0])
	if !ok || stringValue(dependency["uri"]) != expectedDependencyURI {
		return false
	}
	digests, ok := recordValue(dependency["digest"])
	if !ok || len(digests) != 1 || stringValue(digests["gitCommit"]) != commit {
		return false
	}
	runDetails, ok := recordValue(predicate["runDetails"])
	if !ok {
		return false
	}
	builder, ok := recordValue(runDetails["builder"])
	expectedBuilder := "https://github.com/" + officialRepository + "/" +
		officialReleaseWorkflow + "@" + sourceRef
	if !ok || stringValue(builder["id"]) != expectedBuilder {
		return false
	}
	metadata, ok := recordValue(runDetails["metadata"])
	invocation := stringValue(metadata["invocationId"])
	return ok && strings.HasPrefix(invocation, "https://github.com/"+officialRepository+"/actions/runs/") &&
		strings.Contains(invocation, "/attempts/")
}

func recordValue(value any) (map[string]any, bool) {
	record, ok := value.(map[string]any)
	return record, ok
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func identifierMatches(value any, expected string) bool {
	switch typed := value.(type) {
	case string:
		return typed == expected
	case float64:
		return typed == float64(parsePositiveInt64(expected))
	default:
		return false
	}
}

func parsePositiveInt64(value string) int64 {
	parsed, _ := strconv.ParseInt(value, 10, 64)
	return parsed
}

func (source *githubReleaseSource) readJSON(
	ctx context.Context,
	address string,
	limit int64,
	accept string,
	result any,
) error {
	encoded, err := source.readBytes(ctx, address, limit, accept)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	if err := decoder.Decode(result); err != nil {
		return errors.New("GitHub release endpoint returned invalid JSON")
	}
	if err := ensureDecoderEOF(decoder); err != nil {
		return errors.New("GitHub release endpoint returned trailing JSON")
	}
	return nil
}

func ensureDecoderEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func (source *githubReleaseSource) readBytes(
	ctx context.Context,
	address string,
	limit int64,
	accept string,
) ([]byte, error) {
	if err := source.validateAddress(address); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, errors.New("build GitHub release request failed")
	}
	request.Header.Set("accept", accept)
	request.Header.Set("x-github-api-version", "2026-03-10")
	response, err := source.client.Do(request)
	if err != nil {
		return nil, errors.New("GitHub release request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, githubHTTPStatusError("release endpoint", response)
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(encoded)) > limit {
		return nil, errors.New("GitHub release response exceeded its size limit")
	}
	return encoded, nil
}

func (source *githubReleaseSource) validateAddress(address string) error {
	if !source.official {
		return nil
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil {
		return errors.New("GitHub release endpoint is not HTTPS")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "api.github.com" && host != "github.com" &&
		!strings.HasSuffix(host, ".githubusercontent.com") {
		return errors.New("GitHub release endpoint has an unexpected host")
	}
	return nil
}

func (source *githubReleaseSource) Download(
	ctx context.Context,
	release *verifiedRelease,
	artifact releaseArtifact,
) ([]byte, error) {
	asset, ok := release.Assets[artifact.Name]
	if !ok || asset.Size != artifact.Size || artifact.Size <= 0 ||
		artifact.Size > maxReleaseArtifactBytes {
		return nil, errors.New("release artifact metadata does not match the immutable Release")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.APIURL, nil)
	if err != nil {
		return nil, errors.New("build release artifact request failed")
	}
	if err := source.validateAddress(asset.APIURL); err != nil {
		return nil, err
	}
	request.Header.Set("accept", "application/octet-stream")
	response, err := source.client.Do(request)
	if err != nil {
		return nil, errors.New("release artifact download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, githubHTTPStatusError("release artifact endpoint", response)
	}
	var snapshot bytes.Buffer
	snapshot.Grow(int(artifact.Size))
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(&snapshot, hash), io.LimitReader(response.Body, artifact.Size+1))
	if copyErr != nil || written != artifact.Size {
		return nil, errors.New("release artifact size verification failed")
	}
	digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if digest != artifact.SHA256 {
		return nil, errors.New("release artifact SHA-256 verification failed")
	}
	// Artifact authenticity is inherited from the single, verified
	// release-manifest.json subject. Each downloaded byte stream is checked
	// against the manifest's exact immutable asset name, size, and SHA-256.
	return snapshot.Bytes(), nil
}

func githubHTTPStatusError(endpoint string, response *http.Response) error {
	if response == nil {
		return fmt.Errorf("GitHub %s returned no response", endpoint)
	}
	remaining := strings.TrimSpace(response.Header.Get("X-RateLimit-Remaining"))
	reset := strings.TrimSpace(response.Header.Get("X-RateLimit-Reset"))
	if remaining == "0" || ((response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests) && reset != "") {
		resetDescription := "at an unknown time"
		if seconds, err := strconv.ParseInt(reset, 10, 64); err == nil && seconds > 0 {
			resetDescription = time.Unix(seconds, 0).UTC().Format(time.RFC3339)
		}
		limit := strings.TrimSpace(response.Header.Get("X-RateLimit-Limit"))
		limitDescription := ""
		if limit != "" {
			limitDescription = "; limit " + limit
		}
		return fmt.Errorf(
			"GitHub %s hit the API rate limit (HTTP %d; remaining 0%s; resets %s); retry after the reset time",
			endpoint, response.StatusCode, limitDescription, resetDescription,
		)
	}
	if retryAfter := strings.TrimSpace(response.Header.Get("Retry-After")); response.StatusCode == http.StatusTooManyRequests && retryAfter != "" {
		return fmt.Errorf(
			"GitHub %s returned HTTP %d; retry after %s",
			endpoint, response.StatusCode, retryAfter,
		)
	}
	return fmt.Errorf("GitHub %s returned HTTP %d", endpoint, response.StatusCode)
}
