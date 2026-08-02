package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"golang.org/x/mod/semver"
)

const (
	officialRepository        = "Vizards/OneNod"
	officialReleaseWorkflow   = ".github/workflows/release.yml"
	officialRepositoryOwnerID = 13443193
	// This immutable numeric ID pins the repository identity even if the
	// human-readable owner/name is ever deleted and recreated. Never discover
	// and trust this value dynamically at runtime.
	officialRepositoryID      = "1318524698"
	officialLatestReleaseAPI  = "https://api.github.com/repos/Vizards/OneNod/releases/latest"
	officialReleasesAPI       = "https://api.github.com/repos/Vizards/OneNod/releases?per_page=100"
	officialReleaseByTagAPI   = "https://api.github.com/repos/Vizards/OneNod/releases/tags/"
	releaseManifestAssetName  = "release-manifest.json"
	provenanceBundleAssetName = "onenod-provenance.intoto.jsonl"
	localReceiptSchema        = 2
	initializerReceiptSchema  = 1
	manifestSchema            = 1
	mayClientProtocol         = 1
	maxManifestBytes          = 1 << 20
	maxReleaseListBytes       = 4 << 20
	maxReleaseDiscoveryPages  = 100
	maxReleaseArtifactBytes   = 256 << 20
	maxAttestationBytes       = 32 << 20
	releaseRequestTimeout     = 30 * time.Second
	sigstoreTUFRepository     = "https://tuf-repo-cdn.sigstore.dev"
	maxSafeVersionInteger     = uint64(9_007_199_254_740_991)
)

var (
	productVersion       = "0.0.0-dev"
	sourceCommit         = "unknown"
	releaseTag           = "dev"
	semverPattern        = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	productSemverPattern = regexp.MustCompile(
		`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(alpha|beta)\.([1-9][0-9]*))?$`,
	)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type releaseChannel string

const (
	releaseChannelStable releaseChannel = "stable"
	releaseChannelBeta   releaseChannel = "beta"
	releaseChannelAlpha  releaseChannel = "alpha"
)

type releaseSelection struct {
	Channel releaseChannel
	Version string
}

type versionRange struct {
	MaximumExclusive string `json:"maximum_exclusive"`
	Minimum          string `json:"minimum"`
}

type protocolRange struct {
	Maximum int `json:"max"`
	Minimum int `json:"min"`
}

type releaseManifest struct {
	Artifacts    []releaseArtifact `json:"artifacts"`
	Attestations struct {
		Issuer     string `json:"issuer"`
		Repository string `json:"repository"`
		Workflow   string `json:"workflow"`
	} `json:"attestations"`
	Channel    string `json:"channel"`
	Components struct {
		Executor struct {
			AcceptedGatewayProtocol protocolRange `json:"accepted_gateway_protocol"`
			StateSchema             int           `json:"state_schema"`
			Version                 string        `json:"version"`
		} `json:"executor"`
		Gateway struct {
			AcceptedClientProtocol protocolRange `json:"accepted_client_protocol"`
			StateSchema            int           `json:"state_schema"`
			Version                string        `json:"version"`
		} `json:"gateway"`
		KeychainHelper struct {
			HelperProtocol protocolRange `json:"helper_protocol"`
			SourceDigest   string        `json:"source_digest"`
			Version        string        `json:"version"`
		} `json:"keychain_helper"`
		May struct {
			ClientProtocol int    `json:"client_protocol"`
			Version        string `json:"version"`
		} `json:"may"`
		PWA struct {
			Version string `json:"version"`
		} `json:"pwa"`
		Skill struct {
			Version string `json:"version"`
		} `json:"skill"`
		SSHAgent struct {
			Version string `json:"version"`
		} `json:"ssh_agent"`
	} `json:"components"`
	PublishedAt    string `json:"published_at"`
	ProductLabel   string `json:"product_label"`
	ReleaseVersion string `json:"release_version"`
	Requirements   struct {
		MacOS struct {
			Architectures []string `json:"architectures"`
			Minimum       string   `json:"minimum"`
		} `json:"macos"`
		Node               versionRange `json:"node"`
		OnePasswordCLI     versionRange `json:"onepassword_cli"`
		OnePasswordRegions []string     `json:"onepassword_regions"`
		Wrangler           versionRange `json:"wrangler"`
	} `json:"requirements"`
	RevokedArtifactDigests []string `json:"revoked_artifact_digests"`
	SchemaVersion          int      `json:"schema_version"`
	Source                 struct {
		Commit     string `json:"commit"`
		Repository string `json:"repository"`
		Workflow   string `json:"workflow"`
	} `json:"source"`
	Support struct {
		LatestOnly             bool   `json:"latest_only"`
		MinimumSafeVersion     string `json:"minimum_safe_version"`
		PreviousReleaseVersion string `json:"previous_release_version"`
	} `json:"support"`
	Tag     string `json:"tag"`
	Upgrade struct {
		MinimumSafeVersion     string   `json:"minimum_safe_version"`
		MinimumUpdaterVersion  string   `json:"minimum_updater_version"`
		Order                  []string `json:"order"`
		RemoteRollbackSafe     bool     `json:"remote_rollback_safe"`
		RevokedArtifactDigests []string `json:"revoked_artifact_digests"`
	} `json:"upgrade"`
}

type releaseArtifact struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Platform *struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	} `json:"platform,omitempty"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Subject string `json:"subject,omitempty"`
}

type releaseArtifactContract struct {
	Architecture string
	Kind         string
	OS           string
	Subject      string
}

type releaseAsset struct {
	APIURL string
	Name   string
	Size   int64
}

type verifiedRelease struct {
	Assets            map[string]releaseAsset
	Manifest          releaseManifest
	ProvenanceBundles []*bundle.Bundle
	RepositoryID      string
	RequestedVersion  string
	SelectedChannel   releaseChannel
	Tag               string
	Source            releaseSource
}

type releaseSource interface {
	Latest(context.Context, releaseChannel) (*verifiedRelease, error)
	Exact(context.Context, string) (*verifiedRelease, error)
	Download(context.Context, *verifiedRelease, releaseArtifact, string) error
}

type githubReleaseSource struct {
	client          *http.Client
	latestURL       string
	official        bool
	releaseByTagURL string
	releasesURL     string
	verifierOnce    sync.Once
	verifier        *verify.Verifier
	verifierErr     error
}

type localInstallReceipt struct {
	Artifacts map[string]string `json:"artifacts"`
	Channel   string            `json:"channel"`
	Files     map[string]string `json:"files"`
	Helper    struct {
		Artifact     string `json:"artifact"`
		ArtifactSHA  string `json:"artifact_sha256"`
		BinarySHA256 string `json:"binary_sha256"`
		Protocol     int    `json:"protocol"`
		SourceDigest string `json:"source_digest"`
		Version      string `json:"version"`
	} `json:"helper"`
	Skill struct {
		AdoptedBackups []string `json:"adopted_backups"`
		Artifact       string   `json:"artifact"`
		ArtifactSHA    string   `json:"artifact_sha256"`
		Discovery      []string `json:"discovery"`
		TreeSHA256     string   `json:"tree_sha256"`
		Version        string   `json:"version"`
	} `json:"skill"`
	InstalledAt    string `json:"installed_at"`
	Origin         string `json:"origin"`
	ReleaseVersion string `json:"release_version"`
	SchemaVersion  int    `json:"schema_version"`
	SourceCommit   string `json:"source_commit"`
}

type initializerInstallReceipt struct {
	AdoptedBackups []string          `json:"adopted_backups"`
	Artifacts      map[string]string `json:"artifacts"`
	Channel        string            `json:"channel"`
	Files          map[string]string `json:"files"`
	HelperProtocol int               `json:"helper_protocol"`
	HelperVersion  string            `json:"helper_version"`
	InstalledAt    string            `json:"installed_at"`
	ReleaseVersion string            `json:"release_version"`
	SchemaVersion  int               `json:"schema_version"`
	SkillTreeSHA   string            `json:"skill_tree_sha256"`
	SourceCommit   string            `json:"source_commit"`
}

type runtimeVersion struct {
	AcceptedClientProtocol protocolRange `json:"accepted_client_protocol,omitempty"`
	Channel                string        `json:"channel,omitempty"`
	ExecutorVersion        string        `json:"executor_version,omitempty"`
	GatewayProtocol        int           `json:"gateway_protocol,omitempty"`
	GatewayVersion         string        `json:"gateway_version,omitempty"`
	PwaVersion             string        `json:"pwa_version,omitempty"`
}

type deploymentBundleDescriptor struct {
	Executor struct {
		Config     string `json:"config"`
		Entrypoint string `json:"entrypoint"`
		Plugin     string `json:"plugin"`
	} `json:"executor"`
	Gateway struct {
		Assets     string `json:"assets"`
		Config     string `json:"config"`
		Entrypoint string `json:"entrypoint"`
	} `json:"gateway"`
	ReleaseVersion string   `json:"release_version"`
	SchemaVersion  int      `json:"schema_version"`
	SourceCommit   string   `json:"source_commit"`
	TemplateTokens []string `json:"template_tokens"`
}

type deploymentReleaseMetadata struct {
	ArtifactKind   string `json:"artifact_kind"`
	Repository     string `json:"repository"`
	ReleaseVersion string `json:"release_version"`
	SchemaVersion  int    `json:"schema_version"`
	SourceCommit   string `json:"source_commit"`
}

type stagedDeploymentBundle struct {
	Artifact   releaseArtifact
	Descriptor deploymentBundleDescriptor
	Root       string
	Stage      string
}

type updateCheckReport struct {
	Assurance          string         `json:"assurance"`
	Channel            string         `json:"channel"`
	CurrentChannel     string         `json:"current_channel,omitempty"`
	CurrentVersion     string         `json:"current_version,omitempty"`
	LatestVersion      string         `json:"latest_version"`
	MinimumSafeVersion string         `json:"minimum_safe_version"`
	Origin             string         `json:"origin,omitempty"`
	Platform           hostPlatform   `json:"platform"`
	Plan               []string       `json:"plan"`
	RequestedVersion   string         `json:"requested_version,omitempty"`
	Remote             runtimeVersion `json:"remote"`
	Status             string         `json:"status"`
	Warnings           []string       `json:"warnings"`
}

type keychainHelperUpdatePlan struct {
	CurrentProtocol     int
	CurrentSourceDigest string
	CurrentVersion      string
	Replace             bool
	TargetProtocol      protocolRange
	TargetSourceDigest  string
	TargetVersion       string
}

type githubReleaseMetadata struct {
	Assets []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		URL  string `json:"url"`
	} `json:"assets"`
	Draft      bool   `json:"draft"`
	Immutable  bool   `json:"immutable"`
	Prerelease bool   `json:"prerelease"`
	Tag        string `json:"tag_name"`
}

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
		return nil, fmt.Errorf("GitHub release endpoint returned HTTP %d", response.StatusCode)
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
	destination string,
) error {
	asset, ok := release.Assets[artifact.Name]
	if !ok || asset.Size != artifact.Size || artifact.Size <= 0 ||
		artifact.Size > maxReleaseArtifactBytes {
		return errors.New("release artifact metadata does not match the immutable Release")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.APIURL, nil)
	if err != nil {
		return errors.New("build release artifact request failed")
	}
	if err := source.validateAddress(asset.APIURL); err != nil {
		return err
	}
	request.Header.Set("accept", "application/octet-stream")
	response, err := source.client.Do(request)
	if err != nil {
		return errors.New("release artifact download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("release artifact endpoint returned HTTP %d", response.StatusCode)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("create private release artifact failed")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, artifact.Size+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != artifact.Size {
		_ = os.Remove(destination)
		return errors.New("release artifact size verification failed")
	}
	digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if digest != artifact.SHA256 {
		_ = os.Remove(destination)
		return errors.New("release artifact SHA-256 verification failed")
	}
	// Artifact authenticity is inherited from the single, verified
	// release-manifest.json subject. Each downloaded byte stream is checked
	// against the manifest's exact immutable asset name, size, and SHA-256.
	return nil
}

func validateReleaseManifest(
	manifest releaseManifest,
	tag string,
	assets map[string]releaseAsset,
) error {
	expectedChannel := releaseChannelForVersion(manifest.ReleaseVersion)
	if manifest.SchemaVersion != manifestSchema || !validReleaseChannel(expectedChannel) ||
		manifest.Channel != string(expectedChannel) ||
		!validProductLabel(manifest.ProductLabel) ||
		manifest.Tag != tag || tag != "v"+manifest.ReleaseVersion ||
		!validProductVersion(manifest.ReleaseVersion) || manifest.Source.Repository != officialRepository ||
		manifest.Source.Workflow != officialReleaseWorkflow ||
		!commitPattern.MatchString(manifest.Source.Commit) || !manifest.Support.LatestOnly {
		return errors.New("release manifest does not match the official immutable release identity")
	}
	if manifest.Attestations.Issuer != "https://token.actions.githubusercontent.com" ||
		manifest.Attestations.Repository != officialRepository ||
		manifest.Attestations.Workflow != officialReleaseWorkflow {
		return errors.New("release manifest attestation identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339, manifest.PublishedAt); err != nil {
		return errors.New("release manifest published_at is invalid")
	}
	componentVersions := []string{
		manifest.Components.May.Version,
		manifest.Components.SSHAgent.Version,
		manifest.Components.Gateway.Version,
		manifest.Components.Executor.Version,
		manifest.Components.PWA.Version,
		manifest.Components.Skill.Version,
	}
	for _, version := range componentVersions {
		if version != manifest.ReleaseVersion {
			return errors.New("release manifest product component versions are not atomic")
		}
	}
	if manifest.Components.May.ClientProtocol <= 0 ||
		!protocolContains(manifest.Components.Gateway.AcceptedClientProtocol, manifest.Components.May.ClientProtocol) ||
		manifest.Components.Gateway.StateSchema <= 0 || manifest.Components.Executor.StateSchema <= 0 ||
		manifest.Components.KeychainHelper.Version == "" ||
		!digestPattern.MatchString(manifest.Components.KeychainHelper.SourceDigest) ||
		manifest.Components.KeychainHelper.HelperProtocol.Minimum <= 0 ||
		manifest.Components.KeychainHelper.HelperProtocol.Maximum < manifest.Components.KeychainHelper.HelperProtocol.Minimum {
		return errors.New("release manifest compatibility fields are incomplete")
	}
	if !validStableVersion(manifest.Support.MinimumSafeVersion) ||
		compareProductVersions(manifest.Support.MinimumSafeVersion, manifest.ReleaseVersion) > 0 ||
		!validStableVersion(manifest.Upgrade.MinimumUpdaterVersion) ||
		compareProductVersions(manifest.Upgrade.MinimumUpdaterVersion, manifest.ReleaseVersion) > 0 {
		return errors.New("release manifest update safety versions are invalid")
	}
	if manifest.Support.PreviousReleaseVersion != "" &&
		(!validProductVersion(manifest.Support.PreviousReleaseVersion) ||
			compareProductVersions(manifest.Support.PreviousReleaseVersion, manifest.ReleaseVersion) >= 0) {
		return errors.New("release manifest previous release compatibility is invalid")
	}
	if manifest.ReleaseVersion != "0.0.1" && manifest.Support.PreviousReleaseVersion == "" {
		return errors.New("release manifest does not declare N/N-1 compatibility")
	}
	if len(manifest.Upgrade.Order) != 4 ||
		strings.Join(manifest.Upgrade.Order, ",") != "executor,gateway,local,skill" {
		return errors.New("release manifest has an unsupported deployment order")
	}
	if err := validateVersionRange(manifest.Requirements.Wrangler); err != nil {
		return errors.New("release manifest Wrangler requirement is invalid")
	}
	if err := validateVersionRange(manifest.Requirements.OnePasswordCLI); err != nil {
		return errors.New("release manifest 1Password CLI requirement is invalid")
	}
	if err := validateVersionRange(manifest.Requirements.Node); err != nil {
		return errors.New("release manifest Node.js requirement is invalid")
	}
	if manifest.Requirements.MacOS.Minimum != "15.0" ||
		strings.Join(manifest.Requirements.MacOS.Architectures, ",") != "arm64,amd64" ||
		strings.Join(manifest.Requirements.OnePasswordRegions, ",") != "com,ca,eu" {
		return errors.New("release manifest platform or 1Password region support is invalid")
	}
	if manifest.Upgrade.MinimumSafeVersion != manifest.Support.MinimumSafeVersion ||
		strings.Join(manifest.Upgrade.RevokedArtifactDigests, "\n") !=
			strings.Join(manifest.RevokedArtifactDigests, "\n") {
		return errors.New("release manifest duplicated support policy fields disagree")
	}
	revoked := map[string]struct{}{}
	for _, digest := range manifest.RevokedArtifactDigests {
		if !digestPattern.MatchString(digest) {
			return errors.New("release manifest contains an invalid revoked artifact digest")
		}
		revoked[digest] = struct{}{}
	}
	expectedArtifacts := expectedReleaseArtifactContract(manifest)
	if len(manifest.Artifacts) != len(expectedArtifacts) {
		return errors.New("release manifest does not contain the exact canonical artifact set")
	}
	seen := map[string]struct{}{}
	for _, artifact := range manifest.Artifacts {
		asset, ok := assets[artifact.Name]
		if !ok || asset.Size != artifact.Size || artifact.Size <= 0 ||
			artifact.Size > maxReleaseArtifactBytes || !digestPattern.MatchString(artifact.SHA256) {
			return fmt.Errorf("release artifact %q does not match immutable asset metadata", artifact.Name)
		}
		if _, duplicate := seen[artifact.Name]; duplicate {
			return errors.New("release manifest contains duplicate artifacts")
		}
		expected, expectedName := expectedArtifacts[artifact.Name]
		if !expectedName || !artifactMatchesContract(artifact, expected) {
			return fmt.Errorf("release artifact %q has an invalid kind or platform", artifact.Name)
		}
		seen[artifact.Name] = struct{}{}
		if _, isRevoked := revoked[artifact.SHA256]; isRevoked {
			return fmt.Errorf("release artifact %q is explicitly revoked", artifact.Name)
		}
	}
	if len(seen) != len(expectedArtifacts) {
		return errors.New("release manifest artifact inventory is incomplete")
	}
	expectedAssets := map[string]struct{}{
		releaseManifestAssetName:  {},
		provenanceBundleAssetName: {},
		"SHA256SUMS":              {},
	}
	for name := range expectedArtifacts {
		expectedAssets[name] = struct{}{}
	}
	if len(assets) != len(expectedAssets) {
		return errors.New("immutable OneNod Release does not contain the exact canonical asset set")
	}
	for name := range expectedAssets {
		asset, found := assets[name]
		if !found || asset.Size <= 0 {
			return fmt.Errorf("immutable OneNod Release is missing canonical asset %q", name)
		}
	}
	return nil
}

func expectedReleaseArtifactContract(manifest releaseManifest) map[string]releaseArtifactContract {
	version := manifest.ReleaseVersion
	helperVersion := manifest.Components.KeychainHelper.Version
	archives := []string{
		"onenod-darwin-arm64.tar.gz",
		"onenod-darwin-amd64.tar.gz",
		fmt.Sprintf("onenod-deployment-%s.tar.gz", version),
		fmt.Sprintf("onenod-keychain-helper-%s-darwin-arm64.tar.gz", helperVersion),
		fmt.Sprintf("onenod-keychain-helper-%s-darwin-amd64.tar.gz", helperVersion),
		fmt.Sprintf("onenod-skill-%s.tar.gz", version),
	}
	contract := map[string]releaseArtifactContract{
		"onenod-darwin-arm64.tar.gz": {Kind: "local", OS: "darwin", Architecture: "arm64"},
		"onenod-darwin-amd64.tar.gz": {Kind: "local", OS: "darwin", Architecture: "amd64"},
		fmt.Sprintf("onenod-deployment-%s.tar.gz", version): {
			Kind: "deployment",
		},
		fmt.Sprintf("onenod-skill-%s.tar.gz", version): {
			Kind: "skill",
		},
		fmt.Sprintf("onenod-keychain-helper-%s-darwin-arm64.tar.gz", helperVersion): {
			Kind: "keychain_helper", OS: "darwin", Architecture: "arm64",
		},
		fmt.Sprintf("onenod-keychain-helper-%s-darwin-amd64.tar.gz", helperVersion): {
			Kind: "keychain_helper", OS: "darwin", Architecture: "amd64",
		},
		"THIRD_PARTY_NOTICES.txt": {Kind: "notices"},
	}
	for _, archive := range archives {
		contract[strings.TrimSuffix(archive, ".tar.gz")+".spdx.json"] =
			releaseArtifactContract{Kind: "sbom", Subject: archive}
	}
	return contract
}

func artifactMatchesContract(artifact releaseArtifact, expected releaseArtifactContract) bool {
	if artifact.Kind != expected.Kind || artifact.Subject != expected.Subject {
		return false
	}
	if expected.OS == "" {
		return artifact.Platform == nil
	}
	return artifact.Platform != nil && artifact.Platform.OS == expected.OS &&
		artifact.Platform.Architecture == expected.Architecture
}

func validReleaseTag(value string) bool {
	return strings.HasPrefix(value, "v") && validProductVersion(strings.TrimPrefix(value, "v"))
}

func validStableVersion(value string) bool { return semverPattern.MatchString(value) }

func validProductVersion(value string) bool {
	match := productSemverPattern.FindStringSubmatch(value)
	if match == nil || !semver.IsValid("v"+value) {
		return false
	}
	for _, component := range []string{match[1], match[2], match[3], match[5]} {
		if component == "" {
			continue
		}
		parsed, err := strconv.ParseUint(component, 10, 64)
		if err != nil || parsed > maxSafeVersionInteger {
			return false
		}
	}
	return true
}

func releaseChannelForVersion(value string) releaseChannel {
	match := productSemverPattern.FindStringSubmatch(value)
	if match == nil {
		return ""
	}
	switch match[4] {
	case "alpha":
		return releaseChannelAlpha
	case "beta":
		return releaseChannelBeta
	default:
		return releaseChannelStable
	}
}

func validProductLabel(value string) bool {
	if value == "" || len(value) > 64 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if !unicode.IsPrint(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func parseReleaseChannel(value string) (releaseChannel, error) {
	channel := releaseChannel(strings.TrimSpace(value))
	if !validReleaseChannel(channel) {
		return "", errors.New("release channel must be stable, beta, or alpha")
	}
	return channel, nil
}

func releaseChannelFromFlag(value string, fallback releaseChannel) (releaseChannel, error) {
	if value == "" {
		if validReleaseChannel(fallback) {
			return fallback, nil
		}
		return releaseChannelStable, nil
	}
	return parseReleaseChannel(value)
}

func releaseSelectionFromFlags(
	channelValue string,
	versionValue string,
	fallback releaseChannel,
) (releaseSelection, error) {
	if err := validateExplicitReleaseSelection(channelValue, versionValue); err != nil {
		return releaseSelection{}, err
	}
	if versionValue != "" {
		return releaseSelection{
			Channel: releaseChannelForVersion(versionValue),
			Version: versionValue,
		}, nil
	}
	channel, err := releaseChannelFromFlag(channelValue, fallback)
	if err != nil {
		return releaseSelection{}, err
	}
	return releaseSelection{Channel: channel}, nil
}

func validateExplicitReleaseSelection(channelValue string, versionValue string) error {
	if channelValue != "" && versionValue != "" {
		return errors.New(
			"--channel and --version are mutually exclusive; an exact version determines its release channel",
		)
	}
	if versionValue != "" {
		if strings.TrimSpace(versionValue) != versionValue || !validProductVersion(versionValue) {
			return errors.New(
				"release version must be a canonical X.Y.Z, X.Y.Z-alpha.N, or X.Y.Z-beta.N version without a v prefix",
			)
		}
	}
	if channelValue != "" {
		if _, err := parseReleaseChannel(channelValue); err != nil {
			return err
		}
	}
	return nil
}

func resolveSelectedRelease(
	ctx context.Context,
	source releaseSource,
	selection releaseSelection,
) (*verifiedRelease, error) {
	if selection.Version != "" {
		return source.Exact(ctx, selection.Version)
	}
	return source.Latest(ctx, selection.Channel)
}

func releaseSelectionArguments(selection releaseSelection) []string {
	if selection.Version != "" {
		return []string{"--version", selection.Version}
	}
	return []string{"--channel", string(selection.Channel)}
}

func confirmHigherRiskChannel(
	input io.Reader,
	output io.Writer,
	current releaseChannel,
	selected releaseChannel,
	action string,
) error {
	if releaseChannelRisk(selected) <= releaseChannelRisk(current) {
		return nil
	}
	fmt.Fprintf(output,
		"\nPRERELEASE CHANNEL OPT-IN\n  Current channel: %s\n  Requested channel: %s\n  %s will accept %s prereleases and all safer channels.\n",
		current, selected, action, selected,
	)
	confirmed, err := promptYesNo(input, output, "Continue with this higher-risk release channel?", false)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("higher-risk release channel was not approved; no changes were made")
	}
	return nil
}

func validReleaseChannel(channel releaseChannel) bool {
	return channel == releaseChannelStable || channel == releaseChannelBeta || channel == releaseChannelAlpha
}

func releaseChannelRisk(channel releaseChannel) int {
	switch channel {
	case releaseChannelStable:
		return 0
	case releaseChannelBeta:
		return 1
	case releaseChannelAlpha:
		return 2
	default:
		return -1
	}
}

func releaseChannelAccepts(selected, candidate releaseChannel) bool {
	return validReleaseChannel(selected) && validReleaseChannel(candidate) &&
		releaseChannelRisk(candidate) <= releaseChannelRisk(selected)
}

func awaitingCompatibleRelease(
	currentVersion string,
	currentChannel releaseChannel,
	candidateVersion string,
	selectedChannel releaseChannel,
) bool {
	return validProductVersion(currentVersion) && validProductVersion(candidateVersion) &&
		validReleaseChannel(currentChannel) && validReleaseChannel(selectedChannel) &&
		releaseChannelRisk(selectedChannel) < releaseChannelRisk(currentChannel) &&
		compareProductVersions(candidateVersion, currentVersion) < 0
}

func writeAwaitingCompatibleRelease(
	output io.Writer,
	currentVersion string,
	currentChannel releaseChannel,
	candidateVersion string,
	selectedChannel releaseChannel,
) {
	fmt.Fprintf(output,
		"OneNod update status: awaiting_compatible_release\n  current: %s (channel %s)\n  latest acceptable %s release: %s\n  no receipt or runtime state was changed; retry after %s publishes a release at or above %s.\n",
		currentVersion, currentChannel, selectedChannel, candidateVersion,
		selectedChannel, currentVersion,
	)
}

func compareProductVersions(first, second string) int {
	if !validProductVersion(first) || !validProductVersion(second) {
		return strings.Compare(first, second)
	}
	return semver.Compare("v"+first, "v"+second)
}

func selectedReleaseChannel(release *verifiedRelease) releaseChannel {
	if release != nil && validReleaseChannel(release.SelectedChannel) {
		return release.SelectedChannel
	}
	return releaseChannelStable
}

func normalizedReceiptChannel(value string, version string) (releaseChannel, error) {
	if value == "" {
		value = string(releaseChannelStable)
	}
	channel, err := parseReleaseChannel(value)
	if err != nil || !validProductVersion(version) ||
		!releaseChannelAccepts(channel, releaseChannelForVersion(version)) {
		return "", errors.New("receipt release channel is invalid")
	}
	return channel, nil
}

func compareVersions(first, second string) int {
	left := semverPattern.FindStringSubmatch(first)
	right := semverPattern.FindStringSubmatch(second)
	if left == nil || right == nil {
		return strings.Compare(first, second)
	}
	for index := 1; index <= 3; index++ {
		a, _ := strconv.ParseUint(left[index], 10, 64)
		b, _ := strconv.ParseUint(right[index], 10, 64)
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
	}
	return 0
}

func validateVersionRange(requirement versionRange) error {
	if !validStableVersion(requirement.Minimum) ||
		(requirement.MaximumExclusive != "" &&
			(!validStableVersion(requirement.MaximumExclusive) ||
				compareVersions(requirement.Minimum, requirement.MaximumExclusive) >= 0)) {
		return errors.New("invalid version range")
	}
	return nil
}

func protocolContains(accepted protocolRange, version int) bool {
	return accepted.Minimum > 0 && accepted.Maximum >= accepted.Minimum &&
		version >= accepted.Minimum && version <= accepted.Maximum
}

func runningReleaseCanConsume(manifest releaseManifest) (bool, error) {
	if !validProductVersion(productVersion) || releaseTag != "v"+productVersion ||
		!commitPattern.MatchString(sourceCommit) {
		return false, errors.New("unsupported_running_binary: use an immutable official OneNod Release binary")
	}
	if !protocolContains(manifest.Components.KeychainHelper.HelperProtocol, keychainHelperProtocol) {
		return false, errors.New("unsupported_update_path: the running may Keychain-helper protocol is outside the latest Release contract")
	}
	if compareProductVersions(productVersion, manifest.Upgrade.MinimumUpdaterVersion) < 0 {
		return false, fmt.Errorf(
			"unsupported_update_path: running may %s is below minimum_updater_version %s; install a supported official bridge or latest Release binary manually",
			productVersion, manifest.Upgrade.MinimumUpdaterVersion,
		)
	}
	comparison := compareProductVersions(productVersion, manifest.ReleaseVersion)
	if comparison > 0 {
		return false, fmt.Errorf(
			"anti_rollback: running may %s is newer than latest official Release %s",
			productVersion, manifest.ReleaseVersion,
		)
	}
	if comparison == 0 {
		if sourceCommit != manifest.Source.Commit {
			return false, errors.New("same_version_identity_mismatch: running may source commit differs from the signed Release")
		}
		return true, nil
	}
	return false, nil
}

func artifactFor(release *verifiedRelease, name string) (releaseArtifact, error) {
	for _, artifact := range release.Manifest.Artifacts {
		if artifact.Name == name {
			return artifact, nil
		}
	}
	return releaseArtifact{}, fmt.Errorf("verified release does not contain required artifact %q", name)
}

func localArtifactName() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("OneNod requester binaries support macOS only")
	}
	switch runtime.GOARCH {
	case "arm64", "amd64":
		return fmt.Sprintf("onenod-darwin-%s.tar.gz", runtime.GOARCH), nil
	default:
		return "", fmt.Errorf("unsupported macOS architecture %s", runtime.GOARCH)
	}
}

func helperArtifactName(version string) (string, error) {
	if _, err := localArtifactName(); err != nil {
		return "", err
	}
	return fmt.Sprintf("onenod-keychain-helper-%s-darwin-%s.tar.gz", version, runtime.GOARCH), nil
}

func skillArtifactName(version string) string {
	return fmt.Sprintf("onenod-skill-%s.tar.gz", version)
}

func deploymentArtifactName(version string) string {
	return fmt.Sprintf("onenod-deployment-%s.tar.gz", version)
}

func privateStagingDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for release staging failed")
	}
	root := filepath.Join(home, userAgentDirectoryName, "update")
	if err := ensurePrivateInstallDirectory(filepath.Join(home, userAgentDirectoryName)); err != nil {
		return "", err
	}
	if err := ensurePrivateInstallDirectory(root); err != nil {
		return "", err
	}
	return os.MkdirTemp(root, ".stage-")
}

func downloadVerifiedArtifact(
	ctx context.Context,
	release *verifiedRelease,
	artifact releaseArtifact,
	directory string,
) (string, error) {
	if release == nil || release.Source == nil {
		return "", errors.New("verified release source is unavailable")
	}
	path := filepath.Join(directory, artifact.Name)
	if err := release.Source.Download(ctx, release, artifact, path); err != nil {
		return "", err
	}
	return path, nil
}

func extractReleaseArchive(
	archivePath, destination string,
	allowed map[string]os.FileMode,
) error {
	input, err := os.Open(archivePath)
	if err != nil {
		return errors.New("open verified release archive failed")
	}
	defer input.Close()
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return errors.New("verified release artifact is not gzip")
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	root, err := os.OpenRoot(destination)
	if err != nil {
		return errors.New("open release extraction root failed")
	}
	defer root.Close()
	seen := map[string]struct{}{}
	var totalBytes int64
	entryCount := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("read verified release archive failed")
		}
		entryCount++
		if entryCount > 4096 {
			return errors.New("verified release archive contains too many entries")
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		relative := filepath.FromSlash(clean)
		if clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(header.Name) {
			return errors.New("verified release archive contains an unsafe path")
		}
		if !filepath.IsLocal(relative) {
			return errors.New("verified release archive contains an unsafe path")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 ||
			header.Size > maxReleaseArtifactBytes-totalBytes {
			return fmt.Errorf("verified release archive entry %q exceeds the extraction budget", clean)
		}
		totalBytes += header.Size
		if _, duplicate := seen[clean]; duplicate {
			return errors.New("verified release archive contains duplicate files")
		}
		seen[clean] = struct{}{}
		mode, required := allowed[clean]
		if !required {
			continue
		}
		if header.Size <= 0 {
			return fmt.Errorf("verified release archive entry %q is not a bounded regular file", clean)
		}
		if err := root.MkdirAll(filepath.Dir(relative), 0o700); err != nil {
			return errors.New("create release extraction directory failed")
		}
		output, err := root.OpenFile(relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return errors.New("create extracted release file failed")
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, header.Size+1))
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
			return errors.New("extract verified release file failed")
		}
	}
	for path := range allowed {
		if _, ok := seen[path]; !ok {
			return fmt.Errorf("verified release archive omitted %q", path)
		}
	}
	return nil
}

func extractSkillArchive(archivePath, destination string) error {
	input, err := os.Open(archivePath)
	if err != nil {
		return errors.New("open verified Skill archive failed")
	}
	defer input.Close()
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return errors.New("verified Skill artifact is not gzip")
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	root, err := os.OpenRoot(destination)
	if err != nil {
		return errors.New("open Skill extraction root failed")
	}
	defer root.Close()
	seen := map[string]struct{}{}
	var totalBytes int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("read verified Skill archive failed")
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		relative := filepath.FromSlash(clean)
		if clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(header.Name) {
			return errors.New("verified Skill archive contains an unsafe path")
		}
		if !filepath.IsLocal(relative) {
			return errors.New("verified Skill archive contains an unsafe path")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		allowed := strings.HasPrefix(clean, "onenod-skill/onenod/") ||
			clean == "onenod-skill/RELEASE.json" || clean == "onenod-skill/LICENSE"
		if !allowed || header.Typeflag != tar.TypeReg || header.Size <= 0 ||
			header.Size > maxReleaseArtifactBytes-totalBytes || len(seen) >= 4096 {
			return fmt.Errorf("verified Skill archive entry %q is unsafe or exceeds the extraction budget", clean)
		}
		totalBytes += header.Size
		if _, duplicate := seen[clean]; duplicate {
			return errors.New("verified Skill archive contains duplicate files")
		}
		seen[clean] = struct{}{}
		if err := root.MkdirAll(filepath.Dir(relative), 0o700); err != nil {
			return errors.New("create Skill extraction directory failed")
		}
		output, err := root.OpenFile(relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return errors.New("create extracted Skill file failed")
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, header.Size+1))
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
			return errors.New("extract verified Skill file failed")
		}
	}
	if _, ok := seen["onenod-skill/onenod/SKILL.md"]; !ok {
		return errors.New("verified Skill archive omitted onenod/SKILL.md")
	}
	if _, ok := seen["onenod-skill/RELEASE.json"]; !ok {
		return errors.New("verified Skill archive omitted RELEASE.json")
	}
	return nil
}

func stageVerifiedDeploymentBundle(
	ctx context.Context,
	release *verifiedRelease,
) (*stagedDeploymentBundle, error) {
	artifact, err := artifactFor(release, deploymentArtifactName(release.Manifest.ReleaseVersion))
	if err != nil {
		return nil, err
	}
	stage, err := privateStagingDirectory()
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stage)
		}
	}()
	archivePath, err := downloadVerifiedArtifact(ctx, release, artifact, stage)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(stage, "bundle")
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, errors.New("create deployment bundle directory failed")
	}
	if err := extractDeploymentBundleArchive(archivePath, root); err != nil {
		return nil, err
	}
	bundleRoot := filepath.Join(root, "onenod-deployment")
	descriptor, err := validateStagedDeploymentBundle(bundleRoot, release.Manifest)
	if err != nil {
		return nil, err
	}
	cleanup = false
	return &stagedDeploymentBundle{
		Artifact: artifact, Descriptor: descriptor, Root: bundleRoot, Stage: stage,
	}, nil
}

func validateStagedDeploymentBundle(
	bundleRoot string,
	manifest releaseManifest,
) (deploymentBundleDescriptor, error) {
	var descriptor deploymentBundleDescriptor
	if err := readStrictJSONFile(filepath.Join(bundleRoot, "deployment.json"), maxManifestBytes, &descriptor); err != nil {
		return deploymentBundleDescriptor{}, err
	}
	if descriptor.SchemaVersion != 1 || descriptor.ReleaseVersion != manifest.ReleaseVersion ||
		descriptor.SourceCommit != manifest.Source.Commit ||
		descriptor.Gateway.Config != "gateway/wrangler.jsonc" ||
		descriptor.Gateway.Entrypoint != "gateway/worker.mjs" ||
		descriptor.Gateway.Assets != "gateway/assets" ||
		descriptor.Executor.Config != "executor/wrangler.jsonc" ||
		descriptor.Executor.Entrypoint != "executor/worker.mjs" ||
		descriptor.Executor.Plugin != "executor/plugin.wasm" {
		return deploymentBundleDescriptor{}, errors.New("deployment bundle descriptor does not match the verified release contract")
	}
	expectedTokens := []string{
		"__ACCOUNT_ID__", "__ACCOUNT_SUBDOMAIN__", "__EXECUTOR_NAME__", "__GATEWAY_NAME__",
		"__OP_ACCOUNT__", "__OP_VAULT_ID__", "__ORIGIN__", "__RELEASE_VERSION__",
		"__RP_ID__", "__SOURCE_COMMIT__", "__VAPID_PUBLIC_KEY__",
	}
	actualTokens := append([]string(nil), descriptor.TemplateTokens...)
	sort.Strings(expectedTokens)
	sort.Strings(actualTokens)
	if strings.Join(expectedTokens, "\n") != strings.Join(actualTokens, "\n") {
		return deploymentBundleDescriptor{}, errors.New("deployment bundle template token contract is incomplete")
	}
	var releaseFile deploymentReleaseMetadata
	if err := readStrictJSONFile(filepath.Join(bundleRoot, "RELEASE.json"), maxManifestBytes, &releaseFile); err != nil {
		return deploymentBundleDescriptor{}, err
	}
	if releaseFile.SchemaVersion != 1 || releaseFile.ArtifactKind != "deployment" ||
		releaseFile.Repository != officialRepository ||
		releaseFile.ReleaseVersion != manifest.ReleaseVersion ||
		releaseFile.SourceCommit != manifest.Source.Commit {
		return deploymentBundleDescriptor{}, errors.New("deployment bundle RELEASE.json does not match the verified manifest")
	}
	return descriptor, nil
}

func extractDeploymentBundleArchive(archivePath, destination string) error {
	input, err := os.Open(archivePath)
	if err != nil {
		return errors.New("open verified deployment archive failed")
	}
	defer input.Close()
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return errors.New("verified deployment artifact is not gzip")
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	root, err := os.OpenRoot(destination)
	if err != nil {
		return errors.New("open deployment extraction root failed")
	}
	defer root.Close()
	required := deploymentBundleRequiredFiles()
	seen := map[string]struct{}{}
	var totalBytes int64
	entryCount := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("read verified deployment archive failed")
		}
		entryCount++
		if entryCount > 4096 {
			return errors.New("verified deployment archive contains too many entries")
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		relative := filepath.FromSlash(clean)
		if clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(header.Name) {
			return errors.New("verified deployment archive contains an unsafe path")
		}
		if !filepath.IsLocal(relative) {
			return errors.New("verified deployment archive contains an unsafe path")
		}
		if clean != "onenod-deployment" && !strings.HasPrefix(clean, "onenod-deployment/") {
			return errors.New("verified deployment archive contains an unexpected top-level path")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 ||
			header.Size > maxReleaseArtifactBytes-totalBytes {
			return fmt.Errorf("verified deployment archive entry %q exceeds the extraction budget", clean)
		}
		totalBytes += header.Size
		_, exact := required[clean]
		asset := strings.HasPrefix(clean, "onenod-deployment/gateway/assets/")
		if _, duplicate := seen[clean]; duplicate {
			return errors.New("verified deployment archive contains duplicate files")
		}
		seen[clean] = struct{}{}
		if !exact && !asset {
			continue
		}
		if header.Size == 0 {
			return fmt.Errorf("verified deployment archive entry %q is empty", clean)
		}
		if exact {
			required[clean] = true
		}
		if err := root.MkdirAll(filepath.Dir(relative), 0o700); err != nil {
			return errors.New("create deployment extraction directory failed")
		}
		output, err := root.OpenFile(relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return errors.New("create deployment extraction file failed")
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, header.Size+1))
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
			return errors.New("extract verified deployment file failed")
		}
	}
	for path, found := range required {
		if !found {
			return fmt.Errorf("verified deployment archive omitted %q", path)
		}
	}
	assetsRoot := filepath.Join(destination, "onenod-deployment", "gateway", "assets")
	if info, err := os.Stat(assetsRoot); err != nil || !info.IsDir() {
		return errors.New("verified deployment archive contains no Gateway assets")
	}
	return nil
}

func deploymentBundleRequiredFiles() map[string]bool {
	return map[string]bool{
		"onenod-deployment/deployment.json":         false,
		"onenod-deployment/RELEASE.json":            false,
		"onenod-deployment/gateway/wrangler.jsonc":  false,
		"onenod-deployment/gateway/worker.mjs":      false,
		"onenod-deployment/executor/wrangler.jsonc": false,
		"onenod-deployment/executor/worker.mjs":     false,
		"onenod-deployment/executor/plugin.wasm":    false,
	}
}

func readStrictJSONFile(path string, limit int64, value any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > limit {
		return fmt.Errorf("verified release metadata %s is unsafe", filepath.Base(path))
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return errors.New("read verified release metadata failed")
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil || ensureDecoderEOF(decoder) != nil {
		return errors.New("verified release metadata is invalid")
	}
	return nil
}

func renderDeploymentConfigs(
	bundle *stagedDeploymentBundle,
	manifest releaseManifest,
	material *productionInitializationMaterial,
) error {
	values := map[string]string{
		"__ACCOUNT_ID__":        material.AccountID,
		"__ACCOUNT_SUBDOMAIN__": material.AccountSubdomain,
		"__EXECUTOR_NAME__":     material.ExecutorName,
		"__GATEWAY_NAME__":      material.GatewayName,
		"__OP_ACCOUNT__":        material.OnePasswordAccount,
		"__OP_VAULT_ID__":       material.AgentVaultID,
		"__ORIGIN__":            material.Origin,
		"__RELEASE_VERSION__":   manifest.ReleaseVersion,
		"__RP_ID__":             material.RPID,
		"__SOURCE_COMMIT__":     manifest.Source.Commit,
		"__VAPID_PUBLIC_KEY__":  material.VAPID.PublicKey,
	}
	unknownToken := regexp.MustCompile(`__[A-Z][A-Z0-9_]*__`)
	for _, relative := range []string{
		bundle.Descriptor.Executor.Config,
		bundle.Descriptor.Gateway.Config,
	} {
		path := filepath.Join(bundle.Root, filepath.FromSlash(relative))
		encoded, exists, err := readOptionalRegularFile(path, 4<<20)
		if err != nil || !exists {
			return errors.New("read deployment Wrangler template failed")
		}
		rendered := string(encoded)
		for token, value := range values {
			if strings.ContainsAny(value, "\x00\r\n\"") {
				return errors.New("deployment template value contains unsafe characters")
			}
			rendered = strings.ReplaceAll(rendered, token, value)
		}
		if unknownToken.MatchString(rendered) {
			return errors.New("deployment Wrangler template contains an unresolved token")
		}
		if err := writeAtomicUserConfig(path, []byte(rendered), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func localReceiptPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for install receipt failed")
	}
	return filepath.Join(home, userAgentDirectoryName, "install.json"), nil
}

func initializerReceiptPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for initializer receipt failed")
	}
	return filepath.Join(home, userAgentDirectoryName, "initializer.json"), nil
}

func readInitializerInstallReceipt() (*initializerInstallReceipt, bool, error) {
	path, err := initializerReceiptPath()
	if err != nil {
		return nil, false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return nil, false, errors.New("initializer receipt is unsafe or invalid")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, false, errors.New("read initializer receipt failed")
	}
	var receipt initializerInstallReceipt
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || ensureDecoderEOF(decoder) != nil ||
		receipt.SchemaVersion != initializerReceiptSchema ||
		!validProductVersion(receipt.ReleaseVersion) || !commitPattern.MatchString(receipt.SourceCommit) ||
		len(receipt.Artifacts) != 3 || len(receipt.Files) != 3 ||
		receipt.HelperProtocol <= 0 || receipt.HelperVersion == "" ||
		!digestPattern.MatchString(receipt.SkillTreeSHA) {
		return nil, false, errors.New("initializer receipt is invalid")
	}
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil {
		return nil, false, errors.New("initializer receipt has an invalid release channel")
	}
	receipt.Channel = string(channel)
	for _, digest := range receipt.Artifacts {
		if !digestPattern.MatchString(digest) {
			return nil, false, errors.New("initializer receipt contains an invalid artifact digest")
		}
	}
	for _, digest := range receipt.Files {
		if !digestPattern.MatchString(digest) {
			return nil, false, errors.New("initializer receipt contains an invalid file digest")
		}
	}
	home, homeErr := os.UserHomeDir()
	backupRoot := filepath.Join(home, userAgentDirectoryName, "skill-adoption-backups")
	for _, backup := range receipt.AdoptedBackups {
		relative, relativeErr := filepath.Rel(backupRoot, backup)
		if homeErr != nil || relativeErr != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, false, errors.New("initializer receipt contains an unsafe Skill adoption backup")
		}
	}
	return &receipt, true, nil
}

func readLocalInstallReceipt() (*localInstallReceipt, bool, error) {
	path, err := localReceiptPath()
	if err != nil {
		return nil, false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return nil, false, errors.New("local OneNod install receipt is unsafe or invalid")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, false, errors.New("read local OneNod install receipt failed")
	}
	var receipt localInstallReceipt
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil || receipt.SchemaVersion != localReceiptSchema ||
		ensureDecoderEOF(decoder) != nil || !validProductVersion(receipt.ReleaseVersion) ||
		!commitPattern.MatchString(receipt.SourceCommit) {
		return nil, false, errors.New("local OneNod install receipt is invalid")
	}
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil {
		return nil, false, errors.New("local OneNod install receipt has an invalid release channel")
	}
	receipt.Channel = string(channel)
	if parsed, err := parseGatewayOrigin(receipt.Origin); err != nil || parsed.String() != receipt.Origin {
		return nil, false, errors.New("local OneNod install receipt Origin is invalid")
	}
	localName, localErr := localArtifactName()
	if localErr != nil || len(receipt.Artifacts) != 3 ||
		receipt.Artifacts[localName] == "" ||
		receipt.Skill.Artifact != skillArtifactName(receipt.ReleaseVersion) ||
		receipt.Skill.Version != receipt.ReleaseVersion ||
		strings.Join(receipt.Skill.Discovery, ",") != "~/.agents/skills/onenod,~/.claude/skills/onenod" ||
		receipt.Artifacts[receipt.Skill.Artifact] != receipt.Skill.ArtifactSHA ||
		receipt.Helper.Artifact == "" ||
		receipt.Artifacts[receipt.Helper.Artifact] != receipt.Helper.ArtifactSHA ||
		receipt.Helper.Version == "" || receipt.Helper.Protocol <= 0 ||
		!digestPattern.MatchString(receipt.Helper.SourceDigest) ||
		len(receipt.Files) != 2 || receipt.Files["bin/may"] == "" ||
		receipt.Files["bin/"+gitSignAdapterBinaryName] == "" {
		return nil, false, errors.New("local OneNod install receipt has an incomplete component shape")
	}
	for _, digest := range receipt.Artifacts {
		if !digestPattern.MatchString(digest) {
			return nil, false, errors.New("local OneNod install receipt contains an invalid digest")
		}
	}
	for _, digest := range []string{
		receipt.Helper.ArtifactSHA, receipt.Helper.BinarySHA256,
		receipt.Helper.SourceDigest,
		receipt.Skill.ArtifactSHA, receipt.Skill.TreeSHA256,
		receipt.Files["bin/may"], receipt.Files["bin/"+gitSignAdapterBinaryName],
	} {
		if !digestPattern.MatchString(digest) {
			return nil, false, errors.New("local OneNod install receipt contains an invalid component digest")
		}
	}
	home, homeErr := os.UserHomeDir()
	backupRoot := filepath.Join(home, userAgentDirectoryName, "skill-adoption-backups")
	for _, backup := range receipt.Skill.AdoptedBackups {
		relative, err := filepath.Rel(backupRoot, backup)
		if homeErr != nil || err != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, false, errors.New("local OneNod install receipt contains an unsafe Skill adoption backup")
		}
	}
	return &receipt, true, nil
}

func writeLocalInstallReceipt(path string, receipt localInstallReceipt) error {
	receipt.SchemaVersion = localReceiptSchema
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil {
		return err
	}
	receipt.Channel = string(channel)
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return errors.New("encode local OneNod install receipt failed")
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(path)
	staged, err := os.CreateTemp(directory, ".install-receipt-")
	if err != nil {
		return errors.New("stage local OneNod install receipt failed")
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	if err := staged.Chmod(0o600); err != nil {
		staged.Close()
		return errors.New("secure local OneNod install receipt failed")
	}
	if _, err := staged.Write(encoded); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("write local OneNod install receipt failed")
	}
	if err := os.Rename(stagedPath, path); err != nil {
		return errors.New("activate local OneNod install receipt failed")
	}
	return nil
}

func runVersion(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may version [--json]")
	}
	runtimeChannel := releaseChannelForVersion(productVersion)
	runtimeChannelText := string(runtimeChannel)
	if !validReleaseChannel(runtimeChannel) {
		runtimeChannelText = "development"
	}
	selectedChannel := runtimeChannelText
	value := map[string]any{
		"channel": selectedChannel, "release_channel": runtimeChannelText,
		"client_protocol": mayClientProtocol,
		"release_tag":     releaseTag, "repository": officialRepository,
		"source_commit": sourceCommit, "supported_release": validProductVersion(productVersion),
		"version": productVersion,
	}
	receipt, found, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	if found {
		selectedChannel = receipt.Channel
		value["channel"] = selectedChannel
		value["installed_release"] = receipt.ReleaseVersion
		value["origin"] = receipt.Origin
		value["components"] = map[string]any{
			"may":              map[string]any{"sha256": receipt.Files["bin/may"]},
			"ssh_sign_adapter": map[string]any{"sha256": receipt.Files["bin/"+gitSignAdapterBinaryName]},
			"skill": map[string]any{
				"version": receipt.Skill.Version, "tree_sha256": receipt.Skill.TreeSHA256,
				"discovery": receipt.Skill.Discovery,
			},
		}
	} else if initializer, initializerFound, initializerErr := readInitializerInstallReceipt(); initializerErr != nil {
		return initializerErr
	} else if initializerFound {
		selectedChannel = initializer.Channel
		value["channel"] = selectedChannel
		value["initializer_install"] = map[string]any{
			"release_version": initializer.ReleaseVersion,
			"source_commit":   initializer.SourceCommit,
			"components": map[string]any{
				"may":              map[string]any{"sha256": initializer.Files["bin/may"]},
				"ssh_sign_adapter": map[string]any{"sha256": initializer.Files["bin/"+gitSignAdapterBinaryName]},
				"skill":            map[string]any{"tree_sha256": initializer.SkillTreeSHA},
			},
		}
	}
	if helper, err := inspectInstalledKeychainHelper(); err == nil {
		value["keychain_helper"] = map[string]any{
			"protocol": helper.Protocol, "version": helper.Version,
		}
	}
	if running, err := queryRunningAgentVersion(defaultAgentSocket()); err == nil {
		value["running_ssh_agent"] = map[string]any{
			"running": true, "version": running.Version,
			"source_commit": running.SourceCommit, "client_protocol": running.ClientProtocol,
		}
	} else {
		value["running_ssh_agent"] = map[string]any{"running": false, "status": "unavailable_or_incompatible"}
	}
	if *jsonOutput {
		return writeIndentedValue(deps.stdout, value)
	}
	fmt.Fprintf(deps.stdout, "may %s\n", productVersion)
	fmt.Fprintf(deps.stdout, "channel %s (release %s)\n", selectedChannel, runtimeChannelText)
	fmt.Fprintf(deps.stdout, "repository %s\n", officialRepository)
	if !validProductVersion(productVersion) {
		fmt.Fprintln(deps.stdout, "support unsupported development build (main is not a release channel)")
	}
	return nil
}

func runDevVerifyRelease(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("dev verify-release", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	directory := flags.String("directory", "", "release-set directory")
	var selectedArtifacts repeatedStringFlag
	flags.Var(&selectedArtifacts, "artifact", "declared artifact basename to verify (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*directory) == "" {
		return errors.New("usage: may dev verify-release --directory <dist/release> [--artifact <basename>]...")
	}
	if err := requireOfficialRepositoryID(); err != nil {
		return err
	}
	rootPath, err := filepath.Abs(*directory)
	if err != nil {
		return errors.New("resolve release verification directory failed")
	}
	info, err := os.Lstat(rootPath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("release verification directory is unsafe or unavailable")
	}
	manifestPath := filepath.Join(rootPath, releaseManifestAssetName)
	manifestBytes, err := readBoundedRegularFile(manifestPath, maxManifestBytes)
	if err != nil {
		return fmt.Errorf("read release manifest: %w", err)
	}
	var manifest releaseManifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || ensureDecoderEOF(decoder) != nil {
		return errors.New("release manifest is invalid")
	}
	// The developer verifier intentionally supports a selected-artifact subset
	// (used to reuse the prior immutable helper). Build a virtual view of the
	// complete canonical Release from the signed manifest, then verify every
	// selected local byte stream below. Only the GitHub resolver is responsible
	// for proving that the remote Release itself exposes this exact asset set.
	assets := make(map[string]releaseAsset, len(manifest.Artifacts)+3)
	assets[releaseManifestAssetName] = releaseAsset{
		Name: releaseManifestAssetName, Size: int64(len(manifestBytes)),
	}
	assets[provenanceBundleAssetName] = releaseAsset{Name: provenanceBundleAssetName, Size: 1}
	assets["SHA256SUMS"] = releaseAsset{Name: "SHA256SUMS", Size: 1}
	declared := make(map[string]releaseArtifact, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if filepath.Base(artifact.Name) != artifact.Name {
			return fmt.Errorf("release artifact name %q is not a basename", artifact.Name)
		}
		assets[artifact.Name] = releaseAsset{Name: artifact.Name, Size: artifact.Size}
		declared[artifact.Name] = artifact
	}
	toVerify := append([]string(nil), selectedArtifacts...)
	if len(toVerify) == 0 {
		toVerify = sortedArtifactNames(manifest)
	}
	seenSelected := map[string]struct{}{}
	for _, name := range toVerify {
		if filepath.Base(name) != name {
			return fmt.Errorf("selected artifact %q is not a basename", name)
		}
		artifact, ok := declared[name]
		if !ok {
			return fmt.Errorf("selected artifact %q is not declared by the signed manifest", name)
		}
		if _, duplicate := seenSelected[name]; duplicate {
			return fmt.Errorf("selected artifact %q was repeated", name)
		}
		seenSelected[name] = struct{}{}
		path := filepath.Join(rootPath, name)
		value, err := readBoundedRegularFile(path, maxReleaseArtifactBytes)
		if err != nil {
			return fmt.Errorf("read release artifact %q: %w", artifact.Name, err)
		}
		digest := sha256.Sum256(value)
		if int64(len(value)) != artifact.Size ||
			"sha256:"+hex.EncodeToString(digest[:]) != artifact.SHA256 {
			return fmt.Errorf("release artifact %q does not match its manifest entry", artifact.Name)
		}
		if err := verifyReleaseArtifactInstallability(manifest, artifact, path); err != nil {
			return fmt.Errorf("release artifact %q cannot be consumed by may: %w", artifact.Name, err)
		}
	}
	if err := validateReleaseManifest(manifest, manifest.Tag, assets); err != nil {
		return err
	}
	provenanceBytes, err := readBoundedRegularFile(
		filepath.Join(rootPath, provenanceBundleAssetName), maxAttestationBytes,
	)
	if err != nil {
		return fmt.Errorf("read release provenance: %w", err)
	}
	bundles, err := parseProvenanceBundles(provenanceBytes)
	if err != nil {
		return err
	}
	release := &verifiedRelease{
		Assets: assets, Manifest: manifest, ProvenanceBundles: bundles,
		RepositoryID: officialRepositoryID, Tag: manifest.Tag,
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	source := &githubReleaseSource{}
	if err := source.verifyArtifactAttestation(
		context.Background(), release, releaseManifestAssetName,
		manifestDigest[:], manifest.Source.Commit,
	); err != nil {
		return fmt.Errorf("verify release manifest provenance: %w", err)
	}
	fmt.Fprintf(deps.stdout, "Verified OneNod %s release manifest, provenance, and %d selected artifacts.\n",
		manifest.ReleaseVersion, len(toVerify))
	return nil
}

func verifyReleaseArtifactInstallability(
	manifest releaseManifest,
	artifact releaseArtifact,
	path string,
) error {
	if artifact.Kind != "local" && artifact.Kind != "keychain_helper" &&
		artifact.Kind != "deployment" && artifact.Kind != "skill" {
		return nil
	}
	destination, err := os.MkdirTemp("", "onenod-release-contract-")
	if err != nil {
		return errors.New("create release contract verification directory failed")
	}
	defer os.RemoveAll(destination)
	switch artifact.Kind {
	case "local":
		return extractReleaseArchive(path, destination, map[string]os.FileMode{
			"onenod/bin/may": 0o700, "onenod/bin/may-ssh-sign": 0o700,
		})
	case "keychain_helper":
		return extractReleaseArchive(path, destination, map[string]os.FileMode{
			"onenod-keychain-helper/bin/onenod-keychain-helper": 0o700,
		})
	case "deployment":
		if err := extractDeploymentBundleArchive(path, destination); err != nil {
			return err
		}
		_, err := validateStagedDeploymentBundle(
			filepath.Join(destination, "onenod-deployment"), manifest,
		)
		return err
	case "skill":
		return extractSkillArchive(path, destination)
	default:
		return nil
	}
}

type repeatedStringFlag []string

func (values *repeatedStringFlag) String() string { return strings.Join(*values, ",") }

func (values *repeatedStringFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("artifact name cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("file is missing, unsafe, empty, or oversized")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open file failed")
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(value)) != info.Size() || int64(len(value)) > limit {
		return nil, errors.New("read bounded file failed")
	}
	return value, nil
}

func runUpdate(args []string, deps dependencies) error {
	if len(args) > 0 && args[0] == "check" {
		return runUpdateCheck(args[1:], deps)
	}
	return runLocalUpdate(args, deps)
}

func runUpdateCheck(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("update check", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	channelValue := flags.String("channel", "", "release channel: stable, beta, or alpha")
	versionValue := flags.String("version", "", "exact immutable release version")
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateExplicitReleaseSelection(*channelValue, *versionValue); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may update check [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]] [--json]")
	}
	fallback := releaseChannelStable
	if receipt, found, err := readLocalInstallReceipt(); err != nil {
		return err
	} else if found {
		fallback = releaseChannel(receipt.Channel)
	}
	selection, err := releaseSelectionFromFlags(*channelValue, *versionValue, fallback)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), releaseRequestTimeout)
	defer cancel()
	release, err := resolveSelectedRelease(ctx, releaseSourceFor(deps), selection)
	if err != nil {
		return err
	}
	report, err := buildUpdateCheckReport(release, deps)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeIndentedValue(deps.stdout, report)
	}
	writeHumanUpdateReport(deps.stdout, report)
	return nil
}

func buildUpdateCheckReport(release *verifiedRelease, deps dependencies) (updateCheckReport, error) {
	manifest := release.Manifest
	report := updateCheckReport{
		Assurance: "verified_release_and_runtime_self_report",
		Channel:   string(selectedReleaseChannel(release)), LatestVersion: manifest.ReleaseVersion,
		MinimumSafeVersion: manifest.Support.MinimumSafeVersion,
		Plan:               []string{}, RequestedVersion: release.RequestedVersion,
		Warnings: []string{},
	}
	platform, platformErr := currentHostPlatform(deps)
	report.Platform = platform
	if platformErr == nil {
		platformErr = validateReleaseHostPlatform(manifest, platform)
	}
	if platformErr != nil {
		report.Status = "unsupported_platform"
		report.Warnings = append(report.Warnings, platformErr.Error())
		report.Plan = append(report.Plan, "use a supported macOS host before installing or updating OneNod")
		return report, nil
	}
	receipt, installed, err := readLocalInstallReceipt()
	if err != nil {
		return report, err
	}
	if !installed {
		report.Status = "mixed_installation"
		report.Plan = append(report.Plan, "install the verified local OneNod release")
		return report, nil
	}
	report.CurrentVersion = receipt.ReleaseVersion
	report.CurrentChannel = receipt.Channel
	report.Origin = receipt.Origin
	if compareProductVersions(manifest.ReleaseVersion, receipt.ReleaseVersion) < 0 {
		if awaitingCompatibleRelease(
			receipt.ReleaseVersion, releaseChannel(receipt.Channel),
			manifest.ReleaseVersion, selectedReleaseChannel(release),
		) {
			report.Status = "awaiting_compatible_release"
			report.Plan = append(report.Plan, fmt.Sprintf(
				"wait for the %s channel to publish version %s or newer; do not change local or remote state",
				report.Channel, receipt.ReleaseVersion,
			))
			return report, nil
		}
		return report, fmt.Errorf(
			"anti_rollback: latest official release %s is older than installed release %s",
			manifest.ReleaseVersion, receipt.ReleaseVersion,
		)
	}
	if manifest.ReleaseVersion == receipt.ReleaseVersion {
		if err := validateReceiptReleaseIdentity(receipt, manifest); err != nil {
			return report, fmt.Errorf("same_version_identity_mismatch: %w", err)
		}
	}
	if err := validateInstalledReceiptState(receipt); err != nil {
		report.Status = "mixed_installation"
		report.Warnings = append(report.Warnings, err.Error())
		report.Plan = append(report.Plan, "reconcile this Mac from the verified release")
		return report, nil
	}
	for name, digest := range receipt.Artifacts {
		for _, revoked := range manifest.RevokedArtifactDigests {
			if digest == revoked {
				report.Status = "incompatible"
				report.Warnings = append(report.Warnings, "installed artifact is revoked: "+name)
				report.Plan = append(report.Plan, "replace the revoked local release immediately")
				return report, nil
			}
		}
	}
	if compareProductVersions(receipt.ReleaseVersion, manifest.Support.MinimumSafeVersion) < 0 {
		report.Warnings = append(report.Warnings, "installed release is below minimum_safe_version")
	}
	if compareProductVersions(productVersion, manifest.Upgrade.MinimumUpdaterVersion) < 0 &&
		validProductVersion(productVersion) {
		report.Status = "unsupported_update_path"
		report.Plan = append(report.Plan, "install a supported bridge updater before continuing")
		return report, nil
	}
	helper, helperErr := inspectInstalledKeychainHelper()
	if helperErr != nil {
		report.Status = "mixed_installation"
		report.Plan = append(report.Plan, "install the independently versioned Keychain helper")
		return report, nil
	}
	if !protocolContains(manifest.Components.KeychainHelper.HelperProtocol, helper.Protocol) {
		report.Status = "incompatible"
		report.Plan = append(report.Plan, "perform the explicit Keychain helper security-component update")
		return report, nil
	}
	if !helperMatchesRelease(release, receipt, helper) {
		report.Status = "mixed_installation"
		report.Plan = append(report.Plan, "reconcile the Keychain helper from the exact verified release")
		return report, nil
	}
	remote, complete := readRemoteRuntimeVersion(receipt.Origin, deps.httpClient)
	report.Remote = remote
	if !complete {
		report.Status = "check_incomplete"
		report.Warnings = append(report.Warnings, "Gateway does not expose complete release metadata")
	} else if remote.AcceptedClientProtocol.Minimum > 0 &&
		!protocolContains(remote.AcceptedClientProtocol, manifest.Components.May.ClientProtocol) {
		report.Status = "incompatible"
		report.Plan = append(report.Plan, "deploy a compatible Gateway before updating local clients")
		return report, nil
	}
	localCurrent := receipt.ReleaseVersion == manifest.ReleaseVersion &&
		receipt.Channel == string(selectedReleaseChannel(release))
	remoteCurrent := remote.GatewayVersion == manifest.ReleaseVersion &&
		remote.ExecutorVersion == manifest.ReleaseVersion && remote.PwaVersion == manifest.ReleaseVersion
	if localCurrent && remoteCurrent {
		report.Status = "up_to_date"
		return report, nil
	}
	if report.Status == "" || report.Status == "check_incomplete" {
		if !localCurrent {
			report.Plan = append(report.Plan,
				"update this Mac to "+manifest.ReleaseVersion+" on the "+report.Channel+" channel")
		}
		if complete && !remoteCurrent {
			report.Plan = append(report.Plan, "run may operator update from the operator Mac")
		}
		if len(report.Plan) > 0 && report.Status != "check_incomplete" {
			report.Status = "update_available"
		}
	}
	return report, nil
}

func validateInstalledReceiptState(receipt *localInstallReceipt) error {
	if receipt == nil {
		return errors.New("local install receipt is unavailable")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve user home failed")
	}
	root := filepath.Join(home, userAgentDirectoryName)
	versionRoot := filepath.Join(root, "versions", receipt.ReleaseVersion)
	for relative, digest := range receipt.Files {
		name := strings.TrimPrefix(relative, "bin/")
		actual, err := regularFileSHA256(filepath.Join(versionRoot, name), maxReleaseArtifactBytes)
		if err != nil || actual != digest {
			return fmt.Errorf("installed %s bytes differ from the receipt", relative)
		}
		stable := filepath.Join(root, relative)
		if err := stableSymlinkResolvesTo(stable, filepath.Join(versionRoot, name)); err != nil {
			return err
		}
	}
	running, err := queryRunningAgentVersion(filepath.Join(root, "agent.sock"))
	if err != nil || running.Version != receipt.ReleaseVersion || running.SourceCommit != receipt.SourceCommit ||
		running.ClientProtocol != mayClientProtocol {
		return errors.New("running SSH Agent identity differs from the installed release receipt")
	}
	helper, err := inspectInstalledKeychainHelper()
	if err != nil || !installedHelperMatchesReceipt(receipt, helper) {
		return errors.New("installed Keychain helper identity differs from the receipt")
	}
	skillRoot := filepath.Join(root, "skill-versions", receipt.Skill.Version, "onenod")
	digest, err := directoryTreeSHA256(skillRoot)
	if err != nil || digest != receipt.Skill.TreeSHA256 {
		return errors.New("installed managed Skill bytes differ from the receipt")
	}
	if err := stableSymlinkResolvesTo(filepath.Join(root, "skill"), skillRoot); err != nil {
		return err
	}
	for _, relative := range receipt.Skill.Discovery {
		path := filepath.Join(home, strings.TrimPrefix(relative, "~/"))
		if err := stableSymlinkResolvesTo(path, filepath.Join(root, "skill")); err != nil {
			return err
		}
	}
	return nil
}

func stableSymlinkResolvesTo(path, expected string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("managed stable path %s is missing or not a symlink", path)
	}
	target, err := os.Readlink(path)
	if err != nil {
		return errors.New("read managed stable symlink failed")
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
	if resolved != filepath.Clean(expected) {
		return fmt.Errorf("managed stable path %s resolves outside its recorded version", path)
	}
	return nil
}

func validateReceiptReleaseIdentity(receipt *localInstallReceipt, manifest releaseManifest) error {
	if receipt == nil || receipt.SourceCommit != manifest.Source.Commit {
		return errors.New("installed source commit differs from the signed release manifest")
	}
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil || !releaseChannelAccepts(channel, releaseChannel(manifest.Channel)) {
		return errors.New("installed release channel does not accept the signed release manifest")
	}
	if len(receipt.Artifacts) == 0 {
		return errors.New("installed receipt contains no artifact digests")
	}
	manifestDigests := make(map[string]string, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		manifestDigests[artifact.Name] = artifact.SHA256
	}
	for name, digest := range receipt.Artifacts {
		if manifestDigests[name] != digest {
			return fmt.Errorf("installed artifact %q differs from the signed release manifest", name)
		}
	}
	return nil
}

func readRemoteRuntimeVersion(origin string, client *http.Client) (runtimeVersion, bool) {
	var response struct {
		Components struct {
			Executor struct {
				Channel string `json:"channel"`
				Version string `json:"version"`
			} `json:"executor"`
			Gateway struct {
				AcceptedClientProtocol protocolRange `json:"accepted_client_protocol"`
				Channel                string        `json:"channel"`
				Protocol               int           `json:"protocol"`
				Version                string        `json:"version"`
			} `json:"gateway"`
			PWA struct {
				Channel string `json:"channel"`
				Version string `json:"version"`
			} `json:"pwa"`
		} `json:"components"`
		ReleaseChannel string `json:"release_channel"`
		ReleaseVersion string `json:"release_version"`
	}
	if err := readPublicGatewayJSON(safePublicHTTPClient(client), origin, "/api/version", &response); err == nil {
		expectedChannel := releaseChannelForVersion(response.ReleaseVersion)
		remote := runtimeVersion{
			AcceptedClientProtocol: response.Components.Gateway.AcceptedClientProtocol,
			Channel:                response.ReleaseChannel,
			ExecutorVersion:        response.Components.Executor.Version,
			GatewayProtocol:        response.Components.Gateway.Protocol,
			GatewayVersion:         response.Components.Gateway.Version,
			PwaVersion:             response.Components.PWA.Version,
		}
		return remote, validProductVersion(response.ReleaseVersion) && validReleaseChannel(expectedChannel) &&
			releaseChannel(response.ReleaseChannel) == expectedChannel &&
			releaseChannel(response.Components.Gateway.Channel) == expectedChannel &&
			releaseChannel(response.Components.Executor.Channel) == expectedChannel &&
			releaseChannel(response.Components.PWA.Channel) == expectedChannel &&
			remote.GatewayVersion == response.ReleaseVersion &&
			remote.ExecutorVersion == response.ReleaseVersion &&
			remote.PwaVersion == response.ReleaseVersion
	}
	return runtimeVersion{}, false
}

func writeHumanUpdateReport(output io.Writer, report updateCheckReport) {
	fmt.Fprintf(output, "OneNod update status: %s\n", report.Status)
	fmt.Fprintf(output, "  channel: %s (official repository %s)\n", report.Channel, officialRepository)
	if report.CurrentVersion != "" {
		fmt.Fprintf(output, "  this Mac: %s (channel %s)\n", report.CurrentVersion, report.CurrentChannel)
	} else {
		fmt.Fprintln(output, "  this Mac: not installed from a verified release")
	}
	if report.RequestedVersion != "" {
		fmt.Fprintf(output, "  selected: %s (exact immutable release)\n", report.LatestVersion)
	} else {
		fmt.Fprintf(output, "  latest: %s\n", report.LatestVersion)
	}
	fmt.Fprintf(output, "  minimum safe: %s\n", report.MinimumSafeVersion)
	for _, warning := range report.Warnings {
		fmt.Fprintf(output, "  warning: %s\n", warning)
	}
	for _, step := range report.Plan {
		fmt.Fprintf(output, "  next: %s\n", step)
	}
}

func runLocalUpdate(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	channelValue := flags.String("channel", "", "release channel: stable, beta, or alpha")
	versionValue := flags.String("version", "", "exact immutable release version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateExplicitReleaseSelection(*channelValue, *versionValue); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may update [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]")
	}
	receipt, found, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	if !found {
		return errors.New("OneNod is not installed; run may install --origin https://<worker>.<account>.workers.dev")
	}
	currentChannel := releaseChannel(receipt.Channel)
	selection, err := releaseSelectionFromFlags(*channelValue, *versionValue, currentChannel)
	if err != nil {
		return err
	}
	channel := selection.Channel
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	release, err := resolveSelectedRelease(ctx, releaseSourceFor(deps), selection)
	if err != nil {
		return err
	}
	if err := requireSupportedReleaseHost(release.Manifest, deps); err != nil {
		return err
	}
	if compareProductVersions(release.Manifest.ReleaseVersion, receipt.ReleaseVersion) < 0 {
		if awaitingCompatibleRelease(
			receipt.ReleaseVersion, currentChannel,
			release.Manifest.ReleaseVersion, channel,
		) {
			writeAwaitingCompatibleRelease(
				deps.stdout, receipt.ReleaseVersion, currentChannel,
				release.Manifest.ReleaseVersion, channel,
			)
			return nil
		}
		return fmt.Errorf("anti_rollback: latest official release %s is older than installed release %s",
			release.Manifest.ReleaseVersion, receipt.ReleaseVersion)
	}
	if _, err := runningReleaseCanConsume(release.Manifest); err != nil {
		return err
	}
	if receipt.ReleaseVersion == release.Manifest.ReleaseVersion {
		if err := validateReceiptReleaseIdentity(receipt, release.Manifest); err != nil {
			return fmt.Errorf("same_version_identity_mismatch: %w", err)
		}
	}
	if err := confirmHigherRiskChannel(
		deps.stdin, deps.stdout, currentChannel, channel, "Local updates",
	); err != nil {
		return err
	}
	helperPlan := buildKeychainHelperUpdatePlan(release, receipt)
	includeHelper := helperPlan.Replace
	if includeHelper {
		writeKeychainHelperUpdatePlan(deps.stdout, helperPlan)
		confirmed, err := promptYesNo(deps.stdin, deps.stdout, "Update the OneNod Keychain helper now?", false)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("Keychain helper update was not approved; no local components were changed")
		}
	}
	return installVerifiedRelease(ctx, release, receipt.Origin, deps, includeHelper)
}

func buildKeychainHelperUpdatePlan(
	release *verifiedRelease,
	receipt *localInstallReceipt,
) keychainHelperUpdatePlan {
	plan := keychainHelperUpdatePlan{
		TargetProtocol:     release.Manifest.Components.KeychainHelper.HelperProtocol,
		TargetSourceDigest: release.Manifest.Components.KeychainHelper.SourceDigest,
		TargetVersion:      release.Manifest.Components.KeychainHelper.Version,
	}
	if receipt != nil {
		plan.CurrentProtocol = receipt.Helper.Protocol
		plan.CurrentSourceDigest = receipt.Helper.SourceDigest
		plan.CurrentVersion = receipt.Helper.Version
	}
	helper, err := inspectInstalledKeychainHelper()
	plan.Replace = err != nil || !helperMatchesRelease(release, receipt, helper)
	return plan
}

func writeKeychainHelperUpdatePlan(output io.Writer, plan keychainHelperUpdatePlan) {
	if !plan.Replace {
		fmt.Fprintf(output, "  Keychain helper: unchanged at %s (protocol %d; source %s)\n",
			plan.CurrentVersion, plan.CurrentProtocol, plan.CurrentSourceDigest)
		return
	}
	currentVersion := plan.CurrentVersion
	currentSource := plan.CurrentSourceDigest
	currentProtocol := "not installed"
	if currentVersion == "" {
		currentVersion = "not installed"
	}
	if currentSource == "" {
		currentSource = "not recorded"
	}
	if plan.CurrentProtocol > 0 {
		currentProtocol = strconv.Itoa(plan.CurrentProtocol)
	}
	fmt.Fprintf(output,
		"  Keychain helper: replace %s -> %s\n  Helper protocol: %s -> %d-%d\n  Helper source: %s -> %s\n  macOS may require a Keychain confirmation for this independently versioned security component.\n",
		currentVersion, plan.TargetVersion, currentProtocol,
		plan.TargetProtocol.Minimum, plan.TargetProtocol.Maximum,
		currentSource, plan.TargetSourceDigest,
	)
}

func runBinaryInstall(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	channelValue := flags.String("channel", "", "release channel: stable, beta, or alpha")
	versionValue := flags.String("version", "", "exact immutable release version")
	origin := flags.String("origin", "", "public workers.dev Gateway origin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateExplicitReleaseSelection(*channelValue, *versionValue); err != nil {
		return err
	}
	if flags.NArg() != 0 || *origin == "" {
		return errors.New("usage: may install --origin https://<worker>.<account>.workers.dev [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]")
	}
	parsed, err := parseGatewayOrigin(*origin)
	if err != nil || !workersDevHostPattern.MatchString(parsed.Host) {
		return errors.New("install Origin must be a normalized workers.dev HTTPS origin")
	}
	existing, found, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	if found && existing.Origin != *origin {
		return fmt.Errorf("existing OneNod installation targets %s; refusing to switch to %s", existing.Origin, *origin)
	}
	currentChannel := releaseChannelStable
	currentVersion := ""
	if found {
		currentChannel = releaseChannel(existing.Channel)
		currentVersion = existing.ReleaseVersion
	} else if initializer, initializerFound, initializerErr := readInitializerInstallReceipt(); initializerErr != nil {
		return initializerErr
	} else if initializerFound {
		currentChannel = releaseChannel(initializer.Channel)
		currentVersion = initializer.ReleaseVersion
	}
	selection, err := releaseSelectionFromFlags(*channelValue, *versionValue, currentChannel)
	if err != nil {
		return err
	}
	channel := selection.Channel
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	release, err := resolveSelectedRelease(ctx, releaseSourceFor(deps), selection)
	if err != nil {
		return err
	}
	if err := requireSupportedReleaseHost(release.Manifest, deps); err != nil {
		return err
	}
	if currentVersion != "" && compareProductVersions(release.Manifest.ReleaseVersion, currentVersion) < 0 {
		if awaitingCompatibleRelease(
			currentVersion, currentChannel,
			release.Manifest.ReleaseVersion, channel,
		) {
			writeAwaitingCompatibleRelease(
				deps.stdout, currentVersion, currentChannel,
				release.Manifest.ReleaseVersion, channel,
			)
			return nil
		}
		return fmt.Errorf("anti_rollback: selected official release %s is older than installed release %s",
			release.Manifest.ReleaseVersion, currentVersion)
	}
	if _, err := runningReleaseCanConsume(release.Manifest); err != nil {
		return err
	}
	if err := confirmHigherRiskChannel(
		deps.stdin, deps.stdout, currentChannel, channel, "Local installation",
	); err != nil {
		return err
	}
	return installVerifiedRelease(ctx, release, *origin, deps, true)
}

func installVerifiedRelease(
	ctx context.Context,
	release *verifiedRelease,
	origin string,
	deps dependencies,
	includeHelper bool,
) error {
	if err := requireSupportedReleaseHost(release.Manifest, deps); err != nil {
		return err
	}
	localName, err := localArtifactName()
	if err != nil {
		return err
	}
	localArtifact, err := artifactFor(release, localName)
	if err != nil {
		return err
	}
	stage, err := privateStagingDirectory()
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	localArchive, err := downloadVerifiedArtifact(ctx, release, localArtifact, stage)
	if err != nil {
		return err
	}
	localExtract := filepath.Join(stage, "local")
	if err := os.Mkdir(localExtract, 0o700); err != nil {
		return errors.New("create local release extraction directory failed")
	}
	if err := extractReleaseArchive(localArchive, localExtract, map[string]os.FileMode{
		"onenod/bin/may": 0o700, "onenod/bin/may-ssh-sign": 0o700,
	}); err != nil {
		return err
	}
	skillArtifact, err := artifactFor(release, skillArtifactName(release.Manifest.ReleaseVersion))
	if err != nil {
		return err
	}
	skillArchive, err := downloadVerifiedArtifact(ctx, release, skillArtifact, stage)
	if err != nil {
		return err
	}
	skillExtract := filepath.Join(stage, "skill")
	if err := os.Mkdir(skillExtract, 0o700); err != nil {
		return errors.New("create Skill release extraction directory failed")
	}
	if err := extractSkillArchive(skillArchive, skillExtract); err != nil {
		return err
	}
	previous, _, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	helperResponse, helperErr := inspectInstalledKeychainHelper()
	helperCompatible := helperErr == nil && helperMatchesRelease(release, previous, helperResponse)
	var helperSource string
	var helperArtifact releaseArtifact
	if !helperCompatible {
		if !includeHelper {
			return errors.New("verified release requires an explicit Keychain helper update; rerun may install after reviewing the helper change")
		}
		helperName, err := helperArtifactName(release.Manifest.Components.KeychainHelper.Version)
		if err != nil {
			return err
		}
		helperArtifact, err = artifactFor(release, helperName)
		if err != nil {
			return err
		}
		helperArchive, err := downloadVerifiedArtifact(ctx, release, helperArtifact, stage)
		if err != nil {
			return err
		}
		helperExtract := filepath.Join(stage, "helper")
		if err := os.Mkdir(helperExtract, 0o700); err != nil {
			return errors.New("create helper release extraction directory failed")
		}
		if err := extractReleaseArchive(helperArchive, helperExtract, map[string]os.FileMode{
			"onenod-keychain-helper/bin/onenod-keychain-helper": 0o700,
		}); err != nil {
			return err
		}
		helperSource = filepath.Join(helperExtract, "onenod-keychain-helper", "bin", keychainHelperBinaryName)
	}
	return activateVerifiedLocalRelease(
		release, origin,
		filepath.Join(localExtract, "onenod", "bin", "may"),
		filepath.Join(localExtract, "onenod", "bin", gitSignAdapterBinaryName),
		filepath.Join(skillExtract, "onenod-skill", "onenod"),
		helperSource, localArtifact, helperArtifact, skillArtifact, helperResponse, previous, deps,
	)
}

func installVerifiedInitializer(
	ctx context.Context,
	release *verifiedRelease,
	deps dependencies,
) error {
	if err := requireSupportedReleaseHost(release.Manifest, deps); err != nil {
		return err
	}
	localName, err := localArtifactName()
	if err != nil {
		return err
	}
	localArtifact, err := artifactFor(release, localName)
	if err != nil {
		return err
	}
	skillArtifact, err := artifactFor(release, skillArtifactName(release.Manifest.ReleaseVersion))
	if err != nil {
		return err
	}
	helperName, err := helperArtifactName(release.Manifest.Components.KeychainHelper.Version)
	if err != nil {
		return err
	}
	helperArtifact, err := artifactFor(release, helperName)
	if err != nil {
		return err
	}
	stage, err := privateStagingDirectory()
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)

	localArchive, err := downloadVerifiedArtifact(ctx, release, localArtifact, stage)
	if err != nil {
		return err
	}
	localExtract := filepath.Join(stage, "local")
	if err := os.Mkdir(localExtract, 0o700); err != nil {
		return errors.New("create initializer release extraction directory failed")
	}
	if err := extractReleaseArchive(localArchive, localExtract, map[string]os.FileMode{
		"onenod/bin/may": 0o700, "onenod/bin/may-ssh-sign": 0o700,
	}); err != nil {
		return err
	}

	skillArchive, err := downloadVerifiedArtifact(ctx, release, skillArtifact, stage)
	if err != nil {
		return err
	}
	skillExtract := filepath.Join(stage, "skill")
	if err := os.Mkdir(skillExtract, 0o700); err != nil {
		return errors.New("create initializer Skill extraction directory failed")
	}
	if err := extractSkillArchive(skillArchive, skillExtract); err != nil {
		return err
	}

	helperArchive, err := downloadVerifiedArtifact(ctx, release, helperArtifact, stage)
	if err != nil {
		return err
	}
	helperExtract := filepath.Join(stage, "helper")
	if err := os.Mkdir(helperExtract, 0o700); err != nil {
		return errors.New("create initializer helper extraction directory failed")
	}
	if err := extractReleaseArchive(helperArchive, helperExtract, map[string]os.FileMode{
		"onenod-keychain-helper/bin/onenod-keychain-helper": 0o700,
	}); err != nil {
		return err
	}

	return activateVerifiedInitializer(
		release,
		filepath.Join(localExtract, "onenod", "bin", "may"),
		filepath.Join(localExtract, "onenod", "bin", gitSignAdapterBinaryName),
		filepath.Join(skillExtract, "onenod-skill", "onenod"),
		filepath.Join(helperExtract, "onenod-keychain-helper", "bin", keychainHelperBinaryName),
		localArtifact, skillArtifact, helperArtifact, deps,
	)
}

func activateVerifiedInitializer(
	release *verifiedRelease,
	maySource, adapterSource, skillSource, helperSource string,
	localArtifact, skillArtifact, helperArtifact releaseArtifact,
	deps dependencies,
) (returnErr error) {
	if !protocolContains(release.Manifest.Components.KeychainHelper.HelperProtocol, keychainHelperProtocol) {
		return errors.New("verified initializer helper protocol is incompatible with the running may")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve user home for initializer activation failed")
	}
	root := filepath.Join(home, userAgentDirectoryName)
	for _, directory := range []string{
		root, filepath.Join(root, "bin"), filepath.Join(root, "libexec"),
		filepath.Join(root, "versions"), filepath.Join(root, "helper-versions"),
		filepath.Join(root, "skill-versions"),
	} {
		if err := ensurePrivateInstallDirectory(directory); err != nil {
			return err
		}
	}
	previousLocal, _, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	previousInitializer, initializerFound, err := readInitializerInstallReceipt()
	if err != nil {
		return err
	}
	if previousLocal == nil && initializerFound {
		previousLocal = &localInstallReceipt{}
		previousLocal.Helper.Version = previousInitializer.HelperVersion
		previousLocal.Helper.BinarySHA256 = previousInitializer.Files["libexec/"+keychainHelperBinaryName]
	}
	versionDirectory := filepath.Join(root, "versions", release.Manifest.ReleaseVersion)
	if err := installVersionDirectory(versionDirectory, map[string]string{
		"may": maySource, gitSignAdapterBinaryName: adapterSource,
	}); err != nil {
		return err
	}
	skillDirectory := filepath.Join(root, "skill-versions", release.Manifest.ReleaseVersion, "onenod")
	if err := installTreeDirectory(skillDirectory, skillSource); err != nil {
		return err
	}
	helperDirectory := filepath.Join(root, "helper-versions", release.Manifest.Components.KeychainHelper.Version)
	if err := installVersionDirectory(helperDirectory, map[string]string{
		keychainHelperBinaryName: helperSource,
	}); err != nil {
		return err
	}

	var helperRollback *helperReplacement
	defer func() {
		if returnErr == nil || helperRollback == nil {
			return
		}
		if rollbackErr := helperRollback.rollback(); rollbackErr != nil {
			returnErr = fmt.Errorf("%w; initializer helper rollback also failed: %v", returnErr, rollbackErr)
		}
	}()
	helperRollback, err = activateStableHelper(
		filepath.Join(root, "libexec", keychainHelperBinaryName),
		filepath.Join(helperDirectory, keychainHelperBinaryName), previousLocal,
	)
	if err != nil {
		return err
	}
	helper, err := inspectInstalledKeychainHelper()
	if err != nil || helper.Version != release.Manifest.Components.KeychainHelper.Version ||
		helper.Protocol != keychainHelperProtocol {
		return errors.New("verified initializer Keychain helper failed exact identity verification")
	}

	managedLinks := []string{
		filepath.Join(root, "bin", "may"),
		filepath.Join(root, "bin", gitSignAdapterBinaryName),
		filepath.Join(root, "skill"),
	}
	previousLinks, err := captureManagedSymlinks(managedLinks)
	if err != nil {
		return err
	}
	promotionStarted := true
	var discoveryTransaction *skillDiscoveryTransaction
	defer func() {
		if returnErr == nil || !promotionStarted {
			return
		}
		var failures []error
		if rollbackErr := restoreManagedSymlinks(previousLinks); rollbackErr != nil {
			failures = append(failures, rollbackErr)
		}
		if rollbackErr := discoveryTransaction.rollback(); rollbackErr != nil {
			failures = append(failures, rollbackErr)
		}
		if len(failures) > 0 {
			returnErr = fmt.Errorf("%w; initializer stable-path rollback also failed: %v", returnErr, errors.Join(failures...))
		}
	}()
	if err := replaceStableSymlink(filepath.Join(root, "bin", "may"),
		filepath.Join("..", "versions", release.Manifest.ReleaseVersion, "may")); err != nil {
		return err
	}
	if err := replaceStableSymlink(filepath.Join(root, "bin", gitSignAdapterBinaryName),
		filepath.Join("..", "versions", release.Manifest.ReleaseVersion, gitSignAdapterBinaryName)); err != nil {
		return err
	}
	if err := replaceStableSymlink(filepath.Join(root, "skill"),
		filepath.Join("skill-versions", release.Manifest.ReleaseVersion, "onenod")); err != nil {
		return err
	}
	skillDigest, err := directoryTreeSHA256(skillSource)
	if err != nil {
		return err
	}
	_, discoveryTransaction, err = installSkillDiscoveryLinks(home, filepath.Join(root, "skill"), skillDigest)
	if err != nil {
		return err
	}
	receipt := initializerInstallReceipt{
		AdoptedBackups: discoveryTransaction.backupPaths(),
		Artifacts: map[string]string{
			localArtifact.Name:  localArtifact.SHA256,
			skillArtifact.Name:  skillArtifact.SHA256,
			helperArtifact.Name: helperArtifact.SHA256,
		},
		Channel: string(selectedReleaseChannel(release)), Files: map[string]string{}, HelperProtocol: helper.Protocol,
		HelperVersion: helper.Version, InstalledAt: time.Now().UTC().Format(time.RFC3339),
		ReleaseVersion: release.Manifest.ReleaseVersion, SchemaVersion: initializerReceiptSchema,
		SkillTreeSHA: skillDigest, SourceCommit: release.Manifest.Source.Commit,
	}
	if initializerFound {
		receipt.AdoptedBackups = append(previousInitializer.AdoptedBackups, receipt.AdoptedBackups...)
	}
	for relative, path := range map[string]string{
		"bin/may":                             maySource,
		"bin/" + gitSignAdapterBinaryName:     adapterSource,
		"libexec/" + keychainHelperBinaryName: filepath.Join(root, "libexec", keychainHelperBinaryName),
	} {
		receipt.Files[relative], err = regularFileSHA256(path, maxReleaseArtifactBytes)
		if err != nil {
			return err
		}
	}
	receiptPath, err := initializerReceiptPath()
	if err != nil {
		return err
	}
	if err := writeAtomicPrivateJSON(receiptPath, receipt); err != nil {
		return err
	}
	promotionStarted = false
	fmt.Fprintf(deps.stdout, "Installed verified OneNod initializer %s before production authorization.\n", release.Manifest.ReleaseVersion)
	return nil
}

func activateVerifiedLocalRelease(
	release *verifiedRelease,
	origin, maySource, adapterSource, skillSource, helperSource string,
	localArtifact, helperArtifact, skillArtifact releaseArtifact,
	existingHelper keychainHelperResponse,
	previous *localInstallReceipt,
	deps dependencies,
) (returnErr error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve user home for OneNod activation failed")
	}
	root := filepath.Join(home, userAgentDirectoryName)
	for _, directory := range []string{
		root, filepath.Join(root, "bin"), filepath.Join(root, "libexec"),
		filepath.Join(root, "versions"), filepath.Join(root, "helper-versions"),
		filepath.Join(root, "skill-versions"),
		filepath.Join(root, "logs"), filepath.Join(root, "ssh"),
	} {
		if err := ensurePrivateInstallDirectory(directory); err != nil {
			return err
		}
	}
	var helperRollback *helperReplacement
	defer func() {
		if returnErr == nil || helperRollback == nil {
			return
		}
		if rollbackErr := helperRollback.rollback(); rollbackErr != nil {
			returnErr = fmt.Errorf("%w; Keychain helper rollback also failed: %v", returnErr, rollbackErr)
		}
	}()
	versionDirectory := filepath.Join(root, "versions", release.Manifest.ReleaseVersion)
	if err := installVersionDirectory(versionDirectory, map[string]string{
		"may": maySource, gitSignAdapterBinaryName: adapterSource,
	}); err != nil {
		return err
	}
	skillDirectory := filepath.Join(root, "skill-versions", release.Manifest.ReleaseVersion, "onenod")
	if err := installTreeDirectory(skillDirectory, skillSource); err != nil {
		return err
	}
	skillTreeDigest, err := directoryTreeSHA256(skillSource)
	if err != nil {
		return err
	}
	helperVersion := existingHelper.Version
	helperProtocol := existingHelper.Protocol
	if helperSource != "" {
		helperVersion = release.Manifest.Components.KeychainHelper.Version
		helperProtocol = release.Manifest.Components.KeychainHelper.HelperProtocol.Minimum
		helperDirectory := filepath.Join(root, "helper-versions", helperVersion)
		if err := installVersionDirectory(helperDirectory, map[string]string{
			keychainHelperBinaryName: helperSource,
		}); err != nil {
			return err
		}
		helperRollback, err = activateStableHelper(
			filepath.Join(root, "libexec", keychainHelperBinaryName),
			filepath.Join(helperDirectory, keychainHelperBinaryName),
			previous,
		)
		if err != nil {
			return err
		}
		activated, err := inspectInstalledKeychainHelper()
		if err != nil {
			return fmt.Errorf("activated Keychain helper inspection failed: %w", err)
		}
		if activated.Version != helperVersion {
			return fmt.Errorf(
				"activated Keychain helper version mismatch: expected %s, got %s",
				helperVersion, activated.Version,
			)
		}
		if !protocolContains(release.Manifest.Components.KeychainHelper.HelperProtocol, activated.Protocol) {
			return fmt.Errorf(
				"activated Keychain helper protocol %d is outside the verified Release range %d-%d",
				activated.Protocol,
				release.Manifest.Components.KeychainHelper.HelperProtocol.Minimum,
				release.Manifest.Components.KeychainHelper.HelperProtocol.Maximum,
			)
		}
		helperProtocol = activated.Protocol
	}
	managedLinks := []string{
		filepath.Join(root, "bin", "may"),
		filepath.Join(root, "bin", gitSignAdapterBinaryName),
		filepath.Join(root, "skill"),
	}
	previousLinks, err := captureManagedSymlinks(managedLinks)
	if err != nil {
		return err
	}
	managedFiles := []string{
		filepath.Join(root, userAgentEnvFileName),
		filepath.Join(home, "Library", "LaunchAgents", oneNodAgentLabel+".plist"),
	}
	previousFiles, err := captureManagedFiles(managedFiles)
	if err != nil {
		return err
	}
	promotionStarted := true
	agentActivationStarted := false
	var discoveryTransaction *skillDiscoveryTransaction
	defer func() {
		if returnErr == nil || !promotionStarted {
			return
		}
		var rollbackErrors []error
		if agentActivationStarted {
			domain := fmt.Sprintf("gui/%d", os.Getuid())
			output, rollbackErr := runLaunchctl("bootout", domain+"/"+oneNodAgentLabel)
			zeroBytes(output)
			if rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, errors.New("stop partially activated SSH Agent failed"))
			}
		}
		if rollbackErr := restoreManagedSymlinks(previousLinks); rollbackErr != nil {
			rollbackErrors = append(rollbackErrors, rollbackErr)
		}
		if rollbackErr := discoveryTransaction.rollback(); rollbackErr != nil {
			rollbackErrors = append(rollbackErrors, rollbackErr)
		}
		if rollbackErr := restoreManagedFiles(previousFiles); rollbackErr != nil {
			rollbackErrors = append(rollbackErrors, rollbackErr)
		}
		if agentActivationStarted && previous != nil {
			oldPlan := &userCLIInstallPlan{
				binaryPath:      filepath.Join(root, "bin", "may"),
				adapterPath:     filepath.Join(root, "bin", gitSignAdapterBinaryName),
				launchAgentPath: filepath.Join(home, "Library", "LaunchAgents", oneNodAgentLabel+".plist"),
				socketPath:      filepath.Join(root, "agent.sock"),
			}
			if rollbackErr := activateApprovalAgent(oldPlan); rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("prior SSH Agent restart failed: %w", rollbackErr))
			}
		}
		if len(rollbackErrors) > 0 {
			returnErr = fmt.Errorf("%w; local activation rollback also failed: %v", returnErr, errors.Join(rollbackErrors...))
		}
	}()
	if err := replaceStableSymlink(filepath.Join(root, "bin", "may"),
		filepath.Join("..", "versions", release.Manifest.ReleaseVersion, "may")); err != nil {
		return err
	}
	if err := replaceStableSymlink(filepath.Join(root, "bin", gitSignAdapterBinaryName),
		filepath.Join("..", "versions", release.Manifest.ReleaseVersion, gitSignAdapterBinaryName)); err != nil {
		return err
	}
	if err := replaceStableSymlink(filepath.Join(root, "skill"),
		filepath.Join("skill-versions", release.Manifest.ReleaseVersion, "onenod")); err != nil {
		return err
	}
	discovery, discoveryTransaction, err := installSkillDiscoveryLinks(
		home, filepath.Join(root, "skill"), skillTreeDigest,
	)
	if err != nil {
		return err
	}
	if err := installOriginAndLaunchAgent(root, origin, home); err != nil {
		return err
	}
	receiptPath, err := localReceiptPath()
	if err != nil {
		return err
	}
	receipt := localInstallReceipt{
		Artifacts: map[string]string{
			localArtifact.Name: localArtifact.SHA256,
			skillArtifact.Name: skillArtifact.SHA256,
		},
		Channel:     string(selectedReleaseChannel(release)),
		Files:       map[string]string{},
		InstalledAt: time.Now().UTC().Format(time.RFC3339), Origin: origin,
		ReleaseVersion: release.Manifest.ReleaseVersion, SourceCommit: release.Manifest.Source.Commit,
	}
	for relative, path := range map[string]string{
		"bin/may": maySource, "bin/" + gitSignAdapterBinaryName: adapterSource,
	} {
		digest, err := regularFileSHA256(path, maxReleaseArtifactBytes)
		if err != nil {
			return err
		}
		receipt.Files[relative] = digest
	}
	receipt.Skill.Artifact = skillArtifact.Name
	receipt.Skill.ArtifactSHA = skillArtifact.SHA256
	receipt.Skill.Discovery = discovery
	if previous != nil {
		receipt.Skill.AdoptedBackups = append(receipt.Skill.AdoptedBackups, previous.Skill.AdoptedBackups...)
	} else if initializer, found, readErr := readInitializerInstallReceipt(); readErr != nil {
		return readErr
	} else if found {
		receipt.Skill.AdoptedBackups = append(receipt.Skill.AdoptedBackups, initializer.AdoptedBackups...)
	}
	receipt.Skill.AdoptedBackups = append(receipt.Skill.AdoptedBackups, discoveryTransaction.backupPaths()...)
	receipt.Skill.Version = release.Manifest.Components.Skill.Version
	receipt.Skill.TreeSHA256 = skillTreeDigest
	if helperArtifact.Name != "" {
		receipt.Artifacts[helperArtifact.Name] = helperArtifact.SHA256
		receipt.Helper.Artifact = helperArtifact.Name
		receipt.Helper.ArtifactSHA = helperArtifact.SHA256
	} else if previous != nil {
		receipt.Helper.Artifact = previous.Helper.Artifact
		receipt.Helper.ArtifactSHA = previous.Helper.ArtifactSHA
		if receipt.Helper.Artifact != "" {
			receipt.Artifacts[receipt.Helper.Artifact] = receipt.Helper.ArtifactSHA
		}
	}
	receipt.Helper.Protocol = helperProtocol
	receipt.Helper.SourceDigest = release.Manifest.Components.KeychainHelper.SourceDigest
	receipt.Helper.Version = helperVersion
	receipt.Helper.BinarySHA256, err = regularFileSHA256(
		filepath.Join(root, "libexec", keychainHelperBinaryName), maxReleaseArtifactBytes,
	)
	if err != nil {
		return err
	}
	plan := &userCLIInstallPlan{
		binaryPath:      filepath.Join(root, "bin", "may"),
		adapterPath:     filepath.Join(root, "bin", gitSignAdapterBinaryName),
		launchAgentPath: filepath.Join(home, "Library", "LaunchAgents", oneNodAgentLabel+".plist"),
		socketPath:      filepath.Join(root, "agent.sock"),
	}
	agentActivationStarted = true
	if err := activateApprovalAgent(plan); err != nil {
		return err
	}
	if err := writeLocalInstallReceipt(receiptPath, receipt); err != nil {
		return err
	}
	promotionStarted = false
	fmt.Fprintf(deps.stdout, "Installed OneNod %s for %s.\n", release.Manifest.ReleaseVersion, origin)
	fmt.Fprintf(deps.stdout, "Requester CLI: %s\n", plan.binaryPath)
	fmt.Fprintf(deps.stdout, "Keychain helper %s (protocol %d) remains independently versioned.\n", helperVersion, helperProtocol)
	if previous == nil {
		fmt.Fprintln(deps.stdout, "OpenSSH and Git signing configuration were not changed.")
		fmt.Fprintln(deps.stdout, "Optional integrations (each requires a separate human confirmation):")
		fmt.Fprintf(deps.stdout, "  %s configure ssh apply\n", plan.binaryPath)
		fmt.Fprintf(deps.stdout, "  %s configure git-signing apply --signing-key <SSH-public-key-or-path>\n", plan.binaryPath)
	}
	return nil
}

func installVersionDirectory(destination string, sources map[string]string) error {
	if info, err := os.Stat(destination); err == nil && info.IsDir() {
		entries, err := os.ReadDir(destination)
		if err != nil || len(entries) != len(sources) {
			return errors.New("existing version directory does not exactly match the verified release")
		}
		for name, source := range sources {
			target := filepath.Join(destination, name)
			fileInfo, err := os.Lstat(target)
			if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 ||
				fileInfo.Mode().Perm() != 0o700 {
				return errors.New("existing version directory is incomplete or unsafe")
			}
			sourceDigest, err := regularFileSHA256(source, maxReleaseArtifactBytes)
			if err != nil {
				return err
			}
			targetDigest, err := regularFileSHA256(target, maxReleaseArtifactBytes)
			if err != nil || targetDigest != sourceDigest {
				return errors.New("existing version directory bytes differ from the verified release")
			}
		}
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect version directory failed")
	}
	parent := filepath.Dir(destination)
	stage, err := os.MkdirTemp(parent, ".version-")
	if err != nil {
		return errors.New("stage version directory failed")
	}
	defer os.RemoveAll(stage)
	for name, source := range sources {
		target := filepath.Join(stage, name)
		input, err := os.Open(source)
		if err != nil {
			return errors.New("open verified release binary failed")
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
		if err != nil {
			input.Close()
			return errors.New("stage verified release binary failed")
		}
		_, copyErr := io.Copy(output, io.LimitReader(input, maxReleaseArtifactBytes+1))
		input.Close()
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil {
			return errors.New("copy verified release binary failed")
		}
	}
	if err := os.Rename(stage, destination); err != nil {
		return errors.New("activate immutable version directory failed")
	}
	return nil
}

func installTreeDirectory(destination, source string) error {
	sourceDigest, err := directoryTreeSHA256(source)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(destination); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("existing Skill version path is unsafe")
		}
		destinationDigest, err := directoryTreeSHA256(destination)
		if err != nil || destinationDigest != sourceDigest {
			return errors.New("existing Skill version bytes differ from the verified release")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect Skill version directory failed")
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return errors.New("create Skill version parent failed")
	}
	stage, err := os.MkdirTemp(parent, ".skill-")
	if err != nil {
		return errors.New("stage Skill version failed")
	}
	defer os.RemoveAll(stage)
	if err := copyRegularTree(source, stage); err != nil {
		return err
	}
	if err := os.Rename(stage, destination); err != nil {
		return errors.New("activate immutable Skill version failed")
	}
	return nil
}

func copyRegularTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("walk verified Skill tree failed")
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("verified Skill tree contains a symlink")
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.Mkdir(target, 0o700)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("verified Skill tree contains a non-regular file")
		}
		input, err := os.Open(path)
		if err != nil {
			return errors.New("open verified Skill file failed")
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			input.Close()
			return errors.New("stage verified Skill file failed")
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, maxReleaseArtifactBytes+1))
		input.Close()
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != info.Size() {
			return errors.New("copy verified Skill file failed")
		}
		return nil
	})
}

func regularFileSHA256(path string, limit int64) (string, error) {
	value, err := readBoundedRegularFile(path, limit)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func directoryTreeSHA256(root string) (string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("tree contains a symlink")
		}
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxReleaseArtifactBytes {
				return errors.New("tree contains an unsafe file")
			}
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil || len(paths) == 0 || len(paths) > 4096 {
		return "", errors.New("inspect verified tree failed")
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, path := range paths {
		relative, _ := filepath.Rel(root, path)
		digest, err := regularFileSHA256(path, maxReleaseArtifactBytes)
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(hash, filepath.ToSlash(relative))
		_, _ = hash.Write([]byte{0})
		_, _ = io.WriteString(hash, digest)
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func installedHelperMatchesReceipt(receipt *localInstallReceipt, helper keychainHelperResponse) bool {
	if receipt == nil || receipt.Helper.Version != helper.Version ||
		receipt.Helper.Protocol != helper.Protocol || receipt.Helper.Artifact == "" ||
		!digestPattern.MatchString(receipt.Helper.ArtifactSHA) ||
		!digestPattern.MatchString(receipt.Helper.BinarySHA256) {
		return false
	}
	path, err := installedKeychainHelperPath()
	if err != nil {
		return false
	}
	digest, err := regularFileSHA256(path, maxReleaseArtifactBytes)
	return err == nil && digest == receipt.Helper.BinarySHA256 &&
		receipt.Artifacts[receipt.Helper.Artifact] == receipt.Helper.ArtifactSHA
}

func helperMatchesRelease(
	release *verifiedRelease,
	receipt *localInstallReceipt,
	helper keychainHelperResponse,
) bool {
	if release == nil || receipt == nil ||
		helper.Version != release.Manifest.Components.KeychainHelper.Version ||
		receipt.Helper.Version != release.Manifest.Components.KeychainHelper.Version ||
		receipt.Helper.SourceDigest != release.Manifest.Components.KeychainHelper.SourceDigest ||
		!protocolContains(release.Manifest.Components.KeychainHelper.HelperProtocol, helper.Protocol) ||
		!installedHelperMatchesReceipt(receipt, helper) {
		return false
	}
	name, err := helperArtifactName(release.Manifest.Components.KeychainHelper.Version)
	if err != nil || receipt.Helper.Artifact != name {
		return false
	}
	artifact, err := artifactFor(release, name)
	return err == nil && artifact.SHA256 == receipt.Helper.ArtifactSHA
}

func replaceStableSymlink(path, target string) error {
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("refusing to replace unmanaged non-symlink path %s", path)
		}
		oldTarget, err := os.Readlink(path)
		home, homeErr := os.UserHomeDir()
		managedRoot := filepath.Join(home, userAgentDirectoryName)
		resolved := filepath.Clean(filepath.Join(filepath.Dir(path), oldTarget))
		relative, relativeErr := filepath.Rel(managedRoot, resolved)
		if err != nil || homeErr != nil || filepath.IsAbs(oldTarget) || relativeErr != nil ||
			relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("refusing to replace unsafe managed symlink %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect stable OneNod path failed")
	}
	directory := filepath.Dir(path)
	temporary := filepath.Join(directory, ".link-"+filepath.Base(path)+"-new")
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return errors.New("stage stable OneNod path failed")
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("activate stable OneNod path failed")
	}
	return nil
}

type managedSymlinkSnapshot struct {
	Exists bool
	Path   string
	Target string
}

type managedFileSnapshot struct {
	Content []byte
	Exists  bool
	Mode    os.FileMode
	Path    string
}

func captureManagedFiles(paths []string) ([]managedFileSnapshot, error) {
	result := make([]managedFileSnapshot, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			result = append(result, managedFileSnapshot{Path: path})
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Size() <= 0 || info.Size() > maxManifestBytes {
			return nil, fmt.Errorf("managed file %s is unsafe", path)
		}
		content, err := readBoundedRegularFile(path, maxManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("capture managed file %s failed", path)
		}
		result = append(result, managedFileSnapshot{
			Content: content, Exists: true, Mode: info.Mode().Perm(), Path: path,
		})
	}
	return result, nil
}

func restoreManagedFiles(snapshots []managedFileSnapshot) error {
	var failures []error
	for _, snapshot := range snapshots {
		if !snapshot.Exists {
			if err := os.Remove(snapshot.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				failures = append(failures, fmt.Errorf("remove newly created managed file %s failed", snapshot.Path))
			}
			continue
		}
		if err := writeAtomicUserConfig(snapshot.Path, snapshot.Content, snapshot.Mode); err != nil {
			failures = append(failures, fmt.Errorf("restore managed file %s failed: %w", snapshot.Path, err))
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	return nil
}

func captureManagedSymlinks(paths []string) ([]managedSymlinkSnapshot, error) {
	result := make([]managedSymlinkSnapshot, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			result = append(result, managedSymlinkSnapshot{Path: path})
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			return nil, fmt.Errorf("managed path %s is occupied by non-OneNod content", path)
		}
		target, err := os.Readlink(path)
		if err != nil {
			return nil, errors.New("read managed symlink before activation failed")
		}
		result = append(result, managedSymlinkSnapshot{Exists: true, Path: path, Target: target})
	}
	return result, nil
}

func restoreManagedSymlinks(snapshots []managedSymlinkSnapshot) error {
	for _, snapshot := range snapshots {
		if err := os.Remove(snapshot.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("remove promoted managed symlink failed")
		}
		if !snapshot.Exists {
			continue
		}
		if err := os.Symlink(snapshot.Target, snapshot.Path); err != nil {
			return errors.New("restore prior managed symlink failed")
		}
	}
	return nil
}

type skillDiscoveryChange struct {
	Backup string
	Path   string
}

type skillDiscoveryTransaction struct {
	changes []skillDiscoveryChange
}

func (transaction *skillDiscoveryTransaction) rollback() error {
	if transaction == nil {
		return nil
	}
	for index := len(transaction.changes) - 1; index >= 0; index-- {
		change := transaction.changes[index]
		if err := os.Remove(change.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("remove managed Skill discovery link during rollback failed")
		}
		if change.Backup != "" {
			if err := os.Rename(change.Backup, change.Path); err != nil {
				return errors.New("restore adopted Skill during rollback failed")
			}
		}
	}
	return nil
}

func (transaction *skillDiscoveryTransaction) backupPaths() []string {
	var result []string
	if transaction == nil {
		return result
	}
	for _, change := range transaction.changes {
		if change.Backup != "" {
			result = append(result, change.Backup)
		}
	}
	return result
}

func installSkillDiscoveryLinks(
	home, stableSkill, expectedTreeDigest string,
) ([]string, *skillDiscoveryTransaction, error) {
	entries := []string{"~/.agents/skills/onenod", "~/.claude/skills/onenod"}
	type candidate struct {
		adopt bool
		path  string
	}
	var candidates []candidate
	for _, entry := range entries {
		path := filepath.Join(home, strings.TrimPrefix(entry, "~/"))
		if err := ensureSkillDiscoveryDirectory(home, filepath.Dir(path)); err != nil {
			return nil, nil, err
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			candidates = append(candidates, candidate{path: path})
			continue
		}
		if err != nil {
			return nil, nil, errors.New("inspect managed Skill discovery path failed")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return nil, nil, errors.New("read existing Skill discovery link failed")
			}
			resolved := target
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(filepath.Dir(path), resolved)
			}
			resolved = filepath.Clean(resolved)
			if resolved == filepath.Clean(stableSkill) {
				continue
			}
			digest, err := directoryTreeSHA256(resolved)
			if (err != nil || digest != expectedTreeDigest) && !isRecognizableOneNodBootstrapSkill(resolved) {
				return nil, nil, fmt.Errorf("Skill discovery path %s points to different content; refusing to overwrite it", path)
			}
			candidates = append(candidates, candidate{adopt: true, path: path})
			continue
		}
		if !info.IsDir() {
			return nil, nil, fmt.Errorf("Skill discovery path %s is occupied by non-directory content", path)
		}
		digest, err := directoryTreeSHA256(path)
		if (err != nil || digest != expectedTreeDigest) && !isRecognizableOneNodBootstrapSkill(path) {
			return nil, nil, fmt.Errorf("Skill discovery path %s differs from the verified OneNod Skill; refusing to overwrite it", path)
		}
		candidates = append(candidates, candidate{adopt: true, path: path})
	}
	transaction := &skillDiscoveryTransaction{}
	rollbackFailure := func(cause error) ([]string, *skillDiscoveryTransaction, error) {
		if err := transaction.rollback(); err != nil {
			return nil, nil, fmt.Errorf("%w; discovery rollback also failed: %v", cause, err)
		}
		return nil, nil, cause
	}
	backupRoot := filepath.Join(home, userAgentDirectoryName, "skill-adoption-backups")
	for _, candidate := range candidates {
		change := skillDiscoveryChange{Path: candidate.path}
		if candidate.adopt {
			if err := ensurePrivateInstallDirectory(backupRoot); err != nil {
				return rollbackFailure(err)
			}
			id, err := newUUIDv4()
			if err != nil {
				return rollbackFailure(err)
			}
			change.Backup = filepath.Join(backupRoot, id)
			if err := os.Rename(candidate.path, change.Backup); err != nil {
				return rollbackFailure(errors.New("move recognized OneNod bootstrap Skill to private adoption backup failed"))
			}
		}
		relative, err := filepath.Rel(filepath.Dir(candidate.path), stableSkill)
		if err != nil || filepath.IsAbs(relative) {
			if change.Backup != "" {
				_ = os.Rename(change.Backup, candidate.path)
			}
			return rollbackFailure(errors.New("derive managed Skill discovery link failed"))
		}
		if err := os.Symlink(relative, candidate.path); err != nil {
			if change.Backup != "" {
				_ = os.Rename(change.Backup, candidate.path)
			}
			return rollbackFailure(errors.New("activate managed Skill discovery link failed"))
		}
		transaction.changes = append(transaction.changes, change)
	}
	return entries, transaction, nil
}

func isRecognizableOneNodBootstrapSkill(root string) bool {
	path := filepath.Join(root, "SKILL.md")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > maxManifestBytes {
		return false
	}
	content, err := readBoundedRegularFile(path, maxManifestBytes)
	if err != nil || !bytes.HasPrefix(content, []byte("---\n")) {
		return false
	}
	frontmatterEnd := bytes.Index(content[len("---\n"):], []byte("\n---\n"))
	if frontmatterEnd < 0 {
		return false
	}
	frontmatter := string(content[len("---\n") : len("---\n")+frontmatterEnd])
	nameIsOneNod := false
	for _, line := range strings.Split(frontmatter, "\n") {
		if strings.TrimSpace(line) == "name: onenod" {
			nameIsOneNod = true
			break
		}
	}
	return nameIsOneNod && bytes.Contains(content, []byte("https://github.com/Vizards/OneNod"))
}

func ensureSkillDiscoveryDirectory(home, path string) error {
	relative, err := filepath.Rel(home, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("Skill discovery directory is outside the current user home")
	}
	current := home
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o755); err != nil {
				return errors.New("create Skill discovery directory failed")
			}
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("Skill discovery parent must be a directory, not a symlink")
		}
	}
	return nil
}

func replaceStableRegularFile(path, source string) error {
	if existing, err := os.Lstat(path); err == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 ||
			existing.Mode().Perm()&0o022 != 0 {
			return errors.New("refusing to replace an unsafe Keychain helper path")
		}
		existingDigest, existingDigestErr := regularFileSHA256(path, maxReleaseArtifactBytes)
		sourceDigest, sourceDigestErr := regularFileSHA256(source, maxReleaseArtifactBytes)
		if existingDigestErr != nil || sourceDigestErr != nil {
			return errors.New("hash Keychain helper before activation failed")
		}
		if existingDigest == sourceDigest {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect stable Keychain helper path failed")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".helper-")
	if err != nil {
		return errors.New("stage stable Keychain helper failed")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	input, err := os.Open(source)
	if err != nil {
		temporary.Close()
		return errors.New("open verified Keychain helper failed")
	}
	written, copyErr := io.Copy(temporary, io.LimitReader(input, maxReleaseArtifactBytes+1))
	input.Close()
	if copyErr != nil || written <= 0 || written > maxReleaseArtifactBytes ||
		temporary.Chmod(0o700) != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("stage verified Keychain helper failed")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("activate stable Keychain helper failed")
	}
	return nil
}

type helperReplacement struct {
	Changed        bool
	Path           string
	PreviousExists bool
	PreviousSource string
}

func activateStableHelper(path, source string, previous *localInstallReceipt) (*helperReplacement, error) {
	sourceDigest, err := regularFileSHA256(source, maxReleaseArtifactBytes)
	if err != nil {
		return nil, errors.New("hash verified Keychain helper failed")
	}
	transaction := &helperReplacement{Path: path}
	info, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		if err := replaceStableRegularFile(path, source); err != nil {
			return nil, err
		}
		transaction.Changed = true
		return transaction, nil
	}
	if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("refusing to replace an unsafe Keychain helper path")
	}
	existingDigest, err := regularFileSHA256(path, maxReleaseArtifactBytes)
	if err != nil {
		return nil, errors.New("hash installed Keychain helper failed")
	}
	if existingDigest == sourceDigest {
		return transaction, nil
	}
	if previous == nil || existingDigest != previous.Helper.BinarySHA256 {
		return nil, errors.New("installed Keychain helper differs from the verified source and has no exact rollback receipt")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.New("resolve Keychain helper rollback source failed")
	}
	rollbackSource := filepath.Join(home, userAgentDirectoryName, "helper-versions", previous.Helper.Version, keychainHelperBinaryName)
	rollbackDigest, err := regularFileSHA256(rollbackSource, maxReleaseArtifactBytes)
	if err != nil || rollbackDigest != previous.Helper.BinarySHA256 {
		return nil, errors.New("prior Keychain helper rollback source differs from its receipt")
	}
	if err := replaceStableRegularFile(path, source); err != nil {
		return nil, err
	}
	transaction.Changed = true
	transaction.PreviousExists = true
	transaction.PreviousSource = rollbackSource
	return transaction, nil
}

func (replacement *helperReplacement) rollback() error {
	if replacement == nil || !replacement.Changed {
		return nil
	}
	if !replacement.PreviousExists {
		if err := os.Remove(replacement.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("remove newly activated Keychain helper failed")
		}
		return nil
	}
	if err := replaceStableRegularFile(replacement.Path, replacement.PreviousSource); err != nil {
		return errors.New("restore prior Keychain helper failed")
	}
	return nil
}

func installOriginAndLaunchAgent(root, origin, home string) error {
	envPath := filepath.Join(root, userAgentEnvFileName)
	if existing, err := readInstalledUserOrigin(envPath); err != nil {
		return err
	} else if existing != "" && existing != origin {
		return errors.New("refusing to change an installed OneNod Origin")
	}
	envStage, err := os.CreateTemp(root, ".env-")
	if err != nil {
		return errors.New("stage installed OneNod Origin failed")
	}
	envStagePath := envStage.Name()
	defer os.Remove(envStagePath)
	if err := envStage.Chmod(0o600); err != nil {
		envStage.Close()
		return errors.New("secure installed OneNod Origin failed")
	}
	if _, err := io.WriteString(envStage, userAgentOriginKey+"="+origin+"\n"); err != nil ||
		envStage.Sync() != nil || envStage.Close() != nil {
		return errors.New("write installed OneNod Origin failed")
	}
	if err := os.Rename(envStagePath, envPath); err != nil {
		return errors.New("activate installed OneNod Origin failed")
	}
	launchDirectory := filepath.Join(home, "Library", "LaunchAgents")
	if err := ensureLaunchAgentDirectory(launchDirectory); err != nil {
		return err
	}
	launchPath := filepath.Join(launchDirectory, oneNodAgentLabel+".plist")
	staged, err := os.CreateTemp(launchDirectory, ".onenod-agent-")
	if err != nil {
		return errors.New("stage OneNod LaunchAgent failed")
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	if err := staged.Chmod(0o600); err != nil {
		staged.Close()
		return errors.New("secure OneNod LaunchAgent failed")
	}
	plist := renderApprovalAgentPlist(filepath.Join(root, "bin", "may"), filepath.Join(root, "logs"))
	if _, err := io.WriteString(staged, plist); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("write OneNod LaunchAgent failed")
	}
	if err := os.Rename(stagedPath, launchPath); err != nil {
		return errors.New("activate OneNod LaunchAgent failed")
	}
	return nil
}

func checkExternalTool(name string, requirement versionRange, capabilityArgs [][]string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("required external tool %s is not installed", name)
	}
	command := exec.Command(path, "--version")
	command.Env = operatorEnvironment(nil)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("required external tool %s cannot report its version", name)
	}
	version := firstStableVersion(string(output))
	zeroBytes(output)
	if version == "" || compareVersions(version, requirement.Minimum) < 0 ||
		(requirement.MaximumExclusive != "" && compareVersions(version, requirement.MaximumExclusive) >= 0) {
		return "", fmt.Errorf("%s version %q is outside supported range [%s, %s)",
			name, version, requirement.Minimum, requirement.MaximumExclusive)
	}
	for _, arguments := range capabilityArgs {
		command := exec.Command(path, arguments...)
		command.Env = operatorEnvironment(nil)
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Run(); err != nil {
			return "", fmt.Errorf("%s lacks required capability %s", name, strings.Join(arguments, " "))
		}
	}
	return path, nil
}

func firstStableVersion(output string) string {
	search := regexp.MustCompile(`(?:^|[^0-9])([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9]|$)`)
	match := search.FindStringSubmatch(output)
	if len(match) != 2 || !validStableVersion(match[1]) {
		return ""
	}
	return match[1]
}

func promptYesNo(input io.Reader, output io.Writer, prompt string, defaultYes bool) (bool, error) {
	if file, ok := input.(*os.File); ok {
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return false, errors.New("security confirmation requires an interactive terminal")
		}
	}
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	fmt.Fprintf(output, "%s %s ", prompt, suffix)
	line, err := readPromptLine(input)
	if err != nil {
		return false, errors.New("read security confirmation failed")
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer == "" {
		return defaultYes, nil
	}
	if answer == "y" || answer == "yes" {
		return true, nil
	}
	if answer == "n" || answer == "no" {
		return false, nil
	}
	return false, errors.New("confirmation must be y or n")
}

func readPromptLine(input io.Reader) (string, error) {
	if input == nil {
		return "", io.EOF
	}
	var line strings.Builder
	var next [1]byte
	for {
		count, err := input.Read(next[:])
		if count == 1 {
			if next[0] == '\n' {
				return line.String(), nil
			}
			line.WriteByte(next[0])
		}
		if err != nil {
			return line.String(), err
		}
		if count == 0 {
			return line.String(), io.ErrNoProgress
		}
	}
}

func sortedArtifactNames(manifest releaseManifest) []string {
	names := make([]string, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		names = append(names, artifact.Name)
	}
	sort.Strings(names)
	return names
}
