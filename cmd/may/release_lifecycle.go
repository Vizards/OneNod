package main

import (
	"context"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
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
	localReceiptSchema        = 3
	initializerReceiptSchema  = 1
	manifestSchema            = 1
	transportJournalSchema    = 1
	mayClientProtocol         = 2
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
	digestPattern               = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitPattern               = regexp.MustCompile(`^[0-9a-f]{40}$`)
	transportTransactionPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
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

type exactBuildCodeIdentity struct {
	HardenedRuntime bool   `json:"hardened_runtime"`
	Identifier      string `json:"identifier"`
	Scheme          string `json:"scheme"`
	Signing         string `json:"signing"`
}

type exactBuildRuntimeIdentity struct {
	Architecture                    string `json:"architecture"`
	CodeDirectoryHash               string `json:"cdhash"`
	DesignatedRequirementDataSHA256 string `json:"designated_requirement_data_sha256"`
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
			CodeIdentity   exactBuildCodeIdentity `json:"code_identity"`
			HelperProtocol protocolRange          `json:"helper_protocol"`
			SourceDigest   string                 `json:"source_digest"`
			Version        string                 `json:"version"`
		} `json:"keychain_helper"`
		May struct {
			AdapterCodeIdentity exactBuildCodeIdentity `json:"adapter_code_identity"`
			ClientProtocol      int                    `json:"client_protocol"`
			CodeIdentity        exactBuildCodeIdentity `json:"code_identity"`
			Version             string                 `json:"version"`
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
	Download(context.Context, *verifiedRelease, releaseArtifact) ([]byte, error)
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
	ExactCodeIdentities struct {
		May        exactBuildRuntimeIdentity `json:"may"`
		MaySSHSign exactBuildRuntimeIdentity `json:"may_ssh_sign"`
		Helper     exactBuildRuntimeIdentity `json:"keychain_helper"`
	} `json:"exact_code_identities"`
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

type transportUpdateJournal struct {
	HelperChanged    bool              `json:"helper_changed"`
	NewHelperVersion string            `json:"new_helper_version"`
	NewRelease       string            `json:"new_release"`
	NewTargets       map[string]string `json:"new_targets"`
	OldRelease       string            `json:"old_release"`
	OldHelperVersion string            `json:"old_helper_version"`
	OldTargets       map[string]string `json:"old_targets"`
	Origin           string            `json:"origin"`
	Phase            string            `json:"phase"`
	SchemaVersion    int               `json:"schema_version"`
	Slot             string            `json:"slot"`
	TransactionID    string            `json:"transaction_id"`
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

type remoteRuntimeVersionResponse struct {
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

type localReleaseMetadata struct {
	Architecture string `json:"architecture"`
	ArtifactKind string `json:"artifact_kind"`
	BinarySHA256 struct {
		May        string `json:"may"`
		MaySSHSign string `json:"may_ssh_sign"`
	} `json:"binary_sha256"`
	CodeIdentities struct {
		May        exactBuildCodeIdentity `json:"may"`
		MaySSHSign exactBuildCodeIdentity `json:"may_ssh_sign"`
	} `json:"code_identities"`
	ExactCodeIdentities struct {
		May        exactBuildRuntimeIdentity `json:"may"`
		MaySSHSign exactBuildRuntimeIdentity `json:"may_ssh_sign"`
	} `json:"exact_code_identities"`
	ReleaseVersion string `json:"release_version"`
	Repository     string `json:"repository"`
	SchemaVersion  int    `json:"schema_version"`
	SourceCommit   string `json:"source_commit"`
}

type helperReleaseMetadata struct {
	Architecture       string                    `json:"architecture"`
	ArtifactKind       string                    `json:"artifact_kind"`
	BinarySHA256       string                    `json:"binary_sha256"`
	CodeIdentity       exactBuildCodeIdentity    `json:"code_identity"`
	ExactCodeIdentity  exactBuildRuntimeIdentity `json:"exact_code_identity"`
	HelperProtocol     int                       `json:"helper_protocol"`
	HelperSourceDigest string                    `json:"helper_source_digest"`
	HelperVersion      string                    `json:"helper_version"`
	Repository         string                    `json:"repository"`
	SchemaVersion      int                       `json:"schema_version"`
	SourceCommit       string                    `json:"source_commit"`
}

type verifiedLocalTransportDescriptor struct {
	AdapterSHA256   string
	AdapterIdentity exactBuildRuntimeIdentity
	HelperSHA256    string
	HelperIdentity  exactBuildRuntimeIdentity
	MaySHA256       string
	MayIdentity     exactBuildRuntimeIdentity
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
