package beholdercontext

import (
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

type toolInputFeatures struct {
	SchemaVersion           int      `json:"schema_version"`
	Observed                bool     `json:"observed"`
	CommandLengthBucket     string   `json:"command_length_bucket"`
	TokenCountBucket        string   `json:"token_count_bucket"`
	PathTokenCountBucket    string   `json:"path_token_count_bucket"`
	URLTokenCountBucket     string   `json:"url_token_count_bucket"`
	FlagTokenCountBucket    string   `json:"flag_token_count_bucket"`
	Families                []string `json:"families"`
	HasPipe                 bool     `json:"has_pipe"`
	HasRedirection          bool     `json:"has_redirection"`
	HasChaining             bool     `json:"has_chaining"`
	HasBackground           bool     `json:"has_background"`
	HasSubshell             bool     `json:"has_subshell"`
	HasEnvironmentExpansion bool     `json:"has_environment_expansion"`
	HasCommandSubstitution  bool     `json:"has_command_substitution"`
	RawCommandStored        bool     `json:"raw_command_stored"`
	RawTokensStored         bool     `json:"raw_tokens_stored"`
}

func deriveToolInputFeatures(command string) toolInputFeatures {
	features := toolInputFeatures{
		SchemaVersion:       1,
		Observed:            command != "",
		CommandLengthBucket: countBucket(len(command)),
		Families:            []string{},
		RawCommandStored:    false,
		RawTokensStored:     false,
	}
	features.HasPipe = strings.Contains(command, "|")
	features.HasRedirection = strings.ContainsAny(command, "<>")
	features.HasChaining = strings.Contains(command, "&&") || strings.Contains(command, "||") || strings.Contains(command, ";")
	features.HasBackground = strings.Contains(command, "&")
	features.HasSubshell = strings.Contains(command, "(") || strings.Contains(command, ")")
	features.HasEnvironmentExpansion = strings.Contains(command, "$")
	features.HasCommandSubstitution = strings.Contains(command, "$(") || strings.Contains(command, "`")

	tokens := strings.FieldsFunc(command, func(character rune) bool {
		return unicode.IsSpace(character) || strings.ContainsRune(";&|(){}[]<>,", character)
	})
	pathCount, urlCount, flagCount := 0, 0, 0
	families := map[string]bool{}
	for _, rawToken := range tokens {
		token := strings.Trim(rawToken, "\"'`")
		lower := strings.ToLower(token)
		base := strings.ToLower(filepath.Base(lower))
		if strings.Contains(token, "/") {
			pathCount++
		}
		if strings.Contains(lower, "://") {
			urlCount++
		}
		if strings.HasPrefix(token, "-") {
			flagCount++
		}
		classifyExecutableFamily(base, families)
	}
	if features.HasRedirection {
		families["filesystem-write"] = true
	}
	for family := range families {
		features.Families = append(features.Families, family)
	}
	sort.Strings(features.Families)
	features.TokenCountBucket = countBucket(len(tokens))
	features.PathTokenCountBucket = countBucket(pathCount)
	features.URLTokenCountBucket = countBucket(urlCount)
	features.FlagTokenCountBucket = countBucket(flagCount)
	return features
}

func classifyExecutableFamily(base string, families map[string]bool) {
	switch base {
	case "may", "may-ssh-sign":
		families["onenod"] = true
		families["credential"] = true
	case "ssh", "scp", "sftp", "ssh-add", "ssh-keygen", "mac-peer":
		families["ssh"] = true
		families["network"] = true
	case "git":
		families["git"] = true
	case "curl", "wget", "nc", "ncat", "dig", "host":
		families["network"] = true
	case "rg", "grep", "sed", "awk", "find", "ls", "head", "tail", "wc", "stat", "file":
		families["filesystem-read"] = true
	case "cp", "mv", "mkdir", "touch", "tee", "install":
		families["filesystem-write"] = true
	case "rm", "rmdir", "unlink", "truncate", "dd", "diskutil":
		families["destructive"] = true
		families["filesystem-write"] = true
	case "sudo", "doas", "launchctl":
		families["privilege-or-service"] = true
	case "kill", "pkill", "killall", "nohup":
		families["process-control"] = true
	case "go", "cargo", "npm", "npx", "pnpm", "yarn", "bun", "brew", "pip", "pip3":
		families["build-or-package"] = true
	case "python", "python3", "node", "ruby", "perl":
		families["interpreter"] = true
	case "gpg", "codesign", "security":
		families["signing-or-keychain"] = true
	}
}

func countBucket(count int) string {
	switch {
	case count == 0:
		return "0"
	case count == 1:
		return "1"
	case count <= 4:
		return "2-4"
	case count <= 16:
		return "5-16"
	case count <= 64:
		return "17-64"
	case count <= 256:
		return "65-256"
	case count <= 1024:
		return "257-1024"
	default:
		return "1025+"
	}
}
