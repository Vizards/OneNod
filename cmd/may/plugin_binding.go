package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	shellPluginConfigSchema = 1
	maxShellPluginConfig    = 64 * 1024
)

type shellPluginFieldBinding struct {
	FieldID string `json:"field_id"`
	Label   string `json:"label,omitempty"`
}

type shellPluginScope struct {
	Kind string `json:"kind"`
	Root string `json:"root,omitempty"`
}

type shellPluginBinding struct {
	Command          string                             `json:"command"`
	CredentialFields map[string]shellPluginFieldBinding `json:"credential_fields"`
	ItemID           string                             `json:"item_id"`
	ItemTitle        string                             `json:"item_title,omitempty"`
	Plugin           string                             `json:"plugin"`
	Scope            shellPluginScope                   `json:"scope"`
	Target           string                             `json:"target"`
	UpstreamRevision string                             `json:"upstream_revision"`
}

type shellPluginConfig struct {
	Bindings      []shellPluginBinding `json:"bindings"`
	SchemaVersion int                  `json:"schema_version"`
}

func shellPluginConfigPath(home string) string {
	return filepath.Join(home, userAgentDirectoryName, "plugins.json")
}

func readShellPluginConfig(home string) (shellPluginConfig, error) {
	path := shellPluginConfigPath(home)
	encoded, exists, err := readOptionalRegularFile(path, maxShellPluginConfig)
	if err != nil {
		return shellPluginConfig{}, err
	}
	if !exists {
		return shellPluginConfig{SchemaVersion: shellPluginConfigSchema}, nil
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		return shellPluginConfig{}, errors.New("OneNod shell plugin configuration must have mode 0600")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var config shellPluginConfig
	if err := decoder.Decode(&config); err != nil {
		return shellPluginConfig{}, errors.New("OneNod shell plugin configuration is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return shellPluginConfig{}, errors.New("OneNod shell plugin configuration has trailing data")
	}
	if err := validateShellPluginConfig(config); err != nil {
		return shellPluginConfig{}, err
	}
	return config, nil
}

func writeShellPluginConfig(home string, config shellPluginConfig) error {
	config.SchemaVersion = shellPluginConfigSchema
	sort.Slice(config.Bindings, func(left, right int) bool {
		return shellPluginBindingKey(config.Bindings[left]) < shellPluginBindingKey(config.Bindings[right])
	})
	if err := validateShellPluginConfig(config); err != nil {
		return err
	}
	root := filepath.Join(home, userAgentDirectoryName)
	if info, err := os.Lstat(root); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("~/.onenod must be a private directory, not a symlink")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect ~/.onenod failed")
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return errors.New("encode OneNod shell plugin configuration failed")
	}
	encoded = append(encoded, '\n')
	return writeAtomicUserConfig(shellPluginConfigPath(home), encoded, 0o600)
}

func validateShellPluginConfig(config shellPluginConfig) error {
	if config.SchemaVersion != shellPluginConfigSchema {
		return errors.New("unsupported OneNod shell plugin configuration schema")
	}
	seen := make(map[string]bool)
	for _, binding := range config.Bindings {
		definition, found, err := shellPluginDefinitionByName(binding.Command)
		if err != nil {
			return err
		}
		if !found || definition.Command != binding.Command || definition.Plugin.Name != binding.Plugin {
			return fmt.Errorf("shell plugin binding for %q is not supported by this may release", binding.Command)
		}
		if err := validateIdentifier(binding.ItemID, "shell plugin item"); err != nil {
			return err
		}
		if binding.ItemTitle != "" && (len(binding.ItemTitle) > 256 || containsControl(binding.ItemTitle)) {
			return errors.New("shell plugin item title metadata is invalid")
		}
		if !filepath.IsAbs(binding.Target) || filepath.Clean(binding.Target) != binding.Target ||
			len(binding.Target) > 4096 || containsControl(binding.Target) {
			return errors.New("shell plugin target must be a clean absolute path")
		}
		if !validShellPluginRevision(binding.UpstreamRevision) {
			return errors.New("shell plugin upstream revision is invalid")
		}
		if err := validateShellPluginScope(binding.Scope); err != nil {
			return err
		}
		knownFields := make(map[string]bool)
		for _, field := range definition.Credential.Fields {
			knownFields[field.Name.String()] = true
			fieldBinding, exists := binding.CredentialFields[field.Name.String()]
			if !exists {
				if !field.Optional {
					return fmt.Errorf("shell plugin binding %s omits required field %s", binding.Command, field.Name)
				}
				continue
			}
			if err := validateIdentifier(fieldBinding.FieldID, "shell plugin field"); err != nil {
				return err
			}
			if fieldBinding.Label != "" && (len(fieldBinding.Label) > 256 || containsControl(fieldBinding.Label)) {
				return errors.New("shell plugin field label metadata is invalid")
			}
		}
		for name := range binding.CredentialFields {
			if !knownFields[name] {
				return fmt.Errorf("shell plugin binding %s contains unknown field %s", binding.Command, name)
			}
		}
		key := shellPluginBindingKey(binding)
		if seen[key] {
			return fmt.Errorf("duplicate shell plugin binding %s", key)
		}
		seen[key] = true
	}
	return nil
}

func validShellPluginRevision(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}

func validateShellPluginScope(scope shellPluginScope) error {
	switch scope.Kind {
	case "global":
		if scope.Root != "" {
			return errors.New("global shell plugin scope cannot have a root")
		}
	case "directory":
		if !filepath.IsAbs(scope.Root) || filepath.Clean(scope.Root) != scope.Root ||
			len(scope.Root) > 4096 || containsControl(scope.Root) {
			return errors.New("directory shell plugin scope must have a clean absolute root")
		}
	default:
		return errors.New("shell plugin scope must be global or directory")
	}
	return nil
}

func requestedShellPluginScope(value string, cwd string) (shellPluginScope, error) {
	switch value {
	case "global":
		return shellPluginScope{Kind: "global"}, nil
	case "directory":
		root, err := canonicalExistingDirectory(cwd)
		if err != nil {
			return shellPluginScope{}, err
		}
		return shellPluginScope{Kind: "directory", Root: root}, nil
	default:
		return shellPluginScope{}, errors.New("scope must be explicitly set to global or directory")
	}
}

func canonicalExistingDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("resolve current directory failed")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", errors.New("resolve current directory symlinks failed")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("shell plugin directory scope must identify an existing directory")
	}
	return filepath.Clean(resolved), nil
}

func shellPluginBindingKey(binding shellPluginBinding) string {
	return binding.Command + "\x00" + binding.Scope.Kind + "\x00" + binding.Scope.Root
}

func exactShellPluginBindingIndex(config shellPluginConfig, command string, scope shellPluginScope) int {
	key := command + "\x00" + scope.Kind + "\x00" + scope.Root
	for index, binding := range config.Bindings {
		if shellPluginBindingKey(binding) == key {
			return index
		}
	}
	return -1
}

func selectShellPluginBinding(config shellPluginConfig, command string, cwd string) (shellPluginBinding, bool, error) {
	canonicalCWD, err := canonicalExistingDirectory(cwd)
	if err != nil {
		return shellPluginBinding{}, false, err
	}
	bestRootLength := -1
	var selected shellPluginBinding
	found := false
	for _, binding := range config.Bindings {
		if binding.Command != command {
			continue
		}
		if binding.Scope.Kind == "global" {
			if !found {
				selected = binding
				found = true
			}
			continue
		}
		if directoryContains(binding.Scope.Root, canonicalCWD) && len(binding.Scope.Root) > bestRootLength {
			selected = binding
			found = true
			bestRootLength = len(binding.Scope.Root)
		}
	}
	return selected, found, nil
}

func directoryContains(root string, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !filepath.IsAbs(relative) &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func resolveShellPluginTarget(command string, explicit string, scope shellPluginScope, cwd string, home string) (string, error) {
	if explicit != "" {
		candidate := explicit
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(cwd, candidate)
		}
		return validateShellPluginTarget(command, filepath.Clean(candidate), home)
	}
	if scope.Kind == "directory" {
		if candidate, found := nearestProjectExecutable(scope.Root, command); found {
			return validateShellPluginTarget(command, candidate, home)
		}
	}
	for _, directory := range filepath.SplitList(os.Getenv("PATH")) {
		if directory == "" {
			directory = cwd
		}
		candidate := filepath.Join(directory, command)
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		validated, err := validateShellPluginTarget(command, candidate, home)
		if err == nil {
			return validated, nil
		}
	}
	return "", fmt.Errorf("real executable %s was not found; install it or pass --target", command)
}

func nearestProjectExecutable(start string, command string) (string, bool) {
	directory := filepath.Clean(start)
	for {
		candidate := filepath.Join(directory, "node_modules", ".bin", command)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, true
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", false
		}
		directory = parent
	}
}

func validateShellPluginTarget(command string, candidate string, home string) (string, error) {
	absolute, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve real executable %s failed", command)
	}
	absolute = filepath.Clean(absolute)
	info, err := os.Stat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("real executable %s is not an executable regular file", command)
	}
	managedEntry := filepath.Join(home, ".local", "bin", command)
	stableMay := filepath.Join(home, userAgentDirectoryName, "bin", "may")
	if filepath.Clean(absolute) == filepath.Clean(managedEntry) || filepath.Clean(absolute) == filepath.Clean(stableMay) {
		return "", fmt.Errorf("real executable %s resolves to a OneNod managed entry", command)
	}
	if mayInfo, statErr := os.Stat(stableMay); statErr == nil && os.SameFile(info, mayInfo) {
		return "", fmt.Errorf("real executable %s resolves recursively to may", command)
	}
	return absolute, nil
}

type shellPluginEntryState struct {
	Exists  bool
	Managed bool
	Path    string
	Target  string
}

func inspectShellPluginEntry(home string, command string) (shellPluginEntryState, error) {
	state := shellPluginEntryState{
		Path:   filepath.Join(home, ".local", "bin", command),
		Target: filepath.Join(home, userAgentDirectoryName, "bin", "may"),
	}
	info, err := os.Lstat(state.Path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, errors.New("inspect OneNod shell plugin entry failed")
	}
	state.Exists = true
	if info.Mode()&os.ModeSymlink == 0 {
		return state, nil
	}
	target, err := os.Readlink(state.Path)
	if err != nil {
		return state, errors.New("read OneNod shell plugin entry failed")
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(state.Path), target)
	}
	state.Managed = filepath.Clean(target) == filepath.Clean(state.Target)
	return state, nil
}

func applyShellPluginEntry(home string, command string) (bool, error) {
	state, err := inspectShellPluginEntry(home, command)
	if err != nil {
		return false, err
	}
	if state.Exists {
		if !state.Managed {
			return false, fmt.Errorf("refusing to replace unmanaged command entry %s", state.Path)
		}
		return false, nil
	}
	stableInfo, err := os.Stat(state.Target)
	if err != nil || !stableInfo.Mode().IsRegular() || stableInfo.Mode().Perm()&0o111 == 0 {
		return false, errors.New("verified stable may entry is unavailable")
	}
	running, err := os.Executable()
	if err != nil {
		return false, errors.New("resolve running may executable failed")
	}
	runningInfo, err := os.Stat(running)
	if err != nil || !os.SameFile(stableInfo, runningInfo) {
		return false, errors.New("shell plugin entries can only be changed by the installed stable may executable")
	}
	if err := ensureUserCommandDirectory(filepath.Dir(state.Path)); err != nil {
		return false, err
	}
	relative, err := filepath.Rel(filepath.Dir(state.Path), state.Target)
	if err != nil || filepath.IsAbs(relative) {
		return false, errors.New("derive OneNod shell plugin entry target failed")
	}
	if err := replaceStableSymlink(state.Path, relative); err != nil {
		return false, err
	}
	return true, nil
}

func removeShellPluginEntry(home string, command string) (bool, error) {
	state, err := inspectShellPluginEntry(home, command)
	if err != nil {
		return false, err
	}
	if !state.Exists {
		return false, nil
	}
	if !state.Managed {
		return false, fmt.Errorf("refusing to remove unmanaged command entry %s", state.Path)
	}
	if err := os.Remove(state.Path); err != nil {
		return false, errors.New("remove OneNod shell plugin entry failed")
	}
	return true, nil
}

func configHasShellPluginCommand(config shellPluginConfig, command string) bool {
	for _, binding := range config.Bindings {
		if binding.Command == command {
			return true
		}
	}
	return false
}
