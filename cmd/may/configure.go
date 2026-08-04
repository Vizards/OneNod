package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	sshManagedBlockStart       = "# >>> OneNod managed IdentityAgent >>>"
	sshManagedBlockEnd         = "# <<< OneNod managed IdentityAgent <<<"
	configurationReceiptSchema = 1
)

type priorGitValue struct {
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
}

type scopedGitValue struct {
	Present bool
	Scope   string
	Value   string
}

type sshIdentityAgentSetting struct {
	Directive string
	Line      int
	Scope     string
}

type sshIdentityFileSetting struct {
	Directive     string
	LegacyLooking bool
	Line          int
	Scope         string
}

type sshIncludeSetting struct {
	Directive string
	Line      int
	Scope     string
}

type configurationReceipt struct {
	Git map[string]struct {
		Applied string        `json:"applied"`
		Prior   priorGitValue `json:"prior"`
	} `json:"git,omitempty"`
	SSH struct {
		BlockDigest string `json:"block_digest,omitempty"`
		CreatedFile bool   `json:"created_file,omitempty"`
	} `json:"ssh"`
	SchemaVersion int `json:"schema_version"`
}

func runConfigure(args []string, deps dependencies) error {
	if len(args) < 2 {
		return errors.New("usage: may configure <ssh|git-signing> <status|apply|restore>")
	}
	switch args[0] {
	case "ssh":
		return runConfigureSSH(args[1:], deps)
	case "git-signing":
		return runConfigureGitSigning(args[1:], deps)
	default:
		return errors.New("usage: may configure <ssh|git-signing> <status|apply|restore>")
	}
}

func runConfigureSSH(args []string, deps dependencies) error {
	if len(args) != 1 {
		return errors.New("usage: may configure ssh <status|apply|restore>")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve user home for SSH configuration failed")
	}
	path := filepath.Join(home, ".ssh", "config")
	block := sshManagedBlock()
	content, exists, err := readOptionalRegularFile(path, 1<<20)
	if err != nil {
		return err
	}
	managed, altered := inspectManagedSSHBlock(content, block)
	identityFiles := inspectSSHIdentityFileSettings(content)
	includes := inspectSSHIncludeSettings(content)
	switch args[0] {
	case "status":
		status := "not_configured"
		if managed && managedSSHBlockTakesPrecedence(content, block) {
			status = "configured"
		} else if managed || altered {
			status = "needs_attention"
		} else if hasSSHIdentityAgentConflict(content) {
			status = "conflict"
		}
		fmt.Fprintf(deps.stdout, "OneNod SSH configuration: %s\n", status)
		fmt.Fprintln(deps.stdout, "  IdentityAgent ~/.onenod/agent.sock")
		if status == "conflict" {
			writeSSHIdentityAgentSettings(deps.stdout, inspectSSHIdentityAgentSettings(content))
		}
		writeSSHSelectorAdvisory(deps.stdout, identityFiles, includes)
		return nil
	case "apply":
		if managed {
			if !managedSSHBlockTakesPrecedence(content, block) {
				return errors.New("another IdentityAgent now precedes the OneNod managed block; restore or inspect the user-edited SSH config before applying again")
			}
			fmt.Fprintln(deps.stdout, "OneNod SSH configuration is already applied.")
			return nil
		}
		if altered {
			return errors.New("the OneNod SSH managed block was modified; inspect it before applying")
		}
		identityAgentSettings := inspectSSHIdentityAgentSettings(content)
		fmt.Fprintln(deps.stdout, "OpenSSH IdentityAgent configuration plan:")
		if len(identityAgentSettings) == 0 {
			fmt.Fprintln(deps.stdout, "Current direct IdentityAgent directives in ~/.ssh/config: <none>")
		} else {
			writeSSHIdentityAgentSettings(deps.stdout, identityAgentSettings)
		}
		fmt.Fprintln(deps.stdout, "Proposed effective global directive:")
		fmt.Fprintln(deps.stdout, "  Host *")
		fmt.Fprintln(deps.stdout, "    IdentityAgent ~/.onenod/agent.sock")
		if len(identityAgentSettings) > 0 {
			fmt.Fprintln(deps.stdout, "Existing directives remain unchanged underneath and become effective again after restore.")
		}
		writeSSHSelectorAdvisory(deps.stdout, identityFiles, includes)
		confirmed, err := promptYesNo(
			deps.stdin,
			deps.stdout,
			"Configure OpenSSH to use OneNod as the effective global IdentityAgent?",
			false,
		)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("SSH configuration was not changed")
		}
		currentContent, currentExists, err := readOptionalRegularFile(path, 1<<20)
		if err != nil {
			return err
		}
		if currentExists != exists || !bytes.Equal(currentContent, content) {
			return errors.New("SSH config changed while the OneNod plan was being reviewed; inspect it and run apply again")
		}
		receipt, err := readConfigurationReceipt(home)
		if err != nil {
			return err
		}
		updated := prependManagedSSHBlock(content, block)
		if err := writeAtomicUserConfig(path, updated, 0o600); err != nil {
			return err
		}
		receipt.SchemaVersion = configurationReceiptSchema
		receipt.SSH.BlockDigest = textDigest(block)
		receipt.SSH.CreatedFile = !exists
		if err := writeConfigurationReceipt(home, receipt); err != nil {
			rollbackErr := restoreSSHConfiguration(path, content, exists)
			if rollbackErr != nil {
				return fmt.Errorf("write OneNod SSH receipt failed and the original SSH config could not be restored: %v; %w", rollbackErr, err)
			}
			return fmt.Errorf("write OneNod SSH receipt failed; the original SSH config was restored: %w", err)
		}
		fmt.Fprintln(deps.stdout, "Applied the standard OneNod IdentityAgent block first without changing existing SSH directives.")
		return nil
	case "restore":
		receipt, err := readConfigurationReceipt(home)
		if err != nil {
			return err
		}
		if receipt.SSH.BlockDigest == "" {
			return errors.New("OneNod has no SSH configuration receipt to restore")
		}
		if !managed || receipt.SSH.BlockDigest != textDigest(block) {
			return errors.New("the OneNod SSH block no longer matches its receipt; refusing to remove user-edited content")
		}
		updated := removeManagedSSHBlock(content, block)
		if receipt.SSH.CreatedFile && len(bytes.TrimSpace(updated)) == 0 {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.New("remove OneNod-created SSH config failed")
			}
		} else if err := writeAtomicUserConfig(path, updated, 0o600); err != nil {
			return err
		}
		receipt.SSH = struct {
			BlockDigest string `json:"block_digest,omitempty"`
			CreatedFile bool   `json:"created_file,omitempty"`
		}{}
		if err := writeConfigurationReceipt(home, receipt); err != nil {
			rollbackErr := writeAtomicUserConfig(path, content, 0o600)
			if rollbackErr != nil {
				return fmt.Errorf("update OneNod SSH receipt failed and the managed block could not be restored: %v; %w", rollbackErr, err)
			}
			return fmt.Errorf("update OneNod SSH receipt failed; the managed block was restored: %w", err)
		}
		fmt.Fprintln(deps.stdout, "Removed only the unchanged OneNod SSH managed block.")
		return nil
	default:
		return errors.New("usage: may configure ssh <status|apply|restore>")
	}
}

func runConfigureGitSigning(args []string, deps dependencies) error {
	if len(args) == 0 {
		return errors.New("usage: may configure git-signing <status|apply|restore> [--signing-key key-or-path]")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve user home for Git configuration failed")
	}
	keys := []string{"gpg.format", "gpg.ssh.program", "user.signingkey", "commit.gpgsign"}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return errors.New("usage: may configure git-signing status")
		}
		fmt.Fprintln(deps.stdout, "Global Git signing configuration managed by OneNod:")
		for _, key := range keys {
			values, err := gitGlobalValues(key)
			if err != nil {
				return err
			}
			value := "<unset>"
			if len(values) == 1 {
				value = values[0]
			} else if len(values) > 1 {
				value = "<multiple values; needs attention>"
			}
			fmt.Fprintf(deps.stdout, "  %s = %s\n", key, value)
		}
		return writeEffectiveGitSigningStatus(deps.stdout, keys)
	case "apply":
		flags := flag.NewFlagSet("configure git-signing apply", flag.ContinueOnError)
		flags.SetOutput(deps.stderr)
		signingKey := flags.String("signing-key", "", "SSH public key or path to a public-key file")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *signingKey == "" {
			return errors.New("usage: may configure git-signing apply --signing-key <key-or-path>")
		}
		publicKey, err := normalizedSigningKey(*signingKey)
		if err != nil {
			return err
		}
		desired := map[string]string{
			"gpg.format":      "ssh",
			"gpg.ssh.program": filepath.Join(home, userAgentDirectoryName, "bin", gitSignAdapterBinaryName),
			"user.signingkey": publicKey,
			"commit.gpgsign":  "true",
		}
		receipt, err := readConfigurationReceipt(home)
		if err != nil {
			return err
		}
		if receipt.Git != nil {
			allApplied := true
			for key, record := range receipt.Git {
				values, _ := gitGlobalValues(key)
				allApplied = allApplied && len(values) == 1 && values[0] == record.Applied
			}
			if allApplied {
				fmt.Fprintln(deps.stdout, "OneNod Git SSH-signing configuration is already applied.")
				return writeEffectiveGitSigningStatus(deps.stdout, keys)
			}
			return errors.New("recorded OneNod Git configuration was modified; restore or resolve it before applying again")
		}
		prior := map[string]priorGitValue{}
		for _, key := range keys {
			values, err := gitGlobalValues(key)
			if err != nil {
				return err
			}
			if len(values) > 1 {
				return fmt.Errorf("global Git key %s has multiple values; resolve it manually", key)
			}
			if len(values) == 1 {
				prior[key] = priorGitValue{Present: true, Value: values[0]}
			} else {
				prior[key] = priorGitValue{}
			}
		}
		fmt.Fprintln(deps.stdout, "Git commit/tag SSH-signing configuration plan:")
		for _, key := range keys {
			current := "<unset>"
			if prior[key].Present {
				current = fmt.Sprintf("%q", prior[key].Value)
			}
			fmt.Fprintf(deps.stdout, "  %s:\n    current:  %s\n    proposed: %q\n", key, current, desired[key])
		}
		fmt.Fprintln(deps.stdout, "Traditional GPG/OpenPGP configuration is not managed separately; gpg.format changes only if this plan is accepted.")
		if err := writeEffectiveGitSigningStatus(deps.stdout, keys); err != nil {
			return err
		}
		confirmed, err := promptYesNo(
			deps.stdin,
			deps.stdout,
			"Apply this global Git commit/tag SSH-signing configuration?",
			false,
		)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("Git signing configuration was not changed")
		}
		for _, key := range keys {
			values, err := gitGlobalValues(key)
			if err != nil {
				return err
			}
			if !gitValuesMatchPrior(values, prior[key]) {
				return errors.New("global Git configuration changed while the OneNod plan was being reviewed; inspect it and run apply again")
			}
		}
		applied := []string{}
		for _, key := range keys {
			if err := setGitGlobalValue(key, desired[key]); err != nil {
				rollbackGitValues(applied, prior)
				return err
			}
			applied = append(applied, key)
		}
		receipt.SchemaVersion = configurationReceiptSchema
		receipt.Git = map[string]struct {
			Applied string        `json:"applied"`
			Prior   priorGitValue `json:"prior"`
		}{}
		for _, key := range keys {
			receipt.Git[key] = struct {
				Applied string        `json:"applied"`
				Prior   priorGitValue `json:"prior"`
			}{Applied: desired[key], Prior: prior[key]}
		}
		if err := writeConfigurationReceipt(home, receipt); err != nil {
			rollbackGitValues(keys, prior)
			return err
		}
		fmt.Fprintln(deps.stdout, "Applied standard Git SSH signing and recorded only the four prior global values.")
		return nil
	case "restore":
		if len(args) != 1 {
			return errors.New("usage: may configure git-signing restore")
		}
		receipt, err := readConfigurationReceipt(home)
		if err != nil {
			return err
		}
		if len(receipt.Git) == 0 {
			return errors.New("OneNod has no Git configuration receipt to restore")
		}
		for key, record := range receipt.Git {
			values, err := gitGlobalValues(key)
			if err != nil || len(values) != 1 || values[0] != record.Applied {
				return fmt.Errorf("global Git key %s changed after OneNod setup; refusing to overwrite it", key)
			}
		}
		for key, record := range receipt.Git {
			if record.Prior.Present {
				err = setGitGlobalValue(key, record.Prior.Value)
			} else {
				err = unsetGitGlobalValue(key)
			}
			if err != nil {
				return err
			}
		}
		receipt.Git = nil
		if err := writeConfigurationReceipt(home, receipt); err != nil {
			return err
		}
		fmt.Fprintln(deps.stdout, "Restored the four global Git values recorded before OneNod setup.")
		return nil
	default:
		return errors.New("usage: may configure git-signing <status|apply|restore> [--signing-key key-or-path]")
	}
}

func gitValuesMatchPrior(values []string, prior priorGitValue) bool {
	if !prior.Present {
		return len(values) == 0
	}
	return len(values) == 1 && values[0] == prior.Value
}

func sshManagedBlock() string {
	return fmt.Sprintf("%s\nHost *\n  IdentityAgent ~/.onenod/agent.sock\n%s\n",
		sshManagedBlockStart, sshManagedBlockEnd)
}

func inspectManagedSSHBlock(content []byte, expected string) (bool, bool) {
	text := string(content)
	start, end := strings.Index(text, sshManagedBlockStart), strings.Index(text, sshManagedBlockEnd)
	if start < 0 && end < 0 {
		return false, false
	}
	if start < 0 || end < start {
		return false, true
	}
	end += len(sshManagedBlockEnd)
	if end < len(text) && text[end] == '\n' {
		end++
	}
	return text[start:end] == expected, text[start:end] != expected
}

func hasSSHIdentityAgentConflict(content []byte) bool {
	return len(inspectSSHIdentityAgentSettings(content)) > 0
}

func inspectSSHIdentityAgentSettings(content []byte) []sshIdentityAgentSetting {
	settings := []sshIdentityAgentSetting{}
	scope := "global defaults"
	for index, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case strings.EqualFold(fields[0], "Host"), strings.EqualFold(fields[0], "Match"):
			scope = line
		case strings.EqualFold(fields[0], "IdentityAgent"):
			settings = append(settings, sshIdentityAgentSetting{
				Directive: line,
				Line:      index + 1,
				Scope:     scope,
			})
		}
	}
	return settings
}

func inspectSSHIdentityFileSettings(content []byte) []sshIdentityFileSetting {
	settings := []sshIdentityFileSetting{}
	scope := "global defaults"
	for index, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case strings.EqualFold(fields[0], "Host"), strings.EqualFold(fields[0], "Match"):
			scope = line
		case strings.EqualFold(fields[0], "IdentityFile"):
			lower := strings.ToLower(strings.Join(fields[1:], " "))
			settings = append(settings, sshIdentityFileSetting{
				Directive: line,
				LegacyLooking: strings.Contains(lower, ".1p-agent") ||
					strings.Contains(lower, ".1password") ||
					strings.Contains(lower, "approvalctl"),
				Line: index + 1, Scope: scope,
			})
		}
	}
	return settings
}

func inspectSSHIncludeSettings(content []byte) []sshIncludeSetting {
	settings := []sshIncludeSetting{}
	scope := "global defaults"
	for index, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case strings.EqualFold(fields[0], "Host"), strings.EqualFold(fields[0], "Match"):
			scope = line
		case strings.EqualFold(fields[0], "Include"):
			settings = append(settings, sshIncludeSetting{
				Directive: line, Line: index + 1, Scope: scope,
			})
		}
	}
	return settings
}

func writeSSHIdentityAgentSettings(output io.Writer, settings []sshIdentityAgentSetting) {
	fmt.Fprintln(output, "Current IdentityAgent directives in ~/.ssh/config:")
	for _, setting := range settings {
		fmt.Fprintf(
			output,
			"  line %d under %q: %q\n",
			setting.Line,
			setting.Scope,
			setting.Directive,
		)
	}
}

func writeSSHSelectorAdvisory(
	output io.Writer,
	identityFiles []sshIdentityFileSetting,
	includes []sshIncludeSetting,
) {
	if len(identityFiles) == 0 && len(includes) == 0 {
		return
	}
	fmt.Fprintln(output, "Host public-key selector review (not modified by OneNod):")
	for _, setting := range identityFiles {
		marker := ""
		if setting.LegacyLooking {
			marker = " [legacy-looking path; migrate before removing the old file]"
		}
		fmt.Fprintf(
			output,
			"  line %d under %q: %q%s\n",
			setting.Line,
			setting.Scope,
			setting.Directive,
			marker,
		)
	}
	for _, setting := range includes {
		fmt.Fprintf(
			output,
			"  line %d under %q: %q [included files require separate review]\n",
			setting.Line,
			setting.Scope,
			setting.Directive,
		)
	}
	fmt.Fprintln(output, "  IdentityAgent cutover does not rewrite IdentityFile or IdentitiesOnly. Use `may ssh public-key export` after matching each intended Agent item by public fingerprint; never guess a Host-to-item mapping.")
}

func managedSSHBlockTakesPrecedence(content []byte, block string) bool {
	start := strings.Index(string(content), block)
	if start < 0 {
		return false
	}
	return len(inspectSSHIdentityAgentSettings(content[:start])) == 0
}

func prependManagedSSHBlock(content []byte, block string) []byte {
	updated := make([]byte, 0, len(block)+len(content)+1)
	updated = append(updated, []byte(block)...)
	if len(content) > 0 {
		updated = append(updated, '\n')
		updated = append(updated, content...)
	}
	return updated
}

func removeManagedSSHBlock(content []byte, block string) []byte {
	text := string(content)
	if strings.HasPrefix(text, block+"\n") {
		return []byte(strings.TrimPrefix(text, block+"\n"))
	}
	if strings.HasPrefix(text, block) {
		return []byte(strings.TrimPrefix(text, block))
	}
	// Continue to restore the append-at-end shape produced by pre-Public Preview
	// development builds without rewriting unrelated bytes.
	updated := strings.Replace(text, block, "", 1)
	updated = strings.TrimSuffix(updated, "\n\n")
	if updated != "" && !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	return []byte(updated)
}

func normalizedSigningKey(value string) (string, error) {
	encoded := []byte(value)
	if info, err := os.Stat(value); err == nil {
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64*1024 {
			return "", errors.New("SSH signing public-key path is not a bounded regular file")
		}
		encoded, err = os.ReadFile(value)
		if err != nil {
			return "", errors.New("read SSH signing public key failed")
		}
	}
	publicKey, _, _, rest, err := ssh.ParseAuthorizedKey(encoded)
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("signing key must be exactly one valid SSH public key")
	}
	return "key::" + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))), nil
}

func gitGlobalValues(key string) ([]string, error) {
	command := exec.Command("git", "config", "--global", "--get-all", key)
	command.Env = operatorEnvironment(nil)
	output, err := command.Output()
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read global Git key %s failed", key)
	}
	trimmed := strings.TrimSuffix(string(output), "\n")
	if trimmed == "" {
		return []string{""}, nil
	}
	return strings.Split(trimmed, "\n"), nil
}

func gitEffectiveValue(key string) (scopedGitValue, error) {
	command := exec.Command("git", "config", "--null", "--show-scope", "--get", key)
	command.Env = operatorEnvironment(nil)
	output, err := command.Output()
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
		return scopedGitValue{}, nil
	}
	if err != nil {
		return scopedGitValue{}, fmt.Errorf("read effective Git key %s failed", key)
	}
	fields := bytes.Split(output, []byte{0})
	if len(fields) == 3 && len(fields[2]) == 0 {
		fields = fields[:2]
	}
	if len(fields) != 2 || len(fields[0]) == 0 {
		return scopedGitValue{}, fmt.Errorf("read effective Git key %s returned an unexpected response", key)
	}
	return scopedGitValue{
		Present: true,
		Scope:   string(fields[0]),
		Value:   string(fields[1]),
	}, nil
}

func writeEffectiveGitSigningStatus(output io.Writer, keys []string) error {
	fmt.Fprintln(output, "Effective Git signing configuration in the current directory:")
	nonGlobal := false
	for _, key := range keys {
		value, err := gitEffectiveValue(key)
		if err != nil {
			return err
		}
		if !value.Present {
			fmt.Fprintf(output, "  %s = <unset>\n", key)
			continue
		}
		fmt.Fprintf(output, "  %s = %s (scope: %s)\n", key, value.Value, value.Scope)
		nonGlobal = nonGlobal || value.Scope != "global"
	}
	if nonGlobal {
		fmt.Fprintln(output, "OneNod changes only global values. Local, worktree, or command values can override them; system values may remain effective when a global value is unset. OneNod reports but does not modify these scopes.")
	}
	return nil
}

func setGitGlobalValue(key, value string) error {
	command := exec.Command("git", "config", "--global", "--replace-all", key, value)
	command.Env = operatorEnvironment(nil)
	if output, err := command.CombinedOutput(); err != nil {
		zeroBytes(output)
		return fmt.Errorf("set global Git key %s failed", key)
	}
	return nil
}

func unsetGitGlobalValue(key string) error {
	command := exec.Command("git", "config", "--global", "--unset-all", key)
	command.Env = operatorEnvironment(nil)
	if output, err := command.CombinedOutput(); err != nil {
		zeroBytes(output)
		if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 5 {
			return nil
		}
		return fmt.Errorf("unset global Git key %s failed", key)
	}
	return nil
}

func rollbackGitValues(keys []string, prior map[string]priorGitValue) {
	for _, key := range keys {
		value := prior[key]
		if value.Present {
			_ = setGitGlobalValue(key, value.Value)
		} else {
			_ = unsetGitGlobalValue(key)
		}
	}
}

func configurationReceiptPath(home string) string {
	return filepath.Join(home, userAgentDirectoryName, "configuration.json")
}

func readConfigurationReceipt(home string) (configurationReceipt, error) {
	path := configurationReceiptPath(home)
	encoded, exists, err := readOptionalRegularFile(path, maxManifestBytes)
	if err != nil {
		return configurationReceipt{}, err
	}
	if !exists {
		return configurationReceipt{SchemaVersion: configurationReceiptSchema}, nil
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		return configurationReceipt{}, errors.New("OneNod configuration receipt must be private to the current user")
	}
	var receipt configurationReceipt
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil || ensureDecoderEOF(decoder) != nil ||
		receipt.SchemaVersion != configurationReceiptSchema {
		return configurationReceipt{}, errors.New("OneNod configuration receipt is invalid")
	}
	return receipt, nil
}

func restoreSSHConfiguration(path string, content []byte, existed bool) error {
	if !existed {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeAtomicUserConfig(path, content, 0o600)
}

func writeConfigurationReceipt(home string, receipt configurationReceipt) error {
	receipt.SchemaVersion = configurationReceiptSchema
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return errors.New("encode OneNod configuration receipt failed")
	}
	encoded = append(encoded, '\n')
	return writeAtomicUserConfig(configurationReceiptPath(home), encoded, 0o600)
}

func readOptionalRegularFile(path string, limit int64) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() < 0 || info.Size() > limit {
		return nil, false, fmt.Errorf("%s must be a bounded regular file, not a symlink", path)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read %s failed", path)
	}
	return encoded, true, nil
}

func writeAtomicUserConfig(path string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create configuration directory %s failed", directory)
	}
	staged, err := os.CreateTemp(directory, ".onenod-config-")
	if err != nil {
		return errors.New("stage OneNod configuration failed")
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	if err := staged.Chmod(mode); err != nil {
		staged.Close()
		return errors.New("secure staged OneNod configuration failed")
	}
	if _, err := staged.Write(content); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("write staged OneNod configuration failed")
	}
	if err := os.Rename(stagedPath, path); err != nil {
		return errors.New("activate OneNod configuration failed")
	}
	return nil
}

func textDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
