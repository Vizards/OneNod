package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	commandPathBlockStart = "# >>> OneNod managed command path >>>"
	commandPathBlockEnd   = "# <<< OneNod managed command path <<<"
)

type commandDiscoveryPlan struct {
	linkPath       string
	manageLink     bool
	profileContent []byte
	profileExists  bool
	profileMode    os.FileMode
	profilePath    string
	targetPath     string
	writeProfile   bool
}

type commandDiscoveryTransaction struct {
	linkExisted    bool
	linkPath       string
	linkTarget     string
	profileContent []byte
	profileExists  bool
	profileMode    os.FileMode
	profilePath    string
}

func planCommandDiscovery(
	home string,
	targetPath string,
	deps dependencies,
) (*commandDiscoveryPlan, error) {
	plan := &commandDiscoveryPlan{
		linkPath:    filepath.Join(home, ".local", "bin", "may"),
		manageLink:  true,
		profilePath: filepath.Join(home, ".zprofile"),
		targetPath:  targetPath,
	}
	if info, err := os.Lstat(plan.linkPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			plan.manageLink = false
		} else {
			target, readErr := os.Readlink(plan.linkPath)
			if readErr != nil {
				return nil, errors.New("inspect existing ~/.local/bin/may symlink failed")
			}
			resolved := target
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(filepath.Dir(plan.linkPath), resolved)
			}
			if filepath.Clean(resolved) != filepath.Clean(targetPath) {
				plan.manageLink = false
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect user command path failed")
	}

	if !plan.manageLink {
		fmt.Fprintln(deps.stdout, "OneNod did not replace the existing ~/.local/bin/may entry. The verified CLI remains available at ~/.onenod/bin/may.")
		return plan, nil
	}
	if pathContainsDirectory(os.Getenv("PATH"), filepath.Dir(plan.linkPath)) {
		return plan, nil
	}

	content, exists, err := readOptionalShellProfile(plan.profilePath)
	if err != nil {
		return nil, err
	}
	plan.profileContent = content
	plan.profileExists = exists
	plan.profileMode = 0o600
	if exists {
		info, statErr := os.Stat(plan.profilePath)
		if statErr != nil {
			return nil, errors.New("inspect ~/.zprofile failed")
		}
		plan.profileMode = info.Mode().Perm()
	}
	block := commandPathBlock()
	managed, altered := inspectCommandPathBlock(content, block)
	if altered {
		return nil, errors.New("the OneNod command-path block in ~/.zprofile was modified; inspect it before installing")
	}
	if managed {
		return plan, nil
	}

	fmt.Fprintln(deps.stdout, "OneNod command discovery plan:")
	fmt.Fprintln(deps.stdout, "  create ~/.local/bin/may -> ~/.onenod/bin/may")
	fmt.Fprintln(deps.stdout, "  append this bounded block to ~/.zprofile:")
	for _, line := range strings.Split(strings.TrimSuffix(block, "\n"), "\n") {
		fmt.Fprintf(deps.stdout, "    %s\n", line)
	}
	confirmed, err := promptYesNo(
		deps.stdin,
		deps.stdout,
		"Make the short may command available in new zsh login sessions?",
		true,
	)
	if err != nil {
		return nil, err
	}
	plan.writeProfile = confirmed
	if !confirmed {
		fmt.Fprintln(deps.stdout, "Shell profile unchanged. Use ~/.onenod/bin/may, or add ~/.local/bin to PATH later.")
	}
	return plan, nil
}

func (plan *commandDiscoveryPlan) apply() (*commandDiscoveryTransaction, error) {
	if !plan.manageLink {
		return nil, nil
	}
	transaction := &commandDiscoveryTransaction{
		linkPath: plan.linkPath,
	}
	if plan.writeProfile {
		transaction.profileContent = append([]byte(nil), plan.profileContent...)
		transaction.profileExists = plan.profileExists
		transaction.profileMode = plan.profileMode
		transaction.profilePath = plan.profilePath
	}
	if err := ensureUserCommandDirectory(filepath.Dir(plan.linkPath)); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(plan.linkPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return nil, errors.New("~/.local/bin/may changed before activation")
		}
		transaction.linkExisted = true
		transaction.linkTarget, err = os.Readlink(plan.linkPath)
		if err != nil {
			return nil, errors.New("capture existing user command symlink failed")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect user command symlink before activation failed")
	}
	relative, err := filepath.Rel(filepath.Dir(plan.linkPath), plan.targetPath)
	if err != nil || filepath.IsAbs(relative) {
		return nil, errors.New("derive user command symlink failed")
	}
	if err := replaceStableSymlink(plan.linkPath, relative); err != nil {
		return nil, err
	}
	if plan.writeProfile {
		current, exists, err := readOptionalShellProfile(plan.profilePath)
		if err != nil {
			_ = transaction.rollback()
			return nil, err
		}
		if exists != plan.profileExists || !bytes.Equal(current, plan.profileContent) {
			_ = transaction.rollback()
			return nil, errors.New("~/.zprofile changed while the command-path plan was being reviewed")
		}
		updated := appendCommandPathBlock(current, commandPathBlock())
		if err := writeAtomicUserConfig(plan.profilePath, updated, plan.profileMode); err != nil {
			_ = transaction.rollback()
			return nil, err
		}
	}
	return transaction, nil
}

func (transaction *commandDiscoveryTransaction) rollback() error {
	if transaction == nil || transaction.linkPath == "" {
		return nil
	}
	var failures []error
	if err := os.Remove(transaction.linkPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		failures = append(failures, errors.New("remove OneNod user command symlink failed"))
	} else if transaction.linkExisted {
		if err := os.Symlink(transaction.linkTarget, transaction.linkPath); err != nil {
			failures = append(failures, errors.New("restore prior user command symlink failed"))
		}
	}
	if transaction.profilePath != "" {
		if transaction.profileExists {
			if err := writeAtomicUserConfig(
				transaction.profilePath,
				transaction.profileContent,
				transaction.profileMode,
			); err != nil {
				failures = append(failures, errors.New("restore ~/.zprofile failed"))
			}
		} else if err := os.Remove(transaction.profilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, errors.New("remove OneNod-created ~/.zprofile failed"))
		}
	}
	return errors.Join(failures...)
}

func ensureUserCommandDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return errors.New("create ~/.local/bin failed")
		}
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("~/.local/bin must be a directory, not a symlink")
	}
	return nil
}

func readOptionalShellProfile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() < 0 || info.Size() > maxManifestBytes {
		return nil, false, errors.New("~/.zprofile must be a bounded regular file, not a symlink")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false, errors.New("read ~/.zprofile failed")
	}
	return content, true, nil
}

func commandPathBlock() string {
	return commandPathBlockStart + "\n" +
		`export PATH="$HOME/.local/bin:$PATH"` + "\n" +
		commandPathBlockEnd + "\n"
}

func inspectCommandPathBlock(content []byte, expected string) (bool, bool) {
	text := string(content)
	start := strings.Index(text, commandPathBlockStart)
	end := strings.Index(text, commandPathBlockEnd)
	if start < 0 && end < 0 {
		return false, false
	}
	if start < 0 || end < start {
		return false, true
	}
	end += len(commandPathBlockEnd)
	if end < len(text) && text[end] == '\n' {
		end++
	}
	return text[start:end] == expected, text[start:end] != expected
}

func appendCommandPathBlock(content []byte, block string) []byte {
	updated := append([]byte(nil), content...)
	if len(updated) > 0 && updated[len(updated)-1] != '\n' {
		updated = append(updated, '\n')
	}
	if len(updated) > 0 {
		updated = append(updated, '\n')
	}
	updated = append(updated, block...)
	return updated
}

func pathContainsDirectory(pathValue string, directory string) bool {
	expected := filepath.Clean(directory)
	for _, entry := range filepath.SplitList(pathValue) {
		if entry != "" && filepath.Clean(entry) == expected {
			return true
		}
	}
	return false
}
