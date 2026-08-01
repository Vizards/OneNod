package main

import (
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	userAgentDirectoryName = ".onenod"
	userAgentEnvFileName   = "env"
	userAgentOriginKey     = "ONENOD_ORIGIN"
	maxUserAgentEnvBytes   = 4096
	oneNodAgentLabel       = "com.github.vizards.onenod.ssh-agent"
	launchctlStartAttempts = 3
	launchctlRetryDelay    = 100 * time.Millisecond
	agentReadyAttempts     = 20
	agentReadyRetryDelay   = 50 * time.Millisecond
)

type userCLIInstallPlan struct {
	adapterPath     string
	binaryPath      string
	launchAgentPath string
	socketPath      string
}

type approvalAgentProbe func(socketPath string) error
type launchctlRunner func(arguments ...string) ([]byte, error)
type sleeper func(time.Duration)

func resolveDefaultConfiguredOrigin() (string, error) {
	if configured := os.Getenv(userAgentOriginKey); configured != "" {
		return configured, nil
	}
	return installedUserOrigin()
}

func installedUserOrigin() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for may configuration failed")
	}
	return readInstalledUserOrigin(filepath.Join(home, userAgentDirectoryName, userAgentEnvFileName))
}

func readInstalledUserOrigin(path string) (string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("installed may configuration must be a regular file, not a symlink")
	}
	if info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxUserAgentEnvBytes {
		return "", errors.New("installed may configuration has an invalid mode or size")
	}
	fileDescriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", errors.New("open installed may configuration failed")
	}
	file := os.NewFile(uintptr(fileDescriptor), path)
	if file == nil {
		_ = unix.Close(fileDescriptor)
		return "", errors.New("open installed may configuration failed")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return "", errors.New("installed may configuration changed while opening")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxUserAgentEnvBytes+1))
	if err != nil || len(encoded) > maxUserAgentEnvBytes {
		return "", errors.New("read installed may configuration failed")
	}
	return parseInstalledUserOrigin(string(encoded))
}

func parseInstalledUserOrigin(encoded string) (string, error) {
	if strings.Contains(encoded, "\r") || strings.Count(encoded, "\n") != 1 || !strings.HasSuffix(encoded, "\n") {
		return "", errors.New("installed may configuration must contain exactly one newline-terminated entry")
	}
	entry := strings.TrimSuffix(encoded, "\n")
	key, value, found := strings.Cut(entry, "=")
	if !found || key != userAgentOriginKey || value == "" {
		return "", errors.New("installed may configuration may contain only ONENOD_ORIGIN")
	}
	parsed, err := parseGatewayOrigin(value)
	if err != nil || parsed.String() != value {
		return "", errors.New("installed may Origin is invalid or not normalized")
	}
	return value, nil
}

func ensureLaunchAgentDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return errors.New("create LaunchAgents directory failed")
		}
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("LaunchAgents path must be a directory, not a symlink")
	}
	return nil
}

func renderApprovalAgentPlist(binaryPath, logDirectory string) string {
	binary := html.EscapeString(binaryPath)
	stdout := html.EscapeString(filepath.Join(logDirectory, "ssh-agent.log"))
	stderr := html.EscapeString(filepath.Join(logDirectory, "ssh-agent.error.log"))
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + oneNodAgentLabel + `</string>
  <key>ProgramArguments</key><array><string>` + binary + `</string><string>agent</string><string>serve</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>` + stdout + `</string>
  <key>StandardErrorPath</key><string>` + stderr + `</string>
</dict>
</plist>
`
}

func ensurePrivateInstallDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil {
			return errors.New("create private may installation directory failed")
		}
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("may installation directory must be a directory, not a symlink")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return errors.New("secure may installation directory failed")
	}
	return nil
}

func activateApprovalAgent(plan *userCLIInstallPlan) error {
	if err := activateApprovalAgentWith(plan, runLaunchctl, time.Sleep); err != nil {
		return err
	}
	return waitForApprovalAgentReady(plan.socketPath, probeApprovalAgentSocket, time.Sleep)
}

func activateApprovalAgentWith(plan *userCLIInstallPlan, run launchctlRunner, sleep sleeper) error {
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	output, _ := run("bootout", domain+"/"+oneNodAgentLabel)
	zeroBytes(output)
	for attempt := 0; attempt < launchctlStartAttempts; attempt++ {
		if attempt > 0 {
			sleep(launchctlRetryDelay)
		}
		output, err := run("bootstrap", domain, plan.launchAgentPath)
		zeroBytes(output)
		if err == nil {
			return nil
		}
	}
	return errors.New("may was installed but its SSH agent LaunchAgent could not start")
}

func runLaunchctl(arguments ...string) ([]byte, error) {
	return exec.Command("/bin/launchctl", arguments...).CombinedOutput()
}

func waitForApprovalAgentReady(socketPath string, probe approvalAgentProbe, sleep sleeper) error {
	for attempt := 0; attempt < agentReadyAttempts; attempt++ {
		if attempt > 0 {
			sleep(agentReadyRetryDelay)
		}
		if err := probe(socketPath); err == nil {
			return nil
		}
	}
	return errors.New("may was installed but its SSH agent did not become ready")
}

func probeApprovalAgentSocket(socketPath string) error {
	connection, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
	if err != nil {
		return err
	}
	return connection.Close()
}
