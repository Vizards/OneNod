package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const gatewayRequestTimeout = 5 * time.Minute
const approvalObservationGrace = 5 * time.Second

type dependencies struct {
	applicationResolver    applicationResolver
	approvalAgentActivator func(*userCLIInstallPlan) error
	cloudflareTransport    http.RoundTripper
	httpClient             *http.Client
	keychain               keychainStore
	localOnePassword       localOnePasswordFactory
	localSSHAgent          localSSHAgentFactory
	platformProbe          func() (hostPlatform, error)
	releases               releaseSource
	stderr                 io.Writer
	stdin                  io.Reader
	stdout                 io.Writer
}

type cliConfig struct {
	origin       string
	pollInterval time.Duration
	timeout      time.Duration
}

func main() {
	deps := dependencies{
		applicationResolver: resolveApplicationWithHelper,
		httpClient:          &http.Client{Timeout: gatewayRequestTimeout},
		keychain:            keychainStore{},
		stderr:              os.Stderr,
		stdin:               os.Stdin,
		stdout:              os.Stdout,
	}
	var err error
	if filepath.Base(os.Args[0]) == "may" && len(os.Args) > 1 && os.Args[1] == "__transport-finalize" {
		err = runInternalTransportFinalize(os.Args[2:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "may: %v\n", err)
			os.Exit(1)
		}
		return
	}
	switch filepath.Base(os.Args[0]) {
	case gitSignAdapterBinaryName:
		err = runGitSignAdapter(os.Args[1:], deps)
	default:
		err = runCLI(os.Args[1:], deps)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "may: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(args []string, deps dependencies) error {
	if help, ok := requestedHelp(args); ok {
		fmt.Fprintln(deps.stderr, help)
		return nil
	}
	global := flag.NewFlagSet("may", flag.ContinueOnError)
	global.SetOutput(deps.stderr)
	config := cliConfig{}
	defaultConfiguredOrigin := os.Getenv(userAgentOriginKey)
	global.StringVar(
		&config.origin,
		"origin",
		defaultConfiguredOrigin,
		"gateway origin (global flag; place before the command)",
	)
	global.DurationVar(
		&config.pollInterval,
		"poll-interval",
		2*time.Second,
		"approval status polling interval",
	)
	global.DurationVar(
		&config.timeout,
		"timeout",
		10*time.Minute,
		"maximum human approval wait after a request is created",
	)
	global.Usage = func() {
		fmt.Fprintln(deps.stderr, usageText)
	}
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if config.pollInterval <= 0 || config.timeout <= 0 {
		return errors.New("poll-interval and timeout must be positive")
	}
	remaining := global.Args()
	if len(remaining) == 0 {
		global.Usage()
		return errors.New("a command is required")
	}
	if requesterCommand(remaining[0]) {
		if config.origin == "" {
			installedOrigin, err := installedUserOrigin()
			if err != nil {
				return err
			}
			config.origin = installedOrigin
		}
		if config.origin == "" {
			return errors.New(
				"Gateway origin is not configured; run may install --origin URL or pass --origin before the command",
			)
		}
		keychainService, err := requesterKeychainService(config.origin)
		if err != nil {
			return err
		}
		deps.keychain.service = keychainService
		deps.keychain.origin = config.origin
		activeSlot, selected, err := selectedRequesterSlot(config.origin)
		if err != nil {
			return err
		}
		if !selected {
			activeSlot = "active"
		}
		deps.keychain.slot = activeSlot
		deps.keychain.selected = selected
	}

	switch remaining[0] {
	case "preflight":
		return runPreflight(remaining[1:], config, deps)
	case "enroll":
		return runEnroll(remaining[1:], config, deps)
	case "catalog":
		return runCatalog(remaining[1:], config, deps)
	case "read":
		return runRead(remaining[1:], config, deps)
	case "secret":
		return runSecret(remaining[1:], config, deps)
	case "item":
		return runItem(remaining[1:], config, deps)
	case "ssh":
		return runSSH(remaining[1:], config, deps)
	case "agent":
		return runAgent(remaining[1:], config, deps)
	case "install":
		return runBinaryInstall(remaining[1:], deps)
	case "version":
		return runVersion(remaining[1:], deps)
	case "update":
		return runUpdate(remaining[1:], deps)
	case "configure":
		return runConfigure(remaining[1:], deps)
	case "dev":
		return runDev(remaining[1:], deps)
	case "operator":
		return runOperator(remaining[1:], deps)
	case "help", "-h", "--help":
		global.Usage()
		return nil
	default:
		global.Usage()
		return fmt.Errorf("unknown command %q", remaining[0])
	}
}

func requesterCommand(command string) bool {
	switch command {
	case "preflight", "enroll", "catalog", "read", "secret", "item", "ssh", "agent":
		return true
	default:
		return false
	}
}

const usageText = `may — requester for the OneNod approval gateway

Usage:
  may install --origin https://<worker>.<account>.workers.dev [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]
  may version [--json]
  may update check [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]] [--json]
  may update [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]
  may configure ssh <status|apply|restore>
  may configure git-signing status
  may configure git-signing apply --signing-key <key-or-path>
  may configure git-signing restore
  may configure local-fallback status
  may configure local-fallback apply [--account <1Password-account-name-or-UUID>]
  may configure local-fallback restore
  may [--origin URL] preflight
  may [--origin URL] enroll [--name "MacBook"] [--new-identity]
  may [--origin URL] catalog search <query>
  may [--origin URL] read [--no-newline] op://Agent/<item>/<field>
  may [--origin URL] secret read --item <id> --field <id> [--expected-version n] [--raw]
  may [--origin URL] item create --spec <file|->
  may [--origin URL] item patch --item <id> --spec <file|-> [--expected-version n]
  may [--origin URL] item archive --item <id> [--expected-version n]
  may [--origin URL] ssh public-key export --item <id> --output <path.pub>
  may [--origin URL] agent <serve|status|refresh>
  may dev verify-release --directory <dist/release> [--artifact <basename>]...
  may operator init [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]
  may operator update [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]
  may operator revoke-cloudflare

The install and update commands consume manifest- and provenance-verified artifacts from the
selected immutable GitHub Release channel in Vizards/OneNod; stable is the default. They never inspect a
source checkout or update external tools such as Wrangler or 1Password CLI.
For requester commands, the default origin is read from ONENOD_ORIGIN or the
strict per-user ~/.onenod/env, in that order.
Global flags must appear before the command.`

const secretReadUsage = "usage: may [global flags] secret read --item <id> --field <id> [--expected-version n] [--raw]"
const catalogSearchUsage = "usage: may [global flags] catalog search <query>"

func requestedHelp(args []string) (string, bool) {
	helpRequested := false
	for _, argument := range args {
		if argument == "-h" || argument == "--help" {
			helpRequested = true
			break
		}
	}
	if !helpRequested {
		for index := 0; index < len(args); index++ {
			argument := args[index]
			switch argument {
			case "-origin", "--origin", "-poll-interval", "--poll-interval", "-timeout", "--timeout":
				index++
				continue
			}
			if strings.HasPrefix(argument, "-origin=") || strings.HasPrefix(argument, "--origin=") ||
				strings.HasPrefix(argument, "-poll-interval=") || strings.HasPrefix(argument, "--poll-interval=") ||
				strings.HasPrefix(argument, "-timeout=") || strings.HasPrefix(argument, "--timeout=") {
				continue
			}
			helpRequested = argument == "help"
			break
		}
	}
	if !helpRequested {
		return "", false
	}

	command := make([]string, 0, 3)
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "help" || argument == "-h" || argument == "--help" {
			continue
		}
		if len(command) == 0 {
			switch argument {
			case "-origin", "--origin", "-poll-interval", "--poll-interval", "-timeout", "--timeout":
				index++
				continue
			}
			if strings.HasPrefix(argument, "-origin=") || strings.HasPrefix(argument, "--origin=") ||
				strings.HasPrefix(argument, "-poll-interval=") || strings.HasPrefix(argument, "--poll-interval=") ||
				strings.HasPrefix(argument, "-timeout=") || strings.HasPrefix(argument, "--timeout=") {
				continue
			}
		}
		if strings.HasPrefix(argument, "-") {
			continue
		}
		command = append(command, argument)
		if len(command) == 3 {
			break
		}
	}

	for length := len(command); length > 0; length-- {
		if help, exists := commandHelp[strings.Join(command[:length], " ")]; exists {
			return help, true
		}
	}
	return usageText, true
}

var commandHelp = map[string]string{
	"agent":                            "usage: may [global flags] agent <serve|status|refresh>",
	"catalog":                          catalogSearchUsage,
	"catalog search":                   catalogSearchUsage,
	"configure":                        "usage: may configure <ssh|git-signing|local-fallback> <status|apply|restore>",
	"configure git-signing":            "usage: may configure git-signing <status|apply|restore> [--signing-key key-or-path]",
	"configure git-signing apply":      "usage: may configure git-signing apply --signing-key <key-or-path>",
	"configure git-signing restore":    "usage: may configure git-signing restore",
	"configure git-signing status":     "usage: may configure git-signing status",
	"configure local-fallback":         "usage: may configure local-fallback <status|apply|restore> [--account name-or-uuid]",
	"configure local-fallback apply":   "usage: may configure local-fallback apply [--account name-or-uuid]",
	"configure local-fallback restore": "usage: may configure local-fallback restore",
	"configure local-fallback status":  "usage: may configure local-fallback status",
	"configure ssh":                    "usage: may configure ssh <status|apply|restore>",
	"dev":                              "usage: may dev verify-release --directory <path> [--artifact <basename>]...",
	"dev verify-release":               "usage: may dev verify-release --directory <path> [--artifact <basename>]...",
	"enroll":                           "usage: may [global flags] enroll [--name \"MacBook\"] [--new-identity]",
	"install":                          "usage: may install --origin https://<worker>.<account>.workers.dev [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]",
	"item":                             "usage: may [global flags] item <create|patch|archive> ...",
	"item archive":                     itemArchiveUsage,
	"item create":                      itemCreateUsage,
	"item patch":                       itemPatchUsage,
	"operator":                         operatorUsage,
	"operator init":                    "usage: may operator init [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]",
	"operator revoke-cloudflare":       "usage: may operator revoke-cloudflare",
	"operator update":                  "usage: may operator update [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]",
	"preflight":                        "usage: may [global flags] preflight",
	"read":                             "usage: may [global flags] read [--no-newline] op://Agent/<item>/<field>",
	"secret":                           secretReadUsage,
	"secret read":                      secretReadUsage,
	"ssh":                              sshPublicKeyExportUsage,
	"ssh public-key":                   sshPublicKeyExportUsage,
	"ssh public-key export":            sshPublicKeyExportUsage,
	"update":                           "usage: may update [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]",
	"update check":                     "usage: may update check [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]] [--json]",
	"version":                          "usage: may version [--json]",
}
