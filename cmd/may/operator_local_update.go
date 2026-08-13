package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var (
	canonicalLocalUpdateHome     = canonicalExactBuildHome
	runInstalledLocalUpdateChild = runInstalledLocalUpdateProcess
)

// runInstalledLocalUpdate deliberately gives the local transaction back to an
// exact actor already trusted by the installed transport state. The operator
// updater remains responsible for Cloudflare, but it never exercises local
// helper authority on behalf of the current or staged release.
func runInstalledLocalUpdate(
	ctx context.Context,
	operatorOrigin, targetVersion, targetSourceCommit string,
	deps dependencies,
) error {
	actor, err := validateInstalledLocalUpdateHandoff(
		operatorOrigin, targetVersion, targetSourceCommit,
	)
	if err != nil {
		return err
	}
	fmt.Fprintf(
		deps.stdout,
		"Handing local update to the installed exact OneNod release at %s.\n",
		actor,
	)
	return runInstalledLocalUpdateChild(ctx, actor, targetVersion, deps)
}

func runInstalledLocalUpdateProcess(
	ctx context.Context,
	actor, targetVersion string,
	deps dependencies,
) error {
	if !validProductVersion(targetVersion) {
		return errors.New("installed local update target version is invalid")
	}
	command := exec.CommandContext(ctx, actor, "update", "--version", targetVersion)
	environment, err := localUpdateProcessEnvironment()
	if err != nil {
		return err
	}
	command.Env = environment
	command.Stdin = deps.stdin
	command.Stdout = deps.stdout
	command.Stderr = deps.stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return errors.New("installed current OneNod local update timed out")
		}
		return errors.New("installed current OneNod local update failed")
	}
	return nil
}

func localUpdateProcessEnvironment() ([]string, error) {
	home, err := canonicalExactBuildHome()
	if err != nil {
		return nil, err
	}
	environment := []string{"HOME=" + home}
	if path, found := os.LookupEnv("PATH"); found {
		if strings.IndexByte(path, 0) >= 0 {
			return nil, errors.New("local update PATH is invalid")
		}
		environment = append(environment, "PATH="+path)
	}
	return environment, nil
}

// validateInstalledLocalUpdateHandoff runs after the verified updater reexec
// but before Cloudflare authorization. In particular, an older unresolved
// local journal cannot be hidden by completing a newer remote deployment.
func validateInstalledLocalUpdateHandoff(
	operatorOrigin, targetVersion, targetSourceCommit string,
) (string, error) {
	if parsed, err := parseGatewayOrigin(operatorOrigin); err != nil ||
		parsed.String() != operatorOrigin || !validProductVersion(targetVersion) ||
		!commitPattern.MatchString(targetSourceCommit) {
		return "", errors.New("operator local update selection is invalid")
	}
	_, err := requireCanonicalLocalUpdateHome()
	if err != nil {
		return "", err
	}
	// Resolve and return the verified exact actor itself. Executing a stable
	// symlink after validating it would reopen a path-substitution window.
	actor, err := installedLocalUpdateActor(
		operatorOrigin, targetVersion, targetSourceCommit,
	)
	if err != nil {
		return "", err
	}
	return actor, nil
}

func requireCanonicalLocalUpdateHome() (string, error) {
	canonical, err := canonicalLocalUpdateHome()
	ambient, ambientErr := os.UserHomeDir()
	if err != nil || ambientErr != nil || ambient != canonical {
		return "", errors.New("local update requires the canonical account home")
	}
	return canonical, nil
}
