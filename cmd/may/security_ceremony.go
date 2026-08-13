package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

type firstExecutionOperation string

const (
	firstExecutionInstall      firstExecutionOperation = "install"
	firstExecutionOperatorInit firstExecutionOperation = "operator-init"
)

// confirmFirstExecutionCeremony is deliberately independent of terminal-type
// detection. The caller supplies the human-owned input and output streams, so
// tests and embedding environments exercise exactly the same default-no gate.
func confirmFirstExecutionCeremony(
	input io.Reader,
	output io.Writer,
	operation firstExecutionOperation,
	detail string,
) error {
	if operation != firstExecutionInstall && operation != firstExecutionOperatorInit {
		return errors.New("unknown first-execution operation")
	}
	fmt.Fprintln(output, "FIRST EXECUTION SECURITY CEREMONY")
	fmt.Fprintln(output, "No trusted OneNod initializer or complete local installation was found for this macOS user.")
	fmt.Fprintln(output, "The independently verified temporary may is about to establish OneNod's exact-build trust on this Mac.")
	fmt.Fprintf(output, "Operation: %s\n", detail)
	fmt.Fprintln(output, "Before continuing, stop every Agent harness running as this same macOS user, including the Agent that downloaded or verified may.")
	fmt.Fprintln(output, "Continue only from a human-controlled terminal and review every Gatekeeper or Keychain prompt before approving it.")
	confirmed, err := confirmDefaultNoFromStreams(
		input,
		output,
		"Have all same-user Agent harnesses stopped, and do you want to begin this human-owned ceremony?",
	)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("first execution ceremony was not confirmed; no initializer, Keychain helper, managed Skill, or local installation state was changed")
	}
	return nil
}

func confirmFreshRequesterCeremony(
	input io.Reader,
	output io.Writer,
	origin string,
	displayName string,
) error {
	fmt.Fprintln(output, "REQUESTER KEYCHAIN SECURITY CEREMONY")
	fmt.Fprintf(output, "Gateway: %s\nRequester device label: %s\n", origin, displayName)
	fmt.Fprintln(output, "OneNod is about to create a fresh, Create-only requester credential and bind it to the installed exact may build.")
	fmt.Fprintln(output, "Stop every Agent harness running as this same macOS user, then continue only from a human-controlled terminal and review each Keychain prompt.")
	confirmed, err := confirmDefaultNoFromStreams(
		input,
		output,
		"Have all same-user Agent harnesses stopped, and do you want to create this requester credential?",
	)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("requester Keychain ceremony was not confirmed; no new requester credential was written")
	}
	return nil
}

func confirmDefaultNoFromStreams(
	input io.Reader,
	output io.Writer,
	prompt string,
) (bool, error) {
	fmt.Fprintf(output, "%s [y/N] ", prompt)
	line, err := readPromptLine(input)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, errors.New("read security confirmation failed")
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	case "", "n", "no":
		return false, nil
	default:
		return false, errors.New("confirmation must be y or n")
	}
}
