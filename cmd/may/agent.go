package main

import "errors"

func runAgent(args []string, config cliConfig, deps dependencies) error {
	if len(args) != 1 {
		return errors.New("usage: may [global flags] agent <serve|status|refresh>")
	}
	switch args[0] {
	case "serve":
		return runAgentServe(config, deps)
	case "status":
		return runAgentStatus(deps)
	case "refresh":
		identities, err := refreshSSHIdentityCache(config, deps)
		if err != nil {
			return err
		}
		return writeSafeJSON(deps.stdout, map[string]any{
			"identities": len(identities),
			"socket":     defaultAgentSocket(),
			"status":     "refreshed",
		})
	default:
		return errors.New("usage: may [global flags] agent <serve|status|refresh>")
	}
}
