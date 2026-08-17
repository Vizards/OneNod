package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/1Password/shell-plugins/sdk/schema"
)

const (
	shellPluginUsage           = "usage: may plugin <enable|status|doctor|credential|disable> ..."
	shellPluginEnableUsage     = "usage: may plugin enable <plugin-or-command> --scope <global|directory> [--item <id-or-title>] [--search <query>] [--field Name=<id-or-label>] [--target <path>]"
	shellPluginStatusUsage     = "usage: may plugin status [plugin-or-command]"
	shellPluginDoctorUsage     = "usage: may plugin doctor <plugin-or-command>"
	shellPluginCredentialUsage = "usage: may plugin credential <plugin-or-command> --scope <global|directory> [--item <id-or-title>] [--search <query>] [--field Name=<id-or-label>]"
	shellPluginDisableUsage    = "usage: may plugin disable <plugin-or-command> --scope <global|directory>"
)

type repeatedShellPluginFieldFlag []string

func (values *repeatedShellPluginFieldFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *repeatedShellPluginFieldFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func runPlugin(args []string, config cliConfig, deps dependencies) error {
	if len(args) == 0 {
		return errors.New(shellPluginUsage)
	}
	switch args[0] {
	case "enable":
		return runShellPluginEnable(args[1:], config, deps)
	case "status":
		return runShellPluginStatus(args[1:], deps)
	case "doctor":
		return runShellPluginDoctor(args[1:], deps)
	case "credential":
		return runShellPluginCredential(args[1:], config, deps)
	case "disable":
		return runShellPluginDisable(args[1:], deps)
	default:
		return fmt.Errorf("unknown plugin command %q", args[0])
	}
}

func parseShellPluginFlags(flags *flag.FlagSet, args []string) error {
	if len(args) > 0 && args[0] != "--" && !strings.HasPrefix(args[0], "-") {
		pluginName := args[0]
		args = append(append([]string(nil), args[1:]...), pluginName)
	}
	return flags.Parse(args)
}

func runShellPluginEnable(args []string, cli cliConfig, deps dependencies) error {
	flags := flag.NewFlagSet("plugin enable", flag.ContinueOnError)
	flags.SetOutput(writerOrDefault(deps.stderr, os.Stderr))
	scopeValue := flags.String("scope", "", "binding scope: global or directory")
	itemReference := flags.String("item", "", "exact Agent Vault item ID or title")
	searchQuery := flags.String("search", "", "Agent Vault catalog query")
	targetValue := flags.String("target", "", "real executable path")
	var fieldValues repeatedShellPluginFieldFlag
	flags.Var(&fieldValues, "field", "credential field mapping Name=<id-or-label>; repeatable")
	if err := parseShellPluginFlags(flags, args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New(shellPluginEnableUsage)
	}
	definition, found, err := shellPluginDefinitionByName(flags.Arg(0))
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("unsupported shell plugin %q", flags.Arg(0))
	}
	home, cwd, err := shellPluginHomeAndCWD()
	if err != nil {
		return err
	}
	scope, err := requestedShellPluginScope(*scopeValue, cwd)
	if err != nil {
		return err
	}
	target, err := resolveShellPluginTarget(definition.Command, *targetValue, scope, cwd, home)
	if err != nil {
		return err
	}
	config, err := readShellPluginConfig(home)
	if err != nil {
		return err
	}
	entry, err := inspectShellPluginEntry(home, definition.Command)
	if err != nil {
		return err
	}
	if entry.Exists && !entry.Managed {
		return fmt.Errorf("command entry %s is already owned by another installation", entry.Path)
	}
	fieldOverrides, err := parseShellPluginFieldOverrides(definition, fieldValues)
	if err != nil {
		return err
	}
	cli, deps, err = prepareRequesterInvocation(cli, deps)
	if err != nil {
		return err
	}
	item, fields, err := selectShellPluginCredential(
		definition, *itemReference, *searchQuery, fieldOverrides, cli, deps,
	)
	if err != nil {
		return err
	}
	binding := shellPluginBinding{
		Command:          definition.Command,
		CredentialFields: fields,
		ItemID:           item.ItemID,
		ItemTitle:        item.Title,
		Plugin:           definition.Plugin.Name,
		Scope:            scope,
		Target:           target,
		UpstreamRevision: shellPluginUpstreamRevision,
	}
	writeShellPluginEnablePlan(writerOrDefault(deps.stdout, os.Stdout), definition, binding, entry.Path)
	confirmed, err := promptYesNo(
		readerOrDefault(deps.stdin, os.Stdin),
		writerOrDefault(deps.stdout, os.Stdout),
		"Apply this OneNod command-routing change?",
		false,
	)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("shell plugin configuration was not changed")
	}
	if err := requireUnchangedShellPluginConfig(home, config); err != nil {
		return err
	}
	if _, err := validateShellPluginTarget(definition.Command, target, home); err != nil {
		return err
	}
	createdEntry, err := applyShellPluginEntry(home, definition.Command)
	if err != nil {
		return err
	}
	index := exactShellPluginBindingIndex(config, definition.Command, scope)
	if index >= 0 {
		config.Bindings[index] = binding
	} else {
		config.Bindings = append(config.Bindings, binding)
	}
	if err := writeShellPluginConfig(home, config); err != nil {
		if createdEntry {
			_, _ = removeShellPluginEntry(home, definition.Command)
		}
		return err
	}
	fmt.Fprintf(writerOrDefault(deps.stdout, os.Stdout), "Enabled OneNod for bare %s commands in %s scope.\n", definition.Command, formatShellPluginScope(scope))
	return nil
}

func runShellPluginCredential(args []string, cli cliConfig, deps dependencies) error {
	flags := flag.NewFlagSet("plugin credential", flag.ContinueOnError)
	flags.SetOutput(writerOrDefault(deps.stderr, os.Stderr))
	scopeValue := flags.String("scope", "", "binding scope: global or directory")
	itemReference := flags.String("item", "", "exact Agent Vault item ID or title")
	searchQuery := flags.String("search", "", "Agent Vault catalog query")
	var fieldValues repeatedShellPluginFieldFlag
	flags.Var(&fieldValues, "field", "credential field mapping Name=<id-or-label>; repeatable")
	if err := parseShellPluginFlags(flags, args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New(shellPluginCredentialUsage)
	}
	definition, found, err := shellPluginDefinitionByName(flags.Arg(0))
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("unsupported shell plugin %q", flags.Arg(0))
	}
	home, cwd, err := shellPluginHomeAndCWD()
	if err != nil {
		return err
	}
	scope, err := requestedShellPluginScope(*scopeValue, cwd)
	if err != nil {
		return err
	}
	config, err := readShellPluginConfig(home)
	if err != nil {
		return err
	}
	index := exactShellPluginBindingIndex(config, definition.Command, scope)
	if index < 0 {
		return fmt.Errorf("no exact %s binding exists in %s scope", definition.Command, formatShellPluginScope(scope))
	}
	overrides, err := parseShellPluginFieldOverrides(definition, fieldValues)
	if err != nil {
		return err
	}
	cli, deps, err = prepareRequesterInvocation(cli, deps)
	if err != nil {
		return err
	}
	item, fields, err := selectShellPluginCredential(
		definition, *itemReference, *searchQuery, overrides, cli, deps,
	)
	if err != nil {
		return err
	}
	fmt.Fprintf(writerOrDefault(deps.stdout, os.Stdout), "OneNod %s credential change plan:\n", definition.Command)
	fmt.Fprintf(writerOrDefault(deps.stdout, os.Stdout), "  scope: %s\n", formatShellPluginScope(scope))
	fmt.Fprintf(writerOrDefault(deps.stdout, os.Stdout), "  item: %s (%s)\n", item.Title, item.ItemID)
	writeShellPluginFieldPlan(writerOrDefault(deps.stdout, os.Stdout), fields)
	confirmed, err := promptYesNo(
		readerOrDefault(deps.stdin, os.Stdin), writerOrDefault(deps.stdout, os.Stdout),
		"Change this OneNod credential binding?", false,
	)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("shell plugin credential binding was not changed")
	}
	if err := requireUnchangedShellPluginConfig(home, config); err != nil {
		return err
	}
	config.Bindings[index].ItemID = item.ItemID
	config.Bindings[index].ItemTitle = item.Title
	config.Bindings[index].CredentialFields = fields
	config.Bindings[index].UpstreamRevision = shellPluginUpstreamRevision
	if err := writeShellPluginConfig(home, config); err != nil {
		return err
	}
	fmt.Fprintf(writerOrDefault(deps.stdout, os.Stdout), "Updated the %s credential binding without reading a secret value.\n", definition.Command)
	return nil
}

func runShellPluginStatus(args []string, deps dependencies) error {
	if len(args) > 1 {
		return errors.New(shellPluginStatusUsage)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve user home for shell plugin status failed")
	}
	config, err := readShellPluginConfig(home)
	if err != nil {
		return err
	}
	command := ""
	if len(args) == 1 {
		definition, found, err := shellPluginDefinitionByName(args[0])
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("unsupported shell plugin %q", args[0])
		}
		command = definition.Command
	}
	output := writerOrDefault(deps.stdout, os.Stdout)
	written := 0
	for _, binding := range config.Bindings {
		if command != "" && binding.Command != command {
			continue
		}
		entry, err := inspectShellPluginEntry(home, binding.Command)
		if err != nil {
			return err
		}
		status := "entry_missing"
		if entry.Managed {
			status = "configured"
		} else if entry.Exists {
			status = "entry_conflict"
		}
		fmt.Fprintf(output, "%s: %s\n", binding.Command, status)
		fmt.Fprintf(output, "  plugin: %s @ %s\n", binding.Plugin, binding.UpstreamRevision)
		fmt.Fprintf(output, "  scope: %s\n", formatShellPluginScope(binding.Scope))
		fmt.Fprintf(output, "  target: %s\n", binding.Target)
		fmt.Fprintf(output, "  item: %s (%s)\n", binding.ItemTitle, binding.ItemID)
		writeShellPluginFieldPlan(output, binding.CredentialFields)
		if binding.UpstreamRevision != shellPluginUpstreamRevision {
			fmt.Fprintf(output, "  definition: configured revision differs from this release (%s)\n", shellPluginUpstreamRevision)
		}
		written++
	}
	if written == 0 {
		if command == "" {
			fmt.Fprintln(output, "No OneNod shell plugin bindings are configured.")
		} else {
			fmt.Fprintf(output, "%s: not_configured\n", command)
		}
	}
	return nil
}

func runShellPluginDoctor(args []string, deps dependencies) error {
	if len(args) != 1 {
		return errors.New(shellPluginDoctorUsage)
	}
	definition, found, err := shellPluginDefinitionByName(args[0])
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("unsupported shell plugin %q", args[0])
	}
	home, cwd, err := shellPluginHomeAndCWD()
	if err != nil {
		return err
	}
	config, err := readShellPluginConfig(home)
	if err != nil {
		return err
	}
	binding, configured, err := selectShellPluginBinding(config, definition.Command, cwd)
	if err != nil {
		return err
	}
	output := writerOrDefault(deps.stdout, os.Stdout)
	if !configured {
		fmt.Fprintf(output, "%s: no binding applies to %s\n", definition.Command, cwd)
		return nil
	}
	entry, err := inspectShellPluginEntry(home, definition.Command)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "%s doctor:\n", definition.Command)
	fmt.Fprintf(output, "  binding: %s\n", formatShellPluginScope(binding.Scope))
	if entry.Managed {
		fmt.Fprintf(output, "  managed entry: %s\n", entry.Path)
	} else if entry.Exists {
		fmt.Fprintf(output, "  managed entry: conflict at %s\n", entry.Path)
	} else {
		fmt.Fprintf(output, "  managed entry: missing at %s\n", entry.Path)
	}
	if _, err := validateShellPluginTarget(definition.Command, binding.Target, home); err != nil {
		fmt.Fprintf(output, "  target: unavailable (%v)\n", err)
	} else {
		fmt.Fprintf(output, "  target: %s\n", binding.Target)
	}
	if resolved, err := exec.LookPath(definition.Command); err != nil {
		fmt.Fprintln(output, "  PATH: bare command is not currently discoverable")
	} else if filepath.Clean(resolved) != filepath.Clean(entry.Path) {
		fmt.Fprintf(output, "  PATH: bare command currently resolves to %s instead of the managed entry\n", resolved)
	} else {
		fmt.Fprintln(output, "  PATH: bare command resolves to the managed entry")
	}
	if projectTarget, found := nearestProjectExecutable(cwd, definition.Command); found {
		fmt.Fprintf(output, "  package-manager bypass: %s may be executed directly by package scripts or pnpm exec\n", projectTarget)
	}
	var ambient []string
	for _, name := range definition.EnvironmentNames {
		if _, exists := os.LookupEnv(name); exists {
			ambient = append(ambient, name)
		}
	}
	if len(ambient) != 0 {
		fmt.Fprintf(output, "  ambient credential variables present: %s (values not inspected)\n", strings.Join(ambient, ", "))
	}
	fmt.Fprintln(output, "  coverage: bare command only; absolute paths and package-manager private entrypoints can bypass routing")
	return nil
}

func runShellPluginDisable(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("plugin disable", flag.ContinueOnError)
	flags.SetOutput(writerOrDefault(deps.stderr, os.Stderr))
	scopeValue := flags.String("scope", "", "binding scope: global or directory")
	if err := parseShellPluginFlags(flags, args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New(shellPluginDisableUsage)
	}
	definition, found, err := shellPluginDefinitionByName(flags.Arg(0))
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("unsupported shell plugin %q", flags.Arg(0))
	}
	home, cwd, err := shellPluginHomeAndCWD()
	if err != nil {
		return err
	}
	scope, err := requestedShellPluginScope(*scopeValue, cwd)
	if err != nil {
		return err
	}
	config, err := readShellPluginConfig(home)
	if err != nil {
		return err
	}
	index := exactShellPluginBindingIndex(config, definition.Command, scope)
	if index < 0 {
		return fmt.Errorf("no exact %s binding exists in %s scope", definition.Command, formatShellPluginScope(scope))
	}
	output := writerOrDefault(deps.stdout, os.Stdout)
	fmt.Fprintf(output, "Disable OneNod %s binding in %s scope.\n", definition.Command, formatShellPluginScope(scope))
	fmt.Fprintln(output, "The 1Password item and all credential values will remain unchanged.")
	confirmed, err := promptYesNo(
		readerOrDefault(deps.stdin, os.Stdin), output,
		"Remove this OneNod command-routing binding?", false,
	)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("shell plugin binding was not disabled")
	}
	if err := requireUnchangedShellPluginConfig(home, config); err != nil {
		return err
	}
	config.Bindings = append(config.Bindings[:index], config.Bindings[index+1:]...)
	removeEntry := !configHasShellPluginCommand(config, definition.Command)
	entryRemoved := false
	if removeEntry {
		entryRemoved, err = removeShellPluginEntry(home, definition.Command)
		if err != nil {
			return err
		}
	}
	if err := writeShellPluginConfig(home, config); err != nil {
		if entryRemoved {
			_, restoreErr := applyShellPluginEntry(home, definition.Command)
			if restoreErr != nil {
				return fmt.Errorf("write shell plugin configuration failed and managed entry restore also failed: %v; %w", restoreErr, err)
			}
		}
		return err
	}
	fmt.Fprintf(output, "Disabled the %s binding; no credential was deleted or changed.\n", definition.Command)
	return nil
}

func shellPluginHomeAndCWD() (string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", errors.New("resolve user home for shell plugin failed")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", errors.New("resolve current directory for shell plugin failed")
	}
	return home, cwd, nil
}

func parseShellPluginFieldOverrides(
	definition shellPluginDefinition,
	values []string,
) (map[string]string, error) {
	canonical := make(map[string]string)
	for _, field := range definition.Credential.Fields {
		canonical[strings.ToLower(field.Name.String())] = field.Name.String()
	}
	result := make(map[string]string)
	for _, value := range values {
		name, reference, found := strings.Cut(value, "=")
		name = canonical[strings.ToLower(strings.TrimSpace(name))]
		reference = strings.TrimSpace(reference)
		if !found || name == "" || reference == "" || containsControl(reference) || len(reference) > 256 {
			return nil, fmt.Errorf("invalid --field mapping %q", value)
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate --field mapping for %s", name)
		}
		result[name] = reference
	}
	return result, nil
}

func selectShellPluginCredential(
	definition shellPluginDefinition,
	itemReference string,
	searchQuery string,
	fieldOverrides map[string]string,
	cli cliConfig,
	deps dependencies,
) (catalogItemResult, map[string]shellPluginFieldBinding, error) {
	query := strings.TrimSpace(searchQuery)
	if strings.TrimSpace(itemReference) != "" {
		query = strings.TrimSpace(itemReference)
	}
	if query == "" {
		query = definition.Plugin.Platform.Name
	}
	response, err := searchShellPluginCatalog(cli, deps, query)
	if err != nil {
		return catalogItemResult{}, nil, err
	}
	items := response.Items
	if strings.TrimSpace(itemReference) != "" {
		var exact []catalogItemResult
		for _, item := range items {
			if item.ItemID == itemReference || item.Title == itemReference {
				exact = append(exact, item)
			}
		}
		items = exact
		if len(items) > 1 {
			return catalogItemResult{}, nil, fmt.Errorf("exact Agent Vault item reference %q is ambiguous", itemReference)
		}
	}
	if len(items) == 0 {
		return catalogItemResult{}, nil, fmt.Errorf("no exact Agent Vault item matched %q; copy the intended credential into Agent and retry", query)
	}
	item, err := chooseShellPluginItem(items, deps)
	if err != nil {
		return catalogItemResult{}, nil, err
	}
	fields := make(map[string]shellPluginFieldBinding)
	for _, schemaField := range definition.Credential.Fields {
		reference, overridden := fieldOverrides[schemaField.Name.String()]
		if schemaField.Optional && !overridden {
			continue
		}
		selected, err := chooseShellPluginField(schemaField, item.Fields, reference, deps)
		if err != nil {
			return catalogItemResult{}, nil, fmt.Errorf("resolve %s field: %w", schemaField.Name, err)
		}
		fields[schemaField.Name.String()] = shellPluginFieldBinding{
			FieldID: selected.FieldID,
			Label:   selected.Label,
		}
	}
	return item, fields, nil
}

func searchShellPluginCatalog(cli cliConfig, deps dependencies, query string) (catalogSearchResponse, error) {
	credential, err := deps.keychain.Load()
	if err != nil {
		return catalogSearchResponse{}, err
	}
	client, err := newAPIClient(cli.origin, credential, deps.httpClient)
	if err != nil {
		return catalogSearchResponse{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), gatewayRequestTimeout)
	defer cancel()
	return searchCatalogWithLocalFallback(ctx, client, query, deps)
}

func chooseShellPluginItem(items []catalogItemResult, deps dependencies) (catalogItemResult, error) {
	if len(items) == 1 {
		return items[0], nil
	}
	output := writerOrDefault(deps.stdout, os.Stdout)
	fmt.Fprintln(output, "Matching Agent Vault items:")
	for index, item := range items {
		fmt.Fprintf(output, "  %d. %s [%s] (%s)\n", index+1, item.Title, item.Category, item.ItemID)
	}
	choice, err := readShellPluginChoice(
		readerOrDefault(deps.stdin, os.Stdin), output, "Select credential item", len(items),
	)
	if err != nil {
		return catalogItemResult{}, err
	}
	return items[choice], nil
}

func chooseShellPluginField(
	schemaField schema.CredentialField,
	fields []catalogFieldResult,
	reference string,
	deps dependencies,
) (catalogFieldResult, error) {
	compatible := make([]catalogFieldResult, 0, len(fields))
	for _, field := range fields {
		if shellPluginFieldTypeCompatible(schemaField, field) {
			compatible = append(compatible, field)
		}
	}
	if reference != "" {
		var matches []catalogFieldResult
		for _, field := range compatible {
			if field.FieldID == reference {
				return field, nil
			}
			if field.Label == reference {
				matches = append(matches, field)
			}
		}
		if len(matches) != 1 {
			return catalogFieldResult{}, fmt.Errorf("field reference %q resolved to %d compatible matches", reference, len(matches))
		}
		return matches[0], nil
	}
	desiredNames := []string{schemaField.Name.String()}
	desiredNames = append(desiredNames, schemaField.AlternativeNames...)
	var named []catalogFieldResult
	for _, field := range compatible {
		for _, name := range desiredNames {
			if strings.EqualFold(strings.TrimSpace(field.Label), strings.TrimSpace(name)) {
				named = append(named, field)
				break
			}
		}
	}
	if len(named) == 1 {
		return named[0], nil
	}
	if len(named) > 1 {
		compatible = named
	}
	if len(compatible) == 0 {
		return catalogFieldResult{}, errors.New("selected item has no compatible field")
	}
	if len(compatible) == 1 {
		return compatible[0], nil
	}
	output := writerOrDefault(deps.stdout, os.Stdout)
	fmt.Fprintf(output, "Compatible fields for %s:\n", schemaField.Name)
	for index, field := range compatible {
		fmt.Fprintf(output, "  %d. %s [%s] (%s)\n", index+1, field.Label, field.FieldType, field.FieldID)
	}
	choice, err := readShellPluginChoice(
		readerOrDefault(deps.stdin, os.Stdin), output,
		"Select field for "+schemaField.Name.String(), len(compatible),
	)
	if err != nil {
		return catalogFieldResult{}, err
	}
	return compatible[choice], nil
}

func shellPluginFieldTypeCompatible(schemaField schema.CredentialField, field catalogFieldResult) bool {
	if !schemaField.Secret {
		return !strings.EqualFold(field.FieldType, "SshKey")
	}
	switch strings.ToLower(strings.TrimSpace(field.FieldType)) {
	case "concealed", "credential", "password", "secret", "token":
		return true
	default:
		return false
	}
}

func readShellPluginChoice(input io.Reader, output io.Writer, prompt string, maximum int) (int, error) {
	if maximum <= 0 {
		return 0, errors.New("interactive selection has no choices")
	}
	if file, ok := input.(*os.File); ok {
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return 0, errors.New("credential selection requires an interactive terminal")
		}
	}
	fmt.Fprintf(output, "%s [1-%d]: ", prompt, maximum)
	line, err := readPromptLine(input)
	if err != nil {
		return 0, errors.New("read credential selection failed")
	}
	selected, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || selected < 1 || selected > maximum {
		return 0, fmt.Errorf("selection must be between 1 and %d", maximum)
	}
	return selected - 1, nil
}

func writeShellPluginEnablePlan(
	output io.Writer,
	definition shellPluginDefinition,
	binding shellPluginBinding,
	entryPath string,
) {
	fmt.Fprintf(output, "OneNod %s enable plan:\n", definition.Executable.Name)
	fmt.Fprintf(output, "  definition: 1Password shell plugin %s @ %s\n", definition.Plugin.Name, shellPluginUpstreamRevision)
	fmt.Fprintf(output, "  managed command: %s\n", entryPath)
	fmt.Fprintf(output, "  real executable: %s\n", binding.Target)
	fmt.Fprintf(output, "  scope: %s\n", formatShellPluginScope(binding.Scope))
	fmt.Fprintf(output, "  item: %s (%s)\n", binding.ItemTitle, binding.ItemID)
	writeShellPluginFieldPlan(output, binding.CredentialFields)
	fmt.Fprintln(output, "  secret storage: no credential value will be written locally")
}

func writeShellPluginFieldPlan(output io.Writer, fields map[string]shellPluginFieldBinding) {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		field := fields[name]
		fmt.Fprintf(output, "  field %s: %s (%s)\n", name, field.Label, field.FieldID)
	}
}

func formatShellPluginScope(scope shellPluginScope) string {
	if scope.Kind == "directory" {
		return "directory " + scope.Root
	}
	return scope.Kind
}

func requireUnchangedShellPluginConfig(home string, expected shellPluginConfig) error {
	current, err := readShellPluginConfig(home)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, expected) {
		return errors.New("OneNod shell plugin configuration changed while the plan was being reviewed")
	}
	return nil
}
