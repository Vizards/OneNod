package retrieval

import (
	"encoding/json"
	"strings"
)

// ReviewReferences reports citation quality without making an authorization
// decision. A returned page establishes only that a reference was delivered,
// not that the model interpreted it correctly or read an entire paged record.
func ReviewReferences(raw json.RawMessage, delivered map[string]bool) (refs, diagnostics []string) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, []string{"missing"}
	}
	var values []string
	if json.Unmarshal(raw, &values) != nil {
		return nil, []string{"malformed"}
	}
	if len(values) == 0 {
		return nil, []string{"missing"}
	}
	invalid, unread := false, false
	for _, ref := range values {
		if !ValidReference(ref) {
			invalid = true
			continue
		}
		refs = append(refs, ref)
		unread = unread || !delivered[ref]
	}
	if invalid {
		diagnostics = append(diagnostics, "invalid-reference")
	}
	if unread {
		diagnostics = append(diagnostics, "unread-reference")
	}
	return
}

func ValidReference(ref string) bool {
	if len(ref) > 256 {
		return false
	}
	for _, prefix := range []string{"session:L", "request:L"} {
		if digits, ok := strings.CutPrefix(ref, prefix); ok && digits != "" {
			for _, r := range digits {
				if r < '0' || r > '9' {
					return false
				}
			}
			return digits[0] != '0'
		}
	}
	return false
}
