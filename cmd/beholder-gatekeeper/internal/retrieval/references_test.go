package retrieval

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestReferenceDiagnostics(t *testing.T) {
	for _, test := range []struct {
		raw               string
		refs, diagnostics []string
	}{
		{`["session:L1","request:L1"]`, []string{"session:L1", "request:L1"}, nil},
		{``, nil, []string{"missing"}}, {`null`, nil, []string{"missing"}}, {`[]`, nil, []string{"missing"}},
		{`"session:L1"`, nil, []string{"malformed"}},
		{`["session:L2"]`, []string{"session:L2"}, []string{"unread-reference"}},
		{`["session:L0","request:L2","/tmp/file"]`, []string{"request:L2"}, []string{"invalid-reference", "unread-reference"}},
	} {
		refs, diagnostics := ReviewReferences(json.RawMessage(test.raw), map[string]bool{"session:L1": true, "request:L1": true})
		if !reflect.DeepEqual(refs, test.refs) || !reflect.DeepEqual(diagnostics, test.diagnostics) {
			t.Fatal(test.raw, refs, diagnostics)
		}
	}
}
