package retrieval

import (
	"bufio"
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzStreamingPayload(f *testing.F) {
	for _, value := range []string{`{"text":"\u53d1\u7248","n":-0.12e+4}`, `[true,false,null,"汉🧪"]`, `{"x":"\ud800x\ud83e\uddea\u0000"}`, `{"a":1,"a":2}`, `0`, `1e`, `{"x":01}`, `"bad\q"`} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 8192 || !utf8.ValidString(value) || strings.Contains(value, "\n") {
			t.Skip()
		}
		input := `{"type":"response_item","payload":` + value + `}`
		var output bytes.Buffer
		buffer := bufio.NewWriter(&output)
		writer := &payloadWriter{out: buffer}
		parser := newJSONStream(strings.NewReader(input), writer)
		err := parser.envelope()
		buffer.Flush()
		if (err == nil) != json.Valid([]byte(input)) {
			t.Fatal("streaming JSON acceptance differs")
		}
		if err != nil {
			return
		}
		var before, after any
		decode := func(text string, target *any) {
			d := json.NewDecoder(strings.NewReader(text))
			d.UseNumber()
			if err := d.Decode(target); err != nil {
				t.Fatal(err)
			}
		}
		decode(value, &before)
		decode(output.String(), &after)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("normalization changed a JSON value")
		}
	})
}
