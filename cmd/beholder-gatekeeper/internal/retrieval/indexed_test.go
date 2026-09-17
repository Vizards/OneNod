package retrieval

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func frozen(t *testing.T, text, id string) *Store {
	t.Helper()
	s, err := Freeze(context.Background(), strings.NewReader(text), `{"actual_request":"fixture"}`, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestIndexedQueriesAndLegacyParity(t *testing.T) {
	text := `{"type":"event_msg","payload":{"turn_id":"turn","type":"task_started"}}` + "\n" +
		message("user", "allow 发版 <tag>") + message("assistant", "checking") +
		event(map[string]any{"type": "function_call", "call_id": "c", "name": "exec", "arguments": "{}"}) +
		event(map[string]any{"type": "function_call_output", "call_id": "c", "output": strings.Repeat("漢🧪", 100000)}) +
		message("developer", "host policy") + "{partial"
	old := fixture(t, text, "id")
	s := frozen(t, text, "id")
	if old.ID() != s.ID() {
		t.Fatal("snapshot identity changed")
	}
	tests := []struct{ name, args string }{
		{"query_context", `{}`}, {"query_context", `{"roles":["user"],"newest_first":false}`},
		{"query_context", `{"tool_name":"exec"}`}, {"query_context", `{"turn_id":"turn"}`},
		{"read_call", `{"call_id":"c"}`}, {"read_record", `{"record_id":"L3","before":1,"after":2}`},
		{"read_record", `{"record_id":"L5","view":"raw_event","start_char":127999}`},
		{"read_record", `{"record_id":"L7"}`}, {"search_context", `{"terms":["发版","<tag>"],"match":"all"}`},
		{"search_context", `{"terms":["漢🧪"],"kind":"all"}`}, {"read_request", `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name+tt.args, func(t *testing.T) {
			want, got := old.Call(context.Background(), tt.name, []byte(tt.args)), s.Call(context.Background(), tt.name, []byte(tt.args))
			a, _ := json.Marshal(want)
			b, _ := json.Marshal(got)
			if string(a) != string(b) {
				t.Fatalf("query differs: %s", tt.args)
			}
		})
	}
}
func TestIndexedUnicodeEscapesAndJSONValidation(t *testing.T) {
	valid := []string{`{"type":"response_item","payload":{"type":"message","role":"user","text":"\u53d1\u7248\/\ud83e\uddea\ud800x\u0001\u2028","n":-12.03e+4,"a":[null,true,false,{}]}}`,
		`{"type":"response_item","payload":null}`, `{"type":"event_msg"}`}
	for _, text := range valid {
		s := frozen(t, text, "x")
		r := call(s, "read_record", map[string]any{"record_id": "L1"})
		if s.records[0].ParseError != "" || !json.Valid([]byte(r.Records[0].Text)) {
			t.Fatal("valid record rejected")
		}
	}
	s := frozen(t, valid[0], "x")
	if r := call(s, "search_context", map[string]any{"terms": []string{"发版/🧪"}}); r.Matched != 1 {
		t.Fatal("escaped Unicode not searchable")
	}
	for _, text := range []string{`{"payload":{"a":01}}`, `{"payload":[1,]}`, `{"payload":{"x":"\q"}}`, `{"payload":1e}`, `{"payload":{"x":true} garbage}`, `{"payload":{`} {
		s := frozen(t, text, "x")
		r := call(s, "read_record", map[string]any{"record_id": "L1"})
		if s.records[0].ParseError != "invalid-session-envelope" || r.Records[0].Text != text {
			t.Fatal("invalid record not retained")
		}
	}
}
func TestIndexedSnapshotBoundaryCleanupAndConcurrentReaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "live.jsonl")
	prefix := message("user", strings.Repeat("汉🧪", 100000))
	os.WriteFile(path, []byte(prefix), 0600)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	added, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	io.WriteString(added, message("user", "future"))
	added.Close()
	s, err := Freeze(context.Background(), io.NewSectionReader(file, 0, int64(len(prefix))), `{}`, "a")
	if err != nil {
		t.Fatal(err)
	}
	directory := s.files.directory
	defer s.Close()
	other := frozen(t, prefix, "b")
	first := call(s, "query_context", map[string]any{})
	if first.Next == nil {
		t.Fatal("page missing")
	}
	if got := call(other, first.Next.Name, first.Next.Arguments); got.Error == "" {
		t.Fatal("cross-request cursor accepted")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			page := call(s, "query_context", map[string]any{})
			a, _ := json.Marshal(first)
			b, _ := json.Marshal(page)
			if !reflect.DeepEqual(a, b) {
				t.Error("shared state")
			}
			next := call(s, page.Next.Name, page.Next.Arguments)
			if next.Error != "" || !next.Exhausted {
				t.Error("continuation failed")
			}
		}()
	}
	wg.Wait()
	if r := call(s, "search_context", map[string]any{"terms": []string{"future"}}); r.Matched != 0 {
		t.Fatal("included future append")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("temporary files leaked")
	}
}
func TestIndexedLargeSnapshotBoundedHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("large file experiment")
	}
	path := filepath.Join(t.TempDir(), "large.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(f, message("user", "old authorization"))
	io.WriteString(f, `{"type":"response_item","payload":{"type":"function_call_output","call_id":"big","output":"`)
	chunk := strings.Repeat("x", 1024*1024)
	for i := 0; i < 272; i++ {
		if _, err = io.WriteString(f, chunk); err != nil {
			t.Fatal(err)
		}
	}
	io.WriteString(f, "boundaryNEEDLE汉🧪")
	io.WriteString(f, `"}}`+"\n"+message("user", "latest constraint"))
	f.Close()
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	peak.Store(before.HeapAlloc)
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		timer := time.NewTicker(5 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-done:
				return
			case <-timer.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				for old := peak.Load(); m.HeapAlloc > old; old = peak.Load() {
					if peak.CompareAndSwap(old, m.HeapAlloc) {
						break
					}
				}
			}
		}
	}()
	started := time.Now()
	s, err := Freeze(context.Background(), f, `{}`, "big")
	elapsed := time.Since(started)
	close(done)
	<-stopped
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.SourceBytes() <= 256*1024*1024 || s.Count() != 3 {
		t.Fatal("large snapshot lost")
	}
	r := call(s, "query_context", map[string]any{"roles": []string{"user"}})
	if r.Matched != 2 || !strings.Contains(r.Records[0].Text, "latest constraint") {
		t.Fatal("recent messages unavailable")
	}
	r = call(s, "search_context", map[string]any{"terms": []string{"boundaryneedle汉🧪"}, "kind": "tool_result"})
	if r.Matched != 1 {
		t.Fatal("large record search failed")
	}
	r = call(s, "read_record", map[string]any{"record_id": "L2", "start_char": 272 * 1024 * 1024})
	if r.Error != "" || !strings.Contains(r.Records[0].Text, "boundaryNEEDLE") {
		t.Fatal("large record page failed")
	}
	growth := peak.Load() - before.HeapAlloc
	t.Logf("snapshot_bytes=%d records=%d build_ms=%d peak_heap_growth=%d", s.SourceBytes(), s.Count(), elapsed.Milliseconds(), growth)
	if growth > 64*1024*1024 {
		t.Fatalf("snapshot content accumulated in heap: %d", growth)
	}
	destination := filepath.Join(t.TempDir(), "snapshot.jsonl")
	if err = s.Persist(context.Background(), destination); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(destination); info.Size() != s.SourceBytes() || info.Mode().Perm() != 0600 {
		t.Fatal("bad evidence copy")
	}
}
func TestIndexedCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := Freeze(ctx, strings.NewReader(message("user", "x")), `{}`, "x"); err == nil {
		s.Close()
		t.Fatal("cancelled construction succeeded")
	}
	s := frozen(t, message("user", strings.Repeat("x", 1000000)), "x")
	for _, name := range []string{"search_context", "read_record"} {
		args := `{"terms":["absent"]}`
		if name == "read_record" {
			args = `{"record_id":"L1"}`
		}
		if result := s.Call(ctx, name, []byte(args)); result.Error == "" {
			t.Fatal("ignored cancelled read")
		}
	}
}
func TestIndexedRealSnapshotExperiment(t *testing.T) {
	path := os.Getenv("BEHOLDER_INDEXED_EXPERIMENT")
	if path == "" {
		t.Skip("optional local read-only experiment")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, _ := f.Stat()
	started := time.Now()
	s, err := Freeze(context.Background(), io.NewSectionReader(f, 0, info.Size()), `{}`, "experiment")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := call(s, "query_context", map[string]any{"roles": []string{"user"}, "limit": 3})
	if r.Error != "" || len(r.Records) == 0 {
		t.Fatal("no user records")
	}
	fmt.Printf("real_snapshot_bytes=%d records=%d build_ms=%d returned_records=%d\n", s.SourceBytes(), s.Count(), time.Since(started).Milliseconds(), len(r.Records))
}
