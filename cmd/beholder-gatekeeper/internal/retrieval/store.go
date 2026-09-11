// Package retrieval exposes model-selected, read-only navigation over one
// immutable request-time transcript. It neither executes tools nor judges intent.
package retrieval

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	PageCharacters         = 128000
	MaximumSearchTerms     = 32
	MaximumSearchTermBytes = 8192
)

//go:embed tools.json
var toolDefinitions []byte

func Tools() json.RawMessage {
	var definitions any
	if err := json.Unmarshal(toolDefinitions, &definitions); err != nil {
		panic("invalid embedded retrieval tools")
	}
	canonical, err := json.Marshal(definitions)
	if err != nil {
		panic("invalid embedded retrieval tools")
	}
	return canonical
}

type Record struct {
	ID          string `json:"record_id"`
	Line        int    `json:"line"`
	Timestamp   string `json:"timestamp,omitempty"`
	RecordType  string `json:"record_type,omitempty"`
	PayloadType string `json:"payload_type,omitempty"`
	Kind        string `json:"kind"`
	Role        string `json:"role,omitempty"`
	CallID      string `json:"call_id,omitempty"`
	ToolName    string `json:"tool_name,omitempty"`
	TurnID      string `json:"turn_id,omitempty"`
	ParseError  string `json:"parse_error,omitempty"`
	raw, text   string
	when        time.Time
}

type PageRecord struct {
	Record
	View        string `json:"view"`
	SourceClass string `json:"source_class"`
	SourceRef   string `json:"source_ref"`
	Start       int    `json:"start_char"`
	Total       int    `json:"total_chars"`
	Complete    bool   `json:"complete"`
	Text        string `json:"text"`
}

type NextCall struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments"`
}

type Result struct {
	Source        string         `json:"source,omitempty"`
	SnapshotID    string         `json:"snapshot_id,omitempty"`
	Matched       int            `json:"matched_records"`
	Records       []PageRecord   `json:"records"`
	Next          *NextCall      `json:"next_call"`
	Exhausted     bool           `json:"query_exhausted"`
	Effective     map[string]any `json:"effective_query,omitempty"`
	Order         string         `json:"order,omitempty"`
	CallID        string         `json:"call_id,omitempty"`
	CallRecords   int            `json:"call_records,omitempty"`
	ReturnRecords int            `json:"return_records,omitempty"`
	NamespaceNote string         `json:"namespace_note,omitempty"`
	Error         string         `json:"error,omitempty"`
	Detail        string         `json:"detail,omitempty"`
}

type cursor struct {
	Snapshot string         `json:"snapshot"`
	Name     string         `json:"name"`
	Args     map[string]any `json:"args"`
	Index    int            `json:"index"`
	Offset   int            `json:"offset"`
}

type schema struct {
	Function struct {
		Name       string `json:"name"`
		Parameters struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Required   []string                   `json:"required"`
		} `json:"parameters"`
	} `json:"function"`
}

// Store is immutable after construction; independent queries and model variants
// share original records without sharing cursors or decision state.
type Store struct {
	id      string
	records []Record
	byCall  map[string][]int
	request Record
	schemas map[string]schema
}

func New(ctx context.Context, session []byte, request string, binding string) (*Store, error) {
	if !utf8.Valid(session) || !utf8.ValidString(request) || !json.Valid([]byte(request)) {
		return nil, errors.New("invalid retrieval source encoding")
	}
	digest := sha256.New()
	digest.Write(session)
	digest.Write([]byte{0})
	digest.Write([]byte(request))
	digest.Write([]byte{0})
	digest.Write([]byte(binding))
	s := &Store{id: hex.EncodeToString(digest.Sum(nil)), byCall: map[string][]int{}, schemas: map[string]schema{},
		request: Record{ID: "request", Line: 1, Kind: "request", raw: request, text: request}}
	var schemas []schema
	if err := json.Unmarshal(toolDefinitions, &schemas); err != nil {
		return nil, err
	}
	for _, schema := range schemas {
		s.schemas[schema.Function.Name] = schema
	}
	turn := ""
	lines := strings.Split(strings.TrimSuffix(string(session), "\n"), "\n")
	if len(session) == 0 {
		lines = nil
	}
	for i, line := range lines {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var event struct {
			Type      string          `json:"type"`
			Timestamp string          `json:"timestamp"`
			Payload   json.RawMessage `json:"payload"`
		}
		if json.Unmarshal([]byte(line), &event) != nil {
			// A concurrent append can leave the admission prefix with an
			// incomplete last line. Retain it as opaque runtime evidence.
			s.records = append(s.records, Record{ID: fmt.Sprintf("L%d", i+1), Line: i + 1,
				Kind: "runtime", TurnID: turn, raw: line, text: line, ParseError: "invalid-session-envelope"})
			continue
		}
		if len(event.Payload) == 0 {
			event.Payload = json.RawMessage(`{}`)
		}
		var fields struct {
			Type   string `json:"type"`
			Role   string `json:"role"`
			CallID string `json:"call_id"`
			Name   string `json:"name"`
			TurnID string `json:"turn_id"`
		}
		// Non-object payloads are still readable as runtime data.
		_ = json.Unmarshal(event.Payload, &fields)
		if fields.TurnID != "" && (event.Type == "turn_context" || (event.Type == "event_msg" && fields.Type == "task_started")) {
			turn = fields.TurnID
		}
		r := Record{ID: fmt.Sprintf("L%d", i+1), Line: i + 1, Timestamp: event.Timestamp, RecordType: event.Type, PayloadType: fields.Type,
			Kind: "runtime", Role: fields.Role, TurnID: turn, raw: line}
		if event.Timestamp != "" {
			var err error
			r.when, err = time.Parse(time.RFC3339Nano, event.Timestamp)
			if err != nil {
				r.ParseError = "invalid-timestamp"
			}
		}
		if event.Type == "response_item" {
			switch fields.Type {
			case "message":
				r.Kind = "message"
			case "function_call", "custom_tool_call":
				r.Kind = "tool_call"
				r.CallID = fields.CallID
				r.ToolName = fields.Name
			case "function_call_output", "custom_tool_call_output":
				r.Kind = "tool_result"
				r.CallID = fields.CallID
			}
		}
		var payload any
		decoder := json.NewDecoder(bytes.NewReader(event.Payload))
		decoder.UseNumber()
		if err := decoder.Decode(&payload); err != nil {
			return nil, err
		}
		var compact bytes.Buffer
		encoder := json.NewEncoder(&compact)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(payload); err != nil {
			return nil, err
		}
		r.text = strings.TrimSuffix(compact.String(), "\n")
		s.records = append(s.records, r)
		if r.CallID != "" {
			s.byCall[r.CallID] = append(s.byCall[r.CallID], i)
		}
	}
	return s, nil
}

func (s *Store) ID() string { return s.id }
func (s *Store) Count() int { return len(s.records) }

func (s *Store) validate(name string, args map[string]any) error {
	schema, ok := s.schemas[name]
	if !ok || args == nil {
		return errors.New("use a documented read-only tool with object arguments")
	}
	for k := range args {
		if _, ok := schema.Function.Parameters.Properties[k]; !ok {
			return fmt.Errorf("unknown parameter %s", k)
		}
	}
	for _, k := range schema.Function.Parameters.Required {
		if _, ok := args[k]; !ok {
			return fmt.Errorf("missing parameter %s", k)
		}
	}
	return nil
}

func (s *Store) Call(ctx context.Context, name string, raw json.RawMessage) (result Result) {
	result.Records = []PageRecord{}
	fail := func(err error) Result {
		return Result{Records: []PageRecord{}, Error: "invalid-tool-arguments", Detail: err.Error()}
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	var args map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if !json.Valid(raw) || decoder.Decode(&args) != nil {
		return fail(errors.New("use valid JSON object arguments"))
	}
	if err := s.validate(name, args); err != nil {
		return fail(err)
	}
	index, offset := 0, 0
	if name == "read_next" {
		value, ok := args["cursor"].(string)
		if !ok || len(value) > 1024*1024 {
			return fail(errors.New("invalid continuation cursor"))
		}
		decoded, err := base64.URLEncoding.DecodeString(value)
		if err != nil {
			return fail(errors.New("invalid continuation cursor"))
		}
		var next cursor
		d := json.NewDecoder(bytes.NewReader(decoded))
		d.UseNumber()
		if !json.Valid(decoded) || d.Decode(&next) != nil || next.Snapshot != s.id || next.Name == "read_next" || next.Index < 0 || next.Offset < 0 {
			return fail(errors.New("cursor belongs to another snapshot or has an invalid position"))
		}
		name, args, index, offset = next.Name, next.Args, next.Index, next.Offset
		if err := s.validate(name, args); err != nil {
			return fail(err)
		}
	} else {
		var err error
		offset, err = integer(args, "start_char", 0, 0)
		if err != nil {
			return fail(err)
		}
	}
	records, meta, err := s.selectRecords(ctx, name, args)
	if err != nil {
		return fail(err)
	}
	result = meta
	result.Records = []PageRecord{}
	result.SnapshotID = s.id
	result.Matched = len(records)
	limit, err := integer(args, "limit", 20, 1)
	if err != nil {
		return fail(err)
	}
	if index > len(records) {
		return fail(errors.New("cursor exceeds available records"))
	}
	used := 0
	for index < len(records) && len(result.Records) < limit {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		r := records[index]
		text := r.text
		view := "payload"
		if args["view"] == "raw_event" {
			text = r.raw
			view = "raw_event"
		}
		total := utf8.RuneCountInString(text)
		if offset > total {
			return fail(errors.New("text offset exceeds record length"))
		}
		if len(result.Records) > 0 && used+total-offset > PageCharacters {
			break
		}
		take := min(total-offset, PageCharacters-used)
		sourceClass := r.Kind
		if r.Kind == "message" {
			sourceClass = r.Role + "_message"
		}
		ref := "session:" + r.ID
		if result.Source == "request" {
			ref = "request:L1"
		}
		part := text
		if offset != 0 || take != total {
			part = string([]rune(text)[offset : offset+take])
		}
		result.Records = append(result.Records, PageRecord{Record: r, View: view, SourceClass: sourceClass, SourceRef: ref,
			Start: offset, Total: total, Complete: offset == 0 && take == total, Text: part})
		used += take
		if offset+take < total {
			offset += take
			break
		}
		index++
		offset = 0
	}
	result.Exhausted = index == len(records)
	if !result.Exhausted {
		encoded, _ := json.Marshal(cursor{s.id, name, args, index, offset})
		result.Next = &NextCall{Name: "read_next", Arguments: map[string]string{"cursor": base64.URLEncoding.EncodeToString(encoded)}}
	}
	return result
}

func integer(args map[string]any, key string, def, minValue int) (int, error) {
	v, ok := args[key]
	if !ok {
		return def, nil
	}
	var text string
	switch v := v.(type) {
	case json.Number:
		text = string(v)
	case string:
		text = v
	default:
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	n, err := strconv.Atoi(text)
	if err != nil || n < minValue {
		return 0, fmt.Errorf("%s must be an integer at least %d", key, minValue)
	}
	return n, nil
}

var kinds = []string{"conversation", "message", "tool_call", "tool_result", "runtime", "all"}
var roles = []string{"user", "assistant", "developer", "system"}

func list(args map[string]any, key string, allowed []string) ([]string, error) {
	v, ok := args[key]
	if !ok {
		return nil, nil
	}
	values, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", key)
	}
	out := []string{}
	for _, v := range values {
		str, ok := v.(string)
		if !ok || (allowed != nil && !slices.Contains(allowed, str)) {
			return nil, fmt.Errorf("invalid %s value", key)
		}
		out = append(out, str)
	}
	return out, nil
}

func (s *Store) line(value any) (int, error) {
	id, ok := value.(string)
	if !ok || !strings.HasPrefix(id, "L") {
		return 0, errors.New("use a record ID from this snapshot")
	}
	n, err := strconv.Atoi(strings.TrimPrefix(id, "L"))
	if err != nil || n < 1 || n > len(s.records) || s.records[n-1].ID != id {
		return 0, errors.New("unknown record ID")
	}
	return n, nil
}

func (s *Store) selectRecords(ctx context.Context, name string, args map[string]any) ([]Record, Result, error) {
	meta := Result{Source: "session"}
	out := []Record{}
	if name == "read_request" {
		meta.Source = "request"
		return []Record{s.request}, meta, nil
	}
	if name == "read_call" {
		id, ok := args["call_id"].(string)
		if !ok {
			return nil, meta, errors.New("call_id must be a string")
		}
		for _, i := range s.byCall[id] {
			r := s.records[i]
			out = append(out, r)
			if r.Kind == "tool_call" {
				meta.CallRecords++
			} else {
				meta.ReturnRecords++
			}
		}
		meta.CallID = id
		meta.NamespaceNote = "Session call IDs, Core hook tool-use IDs and process/session IDs are distinct. No alias or completion is inferred."
		return out, meta, nil
	}
	if name == "read_record" {
		line, err := s.line(args["record_id"])
		if err != nil {
			return nil, meta, err
		}
		before, err := integer(args, "before", 0, 0)
		if err != nil {
			return nil, meta, err
		}
		after, err := integer(args, "after", 0, 0)
		if err != nil {
			return nil, meta, err
		}
		offset, err := integer(args, "start_char", 0, 0)
		if err != nil {
			return nil, meta, err
		}
		if (before > 0 || after > 0) && offset > 0 {
			return nil, meta, errors.New("start_char requires neighbors omitted")
		}
		if v, ok := args["view"]; ok && v != "payload" && v != "raw_event" {
			return nil, meta, errors.New("unknown view")
		}
		ks, err := list(args, "neighbor_kinds", kinds)
		if err != nil {
			return nil, meta, err
		}
		if ks == nil {
			ks = []string{"conversation", "tool_call", "tool_result"}
		}
		matches := func(r Record) bool {
			return slices.Contains(ks, "all") || slices.Contains(ks, r.Kind) || (slices.Contains(ks, "conversation") && r.Kind == "message" && (r.Role == "user" || r.Role == "assistant"))
		}
		left := []Record{}
		for i := line - 2; i >= 0 && len(left) < before; i-- {
			if matches(s.records[i]) {
				left = append(left, s.records[i])
			}
		}
		slices.Reverse(left)
		out = append(left, s.records[line-1])
		for i, n := line, 0; i < len(s.records) && n < after; i++ {
			if matches(s.records[i]) {
				out = append(out, s.records[i])
				n++
			}
		}
		return out, meta, nil
	}
	effective := map[string]any{}
	for k, v := range args {
		effective[k] = v
	}
	kind := "conversation"
	if _, ok := args["roles"]; ok {
		kind = "message"
	}
	for _, k := range []string{"call_id", "tool_name"} {
		if _, ok := args[k]; ok {
			kind = "all"
		}
	}
	if v, ok := args["kind"]; ok {
		var yes bool
		kind, yes = v.(string)
		if !yes || !slices.Contains(kinds, kind) {
			return nil, meta, errors.New("unknown kind")
		}
	}
	selectedRoles, err := list(args, "roles", roles)
	if err != nil {
		return nil, meta, err
	}
	if kind == "conversation" {
		kind = "message"
		if selectedRoles == nil {
			selectedRoles = []string{"user", "assistant"}
		} else {
			selectedRoles = slices.DeleteFunc(selectedRoles, func(r string) bool { return r != "user" && r != "assistant" })
		}
	}
	effective["kind"] = kind
	if selectedRoles != nil {
		effective["roles"] = selectedRoles
	}
	meta.Effective = effective
	newest := true
	if v, ok := args["newest_first"]; ok {
		var yes bool
		newest, yes = v.(bool)
		if !yes {
			return nil, meta, errors.New("newest_first must be boolean")
		}
	}
	meta.Order = "newest-first"
	if !newest {
		meta.Order = "oldest-first"
	}
	lo, hi := 0, len(s.records)+1
	if v, ok := args["after_record_id"]; ok {
		lo, err = s.line(v)
		if err != nil {
			return nil, meta, err
		}
	}
	if v, ok := args["before_record_id"]; ok {
		hi, err = s.line(v)
		if err != nil {
			return nil, meta, err
		}
	}
	times := map[string]time.Time{}
	for _, key := range []string{"since", "until"} {
		if v, ok := args[key]; ok {
			str, ok := v.(string)
			if !ok {
				return nil, meta, errors.New("timestamp must be a string")
			}
			t, err := time.Parse(time.RFC3339Nano, str)
			if err != nil {
				return nil, meta, errors.New("timestamp must include a timezone")
			}
			times[key] = t
		}
	}
	if !times["since"].IsZero() && !times["until"].IsZero() && times["since"].After(times["until"]) {
		return nil, meta, errors.New("since is later than until")
	}
	for _, key := range []string{"call_id", "tool_name", "turn_id"} {
		if v, ok := args[key]; ok {
			if _, ok := v.(string); !ok {
				return nil, meta, fmt.Errorf("%s must be a string", key)
			}
		}
	}
	var terms []string
	match := "any"
	if name == "search_context" {
		terms, err = searchTerms(ctx, args["terms"])
		if err != nil {
			return nil, meta, err
		}
		if v, ok := args["match"]; ok {
			if v != "all" && v != "any" {
				return nil, meta, errors.New("match must be any or all")
			}
			match = v.(string)
		}
	}
	for _, r := range s.records {
		if err := ctx.Err(); err != nil {
			return nil, meta, err
		}
		if r.Line <= lo || r.Line >= hi || (kind != "all" && r.Kind != kind) || (selectedRoles != nil && !slices.Contains(selectedRoles, r.Role)) {
			continue
		}
		if v, ok := args["call_id"]; ok && v != r.CallID {
			continue
		}
		if v, ok := args["turn_id"]; ok && v != r.TurnID {
			continue
		}
		if v, ok := args["tool_name"]; ok {
			found := false
			for _, j := range s.byCall[r.CallID] {
				if s.records[j].ToolName == v {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if t := times["since"]; !t.IsZero() && r.when.Before(t) {
			continue
		}
		if t := times["until"]; !t.IsZero() && r.when.After(t) {
			continue
		}
		if len(times) > 0 && r.when.IsZero() {
			continue
		}
		if name == "search_context" {
			folded := strings.ToLower(r.text)
			hits := 0
			for _, term := range terms {
				if err := ctx.Err(); err != nil {
					return nil, meta, err
				}
				found := strings.Contains(folded, term)
				if found {
					hits++
				}
				if (match == "any" && found) || (match == "all" && !found) {
					break
				}
			}
			if (match == "any" && hits == 0) || (match == "all" && hits != len(terms)) {
				continue
			}
		}
		out = append(out, r)
	}
	if newest {
		slices.Reverse(out)
	}
	return out, meta, nil
}

// These are query resource budgets, independent of the words being searched.
// Bound the array before allocating or walking it, and honor cancellation both
// while preparing terms and within each record's comparison loop.
func searchTerms(ctx context.Context, value any) ([]string, error) {
	values, ok := value.([]any)
	if !ok || len(values) == 0 || len(values) > MaximumSearchTerms {
		return nil, fmt.Errorf("terms must contain 1 to %d literal strings", MaximumSearchTerms)
	}
	terms := make([]string, len(values))
	total := 0
	for i, value := range values {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		term, ok := value.(string)
		if !ok || term == "" {
			return nil, errors.New("terms must contain nonempty literal strings")
		}
		total += len(term)
		if total > MaximumSearchTermBytes {
			return nil, fmt.Errorf("search terms exceed %d total UTF-8 bytes; split the query", MaximumSearchTermBytes)
		}
		terms[i] = strings.ToLower(term)
	}
	return terms, nil
}
