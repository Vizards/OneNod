package retrieval

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// IndexedFormat keeps compact payload JSON in source member order. Version one
// used encoding/json's sorted object keys; its in-memory reader remains available
// solely for replaying those existing bundles.
const IndexedFormat = "indexed-jsonl-v1"

type span struct {
	offset, bytes int64
	chars         int
}
type indexedRecord struct{ raw, payload span }
type fileStore struct {
	raw, payload *os.File
	directory    string
	size         int64
	digest       string
	records      []indexedRecord
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// Freeze copies exactly the admitted prefix to private disk before indexing it.
// No live path is retained or opened by a tool. Memory is proportional to record
// metadata and returned pages, including when one record exceeds the old limit.
func Freeze(ctx context.Context, source io.Reader, request, binding string) (*Store, error) {
	if !utf8.ValidString(request) || !json.Valid([]byte(request)) {
		return nil, errors.New("invalid retrieval request encoding")
	}
	dir, err := os.MkdirTemp("", "beholder-retrieval-")
	if err != nil {
		return nil, err
	}
	f := &fileStore{directory: dir}
	success := false
	defer func() {
		if !success {
			f.close()
		}
	}()
	f.raw, err = os.OpenFile(filepath.Join(dir, "session.jsonl"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	f.size, err = io.CopyBuffer(io.MultiWriter(f.raw, hash), contextReader{ctx, source}, make([]byte, 64*1024))
	if err != nil {
		return nil, err
	}
	f.digest = hex.EncodeToString(hash.Sum(nil))
	if err = f.raw.Sync(); err != nil {
		return nil, err
	}
	f.payload, err = os.OpenFile(filepath.Join(dir, "payload.jsonl"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	// Reuse the unchanged tool contract and request encoding. Snapshot identity is
	// still SHA256(session || NUL || request || NUL || binding).
	hash.Write([]byte{0})
	hash.Write([]byte(request))
	hash.Write([]byte{0})
	hash.Write([]byte(binding))
	s, err := New(ctx, nil, request, binding)
	if err != nil {
		return nil, err
	}
	s.id = hex.EncodeToString(hash.Sum(nil))
	s.files = f
	if err = s.index(ctx); err != nil {
		return nil, err
	}
	success = true
	return s, nil
}
func (s *Store) Close() error {
	if s.files != nil {
		return s.files.close()
	}
	return nil
}
func (f *fileStore) close() error {
	if f.raw != nil {
		_ = f.raw.Close()
	}
	if f.payload != nil {
		_ = f.payload.Close()
	}
	return os.RemoveAll(f.directory)
}
func (s *Store) SourceDigest() string { return s.files.digest }
func (s *Store) SourceBytes() int64   { return s.files.size }
func (s *Store) Persist(ctx context.Context, path string) error {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	done := false
	defer func() {
		out.Close()
		if !done {
			_ = os.Remove(path)
		}
	}()
	n, err := io.CopyBuffer(out, contextReader{ctx, io.NewSectionReader(s.files.raw, 0, s.files.size)}, make([]byte, 64*1024))
	if err != nil {
		return err
	}
	if n != s.files.size {
		return io.ErrUnexpectedEOF
	}
	if err = out.Sync(); err != nil {
		return err
	}
	done = true
	return out.Close()
}

func (s *Store) index(ctx context.Context) error {
	f := s.files
	// Enumerate offsets in fixed-size pieces. A long line never becomes a
	// line-sized allocation; carry at most one incomplete UTF-8 rune between
	// pieces. This also avoids per-byte buffered-reader overhead on image data.
	reader := bufio.NewReaderSize(contextReader{ctx, io.NewSectionReader(f.raw, 0, f.size)}, 64*1024)
	start, offset := int64(0), int64(0)
	chars := 0
	var pending [utf8.UTFMax]byte
	carry := 0
	for {
		part, err := reader.ReadSlice('\n')
		consumed := len(part)
		if carry > 0 {
			for !utf8.FullRune(pending[:carry]) && len(part) > 0 {
				pending[carry] = part[0]
				carry++
				part = part[1:]
			}
			if !utf8.FullRune(pending[:carry]) || !utf8.Valid(pending[:carry]) {
				return errors.New("invalid retrieval source encoding")
			}
			chars++
			carry = 0
		}
		if len(part) > 0 {
			last := len(part) - 1
			for last > 0 && !utf8.RuneStart(part[last]) {
				last--
			}
			if !utf8.FullRune(part[last:]) {
				carry = copy(pending[:], part[last:])
				part = part[:last]
			}
			if !utf8.Valid(part) {
				return errors.New("invalid retrieval source encoding")
			}
			chars += utf8.RuneCount(part)
		}
		offset += int64(consumed)
		if err == nil {
			f.records = append(f.records, indexedRecord{raw: span{start, offset - start - 1, chars - 1}})
			start = offset
			chars = 0
		} else if err != bufio.ErrBufferFull {
			if err != io.EOF {
				return err
			}
			if carry != 0 {
				return errors.New("invalid retrieval source encoding")
			}
			break
		}
	}
	if offset > start {
		f.records = append(f.records, indexedRecord{raw: span{start, offset - start, chars}})
	}
	out := bufio.NewWriterSize(f.payload, 64*1024)
	writer := &payloadWriter{out: out}
	turn := ""
	parserReader := bufio.NewReaderSize(strings.NewReader(""), 64*1024)
	for i := range f.records {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry := &f.records[i]
		parserReader.Reset(contextReader{ctx, io.NewSectionReader(f.raw, entry.raw.offset, entry.raw.bytes)})
		p := newJSONStream(parserReader, writer)
		err := p.envelope()
		r := Record{ID: fmt.Sprintf("L%d", i+1), Line: i + 1, Kind: "runtime", TurnID: turn}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if writer.err != nil {
				return writer.err
			}
			r.ParseError = "invalid-session-envelope"
			entry.payload = entry.raw // the raw source is selected for opaque records
		} else {
			r.RecordType, r.Timestamp = p.envelopeFields["type"], p.envelopeFields["timestamp"]
			fields := p.payloadFields
			r.PayloadType, r.Role = fields["type"], fields["role"]
			if fields["turn_id"] != "" && (r.RecordType == "turn_context" || (r.RecordType == "event_msg" && r.PayloadType == "task_started")) {
				turn = fields["turn_id"]
			}
			r.TurnID = turn
			if r.Timestamp != "" {
				var err error
				r.when, err = time.Parse(time.RFC3339Nano, r.Timestamp)
				if err != nil {
					r.ParseError = "invalid-timestamp"
				}
			}
			if r.RecordType == "response_item" {
				switch r.PayloadType {
				case "message":
					r.Kind = "message"
				case "function_call", "custom_tool_call":
					r.Kind = "tool_call"
					r.CallID, r.ToolName = fields["call_id"], fields["name"]
				case "function_call_output", "custom_tool_call_output":
					r.Kind = "tool_result"
					r.CallID = fields["call_id"]
				}
			}
			if p.largeMetadata {
				r.ParseError = "oversized-record-metadata"
			}
			entry.payload = p.payload
			if !p.hasPayload {
				entry.payload = span{writer.bytes, 2, 2}
				writer.write([]byte("{}"))
			}
		}
		s.records = append(s.records, r)
		if r.CallID != "" {
			s.byCall[r.CallID] = append(s.byCall[r.CallID], i)
		}
	}
	if err := out.Flush(); err != nil {
		return err
	}
	return writer.err
}

func (s *Store) recordSource(r Record, raw bool) (*os.File, span) {
	entry := s.files.records[r.Line-1]
	if raw || r.ParseError == "invalid-session-envelope" {
		return s.files.raw, entry.raw
	}
	return s.files.payload, entry.payload
}
func (s *Store) textLength(r Record, raw bool) int {
	if s.files != nil && r.Kind != "request" {
		_, part := s.recordSource(r, raw)
		return part.chars
	}
	if raw {
		return utf8.RuneCountInString(r.raw)
	}
	return utf8.RuneCountInString(r.text)
}
func (s *Store) textPage(ctx context.Context, r Record, raw bool, offset, take int) (string, error) {
	if s.files == nil || r.Kind == "request" {
		text := r.text
		if raw {
			text = r.raw
		}
		if offset == 0 && take == utf8.RuneCountInString(text) {
			return text, nil
		}
		return string([]rune(text)[offset : offset+take]), nil
	}
	f, part := s.recordSource(r, raw)
	reader := bufio.NewReaderSize(contextReader{ctx, io.NewSectionReader(f, part.offset, part.bytes)}, 64*1024)
	var out strings.Builder
	for i := 0; i < offset+take; i++ {
		value, _, err := reader.ReadRune()
		if err != nil {
			return "", err
		}
		if i >= offset {
			out.WriteRune(value)
		}
	}
	return out.String(), nil
}
func (s *Store) matches(ctx context.Context, r Record, terms []string, match string) (bool, error) {
	if s.files == nil {
		return matchString(ctx, strings.ToLower(r.text), terms, match)
	}
	f, part := s.recordSource(r, false)
	reader := bufio.NewReaderSize(contextReader{ctx, io.NewSectionReader(f, part.offset, part.bytes)}, 64*1024)
	// Fold complete UTF-8 chunks and retain enough overlap for terms crossing any
	// chunk boundary. Each call owns its buffers; queries never mutate the index.
	longest := 0
	for _, term := range terms {
		longest = max(longest, len(term))
	}
	found := make([]bool, len(terms))
	hits := 0
	tail := ""
	chunk := make([]byte, 32*1024)
	for {
		n, err := reader.Read(chunk)
		if n > 0 {
			var extra [utf8.UTFMax]byte
			k := 0
			for !utf8.Valid(chunk[:n]) && k < len(extra) {
				b, e := reader.ReadByte()
				if e != nil {
					return false, e
				}
				extra[k] = b
				k++
				if utf8.Valid(append(chunk[:n:n], extra[:k]...)) {
					break
				}
			}
			text := tail + strings.ToLower(string(chunk[:n])+string(extra[:k]))
			for i, term := range terms {
				if err := ctx.Err(); err != nil {
					return false, err
				}
				if !found[i] && strings.Contains(text, term) {
					found[i] = true
					hits++
				}
			}
			if (match == "any" && hits > 0) || (match == "all" && hits == len(terms)) {
				return true, nil
			}
			tail = strings.Clone(text[max(0, len(text)-longest):])
		}
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
}
func matchString(ctx context.Context, text string, terms []string, match string) (bool, error) {
	hits := 0
	for _, term := range terms {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		found := strings.Contains(text, term)
		if found {
			hits++
		}
		if (match == "any" && found) || (match == "all" && !found) {
			break
		}
	}
	return (match == "any" && hits > 0) || (match == "all" && hits == len(terms)), nil
}
