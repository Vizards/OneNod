package retrieval

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// This streaming JSON reader normalizes string escapes for literal searches,
// without allocating the contents of strings, arrays, objects or whole records.
// Object member order is retained. Invalid lines stay visible as opaque records.
type payloadWriter struct {
	out   *bufio.Writer
	bytes int64
	chars int
	err   error
}

func (w *payloadWriter) write(p []byte) {
	if w.err != nil {
		return
	}
	var n int
	n, w.err = w.out.Write(p)
	w.bytes += int64(n)
	w.chars += utf8.RuneCount(p[:n])
}

type jsonStream struct {
	in                            *bufio.Reader
	out                           *payloadWriter
	emit                          bool
	envelopeFields, payloadFields map[string]string
	payload                       span
	hasPayload, largeMetadata     bool
}

var errJSON = errors.New("invalid JSON record")

func newJSONStream(r io.Reader, w *payloadWriter) *jsonStream {
	return &jsonStream{in: bufio.NewReaderSize(r, 64*1024), out: w, envelopeFields: map[string]string{}, payloadFields: map[string]string{}}
}
func (p *jsonStream) put(b []byte) {
	if p.emit {
		p.out.write(b)
	}
}
func (p *jsonStream) putByte(b byte) {
	if p.emit && p.out.err == nil {
		p.out.err = p.out.out.WriteByte(b)
		p.out.bytes++
		p.out.chars++
	}
}
func (p *jsonStream) peek() (byte, error) {
	b, err := p.in.Peek(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}
func (p *jsonStream) space() error {
	for {
		b, err := p.peek()
		if err != nil {
			return err
		}
		if b != ' ' && b != '\t' && b != '\r' {
			return nil
		}
		p.in.ReadByte()
	}
}
func (p *jsonStream) take(want byte) error {
	b, err := p.in.ReadByte()
	if err != nil {
		return err
	}
	if b != want {
		return errJSON
	}
	p.putByte(b)
	return nil
}
func (p *jsonStream) envelope() error {
	if err := p.space(); err != nil {
		return err
	}
	if b, _ := p.peek(); b != '{' {
		return errJSON
	}
	if _, err := p.value(0, 1, false); err != nil {
		return err
	}
	err := p.space()
	if err != io.EOF {
		return errJSON
	}
	return p.out.err
}

// scope 1 is the event envelope; scope 2 is its payload object. Other nested
// fields can never masquerade as role, turn, or call attribution metadata.
func (p *jsonStream) value(depth, scope int, capture bool) (string, error) {
	if depth > 10000 {
		return "", errJSON
	}
	if err := p.space(); err != nil {
		return "", err
	}
	b, err := p.peek()
	if err != nil {
		return "", err
	}
	switch b {
	case '"':
		return p.quoted(capture)
	case '{':
		if err = p.take('{'); err != nil {
			return "", err
		}
		if err = p.space(); err != nil {
			return "", err
		}
		if b, _ = p.peek(); b == '}' {
			return "", p.take('}')
		}
		for {
			key, err := p.quoted(scope != 0)
			if err != nil {
				return "", err
			}
			if err = p.space(); err != nil {
				return "", err
			}
			if err = p.take(':'); err != nil {
				return "", err
			}
			nextScope := 0
			known := false
			if scope == 1 {
				known = key == "type" || key == "timestamp"
				if key == "payload" {
					nextScope = 2
				}
			}
			if scope == 2 {
				known = key == "type" || key == "role" || key == "call_id" || key == "name" || key == "turn_id"
			}
			emitting := p.emit
			if nextScope == 2 {
				p.emit = true
				p.payload = span{offset: p.out.bytes}
				p.payloadFields = map[string]string{}
				p.hasPayload = true
			}
			before := p.out.chars
			v, err := p.value(depth+1, nextScope, known)
			if nextScope == 2 {
				p.payload.bytes = p.out.bytes - p.payload.offset
				p.payload.chars = p.out.chars - before
				p.emit = emitting
			}
			if err != nil {
				return "", err
			}
			if known {
				if scope == 1 {
					p.envelopeFields[key] = v
				} else {
					p.payloadFields[key] = v
				}
			}
			if err = p.space(); err != nil {
				return "", err
			}
			b, err = p.peek()
			if err != nil {
				return "", err
			}
			if b == '}' {
				return "", p.take('}')
			}
			if err = p.take(','); err != nil {
				return "", err
			}
			if err = p.space(); err != nil {
				return "", err
			}
		}
	case '[':
		if err = p.take('['); err != nil {
			return "", err
		}
		if err = p.space(); err != nil {
			return "", err
		}
		if b, _ = p.peek(); b == ']' {
			return "", p.take(']')
		}
		for {
			if _, err = p.value(depth+1, 0, false); err != nil {
				return "", err
			}
			if err = p.space(); err != nil {
				return "", err
			}
			if b, _ = p.peek(); b == ']' {
				return "", p.take(']')
			}
			if err = p.take(','); err != nil {
				return "", err
			}
		}
	case 't', 'f', 'n':
		literal := "null"
		if b == 't' {
			literal = "true"
		}
		if b == 'f' {
			literal = "false"
		}
		for i := range literal {
			if err = p.take(literal[i]); err != nil {
				return "", err
			}
		}
		return "", nil
	default:
		return "", p.number()
	}
}
func (p *jsonStream) number() error {
	b, err := p.peek()
	if err != nil {
		return err
	}
	consume := func() { p.in.ReadByte(); p.putByte(b) }
	if b == '-' {
		consume()
		b, err = p.peek()
		if err != nil {
			return err
		}
	}
	if b == '0' {
		consume()
	} else {
		if b < '1' || b > '9' {
			return errJSON
		}
		for {
			consume()
			b, err = p.peek()
			if err != nil || b < '0' || b > '9' {
				break
			}
		}
	}
	b, err = p.peek()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if b == '.' {
		consume()
		b, err = p.peek()
		if err != nil || b < '0' || b > '9' {
			return errJSON
		}
		for {
			consume()
			b, err = p.peek()
			if err != nil || b < '0' || b > '9' {
				break
			}
		}
	}
	b, err = p.peek()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if b == 'e' || b == 'E' {
		consume()
		b, err = p.peek()
		if err != nil {
			return err
		}
		if b == '+' || b == '-' {
			consume()
			b, err = p.peek()
		}
		if err != nil || b < '0' || b > '9' {
			return errJSON
		}
		for {
			consume()
			b, err = p.peek()
			if err != nil || b < '0' || b > '9' {
				break
			}
		}
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}
func (p *jsonStream) quoted(capture bool) (string, error) {
	if b, err := p.in.ReadByte(); err != nil || b != '"' {
		return "", errJSON
	}
	var small []byte
	write := func(b []byte) {
		p.put(b)
		if capture && len(small) <= 4096 {
			take := min(len(b), 4097-len(small))
			small = append(small, b[:take]...)
		}
	}
	write([]byte{'"'})
	for {
		// Most tool output and embedded image data is ordinary ASCII. Process
		// contiguous runs in bounded chunks, not one allocation/write per byte.
		if _, err := p.in.Peek(1); err != nil {
			return "", err
		}
		block, _ := p.in.Peek(p.in.Buffered())
		ordinary := 0
		for _, b := range block {
			if b < 0x20 || b >= utf8.RuneSelf || b == '"' || b == '\\' {
				break
			}
			ordinary++
		}
		if ordinary > 0 {
			write(block[:ordinary])
			p.in.Discard(ordinary)
			continue
		}
		b, err := p.in.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '"' {
			write([]byte{'"'})
			break
		}
		if b < 0x20 {
			return "", errJSON
		}
		if b == '\\' {
			escape, err := p.in.ReadByte()
			if err != nil {
				return "", err
			}
			switch escape {
			case '"', '\\', 'b', 'f', 'n', 'r', 't':
				write([]byte{'\\', escape})
			case '/':
				write([]byte{'/'})
			case 'u':
				var raw [4]byte
				if _, err = io.ReadFull(p.in, raw[:]); err != nil {
					return "", err
				}
				value, err := strconv.ParseUint(string(raw[:]), 16, 16)
				if err != nil {
					return "", errJSON
				}
				r := rune(value)
				if r >= 0xd800 && r <= 0xdbff {
					next, err := p.in.Peek(6)
					if err == nil && next[0] == '\\' && next[1] == 'u' {
						low, e := strconv.ParseUint(string(next[2:]), 16, 16)
						if e == nil && low >= 0xdc00 && low <= 0xdfff {
							p.in.Discard(6)
							r = utf16.DecodeRune(r, rune(low))
						} else {
							r = utf8.RuneError
						}
					} else {
						r = utf8.RuneError
					}
				} else if r >= 0xdc00 && r <= 0xdfff {
					r = utf8.RuneError
				}
				switch r {
				case '"':
					write([]byte{'\\', '"'})
				case '\\':
					write([]byte{'\\', '\\'})
				case '\b':
					write([]byte(`\b`))
				case '\f':
					write([]byte(`\f`))
				case '\n':
					write([]byte(`\n`))
				case '\r':
					write([]byte(`\r`))
				case '\t':
					write([]byte(`\t`))
				default:
					if r < 0x20 || r == 0x2028 || r == 0x2029 {
						write([]byte(fmt.Sprintf(`\u%04x`, r)))
					} else {
						var buf [4]byte
						n := utf8.EncodeRune(buf[:], r)
						write(buf[:n])
					}
				}
			default:
				return "", errJSON
			}
		} else if b >= utf8.RuneSelf {
			if err = p.in.UnreadByte(); err != nil {
				return "", err
			}
			r, n, err := p.in.ReadRune()
			if err != nil || r == utf8.RuneError && n == 1 {
				return "", errJSON
			}
			if r == 0x2028 || r == 0x2029 {
				write([]byte(fmt.Sprintf(`\u%04x`, r)))
			} else {
				var buf [4]byte
				n := utf8.EncodeRune(buf[:], r)
				write(buf[:n])
			}
		} else {
			p.putByte(b)
			if capture && len(small) <= 4096 {
				small = append(small, b)
			}
		}
	}
	if !capture {
		return "", nil
	}
	if len(small) > 4096 {
		p.largeMetadata = true
		return "", nil
	}
	var result string
	if err := json.Unmarshal(small, &result); err != nil {
		return "", err
	}
	return result, nil
}
