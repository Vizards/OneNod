package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type tapTransportWriter struct {
	output  *bytes.Buffer
	onEvent func(transportLogEvent)
}

func (writer tapTransportWriter) Write(value []byte) (int, error) {
	written, err := writer.output.Write(value)
	var event transportLogEvent
	if json.Unmarshal(value, &event) == nil && writer.onEvent != nil {
		writer.onEvent(event)
	}
	return written, err
}

func readTransportEvents(t *testing.T, log *transportLog, output *bytes.Buffer) []transportLogEvent {
	t.Helper()
	log.close()
	select {
	case <-log.done:
	case <-time.After(time.Second):
		t.Fatal("transport log did not drain")
	}
	var events []transportLogEvent
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for {
		var event transportLogEvent
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	return events
}

func TestTransportObservationConcurrentCorrelationAndPrivacy(t *testing.T) {
	var output bytes.Buffer
	log := newTransportLog(&output)
	var group sync.WaitGroup
	for index := 0; index < 8; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			trace := strings.Repeat(string("abcdef12"[index]), 32)
			observation := newTransportObservation(log, "ssh-client", trace)
			span := observation.begin("binding-read", 2*time.Second, time.Now().Add(2*time.Second))
			// The cause deliberately contains private text: only its fixed class
			// may enter diagnostics, including through wrapped OS errors.
			span.finish(&net.OpError{Op: "read", Net: "unix", Err: fmtTransportPrivateError{}})
		}(index)
	}
	group.Wait()
	events := readTransportEvents(t, log, &output)
	if len(events) != 16 || bytes.Contains(output.Bytes(), []byte("PRIVATE")) {
		t.Fatalf("lost events or leaked text: count=%d", len(events))
	}
	connections := map[string]string{}
	finished := 0
	for _, event := range events {
		if event.ConnectionID == "" || len(event.TraceID) != 32 || event.PID == 0 || event.DeadlineAt == nil {
			t.Fatal("missing correlation or deadline")
		}
		if prior, ok := connections[event.ConnectionID]; ok && prior != event.TraceID {
			t.Fatal("concurrent traces shared a connection identity")
		}
		connections[event.ConnectionID] = event.TraceID
		if event.State == "finished" {
			finished++
			if event.Result != "connection-reset" {
				t.Fatalf("lost error classification: %s", event.Result)
			}
		}
	}
	if len(connections) != 8 || finished != 8 {
		t.Fatal("connection or completion was lost")
	}
}

type fmtTransportPrivateError struct{}

func (fmtTransportPrivateError) Error() string { return "PRIVATE socket path and payload" }
func (fmtTransportPrivateError) Unwrap() error { return syscall.ECONNRESET }

type blockedTransportWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	output  bytes.Buffer
}

func (writer *blockedTransportWriter) Write(value []byte) (int, error) {
	writer.once.Do(func() { close(writer.started) })
	<-writer.release
	return writer.output.Write(value)
}

func TestTransportObservationDropsInsteadOfBlockingHandshake(t *testing.T) {
	writer := &blockedTransportWriter{started: make(chan struct{}), release: make(chan struct{})}
	log := newTransportLog(writer)
	observation := newTransportObservation(log, "core", strings.Repeat("a", 32))
	observation.begin("peer-process-capture", 0).finish(nil)
	<-writer.started
	start := time.Now()
	for i := 0; i < 1000; i++ {
		observation.begin("consume-lock-wait", 0).finish(nil)
	}
	if time.Since(start) > time.Second {
		t.Fatal("slow log sink blocked observation")
	}
	if log.dropped.Load() == 0 {
		t.Fatal("overflow was not counted")
	}
	start = time.Now()
	log.close()
	if time.Since(start) > 250*time.Millisecond {
		t.Fatal("blocked sink prevented bounded shutdown")
	}
	close(writer.release)
	select {
	case <-log.done:
	case <-time.After(time.Second):
		t.Fatal("log did not drain after sink recovered")
	}
	if !bytes.Contains(writer.output.Bytes(), []byte("\"dropped_events\":")) {
		t.Fatal("missing evidence was not declared")
	}
}

func TestTransportErrorClassesDoNotRequireErrorText(t *testing.T) {
	for _, test := range []struct {
		err   error
		class string
	}{
		{nil, "ok"}, {io.EOF, "eof"}, {io.ErrUnexpectedEOF, "truncated"}, {io.ErrShortWrite, "short-write"},
		{syscall.EPIPE, "broken-pipe"}, {syscall.ECONNRESET, "connection-reset"}, {syscall.ECONNREFUSED, "connection-refused"},
		{net.ErrClosed, "closed"}, {io.ErrClosedPipe, "closed"}, {errors.New("PRIVATE"), "io-error"},
	} {
		if actual := transportErrorClass(test.err); actual != test.class {
			t.Fatalf("expected %s got %s", test.class, actual)
		}
	}
}
