package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// These metadata-only diagnostics never participate in authority. The bounded
// queue drops observations instead of blocking a handshake on a slow log sink.
// Keep the small implementation in the standalone may/Core modules identical.
type transportLog struct {
	queue   chan transportLogEvent
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	closed  atomic.Bool
	dropped atomic.Uint64
}

type transportLogEvent struct {
	Event         string     `json:"event"`
	SchemaVersion int        `json:"schema_version"`
	ObservedAt    time.Time  `json:"observed_at"`
	Component     string     `json:"component"`
	ConnectionID  string     `json:"connection_id"`
	TraceID       string     `json:"trace_id,omitempty"`
	PID           int        `json:"pid"`
	PeerPID       int        `json:"peer_pid,omitempty"`
	Sequence      uint64     `json:"sequence"`
	Phase         string     `json:"phase"`
	State         string     `json:"state"`
	BudgetMS      int64      `json:"budget_ms,omitempty"`
	DeadlineAt    *time.Time `json:"deadline_at,omitempty"`
	ElapsedUS     int64      `json:"elapsed_us"`
	Result        string     `json:"result,omitempty"`
	Accepted      *bool      `json:"accepted,omitempty"`
	DroppedEvents uint64     `json:"dropped_events,omitempty"`
}

func newTransportLog(writer io.Writer) *transportLog {
	if writer == nil {
		return nil
	}
	log := &transportLog{queue: make(chan transportLogEvent, 256), stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(log.done)
		write := func(event transportLogEvent) {
			event.DroppedEvents = log.dropped.Swap(0)
			// A failed sink also counts as missing evidence. Never log err.Error():
			// it can contain socket paths or untrusted protocol content.
			if json.NewEncoder(writer).Encode(event) != nil {
				log.dropped.Add(event.DroppedEvents + 1)
			}
		}
		for {
			select {
			case event := <-log.queue:
				write(event)
			case <-log.stop:
				for {
					select {
					case event := <-log.queue:
						write(event)
					default:
						return
					}
				}
			}
		}
	}()
	return log
}

func (log *transportLog) emit(event transportLogEvent) {
	if log == nil || log.closed.Load() {
		return
	}
	select {
	case log.queue <- event:
	default:
		log.dropped.Add(1)
	}
}

func (log *transportLog) close() {
	if log == nil {
		return
	}
	log.once.Do(func() { log.closed.Store(true); close(log.stop) })
	// The normal sink drains immediately. A blocked sink cannot keep a CLI or
	// service alive indefinitely; a timeout means the tail may be unavailable.
	select {
	case <-log.done:
	case <-time.After(50 * time.Millisecond):
	}
}

type transportObservation struct {
	log          *transportLog
	component    string
	connectionID string
	traceID      string
	peerPID      int
	sequence     uint64
}

func newTransportObservation(log *transportLog, component, traceID string) *transportObservation {
	if log == nil {
		return nil
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil
	}
	observation := &transportObservation{log: log, component: component, connectionID: hex.EncodeToString(id[:])}
	observation.setTrace(traceID)
	return observation
}

func (observation *transportObservation) setTrace(traceID string) {
	if observation == nil {
		return
	}
	decoded, err := hex.DecodeString(traceID)
	if err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == traceID {
		observation.traceID = traceID
	}
}

func (observation *transportObservation) setPeer(pid int) {
	if observation != nil && pid > 0 {
		observation.peerPID = pid
	}
}

type transportSpan struct {
	observation *transportObservation
	sequence    uint64
	phase       string
	start       time.Time
	budget      time.Duration
	deadline    time.Time
}

func (observation *transportObservation) begin(phase string, budget time.Duration, deadlines ...time.Time) *transportSpan {
	if observation == nil {
		return nil
	}
	observation.sequence++
	span := &transportSpan{observation: observation, sequence: observation.sequence, phase: phase, start: time.Now(), budget: budget}
	if len(deadlines) == 1 {
		span.deadline = deadlines[0]
	}
	span.record("started", "", nil)
	return span
}

func (span *transportSpan) finish(err error) {
	span.finishResult(transportErrorClass(err), nil)
}

func (span *transportSpan) finishResult(result string, accepted *bool) {
	if span != nil {
		span.record("finished", result, accepted)
	}
}

func (span *transportSpan) record(state, result string, accepted *bool) {
	o := span.observation
	var acceptance *bool
	if accepted != nil {
		value := *accepted
		acceptance = &value
	}
	event := transportLogEvent{Event: "beholder-transport", SchemaVersion: 1, ObservedAt: time.Now().UTC(),
		Component: o.component, ConnectionID: o.connectionID, TraceID: o.traceID, PID: os.Getpid(), PeerPID: o.peerPID,
		Sequence: span.sequence, Phase: span.phase, State: state, BudgetMS: span.budget.Milliseconds(), Result: result, Accepted: acceptance}
	if state == "finished" {
		event.ElapsedUS = time.Since(span.start).Microseconds()
	}
	if !span.deadline.IsZero() {
		deadline := span.deadline.UTC()
		event.DeadlineAt = &deadline
	}
	o.log.emit(event)
}

type transportFailure struct {
	message string
	class   string
	cause   error
}

func (failure *transportFailure) Error() string { return failure.message }
func (failure *transportFailure) Unwrap() error { return failure.cause }

func transportErrorClass(err error) string {
	if err == nil {
		return "ok"
	}
	var failure *transportFailure
	if errors.As(err, &failure) {
		return failure.class
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	switch {
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "truncated"
	case errors.Is(err, io.ErrShortWrite):
		return "short-write"
	case errors.Is(err, syscall.EPIPE):
		return "broken-pipe"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection-reset"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection-refused"
	case errors.Is(err, os.ErrNotExist):
		return "not-found"
	case errors.Is(err, os.ErrPermission):
		return "permission-denied"
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe):
		return "closed"
	default:
		return "io-error"
	}
}
