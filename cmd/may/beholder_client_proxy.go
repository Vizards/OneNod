package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	beholderClientProxyAcceptTimeout = 15 * time.Second
	beholderClientProxyFrameLimit    = 64 * 1024
	beholderClientProxyHandshake     = 2 * time.Second
)

type beholderClientProxy struct {
	log          *transportLog
	diagnostic   *beholderDiagnostic
	listener     *net.UnixListener
	root         string
	socketPath   string
	upstreamPath string
	nonce        []byte
	expectedPeer chan int
	done         chan struct{}
	closeOnce    sync.Once
}

func startBeholderClientProxy(nonce []byte) (*beholderClientProxy, error) {
	return startBeholderClientProxyWithDiagnostic(nonce, nil)
}

func startBeholderClientProxyWithDiagnostic(nonce []byte, diagnostic *beholderDiagnostic, logs ...*transportLog) (*beholderClientProxy, error) {
	upstreamPath := defaultAgentSocket()
	if ((len(nonce) < 16 || len(nonce) > 128) && !(len(nonce) == 0 && validBeholderDiagnostic(diagnostic))) || !validBeholderAgentSocket(upstreamPath) {
		return nil, errors.New("Beholder client proxy input is invalid")
	}
	parent := filepath.Dir(upstreamPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 ||
		parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("OneNod Agent directory is not private")
	}
	root, err := os.MkdirTemp(parent, ".beholder-client-")
	if err != nil || os.Chmod(root, 0o700) != nil {
		if root != "" {
			_ = os.RemoveAll(root)
		}
		return nil, errors.New("create Beholder client proxy directory failed")
	}
	socketPath := filepath.Join(root, "agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil || os.Chmod(socketPath, 0o600) != nil {
		if listener != nil {
			_ = listener.Close()
		}
		_ = os.RemoveAll(root)
		return nil, errors.New("create Beholder client proxy socket failed")
	}
	proxy := &beholderClientProxy{
		diagnostic: diagnostic,
		listener:   listener, root: root, socketPath: socketPath, upstreamPath: upstreamPath,
		nonce: append([]byte(nil), nonce...), expectedPeer: make(chan int, 1), done: make(chan struct{}),
	}
	if len(logs) == 1 {
		proxy.log = logs[0]
	}
	go proxy.serve()
	return proxy, nil
}

func (proxy *beholderClientProxy) expectPeer(pid int) {
	if proxy == nil || pid <= 1 {
		return
	}
	select {
	case proxy.expectedPeer <- pid:
	default:
	}
}

func (proxy *beholderClientProxy) serve() {
	defer close(proxy.done)
	defer func() {
		clear(proxy.nonce)
		proxy.nonce = nil
		_ = proxy.listener.Close()
		_ = os.Remove(proxy.socketPath)
		_ = os.Remove(proxy.root)
	}()
	_ = proxy.listener.SetDeadline(time.Now().Add(beholderClientProxyAcceptTimeout))
	downstream, err := proxy.listener.AcceptUnix()
	if err != nil {
		return
	}
	defer downstream.Close()
	var expectedPID int
	select {
	case expectedPID = <-proxy.expectedPeer:
	case <-time.After(beholderClientProxyAcceptTimeout):
		return
	}
	peerPID, err := localUnixPeerPID(downstream)
	if err != nil || peerPID != expectedPID {
		return
	}
	upstream, observation, err := proxy.connectWithDiagnostic(proxy.diagnostic)
	if err != nil {
		return
	}
	if len(proxy.nonce) > 0 {
		if err := sendBeholderBindingExtension(upstream, proxy.nonce, observation); err != nil {
			observation.begin("binding-fallback", 0).finish(err)
			_ = upstream.Close()
			var diagnostic *beholderDiagnostic
			if validBeholderDiagnostic(proxy.diagnostic) {
				value := *proxy.diagnostic
				value.Stage, value.Code = "binding", "binding-extension-rejected"
				diagnostic = &value
			}
			upstream, observation, err = proxy.connectWithDiagnostic(diagnostic)
			if err != nil {
				return
			}
		}
	}
	defer upstream.Close()

	type copyResult struct{ err error }
	results := make(chan copyResult, 2)
	go func() {
		_, copyErr := io.Copy(upstream, downstream)
		if connection, ok := upstream.(*net.UnixConn); ok {
			_ = connection.CloseWrite()
		}
		results <- copyResult{copyErr}
	}()
	go func() {
		_, copyErr := io.Copy(downstream, upstream)
		_ = downstream.CloseWrite()
		results <- copyResult{copyErr}
	}()
	<-results
	<-results
}

func sendBeholderBindingExtension(connection net.Conn, nonce []byte, observations ...*transportObservation) error {
	var observation *transportObservation
	if len(observations) == 1 {
		observation = observations[0]
	}
	contents := make([]byte, 4)
	binary.BigEndian.PutUint32(contents, beholderBindingVersion)
	contents = appendBeholderAgentString(contents, nonce)
	request := []byte{27}
	request = appendBeholderAgentString(request, []byte(beholderBindingExtensionName))
	request = append(request, contents...)
	deadline := time.Now().Add(beholderClientProxyHandshake)
	if err := connection.SetDeadline(deadline); err != nil {
		observation.begin("binding-deadline", beholderClientProxyHandshake, deadline).finish(err)
		return err
	}
	defer connection.SetDeadline(time.Time{})
	write := observation.begin("binding-write", beholderClientProxyHandshake, deadline)
	err := writeBeholderAgentFrame(connection, request)
	write.finish(err)
	if err != nil {
		return err
	}
	read := observation.begin("binding-read", beholderClientProxyHandshake, deadline)
	response, err := readBeholderAgentFrame(connection)
	err = classifyBeholderExtensionResponse(response, err, "Beholder binding extension was rejected")
	read.finish(err)
	return err
}

func classifyBeholderExtensionResponse(response []byte, err error, message string) error {
	if err != nil {
		return &transportFailure{message: message, class: transportErrorClass(err), cause: err}
	}
	if len(response) == 1 {
		switch response[0] {
		case sshAgentSuccessResponse:
			return nil
		case 5, 28: // SSH_AGENT_FAILURE and SSH_AGENT_EXTENSION_FAILURE.
			return &transportFailure{message: message, class: "rejected"}
		}
	}
	return &transportFailure{message: message, class: "malformed-response"}
}

func appendBeholderAgentString(target, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	target = append(target, length[:]...)
	return append(target, value...)
}

func writeBeholderAgentFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > beholderClientProxyFrameLimit {
		return errors.New("invalid SSH Agent frame")
	}
	frame := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	frame = append(frame, payload...)
	written, err := writer.Write(frame)
	if err == nil && written != len(frame) {
		return io.ErrShortWrite
	}
	return err
}

func readBeholderAgentFrame(reader io.Reader) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > beholderClientProxyFrameLimit {
		return nil, &transportFailure{message: "invalid SSH Agent frame", class: "malformed-frame"}
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (proxy *beholderClientProxy) close() {
	if proxy == nil {
		return
	}
	proxy.closeOnce.Do(func() {
		_ = proxy.listener.Close()
		select {
		case <-proxy.done:
		case <-time.After(2 * time.Second):
		}
	})
}

func sendBeholderDiagnosticExtension(connection net.Conn, diagnostic *beholderDiagnostic, observations ...*transportObservation) error {
	var observation *transportObservation
	if len(observations) == 1 {
		observation = observations[0]
	}
	if !validBeholderDiagnostic(diagnostic) {
		return errors.New("invalid Beholder diagnostic")
	}
	encoded, err := json.Marshal(diagnostic)
	if err != nil {
		return err
	}
	request := appendBeholderAgentString([]byte{27}, []byte(beholderDiagnosticExtensionName))
	request = append(request, encoded...)
	deadline := time.Now().Add(beholderClientProxyHandshake)
	_ = connection.SetDeadline(deadline)
	defer connection.SetDeadline(time.Time{})
	write := observation.begin("diagnostic-write", beholderClientProxyHandshake, deadline)
	err = writeBeholderAgentFrame(connection, request)
	write.finish(err)
	if err != nil {
		return err
	}
	read := observation.begin("diagnostic-read", beholderClientProxyHandshake, deadline)
	response, err := readBeholderAgentFrame(connection)
	err = classifyBeholderExtensionResponse(response, err, "diagnostic extension unavailable")
	read.finish(err)
	return err
}

// A rejected or timed-out optional extension must not leave a partial frame on
// the connection used for ordinary SSH Agent traffic.
func (proxy *beholderClientProxy) connectWithDiagnostic(diagnostic *beholderDiagnostic) (net.Conn, *transportObservation, error) {
	traceID := ""
	if validBeholderDiagnostic(proxy.diagnostic) {
		traceID = proxy.diagnostic.TraceID
	}
	dial := func() (net.Conn, *transportObservation, error) {
		observation := newTransportObservation(proxy.log, "ssh-client", traceID)
		span := observation.begin("agent-dial", time.Second)
		connection, err := net.DialTimeout("unix", proxy.upstreamPath, time.Second)
		if err == nil {
			observation.setPeer(transportPeerPID(connection))
		}
		span.finish(err)
		return connection, observation, err
	}
	connection, observation, err := dial()
	if err != nil {
		return nil, observation, err
	}
	if !validBeholderDiagnostic(diagnostic) {
		observation.begin("diagnostic-omitted", 0).finishResult("unavailable", nil)
		return connection, observation, nil
	}
	if err := sendBeholderDiagnosticExtension(connection, diagnostic, observation); err == nil {
		return connection, observation, nil
	} else {
		observation.begin("diagnostic-fallback", 0).finish(err)
	}
	_ = connection.Close()
	connection, observation, err = dial()
	observation.begin("diagnostic-omitted", 0).finishResult("fallback-without-diagnostic", nil)
	return connection, observation, err
}
