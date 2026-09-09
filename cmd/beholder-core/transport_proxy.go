package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	beholderAgentExtensionRequest   = 27
	beholderAgentSuccessResponse    = 6
	beholderBindingExtensionName    = "beholder-bind@github.com/Vizards/OneNod"
	beholderBindingExtensionVersion = 1
	maximumAgentFrameSize           = 64 * 1024
	bindingHandshakeTimeout         = time.Second
)

type boundAgentProxy struct {
	listener        *net.UnixListener
	socketPath      string
	upstreamPath    string
	bindingNonce    []byte
	expectedPeerRef string
	expectedPeerUID uint32
	observation     chan proxyObservation
	closeOnce       sync.Once
}

type proxyObservation struct {
	Forwarded           bool
	SourceMatched       bool
	BindingAcknowledged bool
	BindingFallback     bool
	ErrorCode           string
	BytesToUpstream     int64
	BytesFromUpstream   int64
}

func startBoundAgentProxy(
	root, upstreamPath string,
	bindingNonce []byte,
	requester processIdentity,
) (*boundAgentProxy, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(upstreamPath) ||
		len(bindingNonce) < 16 || len(bindingNonce) > 128 || requester.PID <= 1 {
		return nil, errors.New("invalid bound Agent proxy configuration")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("bound Agent proxy root is writable")
	}
	socketPath := filepath.Join(root, "agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, errors.New("bound Agent proxy listen failed")
	}
	if os.Chmod(socketPath, 0o600) != nil ||
		(os.Geteuid() == 0 && os.Chown(socketPath, int(requester.UID), -1) != nil) {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return nil, errors.New("bound Agent proxy ownership failed")
	}
	proxy := &boundAgentProxy{
		listener: listener, socketPath: socketPath, upstreamPath: upstreamPath,
		bindingNonce:    append([]byte(nil), bindingNonce...),
		expectedPeerRef: rawProcessRef(requester), expectedPeerUID: requester.UID,
		observation: make(chan proxyObservation, 1),
	}
	go proxy.serveOnce()
	return proxy, nil
}

func (proxy *boundAgentProxy) serveOnce() {
	observation := proxyObservation{}
	defer func() {
		clear(proxy.bindingNonce)
		proxy.bindingNonce = nil
		proxy.observation <- observation
	}()
	downstream, err := proxy.listener.AcceptUnix()
	if err != nil {
		observation.ErrorCode = "proxy-accept-failed"
		return
	}
	defer downstream.Close()
	peerPID, err := unixPeerPID(downstream)
	if err != nil {
		observation.ErrorCode = "proxy-peer-unavailable"
		return
	}
	chain, err := captureProcessChain(peerPID)
	if err != nil || !proxy.matchesRequester(chain) || revalidateProcessChain(chain) != "" {
		observation.ErrorCode = "proxy-source-mismatch"
		return
	}
	observation.SourceMatched = true

	upstream, err := net.DialTimeout("unix", proxy.upstreamPath, time.Second)
	if err != nil {
		observation.ErrorCode = "proxy-upstream-unavailable"
		return
	}
	defer upstream.Close()
	if err := sendBindingExtension(upstream, proxy.bindingNonce); err != nil {
		// An older Agent or an unavailable Core must retain OneNod's existing
		// human-approval path. The extension response has already been consumed,
		// so forwarding the original standard frames on this connection is safe.
		observation.BindingFallback = true
	} else {
		observation.BindingAcknowledged = true
	}

	type copyResult struct {
		toUpstream bool
		bytes      int64
		err        error
	}
	results := make(chan copyResult, 2)
	go func() {
		count, copyErr := io.Copy(upstream, downstream)
		if unixConnection, ok := upstream.(*net.UnixConn); ok {
			_ = unixConnection.CloseWrite()
		}
		results <- copyResult{toUpstream: true, bytes: count, err: copyErr}
	}()
	go func() {
		count, copyErr := io.Copy(downstream, upstream)
		_ = downstream.CloseWrite()
		results <- copyResult{bytes: count, err: copyErr}
	}()
	for index := 0; index < 2; index++ {
		result := <-results
		if result.err != nil {
			observation.ErrorCode = "proxy-copy-failed"
			return
		}
		if result.toUpstream {
			observation.BytesToUpstream = result.bytes
		} else {
			observation.BytesFromUpstream = result.bytes
		}
	}
	observation.Forwarded = true
}

func (proxy *boundAgentProxy) matchesRequester(chain processChain) bool {
	if len(chain.Nodes) == 0 || chain.Nodes[0].UID != proxy.expectedPeerUID ||
		chain.Nodes[0].RealUID != proxy.expectedPeerUID {
		return false
	}
	for _, node := range chain.Nodes {
		if rawProcessRef(node) == proxy.expectedPeerRef {
			return true
		}
	}
	return false
}

func revalidateProcessChain(chain processChain) string {
	if len(chain.Nodes) == 0 {
		return "process-missing"
	}
	for index, original := range chain.Nodes {
		current, err := inspectProcess(original.PID)
		if err != nil {
			if index == 0 {
				return "process-exited"
			}
			continue
		}
		if current.ParentPID != original.ParentPID ||
			current.StartSeconds != original.StartSeconds ||
			current.StartMicroseconds != original.StartMicroseconds {
			return "pid-start-mismatch"
		}
	}
	return ""
}

func sendBindingExtension(connection net.Conn, nonce []byte) error {
	contents := make([]byte, 4)
	binary.BigEndian.PutUint32(contents, beholderBindingExtensionVersion)
	contents = appendAgentString(contents, nonce)
	request := []byte{beholderAgentExtensionRequest}
	request = appendAgentString(request, []byte(beholderBindingExtensionName))
	request = append(request, contents...)
	if err := connection.SetDeadline(time.Now().Add(bindingHandshakeTimeout)); err != nil {
		return err
	}
	defer connection.SetDeadline(time.Time{})
	if err := writeAgentFrame(connection, request); err != nil {
		return err
	}
	response, err := readAgentFrame(connection)
	if err != nil {
		return err
	}
	if len(response) != 1 || response[0] != beholderAgentSuccessResponse {
		return errors.New("binding extension was rejected")
	}
	return nil
}

func appendAgentString(target, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	target = append(target, length[:]...)
	return append(target, value...)
}

func writeAgentFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > maximumAgentFrameSize {
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

func readAgentFrame(reader io.Reader) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > maximumAgentFrameSize {
		return nil, errors.New("invalid SSH Agent frame")
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (proxy *boundAgentProxy) wait(timeout time.Duration) proxyObservation {
	select {
	case observation := <-proxy.observation:
		return observation
	case <-time.After(timeout):
		return proxyObservation{ErrorCode: "proxy-timeout"}
	}
}

func (proxy *boundAgentProxy) close() {
	proxy.closeOnce.Do(func() {
		_ = proxy.listener.Close()
		if info, err := os.Lstat(proxy.socketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(proxy.socketPath)
		}
	})
}
