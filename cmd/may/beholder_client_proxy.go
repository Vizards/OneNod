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

func startBeholderClientProxyWithDiagnostic(nonce []byte, diagnostic *beholderDiagnostic) (*beholderClientProxy, error) {
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
	upstream, err := proxy.connectWithDiagnostic(proxy.diagnostic)
	if err != nil {
		return
	}
	if len(proxy.nonce) > 0 {
		if err := sendBeholderBindingExtension(upstream, proxy.nonce); err != nil {
			_ = upstream.Close()
			var diagnostic *beholderDiagnostic
			if validBeholderDiagnostic(proxy.diagnostic) {
				value := *proxy.diagnostic
				value.Stage, value.Code = "binding", "binding-extension-rejected"
				diagnostic = &value
			}
			upstream, err = proxy.connectWithDiagnostic(diagnostic)
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

func sendBeholderBindingExtension(connection net.Conn, nonce []byte) error {
	contents := make([]byte, 4)
	binary.BigEndian.PutUint32(contents, beholderBindingVersion)
	contents = appendBeholderAgentString(contents, nonce)
	request := []byte{27}
	request = appendBeholderAgentString(request, []byte(beholderBindingExtensionName))
	request = append(request, contents...)
	if err := connection.SetDeadline(time.Now().Add(beholderClientProxyHandshake)); err != nil {
		return err
	}
	defer connection.SetDeadline(time.Time{})
	if err := writeBeholderAgentFrame(connection, request); err != nil {
		return err
	}
	response, err := readBeholderAgentFrame(connection)
	if err != nil || len(response) != 1 || response[0] != sshAgentSuccessResponse {
		return errors.New("Beholder binding extension was rejected")
	}
	return nil
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
		return nil, errors.New("invalid SSH Agent frame")
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

func sendBeholderDiagnosticExtension(connection net.Conn, diagnostic *beholderDiagnostic) error {
	if !validBeholderDiagnostic(diagnostic) {
		return errors.New("invalid Beholder diagnostic")
	}
	encoded, err := json.Marshal(diagnostic)
	if err != nil {
		return err
	}
	request := appendBeholderAgentString([]byte{27}, []byte(beholderDiagnosticExtensionName))
	request = append(request, encoded...)
	_ = connection.SetDeadline(time.Now().Add(beholderClientProxyHandshake))
	defer connection.SetDeadline(time.Time{})
	if err := writeBeholderAgentFrame(connection, request); err != nil {
		return err
	}
	response, err := readBeholderAgentFrame(connection)
	if err != nil || len(response) != 1 || response[0] != sshAgentSuccessResponse {
		return errors.New("diagnostic extension unavailable")
	}
	return nil
}

// A rejected or timed-out optional extension must not leave a partial frame on
// the connection used for ordinary SSH Agent traffic.
func (proxy *beholderClientProxy) connectWithDiagnostic(diagnostic *beholderDiagnostic) (net.Conn, error) {
	connection, err := net.DialTimeout("unix", proxy.upstreamPath, time.Second)
	if err != nil {
		return nil, err
	}
	if !validBeholderDiagnostic(diagnostic) || sendBeholderDiagnosticExtension(connection, diagnostic) == nil {
		return connection, nil
	}
	_ = connection.Close()
	return net.DialTimeout("unix", proxy.upstreamPath, time.Second)
}
