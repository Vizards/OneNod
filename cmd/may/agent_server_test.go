package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func TestUpstreamAgentServerPreservesReadOnlyBoundaryAndConnectionCache(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	identity := servedSSHIdentity{
		catalog: sshCatalogIdentity{
			ItemID: "item-read-only",
			Metadata: catalogSSHMetadata{
				Algorithm:     signer.PublicKey().Type(),
				Fingerprint:   ssh.FingerprintSHA256(signer.PublicKey()),
				PublicKeyBlob: base64URL(signer.PublicKey().Marshal()),
			},
			Title:   "Read-only key",
			Version: 1,
		},
		keyBlob: signer.PublicKey().Marshal(),
	}
	loads := 0
	client, _ := newPipeAgentClient(t, approvalAgent{
		context: context.Background(),
		deps:    dependencies{stderr: io.Discard},
		loadIdentities: func() ([]servedSSHIdentity, error) {
			loads++
			return []servedSSHIdentity{identity}, nil
		},
	})
	keys, err := client.List()
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Blob, identity.keyBlob) ||
		keys[0].Comment != "may:"+identity.catalog.Metadata.Fingerprint {
		t.Fatalf("unexpected upstream identity list: %+v, %v", keys, err)
	}
	if loads != 1 {
		t.Fatalf("identity loader ran %d times after one list", loads)
	}

	_, unrelatedPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedSigner, err := ssh.NewSignerFromKey(unrelatedPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(unrelatedSigner.PublicKey(), []byte("not configured")); err == nil {
		t.Fatal("an unconfigured identity was accepted")
	}
	if loads != 1 {
		t.Fatalf("signing discarded the per-connection identity snapshot; loader ran %d times", loads)
	}
	if _, err := client.Sign(keys[0], make([]byte, 64*1024+1)); err == nil {
		t.Fatal("a signing payload larger than 64 KiB was accepted")
	}

	if err := client.Add(sshagent.AddedKey{PrivateKey: privateKey}); err == nil {
		t.Fatal("the read-only agent accepted Add")
	}
	if err := client.Remove(keys[0]); err == nil {
		t.Fatal("the read-only agent accepted Remove")
	}
	if err := client.RemoveAll(); err == nil {
		t.Fatal("the read-only agent accepted RemoveAll")
	}
	if err := client.Lock([]byte("passphrase")); err == nil {
		t.Fatal("the read-only agent accepted Lock")
	}
	if err := client.Unlock([]byte("passphrase")); err == nil {
		t.Fatal("the read-only agent accepted Unlock")
	}
}

func TestAgentSocketIsPrivate(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent.sock")
	listener, err := listenApprovalAgent(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected socket mode %v", info.Mode())
	}
}

func TestAgentListenerCancellationClosesActiveConnections(t *testing.T) {
	directory, err := os.MkdirTemp("", "ag-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := listenApprovalAgent(filepath.Join(directory, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	agent := approvalAgent{context: ctx, deps: dependencies{stderr: io.Discard}}
	result := make(chan error, 1)
	go func() {
		result <- agent.serveListener(ctx, listener)
	}()

	connection, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := sshagent.NewClient(connection)
	identities, err := client.List()
	if err != nil || len(identities) != 0 {
		t.Fatalf("agent did not accept the test connection: %+v, %v", identities, err)
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("canceled listener returned an error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled listener kept an active connection alive")
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.List(); err == nil {
		t.Fatal("active connection remained usable after cancellation")
	}
}

func TestAdapterReplacesOnlyTheSSHSocketEnvironment(t *testing.T) {
	result := withEnvironmentValue(
		[]string{"PATH=/usr/bin", "SSH_AUTH_SOCK=/native.sock", "OTHER=value"},
		"SSH_AUTH_SOCK",
		"/task/agent.sock",
	)
	joined := strings.Join(result, "\n")
	if strings.Count(joined, "SSH_AUTH_SOCK=") != 1 ||
		!strings.Contains(joined, "SSH_AUTH_SOCK=/task/agent.sock") ||
		!strings.Contains(joined, "PATH=/usr/bin") ||
		!strings.Contains(joined, "OTHER=value") {
		t.Fatalf("unexpected child environment: %v", result)
	}
}

func TestAgentUsesOneFixedSocket(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first := defaultAgentSocket()
	second := defaultAgentSocket()
	if first != second || first != filepath.Join(os.Getenv("HOME"), ".onenod", "agent.sock") {
		t.Fatalf("agent socket is not fixed: %q %q", first, second)
	}
}

func TestAgentPrivateVersionExtensionReportsRunningBinaryIdentity(t *testing.T) {
	if versionExtensionName != "version@github.com/Vizards/OneNod" {
		t.Fatalf("private extension must remain bound to the canonical repository path: %q", versionExtensionName)
	}
	client, _ := newPipeAgentClient(t, approvalAgent{
		context: context.Background(),
		deps:    dependencies{stderr: io.Discard},
	})
	response, err := client.Extension(versionExtensionName, nil)
	if err != nil || len(response) < 2 || response[0] != sshAgentSuccessResponse {
		t.Fatalf("version extension failed: %x, %v", response, err)
	}
	reader := wireReader{value: response[1:]}
	encoded, err := reader.string()
	if err != nil || !reader.done() {
		t.Fatal("invalid version extension framing")
	}
	var version agentRuntimeVersion
	if json.Unmarshal(encoded, &version) != nil || version.Version != productVersion ||
		version.SourceCommit != sourceCommit || version.ClientProtocol != mayClientProtocol {
		t.Fatalf("unexpected version metadata %+v", version)
	}
	if _, err := client.Extension(versionExtensionName, []byte{0}); err == nil {
		t.Fatal("version extension accepted trailing data")
	}
	if _, err := client.Extension("unsupported@example.com", nil); !errors.Is(err, sshagent.ErrExtensionUnsupported) {
		t.Fatalf("unsupported extension returned %v", err)
	}
}

func newPipeAgentClient(
	t *testing.T,
	agent approvalAgent,
) (sshagent.ExtendedAgent, *approvalAgentConnection) {
	t.Helper()
	serverConnection, clientConnection := net.Pipe()
	connection := &approvalAgentConnection{
		agent: agent,
		state: sshAgentConnectionState{client: unknownLocalClientContext()},
	}
	result := make(chan error, 1)
	go func() {
		result <- sshagent.ServeAgent(connection, serverConnection)
	}()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
		<-result
	})
	return sshagent.NewClient(clientConnection), connection
}
