package main

import (
	"bytes"
	"encoding/base64"

	"golang.org/x/crypto/ssh"
)

func sessionBindContents(hostKey, sessionID, signature []byte, forwarded byte) []byte {
	payload := new(bytes.Buffer)
	writeWireString(payload, hostKey)
	writeWireString(payload, sessionID)
	writeWireString(payload, signature)
	payload.WriteByte(forwarded)
	return payload.Bytes()
}

func userauthPayload(
	sessionID []byte,
	username string,
	method string,
	key ssh.PublicKey,
	serverHostKey []byte,
) []byte {
	payload := new(bytes.Buffer)
	writeWireString(payload, sessionID)
	payload.WriteByte(50)
	writeWireString(payload, []byte(username))
	writeWireString(payload, []byte("ssh-connection"))
	writeWireString(payload, []byte(method))
	payload.WriteByte(1)
	writeWireString(payload, []byte(key.Type()))
	writeWireString(payload, key.Marshal())
	if method == "publickey-hostbound-v00@openssh.com" {
		writeWireString(payload, serverHostKey)
	}
	return payload.Bytes()
}

func base64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
