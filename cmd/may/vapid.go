package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

type vapidCredential struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Version    int    `json:"version"`
}

func runDev(args []string, deps dependencies) error {
	if len(args) >= 1 && args[0] == "verify-release" {
		return runDevVerifyRelease(args[1:], deps)
	}
	return errors.New("usage: may dev verify-release --directory <path> [--artifact <basename>]...")
}

func runOperator(args []string, deps dependencies) error {
	if len(args) >= 1 && args[0] == "init" {
		return runProductionInitialization(args[1:], deps)
	}
	if len(args) >= 1 && args[0] == "update" {
		return runBinaryOperatorUpdate(args[1:], deps)
	}
	if len(args) >= 1 && args[0] == "revoke-cloudflare" {
		return runOperatorRevokeCloudflare(args[1:], deps)
	}
	return errors.New(operatorUsage)
}

func newVapidCredential() (vapidCredential, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return vapidCredential{}, err
	}
	privateBytes := privateKey.D.FillBytes(make([]byte, 32))
	defer zeroBytes(privateBytes)
	publicBytes := elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y)
	return vapidCredential{
		PrivateKey: base64.RawURLEncoding.EncodeToString(privateBytes),
		PublicKey:  base64.RawURLEncoding.EncodeToString(publicBytes),
		Version:    1,
	}, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
