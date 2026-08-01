package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
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
	if len(args) == 1 && args[0] == "init" {
		return runProductionInitialization(args[1:], deps)
	}
	if len(args) == 1 && args[0] == "update" {
		return runBinaryOperatorUpdate(args[1:], deps)
	}
	return errors.New("usage: may operator init | may operator update")
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

func validateVapidCredential(credential *vapidCredential) error {
	if credential == nil || credential.Version != 1 {
		return errors.New("invalid version")
	}
	privateBytes, err := base64.RawURLEncoding.DecodeString(credential.PrivateKey)
	if err != nil || len(privateBytes) != 32 {
		return errors.New("invalid private key")
	}
	defer zeroBytes(privateBytes)
	publicBytes, err := base64.RawURLEncoding.DecodeString(credential.PublicKey)
	if err != nil || len(publicBytes) != 65 {
		return errors.New("invalid public key")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicBytes)
	if x == nil || y == nil {
		return errors.New("invalid public point")
	}
	derivedX, derivedY := elliptic.P256().ScalarBaseMult(privateBytes)
	if derivedX.Cmp(x) != 0 || derivedY.Cmp(y) != 0 || new(big.Int).SetBytes(privateBytes).Sign() == 0 {
		return errors.New("public key mismatch")
	}
	return nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
