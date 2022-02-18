// Package dsign is a package for working with digital signatures.
package dsign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
)

const (
	// SignatureSize is the size of signatures in bytes.
	SignatureSize = 64
	// PrivateKeySize is the size of private keys in bytes.
	PrivateKeySize = 64
	// PublicKeySize is the size of public keys in bytes.
	PublicKeySize = 32
)

// ErrInvalidKeySize is error that is returned when key has invalid size.
var ErrInvalidKeySize = errors.New("invalid key size")

// Signature is a data hash signed with PrivateKey.
type Signature []byte

// Size returns the size of Signature.
func (s Signature) Size() int {
	return len(s)
}

// Equals checks if two signatures are equal.
func (s Signature) Equals(ss Signature) bool {
	return bytes.Equal(s, ss)
}

// PrivateKey is a private key used for signing.
type PrivateKey []byte

// Size returns the size of PrivateKey.
func (k PrivateKey) Size() int {
	return len(k)
}

// Sign signs data hash with PrivateKey.
func (k PrivateKey) Sign(data io.Reader) (Signature, error) {
	if k.Size() != PrivateKeySize {
		return nil, ErrInvalidKeySize
	}

	h := sha256.New()
	if _, err := io.Copy(h, data); err != nil {
		return nil, err
	}

	// ignoring panic here because we've already checked PrivateKey size
	return ed25519.Sign(ed25519.PrivateKey(k), h.Sum(nil)), nil
}

// PublicKey is a public key used for signature verification.
type PublicKey []byte

// Size returns the size of PublicKey.
func (k PublicKey) Size() int {
	return len(k)
}

// GenerateKeys generates a pair of PrivateKey and PublicKey.
func GenerateKeys() (PrivateKey, PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)

	return PrivateKey(privateKey), PublicKey(publicKey), err
}
