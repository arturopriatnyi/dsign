// Package dsign is a package for working with digital signatures.
package dsign

import "crypto/ed25519"

const (
	// PrivateKeySize is the size of private keys in bytes.
	PrivateKeySize = 64
	// PublicKeySize is the size of public keys in bytes.
	PublicKeySize = 32
)

// PrivateKey is a private key used for signing.
type PrivateKey []byte

// Size returns the size of PrivateKey.
func (k PrivateKey) Size() int {
	return len(k)
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
