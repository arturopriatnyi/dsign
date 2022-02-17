package dsign

import "testing"

func TestGenerateKeys(t *testing.T) {
	privateKey, publicKey, err := GenerateKeys()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if privateKey.Size() != PrivateKeySize {
		t.Errorf("private key size: %v, expected: %v", privateKey.Size(), PrivateKeySize)
	}
	if publicKey.Size() != PublicKeySize {
		t.Errorf("public key size: %v, expected: %v", publicKey.Size(), PublicKeySize)
	}
}
