package dsign

import (
	"errors"
	"io"
	"strings"
	"testing"
)

var (
	testData      = "data"
	testSignature = Signature{
		250, 110, 27, 175, 217, 121, 115, 118, 254, 207,
		35, 116, 88, 86, 84, 171, 139, 35, 240, 244,
		114, 106, 27, 155, 111, 140, 239, 220, 98, 63,
		132, 88, 79, 178, 105, 217, 253, 81, 172, 19,
		11, 131, 83, 198, 73, 246, 165, 225, 156, 217,
		62, 226, 26, 206, 212, 38, 212, 108, 8, 207,
		102, 140, 243, 9,
	}
	testPrivateKey = PrivateKey{
		229, 15, 252, 40, 59, 140, 227, 35, 166, 181,
		199, 33, 13, 105, 157, 9, 118, 58, 33, 219,
		94, 84, 229, 161, 162, 8, 158, 202, 40, 203,
		48, 192, 214, 218, 41, 143, 49, 88, 77, 203,
		255, 20, 45, 70, 126, 18, 67, 110, 35, 196,
		33, 253, 3, 86, 126, 4, 130, 247, 84, 118,
		21, 184, 141, 199,
	}
	testPublicKey = PublicKey{
		214, 218, 41, 143, 49, 88, 77, 203, 255, 20,
		45, 70, 126, 18, 67, 110, 35, 196, 33, 253,
		3, 86, 126, 4, 130, 247, 84, 118, 21, 184,
		141, 199,
	}
)

func TestPrivateKey_Sign(t *testing.T) {
	testcases := map[string]struct {
		privateKey   PrivateKey
		data         io.Reader
		expSignature Signature
		expError     error
	}{
		"data is signed": {
			privateKey:   testPrivateKey,
			data:         strings.NewReader(testData),
			expSignature: testSignature,
			expError:     nil,
		},
		"invalid private key size": {
			privateKey:   PrivateKey{},
			data:         strings.NewReader(testData),
			expSignature: nil,
			expError:     ErrInvalidKeySize,
		},
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			s, err := tc.privateKey.Sign(tc.data)

			if !errors.Is(err, tc.expError) {
				t.Errorf("error: %v, expected: %v", err, tc.expError)
			}
			if tc.expError == nil && s.Size() != SignatureSize {
				t.Errorf("signature size: %v, expected: %v", s.Size(), SignatureSize)
			}
			if tc.expError == nil && !s.Equals(tc.expSignature) {
				t.Errorf("signature: %x, expected: %x", s, tc.expSignature)
			}
		})
	}
}

func TestPublicKey_Verify(t *testing.T) {
	testcases := map[string]struct {
		publicKey   PublicKey
		signature   Signature
		data        io.Reader
		expVerified bool
		expError    error
	}{
		"signature is verified": {
			publicKey:   testPublicKey,
			signature:   testSignature,
			data:        strings.NewReader(testData),
			expVerified: true,
			expError:    nil,
		},
		"invalid public key size": {
			publicKey:   PublicKey{},
			signature:   testSignature,
			data:        strings.NewReader(testData),
			expVerified: false,
			expError:    ErrInvalidKeySize,
		},
		"invalid public key": {
			publicKey:   make([]byte, PublicKeySize),
			signature:   testSignature,
			data:        strings.NewReader(testData),
			expVerified: false,
			expError:    nil,
		},
		"invalid signature": {
			publicKey:   testPublicKey,
			signature:   make([]byte, SignatureSize),
			data:        strings.NewReader(testData),
			expVerified: false,
			expError:    nil,
		},
		"invalid data": {
			publicKey:   testPublicKey,
			signature:   testSignature,
			data:        strings.NewReader("invalid data"),
			expVerified: false,
			expError:    nil,
		},
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			v, err := tc.publicKey.Verify(tc.signature, tc.data)

			if !errors.Is(err, tc.expError) {
				t.Errorf("error: %v, expected: %v", err, tc.expError)
			}
			if v != tc.expVerified {
				t.Errorf("verified: %v, expected: %v", v, tc.expVerified)
			}
		})
	}
}

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
