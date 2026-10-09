package piv

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"testing"
)

// These modulus-sized OAEP encoded blocks have a correct SHA-256 label hash.
// They were constructed per RFC 8017 section 7.1.1 using seed 00..1f and
// independently checked with crypto/rsa, so failures exercise DB structure
// validation rather than an already-invalid label hash.
func TestRSADecryptOAEPBlockStructure(t *testing.T) {
	priv, key := softwareRSAKey(t)
	opts := &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte("block structure")}
	tests := []struct {
		name, encoded string
		invalid       bool
	}{
		{"valid control", "00542c6b0ccb510c5fdac3267c6b97482626b5aa28dc8eabc6a3ee2544d75506dbb5f4264b786e41f30ff8172efd502042122974e3e52bd77f941062f615a1087304a6950a06d3e3308ad7d3606ef810eb124e3943404ca746a12c51c7bf7768390f8d842ac9cb62349779a7537a78327d545aaeb33b2d42c7d1dc3680a4b23628627e9db8ad47bfe76dbe653d03d2c0a35999ed28a5023924150d72508668d2442f95db4b0a7de880458b19966f21918f9644106e8d2eb4aff23845703cd214920c1c9b0bc4358902b823c7675320d59ded234f308b9dfa5f8d844d1978330c669fa873071768cf46b419ad2867bb6313d2376313cbf309df7c71f72450f60c", false},
		{"nonzero PS", "0042e533dc6df20d97f74ad4959729fe0df519863de69f984358f96515e9ca3f30b5f4264b786e41f30ff8172efd502042122974e3e52bd77f941062f615a1087306a6950a06d3e3308ad7d3606ef810eb124e3943404ca746a12c51c7bf7768390f8d842ac9cb62349779a7537a78327d545aaeb33b2d42c7d1dc3680a4b23628627e9db8ad47bfe76dbe653d03d2c0a35999ed28a5023924150d72508668d2442f95db4b0a7de880458b19966f21918f9644106e8d2eb4aff23845703cd214920c1c9b0bc4358902b823c7675320d59ded234f308b9dfa5f8d844d1978330c669fa873071768cf46b419ad2867bb6313d2376313cbf309df7c71f72450f60c", true},
		{"missing delimiter", "0037e5b3a0923e052ae035e95313064d11d141d6edc2056cf35abd9f920684d35cb5f4264b786e41f30ff8172efd502042122974e3e52bd77f941062f615a1087304a6950a06d3e3308ad7d3606ef810eb124e3943404ca746a12c51c7bf7768390f8d842ac9cb62349779a7537a78327d545aaeb33b2d42c7d1dc3680a4b23628627e9db8ad47bfe76dbe653d03d2c0a35999ed28a5023924150d72508668d2442f95db4b0a7de880458b19966f21918f9644106e8d2eb4aff23845703cd214920c1c9b0bc4358902b823c7675320d59ded234f308b9dfa5f8d844d1978330c669fa873071768cf46b419ad2867bb6312b759007caf966dff1f1e9950229960", true},
		{"wrong delimiter", "002a61496a7cbbd848be64890853b0922b6708e746d7eb192e424d4b07ecb5ff7fb5f4264b786e41f30ff8172efd502042122974e3e52bd77f941062f615a1087304a6950a06d3e3308ad7d3606ef810eb124e3943404ca746a12c51c7bf7768390f8d842ac9cb62349779a7537a78327d545aaeb33b2d42c7d1dc3680a4b23628627e9db8ad47bfe76dbe653d03d2c0a35999ed28a5023924150d72508668d2442f95db4b0a7de880458b19966f21918f9644106e8d2eb4aff23845703cd214920c1c9b0bc4358902b823c7675320d59ded234f308b9dfa5f8d844d1978330c669fa873071768cf46b419ad2867bb6310d2376313cbf309df7c71f72450f60c", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em, err := hex.DecodeString(tt.encoded)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext := encryptEncodedRSA(t, &priv.PublicKey, em)
			control, controlErr := priv.Decrypt(nil, ciphertext, opts)
			got, err := key.Decrypt(nil, ciphertext, opts)
			if tt.invalid {
				if !errors.Is(controlErr, rsa.ErrDecryption) || control != nil {
					t.Fatalf("invalid fixture: software control %x/%v", control, controlErr)
				}
				if !errors.Is(err, rsa.ErrDecryption) || got != nil {
					t.Fatalf("invalid OAEP block returned %x/%v", got, err)
				}
			} else if controlErr != nil || err != nil || !bytes.Equal(control, []byte("encoded control")) || !bytes.Equal(got, control) {
				t.Fatalf("valid control: got %x/%v, software %x/%v", got, err, control, controlErr)
			}
		})
	}
}
