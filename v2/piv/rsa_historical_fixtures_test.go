package piv

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"
)

func TestRSAHistoricalEncryptorFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/historical-v6.2.1-rsa-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name                                   string
		Bits                                   int
		PrivateKeyPKCS1, Plaintext, Ciphertext string
		SingleBlock                            bool
	}
	if err = json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			priv, err := x509.ParsePKCS1PrivateKey(decode(f.PrivateKeyPKCS1))
			if err != nil {
				t.Fatal(err)
			}
			cipher, want := decode(f.Ciphertext), decode(f.Plaintext)
			calls := 0
			key := &keyRSA{pub: &priv.PublicKey}
			key.rawDecrypt = func(ciphertext []byte) ([]byte, error) {
				tx := historicalRSATransmitter(func(cmd apdu) ([]byte, error) {
					calls++
					alg, err := rsaAlg(&priv.PublicKey)
					if err != nil {
						t.Fatal(err)
					}
					expected := marshalASN1(0x7c, append([]byte{0x82, 0}, marshalASN1(0x81, ciphertext)...))
					if cmd.instruction != insAuthenticate || cmd.param1 != alg || cmd.param2 != 0x9d || !bytes.Equal(cmd.data, expected) {
						t.Fatal("unexpected actual RSA APDU")
					}
					em := new(big.Int).Exp(new(big.Int).SetBytes(ciphertext), priv.D, priv.N).FillBytes(make([]byte, priv.Size()))
					return marshalASN1(0x7c, marshalASN1(0x82, em)), nil
				})
				return ykDecryptRSA(tx, SlotKeyManagement, &priv.PublicKey, ciphertext)
			}
			// This executes the concrete PIV decrypter and actual APDU parser.
			// Only the card's raw RSA private operation is supplied by software.
			for _, explicit := range []bool{false, true} {
				var opts *rsa.PKCS1v15DecryptOptions
				if explicit {
					opts = &rsa.PKCS1v15DecryptOptions{}
				}
				var got []byte
				if explicit {
					got, err = key.Decrypt(nil, cipher, opts)
				} else {
					got, err = key.Decrypt(nil, cipher, nil)
				}
				if f.SingleBlock {
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("historical ciphertext changed %x/%v; want %x", got, err, want)
					}
				} else if !errors.Is(err, rsa.ErrDecryption) || got != nil {
					t.Fatalf("unsupported historical framing returned %x/%v", got, err)
				}
			}
			expectedCalls := 0
			if f.SingleBlock {
				expectedCalls = 2
			}
			if calls != expectedCalls {
				t.Fatalf("RSA transports %d, want %d", calls, expectedCalls)
			}
		})
	}
}
