package piv

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
)

// This exact test also runs on baseline 31dc15b with only behavior-neutral
// constructor/callback and Transmit interface seams. The baseline's original
// ykDecryptRSA decoder body remains unchanged. The fake supplies only the
// card's raw exponentiation result to that actual APDU response parser.
func TestRSADecryptHistoricalBoundary(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key := &keyRSA{pub: &priv.PublicKey}
	key.rawDecrypt = func(ciphertext []byte) ([]byte, error) {
		tx := historicalRSATransmitter(func(cmd apdu) ([]byte, error) {
			expected := marshalASN1(0x7c, append([]byte{0x82, 0}, marshalASN1(0x81, ciphertext)...))
			if cmd.instruction != insAuthenticate || cmd.param1 != algRSA2048 || cmd.param2 != 0x9d || !bytes.Equal(cmd.data, expected) {
				t.Fatal("unexpected RSA APDU")
			}
			em := new(big.Int).Exp(new(big.Int).SetBytes(ciphertext), priv.D, priv.N).FillBytes(make([]byte, priv.Size()))
			return marshalASN1(0x7c, marshalASN1(0x82, em)), nil
		})
		return ykDecryptRSA(tx, SlotKeyManagement, &priv.PublicKey, ciphertext)
	}
	for _, tt := range []struct {
		name    string
		opts    crypto.DecrypterOpts
		message []byte
	}{
		{"legacy nil control", nil, []byte("legacy control")},
		{"legacy explicit control", &rsa.PKCS1v15DecryptOptions{}, []byte("legacy control")},
		{"legacy maximum control", nil, bytes.Repeat([]byte{0x42}, priv.Size()-11)},
		{"legacy empty plaintext", nil, []byte{}},
		{"OAEP SHA256", &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte("binding")}, []byte("OAEP control")},
		{"OAEP empty plaintext", &rsa.OAEPOptions{Hash: crypto.SHA256}, []byte{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var ciphertext []byte
			var err error
			if o, ok := tt.opts.(*rsa.OAEPOptions); ok {
				ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, tt.message, o.Label)
			} else {
				ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, tt.message)
			}
			if err != nil {
				t.Fatal(err)
			}
			control, controlErr := priv.Decrypt(nil, ciphertext, tt.opts)
			if controlErr != nil || !bytes.Equal(control, tt.message) {
				t.Fatalf("invalid software control: %x/%v", control, controlErr)
			}
			got, err := key.Decrypt(nil, ciphertext, tt.opts)
			if err != nil || !bytes.Equal(got, tt.message) {
				t.Fatalf("wrapper got %x/%v; want %x", got, err, tt.message)
			}
		})
	}
	for _, tt := range []struct {
		name   string
		modify func([]byte)
	}{
		{"invalid PKCS prefix", func(em []byte) { em[1] = 1 }},
		{"short PKCS padding", func(em []byte) { em[9] = 0 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			em := bytes.Repeat([]byte{0x42}, priv.Size())
			em[0], em[1], em[10] = 0, 2, 0
			tt.modify(em)
			ciphertext := new(big.Int).Exp(new(big.Int).SetBytes(em), big.NewInt(int64(priv.E)), priv.N).FillBytes(make([]byte, priv.Size()))
			control, controlErr := priv.Decrypt(nil, ciphertext, nil)
			if controlErr == nil || control != nil {
				t.Fatalf("malformed software control accepted: %x/%v", control, controlErr)
			}
			got, err := key.Decrypt(nil, ciphertext, nil)
			if !errors.Is(err, rsa.ErrDecryption) || got != nil {
				t.Fatalf("malformed wrapper output: %x/%v", got, err)
			}
		})
	}
}

type historicalRSATransmitter func(apdu) ([]byte, error)

func (f historicalRSATransmitter) Transmit(cmd apdu) ([]byte, error) { return f(cmd) }
