package piv

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"testing"
)

type rsaAPDUFunc func(apdu) ([]byte, error)

func (f rsaAPDUFunc) Transmit(cmd apdu) ([]byte, error) { return f(cmd) }

func TestRSADecryptRawAPDU(t *testing.T) {
	tests := []struct {
		bits         int
		algorithm    byte
		outer, input []byte
	}{
		{1024, 0x06, []byte{0x7c, 0x81, 0x85}, []byte{0x81, 0x81, 0x80}},
		{2048, 0x07, []byte{0x7c, 0x82, 0x01, 0x06}, []byte{0x81, 0x82, 0x01, 0x00}},
		{3072, 0x05, []byte{0x7c, 0x82, 0x01, 0x86}, []byte{0x81, 0x82, 0x01, 0x80}},
		{4096, 0x16, []byte{0x7c, 0x82, 0x02, 0x06}, []byte{0x81, 0x82, 0x02, 0x00}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("RSA%d", tt.bits), func(t *testing.T) {
			pub := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(tt.bits-1)), E: 65537}
			ciphertext := bytes.Repeat([]byte{0x42}, pub.Size())
			ciphertext[0] = 0 // Preserve an explicit leading zero at the APDU boundary.
			raw := bytes.Repeat([]byte{0x43}, pub.Size())
			raw[0], raw[1], raw[10] = 0, 2, 0
			want := append(bytes.Clone(tt.outer), 0x82, 0x00)
			want = append(want, tt.input...)
			want = append(want, ciphertext...)
			slot := SlotKeyManagement
			calls := 0
			tx := rsaAPDUFunc(func(cmd apdu) ([]byte, error) {
				calls++
				if cmd.instruction != 0x87 || cmd.param1 != tt.algorithm || cmd.param2 != 0x9d || !bytes.Equal(cmd.data, want) {
					t.Fatalf("incorrect RSA APDU: %+v; want data %x", cmd, want)
				}
				return marshalASN1(0x7c, marshalASN1(0x82, raw)), nil
			})
			got, err := ykDecryptRSA(tx, slot, pub, ciphertext)
			if err != nil || calls != 1 || !bytes.Equal(got, raw) || len(got) != pub.Size() {
				t.Fatalf("raw RSA output: got %x/%v, calls %d", got, err, calls)
			}
		})
	}
}

func TestRSADecryptRawAPDUFailures(t *testing.T) {
	pub := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: 65537}
	ciphertext := make([]byte, pub.Size())
	raw := make([]byte, pub.Size())
	valid := marshalASN1(0x7c, marshalASN1(0x82, raw))
	transportErr := errors.New("software transport failure")
	tests := []struct {
		name     string
		response []byte
		err      error
	}{
		{"empty", nil, nil},
		{"truncated outer length", []byte{0x7c, 0x82, 0x01}, nil},
		{"wrong outer tag", marshalASN1(0x7d, marshalASN1(0x82, raw)), nil},
		{"wrong inner tag", marshalASN1(0x7c, marshalASN1(0x81, raw)), nil},
		{"truncated response", valid[:len(valid)-1], nil},
		{"transport error with bytes", valid, transportErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := rsaAPDUFunc(func(apdu) ([]byte, error) { return tt.response, tt.err })
			got, err := ykDecryptRSA(tx, SlotKeyManagement, pub, ciphertext)
			if err == nil || got != nil {
				t.Fatalf("malformed/failed response returned %x/%v", got, err)
			}
			if tt.err != nil && !errors.Is(err, transportErr) {
				t.Fatalf("transport error lost: %v", err)
			}
		})
	}
	t.Run("unsupported algorithm before transmit", func(t *testing.T) {
		badPub := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 511), E: 65537}
		calls := 0
		tx := rsaAPDUFunc(func(apdu) ([]byte, error) { calls++; return nil, nil })
		got, err := ykDecryptRSA(tx, SlotKeyManagement, badPub, make([]byte, 64))
		if err == nil || got != nil || calls != 0 {
			t.Fatalf("got %x/%v, calls %d", got, err, calls)
		}
	})
}

func TestRSADecryptConstructorPreflight(t *testing.T) {
	priv, _ := rsaKnownAnswerKey(t)
	slot := SlotKeyManagement
	prompts := 0
	auth := KeyAuth{
		PINPolicy: PINPolicyNever,
		PINPrompt: func() (string, error) { prompts++; return "", errors.New("unexpected PIN prompt") },
	}
	// No transaction/device exists. Supplying a manual policy prevents probing
	// during construction, and public-input failures must stop before auth.
	device := &YubiKey{}
	private, err := device.PrivateKey(slot, &priv.PublicKey, auth)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := private.(*keyRSA)
	if !ok || key.yk != device || key.slot != slot || key.pub != &priv.PublicKey || key.pp != PINPolicyNever || key.rawDecrypt == nil {
		t.Fatalf("incorrect RSA key construction: %#v", private)
	}
	if _, ok := private.(crypto.Signer); !ok {
		t.Fatal("RSA signer compatibility lost")
	}
	decrypter, ok := private.(crypto.Decrypter)
	if !ok || decrypter.Public() != &priv.PublicKey {
		t.Fatal("RSA decrypter/public key compatibility lost")
	}
	tests := []struct {
		name       string
		ciphertext []byte
		opts       crypto.DecrypterOpts
	}{
		{"short ciphertext", []byte{0}, nil},
		{"unsupported options", make([]byte, priv.Size()), struct{}{}},
		{"zero OAEP hash", make([]byte, priv.Size()), &rsa.OAEPOptions{}},
		{"session capacity", make([]byte, priv.Size()), &rsa.PKCS1v15DecryptOptions{SessionKeyLen: priv.Size() - 10}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decrypter.Decrypt(nil, tt.ciphertext, tt.opts)
			if err == nil || got != nil || prompts != 0 {
				t.Fatalf("preflight: got %x/%v, PIN prompts %d", got, err, prompts)
			}
		})
	}
}

// A failing test-only PIN prompt stops the real factory callback before any
// transaction can run, while proving valid ciphertext reaches authentication.
func TestRSADecryptConstructorAuthOrdering(t *testing.T) {
	priv, _ := rsaKnownAnswerKey(t)
	sentinel := errors.New("test-only PIN prompt stopped authentication")
	prompts := 0
	auth := KeyAuth{PINPolicy: PINPolicyAlways, PINPrompt: func() (string, error) { prompts++; return "", sentinel }}
	private, err := (&YubiKey{}).PrivateKey(SlotKeyManagement, &priv.PublicKey, auth)
	if err != nil {
		t.Fatal(err)
	}
	decrypter := private.(crypto.Decrypter)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte("control"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name       string
		ciphertext []byte
		opts       crypto.DecrypterOpts
	}{
		{"short ciphertext", ciphertext[1:], nil},
		{"unsupported options", ciphertext, struct{}{}},
		{"zero OAEP hash", ciphertext, &rsa.OAEPOptions{}},
		{"session capacity", ciphertext, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: priv.Size() - 10}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decrypter.Decrypt(nil, tt.ciphertext, tt.opts)
			if err == nil || got != nil || prompts != 0 {
				t.Fatalf("got %x/%v, prompts %d", got, err, prompts)
			}
		})
	}
	t.Run("valid ciphertext reaches prompt", func(t *testing.T) {
		got, err := decrypter.Decrypt(nil, ciphertext, nil)
		if err == nil || err.Error() != "pin prompt: "+sentinel.Error() || got != nil || prompts != 1 {
			t.Fatalf("got %x/%v, prompts %d", got, err, prompts)
		}
	})
}
