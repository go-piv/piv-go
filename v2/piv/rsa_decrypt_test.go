package piv

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"
)

// softwareRSAKey substitutes only the card's raw RSA operation. These tests
// exercise keyRSA.Decrypt, not the PIN/touch policies or physical transport.
// math/big exponentiation is test-only and is not a production RSA implementation.
func softwareRSAKey(t *testing.T) (*rsa.PrivateKey, *keyRSA) {
	t.Helper()
	return softwareRSAKeySize(t, 2048)
}

func softwareRSAKeySize(t *testing.T, bits int) (*rsa.PrivateKey, *keyRSA) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return priv, &keyRSA{
		pub: &priv.PublicKey,
		rawDecrypt: func(ciphertext []byte) ([]byte, error) {
			c := new(big.Int).SetBytes(ciphertext)
			if len(ciphertext) != priv.Size() || c.Cmp(priv.N) >= 0 {
				return nil, rsa.ErrDecryption
			}
			return new(big.Int).Exp(c, priv.D, priv.N).FillBytes(make([]byte, priv.Size())), nil
		},
	}
}

func encryptEncodedRSA(t *testing.T, pub *rsa.PublicKey, em []byte) []byte {
	t.Helper()
	if len(em) != pub.Size() || new(big.Int).SetBytes(em).Cmp(pub.N) >= 0 {
		t.Fatal("test encoded message is not a modulus-sized integer below N")
	}
	return new(big.Int).Exp(new(big.Int).SetBytes(em), big.NewInt(int64(pub.E)), pub.N).
		FillBytes(make([]byte, pub.Size()))
}

func TestRSADecryptOptions(t *testing.T) {
	priv, key := softwareRSAKey(t)
	var decrypter crypto.Decrypter = key
	message := []byte("RSA decryption control")
	t.Run("legacy control", func(t *testing.T) {
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, message)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
		if err != nil || !bytes.Equal(got, message) {
			t.Fatalf("legacy control: got %x, err %v", got, err)
		}
	})
	t.Run("OAEP SHA256 round trip", func(t *testing.T) {
		label := []byte("label binding")
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, message, label)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256, Label: label})
		if err != nil || !bytes.Equal(got, message) {
			t.Fatalf("OAEP: got %x, want %x, err %v", got, message, err)
		}
		got, err = decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte("wrong")})
		if !errors.Is(err, rsa.ErrDecryption) || got != nil {
			t.Fatalf("wrong label: got %x, err %v", got, err)
		}
	})
	t.Run("invalid legacy prefix", func(t *testing.T) {
		em := bytes.Repeat([]byte{0x42}, priv.Size())
		em[0], em[1], em[10] = 0, 1, 0
		ciphertext := encryptEncodedRSA(t, &priv.PublicKey, em)
		got, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
		if !errors.Is(err, rsa.ErrDecryption) || got != nil {
			t.Fatalf("invalid prefix accepted: got %x, err %v", got, err)
		}
	})
}

func TestRSADecryptRoundTrips(t *testing.T) {
	for _, bits := range []int{1024, 2048, 3072, 4096} {
		t.Run(fmt.Sprintf("RSA%d", bits), func(t *testing.T) {
			priv, key := softwareRSAKeySize(t, bits)
			tests := []struct {
				name string
				opts crypto.DecrypterOpts
				max  int
			}{
				{"legacy", nil, priv.Size() - 11},
				{"explicit PKCS1v15", &rsa.PKCS1v15DecryptOptions{}, priv.Size() - 11},
				{"OAEP nil label", &rsa.OAEPOptions{Hash: crypto.SHA256}, priv.Size() - 2*sha256.Size - 2},
				{"OAEP empty label", &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte{}}, priv.Size() - 2*sha256.Size - 2},
				{"OAEP binary label same MGF", &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256, Label: []byte{0, 0xff, 0, 1}}, priv.Size() - 2*sha256.Size - 2},
			}
			if bits >= 2048 {
				tests = append(tests, struct {
					name string
					opts crypto.DecrypterOpts
					max  int
				}{"OAEP SHA512", &rsa.OAEPOptions{Hash: crypto.SHA512}, priv.Size() - 2*sha512.Size - 2})
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					for _, n := range []int{0, 16, tt.max} {
						t.Run(fmt.Sprintf("length-%d", n), func(t *testing.T) {
							message := make([]byte, n)
							for i := range message {
								message[i] = []byte{0, 0x42, 0xff, 0}[i%4]
							}
							var ciphertext []byte
							var err error
							if o, ok := tt.opts.(*rsa.OAEPOptions); ok {
								ciphertext, err = rsa.EncryptOAEP(o.Hash.New(), rand.Reader, &priv.PublicKey, message, o.Label)
							} else {
								ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, message)
							}
							if err != nil {
								t.Fatal(err)
							}
							control, controlErr := priv.Decrypt(rand.Reader, ciphertext, tt.opts)
							got, err := key.Decrypt(rand.Reader, ciphertext, tt.opts)
							if controlErr != nil || err != nil || !bytes.Equal(control, message) || !bytes.Equal(got, message) {
								t.Fatalf("got %x/%v, software control %x/%v", got, err, control, controlErr)
							}
						})
					}
				})
			}
			if bits == 1024 {
				ciphertext := make([]byte, priv.Size())
				calls := 0
				key.rawDecrypt = func([]byte) ([]byte, error) { calls++; return nil, nil }
				got, err := key.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA512})
				if !errors.Is(err, rsa.ErrDecryption) || got != nil || calls != 0 {
					t.Fatalf("1024/SHA512 capacity: got %x/%v, raw calls %d", got, err, calls)
				}
			}
		})
	}
}

func TestRSADecryptMalformed(t *testing.T) {
	priv, key := softwareRSAKey(t)
	valid := bytes.Repeat([]byte{0x42}, priv.Size())
	valid[0], valid[1], valid[10] = 0, 2, 0
	tests := []struct {
		name   string
		modify func([]byte)
	}{
		{"first byte", func(em []byte) { em[0] = 1 }},
		{"block type", func(em []byte) { em[1] = 1 }},
		{"short padding", func(em []byte) { em[9] = 0 }},
		{"missing separator", func(em []byte) { em[10] = 0x42 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em := bytes.Clone(valid)
			tt.modify(em)
			for _, opts := range []crypto.DecrypterOpts{nil, &rsa.PKCS1v15DecryptOptions{}} {
				got, err := key.Decrypt(rand.Reader, encryptEncodedRSA(t, &priv.PublicKey, em), opts)
				if !errors.Is(err, rsa.ErrDecryption) || got != nil {
					t.Fatalf("malformed PKCS1v15: got %x, err %v", got, err)
				}
			}
		})
	}
	label := []byte("correct label")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, []byte("control"), label)
	if err != nil {
		t.Fatal(err)
	}
	em, err := key.rawDecrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 1, 1 + sha256.Size} {
		t.Run(fmt.Sprintf("OAEP encoded byte %d", index), func(t *testing.T) {
			bad := bytes.Clone(em)
			bad[index] ^= 1
			got, err := key.Decrypt(rand.Reader, encryptEncodedRSA(t, &priv.PublicKey, bad),
				&rsa.OAEPOptions{Hash: crypto.SHA256, Label: label})
			if !errors.Is(err, rsa.ErrDecryption) || got != nil {
				t.Fatalf("malformed OAEP: got %x, err %v", got, err)
			}
		})
	}
	for _, opts := range []*rsa.OAEPOptions{
		{Hash: crypto.SHA256, Label: []byte("wrong label")},
		{Hash: crypto.SHA512, Label: label},
		{Hash: crypto.SHA256, MGFHash: crypto.SHA512, Label: label},
	} {
		got, err := key.Decrypt(rand.Reader, ciphertext, opts)
		if !errors.Is(err, rsa.ErrDecryption) || got != nil {
			t.Fatalf("wrong OAEP parameter: got %x, err %v", got, err)
		}
	}
	legacy, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := key.Decrypt(rand.Reader, legacy, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if !errors.Is(err, rsa.ErrDecryption) || got != nil {
		t.Fatalf("OAEP silently selected legacy: got %x, err %v", got, err)
	}
}

type failingRSAReader struct{ err error }

func (r failingRSAReader) Read([]byte) (int, error) { return 0, r.err }

func TestRSADecryptPreflight(t *testing.T) {
	priv, key := softwareRSAKey(t)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte("control"))
	if err != nil {
		t.Fatal(err)
	}
	var typedNilOAEP *rsa.OAEPOptions
	var typedNilPKCS *rsa.PKCS1v15DecryptOptions
	tests := []struct {
		name       string
		opts       crypto.DecrypterOpts
		ciphertext []byte
		random     io.Reader
		pub        *rsa.PublicKey
	}{
		{name: "short ciphertext", ciphertext: ciphertext[1:]},
		{name: "long ciphertext", ciphertext: append(bytes.Clone(ciphertext), 0)},
		{name: "ciphertext equals N", ciphertext: priv.N.FillBytes(make([]byte, priv.Size()))},
		{name: "ciphertext greater than N", ciphertext: bytes.Repeat([]byte{0xff}, priv.Size())},
		{name: "unsupported options", opts: struct{}{}, ciphertext: ciphertext},
		{name: "typed nil OAEP", opts: typedNilOAEP, ciphertext: ciphertext},
		{name: "typed nil PKCS", opts: typedNilPKCS, ciphertext: ciphertext},
		{name: "zero hash", opts: &rsa.OAEPOptions{}, ciphertext: ciphertext},
		{name: "unavailable hash", opts: &rsa.OAEPOptions{Hash: crypto.Hash(255)}, ciphertext: ciphertext},
		{name: "unavailable MGF hash", opts: &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.Hash(255)}, ciphertext: ciphertext},
		{name: "negative session length", opts: &rsa.PKCS1v15DecryptOptions{SessionKeyLen: -1}, ciphertext: ciphertext},
		{name: "oversize session length", opts: &rsa.PKCS1v15DecryptOptions{SessionKeyLen: priv.Size()}, ciphertext: ciphertext},
		{name: "session nil random", opts: &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 16}, ciphertext: ciphertext},
		{name: "session random failure", opts: &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 16}, ciphertext: ciphertext, random: failingRSAReader{io.ErrUnexpectedEOF}},
		{name: "bad exponent", ciphertext: ciphertext, pub: &rsa.PublicKey{N: priv.N, E: 1}},
		{name: "missing modulus", ciphertext: ciphertext, pub: &rsa.PublicKey{}},
		{name: "negative modulus", ciphertext: ciphertext, pub: &rsa.PublicKey{N: new(big.Int).Neg(priv.N), E: priv.E}},
		{name: "unsupported key size", ciphertext: make([]byte, 64), pub: &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 511), E: 65537}},
		{name: "OAEP modulus too small", opts: &rsa.OAEPOptions{Hash: crypto.SHA512}, ciphertext: make([]byte, 128), pub: &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copyKey := *key
			if tt.pub != nil {
				copyKey.pub = tt.pub
			}
			calls := 0
			copyKey.rawDecrypt = func([]byte) ([]byte, error) {
				calls++
				return nil, errors.New("unexpected raw RSA operation")
			}
			got, err := copyKey.Decrypt(tt.random, tt.ciphertext, tt.opts)
			if err == nil || got != nil || calls != 0 {
				t.Fatalf("preflight: got %x, err %v, raw calls %d", got, err, calls)
			}
			if tt.name == "session random failure" && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("random error lost: %v", err)
			}
		})
	}
	t.Run("nil public key", func(t *testing.T) {
		k := &keyRSA{}
		got, err := k.Decrypt(nil, ciphertext, nil)
		if !errors.Is(err, rsa.ErrDecryption) || got != nil {
			t.Fatalf("got %x, err %v", got, err)
		}
	})
}

func TestRSADecryptSessionKey(t *testing.T) {
	priv, key := softwareRSAKey(t)
	message := bytes.Repeat([]byte{0x42}, 16)
	fallback := bytes.Repeat([]byte{0xa5}, len(message))
	good, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, message)
	if err != nil {
		t.Fatal(err)
	}
	wrongLength, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, message[:15])
	if err != nil {
		t.Fatal(err)
	}
	badBlock := bytes.Repeat([]byte{0x42}, priv.Size())
	badBlock[0], badBlock[1], badBlock[10] = 0, 1, 0
	tests := []struct {
		name             string
		ciphertext, want []byte
	}{
		{"valid", good, message},
		{"wrong length", wrongLength, fallback},
		{"invalid padding", encryptEncodedRSA(t, &priv.PublicKey, badBlock), fallback},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := key.Decrypt(bytes.NewReader(fallback), tt.ciphertext,
				&rsa.PKCS1v15DecryptOptions{SessionKeyLen: len(message)})
			if err != nil || !bytes.Equal(got, tt.want) {
				t.Fatalf("got %x, want %x, err %v", got, tt.want, err)
			}
		})
	}
}

func TestRSADecryptRawFailures(t *testing.T) {
	priv, key := softwareRSAKey(t)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte("control"))
	if err != nil {
		t.Fatal(err)
	}
	rawErr := errors.New("raw RSA transport failure")
	tests := []struct {
		name   string
		output []byte
		err    error
	}{
		{"error with partial output", []byte("partial plaintext"), rawErr},
		{"short encoded output", make([]byte, priv.Size()-1), nil},
		{"long encoded output", make([]byte, priv.Size()+1), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key.rawDecrypt = func([]byte) ([]byte, error) { return tt.output, tt.err }
			for _, opts := range []crypto.DecrypterOpts{
				nil,
				&rsa.OAEPOptions{Hash: crypto.SHA256},
				&rsa.PKCS1v15DecryptOptions{SessionKeyLen: 16},
			} {
				got, err := key.Decrypt(rand.Reader, ciphertext, opts)
				if err == nil || got != nil {
					t.Fatalf("got %x, err %v", got, err)
				}
				if tt.err != nil && !errors.Is(err, rawErr) {
					t.Fatalf("raw error lost: %v", err)
				}
			}
		})
	}
}

func TestRSADecryptMissingRawOperation(t *testing.T) {
	priv, key := softwareRSAKey(t)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, []byte("control"))
	if err != nil {
		t.Fatal(err)
	}
	key.rawDecrypt = nil
	got, err := key.Decrypt(nil, ciphertext, nil)
	if err == nil || got != nil {
		t.Fatalf("got %x, err %v", got, err)
	}
}

func FuzzRSADecryptPadding(f *testing.F) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	key := &keyRSA{
		pub: &priv.PublicKey,
		rawDecrypt: func(ciphertext []byte) ([]byte, error) {
			return new(big.Int).Exp(new(big.Int).SetBytes(ciphertext), priv.D, priv.N).
				FillBytes(make([]byte, priv.Size())), nil
		},
	}
	label := []byte("fuzz context")
	message := bytes.Repeat([]byte{0x42}, 16)
	legacy, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, message)
	if err != nil {
		f.Fatal(err)
	}
	oaep, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, message, label)
	if err != nil {
		f.Fatal(err)
	}
	for _, ciphertext := range [][]byte{legacy, oaep} {
		em, err := key.rawDecrypt(ciphertext)
		if err != nil {
			f.Fatal(err)
		}
		for mode := uint8(0); mode < 3; mode++ {
			f.Add(em, mode)
		}
	}
	f.Add(make([]byte, priv.Size()), uint8(0))
	f.Fuzz(func(t *testing.T, em []byte, mode uint8) {
		if len(em) != priv.Size() || new(big.Int).SetBytes(em).Cmp(priv.N) >= 0 {
			t.Skip()
		}
		var opts crypto.DecrypterOpts
		switch mode % 3 {
		case 1:
			opts = &rsa.OAEPOptions{Hash: crypto.SHA256, Label: label}
		case 2:
			opts = &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 16}
		}
		ciphertext := encryptEncodedRSA(t, &priv.PublicKey, em)
		random := bytes.Repeat([]byte{0xa5}, 16)
		want, wantErr := priv.Decrypt(bytes.NewReader(random), ciphertext, opts)
		got, gotErr := key.Decrypt(bytes.NewReader(random), ciphertext, opts)
		if (wantErr == nil) != (gotErr == nil) || !bytes.Equal(got, want) {
			t.Fatalf("mode %d: got %x/%v, software control %x/%v", mode%3, got, gotErr, want, wantErr)
		}
		if gotErr != nil && (got != nil || !errors.Is(gotErr, rsa.ErrDecryption)) {
			t.Fatalf("padding failure returned %x/%v", got, gotErr)
		}
	})
}
