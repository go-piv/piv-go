package piv

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"testing"
)

type countingRSAReader struct {
	reader       io.Reader
	calls, bytes int
}

func (r *countingRSAReader) Read(p []byte) (int, error) {
	r.calls++
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}

func TestRSADecryptSessionBoundaries(t *testing.T) {
	priv, key := rsaKnownAnswerKey(t)
	raw := key.rawDecrypt
	maximum := priv.Size() - 11
	for _, length := range []int{0, 1, 16, maximum} {
		t.Run(fmt.Sprintf("session-%d", length), func(t *testing.T) {
			sizes := []int{0, 1, 16, maximum}
			if length > 0 {
				sizes = []int{length - 1, length}
				if length < maximum {
					sizes = append(sizes, length+1)
				}
			}
			for _, size := range sizes {
				t.Run(fmt.Sprintf("plaintext-%d", size), func(t *testing.T) {
					message := bytes.Repeat([]byte{0x42}, size)
					ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &priv.PublicKey, message)
					if err != nil {
						t.Fatal(err)
					}
					fallback := bytes.Repeat([]byte{0xa5}, length)
					reader := &countingRSAReader{reader: bytes.NewReader(fallback)}
					calls := 0
					key.rawDecrypt = func(ct []byte) ([]byte, error) { calls++; return raw(ct) }
					opts := &rsa.PKCS1v15DecryptOptions{SessionKeyLen: length}
					control, controlErr := priv.Decrypt(bytes.NewReader(fallback), ciphertext, opts)
					got, err := key.Decrypt(reader, ciphertext, opts)
					want := message
					if length > 0 && size != length {
						want = fallback
					}
					if err != nil || controlErr != nil || !bytes.Equal(got, want) || !bytes.Equal(control, want) || reader.bytes != length || calls != 1 {
						t.Fatalf("got %x/%v, control %x/%v, want %x, random bytes %d, raw calls %d", got, err, control, controlErr, want, reader.bytes, calls)
					}
					if length == 0 && reader.calls != 0 {
						t.Fatalf("SessionKeyLen zero read randomness %d times", reader.calls)
					}
				})
			}
		})
	}
	t.Run("above maximum", func(t *testing.T) {
		calls := 0
		key.rawDecrypt = func([]byte) ([]byte, error) { calls++; return nil, nil }
		reader := &countingRSAReader{reader: bytes.NewReader(bytes.Repeat([]byte{0xa5}, maximum+1))}
		got, err := key.Decrypt(reader, make([]byte, priv.Size()), &rsa.PKCS1v15DecryptOptions{SessionKeyLen: maximum + 1})
		if !errors.Is(err, rsa.ErrDecryption) || got != nil || calls != 0 || reader.calls != 0 {
			t.Fatalf("got %x/%v, raw %d, random reads %d", got, err, calls, reader.calls)
		}
	})
}

func TestRSADecryptSessionRandomFailures(t *testing.T) {
	priv, key := rsaKnownAnswerKey(t)
	sentinel := errors.New("test random source failed")
	tests := []struct {
		name   string
		reader io.Reader
		want   error
		bytes  int
	}{
		{"empty", bytes.NewReader(nil), io.EOF, 0},
		{"short", bytes.NewReader(make([]byte, 15)), io.ErrUnexpectedEOF, 15},
		{"failure before bytes", failingRSAReader{sentinel}, sentinel, 0},
		{"failure after bytes", io.MultiReader(bytes.NewReader(make([]byte, 4)), failingRSAReader{sentinel}), sentinel, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			key.rawDecrypt = func([]byte) ([]byte, error) { calls++; return nil, nil }
			reader := &countingRSAReader{reader: tt.reader}
			got, err := key.Decrypt(reader, make([]byte, priv.Size()), &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 16})
			if !errors.Is(err, tt.want) || got != nil || calls != 0 || reader.bytes != tt.bytes || reader.calls == 0 {
				t.Fatalf("got %x/%v, raw %d, random reads %d/%d bytes", got, err, calls, reader.calls, reader.bytes)
			}
		})
	}
}

func TestRSADecryptSessionMalformedBlocks(t *testing.T) {
	priv, key := rsaKnownAnswerKey(t)
	raw := key.rawDecrypt
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
			ciphertext := encryptEncodedRSA(t, &priv.PublicKey, em)
			fallback := bytes.Repeat([]byte{0xa5}, 16)
			opts := &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 16}
			control, controlErr := priv.Decrypt(bytes.NewReader(fallback), ciphertext, opts)
			reader := &countingRSAReader{reader: bytes.NewReader(fallback)}
			calls := 0
			key.rawDecrypt = func(ct []byte) ([]byte, error) { calls++; return raw(ct) }
			got, err := key.Decrypt(reader, ciphertext, opts)
			if err != nil || controlErr != nil || !bytes.Equal(got, fallback) || !bytes.Equal(control, fallback) || reader.bytes != 16 || calls != 1 {
				t.Fatalf("got %x/%v, control %x/%v, random bytes %d, raw %d", got, err, control, controlErr, reader.bytes, calls)
			}
		})
	}
}
