// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in ../third_party/rsa/LICENSE.

package piv

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	_ "crypto/sha1"
	"math/big"
	"testing"
)

// This known-answer vector is from Go 1.20.14 crypto/rsa.Test2DecryptOAEP.
// It exercises a distinct OAEP hash and MGF1 hash through keyRSA.Decrypt:
// https://github.com/golang/go/blob/go1.20.14/src/crypto/rsa/rsa_test.go
func TestRSADecryptDistinctMGFHash(t *testing.T) {
	priv, key := rsaKnownAnswerKey(t)
	message := []byte{0xed, 0x36, 0x90, 0x8d, 0xbe, 0xfc, 0x35, 0x40, 0x70, 0x4f, 0xf5, 0x9d, 0x6e, 0xc2, 0xeb, 0xf5, 0x27, 0xae, 0x65, 0xb0, 0x59, 0x29, 0x45, 0x25, 0x8c, 0xc1, 0x91, 0x22}
	ciphertext := []byte{0x72, 0x26, 0x84, 0xc9, 0xcf, 0xd6, 0xa8, 0x96, 0x04, 0x3e, 0x34, 0x07, 0x2c, 0x4f, 0xe6, 0x52, 0xbe, 0x46, 0x3c, 0xcf, 0x79, 0x21, 0x09, 0x64, 0xe7, 0x33, 0x66, 0x9b, 0xf8, 0x14, 0x22, 0x43, 0xfe, 0x8e, 0x52, 0x8b, 0xe0, 0x5f, 0x98, 0xef, 0x54, 0xac, 0x6b, 0xc6, 0x26, 0xac, 0x5b, 0x1b, 0x4b, 0x7d, 0x2e, 0xd7, 0x69, 0x28, 0x5a, 0x2f, 0x4a, 0x95, 0x89, 0x6c, 0xc7, 0x53, 0x95, 0xc7, 0xd2, 0x89, 0x04, 0x6f, 0x94, 0x74, 0x9b, 0x09, 0x0d, 0xf4, 0x61, 0x2e, 0xab, 0x48, 0x57, 0x4a, 0xbf, 0x95, 0xcb, 0xff, 0x15, 0xe2, 0xa0, 0x66, 0x58, 0xf7, 0x46, 0xf8, 0xc7, 0x0b, 0xb5, 0x1e, 0xa7, 0xba, 0x36, 0xce, 0xdd, 0x36, 0x41, 0x98, 0x6e, 0x10, 0xf9, 0x3b, 0x70, 0xbb, 0xa1, 0xda, 0x00, 0x40, 0xd5, 0xa5, 0x3f, 0x87, 0x64, 0x32, 0x7c, 0xbc, 0x50, 0x52, 0x0e, 0x4f, 0x21, 0xbd}
	opts := &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA1}
	control, err := priv.Decrypt(nil, ciphertext, opts)
	if err != nil || !bytes.Equal(control, message) {
		t.Fatalf("software control: got %x, err %v", control, err)
	}
	got, err := key.Decrypt(nil, ciphertext, opts)
	if err != nil || !bytes.Equal(got, message) {
		t.Fatalf("distinct MGF hash: got %x, want %x, err %v", got, message, err)
	}
	got, err = key.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err == nil || got != nil {
		t.Fatalf("wrong MGF hash accepted: got %x, err %v", got, err)
	}
}

func rsaKnownAnswerKey(t *testing.T) (*rsa.PrivateKey, *keyRSA) {
	t.Helper()
	n, _ := new(big.Int).SetString("a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb", 16)
	d, _ := new(big.Int).SetString("53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1", 16)
	p, _ := new(big.Int).SetString("cc8853d1d54da630fac004f471f281c7b8982d8224a490edbeb33d3e3d5cc93c4765703d1dd791642f1f116a0dd852be2419b2af72bfe9a030e860b0288b5d77", 16)
	q, _ := new(big.Int).SetString("d32737e7267ffe1341b2d5c0d150a81b586fb3132bed2f8d5262864a9cb9f30af38be448598d413a172efb802c21acf1c11c520c2f26a471dcad212eac7ca39d", 16)
	priv := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 65537}, D: d, Primes: []*big.Int{p, q}}
	if err := priv.Validate(); err != nil {
		t.Fatal(err)
	}
	key := &keyRSA{
		pub: &priv.PublicKey,
		rawDecrypt: func(ciphertext []byte) ([]byte, error) {
			return new(big.Int).Exp(new(big.Int).SetBytes(ciphertext), priv.D, priv.N).
				FillBytes(make([]byte, priv.Size())), nil
		},
	}
	return priv, key
}
