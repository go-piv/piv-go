// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package piv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
)

// Slot is a private key and certificate combination managed by the security key.
type Slot struct {
	// Key is a reference for a key type.
	//
	// See: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=32
	Key uint32
	// Object is a reference for data object.
	//
	// See: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=30
	Object uint32
}

// Slot combinations pre-defined by this package.
var (
	SlotAuthentication     = Slot{0x9a, 0x5fc101}
	SlotSignature          = Slot{0x9c, 0x5fc10a}
	SlotCardAuthentication = Slot{0x9e, 0x5fc10b}
)

// Algorithm represents a specific algorithm and bit size supported by the PIV
// specification.
type Algorithm int

// Algorithms supported by this package. Note that not all cards will support
// every algorithm.
//
// For algorithm discovery, see: https://github.com/ericchiang/piv-go/issues/1
const (
	AlgorithmEC256 Algorithm = iota + 1
	AlgorithmEC384
	AlgorithmRSA1024
	AlgorithmRSA2048
)

// PINPolicy represents PIN requirements when signing or decrypting with an
// asymmetric key in a given slot.
type PINPolicy int

// PIN policies supported by this package.
const (
	PINPolicyNever PINPolicy = iota + 1
	PINPolicyOnce
	PINPolicyAlways
)

// TouchPolicy represents proof-of-presence requirements when signing or
// decrypting with asymmetric key in a given slot.
type TouchPolicy int

// Touch policies supported by this package.
const (
	TouchPolicyNever TouchPolicy = iota + 1
	TouchPolicyCached
	TouchPolicyAlways
)

const (
	tagPINPolicy   = 0xaa
	tagTouchPolicy = 0xab
)

var pinPolicyMap = map[PINPolicy]byte{
	PINPolicyNever:  0x01,
	PINPolicyOnce:   0x02,
	PINPolicyAlways: 0x03,
}

var touchPolicyMap = map[TouchPolicy]byte{
	TouchPolicyNever:  0x01,
	TouchPolicyAlways: 0x02,
	TouchPolicyCached: 0x03,
}

var algorithmsMap = map[Algorithm]byte{
	AlgorithmEC256:   algECCP256,
	AlgorithmEC384:   algECCP384,
	AlgorithmRSA1024: algRSA1024,
	AlgorithmRSA2048: algRSA2048,
}

// Certificate returns the certifiate object stored in a given slot.
func (yk *YubiKey) Certificate(slot Slot) (*x509.Certificate, error) {
	tx, err := yk.begin()
	if err != nil {
		return nil, err
	}
	defer tx.Close()
	return ykGetCertificate(tx, slot)
}

func ykGetCertificate(tx *scTx, slot Slot) (*x509.Certificate, error) {
	cmd := apdu{
		instruction: insGetData,
		param1:      0x3f,
		param2:      0xff,
		data: []byte{
			0x5c, // Tag list
			0x03, // Length of tag
			byte(slot.Object >> 16),
			byte(slot.Object >> 8),
			byte(slot.Object),
		},
	}
	resp, err := ykTransmit(tx, cmd)
	if err != nil {
		return nil, fmt.Errorf("command failed: %v", err)
	}
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=85
	obj, _, err := unmarshalASN1(resp, 1, 0x13) // tag 0x53
	if err != nil {
		return nil, fmt.Errorf("unmarshaling response: %v", err)
	}
	certDER, _, err := unmarshalASN1(obj, 1, 0x10) // tag 0x70
	if err != nil {
		return nil, fmt.Errorf("unmarshaling certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %v", err)
	}
	return cert, nil
}

// marshalASN1 encodes a tag, length and data.
//
// TODO: clean this up and maybe switch to cryptobyte?
func marshalASN1(tag byte, data []byte) []byte {
	var l []byte
	n := uint64(len(data))
	if n < 0x80 {
		l = []byte{byte(n)}
	} else if len(data) < 0x100 {
		l = []byte{0x81, byte(n)}
	} else {
		l = []byte{0x82, byte(n >> 8), byte(n)}
	}
	d := append([]byte{tag}, l...)
	return append(d, data...)
}

// SetCertificate stores a certificate object in the provided slot. Setting a
// certificate isn't required to use the associated key for signing or
// decryption.
func (yk *YubiKey) SetCertificate(slot Slot, cert *x509.Certificate) error {
	tx, err := yk.begin()
	if err != nil {
		return err
	}
	defer tx.Close()
	return ykStoreCertificate(tx, slot, cert)
}

func ykStoreCertificate(tx *scTx, slot Slot, cert *x509.Certificate) error {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=40
	data := marshalASN1(0x70, cert.Raw)
	// "for a certificate encoded in uncompressed form CertInfo shall be 0x00"
	data = append(data, marshalASN1(0x71, []byte{0x00})...)
	// Error Detection Code
	data = append(data, marshalASN1(0xfe, nil)...)
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=94
	data = append([]byte{
		0x5c, // Tag list
		0x03, // Length of tag
		byte(slot.Object >> 16),
		byte(slot.Object >> 8),
		byte(slot.Object),
	}, marshalASN1(0x53, data)...)
	cmd := apdu{
		instruction: insPutData,
		param1:      0x3f,
		param2:      0xff,
		data:        data,
	}
	if _, err := ykTransmit(tx, cmd); err != nil {
		return fmt.Errorf("command failed: %v", err)
	}
	return nil
}

// Key is used for key generation and holds different options for the key.
//
// While keys can have default PIN and touch policies, this package currently
// doesn't support this option, and all fields must be provided.
type Key struct {
	// Algorithm to use when generating the key.
	Algorithm Algorithm
	// PINPolicy for the key.
	PINPolicy PINPolicy
	// TouchPolicy for the key.
	TouchPolicy TouchPolicy
}

// GenerateKey generates an asymmetric key on the card, returning the key's
// public key.
func (yk *YubiKey) GenerateKey(slot Slot, opts Key) (crypto.PublicKey, error) {
	tx, err := yk.begin()
	if err != nil {
		return nil, err
	}
	defer tx.Close()
	return ykGenerateKey(tx, slot, opts)
}

func ykGenerateKey(tx *scTx, slot Slot, o Key) (crypto.PublicKey, error) {
	alg, ok := algorithmsMap[o.Algorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm")

	}
	tp, ok := touchPolicyMap[o.TouchPolicy]
	if !ok {
		return nil, fmt.Errorf("unsupported touch policy")
	}
	pp, ok := pinPolicyMap[o.PINPolicy]
	if !ok {
		return nil, fmt.Errorf("unsupported pin policy")
	}
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	cmd := apdu{
		instruction: insGenerateAsymmetric,
		param2:      byte(slot.Key),
		data: []byte{
			0xac,
			0x09, // length of remaining data
			algTag, 0x01, alg,
			tagPINPolicy, 0x01, pp,
			tagTouchPolicy, 0x01, tp,
		},
	}
	resp, err := ykTransmit(tx, cmd)
	if err != nil {
		return nil, fmt.Errorf("command failed: %v", err)
	}

	var curve elliptic.Curve
	switch o.Algorithm {
	case AlgorithmRSA1024, AlgorithmRSA2048:
		pub, err := decodeRSAPublic(resp)
		if err != nil {
			return nil, fmt.Errorf("decoding rsa public key: %v", err)
		}
		return pub, nil
	case AlgorithmEC256:
		curve = elliptic.P256()
	case AlgorithmEC384:
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unsupported algorithm")
	}
	pub, err := decodeECPublic(resp, curve)
	if err != nil {
		return nil, fmt.Errorf("decoding ec public key: %v", err)
	}
	return pub, nil
}

// PrivateKey is used to access signing and decryption options for the key
// stored in the slot. The returned key implements crypto.Signer and/or
// crypto.Decrypter depending on the key type.
func (yk *YubiKey) PrivateKey(slot Slot, public crypto.PublicKey) (crypto.PrivateKey, error) {
	switch pub := public.(type) {
	case *ecdsa.PublicKey:
		return &keyECDSA{yk, slot, pub}, nil
	case *rsa.PublicKey:
		return &keyRSA{yk, slot, pub}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", public)
	}
}

type keyECDSA struct {
	yk   *YubiKey
	slot Slot
	pub  *ecdsa.PublicKey
}

func (k *keyECDSA) Public() crypto.PublicKey {
	return k.pub
}

func (k *keyECDSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	tx, err := k.yk.begin()
	if err != nil {
		return nil, err
	}
	defer tx.Close()
	return ykSignECDSA(tx, k.slot, k.pub, digest)
}

type keyRSA struct {
	yk   *YubiKey
	slot Slot
	pub  *rsa.PublicKey
}

func (k *keyRSA) Public() crypto.PublicKey {
	return k.pub
}

func (k *keyRSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	tx, err := k.yk.begin()
	if err != nil {
		return nil, err
	}
	defer tx.Close()
	return ykSignRSA(tx, k.slot, k.pub, digest, opts)
}

func (k *keyRSA) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	tx, err := k.yk.begin()
	if err != nil {
		return nil, err
	}
	defer tx.Close()
	return ykDecryptRSA(tx, k.slot, k.pub, msg)
}

func ykSignECDSA(tx *scTx, slot Slot, pub *ecdsa.PublicKey, digest []byte) ([]byte, error) {
	var alg byte
	size := pub.Params().BitSize
	switch size {
	case 256:
		alg = algECCP256
	case 384:
		alg = algECCP384
	default:
		return nil, fmt.Errorf("unsupported curve: %d", size)
	}

	// Same as the standard library
	// https://github.com/golang/go/blob/go1.13.5/src/crypto/ecdsa/ecdsa.go#L125-L128
	orderBytes := (size + 7) / 8
	if len(digest) > orderBytes {
		digest = digest[:orderBytes]
	}

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=118
	cmd := apdu{
		instruction: insAuthenticate,
		param1:      alg,
		param2:      byte(slot.Key),
		data: marshalASN1(0x7c,
			append([]byte{0x82, 0x00},
				marshalASN1(0x81, digest)...)),
	}
	resp, err := ykTransmit(tx, cmd)
	if err != nil {
		return nil, fmt.Errorf("command failed: %v", err)
	}
	sig, _, err := unmarshalASN1(resp, 1, 0x1c) // 0x7c
	if err != nil {
		return nil, fmt.Errorf("unmarshal response: %v", err)
	}
	rs, _, err := unmarshalASN1(sig, 2, 0x02) // 0x82
	if err != nil {
		return nil, fmt.Errorf("unmarshal response signature: %v", err)
	}
	return rs, nil
}

func unmarshalASN1(b []byte, class, tag int) (obj, rest []byte, err error) {
	var v asn1.RawValue
	rest, err = asn1.Unmarshal(b, &v)
	if err != nil {
		return nil, nil, err
	}
	if v.Class != class || v.Tag != tag {
		return nil, nil, fmt.Errorf("unexpected class=%d and tag=0x%x", v.Class, v.Tag)
	}
	return v.Bytes, rest, nil
}

func decodeECPublic(b []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	r, _, err := unmarshalASN1(b, 1, 0x49)
	if err != nil {
		return nil, fmt.Errorf("unmarshal response: %v", err)
	}
	p, _, err := unmarshalASN1(r, 2, 0x06)
	if err != nil {
		return nil, fmt.Errorf("unmarshal points: %v", err)
	}
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=96
	size := curve.Params().BitSize / 8
	if len(p) != (size*2)+1 {
		return nil, fmt.Errorf("unexpected points length: %d", len(p))
	}
	// Are points uncompressed?
	if p[0] != 0x04 {
		return nil, fmt.Errorf("points were not uncompressed")
	}
	p = p[1:]
	var x, y big.Int
	x.SetBytes(p[:size])
	y.SetBytes(p[size:])
	if !curve.IsOnCurve(&x, &y) {
		return nil, fmt.Errorf("resulting points are not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}, nil
}

func decodeRSAPublic(b []byte) (*rsa.PublicKey, error) {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	r, _, err := unmarshalASN1(b, 1, 0x49)
	if err != nil {
		return nil, fmt.Errorf("unmarshal response: %v", err)
	}
	mod, r, err := unmarshalASN1(r, 2, 0x01)
	if err != nil {
		return nil, fmt.Errorf("unmarshal modulus: %v", err)
	}
	exp, _, err := unmarshalASN1(r, 2, 0x02)
	if err != nil {
		return nil, fmt.Errorf("unmarshal exponent: %v", err)
	}
	var n, e big.Int
	n.SetBytes(mod)
	e.SetBytes(exp)
	if !e.IsInt64() {
		return nil, fmt.Errorf("returned exponent too large: %s", e.String())
	}
	return &rsa.PublicKey{N: &n, E: int(e.Int64())}, nil
}

func rsaAlg(pub *rsa.PublicKey) (byte, error) {
	size := pub.N.BitLen()
	switch size {
	case 1024:
		return algRSA1024, nil
	case 2048:
		return algRSA2048, nil
	default:
		return 0, fmt.Errorf("unsupported rsa key size: %d", size)
	}
}

func ykDecryptRSA(tx *scTx, slot Slot, pub *rsa.PublicKey, data []byte) ([]byte, error) {
	alg, err := rsaAlg(pub)
	if err != nil {
		return nil, err
	}
	cmd := apdu{
		instruction: insAuthenticate,
		param1:      alg,
		param2:      byte(slot.Key),
		data: marshalASN1(0x7c,
			append([]byte{0x82, 0x00},
				marshalASN1(0x81, data)...)),
	}
	resp, err := ykTransmit(tx, cmd)
	if err != nil {
		return nil, fmt.Errorf("command failed: %v", err)
	}

	sig, _, err := unmarshalASN1(resp, 1, 0x1c) // 0x7c
	if err != nil {
		return nil, fmt.Errorf("unmarshal response: %v", err)
	}
	decrypted, _, err := unmarshalASN1(sig, 2, 0x02) // 0x82
	if err != nil {
		return nil, fmt.Errorf("unmarshal response signature: %v", err)
	}
	// Decrypted blob contains a bunch of random data. Look for a NULL byte which
	// indicates where the plain text starts.
	for i := 2; i+1 < len(decrypted); i++ {
		if decrypted[i] == 0x00 {
			return decrypted[i+1:], nil
		}
	}
	return nil, fmt.Errorf("invalid pkcs#1 v1.5 padding")
}

// PKCS#1 v15 is largely informed by the standard library
// https://github.com/golang/go/blob/go1.13.5/src/crypto/rsa/pkcs1v15.go

func ykSignRSA(tx *scTx, slot Slot, pub *rsa.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, fmt.Errorf("rsassa-pss signatures not supported")
	}

	alg, err := rsaAlg(pub)
	if err != nil {
		return nil, err
	}
	hash := opts.HashFunc()
	if hash.Size() != len(digest) {
		return nil, fmt.Errorf("input must be a hashed message")
	}
	prefix, ok := hashPrefixes[hash]
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm: crypto.Hash(%d)", hash)
	}

	// https://tools.ietf.org/pdf/rfc2313.pdf#page=9
	d := make([]byte, len(prefix)+len(digest))
	copy(d[:len(prefix)], prefix)
	copy(d[len(prefix):], digest)

	paddingLen := pub.Size() - 3 - len(d)
	if paddingLen < 0 {
		return nil, fmt.Errorf("message too large")
	}

	padding := make([]byte, paddingLen)
	for i := range padding {
		padding[i] = 0xff
	}

	// https://tools.ietf.org/pdf/rfc2313.pdf#page=9
	data := append([]byte{0x00, 0x01}, padding...)
	data = append(data, 0x00)
	data = append(data, d...)

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=117
	cmd := apdu{
		instruction: insAuthenticate,
		param1:      alg,
		param2:      byte(slot.Key),
		data: marshalASN1(0x7c,
			append([]byte{0x82, 0x00},
				marshalASN1(0x81, data)...)),
	}
	resp, err := ykTransmit(tx, cmd)
	if err != nil {
		return nil, fmt.Errorf("command failed: %v", err)
	}

	sig, _, err := unmarshalASN1(resp, 1, 0x1c) // 0x7c
	if err != nil {
		return nil, fmt.Errorf("unmarshal response: %v", err)
	}
	pkcs1v15Sig, _, err := unmarshalASN1(sig, 2, 0x02) // 0x82
	if err != nil {
		return nil, fmt.Errorf("unmarshal response signature: %v", err)
	}
	return pkcs1v15Sig, nil
}

var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}
