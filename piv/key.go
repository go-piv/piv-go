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
	"math/big"
)

// Slot is a private key and certificate pair managed by the security key.
//
// Slot IDs can be found at:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=27
//
// Associated object IDs for X.509 certificates can be found at:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=30
type Slot struct {
	ID     uint32
	Object uint32
}

var (
	SlotAuthentication     = Slot{0x9a, 0x5fc101}
	SlotSignature          = Slot{0x9c, 0x5fc10a}
	SlotCardAuthentication = Slot{0x9e, 0x5fc10b}
)

type Algorithm int

const (
	AlgorithmEC256 Algorithm = iota
	AlgorithmEC384
	AlgorithmRSA1024
	AlgorithmRSA2048
)

type PinPolicy int

const (
	PinPolicyNever PinPolicy = iota
	PinPolicyOnce
	PinPolicyAlways
)

type TouchPolicy int

const (
	TouchPolicyNever TouchPolicy = iota
	TouchPolicyCached
	TouchPolicyAlways
)

const (
	tagPinPolicy   = 0xaa
	tagTouchPolicy = 0xab
)

var pinPolicyMap = map[PinPolicy]byte{
	PinPolicyNever:  0x01,
	PinPolicyOnce:   0x02,
	PinPolicyAlways: 0x03,
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

type keyOptions struct {
	alg   Algorithm
	pin   PinPolicy
	touch TouchPolicy
}

func ykGenerateKey(tx *scTx, slot Slot, o keyOptions) (crypto.PublicKey, error) {
	alg, ok := algorithmsMap[o.alg]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm")

	}
	tp, ok := touchPolicyMap[o.touch]
	if !ok {
		return nil, fmt.Errorf("unsupported touch policy")
	}
	pp, ok := pinPolicyMap[o.pin]
	if !ok {
		return nil, fmt.Errorf("unsupported pin policy")
	}
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	cmd := apdu{
		instruction: insGenerateAsymmetric,
		param2:      byte(slot.ID),
		data: []byte{
			0xac,
			0x09, // length of remaining data
			algTag, 0x01, alg,
			tagPinPolicy, 0x01, pp,
			tagTouchPolicy, 0x01, tp,
		},
	}
	resp, err := ykTransmit(tx, cmd)
	if err != nil {
		return nil, fmt.Errorf("command failed: %v", err)
	}

	var curve elliptic.Curve
	switch o.alg {
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
