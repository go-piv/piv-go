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
	"encoding/asn1"
	"fmt"
	"math/big"
)

type SlotID byte

const (
	SlotAuthentication     SlotID = 0x9a
	SlotSignature          SlotID = 0x9c
	SlotCardAuthentication SlotID = 0x9e
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

type keyOptions struct {
	alg   Algorithm
	pin   PinPolicy
	touch TouchPolicy
}

func ykGenerateKey(tx *scTx, slotID SlotID, o keyOptions) (crypto.PublicKey, error) {
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
		param2:      byte(slotID),
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
	r, _, err := unmarshalASN1(b, 1, 0x49)
	if err != nil {
		return nil, fmt.Errorf("unmarshal response: %v", err)
	}
	p, _, err := unmarshalASN1(r, 2, 0x06)
	if err != nil {
		return nil, fmt.Errorf("unmarshal points: %v", err)
	}
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
