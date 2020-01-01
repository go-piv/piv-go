package ykpiv

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
	AlgorithmEC Algorithm = iota
	AlgorithmRSA
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

func ykAlg(alg Algorithm, bits int) (byte, error) {
	switch alg {
	case AlgorithmEC:
		switch bits {
		case 256:
			return algECCP256, nil
		case 384:
			return algECCP384, nil
		default:
			return 0, fmt.Errorf("bits for ec key must be 256 or 384")
		}
	case AlgorithmRSA:
		switch bits {
		case 1024:
			return algRSA1024, nil
		case 2048:
			return algRSA2048, nil
		default:
			return 0, fmt.Errorf("bits for rsa key must be 1024 or 2048")
		}
	default:
		return 0, fmt.Errorf("algorithm must be ec or rsa")
	}
}

type keyOptions struct {
	alg   Algorithm
	bits  int
	pin   PinPolicy
	touch TouchPolicy
}

func ykGenerateKey(tx *scTx, slotID SlotID, o keyOptions) (crypto.PublicKey, error) {
	alg, err := ykAlg(o.alg, o.bits)
	if err != nil {
		return nil, err
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
	switch o.alg {
	case AlgorithmRSA:
		pub, err := decodeRSAPublic(resp)
		if err != nil {
			return nil, fmt.Errorf("decoding rsa public key: %v", err)
		}
		return pub, nil
	case AlgorithmEC:
		var curve elliptic.Curve
		switch o.bits {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("invalid curve length: %d", o.bits)
		}
		pub, err := decodeECPublic(resp, curve)
		if err != nil {
			return nil, fmt.Errorf("decoding ec public key: %v", err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm")
	}
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
