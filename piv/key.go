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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
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

var (
	extIDFirmwareVersion = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 3})
	extIDSerialNumber    = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 7})
	extIDKeyPolicy       = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 8})
	extIDFormFactor      = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 41482, 3, 9})
)

// Version encodes a major, minor, and patch version.
type Version struct {
	Major int
	Minor int
	Patch int
}

// Formfactor enumerates the physical set of forms a key can take. USB-A vs.
// USB-C and Keychain vs. Nano.
type Formfactor int

// Formfactors recognized by this package.
const (
	FormfactorUSBAKeychain = iota + 1
	FormfactorUSBANano
	FormfactorUSBCKeychain
	FormfactorUSBCNano
)

// Attestation returns additional information about a key attested to be on a
// card.
type Attestation struct {
	// Version of the YubiKey's firmware.
	Version Version
	// Serial is the YubiKey's serial number.
	Serial uint32
	// Formfactor indicates the physical type of the YubiKey.
	//
	// Formfactor may be empty Formfactor(0) for some YubiKeys.
	Formfactor Formfactor

	// PINPolicy set on the slot.
	PINPolicy PINPolicy
	// TouchPolicy set on the slot.
	TouchPolicy TouchPolicy
}

func (a *Attestation) addExt(e pkix.Extension) error {
	if e.Id.Equal(extIDFirmwareVersion) {
		if len(e.Value) != 3 {
			return fmt.Errorf("expected 3 bytes for firmware version, got: %d", len(e.Value))
		}
		a.Version = Version{
			Major: int(e.Value[0]),
			Minor: int(e.Value[1]),
			Patch: int(e.Value[2]),
		}
	} else if e.Id.Equal(extIDSerialNumber) {
		var serial int64
		if _, err := asn1.Unmarshal(e.Value, &serial); err != nil {
			return fmt.Errorf("parsing serial number: %v", err)
		}
		if serial < 0 {
			return fmt.Errorf("serial number was negative: %d", serial)
		}
		a.Serial = uint32(serial)
	} else if e.Id.Equal(extIDKeyPolicy) {
		if len(e.Value) != 2 {
			return fmt.Errorf("expected 2 bytes from key policy, got: %d", len(e.Value))
		}
		switch e.Value[0] {
		case 0x01:
			a.PINPolicy = PINPolicyNever
		case 0x02:
			a.PINPolicy = PINPolicyOnce
		case 0x03:
			a.PINPolicy = PINPolicyAlways
		default:
			return fmt.Errorf("unrecognized pin policy: 0x%x", e.Value[0])
		}
		switch e.Value[1] {
		case 0x01:
			a.TouchPolicy = TouchPolicyNever
		case 0x02:
			a.TouchPolicy = TouchPolicyAlways
		case 0x03:
			a.TouchPolicy = TouchPolicyCached
		default:
			return fmt.Errorf("unrecognized touch policy: 0x%x", e.Value[1])
		}
	} else if e.Id.Equal(extIDFormFactor) {
		if len(e.Value) != 1 {
			return fmt.Errorf("expected 1 byte from formfactor, got: %d", len(e.Value))
		}
		switch e.Value[0] {
		case 0x01:
			a.Formfactor = FormfactorUSBAKeychain
		case 0x02:
			a.Formfactor = FormfactorUSBANano
		case 0x03:
			a.Formfactor = FormfactorUSBCKeychain
		case 0x04:
			a.Formfactor = FormfactorUSBCNano
		default:
			return fmt.Errorf("unrecognized formfactor: 0x%x", e.Value[0])
		}
	}
	return nil
}

func verifySignature(parent, c *x509.Certificate) error {
	return parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
}

// Verify proves that a key was generated on a YubiKey. It ensures the slot and
// YubiKey certificate chains up to the Yubico CA, parsing additional information
// out of the slot certificate, such as the touch and PIN policies of a key.
func Verify(attestationCert, slotCert *x509.Certificate) (*Attestation, error) {
	var v verifier
	return v.Verify(attestationCert, slotCert)
}

type verifier struct {
	Root *x509.Certificate
}

func (v *verifier) Verify(attestationCert, slotCert *x509.Certificate) (*Attestation, error) {
	root := v.Root
	if root == nil {
		ca, err := yubicoCA()
		if err != nil {
			return nil, fmt.Errorf("parsing yubico ca: %v", err)
		}
		root = ca
	}
	if err := verifySignature(root, attestationCert); err != nil {
		return nil, fmt.Errorf("attestation certifcate not signed by : %v", err)
	}
	if err := verifySignature(attestationCert, slotCert); err != nil {
		return nil, fmt.Errorf("slot certificate not signed by attestation certifcate: %v", err)
	}
	var a Attestation
	for _, ext := range slotCert.Extensions {
		if err := a.addExt(ext); err != nil {
			return nil, fmt.Errorf("parsing extension: %v", err)
		}
	}
	return &a, nil
}

// yubicoPIVCAPEM is the PEM encoded attestation certificate used by Yubico.
//
// https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
const yubicoPIVCAPEM = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1
YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY
DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg
U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2
cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E
ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq
joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH
BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf
wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet
X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0
1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s
XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2
lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d
bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq
Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8
SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7
-----END CERTIFICATE-----`

func yubicoCA() (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(yubicoPIVCAPEM))
	if b == nil {
		return nil, fmt.Errorf("failed to decode yubico pem data")
	}
	return x509.ParseCertificate(b.Bytes)
}

// Slot combinations pre-defined by this package.
//
// Object IDs are specified in NIST 800-73-4 section 4.3:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=30
//
// Key IDs are specified in NIST 800-73-4 section 5.1:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=32
var (
	SlotAuthentication     = Slot{0x9a, 0x5fc105}
	SlotSignature          = Slot{0x9c, 0x5fc10a}
	SlotCardAuthentication = Slot{0x9e, 0x5fc101}
	SlotKeyManagement      = Slot{0x9d, 0x5fc10b}

	slotAttestation = Slot{0xf9, 0x5fff01}
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

// AttestationCertificate returns the YubiKey's attestation certificate, which
// is unique to the key and signed by Yubico.
func (yk *YubiKey) AttestationCertificate() (*x509.Certificate, error) {
	return yk.Certificate(slotAttestation)
}

// Attest generates a certificate for a key, signed by the YubiKey's attestation
// certificate. This can be used to prove a key was generate on a specific
// YubiKey.
func (yk *YubiKey) Attest(slot Slot) (*x509.Certificate, error) {
	tx, err := yk.begin()
	if err != nil {
		return nil, err
	}
	defer tx.Close()
	return ykAttest(tx, slot)
}

func ykAttest(tx *scTx, slot Slot) (*x509.Certificate, error) {
	cmd := apdu{
		instruction: insAttest,
		param1:      byte(slot.Key),
	}
	resp, err := ykTransmit(tx, cmd)
	if err != nil {
		return nil, fmt.Errorf("command failed: %v", err)
	}
	if bytes.HasPrefix(resp, []byte{0x70}) {
		b, _, err := unmarshalASN1(resp, 0, 0x10) // tag 0x70
		if err != nil {
			return nil, fmt.Errorf("unmarshaling certificate: %v", err)
		}
		resp = b
	}
	cert, err := x509.ParseCertificate(resp)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %v", err)
	}
	return cert, nil
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
func (yk *YubiKey) SetCertificate(key [24]byte, slot Slot, cert *x509.Certificate) error {
	tx, err := yk.begin()
	if err != nil {
		return err
	}
	defer tx.Close()
	if err := ykAuthenticate(tx, key, yk.rand); err != nil {
		return fmt.Errorf("authenticating with management key: %v", err)
	}
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
func (yk *YubiKey) GenerateKey(key [24]byte, slot Slot, opts Key) (crypto.PublicKey, error) {
	tx, err := yk.begin()
	if err != nil {
		return nil, err
	}
	defer tx.Close()
	if err := ykAuthenticate(tx, key, yk.rand); err != nil {
		return nil, fmt.Errorf("authenticating with management key: %v", err)
	}
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

// KeyAuth is used to authenticate against the YubiKey on each signing  and
// decryption request.
type KeyAuth struct {
	// PIN, if provided, is a static PIN used to authenticate against the key.
	// If provided, PINPrompt is ignored.
	PIN string
	// PINPrompt should be used to interactively request the PIN from the user.
	PINPrompt func() (pin string, err error)
}

func (k KeyAuth) begin(yk *YubiKey) (tx *scTx, err error) {
	tx, err = yk.begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			tx.Close()
		}
	}()

	// TODO(ericchiang): support cached pin and touch policies, possibly by
	// attempting to sign, then prompting on specific apdu error codes.
	if k.PIN != "" {
		if err := ykLogin(tx, k.PIN); err != nil {
			return nil, fmt.Errorf("authenticating with pin: %v", err)
		}
	} else if k.PINPrompt != nil {
		pin, err := k.PINPrompt()
		if err != nil {
			return nil, fmt.Errorf("pin prompt: %v", err)
		}
		if err := ykLogin(tx, pin); err != nil {
			return nil, fmt.Errorf("authenticating with pin: %v", err)
		}
	}
	return tx, nil
}

// PrivateKey is used to access signing and decryption options for the key
// stored in the slot. The returned key implements crypto.Signer and/or
// crypto.Decrypter depending on the key type.
//
// If the public key hasn't been stored externally, it can be provided by
// fetching the slot's attestation certificate:
//
//		cert, err := yk.Attest(slot)
//		if err != nil {
//			// ...
//		}
//		priv, err := yk.PrivateKey(slot, cert.PublicKey, auth)
//
func (yk *YubiKey) PrivateKey(slot Slot, public crypto.PublicKey, auth KeyAuth) (crypto.PrivateKey, error) {
	switch pub := public.(type) {
	case *ecdsa.PublicKey:
		return &keyECDSA{yk, slot, pub, auth}, nil
	case *rsa.PublicKey:
		return &keyRSA{yk, slot, pub, auth}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", public)
	}
}

type keyECDSA struct {
	yk   *YubiKey
	slot Slot
	pub  *ecdsa.PublicKey
	auth KeyAuth
}

func (k *keyECDSA) Public() crypto.PublicKey {
	return k.pub
}

func (k *keyECDSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	tx, err := k.auth.begin(k.yk)
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
	auth KeyAuth
}

func (k *keyRSA) Public() crypto.PublicKey {
	return k.pub
}

func (k *keyRSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	tx, err := k.auth.begin(k.yk)
	if err != nil {
		return nil, err
	}
	defer tx.Close()
	return ykSignRSA(tx, k.slot, k.pub, digest, opts)
}

func (k *keyRSA) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	tx, err := k.auth.begin(k.yk)
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
