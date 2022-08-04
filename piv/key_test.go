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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestYubiKeySignECDSA(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	if err := yk.Reset(); err != nil {
		t.Fatalf("reset yubikey: %v", err)
	}

	slot := SlotAuthentication

	key := Key{
		Algorithm:   AlgorithmEC256,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pubKey, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not an ecdsa key")
	}
	data := sha256.Sum256([]byte("hello"))
	priv, err := yk.PrivateKey(slot, pub, KeyAuth{})
	if err != nil {
		t.Fatalf("getting private key: %v", err)
	}
	s, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("expected private key to implement crypto.Signer")
	}
	out, err := s.Sign(rand.Reader, data[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(out, &sig); err != nil {
		t.Fatalf("unmarshaling signature: %v", err)
	}
	if !ecdsa.Verify(pub, data[:], sig.R, sig.S) {
		t.Errorf("signature didn't match")
	}
}

func TestYubiKeyECDSASharedKey(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	slot := SlotAuthentication

	key := Key{
		Algorithm:   AlgorithmEC256,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pubKey, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not an ecdsa key")
	}
	priv, err := yk.PrivateKey(slot, pub, KeyAuth{})
	if err != nil {
		t.Fatalf("getting private key: %v", err)
	}
	privECDSA, ok := priv.(*ECDSAPrivateKey)
	if !ok {
		t.Fatalf("expected private key to be ECDSA private key")
	}

	t.Run("good", func(t *testing.T) {
		eph, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("cannot generate key: %v", err)
		}
		mult, _ := pub.ScalarMult(pub.X, pub.Y, eph.D.Bytes())
		secret1 := mult.Bytes()

		secret2, err := privECDSA.SharedKey(&eph.PublicKey)
		if err != nil {
			t.Fatalf("key agreement failed: %v", err)
		}
		if !bytes.Equal(secret1, secret2) {
			t.Errorf("key agreement didn't match")
		}
	})

	t.Run("bad", func(t *testing.T) {
		t.Run("size", func(t *testing.T) {
			eph, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatalf("cannot generate key: %v", err)
			}
			_, err = privECDSA.SharedKey(&eph.PublicKey)
			if !errors.Is(err, errMismatchingAlgorithms) {
				t.Fatalf("unexpected error value: wanted errMismatchingAlgorithms: %v", err)
			}
		})
	})
}

func TestPINPrompt(t *testing.T) {
	tests := []struct {
		name   string
		policy PINPolicy
		want   int
	}{
		{"Never", PINPolicyNever, 0},
		{"Once", PINPolicyOnce, 1},
		{"Always", PINPolicyAlways, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			yk, close := newTestYubiKey(t)
			defer close()

			k := Key{
				Algorithm:   AlgorithmEC256,
				PINPolicy:   test.policy,
				TouchPolicy: TouchPolicyNever,
			}
			pub, err := yk.GenerateKey(DefaultManagementKey, SlotAuthentication, k)
			if err != nil {
				t.Fatalf("generating key on slot: %v", err)
			}
			got := 0
			auth := KeyAuth{
				PINPrompt: func() (string, error) {
					got++
					return DefaultPIN, nil
				},
			}

			if !supportsAttestation(yk) {
				auth.PINPolicy = test.policy
			}

			priv, err := yk.PrivateKey(SlotAuthentication, pub, auth)
			if err != nil {
				t.Fatalf("building private key: %v", err)
			}
			s, ok := priv.(crypto.Signer)
			if !ok {
				t.Fatalf("expected crypto.Signer got %T", priv)
			}
			data := sha256.Sum256([]byte("foo"))
			if _, err := s.Sign(rand.Reader, data[:], crypto.SHA256); err != nil {
				t.Errorf("signing error: %v", err)
			}
			if _, err := s.Sign(rand.Reader, data[:], crypto.SHA256); err != nil {
				t.Errorf("signing error: %v", err)
			}
			if got != test.want {
				t.Errorf("PINPrompt called %d times, want=%d", got, test.want)
			}
		})
	}
}

func supportsAttestation(yk *YubiKey) bool {
	return supportsVersion(yk.Version(), 4, 3, 0)
}

func TestSlots(t *testing.T) {
	yk, close := newTestYubiKey(t)
	if err := yk.Reset(); err != nil {
		t.Fatalf("resetting yubikey: %v", err)
	}
	close()

	tests := []struct {
		name string
		slot Slot
	}{
		{"Authentication", SlotAuthentication},
		{"CardAuthentication", SlotCardAuthentication},
		{"KeyManagement", SlotKeyManagement},
		{"Signature", SlotSignature},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			yk, close := newTestYubiKey(t)
			defer close()

			if supportsAttestation(yk) {
				if _, err := yk.Attest(test.slot); err == nil || !errors.Is(err, ErrNotFound) {
					t.Errorf("attest: got err=%v, want=ErrNotFound", err)
				}
			}

			k := Key{
				Algorithm:   AlgorithmEC256,
				PINPolicy:   PINPolicyNever,
				TouchPolicy: TouchPolicyNever,
			}
			pub, err := yk.GenerateKey(DefaultManagementKey, test.slot, k)
			if err != nil {
				t.Fatalf("generating key on slot: %v", err)
			}

			if supportsAttestation(yk) {
				if _, err := yk.Attest(test.slot); err != nil {
					t.Errorf("attest: %v", err)
				}
			}

			priv, err := yk.PrivateKey(test.slot, pub, KeyAuth{PIN: DefaultPIN})
			if err != nil {
				t.Fatalf("private key: %v", err)
			}

			tmpl := &x509.Certificate{
				Subject:      pkix.Name{CommonName: "my-client"},
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(time.Hour),
				KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
			if err != nil {
				t.Fatalf("signing self-signed certificate: %v", err)
			}
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				t.Fatalf("parse certificate: %v", err)
			}

			if _, err := yk.Certificate(test.slot); err == nil || !errors.Is(err, ErrNotFound) {
				t.Errorf("get certificate, got err=%v, want=ErrNotFound", err)
			}
			if err := yk.SetCertificate(DefaultManagementKey, test.slot, cert); err != nil {
				t.Fatalf("set certificate: %v", err)
			}
			got, err := yk.Certificate(test.slot)
			if err != nil {
				t.Fatalf("get certifiate: %v", err)
			}
			if !bytes.Equal(got.Raw, raw) {
				t.Errorf("certificate from slot didn't match the certificate written")
			}
		})
	}
}

func TestYubiKeySignRSA(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		long bool
	}{
		{"rsa1024", AlgorithmRSA1024, false},
		{"rsa2048", AlgorithmRSA2048, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.long && testing.Short() {
				t.Skip("skipping test in short mode")
			}
			yk, close := newTestYubiKey(t)
			defer close()
			slot := SlotAuthentication
			key := Key{
				Algorithm:   test.alg,
				TouchPolicy: TouchPolicyNever,
				PINPolicy:   PINPolicyNever,
			}
			pubKey, err := yk.GenerateKey(DefaultManagementKey, slot, key)
			if err != nil {
				t.Fatalf("generating key: %v", err)
			}
			pub, ok := pubKey.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("public key is not an rsa key")
			}
			data := sha256.Sum256([]byte("hello"))
			priv, err := yk.PrivateKey(slot, pub, KeyAuth{})
			if err != nil {
				t.Fatalf("getting private key: %v", err)
			}
			s, ok := priv.(crypto.Signer)
			if !ok {
				t.Fatalf("private key didn't implement crypto.Signer")
			}
			out, err := s.Sign(rand.Reader, data[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, data[:], out); err != nil {
				t.Errorf("failed to verify signature: %v", err)
			}
		})
	}
}

func TestYubiKeyDecryptRSA(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		long bool
	}{
		{"rsa1024", AlgorithmRSA1024, false},
		{"rsa2048", AlgorithmRSA2048, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.long && testing.Short() {
				t.Skip("skipping test in short mode")
			}
			yk, close := newTestYubiKey(t)
			defer close()
			slot := SlotAuthentication
			key := Key{
				Algorithm:   test.alg,
				TouchPolicy: TouchPolicyNever,
				PINPolicy:   PINPolicyNever,
			}
			pubKey, err := yk.GenerateKey(DefaultManagementKey, slot, key)
			if err != nil {
				t.Fatalf("generating key: %v", err)
			}
			pub, ok := pubKey.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("public key is not an rsa key")
			}

			data := []byte("hello")
			ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			priv, err := yk.PrivateKey(slot, pub, KeyAuth{})
			if err != nil {
				t.Fatalf("getting private key: %v", err)
			}
			d, ok := priv.(crypto.Decrypter)
			if !ok {
				t.Fatalf("private key didn't implement crypto.Decypter")
			}
			got, err := d.Decrypt(rand.Reader, ct, nil)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}
			if !bytes.Equal(data, got) {
				t.Errorf("decrypt, got=%q, want=%q", got, data)
			}
		})
	}
}

func TestYubiKeyAttestation(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()
	key := Key{
		Algorithm:   AlgorithmEC256,
		PINPolicy:   PINPolicyNever,
		TouchPolicy: TouchPolicyNever,
	}

	testRequiresVersion(t, yk, 4, 3, 0)

	cert, err := yk.AttestationCertificate()
	if err != nil {
		t.Fatalf("getting attestation certificate: %v", err)
	}

	pub, err := yk.GenerateKey(DefaultManagementKey, SlotAuthentication, key)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_ = pub
	c, err := yk.Attest(SlotAuthentication)
	if err != nil {
		t.Fatalf("attesting key: %v", err)
	}
	a, err := Verify(cert, c)
	if err != nil {
		t.Fatalf("failed to verify attestation: %v", err)
	}
	serial, err := yk.Serial()
	if err != nil {
		t.Errorf("getting serial number: %v", err)
	} else if a.Serial != serial {
		t.Errorf("attestation serial got=%d, wanted=%d", a.Serial, serial)
	}

	if a.PINPolicy != key.PINPolicy {
		t.Errorf("attestation pin policy got=0x%x, wanted=0x%x", a.TouchPolicy, key.PINPolicy)
	}
	if a.TouchPolicy != key.TouchPolicy {
		t.Errorf("attestation touch policy got=0x%x, wanted=0x%x", a.TouchPolicy, key.TouchPolicy)
	}
	if a.Version != yk.Version() {
		t.Errorf("attestation version got=%#v, wanted=%#v", a.Version, yk.Version())
	}
	if a.Slot != SlotAuthentication {
		t.Errorf("attested slot got=%v, wanted=%v", a.Slot, SlotAuthentication)
	}
	if a.Slot.String() != "9a" {
		t.Errorf("attested slot name got=%s, wanted=%s", a.Slot.String(), "9a")
	}
}

func TestYubiKeyStoreCertificate(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()
	slot := SlotAuthentication

	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ca private: %v", err)
	}
	// Generate a self-signed certificate
	caTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "my-ca"},
		SerialNumber:          big.NewInt(100),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPriv.Public(), caPriv)
	if err != nil {
		t.Fatalf("generating self-signed certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parsing ca cert: %v", err)
	}

	key := Key{
		Algorithm:   AlgorithmEC256,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pub, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	cliTmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "my-client"},
		SerialNumber: big.NewInt(101),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliCertDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, pub, caPriv)
	if err != nil {
		t.Fatalf("creating client cert: %v", err)
	}
	cliCert, err := x509.ParseCertificate(cliCertDER)
	if err != nil {
		t.Fatalf("parsing cli cert: %v", err)
	}
	if err := yk.SetCertificate(DefaultManagementKey, slot, cliCert); err != nil {
		t.Fatalf("storing client cert: %v", err)
	}
	gotCert, err := yk.Certificate(slot)
	if err != nil {
		t.Fatalf("getting client cert: %v", err)
	}
	if !bytes.Equal(gotCert.Raw, cliCert.Raw) {
		t.Errorf("stored cert didn't match cert retrieved")
	}
}

func TestYubiKeyGenerateKey(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		bits int
		long bool // Does the key generation take a long time?
	}{
		{
			name: "ec_256",
			alg:  AlgorithmEC256,
		},
		{
			name: "ec_384",
			alg:  AlgorithmEC384,
		},
		{
			name: "rsa_1024",
			alg:  AlgorithmRSA1024,
		},
		{
			name: "rsa_2048",
			alg:  AlgorithmRSA2048,
			long: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.long && testing.Short() {
				t.Skip("skipping test in short mode")
			}
			yk, close := newTestYubiKey(t)
			defer close()
			if test.alg == AlgorithmEC384 {
				testRequiresVersion(t, yk, 4, 3, 0)
			}

			key := Key{
				Algorithm:   test.alg,
				TouchPolicy: TouchPolicyNever,
				PINPolicy:   PINPolicyNever,
			}
			if _, err := yk.GenerateKey(DefaultManagementKey, SlotAuthentication, key); err != nil {
				t.Errorf("generating key: %v", err)
			}
		})
	}
}

func TestYubiKeyPrivateKey(t *testing.T) {
	alg := AlgorithmEC256
	slot := SlotAuthentication

	yk, close := newTestYubiKey(t)
	defer close()

	key := Key{
		Algorithm:   alg,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyNever,
	}
	pub, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not an *ecdsa.PublicKey: %T", pub)
	}

	auth := KeyAuth{PIN: DefaultPIN}
	priv, err := yk.PrivateKey(slot, pub, auth)
	if err != nil {
		t.Fatalf("getting private key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("private key doesn't implement crypto.Signer")
	}

	b := sha256.Sum256([]byte("hello"))
	hash := b[:]
	sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	var ecdsaSignature struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &ecdsaSignature); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !ecdsa.Verify(ecdsaPub, hash, ecdsaSignature.R, ecdsaSignature.S) {
		t.Fatalf("signature validation failed")
	}
}

func TestYubiKeyPrivateKeyPINError(t *testing.T) {
	alg := AlgorithmEC256
	slot := SlotAuthentication

	yk, close := newTestYubiKey(t)
	defer close()

	key := Key{
		Algorithm:   alg,
		TouchPolicy: TouchPolicyNever,
		PINPolicy:   PINPolicyAlways,
	}
	pub, err := yk.GenerateKey(DefaultManagementKey, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	auth := KeyAuth{
		PINPrompt: func() (string, error) {
			return "", errors.New("test error")
		},
	}

	priv, err := yk.PrivateKey(slot, pub, auth)
	if err != nil {
		t.Fatalf("getting private key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("private key doesn't implement crypto.Signer")
	}

	b := sha256.Sum256([]byte("hello"))
	hash := b[:]
	if _, err := signer.Sign(rand.Reader, hash, crypto.SHA256); err == nil {
		t.Errorf("expected sign to fail with pin prompt that returned error")
	}
}

func TestRetiredKeyManagementSlot(t *testing.T) {
	tests := []struct {
		name     string
		key      uint32
		wantSlot Slot
		wantOk   bool
	}{
		{
			name:     "Non-existent slot, before range",
			key:      0x0,
			wantSlot: Slot{},
			wantOk:   false,
		},
		{
			name:     "Non-existent slot, after range",
			key:      0x96,
			wantSlot: Slot{},
			wantOk:   false,
		},
		{
			name:     "First retired slot key",
			key:      0x82,
			wantSlot: Slot{0x82, 0x5fc10d},
			wantOk:   true,
		},
		{
			name:     "Last retired slot key",
			key:      0x95,
			wantSlot: Slot{0x95, 0x5fc120},
			wantOk:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSlot, gotOk := RetiredKeyManagementSlot(tt.key)
			if gotSlot != tt.wantSlot {
				t.Errorf("RetiredKeyManagementSlot() got = %v, want %v", gotSlot, tt.wantSlot)
			}
			if gotOk != tt.wantOk {
				t.Errorf("RetiredKeyManagementSlot() got1 = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}

func TestSetRSAPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		slot    Slot
		wantErr error
	}{

		{
			name:    "rsa 1024",
			bits:    1024,
			slot:    SlotSignature,
			wantErr: nil,
		},
		{
			name:    "rsa 2048",
			bits:    2048,
			slot:    SlotCardAuthentication,
			wantErr: nil,
		},
		{
			name:    "rsa 4096",
			bits:    4096,
			slot:    SlotAuthentication,
			wantErr: errUnsupportedKeySize,
		},
		{
			name:    "rsa 512",
			bits:    512,
			slot:    SlotKeyManagement,
			wantErr: errUnsupportedKeySize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yk, close := newTestYubiKey(t)
			defer close()

			generated, err := rsa.GenerateKey(rand.Reader, tt.bits)
			if err != nil {
				t.Fatalf("generating private key: %v", err)
			}

			err = yk.SetPrivateKeyInsecure(DefaultManagementKey, tt.slot, generated, Key{
				PINPolicy:   PINPolicyNever,
				TouchPolicy: TouchPolicyNever,
			})
			if err != tt.wantErr {
				t.Fatalf("SetPrivateKeyInsecure(): wantErr=%v, got err=%v", tt.wantErr, err)
			}
			if err != nil {
				return
			}

			priv, err := yk.PrivateKey(tt.slot, &generated.PublicKey, KeyAuth{})
			if err != nil {
				t.Fatalf("getting private key: %v", err)
			}

			data := []byte("Test data that we will encrypt")

			// Encrypt the data using our generated key
			encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &generated.PublicKey, data)
			if err != nil {
				t.Fatalf("encrypting data: %v", err)
			}

			deviceDecrypter := priv.(crypto.Decrypter)

			// Decrypt the data on the device
			decrypted, err := deviceDecrypter.Decrypt(rand.Reader, encrypted, nil)
			if err != nil {
				t.Fatalf("decrypting data: %v", err)
			}

			if !bytes.Equal(data, decrypted) {
				t.Fatalf("decrypted data is different to the source data")
			}
		})
	}
}

func TestSetECDSAPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		curve   elliptic.Curve
		slot    Slot
		wantErr error
	}{
		{
			name:    "ecdsa P256",
			curve:   elliptic.P256(),
			slot:    SlotSignature,
			wantErr: nil,
		},
		{
			name:    "ecdsa P384",
			curve:   elliptic.P384(),
			slot:    SlotCardAuthentication,
			wantErr: nil,
		},
		{
			name:    "ecdsa P224",
			curve:   elliptic.P224(),
			slot:    SlotAuthentication,
			wantErr: unsupportedCurveError{curve: 224},
		},
		{
			name:    "ecdsa P521",
			curve:   elliptic.P521(),
			slot:    SlotKeyManagement,
			wantErr: unsupportedCurveError{curve: 521},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yk, close := newTestYubiKey(t)
			defer close()

			generated, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generating private key: %v", err)
			}

			err = yk.SetPrivateKeyInsecure(DefaultManagementKey, tt.slot, generated, Key{
				PINPolicy:   PINPolicyNever,
				TouchPolicy: TouchPolicyNever,
			})
			if err != tt.wantErr {
				t.Fatalf("SetPrivateKeyInsecure(): wantErr=%v, got err=%v", tt.wantErr, err)
			}
			if err != nil {
				return
			}

			priv, err := yk.PrivateKey(tt.slot, &generated.PublicKey, KeyAuth{})
			if err != nil {
				t.Fatalf("getting private key: %v", err)
			}

			deviceSigner := priv.(crypto.Signer)

			hash := []byte("Test data to sign")
			// Sign the data on the device
			sig, err := deviceSigner.Sign(rand.Reader, hash, nil)
			if err != nil {
				t.Fatalf("signing data: %v", err)
			}

			// Verify the signature using the generated key
			if !ecdsa.VerifyASN1(&generated.PublicKey, hash, sig) {
				t.Fatal("Failed to verify signed data")
			}
		})
	}
}

func TestParseSlot(t *testing.T) {
	tests := []struct {
		name string
		cn   string
		ok   bool
		slot Slot
	}{
		{
			name: "Missing Yubico PIV Prefix",
			cn:   "invalid",
			ok:   false,
			slot: Slot{},
		},
		{
			name: "Invalid Slot Name",
			cn:   yubikeySubjectCNPrefix + "xy",
			ok:   false,
			slot: Slot{},
		},
		{
			name: "Valid -- SlotAuthentication",
			cn:   yubikeySubjectCNPrefix + "9a",
			ok:   true,
			slot: SlotAuthentication,
		},
		{
			name: "Valid -- Retired Management Key",
			cn:   yubikeySubjectCNPrefix + "89",
			ok:   true,
			slot: retiredKeyManagementSlots[uint32(137)],
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			slot, ok := parseSlot(test.cn)

			if ok != test.ok {
				t.Errorf("ok status returned %v, expected %v", ok, test.ok)
			}

			if slot != test.slot {
				t.Errorf("returned slot %+v did not match expected %+v", slot, test.slot)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name       string
		deviceCert string
		keyCert    string
		ok         bool
	}{
		{
			// Valid attestation chain from a recent YubiKey.
			name:       "ValidChain",
			deviceCert: "-----BEGIN CERTIFICATE-----\nMIIC+jCCAeKgAwIBAgIJAKs/UIpBjg1uMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV\nBAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw\nMDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0\ndGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0zdJWGnk\naLE8Rb+TP7iSffhJV9SJEp2Me4QcfVidgHqyIdo0lruBk69RF1nrmS3i+G1yyUh/\nymAPZkcQCpms0E23Dmhue1VRpBedcsVtO/xSrfu0qAWTslp/k57ry6vkidrQU1cx\nl2KodH3KTmnZmaskQD8eGtxXwcmLOmhKem6GSqhN/3QznaDhZmVUAvUKSOaIzOxn\n2u1mDHhGwaHhR7dklsDwN7oni4WWX1GJXtzpB8j6JhoqyqXwSbq+ck54PfzUoOFd\n/2yKyFRDXnQvzbNL7+afbxBQQMxxo1e24DNE/cp+K09eT7Gh1Urao6meaSssN4aV\nFfmkhC2NapGKMQIDAQABoykwJzARBgorBgEEAYLECgMDBAMFBAMwEgYDVR0TAQH/\nBAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAJfOLOQYGyIMQ5y+sDkYz+e6G\nH8BqqiYL9VOC3U3KQX9mrtZnaIexqJOCQyCFOSvaTFJvOfNiCCKQuLbmS+Qn4znd\nnSitCsdJSFKskQP7hbXqUK01epb6iTuuko4w3V57YVudnniZBD2s4XoNcJ6BFizZ\n3iXQqRMaLVfFHS9Qx0iLZLcR2s29nIl6NI/qFdIgkyo07J5cPnBiD6wxQft8FdfR\nbgx9yrrjY0mvj/k5LRN6lab8lTolgI5luJtKNueq96LVkTkAzcCaJPQ9YQ4cxeU9\nOapsEeOk6xf5bRPtdf0WhEKthXywt9D0pSHhAI+fpLNe/VtlZpt3hn9aTbqSug==\n-----END CERTIFICATE-----\n",
			keyCert:    "-----BEGIN CERTIFICATE-----\nMIICVTCCAT2gAwIBAgIQAU4Yg7Qnw9FZgMBEaJ7ZMzANBgkqhkiG9w0BAQsFADAh\nMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw\nMFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl\nc3RhdGlvbiA5YTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABATzM3sJuwemL2Ha\nHkGIzmCVjUMreNIVrRLOvnbZjoVflk1eab/iLUlKzk/2jXTu9TISRg2dhyXcutct\nvnqr66yjTjBMMBEGCisGAQQBgsQKAwMEAwUEAzAUBgorBgEEAYLECgMHBAYCBADw\nDxQwEAYKKwYBBAGCxAoDCAQCAgEwDwYKKwYBBAGCxAoDCQQBBDANBgkqhkiG9w0B\nAQsFAAOCAQEAFX0hL5gi/g4ZM7vCH5kDAtma7eBp0LpbCzR313GGyBR7pJFtuj2l\nbWU+V3SFRihXBTDb8q+uvyCBqgz1szdZzrpfjqNkhEPfPNabxjxJxVoe6Gdcn115\naduxfqqT2u+YIsERzaIIIisehLQkc/5zLkpocA6jbKBZnZWUBJIxuz4QmYTIf0O4\nHPE2o4JbAyGx/hRaqVvDgNeAz94ZFjb4Mp3RNbbdRUZB0ehrT/IGRJoHRu2HKFGM\nylRJL2kjKPoEc4XHbCu+MfmAIrQ4Xseg85zyI7ThhYvAzktdLHhQyfYr4wrrLCN3\noeTzmiqIHe9AataJXQ+mEQEEc9TNY23RFg==\n-----END CERTIFICATE-----\n",
			ok:         true,
		},
		{
			// Valid attestation chain from a yubikey manufactured in 2018 showing a manufacture bug (device certified using U2F root, and device cert does not encode X509 basic constraints).
			name:       "ValidChain2018",
			deviceCert: "-----BEGIN CERTIFICATE-----\nMIIC6TCCAdGgAwIBAgIJALvwZFDESwMlMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNV\nBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgw\nMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElW\nIEF0dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXnZ\n+lxX0nNzy3jn+lrZ+1cHTVUNYVKPqGTjvRw/7XOEnInWC1VCPJqwHYtnnoH4EIXN\n7kDGXwInfs9pwyjpgQw/V23yywFtUhaR8Xgw8zqC/YfJpeK4PetJ9/k+xFbICuX7\nWDv/k5Wth3VZSaVjm/tunWajtt3OLOQQaMSoLqP41XAHHuCyzfCwJ2Vsa2FyCINF\nyG6XobokeICDRnH44POqudcLVIDvZLQqu2LF+mZd+OO5nqmTa68kkwRf/m93eOJP\no7GvYtQSp7CPJC7ks2gl8U7wuT9DQT5/0wqkoEyLZg/KLUlzgXjMa+7GtCLTC1Ku\nOh9vw02f4K44RW4nWwIDAQABoxUwEzARBgorBgEEAYLECgMDBAMEAwcwDQYJKoZI\nhvcNAQELBQADggEBAHD/uXqNgCYywj2ee7s7kix2TT4XN9OIn0fTNh5LEiUN+q7U\nzJc9q7b5WD7PfaG6UNyuaSnLaq+dLOCJ4bX4h+/MwQSndQg0epMra1ThVQZkMkGa\nktAJ5JT6j9qxNxD1RWMl91e4JwtGzFyDwFyyUGnSwhMsqMdwfBsmTpvgxmAD/NMs\nkWB/m91FV9D+UBqsZRoLoc44kEFYBZ09ypTsR699oJRsBfG0AqVYyK7rnG6663fF\nGUSWk7noVdUPXedlwXCqCymCsVheoss9qF1cffaFIl9RxGvVvCFybx0LGiYDxfgv\n80yGZIY/mAqZVDWyHZSs4f6kWK9GeLKU2Y9yby4=\n-----END CERTIFICATE-----\n",
			keyCert:    "-----BEGIN CERTIFICATE-----\nMIICLzCCARegAwIBAgIRAIxiihk4fSKK6keqJYujvnkwDQYJKoZIhvcNAQELBQAw\nITEfMB0GA1UEAwwWWXViaWNvIFBJViBBdHRlc3RhdGlvbjAgFw0xNDA4MDEwMDAw\nMDBaGA8yMDUwMDkwNDAwMDAwMFowJTEjMCEGA1UEAwwaWXViaUtleSBQSVYgQXR0\nZXN0YXRpb24gOWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATHEzJsrhTHuvsx\n685AiWsAuT8Poe/zQfDRZNfpUSzJ31v6MZ9nz70pNrdd/sbG7O1UA6ceWhq1jHTU\n96Dnp99voycwJTARBgorBgEEAYLECgMDBAMEAwcwEAYKKwYBBAGCxAoDCAQCAgEw\nDQYJKoZIhvcNAQELBQADggEBADoswZ1LJ5GYVNgtRE0+zMQkAzam8YqeKmIDHtir\nvolIpGtJHzgCG2SdJlR/KnjRWF/1i8TRMhQ0O/KgkIEh+IyhJtD7DojgWvIBsCnX\nJXF7EPQMy17l7/9940QSOnQRIDb+z0eq9ACAjC3FWzqeR5VgN4C1QpCw7gKgqLTs\npmmDHHg4HsKl0PsPwim0bYIqEHttrLjPQiPnoa3qixzNKbwJjXb4/f/dvCTx9dRP\n0FVABj5Yh8f728xzrzw2nLZ9X/c0GoXfKu9s7lGNLcZ5OO+zys1ATei2h/PFJLDH\nAdrenw31WOYRtdjcNBKyAk80ajryjTAX3GXfbKpkdVB9hEo=\n-----END CERTIFICATE-----\n",
			ok:         true,
		},
		{
			// Invalid attestation chain. Device cert from yubikey A, key cert from yubikey B.
			name:       "InvalidChain",
			deviceCert: "-----BEGIN CERTIFICATE-----\nMIIC+jCCAeKgAwIBAgIJAKs/UIpBjg1uMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNV\nBAMMIFl1YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAw\nMDAwMFoYDzIwNTIwNDE3MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0\ndGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0zdJWGnk\naLE8Rb+TP7iSffhJV9SJEp2Me4QcfVidgHqyIdo0lruBk69RF1nrmS3i+G1yyUh/\nymAPZkcQCpms0E23Dmhue1VRpBedcsVtO/xSrfu0qAWTslp/k57ry6vkidrQU1cx\nl2KodH3KTmnZmaskQD8eGtxXwcmLOmhKem6GSqhN/3QznaDhZmVUAvUKSOaIzOxn\n2u1mDHhGwaHhR7dklsDwN7oni4WWX1GJXtzpB8j6JhoqyqXwSbq+ck54PfzUoOFd\n/2yKyFRDXnQvzbNL7+afbxBQQMxxo1e24DNE/cp+K09eT7Gh1Urao6meaSssN4aV\nFfmkhC2NapGKMQIDAQABoykwJzARBgorBgEEAYLECgMDBAMFBAMwEgYDVR0TAQH/\nBAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAQEAJfOLOQYGyIMQ5y+sDkYz+e6G\nH8BqqiYL9VOC3U3KQX9mrtZnaIexqJOCQyCFOSvaTFJvOfNiCCKQuLbmS+Qn4znd\nnSitCsdJSFKskQP7hbXqUK01epb6iTuuko4w3V57YVudnniZBD2s4XoNcJ6BFizZ\n3iXQqRMaLVfFHS9Qx0iLZLcR2s29nIl6NI/qFdIgkyo07J5cPnBiD6wxQft8FdfR\nbgx9yrrjY0mvj/k5LRN6lab8lTolgI5luJtKNueq96LVkTkAzcCaJPQ9YQ4cxeU9\nOapsEeOk6xf5bRPtdf0WhEKthXywt9D0pSHhAI+fpLNe/VtlZpt3hn9aTbqSug==\n-----END CERTIFICATE-----\n",
			keyCert:    "-----BEGIN CERTIFICATE-----\nMIICLzCCARegAwIBAgIRAIxiihk4fSKK6keqJYujvnkwDQYJKoZIhvcNAQELBQAw\nITEfMB0GA1UEAwwWWXViaWNvIFBJViBBdHRlc3RhdGlvbjAgFw0xNDA4MDEwMDAw\nMDBaGA8yMDUwMDkwNDAwMDAwMFowJTEjMCEGA1UEAwwaWXViaUtleSBQSVYgQXR0\nZXN0YXRpb24gOWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATHEzJsrhTHuvsx\n685AiWsAuT8Poe/zQfDRZNfpUSzJ31v6MZ9nz70pNrdd/sbG7O1UA6ceWhq1jHTU\n96Dnp99voycwJTARBgorBgEEAYLECgMDBAMEAwcwEAYKKwYBBAGCxAoDCAQCAgEw\nDQYJKoZIhvcNAQELBQADggEBADoswZ1LJ5GYVNgtRE0+zMQkAzam8YqeKmIDHtir\nvolIpGtJHzgCG2SdJlR/KnjRWF/1i8TRMhQ0O/KgkIEh+IyhJtD7DojgWvIBsCnX\nJXF7EPQMy17l7/9940QSOnQRIDb+z0eq9ACAjC3FWzqeR5VgN4C1QpCw7gKgqLTs\npmmDHHg4HsKl0PsPwim0bYIqEHttrLjPQiPnoa3qixzNKbwJjXb4/f/dvCTx9dRP\n0FVABj5Yh8f728xzrzw2nLZ9X/c0GoXfKu9s7lGNLcZ5OO+zys1ATei2h/PFJLDH\nAdrenw31WOYRtdjcNBKyAk80ajryjTAX3GXfbKpkdVB9hEo=\n-----END CERTIFICATE-----\n",
			ok:         false,
		},
		{
			// Invalid attestation chain. Device cert from yubikey B, key cert from yubikey A.
			name:       "InvalidChain2",
			deviceCert: "-----BEGIN CERTIFICATE-----\nMIIC6TCCAdGgAwIBAgIJALvwZFDESwMlMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNV\nBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgw\nMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAhMR8wHQYDVQQDDBZZdWJpY28gUElW\nIEF0dGVzdGF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXnZ\n+lxX0nNzy3jn+lrZ+1cHTVUNYVKPqGTjvRw/7XOEnInWC1VCPJqwHYtnnoH4EIXN\n7kDGXwInfs9pwyjpgQw/V23yywFtUhaR8Xgw8zqC/YfJpeK4PetJ9/k+xFbICuX7\nWDv/k5Wth3VZSaVjm/tunWajtt3OLOQQaMSoLqP41XAHHuCyzfCwJ2Vsa2FyCINF\nyG6XobokeICDRnH44POqudcLVIDvZLQqu2LF+mZd+OO5nqmTa68kkwRf/m93eOJP\no7GvYtQSp7CPJC7ks2gl8U7wuT9DQT5/0wqkoEyLZg/KLUlzgXjMa+7GtCLTC1Ku\nOh9vw02f4K44RW4nWwIDAQABoxUwEzARBgorBgEEAYLECgMDBAMEAwcwDQYJKoZI\nhvcNAQELBQADggEBAHD/uXqNgCYywj2ee7s7kix2TT4XN9OIn0fTNh5LEiUN+q7U\nzJc9q7b5WD7PfaG6UNyuaSnLaq+dLOCJ4bX4h+/MwQSndQg0epMra1ThVQZkMkGa\nktAJ5JT6j9qxNxD1RWMl91e4JwtGzFyDwFyyUGnSwhMsqMdwfBsmTpvgxmAD/NMs\nkWB/m91FV9D+UBqsZRoLoc44kEFYBZ09ypTsR699oJRsBfG0AqVYyK7rnG6663fF\nGUSWk7noVdUPXedlwXCqCymCsVheoss9qF1cffaFIl9RxGvVvCFybx0LGiYDxfgv\n80yGZIY/mAqZVDWyHZSs4f6kWK9GeLKU2Y9yby4=\n-----END CERTIFICATE-----\n",
			keyCert:    "-----BEGIN CERTIFICATE-----\nMIICVTCCAT2gAwIBAgIQAU4Yg7Qnw9FZgMBEaJ7ZMzANBgkqhkiG9w0BAQsFADAh\nMR8wHQYDVQQDDBZZdWJpY28gUElWIEF0dGVzdGF0aW9uMCAXDTE2MDMxNDAwMDAw\nMFoYDzIwNTIwNDE3MDAwMDAwWjAlMSMwIQYDVQQDDBpZdWJpS2V5IFBJViBBdHRl\nc3RhdGlvbiA5YTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABATzM3sJuwemL2Ha\nHkGIzmCVjUMreNIVrRLOvnbZjoVflk1eab/iLUlKzk/2jXTu9TISRg2dhyXcutct\nvnqr66yjTjBMMBEGCisGAQQBgsQKAwMEAwUEAzAUBgorBgEEAYLECgMHBAYCBADw\nDxQwEAYKKwYBBAGCxAoDCAQCAgEwDwYKKwYBBAGCxAoDCQQBBDANBgkqhkiG9w0B\nAQsFAAOCAQEAFX0hL5gi/g4ZM7vCH5kDAtma7eBp0LpbCzR313GGyBR7pJFtuj2l\nbWU+V3SFRihXBTDb8q+uvyCBqgz1szdZzrpfjqNkhEPfPNabxjxJxVoe6Gdcn115\naduxfqqT2u+YIsERzaIIIisehLQkc/5zLkpocA6jbKBZnZWUBJIxuz4QmYTIf0O4\nHPE2o4JbAyGx/hRaqVvDgNeAz94ZFjb4Mp3RNbbdRUZB0ehrT/IGRJoHRu2HKFGM\nylRJL2kjKPoEc4XHbCu+MfmAIrQ4Xseg85zyI7ThhYvAzktdLHhQyfYr4wrrLCN3\noeTzmiqIHe9AataJXQ+mEQEEc9TNY23RFg==\n-----END CERTIFICATE-----\n",
			ok:         false,
		},
	}

	parseCert := func(cert string) (*x509.Certificate, error) {
		block, _ := pem.Decode([]byte(cert))
		if block == nil {
			t.Fatalf("decoding PEM cert, empty block")
		}
		return x509.ParseCertificate(block.Bytes)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deviceCert, err := parseCert(test.deviceCert)
			if err != nil {
				t.Fatalf("parsing device cert: %v", err)
			}

			keyCert, err := parseCert(test.keyCert)
			if err != nil {
				t.Fatalf("parsing key cert: %v", err)
			}

			_, err = Verify(deviceCert, keyCert)
			if (err == nil) != test.ok {
				t.Errorf("Verify returned %v, expected test outcome %v", err, test.ok)
			}
		})
	}
}
