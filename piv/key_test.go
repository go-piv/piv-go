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
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestYubiKeySignECDSA(t *testing.T) {
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

			k := Key{
				Algorithm:   AlgorithmEC256,
				PINPolicy:   PINPolicyNever,
				TouchPolicy: TouchPolicyNever,
			}
			pub, err := yk.GenerateKey(DefaultManagementKey, test.slot, k)
			if err != nil {
				t.Fatalf("generating key on slot: %v", err)
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
		PINPolicy:   PINPolicyNever,
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
	sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err == nil || !strings.Contains(err.Error(), "test error") {
		t.Errorf("PINPrompt error should be propagated, got sig=%v err=%v", sig, err)
		// and should not crash
	}
}
