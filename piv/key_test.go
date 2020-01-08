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
	"math/big"
	"testing"
	"time"
)

func TestYubiKeySignECDSA(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()
	tx, err := yk.begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Close()

	slot := SlotAuthentication

	if err := ykAuthenticate(tx, DefaultManagementKey); err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	if err := ykLogin(tx, DefaultPIN); err != nil {
		t.Fatalf("logging in: %v", err)
	}
	key := keyOptions{alg: AlgorithmEC256}
	pubKey, err := ykGenerateKey(tx, slot, key)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is not an ecdsa key")
	}
	data := sha256.Sum256([]byte("hello"))

	out, err := ykSignECDSA(tx, slot, pub, data[:])
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
			tx, err := yk.begin()
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Close()

			slot := SlotAuthentication

			if err := ykAuthenticate(tx, DefaultManagementKey); err != nil {
				t.Fatalf("authenticating: %v", err)
			}
			if err := ykLogin(tx, DefaultPIN); err != nil {
				t.Fatalf("logging in: %v", err)
			}
			key := keyOptions{alg: AlgorithmRSA1024}
			pubKey, err := ykGenerateKey(tx, slot, key)
			if err != nil {
				t.Fatalf("generating key: %v", err)
			}
			pub, ok := pubKey.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("public key is not an rsa key")
			}
			data := sha256.Sum256([]byte("hello"))

			out, err := ykSignRSA(tx, slot, pub, data[:], crypto.SHA256)
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
			tx, err := yk.begin()
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Close()

			slot := SlotAuthentication

			if err := ykAuthenticate(tx, DefaultManagementKey); err != nil {
				t.Fatalf("authenticating: %v", err)
			}
			key := keyOptions{alg: AlgorithmRSA1024}
			pubKey, err := ykGenerateKey(tx, slot, key)
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

			got, err := ykDecryptRSA(tx, slot, pub, ct)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}
			if !bytes.Equal(data, got) {
				t.Errorf("decrypt, got=%q, want=%q", got, data)
			}
		})
	}
}

func TestYubiKeyStoreCertificate(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()
	tx, err := yk.begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Close()

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

	if err := ykAuthenticate(tx, DefaultManagementKey); err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	key := keyOptions{alg: AlgorithmEC256}
	pub, err := ykGenerateKey(tx, slot, key)
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
	if err := ykStoreCertificate(tx, slot, cliCert); err != nil {
		t.Fatalf("storing client cert: %v", err)
	}
	gotCert, err := ykGetCertificate(tx, slot)
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
			tx, err := yk.begin()
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Close()

			if err := ykAuthenticate(tx, DefaultManagementKey); err != nil {
				t.Fatalf("authenticating: %v", err)
			}

			key := keyOptions{alg: test.alg}
			if _, err := ykGenerateKey(tx, SlotAuthentication, key); err != nil {
				t.Errorf("generating key: %v", err)
			}
		})
	}
}
