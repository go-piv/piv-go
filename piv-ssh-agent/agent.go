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

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ericchiang/piv-go/piv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	agentFilepathCreds = "creds"
	agentFilepathAuth  = "auth.sock"
)

type config struct {
	home string
}

func newAgent(c config) (*sshAgent, error) {
	home := c.home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("")
		}
		home = h
	}
	dir := filepath.Join(home, ".config", "piv-ssh-agent")
	if _, err := os.Stat(dir); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("configuring agent directory: %v", err)
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("creating agent directory: %v", err)
		}
	}

	return &sshAgent{dir, rand.Reader}, nil
}

type sshAgent struct {
	dir string

	// source of randomness
	rand io.Reader
}

func (a *sshAgent) List() ([]*agent.Key, error) {
	var keys []*agent.Key
	err := a.visitCards(func(yk *piv.YubiKey, cred credential) (bool, error) {
		cert, err := yk.Certificate(piv.SlotAuthentication)
		if err != nil {
			return false, fmt.Errorf("getting ssh key: %v", err)
		}
		pub, err := ssh.NewPublicKey(cert.PublicKey)
		if err != nil {
			return false, fmt.Errorf("getting ssh public key: %v", err)
		}
		key := &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: cert.Subject.CommonName,
		}
		keys = append(keys, key)
		return false, nil
	})
	return keys, err
}

func (a *sshAgent) visitCards(visit func(yk *piv.YubiKey, cred credential) (bool, error)) error {
	creds, err := a.listCredentials()
	if err != nil {
		return fmt.Errorf("listing cards: %v", err)
	}
	if len(creds) == 0 {
		return nil
	}
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("listing cards: %v", err)
	}
	for _, card := range cards {
		if !isYubiKey(card) {
			continue
		}
		yk, err := piv.Open(card)
		if err != nil {
			return fmt.Errorf("opening card: %v", err)
		}
		s, err := yk.Serial()
		if err != nil {
			yk.Close()
			return fmt.Errorf("getting serial: %v", err)
		}
		var done bool
		for _, cred := range creds {
			if cred.serial != s {
				continue
			}
			done, err = visit(yk, cred)
			break
		}
		yk.Close()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return nil
}

func (a *sshAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	var sig *ssh.Signature
	err := a.visitCards(func(yk *piv.YubiKey, cred credential) (bool, error) {
		cert, err := yk.Certificate(piv.SlotAuthentication)
		if err != nil {
			return false, fmt.Errorf("getting ssh key: %v", err)
		}
		pub, err := ssh.NewPublicKey(cert.PublicKey)
		if err != nil {
			return false, fmt.Errorf("getting ssh public key: %v", err)
		}
		if !bytes.Equal(key.Marshal(), pub.Marshal()) {
			return false, nil
		}
		auth := piv.KeyAuth{PIN: cred.pin}
		priv, err := yk.PrivateKey(piv.SlotAuthentication, cert.PublicKey, auth)
		if err != nil {
			return false, fmt.Errorf("getting private key: %v", err)
		}
		signer, ok := priv.(crypto.Signer)
		if !ok {
			return false, fmt.Errorf("key doesn't implement signer")
		}
		s, err := ssh.NewSignerFromSigner(signer)
		if err != nil {
			return false, fmt.Errorf("initializing ssh signer: %v", err)
		}
		sshSig, err := s.Sign(rand.Reader, data)
		if err != nil {
			return false, fmt.Errorf("signing data: %v", err)
		}
		sig = sshSig
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if sig == nil {
		return nil, fmt.Errorf("card not found")
	}
	return sig, nil
}

// deferredSigner implement ssh.Signer without holding an active connection to
// a YubiKey.
type deferredSigner struct {
	agent  *sshAgent
	serial uint32

	// pub is required to access the private key, while sshPub is required to
	// satisfy the ssh.Signer interface.
	pub    crypto.PublicKey
	sshPub ssh.PublicKey
}

func (d *deferredSigner) PublicKey() ssh.PublicKey {
	return d.sshPub
}

func (d *deferredSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	var sig *ssh.Signature
	err := d.agent.visitCards(func(yk *piv.YubiKey, cred credential) (bool, error) {
		if cred.serial != d.serial {
			return false, nil
		}
		auth := piv.KeyAuth{PIN: cred.pin}
		priv, err := yk.PrivateKey(piv.SlotAuthentication, d.pub, auth)
		if err != nil {
			return false, fmt.Errorf("getting private key: %v", err)
		}
		signer, ok := priv.(crypto.Signer)
		if !ok {
			return false, fmt.Errorf("key doesn't implement signer")
		}
		s, err := ssh.NewSignerFromSigner(signer)
		if err != nil {
			return false, fmt.Errorf("initializing ssh signer: %v", err)
		}
		sshSig, err := s.Sign(rand, data)
		if err != nil {
			return false, fmt.Errorf("signing data: %v", err)
		}
		sig = sshSig
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (a *sshAgent) Signers() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	err := a.visitCards(func(yk *piv.YubiKey, cred credential) (bool, error) {
		cert, err := yk.Certificate(piv.SlotAuthentication)
		if err != nil {
			return false, fmt.Errorf("getting ssh key: %v", err)
		}
		pub, err := ssh.NewPublicKey(cert.PublicKey)
		if err != nil {
			return false, fmt.Errorf("getting ssh public key: %v", err)
		}
		signers = append(signers, &deferredSigner{
			agent:  a,
			serial: cred.serial,
			pub:    cert.PublicKey,
			sshPub: pub,
		})
		return false, nil
	})
	return signers, err
}

func (a *sshAgent) Add(key agent.AddedKey) error {
	return fmt.Errorf("adding keys to agent not supported")
}

func (a *sshAgent) Remove(key ssh.PublicKey) error {
	return fmt.Errorf("removing keys from agent not supported")
}

func (a *sshAgent) RemoveAll() error {
	return fmt.Errorf("removing keys from agent not supported")
}

func (a *sshAgent) Lock(passphrase []byte) error {
	return fmt.Errorf("locking agent not supported")
}

func (a *sshAgent) Unlock(passphrase []byte) error {
	return fmt.Errorf("unlocking agent not supported")
}

func (a *sshAgent) listManagedCards() ([]uint32, error) {
	creds, err := a.listCredentials()
	if err != nil {
		return nil, err
	}
	var serials []uint32
	for _, c := range creds {
		serials = append(serials, c.serial)
	}
	return serials, nil
}

func (a *sshAgent) listCredentials() ([]credential, error) {
	p := filepath.Join(a.dir, agentFilepathCreds)
	data, err := ioutil.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
	}
	creds, err := parseCredentials(data)
	if err != nil {
		return nil, fmt.Errorf("parsing credentials file %s: %v", p, err)
	}
	return creds, nil
}

func (a *sshAgent) addManagedCard(cred credential) error {
	creds, err := a.listCredentials()
	if err != nil {
		return err
	}
	creds = append(creds, cred)
	data := marshalCredentials(creds)

	if err := os.MkdirAll(a.dir, 0755); err != nil {
		return fmt.Errorf("creating agent directory: %v", err)
	}
	p := filepath.Join(a.dir, agentFilepathCreds)
	if err := ioutil.WriteFile(p, data, 0600); err != nil {
		return fmt.Errorf("writing credentials file: %v", err)
	}
	return nil
}

func generateCreds(r io.Reader) (pin, puk string, key [24]byte, err error) {
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return "", "", key, fmt.Errorf("generating management key: %v", err)
	}
	// NOTE(ericchiang): PINs can be 8 digits, but they're more commonly 6
	pinN, err := rand.Int(r, big.NewInt(1_000_000))
	if err != nil {
		return "", "", key, fmt.Errorf("generating pin: %v", err)
	}
	pukN, err := rand.Int(r, big.NewInt(100_000_000))
	if err != nil {
		return "", "", key, fmt.Errorf("generating puk: %v", err)
	}
	// Use sprintf for zero padding
	pin = fmt.Sprintf("%06d", pinN)
	puk = fmt.Sprintf("%08d", pukN)
	return pin, puk, key, nil
}

type keyGenerator struct {
	slot piv.Slot
	rand io.Reader
	now  func() time.Time
}

// newSSHKey generates a SSH key in a YubiKey's slot. Since we need to track the
// public key, newSSHKey also generates a self-signed certificate and stores it
// in the key's associated certificate slot.
func (k *keyGenerator) newSSHKey(yk *piv.YubiKey, mgmtKey [24]byte) error {
	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyAlways,
	}

	pub, err := yk.GenerateKey(mgmtKey, k.slot, key)
	if err != nil {
		return fmt.Errorf("generating key: %v", err)
	}

	// We want to store the public key on the YubiKey, but slots only take X.509
	// certificates. Generate a X.509 cert for the public key, and store in the
	// slot.

	// Using the key to self-sign a certificate would require a touch, so create a
	// throw away CA to sign the certificate instead.
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), k.rand)
	if err != nil {
		return fmt.Errorf("generating temporary key: %v", err)
	}
	caSerial, err := rand.Int(k.rand, big.NewInt(1_000_000))
	if err != nil {
		return fmt.Errorf("generating random serial: %v", err)
	}
	caTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "tmp-ca"},
		SerialNumber:          caSerial,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 200),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(k.rand, caTmpl, caTmpl, caPriv.Public(), caPriv)
	if err != nil {
		return fmt.Errorf("creating temporary ca: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("parsing temporary ca cert: %v", err)
	}

	// Use the CA to sign a certificate for the public key.
	cliSerial, err := rand.Int(k.rand, big.NewInt(1_000_000))
	if err != nil {
		return fmt.Errorf("generating random serial for client cert: %v", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("getting hostname: %v", err)
	}
	cliTmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: hostname},
		SerialNumber: cliSerial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365 * 200),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliCertDER, err := x509.CreateCertificate(k.rand, cliTmpl, caCert, pub, caPriv)
	if err != nil {
		return fmt.Errorf("creating certificate for ssh key: %v", err)
	}
	cliCert, err := x509.ParseCertificate(cliCertDER)
	if err != nil {
		return fmt.Errorf("parsing temporary ca cert: %v", err)
	}
	if err := yk.SetCertificate(mgmtKey, k.slot, cliCert); err != nil {
		return fmt.Errorf("updating slot with certificate: %v", err)
	}
	return nil
}

func (a *sshAgent) initCard(serial uint32) error {
	cards, err := a.listManagedCards()
	if err != nil {
		return fmt.Errorf("listing existing managed cards: %v", err)
	}
	for _, card := range cards {
		if card == serial {
			return fmt.Errorf("smart card is already initialized")
		}
	}

	pin, puk, key, err := generateCreds(a.rand)
	if err != nil {
		return fmt.Errorf("creating new credentials: %v", err)
	}

	yk, err := openCard(serial)
	if err != nil {
		return err
	}
	defer yk.Close()

	// Update YubiKey credentials.
	if err := yk.SetPIN(piv.DefaultPIN, pin); err != nil {
		// TODO: consider checking pin retry count first? If it's less than 3
		// we can assume that the card isn't in a default state and not
		// unintentionally block a card.
		return fmt.Errorf("changing pin (need to reset card?): %v", err)
	}
	// Intentionally throw out PUK. If there's a better strategy later, then
	// we can figure that out.
	if err := yk.SetPUK(piv.DefaultPUK, puk); err != nil {
		return fmt.Errorf("changing puk: %v", err)
	}
	if err := yk.SetManagementKey(piv.DefaultManagementKey, key); err != nil {
		return fmt.Errorf("changing management key: %v", err)
	}
	m, err := yk.Metadata(pin)
	if err != nil {
		return fmt.Errorf("getting card metadata: %v", err)
	}
	m.ManagementKey = &key
	if err := yk.SetMetadata(key, m); err != nil {
		return fmt.Errorf("updating card metadata: %v", err)
	}

	// Store new credentials in the agent's config directory.
	cred := credential{
		serial: serial,
		pin:    pin,
	}
	if err := a.addManagedCard(cred); err != nil {
		return fmt.Errorf("storing card's new credentials: %v", err)
	}

	// Generate a SSH key.
	kg := keyGenerator{
		rand: a.rand,
		now:  time.Now,
		slot: piv.SlotAuthentication,
	}
	if err := kg.newSSHKey(yk, key); err != nil {
		return fmt.Errorf("creating ssh key: %v", err)
	}
	return nil
}

type credential struct {
	serial uint32
	pin    string
}

func isNotNumeric(r rune) bool {
	return '0' > r || r > '9'
}

func parseSerial(b []byte) (uint32, bool) {
	if len(b) != 8 {
		return 0, false
	}
	var s [4]byte
	if _, err := hex.Decode(s[:], b); err != nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(s[:]), true
}

func parseCredentials(b []byte) ([]credential, error) {
	var creds []credential
	for i, line := range bytes.Split(b, []byte{'\n'}) {
		parts := bytes.Fields(line)
		if len(parts) < 2 {
			continue
		}
		serial, ok := parseSerial(parts[0])
		if !ok {
			return nil, fmt.Errorf("line %d, invalid serial number", i+1)
		}
		pin := string(parts[1])
		if len(pin) == 0 || strings.IndexFunc(pin, isNotNumeric) >= 0 {
			return nil, fmt.Errorf("line %d, invalid pin", i+1)
		}
		creds = append(creds, credential{serial, pin})
	}
	return creds, nil
}

func marshalCredentials(creds []credential) []byte {
	b := &bytes.Buffer{}
	for _, c := range creds {
		var s [4]byte
		binary.BigEndian.PutUint32(s[:], c.serial)
		b.WriteString(hex.EncodeToString(s[:]))
		b.WriteString(" ")
		b.WriteString(c.pin)
		b.WriteString("\n")
	}
	return b.Bytes()
}

func isYubiKey(card string) bool {
	return strings.Contains(strings.ToLower(card), "yubikey")
}

func (a *sshAgent) reset(force bool, serial uint32) error {
	yk, err := openCard(serial)
	if err != nil {
		return err
	}
	defer yk.Close()
	if !force {
		if err := resetPrompt(); err != nil {
			return err
		}
	}
	if err := yk.Reset(); err != nil {
		return fmt.Errorf("resetting card: %v", err)
	}
	return nil
}

func resetPrompt() error {
	for i := 0; i < 3; i++ {
		fmt.Print("Reset card [y/n]: ")
		var s string
		if _, err := fmt.Scanln(&s); err != nil {
			return fmt.Errorf("reading from stdin: %v", err)
		}
		switch s {
		case "y":
			return nil
		case "n":
			return fmt.Errorf("reset canceled")
		default:
			fmt.Fprintln(os.Stderr, "error: response must be 'y' or 'n'.")
		}
	}
	return fmt.Errorf("too many invalid responses")
}

type multiErr struct {
	errors []error
}

func (m *multiErr) errorf(format string, v ...interface{}) {
	m.errors = append(m.errors, fmt.Errorf(format, v...))
}

func (m *multiErr) Error() string {
	if len(m.errors) == 1 {
		return m.errors[0].Error()
	}
	return fmt.Sprintf("errors: %v", m.errors)
}

func openCard(serial uint32) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("listing cards: %v", err)
	}
	e := &multiErr{}
	for _, card := range cards {
		if !isYubiKey(card) {
			continue
		}
		yk, err := piv.Open(card)
		if err != nil {
			e.errorf("opening card: %v", err)
			continue
		}
		s, err := yk.Serial()
		if err != nil {
			e.errorf("getting card serial number %s: %v", card, err)
			yk.Close()
			continue
		}
		if s != serial {
			yk.Close()
			continue
		}
		return yk, nil
	}
	if len(e.errors) != 0 {
		return nil, e
	}
	return nil, fmt.Errorf("card not found")
}
