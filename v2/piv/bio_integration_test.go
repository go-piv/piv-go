package piv

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
)

// Hardware integration tests for YubiKey Bio (PIV).
// Requires a physical YK and will destructively modify slot 9a.
// Run: PIV_BIO_TESTS=1 go test ./piv -run TestPINPolicyMatch -wipe-yubikey

func TestPINPolicyMatchOnceIntegration(t *testing.T) {
	requireBioTests(t)

	yk, close := newTestYubiKey(t)
	defer close()

	pub, err := getPublicKeyFromSlot(yk)
	if err != nil {
		key := Key{
			Algorithm:   AlgorithmEC256,
			PINPolicy:   PINPolicyMatchAlways,
			TouchPolicy: TouchPolicyNever,
		}
		pub, err = yk.GenerateKey(DefaultManagementKey, SlotAuthentication, key)
		if err != nil {
			if isUnsupportedMatchPolicy(err) {
				t.Skipf("match policy not supported: %v", err)
			}
			t.Fatalf("generating key: %v", err)
		}
	}

	info, err := yk.KeyInfo(SlotAuthentication)
	if err != nil {
		t.Fatalf("reading key info: %v", err)
	}
	if info.PINPolicy != PINPolicyMatchOnce && info.PINPolicy != PINPolicyMatchAlways {
		t.Fatalf("unexpected PIN policy: %v", info.PINPolicy)
	}

	priv, err := yk.PrivateKey(SlotAuthentication, pub, KeyAuth{
		PINPolicy: info.PINPolicy,
	})
	if err != nil {
		t.Fatalf("building private key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("expected crypto.Signer got %T", priv)
	}

	message := []byte("bio")
	signWithBioRetry(t, signer, message)
}

func TestPINPolicyMatchAlwaysTwoVerifications(t *testing.T) {
	requireBioTests(t)

	yk, close := newTestYubiKey(t)
	defer close()

	key := Key{
		Algorithm:   AlgorithmEC256,
		PINPolicy:   PINPolicyMatchAlways,
		TouchPolicy: TouchPolicyNever,
	}
	pub, err := yk.GenerateKey(DefaultManagementKey, SlotAuthentication, key)
	if err != nil {
		if isUnsupportedMatchPolicy(err) {
			t.Skipf("match policy not supported: %v", err)
		}
		t.Fatalf("generating key: %v", err)
	}

	info, err := yk.KeyInfo(SlotAuthentication)
	if err != nil {
		t.Fatalf("reading key info: %v", err)
	}
	if info.PINPolicy != PINPolicyMatchAlways {
		t.Fatalf("unexpected PIN policy: %v", info.PINPolicy)
	}

	priv, err := yk.PrivateKey(SlotAuthentication, pub, KeyAuth{
		PINPolicy: info.PINPolicy,
	})
	if err != nil {
		t.Fatalf("building private key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("expected crypto.Signer got %T", priv)
	}

	message := []byte("bio")
	fmt.Fprintln(os.Stderr, "MatchAlways: touch/biometric required for sign 1 of 2.")
	signWithBioRetry(t, signer, message)
	fmt.Fprintln(os.Stderr, "MatchAlways: touch/biometric required for sign 2 of 2.")
	signWithBioRetry(t, signer, message)
}

func TestPINPolicyMatchOnceSingleVerification(t *testing.T) {
	requireBioTests(t)

	yk, close := newTestYubiKey(t)
	defer close()

	key := Key{
		Algorithm:   AlgorithmEC256,
		PINPolicy:   PINPolicyMatchOnce,
		TouchPolicy: TouchPolicyNever,
	}
	pub, err := yk.GenerateKey(DefaultManagementKey, SlotAuthentication, key)
	if err != nil {
		if isUnsupportedMatchPolicy(err) {
			t.Skipf("match policy not supported: %v", err)
		}
		t.Fatalf("generating key: %v", err)
	}

	info, err := yk.KeyInfo(SlotAuthentication)
	if err != nil {
		t.Fatalf("reading key info: %v", err)
	}
	if info.PINPolicy != PINPolicyMatchOnce {
		t.Fatalf("unexpected PIN policy: %v", info.PINPolicy)
	}

	priv, err := yk.PrivateKey(SlotAuthentication, pub, KeyAuth{
		PINPolicy: info.PINPolicy,
	})
	if err != nil {
		t.Fatalf("building private key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("expected crypto.Signer got %T", priv)
	}

	message := []byte("bio")
	fmt.Fprintln(os.Stderr, "MatchOnce: touch/biometric required for sign 1 of 2.")
	signWithBioRetry(t, signer, message)
	fmt.Fprintln(os.Stderr, "MatchOnce: sign 2 of 2 should not require biometric.")
	signWithoutBioExpected(t, signer, message)
}

func isUnsupportedMatchPolicy(err error) bool {
	var apdu *apduErr
	if !errors.As(err, &apdu) {
		return false
	}
	switch apdu.Status() {
	case 0x6a80, 0x6a81, 0x6a86, 0x6d00:
		return true
	default:
		return false
	}
}

func getPublicKeyFromSlot(yk *YubiKey) (crypto.PublicKey, error) {
	cert, err := yk.Certificate(SlotAuthentication)
	if err == nil {
		return cert.PublicKey, nil
	}
	attest, err := yk.Attest(SlotAuthentication)
	if err != nil {
		return nil, fmt.Errorf("no cert or attestation: %w", err)
	}
	return attest.PublicKey, nil
}

func requireBioTests(t *testing.T) {
	if !canModifyYubiKey {
		t.Skip("not running test that accesses yubikey, provide --wipe-yubikey flag")
	}
	if os.Getenv("PIV_BIO_TESTS") == "" {
		t.Skip("set PIV_BIO_TESTS=1 to run biometric integration tests")
	}
}

func signWithBioRetry(t *testing.T, signer crypto.Signer, message []byte) {
	const maxAttempts = 3
	digest := sha256.Sum256(message)
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			if isUnsupportedMatchPolicy(err) {
				t.Skipf("match policy not supported: %v", err)
			}
			var authErr AuthErr
			if errors.As(err, &authErr) {
				if attempt == maxAttempts {
					t.Fatalf("signing failed after %d attempts: %v", attempt, err)
				}
				continue
			}
			t.Fatalf("signing failed: %v", err)
		}
		_ = sig
		return
	}
}

func signWithoutBioExpected(t *testing.T, signer crypto.Signer, message []byte) {
	digest := sha256.Sum256(message)
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		if isUnsupportedMatchPolicy(err) {
			t.Skipf("match policy not supported: %v", err)
		}
		t.Fatalf("expected signing to succeed without biometric verification: %v", err)
	}
	_ = sig
}
