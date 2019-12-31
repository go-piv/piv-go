package ykpiv

import (
	"crypto/rand"
	"io"
	"testing"
)

func testGetVersion(t *testing.T, h *scHandle) {
	tx, err := h.Begin()
	if err != nil {
		t.Fatalf("new transaction: %v", err)
	}
	defer tx.Close()
	if err := ykSelectApplication(tx, aidPIV[:]); err != nil {
		t.Fatalf("selecting application: %v", err)
	}
	if _, err := ykVersion(tx); err != nil {
		t.Fatalf("listing version: %v", err)
	}
}

func TestGetVersion(t *testing.T) { runHandleTest(t, testGetVersion) }

func TestSmartcards(t *testing.T) {
	if _, err := Smartcards(); err != nil {
		t.Fatalf("listing cards: %v", err)
	}
}

func newTestYubikey(t *testing.T) (*Yubikey, func()) {
	cards, err := Smartcards()
	if err != nil {
		t.Fatalf("listing cards: %v", err)
	}
	for _, card := range cards {
		yk, err := newYubikey(card)
		if err != nil {
			t.Fatalf("getting new yubikey: %v", err)
		}
		return yk, func() {
			if err := yk.Close(); err != nil {
				t.Errorf("closing yubikey: %v", err)
			}
		}
	}
	t.Skip("no yubikeys detected, skipping")
	return nil, nil
}

func TestNewYubikey(t *testing.T) {
	_, close := newTestYubikey(t)
	defer close()
}

func TestYubikeySerial(t *testing.T) {
	yk, close := newTestYubikey(t)
	defer close()

	if _, err := yk.Serial(); err != nil {
		t.Fatalf("getting serial number: %v", err)
	}
}

func TestYubikeyPINRetries(t *testing.T) {
	yk, close := newTestYubikey(t)
	defer close()
	retries, err := yk.PINRetries()
	if err != nil {
		t.Fatalf("getting retries: %v", err)
	}
	if retries < 0 || retries > 15 {
		t.Fatalf("invalid number of retries: %d", retries)
	}
}

func TestYubikeyLogin(t *testing.T) {
	yk, close := newTestYubikey(t)
	defer close()

	if err := yk.Login(DefaultPIN); err != nil {
		t.Fatalf("login: %v", err)
	}
}

func TestYubikeyAuthenticate(t *testing.T) {
	yk, close := newTestYubikey(t)
	defer close()

	tx, err := yk.begin()
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Close()

	if err := ykAuthenticate(tx, DefaultManagementKey); err != nil {
		t.Errorf("authenticating: %v", err)
	}
}

func TestYubikeySetManagementKey(t *testing.T) {
	yk, close := newTestYubikey(t)
	defer close()

	var mgmtKey [24]byte
	if _, err := io.ReadFull(rand.Reader, mgmtKey[:]); err != nil {
		t.Fatalf("generating management key: %v", err)
	}

	tx, err := yk.begin()
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Close()

	if err := ykSetManagementKey(tx, mgmtKey, false); err == nil {
		t.Errorf("set management key without authenticating, expected error")
	}

	if err := ykAuthenticate(tx, DefaultManagementKey); err != nil {
		t.Errorf("authenticating: %v", err)
	}

	if err := ykSetManagementKey(tx, mgmtKey, false); err != nil {
		t.Fatalf("setting management key: %v", err)
	}
	if err := ykAuthenticate(tx, mgmtKey); err != nil {
		t.Errorf("authenticating with new management key: %v", err)
	}
	if err := ykSetManagementKey(tx, DefaultManagementKey, false); err != nil {
		t.Fatalf("setting management key: %v", err)
	}
}
