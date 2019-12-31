package ykpiv

import (
	"crypto/rand"
	"errors"
	"io"
	"math/bits"
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

func TestSmartCards(t *testing.T) {
	if _, err := SmartCards(); err != nil {
		t.Fatalf("listing cards: %v", err)
	}
}

func newTestYubikey(t *testing.T) (*Yubikey, func()) {
	cards, err := SmartCards()
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
	tx, err := yk.begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Close()

	retries, err := ykPINRetries(tx)
	if err != nil {
		t.Fatalf("getting retries: %v", err)
	}
	if retries < 0 || retries > 15 {
		t.Fatalf("invalid number of retries: %d", retries)
	}
}

func TestYubikeyReset(t *testing.T) {
	yk, close := newTestYubikey(t)
	defer close()
	tx, err := yk.begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	err = ykReset(tx)
	tx.Close()
	if err != nil {
		t.Fatalf("resetting yubikey: %v", err)
	}

	tx, err = yk.begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Close()
	if err := ykLogin(tx, DefaultPIN); err != nil {
		t.Errorf("login with default pin failed: %v", err)
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

func TestYubikeyUnblockPIN(t *testing.T) {
	yk, close := newTestYubikey(t)
	defer close()

	tx, err := yk.begin()
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Close()

	badPIN := "0"
	for {
		err := ykLogin(tx, badPIN)
		if err == nil {
			t.Fatalf("login with bad pin succeeded")
		}
		var e *ErrWrongPIN
		if !errors.As(err, &e) {
			t.Fatalf("error returned was not a wrong pin error: %v", err)
		}
		if e.Retries == 0 {
			break
		}
	}

	if err := ykUnblockPIN(tx, DefaultPUK, DefaultPIN); err != nil {
		t.Fatalf("unblocking pin: %v", err)
	}
	if err := ykLogin(tx, DefaultPIN); err != nil {
		t.Errorf("failed to login with pin after unblock: %v", err)
	}
}

func TestYubikeyChangePIN(t *testing.T) {
	yk, close := newTestYubikey(t)
	defer close()

	newPIN := "654321"

	tx, err := yk.begin()
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Close()

	if err := ykChangePIN(tx, newPIN, newPIN); err == nil {
		t.Errorf("successfully changed pin with invalid pin, expected error")
	}

	if err := ykChangePIN(tx, DefaultPIN, newPIN); err != nil {
		t.Fatalf("changing pin: %v", err)
	}
	if err := ykLogin(tx, newPIN); err != nil {
		t.Errorf("failed to login with new pin: %v", err)
	}
	if err := ykChangePIN(tx, newPIN, DefaultPIN); err != nil {
		t.Fatalf("resetting pin: %v", err)
	}
}

func TestYubikeyChangePUK(t *testing.T) {
	yk, close := newTestYubikey(t)
	defer close()

	newPUK := "87654321"

	tx, err := yk.begin()
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Close()

	if err := ykChangePUK(tx, newPUK, newPUK); err == nil {
		t.Errorf("successfully changed puk with invalid puk, expected error")
	}

	if err := ykChangePUK(tx, DefaultPUK, newPUK); err != nil {
		t.Fatalf("changing puk: %v", err)
	}
	if err := ykChangePUK(tx, newPUK, DefaultPUK); err != nil {
		t.Fatalf("resetting puk: %v", err)
	}
}

func TestChangeManagementKey(t *testing.T) {
	yk, close := newTestYubikey(t)
	defer close()

	var newKey [24]byte
	if _, err := io.ReadFull(rand.Reader, newKey[:]); err != nil {
		t.Fatalf("generating new management key: %v", err)
	}
	// Apply odd-parity
	for i, b := range newKey {
		if bits.OnesCount8(uint8(b))%2 == 0 {
			newKey[i] = b ^ 1 // flip least significant bit
		}
	}

	tx, err := yk.begin()
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Close()

	if err := ykAuthenticate(tx, DefaultManagementKey); err != nil {
		t.Fatalf("authenticating with default management key: %v", err)
	}
	if err := ykChangeManagementKey(tx, newKey); err != nil {
		t.Fatalf("changing management key: %v", err)
	}
	if err := ykAuthenticate(tx, newKey); err != nil {
		t.Errorf("failed to authenticate with new management key: %v", err)
	}
	if err := ykChangeManagementKey(tx, DefaultManagementKey); err != nil {
		t.Fatalf("resetting management key: %v", err)
	}
}
