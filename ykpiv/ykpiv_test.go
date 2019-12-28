package ykpiv

import "testing"

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
