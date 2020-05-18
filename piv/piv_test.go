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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math/bits"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/internal/pivtest"
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

func supportsVersion(v Version, major, minor, patch int) bool {
	if v.Major != major {
		return v.Major > major
	}
	if v.Minor != minor {
		return v.Minor > minor
	}
	return v.Patch >= patch
}

func testRequiresVersion(t *testing.T, yk *YubiKey, major, minor, patch int) {
	v := yk.Version()
	if !supportsVersion(v, major, minor, patch) {
		t.Skipf("test requires yubikey version %d.%d.%d: got %d.%d.%d", major, minor, patch, v.Major, v.Minor, v.Patch)
	}
}

func TestGetVersion(t *testing.T) { runHandleTest(t, testGetVersion) }

func TestCards(t *testing.T) {
	if _, err := Cards(); err != nil {
		t.Fatalf("listing cards: %v", err)
	}
}

func newTestYubiKey(t *testing.T) (*YubiKey, func()) {
	cards, err := Cards()
	if err != nil {
		t.Fatalf("listing cards: %v", err)
	}
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}
		if !pivtest.CanModifyYubiKey {
			t.Skip("not running test that accesses yubikey, provide --wipe-yubikey flag")
		}
		yk, err := Open(card)
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

func TestNewYubiKey(t *testing.T) {
	_, close := newTestYubiKey(t)
	defer close()
}

func TestMultipleConnections(t *testing.T) {
	cards, err := Cards()
	if err != nil {
		t.Fatalf("listing cards: %v", err)
	}
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}
		if !pivtest.CanModifyYubiKey {
			t.Skip("not running test that accesses yubikey, provide --wipe-yubikey flag")
		}
		yk, err := Open(card)
		if err != nil {
			t.Fatalf("getting new yubikey: %v", err)
		}
		defer func() {
			if err := yk.Close(); err != nil {
				t.Errorf("closing yubikey: %v", err)
			}
		}()

		_, oerr := Open(card)
		if oerr == nil {
			t.Fatalf("expected second open operation to fail")
		}
		var e *scErr
		if !errors.As(oerr, &e) {
			t.Fatalf("expected scErr, got %v", oerr)
		}
		if e.rc != 0x8010000B {
			t.Fatalf("expected return code 0x8010000B, got 0x%x", e.rc)
		}
		return
	}
	t.Skip("no yubikeys detected, skipping")
}

func TestYubiKeySerial(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	if _, err := yk.Serial(); err != nil {
		t.Fatalf("getting serial number: %v", err)
	}
}

func TestYubiKeyLoginNeeded(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	testRequiresVersion(t, yk, 4, 3, 0)

	if !ykLoginNeeded(yk.tx) {
		t.Errorf("expected login needed")
	}
	if err := ykLogin(yk.tx, DefaultPIN); err != nil {
		t.Fatalf("login: %v", err)
	}
	if ykLoginNeeded(yk.tx) {
		t.Errorf("expected no login needed")
	}
}

func TestYubiKeyPINRetries(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()
	retries, err := yk.Retries()
	if err != nil {
		t.Fatalf("getting retries: %v", err)
	}
	if retries < 0 || retries > 15 {
		t.Fatalf("invalid number of retries: %d", retries)
	}
}

func TestYubiKeyReset(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	yk, close := newTestYubiKey(t)
	defer close()
	if err := yk.Reset(); err != nil {
		t.Fatalf("resetting yubikey: %v", err)
	}
	if err := yk.authPIN(DefaultPIN); err != nil {
		t.Fatalf("login: %v", err)
	}
}

func TestYubiKeyLogin(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	if err := yk.authPIN(DefaultPIN); err != nil {
		t.Fatalf("login: %v", err)
	}
}

func TestYubiKeyAuthenticate(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	if err := yk.authManagementKey(DefaultManagementKey); err != nil {
		t.Errorf("authenticating: %v", err)
	}
}

func TestYubiKeySetManagementKey(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	var mgmtKey [24]byte
	if _, err := io.ReadFull(rand.Reader, mgmtKey[:]); err != nil {
		t.Fatalf("generating management key: %v", err)
	}

	if err := yk.SetManagementKey(DefaultManagementKey, mgmtKey); err != nil {
		t.Fatalf("setting management key: %v", err)
	}
	if err := yk.authManagementKey(mgmtKey); err != nil {
		t.Errorf("authenticating with new management key: %v", err)
	}
	if err := yk.SetManagementKey(mgmtKey, DefaultManagementKey); err != nil {
		t.Fatalf("resetting management key: %v", err)
	}
}

func TestYubiKeyUnblockPIN(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	badPIN := "0"
	for {
		err := ykLogin(yk.tx, badPIN)
		if err == nil {
			t.Fatalf("login with bad pin succeeded")
		}
		var e AuthErr
		if !errors.As(err, &e) {
			t.Fatalf("error returned was not a wrong pin error: %v", err)
		}
		if e.Retries == 0 {
			break
		}
	}

	if err := yk.Unblock(DefaultPUK, DefaultPIN); err != nil {
		t.Fatalf("unblocking pin: %v", err)
	}
	if err := ykLogin(yk.tx, DefaultPIN); err != nil {
		t.Errorf("failed to login with pin after unblock: %v", err)
	}
}

func TestYubiKeyChangePIN(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	newPIN := "654321"
	if err := yk.SetPIN(newPIN, newPIN); err == nil {
		t.Errorf("successfully changed pin with invalid pin, expected error")
	}
	if err := yk.SetPIN(DefaultPIN, newPIN); err != nil {
		t.Fatalf("changing pin: %v", err)
	}
	if err := yk.SetPIN(newPIN, DefaultPIN); err != nil {
		t.Fatalf("resetting pin: %v", err)
	}
}

func TestYubiKeyChangePUK(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	newPUK := "87654321"
	if err := yk.SetPUK(newPUK, newPUK); err == nil {
		t.Errorf("successfully changed puk with invalid puk, expected error")
	}
	if err := yk.SetPUK(DefaultPUK, newPUK); err != nil {
		t.Fatalf("changing puk: %v", err)
	}
	if err := yk.SetPUK(newPUK, DefaultPUK); err != nil {
		t.Fatalf("resetting puk: %v", err)
	}
}

func TestChangeManagementKey(t *testing.T) {
	yk, close := newTestYubiKey(t)
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
	if err := yk.SetManagementKey(newKey, newKey); err == nil {
		t.Errorf("successfully changed management key with invalid key, expected error")
	}
	if err := yk.SetManagementKey(DefaultManagementKey, newKey); err != nil {
		t.Fatalf("changing management key: %v", err)
	}
	if err := yk.SetManagementKey(newKey, DefaultManagementKey); err != nil {
		t.Fatalf("resetting management key: %v", err)
	}
}

func TestMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	func() {
		yk, close := newTestYubiKey(t)
		defer close()
		if err := yk.Reset(); err != nil {
			t.Fatalf("resetting yubikey: %v", err)
		}
	}()

	yk, close := newTestYubiKey(t)
	defer close()

	if m, err := yk.Metadata(DefaultPIN); err != nil {
		t.Errorf("getting metadata: %v", err)
	} else if m.ManagementKey != nil {
		t.Errorf("expected no management key set")
	}

	wantKey := [24]byte{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	m := &Metadata{
		ManagementKey: &wantKey,
	}
	if err := yk.SetMetadata(DefaultManagementKey, m); err != nil {
		t.Fatalf("setting metadata: %v", err)
	}
	got, err := yk.Metadata(DefaultPIN)
	if err != nil {
		t.Fatalf("getting metadata: %v", err)
	}
	if got.ManagementKey == nil {
		t.Errorf("no management key")
	} else if *got.ManagementKey != wantKey {
		t.Errorf("wanted management key=0x%x, got=0x%x", wantKey, got.ManagementKey)
	}
}

func TestMetadataUnmarshal(t *testing.T) {
	data, _ := hex.DecodeString("881a891809d98781fbdcc9b691a205806ec0ba8431ac0d9f59a500ad")
	wantKey := [24]byte{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	var m Metadata
	if err := m.unmarshal(data); err != nil {
		t.Fatalf("parsing metadata: %v", err)
	}
	if m.ManagementKey == nil {
		t.Fatalf("no management key")
	}
	gotKey := *m.ManagementKey
	if gotKey != wantKey {
		t.Errorf("(*Metadata).unmarshal, got key=0x%x, want key=0x%x", gotKey, wantKey)
	}
}

func TestMetadataMarshal(t *testing.T) {
	key := [24]byte{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	want := append([]byte{
		0x88,
		26,
		0x89,
		24,
	}, key[:]...)
	m := Metadata{
		ManagementKey: &key,
	}
	got, err := m.marshal()
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("(*Metadata.marshal, got=0x%x, want=0x%x", got, want)
	}
}

func TestMetadataUpdate(t *testing.T) {
	key := [24]byte{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	want := append([]byte{
		0x88,
		26,
		0x89,
		24,
	}, key[:]...)

	m1 := Metadata{
		ManagementKey: &DefaultManagementKey,
	}
	raw, err := m1.marshal()
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	m2 := Metadata{
		ManagementKey: &key,
		raw:           raw,
	}
	got, err := m2.marshal()
	if err != nil {
		t.Fatalf("marshaling updated metadata: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("(*Metadata.marshal, got=0x%x, want=0x%x", got, want)
	}
}

func TestMetadataAdditoinalFields(t *testing.T) {
	key := [24]byte{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	raw := []byte{
		0x88,
		4,
		// Unrecognized sub-object. The key should be added, but this object
		// shouldn't be impacted.
		0x87,
		2,
		0x00,
		0x01,
	}

	want := append([]byte{
		0x88,
		30,
		// Unrecognized sub-object.
		0x87,
		2,
		0x00,
		0x01,
		// Added management key.
		0x89,
		24,
	}, key[:]...)

	m := Metadata{
		ManagementKey: &key,
		raw:           raw,
	}
	got, err := m.marshal()
	if err != nil {
		t.Fatalf("marshaling updated metadata: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("(*Metadata.marshal, got=0x%x, want=0x%x", got, want)
	}
}

func TestYubiKeyCardId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	yk, close := newTestYubiKey(t)
	defer close()
	if err := yk.Reset(); err != nil {
		t.Fatalf("resetting yubikey: %v", err)
	}
	if _, err := yk.CardID(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expecting not found chuid")
	}
	var cardID = CardID{GUID: [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff},
	}
	if err := yk.SetCardID(DefaultManagementKey, &cardID); err != nil {
		t.Fatal(err)
	}
	newCID, err := yk.CardID()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(newCID.GUID[:], cardID.GUID[:]) {
		t.Errorf("(*CardID, got=0x%x, want=0x%x", newCID.GUID, cardID.GUID)
	}
}
