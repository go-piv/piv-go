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
	"flag"
	"io"
	"math/bits"
	"strings"
	"testing"
)

// canModifyYubiKey indicates whether the test running has constented to
// destroying data on YubiKeys connected to the system.
var canModifyYubiKey bool

var (
	version43 = version{4, 3, 0} // EC384 and Attestation
	version53 = version{5, 3, 0} // PINPolicy and KeyInfo
	version57 = version{5, 7, 0} // RSA3072, RSA4096, Ed25519, and X25519
)

func init() {
	flag.BoolVar(&canModifyYubiKey, "wipe-yubikey", false,
		"Flag required to run tests that access the yubikey")
}

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

func testRequiresVersion(t *testing.T, yk *YubiKey, v version) {
	if !supportsVersion(yk.version, v.major, v.minor, v.patch) {
		t.Skipf("test requires yubikey version %d.%d.%d: got %d.%d.%d", v.major, v.minor, v.patch, yk.version.major, yk.version.minor, yk.version.patch)
	}
}

func TestGetVersion(t *testing.T) { runHandleTest(t, testGetVersion) }

func TestCards(t *testing.T) {
	if !canModifyYubiKey {
		t.Skip("not running test that accesses yubikey, provide --wipe-yubikey flag")
	}

	if _, err := Cards(); err != nil {
		t.Fatalf("listing cards: %v", err)
	}
}

func newTestYubiKey(t *testing.T) (*YubiKey, func()) {
	if !canModifyYubiKey {
		t.Skip("not running test that accesses yubikey, provide --wipe-yubikey flag")
	}

	cards, err := Cards()
	if err != nil {
		t.Fatalf("listing cards: %v", err)
	}
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
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
	if !canModifyYubiKey {
		t.Skip("not running test that accesses yubikey, provide --wipe-yubikey flag")
	}

	cards, err := Cards()
	if err != nil {
		t.Fatalf("listing cards: %v", err)
	}
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}
		if !canModifyYubiKey {
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

	testRequiresVersion(t, yk, version43)

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
	// The call to Retries may fail after performing the login in
	// TestYubiKeyLoginNeeded. It appears that the YubiKey doesn’t close the
	// connection immediately, leading to test failures. To prevent this, we
	// will reset the YubiKey before running the test.
	func() {
		yk, close := newTestYubiKey(t)
		defer close()
		if err := yk.Reset(); err != nil {
			t.Fatalf("resetting key: %v", err)
		}
	}()

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
	if err := yk.VerifyPIN(DefaultPIN); err != nil {
		t.Fatalf("login: %v", err)
	}
}

func TestYubiKeyLogin(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	if err := yk.VerifyPIN(DefaultPIN); err != nil {
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

	if err := yk.SetManagementKey(DefaultManagementKey, mgmtKey[:]); err != nil {
		t.Fatalf("setting management key: %v", err)
	}
	if err := yk.authManagementKey(mgmtKey[:]); err != nil {
		t.Errorf("authenticating with new management key: %v", err)
	}
	if err := yk.SetManagementKey(mgmtKey[:], DefaultManagementKey); err != nil {
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

func TestYubiKeyChangeRetries(t *testing.T) {
	yk, close := newTestYubiKey(t)
	defer close()

	if err := yk.SetRetries(DefaultManagementKey, DefaultPIN, 3, 0); err == nil {
		t.Errorf("successfully set retries to zeros, expected error")
	}
	if err := yk.SetRetries(DefaultManagementKey, DefaultPIN, 256, 3); err == nil {
		t.Errorf("successfully set retries greater than 255, expected error")
	}
	if err := yk.SetRetries(DefaultManagementKey, DefaultPIN, 5, 3); err != nil {
		t.Fatalf("setting pin/puk retries: %v", err)
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
	if err := yk.SetManagementKey(newKey[:], newKey[:]); err == nil {
		t.Errorf("successfully changed management key with invalid key, expected error")
	}
	if err := yk.SetManagementKey(DefaultManagementKey, newKey[:]); err != nil {
		t.Fatalf("changing management key: %v", err)
	}
	if err := yk.SetManagementKey(newKey[:], DefaultManagementKey); err != nil {
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

	wantKey := []byte{
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
	} else if !bytes.Equal(*got.ManagementKey, wantKey) {
		t.Errorf("wanted management key=0x%x, got=0x%x", wantKey, got.ManagementKey)
	}
	if flags := testPivmanFlags(t, yk); flags != pivmanFlagKeyStored {
		t.Errorf("pivman flags after storing key, got=0x%x, want=0x%x", flags, pivmanFlagKeyStored)
	}

	if err := yk.SetMetadata(DefaultManagementKey, &Metadata{}); err != nil {
		t.Fatalf("clearing metadata: %v", err)
	}
	if flags := testPivmanFlags(t, yk); flags != 0 {
		t.Errorf("pivman flags after clearing key, got=0x%x, want=0x0", flags)
	}
}

// testPivmanFlags returns the flags in the pivman data object, or 0 if the
// object isn't set.
func testPivmanFlags(t *testing.T, yk *YubiKey) byte {
	t.Helper()
	obj, err := ykGetObject(yk.tx, objectPivmanData)
	if errors.Is(err, ErrNotFound) {
		return 0
	}
	if err != nil {
		t.Fatalf("getting pivman data: %v", err)
	}
	var p pivmanData
	if err := p.unmarshal(obj); err != nil {
		t.Fatalf("parsing pivman data: %v", err)
	}
	return p.flags
}

func TestMetadataPreservesPivmanData(t *testing.T) {
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

	// Pivman data with the PUK blocked flag set, as written by YubiKey
	// Manager. This only records the flag, the PUK isn't actually blocked.
	if err := yk.authManagementKey(DefaultManagementKey); err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	if err := ykPutObject(yk.tx, objectPivmanData, []byte{0x80, 0x03, 0x81, 0x01, 0x01}); err != nil {
		t.Fatalf("setting pivman data: %v", err)
	}

	key := []byte{
		0x09, 0xd9, 0x87, 0x81, 0xfb, 0xdc, 0xc9, 0xb6,
		0x91, 0xa2, 0x05, 0x80, 0x6e, 0xc0, 0xba, 0x84,
		0x31, 0xac, 0x0d, 0x9f, 0x59, 0xa5, 0x00, 0xad,
	}
	if err := yk.SetMetadata(DefaultManagementKey, &Metadata{ManagementKey: &key}); err != nil {
		t.Fatalf("setting metadata: %v", err)
	}
	if flags := testPivmanFlags(t, yk); flags != 0x01|pivmanFlagKeyStored {
		t.Errorf("pivman flags after storing key, got=0x%x, want=0x%x", flags, 0x01|pivmanFlagKeyStored)
	}
	if err := yk.SetMetadata(DefaultManagementKey, &Metadata{}); err != nil {
		t.Fatalf("clearing metadata: %v", err)
	}
	if flags := testPivmanFlags(t, yk); flags != 0x01 {
		t.Errorf("pivman flags after clearing key, got=0x%x, want=0x1", flags)
	}
}

func TestMetadataUnmarshal(t *testing.T) {
	data, _ := hex.DecodeString("881a891809d98781fbdcc9b691a205806ec0ba8431ac0d9f59a500ad")
	wantKey := []byte{
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
	if !bytes.Equal(gotKey, wantKey) {
		t.Errorf("(*Metadata).unmarshal, got key=0x%x, want key=0x%x", gotKey, wantKey)
	}
}

func TestMetadataMarshal(t *testing.T) {
	key := []byte{
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
	key := []byte{
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
	key := []byte{
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

func TestPivmanDataUnmarshal(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantFlags byte
		wantRest  string
	}{
		{"empty", "", 0, ""},
		{"key stored", "8003810102", pivmanFlagKeyStored, ""},
		{
			// PUK blocked, salt and PIN timestamp, as written by YubiKey Manager.
			"other fields",
			"801b8101018210000102030405060708090a0b0c0d0e0f830401020304",
			0x01,
			"8210000102030405060708090a0b0c0d0e0f830401020304",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, _ := hex.DecodeString(test.data)
			var p pivmanData
			if err := p.unmarshal(data); err != nil {
				t.Fatalf("parsing pivman data: %v", err)
			}
			if p.flags != test.wantFlags {
				t.Errorf("(*pivmanData).unmarshal, got flags=0x%x, want flags=0x%x", p.flags, test.wantFlags)
			}
			if got := hex.EncodeToString(p.rest); got != test.wantRest {
				t.Errorf("(*pivmanData).unmarshal, got rest=0x%s, want rest=0x%s", got, test.wantRest)
			}
		})
	}
}

func TestPivmanDataUnmarshalInvalid(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"wrong tag", "8803810102"},
		{"truncated", "80038101"},
		{"long flags", "800481020102"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, _ := hex.DecodeString(test.data)
			var p pivmanData
			if err := p.unmarshal(data); err == nil {
				t.Errorf("(*pivmanData).unmarshal(0x%s), expected error", test.data)
			}
		})
	}
}

func TestPivmanDataMarshal(t *testing.T) {
	rest, _ := hex.DecodeString("8210000102030405060708090a0b0c0d0e0f830401020304")
	tests := []struct {
		name string
		p    pivmanData
		want string
	}{
		{"empty", pivmanData{}, ""},
		{"key stored", pivmanData{flags: pivmanFlagKeyStored}, "8003810102"},
		{
			"other fields",
			pivmanData{flags: 0x01 | pivmanFlagKeyStored, rest: rest},
			"801b8101038210000102030405060708090a0b0c0d0e0f830401020304",
		},
		{
			// The flags are omitted when clear, like YubiKey Manager does.
			"no flags",
			pivmanData{rest: rest},
			"80188210000102030405060708090a0b0c0d0e0f830401020304",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hex.EncodeToString(test.p.marshal()); got != test.want {
				t.Errorf("(*pivmanData).marshal, got=0x%s, want=0x%s", got, test.want)
			}
		})
	}
}

func TestCardID(t *testing.T) {
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

	if _, err := yk.CardID(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("getting card id before setting it, got err=%v, want ErrNotFound", err)
	}

	for _, want := range []CardID{
		{GUID: [16]byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		}},
		// Setting the card id again replaces the old one.
		{GUID: [16]byte{
			0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80,
			0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00,
		}},
	} {
		if err := yk.SetCardID(DefaultManagementKey, &want); err != nil {
			t.Fatalf("setting card id: %v", err)
		}
		got, err := yk.CardID()
		if err != nil {
			t.Fatalf("getting card id: %v", err)
		}
		if got.GUID != want.GUID {
			t.Errorf("wanted guid=0x%x, got=0x%x", want.GUID, got.GUID)
		}
	}
}

func TestCardIDMarshal(t *testing.T) {
	// Generated by YubiKey Manager's generate_chuid() for the same GUID.
	want := "3019d4e739da739ced39ce739d836858210842108421c84210c3eb" +
		"34100102030405060708090a0b0c0d0e0f10" +
		"35083230333030313031" +
		"3e00" +
		"fe00"
	c := CardID{GUID: [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}}
	if got := hex.EncodeToString(c.marshal()); got != want {
		t.Errorf("(*CardID).marshal, got=0x%s, want=0x%s", got, want)
	}
}

func TestCardIDUnmarshal(t *testing.T) {
	wantGUID := [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	tests := []struct {
		name string
		data string
	}{
		{
			"yubikey manager",
			"3019d4e739da739ced39ce739d836858210842108421c84210c3eb" +
				"34100102030405060708090a0b0c0d0e0f10" +
				"35083230333030313031" +
				"3e00" +
				"fe00",
		},
		{
			// Optional fields from SP 800-73-4 and a signature, which aren't
			// interpreted.
			"other fields",
			"ee020100" + // Buffer Length
				"3019d4e739da739ced39ce739d836858210842108421c84210c3eb" +
				"310400000000" + // Agency Code
				"34100102030405060708090a0b0c0d0e0f10" +
				"35083230333030313031" +
				"3e03010203" + // Issuer Asymmetric Signature
				"fe00",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, _ := hex.DecodeString(test.data)
			var c CardID
			if err := c.unmarshal(data); err != nil {
				t.Fatalf("parsing card id: %v", err)
			}
			if c.GUID != wantGUID {
				t.Errorf("(*CardID).unmarshal, got guid=0x%x, want guid=0x%x", c.GUID, wantGUID)
			}
		})
	}
}

func TestCardIDUnmarshalInvalid(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"no guid", "3e00fe00"},
		{"short guid", "340f0102030405060708090a0b0c0d0e0f"},
		{"truncated guid", "34100102030405060708"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, _ := hex.DecodeString(test.data)
			var c CardID
			if err := c.unmarshal(data); err == nil {
				t.Errorf("(*CardID).unmarshal(0x%s), expected error", test.data)
			}
		})
	}
}
