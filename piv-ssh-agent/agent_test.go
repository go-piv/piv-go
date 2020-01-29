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
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ericchiang/piv-go/internal/pivtest"
	"github.com/ericchiang/piv-go/piv"
)

func newTestAgent(t *testing.T) (*agent, func()) {
	tempdir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	cleanup := func() {
		if err := os.RemoveAll(tempdir); err != nil {
			t.Errorf("cleaning up temp dir: %v", err)
		}
	}
	a, err := newAgent(config{home: tempdir})
	if err != nil {
		cleanup()
		t.Fatalf("new agent: %v", err)
	}
	return a, cleanup
}

func newTestYubiKeySerial(t *testing.T) uint32 {
	yk, close := newTestYubiKey(t)
	serial, err := yk.Serial()
	close()
	if err != nil {
		t.Fatalf("getting serial number: %v", err)
	}
	return serial
}

func newTestYubiKey(t *testing.T) (*piv.YubiKey, func()) {
	cards, err := piv.Cards()
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
		yk, err := piv.Open(card)
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

func TestGenerateCreds(t *testing.T) {
	for i := 0; i < 100; i++ {
		pin, puk, key, err := generateCreds(rand.Reader)
		if err != nil {
			t.Fatalf("generating creds: %v", err)
		}
		if len(pin) != 6 {
			t.Errorf("expected 6 digit pin, got %s", pin)
		}
		if len(puk) != 8 {
			t.Errorf("expected 8 digit puk, got %s", puk)
		}
		if key == [24]byte{} {
			// test will flake 1/2^(24*8) times run
			t.Errorf("key wasn't initialized")
		}
	}
}

func TestCmdInit(t *testing.T) {
	serial := newTestYubiKeySerial(t)
	a, cleanup := newTestAgent(t)
	defer cleanup()

	if err := a.reset(true, serial); err != nil {
		t.Fatalf("resetting yubikey: %v", err)
	}
	if err := a.initCard(serial); err != nil {
		t.Fatalf("initializing card: %v", err)
	}
}

func TestCmdReset(t *testing.T) {
	serial := newTestYubiKeySerial(t)
	a, cleanup := newTestAgent(t)
	defer cleanup()
	if err := a.reset(true, serial); err != nil {
		t.Fatalf("resetting yubikey: %v", err)
	}
}

func TestListCreds(t *testing.T) {
	a, cleanup := newTestAgent(t)
	defer cleanup()

	p := filepath.Join(a.dir, agentFilepathCreds)
	if err := ioutil.WriteFile(p, []byte(`11112222 123456
ffffaaaa 654321
`), 0600); err != nil {
		t.Fatalf("writing creds file: %v", err)
	}

	want := []uint32{
		0x11112222, 0xffffaaaa,
	}
	got, err := a.listManagedCards()
	if err != nil {
		t.Fatalf("listing cards: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got=%x, want=%x", got, want)
	}
}

func TestListCredsEmpty(t *testing.T) {
	a, cleanup := newTestAgent(t)
	defer cleanup()

	cards, err := a.listManagedCards()
	if err != nil {
		t.Fatalf("listing cards: %v", err)
	}
	if len(cards) != 0 {
		t.Errorf("expected no cards, got: %x", cards)
	}
}

func TestParseCredentials(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    []credential
		wantErr bool
	}{
		{
			name: "Cred",
			data: `
				11111111 123456
			`,
			want: []credential{
				{
					serial: 0x11111111,
					pin:    "123456",
				},
			},
		},
		{
			name: "Creds",
			data: `
				11111111 123456
				ffff0000 090909
			`,
			want: []credential{
				{
					serial: 0x11111111,
					pin:    "123456",
				},
				{
					serial: 0xffff0000,
					pin:    "090909",
				},
			},
		},
		{
			name: "InvalidSerial",
			data: `
				11111111 123456
				fffff0000 090909
			`,
			wantErr: true,
		},
		{
			name: "InvalidPIN",
			data: `
				11111111 123456
				ffff0000 09090a
			`,
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseCredentials([]byte(test.data))
			gotErr := err != nil
			if test.wantErr != gotErr || !reflect.DeepEqual(test.want, got) {
				t.Errorf("parseCredentials: got=(creds=%v, err=%v), want=(creds=%v, wantErr=%v)",
					got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestMarshalCredentials(t *testing.T) {

	want := []byte(`11111111 123456
ffff0000 090909
`)
	got := marshalCredentials([]credential{
		{
			serial: 0x11111111,
			pin:    "123456",
		},
		{
			serial: 0xffff0000,
			pin:    "090909",
		},
	})
	if !bytes.Equal(want, got) {
		t.Errorf("got=%s, want=%s", got, want)
	}
}

func TestMarshalParseCredentials(t *testing.T) {
	want := []credential{
		{
			serial: 0x11111111,
			pin:    "123456",
		},
		{
			serial: 0xffff0000,
			pin:    "090909",
		},
	}
	got, err := parseCredentials(marshalCredentials(want))
	if err != nil {
		t.Fatalf("parsing credentials: %v", err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("got=%v, want=%v", got, want)
	}
}
