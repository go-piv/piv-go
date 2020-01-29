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
	"fmt"
	"strings"
	"testing"

	"github.com/ericchiang/piv-go/internal/pivtest"
	"github.com/ericchiang/piv-go/piv"
)

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

func TestCmdReset(t *testing.T) {
	yk, cancel := newTestYubiKey(t)
	serial, err := yk.Serial()
	cancel()
	if err != nil {
		t.Fatalf("getting serial number: %v", err)
	}
	if err := cmdReset([]string{
		"--force",
		fmt.Sprintf("%08x", serial),
	}); err != nil {
		t.Errorf("failed to reset card: %v", err)
	}
}
