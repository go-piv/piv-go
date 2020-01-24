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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/ericchiang/piv-go/piv"
)

const (
	agentFilepathCreds = "creds"
	agentFilepathAuth  = "auth.sock"
)

type config struct {
	home string
}

func newAgent(c config) (*agent, error) {
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

	return &agent{dir}, nil
}

type agent struct {
	dir string
}

func (a *agent) listCards() ([]uint32, error) {
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
	var serials []uint32
	for _, c := range creds {
		serials = append(serials, c.serial)
	}
	return serials, nil
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

type resetter struct {
	errors []error
	out    io.Writer
	prompt func() error
}

func (r *resetter) reset(serial uint32) error {
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("listing cards: %v", err)
	}
	for _, card := range cards {
		if !isYubiKey(card) {
			continue
		}
		ok, err := r.resetCard(card, serial)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	if len(r.errors) == 0 {
		return fmt.Errorf("card not found")
	}
	for _, err := range r.errors {
		fmt.Fprintln(r.out, err)
	}
	return fmt.Errorf("failed accessing cards")
}

func (r *resetter) errorf(format string, v ...interface{}) {
	r.errors = append(r.errors, fmt.Errorf(format, v...))
}

func (r *resetter) resetCard(card string, serial uint32) (bool, error) {
	yk, err := piv.Open(card)
	if err != nil {
		r.errorf("opening card %s: %v", card, err)
		return false, nil
	}
	defer yk.Close()

	s, err := yk.Serial()
	if err != nil {
		r.errorf("getting card serial number %s: %v", card, err)
		return false, nil
	}
	if s != serial {
		return false, nil
	}
	if r.prompt != nil {
		if err := r.prompt(); err != nil {
			return false, err
		}
	}
	if err := yk.Reset(); err != nil {
		return false, fmt.Errorf("resetting card: %v", err)
	}
	return true, nil
}
