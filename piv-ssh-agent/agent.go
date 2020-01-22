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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const (
	credsFilepath = "creds"
	authFilepath  = "auth.sock"
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
	p := filepath.Join(a.dir, credsFilepath)
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

func parseCredentials(b []byte) ([]credential, error) {
	var creds []credential
	for i, line := range bytes.Split(b, []byte{'\n'}) {
		parts := bytes.Fields(line)
		if len(parts) < 2 {
			continue
		}
		if len(parts[0]) != 8 {
			return nil, fmt.Errorf("line %d, invalid serial number", i+1)
		}
		var s [4]byte
		if _, err := hex.Decode(s[:], parts[0]); err != nil {
			return nil, fmt.Errorf("line %d, invalid serial number: %v", i+1, err)
		}
		serial := binary.BigEndian.Uint32(s[:])
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
