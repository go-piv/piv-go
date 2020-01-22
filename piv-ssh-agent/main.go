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
	"io"
	"os"
	"strings"

	"github.com/ericchiang/piv-go/piv"
)

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: piv-ssh-agent

An SSH agent that stores SSH keys on a YubiKey.

Subcommands:

    init  Initialize a key.
    list  List all available YubiKeys and which ones have been initialized.
	reset Reset the PIV applet on a YubiKey.
    run   Run the agent and begin listening for requests on a socket.

`)
}

func usageList(w io.Writer) {
	fmt.Fprint(w, `Usage: piv-ssh-agent list

List all available YubiKeys.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "-h", "--help":
		usage(os.Stdout)
		os.Exit(0)
	case "list":
		cmdList(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unrecognized command: %s\n", os.Args[1])
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func contains(sli []uint32, ele uint32) bool {
	for _, e := range sli {
		if e == ele {
			return true
		}
	}
	return false
}

func cmdList(args []string) error {
	if len(args) > 0 {
		if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
			usageList(os.Stdout)
			return nil
		}
		return fmt.Errorf("list subcommand takes no arguments")
	}
	a, err := newAgent(config{})
	if err != nil {
		return fmt.Errorf("initializing agent: %v", err)
	}
	managedCards, err := a.listCards()
	if err != nil {
		return fmt.Errorf("fetching cards managed by agent: %v", err)
	}
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("listing cards: %v", err)
	}
	gotErr := false
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}
		yk, err := piv.Open(card)
		if err != nil {
			fmt.Println(card, err)
			continue
		}
		serial, err := yk.Serial()
		yk.Close()
		if err != nil {
			fmt.Println(card, err)
			continue
		}
		if contains(managedCards, serial) {
			fmt.Printf("%s: %x\n", card, serial)
		} else {
			fmt.Printf("%s (uninitialized): %x\n", card, serial)
		}
	}
	if gotErr {
		return fmt.Errorf("failed to query cards")
	}
	return nil
}
