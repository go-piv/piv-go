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
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/ericchiang/piv-go/piv"
)

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: piv-ssh-agent

An SSH agent that stores SSH keys on a YubiKey.

Subcommands:

    init  Initialize a YubiKey.
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

func usageReset(w io.Writer) {
	fmt.Fprint(w, `Usage: piv-ssh-agent reset [flags] [serial number]

Reset the YubiKey's PIV applet. This doesn't effect other applets cards, such
as GPG and U2F/FIDO2 data.

Flags:

    --force  Reset the applet without prompting first.

Example:

    $ piv-ssh-agent list
    Yubico YubiKey OTP+FIDO+CCID: 005d404d
    $ piv-ssh-agent reset 005d404d
    Reset PIV applet? [y/n]: y

`)
}

func usageInit(w io.Writer) {
	fmt.Fprint(w, `Usage: piv-ssh-agent init [flags] [serial number]

Initialize a YubiKey with a random PIN, PUK, and Management Key, and generate
an SSH key on the card.

The YubiKey must not have been initialized or had its credentials changed. To
wipe card with non-default values, use the "reset" subcommand.

Example:

    $ piv-ssh-agent list
    Yubico YubiKey OTP+FIDO+CCID: 005d404d
    $ piv-ssh-agent init 005d404d

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
		err = cmdList(os.Args[2:])
	case "reset":
		err = cmdReset(os.Args[2:])
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
	managedCards, err := a.listManagedCards()
	if err != nil {
		return fmt.Errorf("fetching cards managed by agent: %v", err)
	}
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("listing cards: %v", err)
	}
	gotErr := false
	for _, card := range cards {
		if !isYubiKey(card) {
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
			fmt.Printf("%s: %08x\n", card, serial)
		} else {
			fmt.Printf("%s (uninitialized): %08x\n", card, serial)
		}
	}
	if gotErr {
		return fmt.Errorf("failed to query cards")
	}
	return nil
}

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.SetOutput(ioutil.Discard)
	return fs
}

func cmdReset(args []string) error {
	var force bool
	fs := newFlagSet()
	fs.BoolVar(&force, "force", false, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usageReset(os.Stdout)
			return nil
		}
		return fmt.Errorf("parsing flags: %v", err)
	}
	switch len(fs.Args()) {
	case 0:
		return fmt.Errorf("usage: piv-ssh-agent reset [flags] [serial number]")
	case 1:
	default:
		return fmt.Errorf("invalid number of arguments")
	}
	s := fs.Args()[0]
	serial, ok := parseSerial([]byte(s))
	if !ok {
		return fmt.Errorf("invalid serial number: %s", s)
	}
	a, err := newAgent(config{})
	if err != nil {
		return fmt.Errorf("initializing agent: %v", err)
	}
	return a.reset(force, serial)
}

func cmdInit(args []string) error {
	fs := newFlagSet()
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usageInit(os.Stdout)
			return nil
		}
		return fmt.Errorf("parsing flags: %v", err)
	}
	switch len(fs.Args()) {
	case 0:
		return fmt.Errorf("usage: piv-ssh-agent init [flags] [serial number]")
	case 1:
	default:
		return fmt.Errorf("invalid number of arguments")
	}

	s := fs.Args()[0]
	serial, ok := parseSerial([]byte(s))
	if !ok {
		return fmt.Errorf("invalid serial number: %s", s)
	}
	a, err := newAgent(config{})
	if err != nil {
		return fmt.Errorf("initializing agent: %v", err)
	}
	return a.initCard(serial)
}
