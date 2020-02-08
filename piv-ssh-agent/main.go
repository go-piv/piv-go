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
	"os/user"
	"path/filepath"

	"github.com/ericchiang/piv-go/piv"
)

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: piv-ssh-agent

An SSH agent that stores SSH keys on a YubiKey.

Subcommands:

    add   Initialize a key on a YubiKey.
    list  List all available YubiKeys and which ones have been initialized.
    reset Reset the PIV applet on a YubiKey.
    serve Run the agent and begin listening for requests on a socket.

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

func usageAdd(w io.Writer) {
	fmt.Fprint(w, `Usage: piv-ssh-agent add [flags] [serial number]

Initialize a YubiKey with a random PIN, PUK, and Management Key, and generate
an SSH key on the card.

The YubiKey must not have been initialized or had its credentials changed. To
wipe card with non-default values, use the "reset" subcommand.

Example:

    $ piv-ssh-agent list
    Yubico YubiKey OTP+FIDO+CCID: 005d404d
    $ piv-ssh-agent add 005d404d

`)
}

func usageServe(w io.Writer) {
	fmt.Fprint(w, `Usage: piv-ssh-agent serve [flags]

Begin serving the SSH agent socket.

Flags:

    --sock  Path to agent socket. Defaults to /run/user/$UID/piv-ssh-agent/auth.sock

Example:

    $ piv-ssh-agent serve
	// In another tab
	$ export SSH_AUTH_SOCK=/run/user/$UID/piv-ssh-agent/auth.sock
	$ ssh-add -L

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
	case "add":
		err = cmdAdd(os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "reset":
		err = cmdReset(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unrecognized command: %s\n", os.Args[1])
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func cmdList(args []string) error {
	if len(args) > 0 {
		if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
			usageList(os.Stdout)
			return nil
		}
		return fmt.Errorf("list subcommand takes no arguments")
	}
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("listing cards: %v", err)
	}
	found := false
	for _, card := range cards {
		if !isYubiKey(card) {
			continue
		}
		yk, err := piv.Open(card)
		if err != nil {
			return fmt.Errorf("opening card %s: %v", card, err)
		}
		serial, err := yk.Serial()
		yk.Close()
		if err != nil {
			return fmt.Errorf("getting serial number of card %s: %v", card, err)
		}
		fmt.Printf("%s: %08x\n", card, serial)
		found = true
	}
	if !found {
		fmt.Fprintln(os.Stderr, "[no yubikeys found]")
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

func cmdAdd(args []string) error {
	fs := newFlagSet()
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usageAdd(os.Stdout)
			return nil
		}
		return fmt.Errorf("parsing flags: %v", err)
	}
	switch len(fs.Args()) {
	case 0:
		return fmt.Errorf("usage: piv-ssh-agent add [flags] [serial number]")
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

func cmdServe(args []string) error {
	var sockPath string
	fs := newFlagSet()
	fs.StringVar(&sockPath, "", "", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usageServe(os.Stdout)
			return nil
		}
		return fmt.Errorf("parsing flags: %v", err)
	}
	a, err := newAgent(config{})
	if err != nil {
		return fmt.Errorf("initializing agent: %v", err)
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("usage: piv-ssh-agent serve [flags] [serial number]")
	}
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("determining current user: %v", err)
	}
	if sockPath == "" {
		sockPath = filepath.Join("/run/user", u.Uid, "piv-ssh-agent/auth.sock")
	}
	l, err := a.listen(sockPath)
	if err != nil {
		return err
	}
	defer l.close()
	return l.wait()
}
