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
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/bertlv"
)

type scErr struct {
	// rc holds the return code for a given call.
	rc int64
}

func (e *scErr) Error() string {
	if msg, ok := pcscErrMsgs[e.rc]; ok {
		return msg
	}
	return fmt.Sprintf("unknown pcsc return code 0x%08x", e.rc)
}

// AuthErr is an error indicating an authentication error occurred (wrong PIN or blocked).
type AuthErr struct {
	// Retries is the number of retries remaining if this error resulted from a retriable
	// authentication attempt.  If the authentication method is blocked or does not support
	// retries, this will be 0.
	Retries int
}

func retries(n int) string {
	r := "retries"
	if n == 1 {
		r = "retry"
	}
	return fmt.Sprintf("verification failed (%d %s remaining)", n, r)
}

func (v AuthErr) Error() string {
	return retries(v.Retries)
}

// ErrNotFound is returned when the requested object on the smart card is not found.
var ErrNotFound = errors.New("data object or application not found")

// apduErr is an error interacting with the PIV application on the smart card.
// This error may wrap more accessible errors, like ErrNotFound or an instance
// of AuthErr, so callers are encouraged to use errors.Is and errors.As for
// these common cases.
type apduErr struct {
	sw1 byte
	sw2 byte
}

// Status returns the Status Word returned by the card command.
func (a *apduErr) Status() uint16 {
	return uint16(a.sw1)<<8 | uint16(a.sw2)
}

func (a *apduErr) Error() string {
	var msg string
	if u := a.Unwrap(); u != nil {
		msg = u.Error()
	}

	if a.sw1 == 0x61 {
		msg = fmt.Sprintf("0x%02x bytes available", a.sw2)
	}

	if a.sw1 == 0x63 && a.sw2&0xf0 == 0xc0 {
		msg = retries(int(a.Status() & 0x0f))
	}

	switch a.Status() {
	case 0x6581:
		msg = "decryption failed"

	case 0x6600:
		msg = "security-related issues (reserved for UIF in this application)"

	case 0x6700:
		msg = "wrong length (Lc and/or Le)"

	// 0x6300 is "verification failed", represented as AuthErr{0}
	// 0x63Cn is "verification failed" with retry, represented as AuthErr{n}
	case 0x6881:
		msg = "logical channel not supported"
	case 0x6882:
		msg = "secure messaging not supported"
	case 0x6883:
		msg = "last command of the chain expected"
	case 0x6884:
		msg = "command chaining not supported"

	case 0x6982:
		// Security status not satisfied PW wrong PW not checked (command not allowed) Secure messaging incorrect (checksum and/or cryptogram)
		msg = "security status not satisfied"
	case 0x6983:
		// This will also be AuthErr{0} but we override the message here
		// so that it's clear that the reason is a block rather than a simple
		// failed authentication verification.
		// Authentication method blocked PW blocked (error counter zero)
		msg = "authentication method blocked"
	case 0x6985:
		msg = "Condition of use not satisfied"
	case 0x6987:
		// Expected secure messaging DOs missing (e. g. SM-key)
		msg = "expected secure messaging data objects are missing"
	case 0x6988:
		// SM data objects incorrect (e. g. wrong TLV-structure in command data)
		msg = "secure messaging data objects are incorrect"
	case 0x6a80:
		msg = "incorrect parameter in command data field"
	case 0x6a81:
		msg = "function not supported"
	// 0x6a82 is "data object or application not found" aka ErrNotFound
	case 0x6a84:
		msg = "not enough memory"
	case 0x6a86:
		msg = "incorrect parameter in P1 or P2"
	case 0x6a88:
		// Referenced data, reference data or DO not found
		msg = "referenced data or reference data not found"
	case 0x6b00:
		msg = "Wrong parameters P1-P2"
	case 0x6d00:
		msg = "Instruction code (INS) not supported or invalid"
	case 0x6e00:
		msg = "Class (CLA) not supported"
	case 0x6f00:
		msg = "No precise diagnosis"
	case 0x9000:
		msg = "Command correct"
	}

	if msg != "" {
		msg = ": " + msg
	}
	return fmt.Sprintf("smart card error %04x%s", a.Status(), msg)
}

// Unwrap retrieves an accessible error type, if able.
func (a *apduErr) Unwrap() error {
	st := a.Status()
	switch {
	case st == 0x6a82:
		return ErrNotFound
	case st == 0x6300:
		return AuthErr{0}
	case st == 0x6982:
		// odd, gpg returns 0x6982 but no retries number.
		return AuthErr{-1}
	case st == 0x6983:
		return AuthErr{0}
	case st&0xfff0 == 0x63c0:
		return AuthErr{int(st & 0xf)}
	case st&0xfff0 == 0x6300:
		// Older YubiKeys sometimes return sw1=0x63 and sw2=0x0N to indicate the
		// number of retries. This isn't spec compliant, but support it anyway.
		//
		// https://github.com/go-piv/piv-go/issues/60
		return AuthErr{int(st & 0xf)}
	}
	return nil
}

type apdu struct {
	instruction byte
	param1      byte
	param2      byte
	data        []byte
}

func (t *scTx) Transmit(d apdu) ([]byte, error) {
	if t.debug {
		fmt.Printf("Transmit: [%s]\n", bertlv.MakeJSONString(d))
	}

	data := d.data
	var resp []byte
	const maxAPDUDataSize = 0xff
	for len(data) > maxAPDUDataSize {
		req := make([]byte, 5+maxAPDUDataSize)
		req[0] = 0x10 // ISO/IEC 7816-4 5.1.1
		req[1] = d.instruction
		req[2] = d.param1
		req[3] = d.param2
		req[4] = 0xff
		copy(req[5:], data[:maxAPDUDataSize])
		data = data[maxAPDUDataSize:]
		_, r, err := t.transmit(req)
		if err != nil {
			if t.debug {
				fmt.Printf("Transmit failed: %v\nreq:\n%s\nresp:\n%s\n", err, hex.Dump(req), hex.Dump(r))
			}

			return nil, fmt.Errorf("transmitting initial chunk %w", err)
		}
		resp = append(resp, r...)
	}

	req := make([]byte, 5+len(data))
	req[1] = d.instruction
	req[2] = d.param1
	req[3] = d.param2
	req[4] = byte(len(data))
	copy(req[5:], data)
	hasMore, r, err := t.transmit(req)
	if err != nil {
		if t.debug {
			fmt.Printf("Transmit failed: %v hasmore: %t\nreq:\n%s\nresp:\n%s\n", err, hasMore, hex.Dump(req), hex.Dump(r))
		}

		return nil, err
	}
	resp = append(resp, r...)

	for hasMore {
		req := make([]byte, 5)
		req[1] = insGetResponseAPDU
		var r []byte
		hasMore, r, err = t.transmit(req)
		if err != nil {
			if t.debug {
				fmt.Printf("Transmit failed: %v hasmore: %t\nreq:\n%s\nresp:\n%s\n", err, hasMore, hex.Dump(req), hex.Dump(r))
			}

			return nil, fmt.Errorf("reading further response: %w", err)
		}
		resp = append(resp, r...)
	}

	if t.debug {
		fmt.Printf("Response:\n%s\n", hex.Dump(resp[:]))
	}

	return resp, nil
}
