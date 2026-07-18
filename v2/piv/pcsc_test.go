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
	"errors"
	"strings"
	"testing"
)

func runContextTest(t *testing.T, f func(t *testing.T, c *scContext)) {
	if !canModifyYubiKey {
		t.Skip("not running test that accesses yubikey, provide --wipe-yubikey flag")
	}
	ctx, err := newSCContext()
	if err != nil {
		t.Fatalf("creating context: %v", err)
	}
	defer func() {
		if err := ctx.Close(); err != nil {
			t.Errorf("closing context: %v", err)
		}
	}()
	f(t, ctx)
}

func TestContextClose(t *testing.T) {
	runContextTest(t, func(t *testing.T, c *scContext) {})
}

func TestContextListReaders(t *testing.T) {
	runContextTest(t, testContextListReaders)
}

func testContextListReaders(t *testing.T, c *scContext) {
	if _, err := c.ListReaders(); err != nil {
		t.Errorf("listing readers: %v", err)
	}
}

func runHandleTest(t *testing.T, f func(t *testing.T, h *scHandle)) {
	runContextTest(t, func(t *testing.T, c *scContext) {
		readers, err := c.ListReaders()
		if err != nil {
			t.Fatalf("listing smartcard readers: %v", err)
		}
		reader := ""
		for _, r := range readers {
			if strings.Contains(strings.ToLower(r), "yubikey") {
				reader = r
				break
			}
		}
		if reader == "" {
			t.Skip("could not find yubikey, skipping testing")
		}
		h, err := c.Connect(reader)
		if err != nil {
			t.Fatalf("connecting to %s: %v", reader, err)
		}
		defer func() {
			if err := h.Close(); err != nil {
				t.Errorf("disconnecting from handle: %v", err)
			}
		}()
		f(t, h)
	})
}

func TestHandle(t *testing.T) {
	runHandleTest(t, func(t *testing.T, h *scHandle) {})
}

func TestTransaction(t *testing.T) {
	runHandleTest(t, func(t *testing.T, h *scHandle) {
		tx, err := h.Begin()
		if err != nil {
			t.Fatalf("beginning transaction: %v", err)
		}
		if err := tx.Close(); err != nil {
			t.Fatalf("closing transaction: %v", err)
		}
	})
}

func TestErrors(t *testing.T) {
	tests := []struct {
		sw1, sw2      byte
		isErrNotFound bool
		isAuthErr     bool
		retries       int
		desc          string
	}{
		{0x68, 0x82, false, false, 0, "secure messaging not supported"},
		{0x63, 0x00, false, true, 0, "verification failed"},
		{0x63, 0xc0, false, true, 0, "verification failed (0 retries remaining)"},
		{0x63, 0xc1, false, true, 1, "verification failed (1 retry remaining)"},
		{0x63, 0xcf, false, true, 15, "verification failed (15 retries remaining)"},
		{0x63, 0x01, false, true, 1, "verification failed (1 retry remaining)"},
		{0x63, 0x0f, false, true, 15, "verification failed (15 retries remaining)"},
		{0x69, 0x83, false, true, 0, "authentication method blocked"},
		{0x6a, 0x82, true, false, 0, "data object or application not found"},
	}

	for _, tc := range tests {
		err := &apduErr{tc.sw1, tc.sw2}
		if errors.Is(err, ErrNotFound) != tc.isErrNotFound {
			var s string
			if !tc.isErrNotFound {
				s = " not"
			}
			t.Errorf("%q should%s be ErrNotFound", tc.desc, s)
		}

		var authErr AuthErr
		if errors.As(err, &authErr) != tc.isAuthErr {
			var s string
			if !tc.isAuthErr {
				s = " not"
			}
			t.Errorf("%q should%s be AuthErr", tc.desc, s)
		}
		if authErr.Retries != tc.retries {
			t.Errorf("%q retries should be %d, got %d", tc.desc, tc.retries, authErr.Retries)
		}
		if !strings.Contains(err.Error(), tc.desc) {
			t.Errorf("Error %v should contain text %v", err, tc.desc)
		}
	}
}

func TestSCError(t *testing.T) {
	// as32 returns rc as it arrives through a 32 bit signed C type (long on
	// 32 bit unix, int on darwin): the leading bit is read as a sign bit.
	as32 := func(rc uint32) int64 { return int64(int32(rc)) }

	tests := []struct {
		rc   int64
		desc string
	}{
		{0x8010000b, "the smart card cannot be accessed because of other connections outstanding"},
		{as32(0x8010000b), "the smart card cannot be accessed because of other connections outstanding"},
		{0x8010000c, "the operation requires a Smart Card, but no Smart Card is currently in the device"},
		{as32(0x8010000c), "the operation requires a Smart Card, but no Smart Card is currently in the device"},
		{0x80100069, "the smart card has been removed, so further communication is not possible"},
		{as32(0x80100069), "the smart card has been removed, so further communication is not possible"},
		{0x00000000, "no error was encountered"},
		{0x0000ffff, "unknown pcsc return code 0x0000ffff"},
		{as32(0x80100022), "unknown pcsc return code 0x80100022"},
	}

	for _, tc := range tests {
		e := newSCErr(tc.rc)
		if got := e.Error(); got != tc.desc {
			t.Errorf("return code 0x%08x: got %q, want %q", tc.rc, got, tc.desc)
		}
		// Callers compare against rc directly, so the field itself must hold
		// the positive code, not just render as one.
		if e.rc < 0 {
			t.Errorf("return code 0x%08x: rc field holds 0x%x, want the positive code", tc.rc, e.rc)
		}
	}
}
