package piv

import (
	"strings"
	"testing"
)

func runContextTest(t *testing.T, f func(t *testing.T, c *scContext)) {
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
			if strings.Contains(r, "Yubikey") {
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
