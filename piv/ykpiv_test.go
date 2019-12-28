package piv

import "testing"

func testGetVersion(t *testing.T, h *scHandle) {
	tx, err := h.Begin()
	if err != nil {
		t.Fatalf("new transaction: %v", err)
	}
	defer tx.Close()
	if err := ykSelectApplication(tx); err != nil {
		t.Fatalf("selecting application: %v", err)
	}
	v, err := ykVersion(tx)
	if err != nil {
		t.Fatalf("listing version: %v", err)
	}
	t.Logf("%#v", v)
}

func TestGetVersion(t *testing.T) { runHandleTest(t, testGetVersion) }
