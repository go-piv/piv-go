package piv

import "testing"

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
	readers, err := c.ListReaders()
	if err != nil {
		t.Errorf("listing readers: %v", err)
	}
	t.Log(readers)
}
