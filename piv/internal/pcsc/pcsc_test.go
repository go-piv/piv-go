// Copyright 2021 Google LLC
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

package pcsc

import (
	"context"
	"testing"
)

func TestVersion(t *testing.T) {
	c, err := NewClient(context.Background(), &Config{})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	if err := c.checkVersion(); err != nil {
		t.Fatalf("checking client client version: %v", err)
	}
}

func TestListReaders(t *testing.T) {
	c, err := NewClient(context.Background(), &Config{})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	if _, err := c.Readers(); err != nil {
		t.Fatalf("listing readers: %v", err)
	}
}

func TestNewContext(t *testing.T) {
	c, err := NewClient(context.Background(), &Config{})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	ctx, err := c.NewContext()
	if err != nil {
		t.Fatalf("create context: %v", err)
	}
	if err := ctx.Close(); err != nil {
		t.Fatalf("close context: %v", err)
	}
}

func TestConnect(t *testing.T) {
	c, err := NewClient(context.Background(), &Config{})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	ctx, err := c.NewContext()
	if err != nil {
		t.Fatalf("create context: %v", err)
	}
	defer func() {
		if err := ctx.Close(); err != nil {
			t.Fatalf("close context: %v", err)
		}
	}()

	readers, err := c.Readers()
	if err != nil {
		t.Fatalf("listing readers: %v", err)
	}
	if len(readers) == 0 {
		t.Skipf("no readers available for test")
	}
	reader := readers[0]

	card, err := ctx.Connect(reader, Exclusive)
	if err != nil {
		t.Fatalf("new card: %v", err)
	}
	if err := card.Close(); err != nil {
		t.Fatalf("close card: %v", err)
	}
}

func TestBeginTransaction(t *testing.T) {
	c, err := NewClient(context.Background(), &Config{})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	ctx, err := c.NewContext()
	if err != nil {
		t.Fatalf("create context: %v", err)
	}
	defer func() {
		if err := ctx.Close(); err != nil {
			t.Fatalf("close context: %v", err)
		}
	}()

	readers, err := c.Readers()
	if err != nil {
		t.Fatalf("listing readers: %v", err)
	}
	if len(readers) == 0 {
		t.Skipf("no readers available for test")
	}
	reader := readers[0]
	card, err := ctx.Connect(reader, Exclusive)
	if err != nil {
		t.Fatalf("new card: %v", err)
	}
	defer func() {
		if err := card.Close(); err != nil {
			t.Fatalf("close card: %v", err)
		}
	}()
	if err := card.BeginTransaction(); err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	if err := card.EndTransaction(); err != nil {
		t.Fatalf("end transaction: %v", err)
	}
}
