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

	major, minor, err := c.version()
	if err != nil {
		t.Fatalf("getting client version: %v", err)
	}
	t.Log(major, minor)
}

func TestListReaders(t *testing.T) {
	c, err := NewClient(context.Background(), &Config{})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer c.Close()

	readers, err := c.readers()
	if err != nil {
		t.Fatalf("listing readers: %v", err)
	}
	t.Log(readers)
}
