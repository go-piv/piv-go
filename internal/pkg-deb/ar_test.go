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
	"bytes"
	"io/ioutil"
	"testing"
	"time"
)

func TestARHeaderMarshal(t *testing.T) {
	mod := time.Date(2020, time.February, 22, 4, 32, 33, 0, time.UTC)
	h := arHeader{
		filename: "debian-binary",
		mod:      mod,
		size:     2,
	}
	got, err := h.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	want := []byte("debian-binary   ")
	want = append(want, []byte("1582345953  ")...)
	want = append(want, []byte("0     ")...)
	want = append(want, []byte("0     ")...)
	want = append(want, []byte("100644  ")...)
	want = append(want, []byte("2         ")...)
	want = append(want, []byte("`\n")...)

	if !bytes.Equal(got[:], want) {
		t.Fatalf("marshal header, got=%s, want=%s", got, want)
	}
}

func TestLimitedWriter(t *testing.T) {
	w := limitedWriter(ioutil.Discard, 10)
	if _, err := w.Write([]byte("012345")); err != nil {
		t.Errorf("wrote less than limit: %v", err)
	}
	if _, err := w.Write([]byte("6789")); err != nil {
		t.Errorf("wrote limit: %v", err)
	}
	if _, err := w.Write([]byte("01")); err == nil {
		t.Errorf("wrote more than limit, got no error")
	}
}
