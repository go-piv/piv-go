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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := ioutil.WriteFile(p, data, 0644); err != nil {
		t.Fatalf("writing file: %v", err)
	}
}

func TestBuildMD5Sums(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("new temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	f1 := filepath.Join(tempDir, "hi")
	f2 := filepath.Join(tempDir, "bye")

	writeFile(t, f1, []byte("foo"))
	writeFile(t, f2, []byte("bar"))

	files := []debFile{
		{path: f2, as: "/usr/bin/bye"},
		{path: f1, as: "/usr/bin/hi"},
	}

	got, err := buildMD5Sums(files)
	if err != nil {
		t.Fatalf("buildMD5Sums(): %v", err)
	}
	want := []byte(`37b51d194a7513e45b56f6524f2d51f2  usr/bin/bye
acbd18db4cc2f85cedef654fccc4a4d8  usr/bin/hi
`)
	if !bytes.Equal(got, want) {
		t.Fatalf("buildMD5Sum(): got=%s, want=%s", got, want)
	}
}

func wantNextTAR(t *testing.T, tr *tar.Reader, path string, isDir bool) {
	t.Helper()
	h, err := tr.Next()
	if err != nil {
		t.Errorf("want=%s, read header: %v", path, err)
		return
	}
	gotIsDir := h.Typeflag == tar.TypeDir
	if h.Name != path || gotIsDir != isDir {
		t.Errorf("got=%s (isDir=%v), want=%s (isDir=%v)", h.Name, gotIsDir, path, isDir)
	}
}

func TestWriteData(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("new temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	f1 := filepath.Join(tempDir, "hi")
	f2 := filepath.Join(tempDir, "bye")

	writeFile(t, f1, []byte("foo"))
	writeFile(t, f2, []byte("bar"))

	files := []debFile{
		{path: f2, as: "/usr/bin/bye"},
		{path: f1, as: "/usr/bin/hi"},
	}
	mod := time.Now()
	out := &bytes.Buffer{}
	if err := writeData(files, mod, out); err != nil {
		t.Fatalf("write data: %v", err)
	}
	gzr, err := gzip.NewReader(out)
	if err != nil {
		t.Fatalf("create gzip reader: %v", err)
	}
	tr := tar.NewReader(gzr)

	wantNextTAR(t, tr, "./", true)
	wantNextTAR(t, tr, "./usr/", true)
	wantNextTAR(t, tr, "./usr/bin/", true)
	wantNextTAR(t, tr, "./usr/bin/bye", false)
	wantNextTAR(t, tr, "./usr/bin/hi", false)

	if err := gzr.Close(); err != nil {
		t.Errorf("check gzip checksum: %v", err)
	}
}
