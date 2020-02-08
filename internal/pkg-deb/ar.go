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
	"fmt"
	"io"
	"strconv"
	"time"
)

type limitWriter struct {
	w io.Writer
	n int64
}

func limitedWriter(w io.Writer, n int64) *limitWriter {
	return &limitWriter{w, n}
}

func (l *limitWriter) Write(b []byte) (int, error) {
	n := int64(len(b))
	if n > l.n {
		return 0, fmt.Errorf("write too large")
	}
	l.n = l.n - n
	return l.w.Write(b)
}

const (
	arMagic = "!<arch>\n"
)

type arHeader struct {
	filename string
	mod      time.Time
	size     int64
}

func setField(b []byte, s string) error {
	if len(s) > len(b) {
		return fmt.Errorf("field too long")
	}
	for i := 0; i < len(b); i++ {
		if i < len(s) {
			b[i] = s[i]
		} else {
			b[i] = 0x20
		}
	}
	return nil
}

func (h *arHeader) marshal() ([60]byte, error) {
	var b [60]byte
	if err := setField(b[0:16], h.filename); err != nil {
		return b, fmt.Errorf("filename: %v", err)
	}
	mod := strconv.FormatInt(h.mod.Unix(), 10)
	if err := setField(b[16:16+12], mod); err != nil {
		return b, fmt.Errorf("mod: %v", err)
	}
	setField(b[28:28+6], "0")      // owner ID
	setField(b[34:34+6], "0")      // group ID
	setField(b[40:40+8], "100644") // file mode
	size := strconv.FormatInt(h.size, 10)
	if err := setField(b[48:48+10], size); err != nil {
		return b, fmt.Errorf("size: %v", err)
	}
	b[58] = 0x60
	b[59] = 0x0A
	return b, nil
}

type arWriter struct {
	magicWritten bool
	needPadding  bool

	w  io.Writer
	lw *limitWriter
}

func newARWriter(w io.Writer) *arWriter {
	return &arWriter{w: w}
}

func (a *arWriter) flush() error {
	if a.lw != nil && a.lw.n != 0 {
		return fmt.Errorf("not enough data written for last header")
	}
	if a.needPadding {
		if _, err := io.WriteString(a.w, "\n"); err != nil {
			return fmt.Errorf("write padding: %v", err)
		}
	}
	return nil
}

func (a *arWriter) WriteHeader(h *arHeader) error {
	if !a.magicWritten {
		if _, err := io.WriteString(a.w, arMagic); err != nil {
			return fmt.Errorf("write header: %v", err)
		}
		a.magicWritten = true
	}
	if err := a.flush(); err != nil {
		return err
	}
	b, err := h.marshal()
	if err != nil {
		return err
	}
	if _, err := a.w.Write(b[:]); err != nil {
		return err
	}
	a.lw = limitedWriter(a.w, h.size)
	a.needPadding = h.size%2 == 1
	return nil
}

func (a *arWriter) Write(b []byte) (int, error) {
	return a.lw.Write(b)
}

func (a *arWriter) Close() error {
	return a.flush()
}
