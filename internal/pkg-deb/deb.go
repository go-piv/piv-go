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

// The pkg-deb command is a self-contained tool for building Debian archives.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"
)

type filesFlag struct {
	files []debFile
}

func (d *filesFlag) Set(s string) error {
	parts := strings.Split(s, "=")
	if len(parts) != 2 {
		return fmt.Errorf("expected key=val")
	}
	p := parts[0]
	as := parts[1]
	if !path.IsAbs(as) {
		return fmt.Errorf("path to write to must be absolute: %s", as)
	}
	d.files = append(d.files, debFile{p, as})
	return nil
}

func (d *filesFlag) String() string {
	return fmt.Sprintf("%s", d.files)
}

func (d *filesFlag) Get() interface{} {
	return d.files
}

func main() {
	l := debLoader{}
	files := filesFlag{}
	out := ""

	flag.StringVar(&l.control, "control", "",
		"Specify the control file for the deb archive.")
	flag.StringVar(&l.preinst, "preinst", "",
		"Specify the preinst file for the deb archive.")
	flag.StringVar(&l.postinst, "postinst", "",
		"Specify the postinst file for the deb archive.")
	flag.StringVar(&l.prerm, "prerm", "",
		"Specify the prerm file for the deb archive.")
	flag.StringVar(&l.postrm, "postrm", "",
		"Specify the postrm file for the deb archive.")
	flag.StringVar(&out, "out", "",
		"Path to write the file to.")
	flag.Var(&files, "file",
		"Provide files to write to the deb.")
	flag.Parse()

	var outFile io.Writer = os.Stdout
	if out != "" {
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open output file:", err)
		}
		defer f.Close()
		outFile = f
	}

	l.files = files.files
	if err := l.build(outFile); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type debFile struct {
	path string
	as   string
}

func (d debFile) String() string {
	return fmt.Sprintf("%s=%s", d.path, d.as)
}

type debLoader struct {
	control  string
	preinst  string
	postinst string
	prerm    string
	postrm   string

	files []debFile
}

func readFile(filepath string) ([]byte, error) {
	if filepath == "" {
		return nil, nil
	}
	return ioutil.ReadFile(filepath)
}

func (d *debLoader) build(w io.Writer) error {
	control, err := readFile(d.control)
	if err != nil {
		return fmt.Errorf("read control: %v", err)
	}
	preinst, err := readFile(d.preinst)
	if err != nil {
		return fmt.Errorf("read preinst: %v", err)
	}
	postinst, err := readFile(d.postinst)
	if err != nil {
		return fmt.Errorf("read postinst: %v", err)
	}
	prerm, err := readFile(d.prerm)
	if err != nil {
		return fmt.Errorf("read prerm: %v", err)
	}
	postrm, err := readFile(d.postrm)
	if err != nil {
		return fmt.Errorf("read postrm: %v", err)
	}

	return (&deb{
		control:  control,
		preinst:  preinst,
		postinst: postinst,
		prerm:    prerm,
		postrm:   postrm,
		files:    d.files,
		mod:      time.Now(),
	}).build(w)
}

type deb struct {
	control   []byte
	conffiles []string
	preinst   []byte
	postinst  []byte
	prerm     []byte
	postrm    []byte

	files []debFile

	mod time.Time
}

type arCopier struct {
	name     string
	mod      time.Time
	w        *arWriter
	tempFile *os.File
}

func newARCopier(w *arWriter, mod time.Time, name string) (*arCopier, error) {
	tempFile, err := ioutil.TempFile("", "")
	if err != nil {
		return nil, fmt.Errorf("temp file: %v", err)
	}
	return &arCopier{name: name, mod: mod, w: w, tempFile: tempFile}, nil
}

func (a *arCopier) copy() error {
	stat, err := a.tempFile.Stat()
	if err != nil {
		return fmt.Errorf("stat: %v", err)
	}
	size := stat.Size()
	if _, err := a.tempFile.Seek(io.SeekStart, 0); err != nil {
		return fmt.Errorf("seek start: %v", err)
	}
	h := &arHeader{
		filename: a.name,
		mod:      a.mod,
		size:     size,
	}
	if err := a.w.WriteHeader(h); err != nil {
		return fmt.Errorf("write header: %v", err)
	}
	if _, err := io.Copy(a.w, a.tempFile); err != nil {
		return fmt.Errorf("copy from temp file: %v", err)
	}
	return nil
}

func (a *arCopier) Write(b []byte) (int, error) {
	return a.tempFile.Write(b)
}

func (a *arCopier) Close() error {
	stat, err := a.tempFile.Stat()
	if err != nil {
		return err
	}
	if err := a.tempFile.Close(); err != nil {
		return err
	}
	return os.Remove(stat.Name())
}

func (d *deb) build(w io.Writer) error {
	aw := newARWriter(w)
	debVersion := []byte("2.0\n")
	h := &arHeader{
		filename: "debian-binary",
		mod:      d.mod,
		size:     int64(len(debVersion)),
	}

	if err := aw.WriteHeader(h); err != nil {
		return err
	}
	if _, err := aw.Write(debVersion); err != nil {
		return err
	}

	cw, err := newARCopier(aw, d.mod, "control.tar.gz")
	if err != nil {
		return fmt.Errorf("ar copier: %v", err)
	}
	defer cw.Close()
	if err := d.writeControl(cw); err != nil {
		return fmt.Errorf("build control.tar.gz: %v", err)
	}
	if err := cw.copy(); err != nil {
		return fmt.Errorf("write control.tar.gz: %v", err)
	}

	dw, err := newARCopier(aw, d.mod, "data.tar.gz")
	if err != nil {
		return fmt.Errorf("ar copier: %v", err)
	}
	defer dw.Close()
	if err := writeData(d.files, d.mod, dw); err != nil {
		return fmt.Errorf("build data.tar.gz: %v", err)
	}
	if err := dw.copy(); err != nil {
		return fmt.Errorf("write data.tar.gz: %v", err)
	}

	if err := aw.Close(); err != nil {
		return fmt.Errorf("close ar: %v", err)
	}
	return nil
}

func buildMD5Sums(files []debFile) ([]byte, error) {
	var b bytes.Buffer
	for _, f := range files {
		if !path.IsAbs(f.as) {
			return nil, fmt.Errorf("path must be absolute: %s", f.as)
		}
		as := strings.TrimPrefix(f.as, "/")
		hash, err := md5Sum(f.path)
		if err != nil {
			return nil, fmt.Errorf("has of %s: %v", f.path, err)
		}
		b.WriteString(hash)
		b.WriteString("  ")
		b.WriteString(as)
		b.WriteString("\n")
	}
	return b.Bytes(), nil
}

func md5Sum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading file: %v", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// dataWriter is used to write a data archive.
type dataWriter struct {
	// written tracks directories that have already been written.
	written map[string]bool
	// mod is the modification time of all files written to the archive.
	mod time.Time
	// w is the underlying tar writer.
	w *tar.Writer
}

func (d *dataWriter) writeFile(f debFile) error {
	stat, err := os.Stat(f.path)
	if err != nil {
		return err
	}
	if !path.IsAbs(f.as) {
		return fmt.Errorf("path must be absolute: %s", f.as)
	}
	if err := d.writeDir(path.Dir(f.as)); err != nil {
		return fmt.Errorf("write dir: %v", err)
	}
	h := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "." + f.as,
		Uname:    "root",
		Gname:    "root",
		Mode:     int64(stat.Mode().Perm()),
		ModTime:  d.mod,
		Size:     stat.Size(),
	}
	if err := d.w.WriteHeader(h); err != nil {
		return fmt.Errorf("write header: %v", err)
	}
	fh, err := os.Open(f.path)
	if err != nil {
		return fmt.Errorf("open file: %v", err)
	}
	defer fh.Close()
	if _, err := io.Copy(d.w, fh); err != nil {
		return fmt.Errorf("copy file: %v", err)
	}
	return nil
}

func (d *dataWriter) writeDir(dirPath string) error {
	// Explicitly use path instead of filepath.
	if !path.IsAbs(dirPath) {
		return fmt.Errorf("path must be absolute: %s", dirPath)
	}
	if d.written[dirPath] {
		return nil
	}
	d.written[dirPath] = true
	if dirPath != "/" {
		if err := d.writeDir(path.Dir(dirPath)); err != nil {
			return err
		}
	}
	p := "." + dirPath
	if p != "./" {
		p += "/"
	}
	h := &tar.Header{
		Typeflag: tar.TypeDir,
		Name:     p,
		Uname:    "root",
		Gname:    "root",
		Mode:     0755,
		ModTime:  d.mod,
	}
	if err := d.w.WriteHeader(h); err != nil {
		return fmt.Errorf("write header: %v", err)
	}
	return nil
}

func writeData(files []debFile, mod time.Time, w io.Writer) error {
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)

	dw := dataWriter{
		written: make(map[string]bool),
		mod:     mod,
		w:       tw,
	}

	for _, f := range files {
		if err := dw.writeFile(f); err != nil {
			return fmt.Errorf("writing file %s: %v", f.path, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("write tar: %v", err)
	}
	if err := gzw.Close(); err != nil {
		return fmt.Errorf("write gzip data: %v", err)
	}
	return nil
}

func (d *deb) writeControl(w io.Writer) error {
	md5Sums, err := buildMD5Sums(d.files)
	if err != nil {
		return fmt.Errorf("compute file checksums: %v", err)
	}
	gzw := gzip.NewWriter(w)
	tw := tar.NewWriter(gzw)

	h := &tar.Header{
		Typeflag: tar.TypeDir,
		Name:     "./",
		Uname:    "root",
		Gname:    "root",
		Mode:     0755,
		ModTime:  d.mod,
	}
	if err := tw.WriteHeader(h); err != nil {
		return fmt.Errorf("write header: %v", err)
	}

	files := []struct {
		name string
		data []byte
		mode int64
	}{
		{"./control", d.control, 0644},
		{"./md5sums", md5Sums, 0644},
		{"./preinst", d.preinst, 0755},
		{"./postinst", d.postinst, 0755},
		{"./prerm", d.prerm, 0755},
		{"./postrm", d.postrm, 0755},
	}
	for _, f := range files {
		if len(f.data) == 0 {
			continue
		}
		h := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     f.name,
			Uname:    "root",
			Gname:    "root",
			Mode:     f.mode,
			ModTime:  d.mod,
			Size:     int64(len(f.data)),
		}
		if err := tw.WriteHeader(h); err != nil {
			return fmt.Errorf("write header %s: %v", f.name, err)
		}
		if _, err := tw.Write(f.data); err != nil {
			return fmt.Errorf("write file %s: %v", f.name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("write tar: %v", err)
	}
	if err := gzw.Close(); err != nil {
		return fmt.Errorf("write gzip data: %v", err)
	}
	return nil
}
