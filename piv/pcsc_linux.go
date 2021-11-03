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

// #cgo darwin LDFLAGS: -framework PCSC
// #cgo linux pkg-config: libpcsclite
// #cgo freebsd CFLAGS: -I/usr/local/include/
// #cgo freebsd CFLAGS: -I/usr/local/include/PCSC
// #cgo freebsd LDFLAGS: -L/usr/local/lib/
// #cgo freebsd LDFLAGS: -lpcsclite
// #include <PCSC/winscard.h>
// #include <PCSC/wintypes.h>
import "C"

// Return codes for PCSC are different on different platforms (int vs. long).

func scCheck(rc C.long) error {
	if rc == rcSuccess {
		return nil
	}
	return &scErr{int64(rc)}
}

func isRCNoReaders(rc C.long) bool {
	return C.ulong(rc) == 0x8010002E
}

func (c *scContext) Connect(reader string) (*scHandle, error) {
	var (
		handle         C.SCARDHANDLE
		activeProtocol C.DWORD
	)
	opt := C.SCARD_SHARE_EXCLUSIVE
	if c.shared {
		opt = C.SCARD_SHARE_SHARED
	}
	rc := C.SCardConnect(c.ctx, C.CString(reader),
		C.ulong(opt), C.SCARD_PROTOCOL_T1,
		&handle, &activeProtocol)
	if err := scCheck(rc); err != nil {
		return nil, err
	}
	return &scHandle{handle}, nil
}