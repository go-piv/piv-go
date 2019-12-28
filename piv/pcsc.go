package piv

// https://ludovicrousseau.blogspot.com/2010/04/pcsc-sample-in-c.html

// #cgo LDFLAGS: -framework PCSC
// #include <PCSC/winscard.h>
// #include <PCSC/wintypes.h>
import "C"

import (
	"bytes"
	"fmt"
	"unsafe"
)

type scErr struct {
	rc C.int
}

func (e *scErr) Error() string {
	if msg, ok := pcscErrMsgs[int64(e.rc)]; ok {
		return msg
	}
	return fmt.Sprintf("unknown pcsc return code 0x%08x", e)
}

func check(rc C.int) error {
	if rc == C.SCARD_S_SUCCESS {
		return nil
	}
	return &scErr{rc}
}

type scContext struct {
	ctx C.SCARDCONTEXT
}

func newSCContext() (*scContext, error) {
	var ctx C.SCARDCONTEXT
	rc := C.SCardEstablishContext(C.SCARD_SCOPE_SYSTEM, nil, nil, &ctx)
	if err := check(rc); err != nil {
		return nil, err
	}
	return &scContext{ctx: ctx}, nil
}

func (c *scContext) Close() error {
	return check(C.SCardReleaseContext(c.ctx))
}

func (c *scContext) ListReaders() ([]string, error) {
	var n C.DWORD
	rc := C.SCardListReaders(c.ctx, nil, nil, &n)
	if err := check(rc); err != nil {
		return nil, err
	}
	d := make([]byte, n)
	rc = C.SCardListReaders(c.ctx, nil, (*C.char)(unsafe.Pointer(&d[0])), &n)
	if err := check(rc); err != nil {
		return nil, err
	}

	var readers []string
	for _, d := range bytes.Split(d, []byte{0}) {
		if len(d) > 0 {
			readers = append(readers, string(d))
		}
	}
	return readers, nil
}
