package ykpiv

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

func scCheck(rc C.int) error {
	if rc == C.SCARD_S_SUCCESS {
		return nil
	}
	return &scErr{rc}
}

type apduErr struct {
	sw1 byte
	sw2 byte
}

func (a *apduErr) Error() string {
	// TODO: Generate error messages
	// https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/
	return fmt.Sprintf("command failed: sw1=0x%02x, sw2=0x%02x", a.sw1, a.sw2)
}

type scContext struct {
	ctx C.SCARDCONTEXT
}

func newSCContext() (*scContext, error) {
	var ctx C.SCARDCONTEXT
	rc := C.SCardEstablishContext(C.SCARD_SCOPE_SYSTEM, nil, nil, &ctx)
	if err := scCheck(rc); err != nil {
		return nil, err
	}
	return &scContext{ctx: ctx}, nil
}

func (c *scContext) Close() error {
	return scCheck(C.SCardReleaseContext(c.ctx))
}

func (c *scContext) ListReaders() ([]string, error) {
	var n C.DWORD
	rc := C.SCardListReaders(c.ctx, nil, nil, &n)
	if err := scCheck(rc); err != nil {
		return nil, err
	}
	d := make([]byte, n)
	rc = C.SCardListReaders(c.ctx, nil, (*C.char)(unsafe.Pointer(&d[0])), &n)
	if err := scCheck(rc); err != nil {
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

type scHandle struct {
	h C.SCARDHANDLE
}

func (c *scContext) Connect(reader string) (*scHandle, error) {
	var (
		handle         C.SCARDHANDLE
		activeProtocol C.DWORD
	)
	rc := C.SCardConnect(c.ctx, C.CString(reader),
		C.SCARD_SHARE_SHARED, C.SCARD_PROTOCOL_T1,
		&handle, &activeProtocol)
	if err := scCheck(rc); err != nil {
		return nil, err
	}
	return &scHandle{handle}, nil
}

func (h *scHandle) Close() error {
	return scCheck(C.SCardDisconnect(h.h, C.SCARD_LEAVE_CARD))
}

type scTx struct {
	h C.SCARDHANDLE
}

func (h *scHandle) Begin() (*scTx, error) {
	if err := scCheck(C.SCardBeginTransaction(h.h)); err != nil {
		return nil, err
	}
	return &scTx{h.h}, nil
}

func (t *scTx) Close() error {
	return scCheck(C.SCardEndTransaction(t.h, C.SCARD_LEAVE_CARD))
}

type apdu struct {
	instruction byte
	param1      byte
	param2      byte
	data        []byte
}

func (t *scTx) transmit(req []byte) (more bool, b []byte, err error) {
	var resp [C.MAX_BUFFER_SIZE_EXTENDED]byte
	reqN := C.DWORD(len(req))
	respN := C.DWORD(len(resp))
	rc := C.SCardTransmit(
		t.h,
		C.SCARD_PCI_T1,
		(*C.BYTE)(&req[0]), reqN, nil,
		(*C.BYTE)(&resp[0]), &respN)
	if err := scCheck(rc); err != nil {
		return false, nil, fmt.Errorf("transmitting request: %v", err)
	}
	if respN < 2 {
		return false, nil, fmt.Errorf("scard response too short: %d", respN)
	}
	sw1 := resp[respN-2]
	sw2 := resp[respN-1]
	if sw1 == 0x90 && sw2 == 0x00 {
		return false, resp[:respN-2], nil
	}
	if sw1 == 0x61 {
		return true, resp[:respN-2], nil
	}
	return false, nil, &apduErr{sw1, sw2}
}

const maxAPDUDataSize = 0xff

func (t *scTx) Transmit(d apdu) ([]byte, error) {
	data := d.data
	var resp []byte
	for len(data) > maxAPDUDataSize {
		req := make([]byte, 5+maxAPDUDataSize)
		req[0] = 0x10 // ISO/IEC 7816-4 5.1.1
		req[1] = d.instruction
		req[2] = d.param1
		req[3] = d.param2
		copy(req[5:], data[:maxAPDUDataSize])
		data = data[maxAPDUDataSize:]
		_, r, err := t.transmit(req)
		if err != nil {
			return nil, err
		}
		resp = append(resp, r...)
	}

	req := make([]byte, 5+len(d.data))
	req[1] = d.instruction
	req[2] = d.param1
	req[3] = d.param2
	req[4] = byte(len(data))
	copy(req[5:], data)
	hasMore, r, err := t.transmit(req)
	if err != nil {
		return nil, err
	}
	resp = append(resp, r...)

	for hasMore {
		req := make([]byte, 5)
		req[1] = insGetResponseAPDU
		var r []byte
		hasMore, r, err = t.transmit(req)
		if err != nil {
			return nil, err
		}
		resp = append(resp, r...)
	}

	return resp, nil
}
