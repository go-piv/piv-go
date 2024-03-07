package piv

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/areese/piv-go/bertlv"
)

var (
	ErrApduMismatch       = errors.New("src != expected ")
	ErrApduBadInstruction = errors.New("src.instruction != expected.instruction ")
	ErrApduBadParam       = errors.New("src.param != expected.param ")
	ErrApduBadData        = errors.New("src.data != expected.data ")
)

type TestSCConstructor struct {
	Ctx     TestSCContext
	OpenErr error
}

type TestSCContext struct {
	CloseErr error

	ConnectFunc    func(string) (SCHandle, error)
	Handle         SCHandle
	ConnectErr     error
	ListReadersErr error
	Readers        []string
}

type TestSCHandle struct {
	BeginErr error
	Ctx      SCTx
	CloseErr error
}

type TestSCTx struct {
	CurrentAPDUIndex  int
	APDUList          []apdu
	ResponseList      [][]byte
	CloseErr          error
	TransmitData      []byte
	TransmitErr       []error
	TransmitBytesMore bool
	TransmitBytesData []byte
	TransmitBytesErr  error
}

var (
	_ SCConstructor = (*TestSCConstructor)(nil)
	_ SCContext     = (*TestSCContext)(nil)
	_ SCHandle      = (*TestSCHandle)(nil)
	_ SCTx          = (*TestSCTx)(nil)
)

// nolint:ireturn
func (p *TestSCConstructor) NewSCContext() (SCContext, error) {
	if p.Ctx.ConnectFunc == nil {
		p.Ctx.ConnectFunc = p.Ctx.SimpleConnect
	}

	return &p.Ctx, p.OpenErr
}

func (p *TestSCConstructor) String() string {
	return bertlv.MakeJSONString(p)
}

func (p *TestSCContext) Close() error {
	return p.CloseErr
}

// nolint:ireturn
func (p *TestSCContext) SimpleConnect(reader string) (SCHandle, error) {
	return p.Handle, p.ConnectErr
}

// nolint:ireturn
func (p *TestSCContext) Connect(reader string) (SCHandle, error) {
	return p.ConnectFunc(reader)
}

func (p *TestSCContext) ListReaders() ([]string, error) {
	return p.Readers, p.ListReadersErr
}

func (p *TestSCContext) String() string {
	return bertlv.MakeJSONString(p)
}

// nolint:ireturn
func (p *TestSCHandle) Begin() (SCTx, error) {
	return p.Ctx, p.BeginErr
}

func (p *TestSCHandle) Close() error {
	return p.CloseErr
}

func (p *TestSCHandle) String() string {
	return bertlv.MakeJSONString(p)
}

func (p *TestSCTx) Close() error {
	return p.CloseErr
}

func (p *TestSCTx) IsDebugEnabled() bool {
	return false
}

func (p *TestSCTx) DisableDebug() {
}

func (p *TestSCTx) EnableDebug() {
}

func (p *TestSCTx) getTransmitError() error {
	if len(p.TransmitErr) > 0 && p.CurrentAPDUIndex < len(p.TransmitErr) {
		return p.TransmitErr[p.CurrentAPDUIndex]
	}

	return nil
}

func (p *TestSCTx) Transmit(d apdu) ([]byte, error) {
	if p.APDUList == nil || p.ResponseList == nil {
		return p.TransmitData, p.getTransmitError()
	}

	if p.CurrentAPDUIndex >= len(p.APDUList) {
		return nil, ErrNotFound
	}

	if ok, matchErr := apdusMatch(&d, &p.APDUList[p.CurrentAPDUIndex]); !ok {
		return nil, matchErr
	}

	defer func() { p.CurrentAPDUIndex++ }()

	if p.CurrentAPDUIndex < len(p.ResponseList) {
		rv := p.ResponseList[p.CurrentAPDUIndex]

		return rv, nil
	}

	return p.TransmitData, p.getTransmitError()
}

func (p *TestSCTx) TransmitBytes(req []byte) (more bool, b []byte, err error) {
	return p.TransmitBytesMore, p.TransmitBytesData, p.TransmitBytesErr
}

func (p *TestSCTx) String() string {
	return bertlv.MakeJSONString(p)
}

// VerifyAPDU is to ensure that the apdu's are sent in an expected order.
func (p *TestSCTx) VerifyAPDU(d apdu) ([]byte, error) {
	return p.TransmitData, p.getTransmitError()
}

func apdusMatch(src *apdu, expected *apdu) (bool, error) {
	var errorsFound []error

	if src == nil && expected == nil {
		return true, nil
	}

	if src == nil {
		return false, fmt.Errorf("src == nil expected == %p: %w", expected, ErrApduMismatch)
	}

	if expected == nil {
		return false, fmt.Errorf("src == %p expected == nil: %w", src, ErrApduMismatch)
	}

	if src.instruction != expected.instruction {
		errorsFound = append(errorsFound, fmt.Errorf("src.instruction == [0x%x] expected.instruction == [0x%x]: %w", src.instruction, expected.instruction, ErrApduBadInstruction))
	}

	if src.param1 != expected.param1 {
		errorsFound = append(errorsFound, fmt.Errorf("src.param1 == [0x%x] expected.param1 == [0x%x]: %w", src.param1, expected.param1, ErrApduBadParam))
	}

	if src.param2 != expected.param2 {
		errorsFound = append(errorsFound, fmt.Errorf("src.param2 == [0x%x] expected.param2 == [0x%x]: %w", src.param2, expected.param2, ErrApduBadParam))
	}

	if !bytes.Equal(src.data, expected.data) {
		errorsFound = append(errorsFound, fmt.Errorf("src.data      == [%x]\nexpected.data == [%x]\n: %w", hex.EncodeToString(src.data), hex.EncodeToString(expected.data), ErrApduBadData))
	}

	if len(errorsFound) > 0 {
		result := make([]string, len(errorsFound))

		for i, e := range errorsFound {
			result[i] = e.Error()
		}

		return false, fmt.Errorf("failed: %s:%w", strings.Join(result, ":"), ErrApduMismatch)
	}

	return true, nil
}
