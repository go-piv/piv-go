package ykpiv

import (
	"encoding/binary"
	"fmt"
)

/*
union u_APDU {
  struct {
    unsigned char cla;
    unsigned char ins;
    unsigned char p1;
    unsigned char p2;
    unsigned char lc;
    unsigned char data[0xff];
  } st;
  unsigned char raw[0xff + 5];
};
*/

func Smartcards() ([]string, error) {
	ctx, err := newSCContext()
	if err != nil {
		return nil, fmt.Errorf("connecting to pscs: %v", err)
	}
	defer ctx.Close()
	return ctx.ListReaders()
}

const (
	// Blindly copied from ykpiv.h. Is this from the PIV spec?
	insVerify             = 0x20
	insChangeReference    = 0x24
	insResetRetry         = 0x2c
	insGenerateAsymmetric = 0x47
	insAuthenticated      = 0x87
	insGetData            = 0xcb
	insPutData            = 0xdb
	insSelectApplication  = 0xa4
	insGetResponseAPDU    = 0xc0

	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.h#L656
	insSetMGMKey     = 0xff
	insImportKey     = 0xfe
	insGetVersion    = 0xfd
	insReset         = 0xfb
	insSetPINRetries = 0xfa
	insAttest        = 0xf9
	insGetSerial     = 0xf8
)

type Yubikey struct {
	ctx *scContext
	h   *scHandle

	// Used to determine how to access certain functionality.
	version *version
}

func (y *Yubikey) Close() error {
	err1 := y.h.Close()
	err2 := y.ctx.Close()
	if err1 == nil {
		return err2
	}
	return err1
}

func newYubikey(card string) (*Yubikey, error) {
	ctx, err := newSCContext()
	if err != nil {
		return nil, fmt.Errorf("connecting to smartcard daemon: %v", err)
	}

	h, err := ctx.Connect(card)
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("connecting to smartcard: %v", err)
	}

	yk := &Yubikey{ctx: ctx, h: h}
	tx, err := yk.begin()
	if err != nil {
		yk.Close()
		return nil, fmt.Errorf("initializing yubikey: %v", err)
	}
	v, err := ykVersion(tx)
	if err != nil {
		yk.Close()
		return nil, fmt.Errorf("getting yubikey version: %v", err)
	}
	yk.version = v
	return yk, nil
}

func (yk *Yubikey) begin() (*scTx, error) {
	tx, err := yk.h.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning smartcard transaction: %v", err)
	}
	if err := ykSelectApplication(tx, aidPIV[:]); err != nil {
		tx.Close()
		return nil, fmt.Errorf("selecting piv applet: %v", err)
	}
	return tx, nil
}

func (yk *Yubikey) Serial() (uint32, error) {
	tx, err := yk.begin()
	if err != nil {
		return 0, err
	}
	defer tx.Close()
	return ykSerial(tx, yk.version)
}

type version struct {
	major byte
	minor byte
	patch byte
}

var (
	// Smartcard Application IDs for Yubikeys.
	//
	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.c#L1877
	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.c#L108-L110
	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.c#L1117

	aidManagement = [...]byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17}
	aidPIV        = [...]byte{0xa0, 0x00, 0x00, 0x03, 0x08}
	aidYubikey    = [...]byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01}
)

func ykSelectApplication(tx *scTx, id []byte) error {
	cmd := adpu{
		instruction: insSelectApplication,
		param1:      0x04,
		data:        id[:],
	}
	if _, err := tx.Transmit(cmd); err != nil {
		return fmt.Errorf("command failed: %v", err)
	}
	return nil
}

func ykVersion(tx *scTx) (*version, error) {
	cmd := adpu{
		instruction: insGetVersion,
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("command failed: %v", err)
	}
	if n := len(resp); n < 3 {
		return nil, fmt.Errorf("response was too short: %d", n)
	}
	return &version{resp[0], resp[1], resp[2]}, nil
}

func ykSerial(tx *scTx, v *version) (uint32, error) {
	cmd := adpu{instruction: insGetSerial}
	if v.major < 5 {
		// Earlier versions of Yubikeys required using the yubikey applet to get
		// the serial number. Newer ones have this built into the PIV applet.
		if err := ykSelectApplication(tx, aidYubikey[:]); err != nil {
			return 0, fmt.Errorf("selecting yubikey applet: %v", err)
		}
		defer ykSelectApplication(tx, aidPIV[:])
		cmd = adpu{instruction: 0x01, param1: 0x10}
	}
	resp, err := tx.Transmit(cmd)
	if err != nil {
		return 0, fmt.Errorf("smartcard command: %v", err)
	}
	if n := len(resp); n != 4 {
		return 0, fmt.Errorf("expected 4 byte serial number, got %d", n)
	}
	return binary.BigEndian.Uint32(resp), nil
}
