package piv

import "fmt"

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

var aid = [...]byte{
	0xa0, 0x00, 0x00, 0x03, 0x08,
}

type version struct {
	major byte
	minor byte
	patch byte
}

func ykSelectApplication(tx *scTx) error {
	// copied from https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0//lib/ykpiv.c#L273
	cmd := adpu{
		instruction: insSelectApplication,
		param1:      0x04,
		data:        aid[:],
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
