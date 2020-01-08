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

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const (
	// DefaultPIN for the PIV applet. The PIN is used to change the Management Key,
	// and slots can optionally require it to perform signing operations.
	//
	// For compatibility, the PIN should be 1-8 numeric characters.
	DefaultPIN = "123456"
	// DefaultPUK for the PIV applet. The PUK is only used to reset the PIN when
	// the card's PIN retries have been exhausted.
	//
	// For compatibility, the PUK should be 1-8 numeric characters.
	DefaultPUK = "12345678"
)

var (
	// DefaultManagementKey for the PIV applet. The Management Key is a Triple-DES
	// key required for slot actions such as generating keys, setting certificates,
	// and signing.
	//
	// YubiKey's PIV tools can optionally derive the Management Key from the PIN,
	// storing a salt on the YubiKey. This functionality is currently unsupported
	// by this package.
	DefaultManagementKey = [24]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
)

// errWrongPIN is the error returned when a login attempt fails because of an
// invalid PIN or PUK.
//
// Use errors.As when checking for this error return.
//
//		err := yk.Login(badPIN)
//		if err != nil {
//			var e *yk.errWrongPIN
//			if errors.As(err, &e) {
//				// ...
//			}
//		}
//
type errWrongPIN struct {
	Retries int
}

// Error reports the number of retries left for a PIN or PUK.
func (e *errWrongPIN) Error() string {
	s := "retries"
	if e.Retries == 1 {
		s = "retry"
	}
	return fmt.Sprintf("wrong pin, %d %s left", e.Retries, s)
}

func ykTransmit(tx *scTx, cmd apdu) ([]byte, error) {
	resp, err := tx.Transmit(cmd)
	if err == nil {
		return resp, nil
	}

	// Check for specific errors.
	var e *apduErr
	if !errors.As(err, &e) {
		return nil, err
	}
	// "Authentication method blocked"
	if e.sw1 == 0x69 && e.sw2 == 0x83 {
		return nil, &errWrongPIN{0}
	}

	// Verify fail status codes 0xc[0-f] communicate the number of retries.
	if e.sw1 == 0x63 && (e.sw2&0xf0 == 0xc0) {
		return nil, &errWrongPIN{int(e.sw2 ^ 0xc0)}
	}
	return nil, err
}

// Cards lists all smart cards available via PC/SC interface. Card names are
// strings describing the key, such as "Yubico Yubikey NEO OTP+U2F+CCID 00 00".
//
// Card names depend on the operating system and what port a card is plugged
// into. To uniquely identify a card, use its serial number.
//
// See: https://ludovicrousseau.blogspot.com/2010/05/what-is-in-pcsc-reader-name.html
func Cards() ([]string, error) {
	ctx, err := newSCContext()
	if err != nil {
		return nil, fmt.Errorf("connecting to pscs: %v", err)
	}
	defer ctx.Close()
	return ctx.ListReaders()
}

const (
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-4.pdf#page=17
	algTag     = 0x80
	alg3DES    = 0x03
	algRSA1024 = 0x06
	algRSA2048 = 0x07
	algECCP256 = 0x11
	algECCP384 = 0x14

	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-78-4.pdf#page=16
	keyAuthentication     = 0x9a
	keyCardManagement     = 0x9b
	keySignature          = 0x9c
	keyKeyManagement      = 0x9d
	keyCardAuthentication = 0x9e
	keyAttestation        = 0xf9

	insVerify             = 0x20
	insChangeReference    = 0x24
	insResetRetry         = 0x2c
	insGenerateAsymmetric = 0x47
	insAuthenticate       = 0x87
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

// YubiKey is an open connection to a YubiKey smart card.
type YubiKey struct {
	ctx *scContext
	h   *scHandle

	// Used to determine how to access certain functionality.
	//
	// TODO: It's not clear what this actually communicates. Is this the
	// YubiKey's version or PIV version? A NEO reports v1.0.4. Figure this out
	// before exposing an API.
	version *version
}

// Close releases the connection to the smart card.
func (yk *YubiKey) Close() error {
	err1 := yk.h.Close()
	err2 := yk.ctx.Close()
	if err1 == nil {
		return err2
	}
	return err1
}

// Open connects to a YubiKey smart card.
func Open(card string) (*YubiKey, error) {
	ctx, err := newSCContext()
	if err != nil {
		return nil, fmt.Errorf("connecting to smart card daemon: %v", err)
	}

	h, err := ctx.Connect(card)
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("connecting to smart card: %v", err)
	}

	yk := &YubiKey{ctx: ctx, h: h}
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

func (yk *YubiKey) begin() (*scTx, error) {
	tx, err := yk.h.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning smart card transaction: %v", err)
	}
	if err := ykSelectApplication(tx, aidPIV[:]); err != nil {
		tx.Close()
		return nil, fmt.Errorf("selecting piv applet: %v", err)
	}
	return tx, nil
}

// Serial returns the YubiKey's serial number.
func (yk *YubiKey) Serial() (uint32, error) {
	tx, err := yk.begin()
	if err != nil {
		return 0, err
	}
	defer tx.Close()
	return ykSerial(tx, yk.version)
}

func encodePIN(pin string) ([]byte, error) {
	data := []byte(pin)
	if len(data) == 0 {
		return nil, fmt.Errorf("pin cannot be empty")
	}
	if len(data) > 8 {
		return nil, fmt.Errorf("pin longer than 8 bytes")
	}
	// apply padding
	for i := len(data); i < 8; i++ {
		data = append(data, 0xff)
	}
	return data, nil
}

func (yk *YubiKey) Login(pin string) error {
	tx, err := yk.begin()
	if err != nil {
		return err
	}
	defer tx.Close()
	return ykLogin(tx, pin)
}

func ykLogin(tx *scTx, pin string) error {
	data, err := encodePIN(pin)
	if err != nil {
		return err
	}

	cmd := apdu{instruction: insVerify, param2: 0x80, data: data}
	if _, err := ykTransmit(tx, cmd); err != nil {
		return fmt.Errorf("verify pin: %w", err)
	}
	return nil
}

// PINRetries returns the number of attempts remaining to enter the correct PIN.
func (yk *YubiKey) PINRetries() (int, error) {
	tx, err := yk.begin()
	if err != nil {
		return 0, err
	}
	defer tx.Close()
	return ykPINRetries(tx)
}

func ykPINRetries(tx *scTx) (int, error) {
	cmd := apdu{instruction: insVerify, param2: 0x80}
	_, err := ykTransmit(tx, cmd)
	if err == nil {
		return 0, fmt.Errorf("expected error code from empty pin")
	}
	var e *errWrongPIN
	if errors.As(err, &e) {
		return e.Retries, nil
	}
	return 0, fmt.Errorf("invalid response: %v", err)
}

// Reset resets the YubiKey PIV applet to its factory settings, wiping all slots
// and resetting the PIN, PUK, and Management Key to their default values. This
// does NOT affect data on other applets, such as GPG or U2F.
func (yk *YubiKey) Reset() error {
	tx, err := yk.begin()
	if err != nil {
		return err
	}
	defer tx.Close()
	return ykReset(tx)
}

func ykReset(tx *scTx) error {
	// Reset only works if both the PIN and PUK are blocked. Before resetting,
	// try the wrong PIN and PUK multiple times to block them.

	maxPIN := big.NewInt(100_000_000)
	pinInt, err := rand.Int(rand.Reader, maxPIN)
	if err != nil {
		return fmt.Errorf("generating random pin: %v", err)
	}
	pukInt, err := rand.Int(rand.Reader, maxPIN)
	if err != nil {
		return fmt.Errorf("generating random puk: %v", err)
	}

	pin := pinInt.String()
	puk := pukInt.String()

	for {
		err := ykLogin(tx, pin)
		if err == nil {
			// TODO: do we care about a 1/100million chance?
			return fmt.Errorf("expected error with random pin")
		}
		var e *errWrongPIN
		if !errors.As(err, &e) {
			return fmt.Errorf("blocking pin: %v", err)
		}
		if e.Retries == 0 {
			break
		}
	}

	for {
		err := ykChangePUK(tx, puk, puk)
		if err == nil {
			// TODO: do we care about a 1/100million chance?
			return fmt.Errorf("expected error with random puk")
		}
		var e *errWrongPIN
		if !errors.As(err, &e) {
			return fmt.Errorf("blocking puk: %v", err)
		}
		if e.Retries == 0 {
			break
		}
	}

	cmd := apdu{instruction: insReset}
	if _, err := ykTransmit(tx, cmd); err != nil {
		return fmt.Errorf("reseting yubikey: %v", err)
	}
	return nil
}

type version struct {
	major byte
	minor byte
	patch byte
}

var (
	// Smartcard Application IDs for YubiKeys.
	//
	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.c#L1877
	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.c#L108-L110
	// https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-1.7.0/lib/ykpiv.c#L1117

	aidManagement = [...]byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17}
	aidPIV        = [...]byte{0xa0, 0x00, 0x00, 0x03, 0x08}
	aidYubiKey    = [...]byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01}
)

func ykAuthenticate(tx *scTx, key [24]byte) error {
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=92
	// https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=918402#page=114

	// request a witness
	cmd := apdu{
		instruction: insAuthenticate,
		param1:      alg3DES,
		param2:      keyCardManagement,
		data: []byte{
			0x7c, // Dynamic Authentication Template tag
			0x02, // Length of object
			0x80, // 'Witness'
			0x00, // Return encrypted random
		},
	}
	resp, err := ykTransmit(tx, cmd)
	if err != nil {
		return fmt.Errorf("get auth challenge: %v", err)
	}
	if n := len(resp); n < 12 {
		return fmt.Errorf("challenge didn't return enough bytes: %d", n)
	}
	if !bytes.Equal(resp[:4], []byte{
		0x7c,
		0x0a,
		0x80, // 'Witness'
		0x08, // Tag length
	}) {
		return fmt.Errorf("invalid authentication object header: %x", resp[:4])
	}

	cardChallenge := resp[4 : 4+8]
	cardResponse := make([]byte, 8)

	block, err := des.NewTripleDESCipher(key[:])
	if err != nil {
		return fmt.Errorf("creating triple des block cipher: %v", err)
	}
	block.Decrypt(cardResponse, cardChallenge)

	challenge := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		return fmt.Errorf("reading rand data: %v", err)
	}
	response := make([]byte, 8)
	block.Encrypt(response, challenge)

	data := append([]byte{
		0x7c, // Dynamic Authentication Template tag
		20,   // 2+8+2+8
		0x80, // 'Witness'
		0x08, // Tag length
	})
	data = append(data, cardResponse...)
	data = append(data,
		0x81, // 'Challenge'
		0x08, // Tag length
	)
	data = append(data, challenge...)

	cmd = apdu{
		instruction: insAuthenticate,
		param1:      alg3DES,
		param2:      keyCardManagement,
		data:        data,
	}
	resp, err = ykTransmit(tx, cmd)
	if err != nil {
		return fmt.Errorf("auth challenge: %v", err)
	}
	if n := len(resp); n < 12 {
		return fmt.Errorf("challenge response didn't return enough bytes: %d", n)
	}
	if !bytes.Equal(resp[:4], []byte{
		0x7c,
		0x0a,
		0x82, // 'Response'
		0x08,
	}) {
		return fmt.Errorf("response invalid authentication object header: %x", resp[:4])
	}
	if !bytes.Equal(resp[4:4+8], response) {
		return fmt.Errorf("challenge failed")
	}

	return nil
}

// ykSetManagementKey updates the management key to a new key. This requires
// authenticating with the existing management key.
func ykSetManagementKey(tx *scTx, key [24]byte, touch bool) error {
	cmd := apdu{
		instruction: insSetMGMKey,
		param1:      0xff,
		param2:      0xff,
		data: append([]byte{
			alg3DES, keyCardManagement, 24,
		}, key[:]...),
	}
	if touch {
		cmd.param2 = 0xfe
	}
	if _, err := ykTransmit(tx, cmd); err != nil {
		return fmt.Errorf("command failed: %v", err)
	}
	return nil
}

func ykChangePIN(tx *scTx, oldPIN, newPIN string) error {
	oldPINData, err := encodePIN(oldPIN)
	if err != nil {
		return fmt.Errorf("encoding old pin: %v", err)
	}
	newPINData, err := encodePIN(newPIN)
	if err != nil {
		return fmt.Errorf("encoding new pin: %v", err)
	}
	cmd := apdu{
		instruction: insChangeReference,
		param2:      0x80,
		data:        append(oldPINData, newPINData...),
	}
	_, err = ykTransmit(tx, cmd)
	return err
}

func ykUnblockPIN(tx *scTx, puk, newPIN string) error {
	pukData, err := encodePIN(puk)
	if err != nil {
		return fmt.Errorf("encoding puk: %v", err)
	}
	newPINData, err := encodePIN(newPIN)
	if err != nil {
		return fmt.Errorf("encoding new pin: %v", err)
	}
	cmd := apdu{
		instruction: insResetRetry,
		param2:      0x80,
		data:        append(pukData, newPINData...),
	}
	_, err = ykTransmit(tx, cmd)
	return err
}

func ykChangePUK(tx *scTx, oldPUK, newPUK string) error {
	oldPUKData, err := encodePIN(oldPUK)
	if err != nil {
		return fmt.Errorf("encoding old puk: %v", err)
	}
	newPUKData, err := encodePIN(newPUK)
	if err != nil {
		return fmt.Errorf("encoding new puk: %v", err)
	}
	cmd := apdu{
		instruction: insChangeReference,
		param2:      0x81,
		data:        append(oldPUKData, newPUKData...),
	}
	_, err = ykTransmit(tx, cmd)
	return err
}

func ykSelectApplication(tx *scTx, id []byte) error {
	cmd := apdu{
		instruction: insSelectApplication,
		param1:      0x04,
		data:        id[:],
	}
	if _, err := ykTransmit(tx, cmd); err != nil {
		return fmt.Errorf("command failed: %v", err)
	}
	return nil
}

func ykVersion(tx *scTx) (*version, error) {
	cmd := apdu{
		instruction: insGetVersion,
	}
	resp, err := ykTransmit(tx, cmd)
	if err != nil {
		return nil, fmt.Errorf("command failed: %v", err)
	}
	if n := len(resp); n < 3 {
		return nil, fmt.Errorf("response was too short: %d", n)
	}
	return &version{resp[0], resp[1], resp[2]}, nil
}

func ykSerial(tx *scTx, v *version) (uint32, error) {
	cmd := apdu{instruction: insGetSerial}
	if v.major < 5 {
		// Earlier versions of YubiKeys required using the yubikey applet to get
		// the serial number. Newer ones have this built into the PIV applet.
		if err := ykSelectApplication(tx, aidYubiKey[:]); err != nil {
			return 0, fmt.Errorf("selecting yubikey applet: %v", err)
		}
		defer ykSelectApplication(tx, aidPIV[:])
		cmd = apdu{instruction: 0x01, param1: 0x10}
	}
	resp, err := ykTransmit(tx, cmd)
	if err != nil {
		return 0, fmt.Errorf("smart card command: %v", err)
	}
	if n := len(resp); n != 4 {
		return 0, fmt.Errorf("expected 4 byte serial number, got %d", n)
	}
	return binary.BigEndian.Uint32(resp), nil
}

// ykChangeManagementKey sets the Management Key to the new key provided. The
// user must have authenticated with the existing key first.
func ykChangeManagementKey(tx *scTx, key [24]byte) error {
	cmd := apdu{
		instruction: insSetMGMKey,
		param1:      0xff,
		param2:      0xff, // TODO: support touch policy
		data: append([]byte{
			alg3DES, keyCardManagement, 24,
		}, key[:]...),
	}
	if _, err := ykTransmit(tx, cmd); err != nil {
		return fmt.Errorf("command failed: %v", err)
	}
	return nil
}
