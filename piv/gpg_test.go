package piv

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/go-piv/piv-go/bertlv"
)

type gpgDataTestCases struct {
	name                 string
	expectedError        error
	key                  GPGYubiKey
	expectedSerial       uint32
	expectedSerialString string
}

const (
	rcErr1 int64 = 0x80100003
	rcErr2 int64 = 0x80100004
)

func TestGpgData_GetTag(t *testing.T) {
	t.Parallel()

	cases := []gpgDataTestCases{
		{
			name:          "nil",
			expectedError: ErrNotFound,
			key: GPGYubiKey{
				gpgData: nil,
				trace:   false,
			},
		},
		{
			name:          "empty",
			expectedError: ErrNotFound,
			key: GPGYubiKey{
				gpgData: &GpgData{},
				trace:   false,
			},
		},
		{
			name:          "empty",
			expectedError: nil,
			key: GPGYubiKey{
				gpgData: &GpgData{
					Serial:    "123456",
					SerialInt: 123456,
				},
				trace: false,
			},
			expectedSerial:       123456,
			expectedSerialString: "123456",
		},
	}

	for _, tc := range cases {
		// avoid aliasing due to test.paralell.
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testSerials(t, tc)
		})
	}
}

func testSerials(t *testing.T, tc gpgDataTestCases) {
	t.Helper()

	serial, err := tc.key.Serial()
	if err != nil && tc.expectedError == nil {
		t.Errorf("expected no error got :[%v]", err)
		t.Fail()
	}

	if serial != tc.expectedSerial {
		t.Errorf("serial [%d] != expected [%d]", serial, tc.expectedSerial)
		t.Fail()
	}

	serialString, err := tc.key.SerialString()
	if err != nil && tc.expectedError == nil {
		t.Errorf("expected no error got :[%v]", err)
		t.Fail()
	}

	if serialString != tc.expectedSerialString {
		t.Errorf("serial [%s] != expected [%s]", serialString, tc.expectedSerialString)
		t.Fail()
	}
}

type anyfunc func() (any, error)

func TestGpgData_Serial_Fail(t *testing.T) {
	t.Parallel()
	key := GPGYubiKey{}
	_, err := key.Serial()
	expectedError(t, err, ErrNotFound)
}

func TestGpgData_SerialString_Fail(t *testing.T) {
	t.Parallel()
	key := GPGYubiKey{}
	_, err := key.SerialString()
	expectedError(t, err, ErrNotFound)
}

func TestGpgData_GPGData_Fail(t *testing.T) {
	t.Parallel()
	key := GPGYubiKey{}
	_, err := key.GPGData()

	expectedError(t, err, ErrNotFound)
}

func TestGpgData_AuthPIN_Fail(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		pin  []byte
		err  error
	}{
		{
			name: "nil",
			pin:  nil,
			err:  ErrTooShort,
		},
		{
			name: "empty",
			pin:  []byte{},
			err:  ErrTooShort,
		},
		{
			name: "< minPW1Length",
			pin:  make([]byte, minPW1Length-1),
			err:  ErrTooShort,
		},
		{
			name: "no gpgdata",
			pin:  make([]byte, minPW1Length),
			err:  ErrNotFound,
		},
	}

	for _, tc := range cases {
		// avoid aliasing due to test.parallel.
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := GPGYubiKey{}
			err := key.AuthPIN(tc.pin)
			expectedError(t, err, tc.err)
		})
	}
}

func TestGpgData_Decrypt_Fail(t *testing.T) {
	t.Parallel()
	key := GPGYubiKey{}
	_, err := key.Decrypt(nil)
	expectedError(t, err, ErrNotFound)
}

func TestGpgOpen_Fail(t *testing.T) {
	t.Parallel()
	c := &Client{
		client: &client{},
		SCConstruct: &TestSCConstructor{
			Ctx:     TestSCContext{},
			OpenErr: &scErr{rc: rcErr1},
		},
	}

	_, err := c.OpenGPG("")

	expectedError(t, err, &scErr{rc: rcErr1})
}

func TestGpgOpenConnect_Fail(t *testing.T) {
	t.Parallel()
	c := &Client{
		client: &client{},
		SCConstruct: &TestSCConstructor{
			Ctx: TestSCContext{
				ConnectFunc: func(string) (SCHandle, error) {
					return nil, &scErr{rc: rcErr1}
				},
			},
		},
	}

	_, err := c.OpenGPG("")

	expectedError(t, err, &scErr{rc: rcErr1})
}

func CreateTestClient(tb testing.TB, closeErr, connectErr error, handle *TestSCHandle) *Client {
	c := &Client{
		client: &client{},
		SCConstruct: &TestSCConstructor{
			Ctx: TestSCContext{
				CloseErr: nil,
				ConnectFunc: func(string) (SCHandle, error) {
					return handle, connectErr
				},
			},
		},
	}

	return c
}

func TestGpgHandleBegin_Fail(t *testing.T) {
	t.Parallel()
	c := CreateTestClient(t, nil, nil,
		&TestSCHandle{
			BeginErr: &scErr{rc: rcErr2},
		},
	)

	_, err := c.OpenGPG("")

	expectedError(t, err, &scErr{rc: rcErr2})
}

func BasicSCHandle(tb testing.TB) *Client {
	tb.Helper()

	rv := &TestSCHandle{
		BeginErr: nil,
		Ctx: &TestSCTx{
			APDUList: []apdu{
				{
					instruction: insSelectApplication,
					param1:      paramOpenGPGASelectApplication,
					data:        aidOpenPGP[:],
				},
				{
					instruction: insGetDataA,
					param2:      cardHolderDataTag,
				},
				{
					instruction: insGetDataA,
					param2:      applicationRelatedDataTag,
				},
				{
					instruction: insGetDataA,
					param2:      securitySupportTemplateTag,
				},
				{
					instruction: insGetGPGAppletVersion,
				},
			},
			ResponseList: [][]byte{
				{}, // no result from select.
				{0x65, 0x09, 0x5b, 0x00, 0x5f, 0x2d, 0x00, 0x5f, 0x35, 0x01, 0x39, 0x90, 0x00},
				{
					0x6e, 0x81, 0xde, 0x4f, 0x10, 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x02, 0x00, 0x00, 0x06, 0x03,
					0x50, 0x69, 0x94, 0x00, 0x00, 0x5f, 0x52, 0x0f, 0x00, 0x73, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x81, 0xb7, 0xc0, 0x0a, 0xf0, 0x00, 0x00, 0xff,
					0x04, 0xc0, 0x00, 0xff, 0x00, 0xff, 0xc1, 0x06, 0x01, 0x08, 0x00, 0x00, 0x11, 0x03, 0xc2, 0x06,
					0x01, 0x08, 0x00, 0x00, 0x11, 0x03, 0xc3, 0x06, 0x01, 0x08, 0x00, 0x00, 0x11, 0x03, 0xc4, 0x07,
					0x00, 0x7f, 0x7f, 0x7f, 0x00, 0x03, 0x03, 0xc5, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0xcd, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x90, 0x00,
				},
				{0x7a, 0x05, 0x93, 0x03, 0x00, 0x00, 0x00, 0x90, 0x00},
				{0x05, 0x02, 0x06},
			},
		},
	}

	c := CreateTestClient(tb, nil, nil, rv)

	return c
}

func TestGpg_Good(t *testing.T) {
	t.Parallel()

	c := BasicSCHandle(t)
	_, err := c.OpenGPG("")

	expectedError(t, err, nil)
}

func TestGpg_Basic(t *testing.T) {
	t.Parallel()
	// openpgp should not panic.
	key, err := OpenGPG("")

	if err == nil || key != nil {
		t.Errorf("Expected key to be nil")
		t.FailNow()
	}
}

func expectedError(t *testing.T, err, expectedError error) bool {
	t.Helper()

	// good.
	if err == nil && expectedError == nil {
		return true
	}

	// bad
	if err != nil && expectedError == nil {
		t.Errorf("expected no error got :[%v]", err)
		t.Fail()

		return false
	}

	scErr1, ok1 := errors.Unwrap(err).(*scErr)
	expectedScError, ok2 := expectedError.(*scErr)

	if ok1 != ok2 {
		t.Errorf("got: ok1: [%t] ok2: [%t] [%v] expected [%v] ", ok1, ok2, err, expectedError)
		t.Fail()

		return false
	}

	if ok1 && ok2 {
		if scErr1.rc != expectedScError.rc {
			t.Errorf("got: rc1: [%x] rc2: [%x] [%v] expected [%v] ", scErr1.rc, expectedScError.rc, err, expectedError)
			t.Fail()
		}

		return false
	}

	if !errors.Is(err, expectedError) {
		t.Errorf("got :[%v] expected [%v] ", err, expectedError)
		t.Fail()

		return false
	}

	return true
}

var (
	openGpgGoodModulus  = []byte{0xc2, 0xe8, 0x26, 0x70, 0x45, 0xda, 0xb5, 0x4e, 0x55, 0x3b, 0xb3, 0x76, 0xb1, 0xad, 0xe1, 0x74, 0x27, 0xf2, 0x3b, 0xd9, 0x7e, 0xf5, 0x9b, 0x3b, 0xc5, 0x9c, 0x15, 0x61, 0x9d, 0xb6, 0xb7, 0x77, 0xe3, 0x6e, 0xb3, 0xd3, 0xb4, 0x47, 0x3a, 0x08, 0x2e, 0x8d, 0x8d, 0x6f, 0xa1, 0xdf, 0xa0, 0x3e, 0xa3, 0xbb, 0x65, 0x5f, 0xdb, 0xbb, 0x6c, 0xae, 0xdc, 0x72, 0xb2, 0xb5, 0x4c, 0x08, 0x09, 0x09, 0x92, 0xca, 0xab, 0xa0, 0x27, 0x2b, 0x1a, 0xd8, 0x8e, 0xba, 0xa5, 0x9a, 0xa9, 0xd1, 0x8d, 0xb8, 0xf4, 0xcf, 0x3c, 0xa6, 0x39, 0xcc, 0x58, 0xe4, 0x77, 0xc9, 0xdc, 0x89, 0x52, 0x70, 0x95, 0xd2, 0x58, 0xa4, 0x00, 0x09, 0x96, 0x26, 0x63, 0x14, 0xee, 0xfd, 0x84, 0x56, 0x73, 0xec, 0xc1, 0x4f, 0x51, 0x43, 0x4e, 0x16, 0x3f, 0x30, 0x8f, 0xc7, 0x61, 0x0f, 0x78, 0x8d, 0xd6, 0x2c, 0x76, 0x0a, 0x28, 0xe8, 0x68, 0xbc, 0xe1, 0x5e, 0xfe, 0xc4, 0x3f, 0x23, 0xa1, 0xc3, 0xc4, 0xbf, 0xb0, 0xfb, 0x8a, 0x24, 0xba, 0x57, 0x56, 0x84, 0x4e, 0xf5, 0x76, 0x63, 0xa1, 0xc7, 0x13, 0x37, 0xcc, 0x30, 0x62, 0x68, 0x8f, 0x46, 0x1b, 0x12, 0x57, 0x75, 0xb5, 0xd8, 0x6a, 0x92, 0xb1, 0x99, 0xdc, 0x47, 0x34, 0xe0, 0xb6, 0x63, 0x87, 0xb0, 0xa9, 0xa7, 0x20, 0x64, 0x6d, 0x2d, 0x7b, 0x7f, 0x5f, 0xea, 0x3e, 0x85, 0xc2, 0xe9, 0x0f, 0xb4, 0x0e, 0xe3, 0xcc, 0x64, 0xad, 0x51, 0xf5, 0xbd, 0x39, 0xe0, 0xfa, 0x4e, 0xa3, 0x55, 0xac, 0xdc, 0xc9, 0xcd, 0x3a, 0x80, 0xff, 0x99, 0xb3, 0x0c, 0xe4, 0xc3, 0xda, 0xd4, 0x45, 0xb8, 0x79, 0x17, 0x20, 0xe4, 0x7b, 0x78, 0x87, 0xfe, 0xce, 0xca, 0x43, 0x30, 0xef, 0xe5, 0x5d, 0xfe, 0x3c, 0x87, 0xbd, 0x61, 0x01}
	openGpgGoodExponent = []byte{0x01, 0x00, 0x01}
)

func TestGpg_ParsePublicKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		data         bertlv.TLVData
		parseError   error
		encryptError error
	}{
		{
			name: "valid",
			data: bertlv.TLVData{
				openGpgModulusTag:  openGpgGoodModulus,
				openGpgExponentTag: openGpgGoodExponent,
			},
		},
		{
			name: "small exponent",
			data: bertlv.TLVData{
				openGpgModulusTag:  openGpgGoodModulus,
				openGpgExponentTag: {0x01},
			},
			parseError: ErrPublicExponentSmall,
		},
		{
			name: "big exponent",
			data: bertlv.TLVData{
				openGpgModulusTag:  openGpgGoodModulus,
				openGpgExponentTag: {0x80, 0x0, 0x0, 0x0},
			},
			parseError: ErrPublicExponentLarge,
		},
		{
			name:       "no modulus",
			data:       bertlv.TLVData{},
			parseError: ErrNoPublicKeyModulus,
		},
		{
			name:       "no exponent",
			data:       bertlv.TLVData{openGpgModulusTag: openGpgGoodModulus},
			parseError: ErrNoPublicKeyExponent,
		},
	}

	for _, tc := range cases {
		// avoid aliasing due to test.parallel.
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pub, err := parsePublicKey(&tc.data)
			if !expectedError(t, err, tc.parseError) || err != nil {
				return
			}

			_, err = rsa.EncryptPKCS1v15(rand.Reader, pub, []byte{1, 2, 3, 4})
			if !expectedError(t, err, tc.encryptError) || err != nil {
				return
			}
		})
	}
}

func TestGpgData_ReadPublicKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		keyType      AsymmetricKeyType
		key          GPGYubiKey
		parseError   error
		encryptError error
	}{
		{
			name:       "KeyTypeUnknown",
			keyType:    KeyTypeUnknown,
			parseError: ErrNotFound,
		},
		{
			name:       "AsymmetricDigitalSignature",
			keyType:    AsymmetricDigitalSignature,
			parseError: ErrNotFound,
		},
		{
			name:       "AsymmetricConfidentiality",
			keyType:    AsymmetricConfidentiality,
			parseError: ErrNotFound,
		},
		{
			name:       "AsymmetricAuthentication",
			keyType:    AsymmetricAuthentication,
			parseError: ErrNotFound,
		},
	}
	for _, tc := range cases {
		// avoid aliasing due to test.parallel.
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tc.key.ReadPublicKey(tc.keyType)
			expectedError(t, err, tc.parseError)
		})
	}
}

func TestGpgData_Origin(t *testing.T) {
	t.Parallel()

	maketag := func(keyType KeyType, value KeyOrigin) []byte {
		rv := make([]byte, KeyTypeSize)
		rv[keyType.Offset()] = byte(value)
		return rv
	}

	cases := []struct {
		name      string
		data      bertlv.TLVData
		keyType   KeyType
		keyOrigin KeyOrigin
		err       error
	}{
		{
			name:      "KeyTypeUnknown",
			keyType:   KeyTypeUnknown,
			keyOrigin: KeyNotPresent,
			err:       ErrKeyNotPresent,
		},
		{
			name: "MissingOrigin",
			data: bertlv.TLVData{
				keyOriginAttributesTag: nil,
			},
			keyType:   SignatureKey,
			keyOrigin: KeyNotPresent,
			err:       ErrKeyNotPresent,
		},
		{
			name:      "BadSize(Small)",
			data:      bertlv.TLVData{keyOriginAttributesTag: make([]byte, KeyTypeSize-1)},
			keyType:   SignatureKey,
			keyOrigin: KeyNotPresent,
			err:       ErrTooShort,
		},
		{
			name:      "BadSize(Large)",
			data:      bertlv.TLVData{keyOriginAttributesTag: make([]byte, KeyTypeSize+1)},
			keyType:   SignatureKey,
			keyOrigin: KeyNotPresent,
			err:       nil,
		},
		{
			name:      "BadData",
			keyType:   SignatureKey,
			keyOrigin: KeyNotPresent,
			err:       ErrKeyNotPresent,
		},
		{
			name:      "SignatureKey",
			keyType:   SignatureKey,
			data:      bertlv.TLVData{keyOriginAttributesTag: maketag(SignatureKey, KeyGeneratedByCard)},
			keyOrigin: KeyGeneratedByCard,
		},
		{
			name:      "DecryptionKey",
			keyType:   DecryptionKey,
			data:      bertlv.TLVData{keyOriginAttributesTag: maketag(DecryptionKey, KeyGeneratedByCard)},
			keyOrigin: KeyGeneratedByCard,
		},
		{
			name:      "AuthenticationKey",
			keyType:   AuthenticationKey,
			data:      bertlv.TLVData{keyOriginAttributesTag: maketag(AuthenticationKey, KeyImportedToCard)},
			keyOrigin: KeyImportedToCard,
		},
		{
			name:      "UnknownKey",
			keyType:   AuthenticationKey,
			data:      bertlv.TLVData{keyOriginAttributesTag: maketag(AuthenticationKey, KeyOriginLast+1)},
			err:       ErrUnknownKeyOrigin,
			keyOrigin: KeyNotPresent,
		},
	}

	for _, tc := range cases {
		// avoid aliasing due to test.parallel.
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gpgData := GpgData{
				tlvValues: tc.data,
			}
			origin, err := gpgData.Origin(tc.keyType)
			expectedError(t, err, tc.err)

			if origin != tc.keyOrigin {
				t.Errorf("origin: [%d][%s] != expected: [%d][%s]", origin, origin, tc.keyOrigin, tc.keyOrigin)
			}

			// check date as well.
			_, err = gpgData.Date(tc.keyType)
			expectedError(t, err, ErrNoSuchTag)
		})
	}
}

func Test_gpgLogin(t *testing.T) {
	t.Parallel()

	goodPinResponseList := [][]byte{}
	goodPin := []byte{1, 2, 3, 7, 8, 4}
	badPin := []byte{1, 2, 3, 4, 5, 6}

	goodPinAPDUList := []apdu{
		{
			instruction: insVerify,
			param2:      paramOpenGPGVerifyPW1,
			data:        goodPin,
		},
	}
	_ = goodPinAPDUList
	_ = goodPinResponseList
	badPinAPDUList := []apdu{
		{
			instruction: insVerify,
			param2:      paramOpenGPGVerifyPW1,
			data:        badPin,
		},
		{
			instruction: insGetDataA,
			param2:      paramOpenGPGGetRetries,
		},
	}

	badPinResponseList := [][]byte{}
	Ctx := &TestSCTx{}

	// no field
	err := gpgLogin(nil, nil, 0)
	expectedError(t, err, ErrNotFound)

	// no pin
	err = gpgLogin(Ctx, nil, paramOpenGPGVerifyPW1)
	expectedError(t, err, ErrNotFound)

	// bad pin
	// 	case st == 0x6982:
	//		// odd, gpg returns 0x6982 but no retries number.
	//		return AuthErr{-1}
	Ctx.TransmitErr = []error{&apduErr{0x69, 0x82}}
	Ctx.CurrentAPDUIndex = 0
	Ctx.APDUList = badPinAPDUList
	Ctx.ResponseList = badPinResponseList
	err = gpgLogin(Ctx, badPin, paramOpenGPGVerifyPW1)
	expectedError(t, err, ErrNotFound)
}

func Test_GetAttestationCert(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		keyType KeyType
		err     error
	}{
		{
			name:    "AttestKey",
			keyType: AttestKey,
			err:     ErrUnknownKeyType,
		},
		{
			name:    "KeyTypeUnknown",
			keyType: KeyTypeUnknown,
			err:     ErrUnknownKeyType,
		},
	}

	for _, tc := range cases {
		// avoid aliasing due to test.parallel.
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cert, err := gpgAttestationCertByType(nil, tc.keyType)
			expectedError(t, err, tc.err)
			if cert != nil {
				t.Errorf("Expected cert to be nil.")
				t.FailNow()
			}
		})
	}
}

func Test_GetAttestationCert2(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		yk      *GPGYubiKey
		keyType KeyType
		err     error
	}{
		{
			name:    "AttestKey",
			keyType: AttestKey,
			yk:      &GPGYubiKey{},
			err:     ErrNotFound,
		},
		{
			name:    "KeyTypeUnknown",
			keyType: KeyTypeUnknown,
			yk: &GPGYubiKey{
				gpgData: &GpgData{},
			},
			err: ErrUnknownKeyType,
		},
		{
			name:    "SignatureKey",
			keyType: SignatureKey,
			err:     ErrNotFound,
		},
		{
			name:    "DecryptionKey",
			keyType: DecryptionKey,
			err:     ErrNotFound,
		},
		{
			name:    "AuthenticationKey",
			keyType: AuthenticationKey,
			err:     ErrNotFound,
		},
		{
			name:    "AttestKey",
			keyType: AttestKey,
			err:     ErrNotFound,
		},
		{
			name:    "KeyTypeUnknown",
			keyType: KeyTypeUnknown,
			err:     ErrUnknownKeyType,
		},
	}

	for _, tc := range cases {
		// avoid aliasing due to test.parallel.
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var err error

			yk := tc.yk
			if yk == nil {
				c := BasicSCHandle(t)
				yk, err = c.OpenGPG("")
				expectedError(t, err, nil)
			}

			cert, err := yk.GetAttestationCert(tc.keyType)
			expectedError(t, err, tc.err)
			if cert != nil {
				t.Errorf("Expected cert to be nil.")
				t.FailNow()
			}
		})
	}
}

func Test_ParseCardHolderName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		testName       string
		cardholderName []byte
		expected       string
	}{
		{
			testName:       "nil",
			cardholderName: nil,
			expected:       NameNotSet,
		},
		{
			testName:       "empty",
			cardholderName: []byte{},
			expected:       NameNotSet,
		},
		{
			testName:       "empty",
			cardholderName: []byte(""),
			expected:       NameNotSet,
		},
		{
			testName:       "SnowFlake<1",
			cardholderName: []byte("SnowFlake<1"),
			expected:       "SnowFlake 1",
		},
		{
			testName:       "SnowFlake<1<",
			cardholderName: []byte("SnowFlake<1<"),
			expected:       "SnowFlake 1 ",
		},
		{
			testName:       "SnowFlake<1<<",
			cardholderName: []byte("SnowFlake<1<<"),
			expected:       "SnowFlake 1",
		},
		{
			testName:       "SnowFlake<1<<3",
			cardholderName: []byte("SnowFlake<1<<3"),
			expected:       "3\nSnowFlake 1",
		},
		{
			cardholderName: []byte("SnowFlake<1<<3<<<"),
			expected:       "3<<<\nSnowFlake 1",
		},
	}

	for _, tc := range cases {
		// avoid aliasing due to test.parallel.
		tc := tc
		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			result := ParseCardHolderName(tc.cardholderName)
			if result != tc.expected {
				t.Errorf("Expected %q != %q", tc.expected, result)
				t.FailNow()
			}
		})
	}
}
