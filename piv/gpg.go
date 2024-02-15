package piv

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/go-piv/piv-go/bertlv"
)

var (
	// Smartcard Application IDs for YubiKeys.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 15
	// 4.2.1 Application Identifier (AID).
	aidOpenPGP = [...]byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}

	// CRT fields for generating key pairs.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 74
	// 7.2.14 GENERATE ASYMMETRIC KEY PAIR.
	// Digital signature: B6 00 or B6 03 84 01 01.
	// Confidentiality: B8 00 or B8 03 84 01 02.
	// Authentication: A4 00 or A4 03 84 01 03.
	crtDigitalSignature    = [...]byte{0xB6, 0x00}
	crtConfidentiality     = [...]byte{0xB8, 0x00}
	crtAuthentication      = [...]byte{0xA4, 0x00}
	crtDigitalSignatureExt = [...]byte{0xB6, 0x03, 0x84, 0x01, 0x011}
	crtConfidentialityExt  = [...]byte{0xB8, 0x03, 0x84, 0x01, 0x02}
	crtAuthenticationExt   = [...]byte{0xA4, 0x03, 0x84, 0x01, 0x03}
)

// OpenGPG connects to a YubiKey OpenGPG smart card.
func OpenGPG(card string) (*GPGYubiKey, error) {
	var c client

	return c.OpenGPG(card)
}

// OpenGPG connects to a YubiKey OpenGPG smart card.
func (c *client) OpenGPG(card string) (*GPGYubiKey, error) {
	ctx, err := newSCContext()
	if err != nil {
		return nil, fmt.Errorf("connecting to smart card daemon: %w", err)
	}

	h, err := ctx.Connect(card)
	if err != nil {
		ctx.Close()

		return nil, fmt.Errorf("connecting to smart card: %w", err)
	}

	tx, err := h.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning smart card transaction: %w", err)
	}

	// if DebugOpen was set, set debug on the tx so we can see dumps from here out.
	if DebugOpen {
		tx.EnableDebug()
	}

	err = ykSelectOpenGPGApplication(tx)
	if err != nil {
		tx.Close()

		return nil, fmt.Errorf("selecting openpgp applet: %w", err)
	}
	//

	yk := &GPGYubiKey{
		YubiKey: YubiKey{ctx: ctx, h: h, tx: tx},
		gpgData: nil,
	}

	// tx.EnableDebug()
	yk.gpgData, err = ykOpenGPGData(tx, card)
	if err != nil {
		tx.Close()

		return nil, fmt.Errorf("selecting openpgp applet: %w", err)
	}

	return yk, nil
}

func ykSelectOpenGPGApplication(tx *scTx) error {
	cmd := apdu{
		instruction: insSelectApplication,
		param1:      0x04,
		data:        aidOpenPGP[:],
	}

	if _, err := tx.Transmit(cmd); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

//
//// CRT fields for generating key pairs.
//// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 74
//// 7.2.14 GENERATE ASYMMETRIC KEY PAIR.
//// Digital signature: B6 00 or B6 03 84 01 01
//// Confidentiality: B8 00 or B8 03 84 01 02
//// Authentication: A4 00 or A4 03 84 01 03
//// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
//// see ykGenerateKey
//func ykOpenGPGGenerateKey(tx *scTx, keyType AsymmetricKeyType) error {
//	cmd := apdu{
//		instruction: insGenerateAsymmetric,
//		param1:      0x04,
//		data:        aidOpenPGP[:],
//	}
//
//	if _, err := tx.Transmit(cmd); err != nil {
//		return fmt.Errorf("command failed: %w", err)
//	}
//
//	return nil
//}

func ykOpenGPGValidateReadOrGenerate(readOrGenerate int) (byte, error) {
	switch readOrGenerate {
	case AsymmetricReadKey:
		return paramOpenGPGAsymmetricRead, nil
	case AsymmetricGenerateKey:
		return paramOpenGPGAsymmetricGenerate, nil
	default:
		return 0, fmt.Errorf("%w: unexpected read/generate type: %d", ErrUnknownKeyType, readOrGenerate)
	}
}

func ykOpenGPGValidateKeyType(keyType AsymmetricKeyType) ([]byte, error) {
	switch keyType {
	case AsymmetricDigitalSignature:
		return crtDigitalSignature[:], nil
	case AsymmetricConfidentiality:
		return crtConfidentiality[:], nil
	case AsymmetricAuthentication:
		return crtAuthentication[:], nil
	case AsymmetricDigitalSignatureExt:
		return crtDigitalSignatureExt[:], nil
	case AsymmetricConfidentialityExt:
		return crtConfidentialityExt[:], nil
	case AsymmetricAuthenticationExt:
		return crtAuthenticationExt[:], nil
	default:
		return nil, fmt.Errorf("%w: unexpected keyType: %d", ErrUnknownKeyType, keyType)
	}
}

// CRT fields for generating key pairs.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 74
// 7.2.14 GENERATE ASYMMETRIC KEY PAIR.
// Digital signature: B6 00 or B6 03 84 01 01
// Confidentiality: B8 00 or B8 03 84 01 02
// Authentication: A4 00 or A4 03 84 01 03
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
// see ykGenerateKey.
func ykOpenGPGReadKey(tx *scTx, keyType AsymmetricKeyType, readOrGenerate int) (*bertlv.TLVData, error) {
	cmd := apdu{
		instruction: insGenerateAsymmetric,
	}

	var err error

	// 0x80 generate, 0x81 == read
	cmd.param1, err = ykOpenGPGValidateReadOrGenerate(readOrGenerate)
	if err != nil {
		return nil, fmt.Errorf("failed reading key %s: %w", keyType, err)
	}

	cmd.data, err = ykOpenGPGValidateKeyType(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed validating keytype  %s: %w", keyType, err)
	}

	data, err := tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed getting key %s: %w", keyType, err)
	}

	if tx.debug {
		fmt.Printf("data: %s\n", bertlv.MakeJSONString(data))
	}

	tlvData := &bertlv.TLVData{}
	_, err = bertlv.Parse(data, tlvData)
	if err != nil {
		return nil, fmt.Errorf("failed parsing key %s: %w", keyType, err)
	}

	return tlvData, nil
}

// ykOpenGPGData calls GET Data for Data Objects 65, 6E, 7A.
func ykOpenGPGData(tx *scTx, reader string) (*GpgData, error) {
	gpgData := &GpgData{
		tlvValues: bertlv.TLVData{},
		Reader:    reader,
	}

	for _, dataByte := range []byte{cardHolderDataTag, applicationRelatedDataTag, securitySupportTemplateTag} {
		cmd := apdu{
			instruction: insGetDataA,
			param1:      0,
			param2:      dataByte,
			data:        []byte{},
		}

		data, err := tx.Transmit(cmd)
		if err != nil {
			return nil, fmt.Errorf("command failed: %w", err)
		}

		gpgData.dprintf("data: %s\n", bertlv.MakeJSONString(data))

		rv, err := bertlv.Parse(data, &gpgData.tlvValues)
		if err != nil {
			return nil, err
		}

		gpgData.dprintf("bertlv: %s\n", bertlv.MakeJSONString(rv))
	}

	// need to call update to set up the fields.
	err := gpgData.update()
	if err != nil {
		return nil, err
	}

	// get the applet version
	gpgData.AppletVersion, err = gpgAppletVersion(tx)
	if err != nil {
		return nil, err
	}

	gpgData.dprintf(gpgData.String())

	return gpgData, nil
}

// GetTag will get the results from a tag.
// if expectedLen is >0 it will verify the length.
func (g *GpgData) GetTag(key string, expectedLen int) ([]byte, error) {
	aid, ok := g.tlvValues[key]
	if !ok {
		return nil, ErrNoSuchTag
	}

	if len(aid) < expectedLen {
		return nil, fmt.Errorf("tlvValue %s too short, got [%d] needed at least [%d], %w", key, len(aid), expectedLen, ErrTooShort)
	}

	return aid, nil
}

// PublicKey returns blah.
//       from Crypto.PublicKey import RSA		# python3 -m pip install pycryptodome
//        from Crypto.Cipher import PKCS1_v1_5
//
//        # read the encryption public key (7.2.14 page 74)
//        # 0x00 instruction, param1=0x81, param2=0x00, len=0x02, data[0xBB,0x00], 0x00
//        apdu = [0x00, 0x47, 0x81, 0x00, 0x02, 0xB8, 0x00, 0x00]
//        resp = send_apdu(card, apdu)
//
//        pubdata = tlvbuf(resp).parse_ber()
//
//        if debug:
//            pubdata.print()
func (yk *GPGYubiKey) PublicKey(keyType AsymmetricKeyType, readOrGenerate int) (*rsa.PublicKey, error) {
	keyOrigin, err := yk.gpgData.Origin(keyType.KeyType())
	if err != nil {
		return nil, err
	}

	if keyOrigin == KeyNotPresent {
		return nil, fmt.Errorf("%w: key type %s not present", ErrKeyNotPresent, keyType)
	}

	tlvData, err := ykOpenGPGReadKey(yk.tx, keyType, readOrGenerate)
	if err != nil {
		return nil, err
	}

	// need to parse the data we got back now.
	//        # read the encryption public key (7.2.14 page 74)
	//    # extract modulus (N) into python big-integer
	//    N = 0
	//    for x in pubdata['3FC9.81']:
	//        N = N * 256 + x
	N := big.NewInt(0)
	shifter := big.NewInt(256)

	for _, value := range (*tlvData)[openGpgModulusTag] {
		// first shift by 8  (*256)
		N = N.Mul(N, shifter)
		// then add v
		N = N.Add(N, big.NewInt(int64(value)))
	}

	//    # extract exponent (V) into python integer
	//    V = 0
	//    for x in pubdata['3FC9.82']:
	//        V = V * 256 + x
	E := 0
	for _, value := range (*tlvData)[openGpgExponentTag] {
		E = E*256 + int(value)
	}
	//    # construct an RSA public key object
	//    pubkey = RSA.construct( (N, V) )
	//
	//    if args.show_public:
	//        print(pubkey.exportKey(format='PEM').decode())

	return &rsa.PublicKey{N: N, E: E}, nil
}

// SerialString returns the YubiKey's serial number.
func (yk *GPGYubiKey) SerialString() (string, error) {
	if yk.gpgData == nil {
		return "", ErrNotFound
	}

	return yk.gpgData.Serial, nil
}

// Serial returns the YubiKey's serial number.
// this is odd.  ykman list will show hex output of this.
// if you are comparing to ykman list, you want to use:
// fmt.Sprintf("%X%02X%02X%02X", (serial & 0xff000000) >> 24), (serial & 0x00ff0000) >> 16), (serial & 0x0000ff00) >> 8), (serial & 0x000000ff)).
func (yk *GPGYubiKey) Serial() (uint32, error) {
	if yk.gpgData == nil {
		return 0, ErrNotFound
	}

	return yk.gpgData.SerialInt, nil
}

// GPGData returns the GpgData if it was opened in GPG mode.
func (yk *GPGYubiKey) GPGData() (*GpgData, error) {
	if yk.gpgData == nil {
		return nil, fmt.Errorf("%w: card not opened in gpg mode", ErrNotFound)
	}

	return yk.gpgData, nil
}

func getPinRetries(tx *scTx) ([]byte, error) {
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 16.
	// 4.3 User Verification in the OpenPGP Application.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23

	// 7.2 Commands in Detail.
	// 7.2.2 VERIFY.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 52-53.
	// If the command is called with P1 = 00 and no data (Lc empty), then the actual access status of the addressed password in P2 is returned. If the password is still verified the cards answers with normal status bytes (SW1-SW2 = 9000). If the password is not checked and the verification is required, then the card answers with the status bytes 63CX, where 'X' encodes the number of further allowed retries.
	cmd := apdu{instruction: insGetDataA, param1: 0x00, param2: paramOpenGPGGetRetries}

	return tx.Transmit(cmd)
}

func parsePinRetries(data []byte, pwField byte) (byte, error) {
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23
	switch pwField {
	case paramOpenGPGVerifyPW1:
		return getByteWith1BasedIndexing(data, 5), nil
	case paramOpenGPGVerifyPW2:
		return getByteWith1BasedIndexing(data, 6), nil
	case paramOpenGPGVerifyPW3:
		return getByteWith1BasedIndexing(data, 7), nil
	default:
		return 0, fmt.Errorf("%w: pwField 0x%x", ErrNotFound, pwField)
	}
}

func gpgLogin(tx *scTx, pin string, pwField byte) error {
	switch pwField {
	case paramOpenGPGVerifyPW1, paramOpenGPGVerifyPW2, paramOpenGPGVerifyPW3:
		break
	default:
		return fmt.Errorf("%w: pwField 0x%x", ErrNotFound, pwField)
	}

	data := []byte(pin)

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 16.
	// 4.3 User Verification in the OpenPGP Application.

	// 7.2 Commands in Detail.
	// 7.2.2 VERIFY.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 52-53.
	cmd := apdu{instruction: insVerify, param1: 0x00, param2: pwField, data: data}
	if _, err := tx.Transmit(cmd); err != nil {
		e2 := errors.Unwrap(err)
		if e2 != nil && errors.Is(e2, AuthErr{-1}) {
			fmt.Printf("Need to check retries\n")

			data, err = getPinRetries(tx)
			if err == nil {
				// we got data back.
				retries, err := parsePinRetries(data, pwField)
				if err == nil {
					// we have retries.
					return AuthErr{Retries: int(retries)}
				}
			}
		}

		return fmt.Errorf("verify pin: %w", err)
	}

	return nil
}

// AuthPIN attempts to authenticate against the card with the provided PIN.
// The PIN is required to use and modify certain slots.
//
// After a specific number of authentication attempts with an invalid PIN,
// usually 3, the PIN will become block and refuse further attempts. At that
// point the PUK must be used to unblock the PIN.
//
// Use DefaultPIN if the PIN hasn't been set.
func (yk *GPGYubiKey) AuthPIN(pin string) error {
	// snowflake uses 2
	return gpgLogin(yk.tx, pin, paramOpenGPGVerifyPW2)
}

func gpgAppletVersion(tx *scTx) (string, error) {
	v, err := loadYkVersion(tx, insGetGPGAppletVersion)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch), nil
}

func gpgComputeDigitalSignature(tx *scTx, data []byte) ([]byte, error) {
	cmd := apdu{
		instruction: insPerformSecurityOperation,
		param1:      securityOperationComputeDigitalSignatureParam1,
		param2:      securityOperationComputeDigitalSignatureParam2,
		data:        data,
	}

	signature, err := tx.Transmit(cmd)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// gpgDecipher requires PW1 (82) has been presented.
// data should already be in pkcs#1 format.
func gpgDecipher(tx *scTx, ciphertext []byte) ([]byte, error) {
	cmd := apdu{
		instruction: insPerformSecurityOperation,
		param1:      securityOperationDecipherParam1,
		param2:      securityOperationDecipherParam2,
		// add 1 for padding byte
		data: make([]byte, len(ciphertext)+1),
	}

	// padding byte is zero, add data after it.
	copy(cmd.data[1:], ciphertext)

	// FIXME: add support for the DO decryption.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 68
	// if aes &&gpgData.SupportsPSODecryptionEncryptionWithAES { cmd.data[0]=0x02}

	data, err := tx.Transmit(cmd)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func gpgEncipher(tx *scTx, data []byte) ([]byte, error) {
	// needs to be a multiple of 16
	dl := len(data)

	cmd := apdu{
		instruction: insPerformSecurityOperation,
		param1:      securityOperationEncipherParam1,
		param2:      securityOperationEncipherParam2,
	}

	if dl%16 == 0 {
		cmd.data = data
	} else {
		// only copy if we need to pad.
		cmd.data = make([]byte, dl+16-(dl%16))
		copy(cmd.data, data)
	}

	result, err := tx.Transmit(cmd)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (yk *GPGYubiKey) Decrypt(data []byte) ([]byte, error) {
	return gpgDecipher(yk.tx, data)
}

func (yk *GPGYubiKey) String() string {
	return bertlv.MakeJSONString(*yk)
}

func (yk *YubiKey) String() string {
	return bertlv.MakeJSONString(*yk)
}
