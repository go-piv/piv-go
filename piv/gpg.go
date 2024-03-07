package piv

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/areese/piv-go/bertlv"
)

// nolint:gochecknoglobals
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
	c := Client{
		client:      &client{},
		SCConstruct: &PCSCConstructor{},
	}

	return c.OpenGPG(card)
}

// OpenGPG connects to a YubiKey OpenGPG smart card.
func (c *Client) OpenGPG(card string) (*GPGYubiKey, error) {
	ctx, err := c.SCConstruct.NewSCContext()
	if err != nil {
		return nil, fmt.Errorf("connecting to smart card daemon: %w", err)
	}

	h, err := ctx.Connect(card)
	if err != nil {
		// FIXME: add logging to log the close errors
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
		ctx:     ctx,
		h:       h,
		tx:      tx,
		gpgData: nil,
		trace:   false,
	}

	// tx.EnableDebug()
	yk.gpgData, err = ykOpenGPGData(tx, card)
	if err != nil {
		tx.Close()

		return nil, fmt.Errorf("selecting openpgp applet: %w", err)
	}

	return yk, nil
}

func ykSelectOpenGPGApplication(tx SCTx) error {
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 51.
	// 7.2.1 SELECT.
	cmd := apdu{
		instruction: insSelectApplication,
		param1:      paramOpenGPGASelectApplication,
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
func ykOpenGPGReadKey(tx SCTx, keyType AsymmetricKeyType, generateKey bool) (*bertlv.TLVData, error) {
	cmd := apdu{
		instruction: insGenerateAsymmetric,
		// default to read
		param1: paramOpenGPGAsymmetricRead,
	}

	var err error

	// 0x80 generate, 0x81 == read
	if generateKey {
		cmd.param1 = paramOpenGPGAsymmetricGenerate
	}

	cmd.data, err = ykOpenGPGValidateKeyType(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed validating keytype  %s: %w", keyType, err)
	}

	data, err := tx.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed getting key %s: %w", keyType, err)
	}

	if tx.IsDebugEnabled() {
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
func ykOpenGPGData(tx SCTx, reader string) (*GpgData, error) {
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

// ReadPublicKey returns the public Key stored in the yubikey.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 74.
// 7.2.14 GENERATE ASYMMETRIC KEY PAIR.
func (yk *GPGYubiKey) ReadPublicKey(keyType AsymmetricKeyType) (*rsa.PublicKey, error) {
	return yk.readOrGeneratePublicKey(keyType, KeyOriginAny, false)
}

// ReadPublicKeyWithOrigin returns the public Key stored in the yubikey only if it originates from the requested place.
// Origin is Generated or Imported.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 74.
// 7.2.14 GENERATE ASYMMETRIC KEY PAIR.
func (yk *GPGYubiKey) ReadPublicKeyWithOrigin(keyType AsymmetricKeyType, requestedOrigin KeyOrigin) (*rsa.PublicKey, error) {
	return yk.readOrGeneratePublicKey(keyType, requestedOrigin, false)
}

// GenerateKey generates key on the yubikey and returns the public key portion.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 74.
// 7.2.14 GENERATE ASYMMETRIC KEY PAIR.
func (yk *GPGYubiKey) GenerateKey(keyType AsymmetricKeyType) (*rsa.PublicKey, error) {
	// FIXME: In case of key pair generation the command does not set the values of the corresponding fingerprint.
	// FIXME: After receiving the public key the terminal has to calculate the fingerprint and store it in the relevant DO.
	// FIXME: The generation of a key pair for digital signature resets the digital signature counter to zero (000000), other related DO (e. g. certificates) may be reset also.
	// FIXME: The command can only be used after correct presentation of PW3 for the generation of a key pair.
	// FIXME: Reading of a public key is always possible.
	return yk.readOrGeneratePublicKey(keyType, KeyOriginAny, true)
}

// readOrGeneratePublicKey calls the actual function to read or generate.
// CRT fields for generating key pairs.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 74
// 7.2.14 GENERATE ASYMMETRIC KEY PAIR.
func (yk *GPGYubiKey) readOrGeneratePublicKey(keyType AsymmetricKeyType, requestedOrigin KeyOrigin, generateKey bool) (*rsa.PublicKey, error) {
	if yk.trace {
		fmt.Println("\u001b[31mGPGYubiKey.PublicKey\u001b[0m")
	}

	if yk.gpgData == nil {
		return nil, ErrNotFound
	}

	// FIXME: not sure origin makes sense for generating keys.
	keyOrigin, err := yk.gpgData.Origin(keyType.KeyType())
	if err != nil {
		return nil, err
	}

	if requestedOrigin != KeyOriginAny {
		if keyOrigin != requestedOrigin {
			return nil, fmt.Errorf("%w: keyOrigin: %s requested, but key origin is %s", ErrKeyNotPresent, requestedOrigin.String(), keyOrigin.String())
		}
	}

	tlvData, err := ykOpenGPGReadKey(yk.tx, keyType, generateKey)
	if err != nil {
		return nil, err
	}

	return parsePublicKey(tlvData)
}

// CRT fields for generating key pairs.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 74
// 7.2.14 GENERATE ASYMMETRIC KEY PAIR.
func parsePublicKey(tlvDataPtr *bertlv.TLVData) (*rsa.PublicKey, error) {
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 75
	// Set of public key data objects for RSA:
	// 3FC9.81: 81 xx Modulus (a number denoted as n coded on x bytes)
	// 3FC9.82 xx Public exponent (a number denoted as v, e.g. 65537 dec.)
	// Set of public key data objects for ECDSA/ECDH
	// 86 xx Public key (a point denoted as PP on the curve, equal to x times PB where x is the private key, coded on 2z or z+1 bytes)
	// FIXME: this does not support ECDSA.

	tlvData := *tlvDataPtr

	if _, ok := tlvData[openGpgModulusTag]; !ok {
		return nil, ErrNoPublicKeyModulus
	}

	if _, ok := tlvData[openGpgExponentTag]; !ok {
		return nil, ErrNoPublicKeyExponent
	}

	// need to parse the data we got back now.
	// read the encryption public key (7.2.14 page 74)
	// extract modulus (N)
	N := big.NewInt(0)
	shifter := big.NewInt(256)

	for _, value := range tlvData[openGpgModulusTag] {
		// first shift by 8  (*256)
		N = N.Mul(N, shifter)

		// then add v
		N = N.Add(N, big.NewInt(int64(value)))
	}

	// extract exponent (V)
	E := 0
	for _, value := range tlvData[openGpgExponentTag] {
		E = E*256 + int(value)
	}

	// construct an RSA public key object

	// checkpub isn't public, so.....
	if E < 2 {
		return nil, ErrPublicExponentSmall
	}

	if E > 1<<31-1 {
		return nil, ErrPublicExponentLarge
	}

	if b := N.Bits(); len(b) == 0 {
		return nil, errors.New("modulus must be >= 0")
	} else if b[0]&1 != 1 {
		return nil, errors.New("modulus must be odd")
	}

	return &rsa.PublicKey{N: N, E: E}, nil
}

// SerialString returns the YubiKey's serial number.
func (yk *GPGYubiKey) SerialString() (string, error) {
	if yk == nil {
		return "", ErrNotFound
	}

	if yk.trace {
		fmt.Println("\u001b[31mGPGYubiKey.SerialString\u001b[0m")
	}

	if yk.gpgData == nil {
		return "", ErrNotFound
	}

	return yk.gpgData.Serial, nil
}

// CardHolder returns the Cardholder of the key.
func (yk *GPGYubiKey) CardHolder() (string, error) {
	if yk == nil {
		return "", ErrNotFound
	}

	if yk.trace {
		fmt.Println("\u001b[31mGPGYubiKey.CardHolder\u001b[0m")
	}

	if yk.gpgData == nil {
		return "", ErrNotFound
	}

	return yk.gpgData.GetCardHolder(), nil
}

// Version returns the version of the key.
func (yk *GPGYubiKey) Version() (string, error) {
	if yk == nil {
		return "", ErrNotFound
	}

	if yk.trace {
		fmt.Println("\u001b[31mGPGYubiKey.Version\u001b[0m")
	}

	return yk.gpgData.GetVersion(), nil
}

// AppletVersion returns the version of the applet.
func (yk *GPGYubiKey) AppletVersion() (string, error) {
	if yk == nil {
		return "", ErrNotFound
	}

	if yk.trace {
		fmt.Println("\u001b[31mGPGYubiKey.AppletVersion\u001b[0m")
	}

	return yk.gpgData.GetAppletVersion(), nil
}

// Serial returns the YubiKey's serial number.
// this is odd.  ykman list will show hex output of this.
// if you are comparing to ykman list, you want to use:
// fmt.Sprintf("%X%02X%02X%02X", (serial & 0xff000000) >> 24), (serial & 0x00ff0000) >> 16), (serial & 0x0000ff00) >> 8), (serial & 0x000000ff)).
func (yk *GPGYubiKey) Serial() (uint32, error) {
	if yk == nil {
		return 0, ErrNotFound
	}

	if yk.trace {
		fmt.Println("\u001b[31mGPGYubiKey.Serial\u001b[0m")
	}

	if yk.gpgData == nil {
		return 0, ErrNotFound
	}

	return yk.gpgData.SerialInt, nil
}

// GPGData returns the GpgData if it was opened in GPG mode.
func (yk *GPGYubiKey) GPGData() (*GpgData, error) {
	if yk.trace {
		fmt.Println("\u001b[31mGPGYubiKey.GPGData\u001b[0m")
	}

	if yk.gpgData == nil {
		return nil, fmt.Errorf("%w: card not opened in gpg mode", ErrNotFound)
	}

	return yk.gpgData, nil
}

func getPinRetries(tx SCTx) ([]byte, error) {
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 17.
	// 4.3 User Verification in the OpenPGP Application
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23
	// 4.3 User Verification in the OpenPGP Application
	// 4.4.1 DOs for GET DATA

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 52-53.
	// 7.2 Commands in Detail.
	// 7.2.2 VERIFY.
	// If the command is called with P1 = 00 and no data (Lc empty), then the actual access status of the addressed password in P2 is returned.
	// If the password is still verified the cards answers with normal status bytes (SW1-SW2 = 9000).
	// If the password is not checked and the verification is required, then the card answers with the status bytes 63CX, where 'X' encodes the number of further allowed retries.
	cmd := apdu{instruction: insGetDataA, param1: 0x00, param2: paramOpenGPGGetRetries}

	return tx.Transmit(cmd)
}

func parsePinRetries(data []byte, pwField byte) (byte, error) {
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23
	// 4.3 User Verification in the OpenPGP Application
	// 4.4.1 DOs for GET DATA
	switch pwField {
	case paramOpenGPGVerifyPW1:
		return getByteWith1BasedIndexing(data, 5)
	case paramOpenGPGVerifyPW2:
		return getByteWith1BasedIndexing(data, 6)
	case paramOpenGPGVerifyPW3:
		return getByteWith1BasedIndexing(data, 7)
	default:
		return 0, fmt.Errorf("%w: pwField 0x%x", ErrNotFound, pwField)
	}
}

func gpgLogin(tx SCTx, pin []byte, pwField byte) error {
	switch pwField {
	case paramOpenGPGVerifyPW1, paramOpenGPGVerifyPW2, paramOpenGPGVerifyPW3:
		break
	default:
		return fmt.Errorf("%w: pwField 0x%x", ErrNotFound, pwField)
	}

	if len(pin) == 0 {
		return fmt.Errorf("%w: pin length 0", ErrNotFound)
	}

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 16.
	// 4.3 User Verification in the OpenPGP Application.

	// 7.2 Commands in Detail.
	// 7.2.2 VERIFY.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 52-53.
	cmd := apdu{instruction: insVerify, param1: 0x00, param2: pwField, data: pin}
	if _, err := tx.Transmit(cmd); err != nil {
		e2 := errors.Unwrap(err)
		if e2 != nil && errors.Is(e2, AuthErr{-1}) {
			// fmt.Printf("Need to check retries\n")

			var data []byte

			data, err = getPinRetries(tx)
			if err == nil {
				var numRetriesLeft byte

				// we got data back.
				numRetriesLeft, err = parsePinRetries(data, pwField)
				if err == nil {
					// we have retries.
					return AuthErr{Retries: int(numRetriesLeft)}
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
// FIXME: this only makes calls against PW2, might have to check PW1 and PW3 for some use cases.
func (yk *GPGYubiKey) AuthPIN(pin []byte) error {
	if yk == nil {
		return ErrNotFound
	}

	// snowflake uses 2
	if yk.trace {
		fmt.Println("\u001b[31mGPGYubiKey.AuthPIN\u001b[0m")
	}

	// Says PW1 len, but this is also for PW2.
	if len(pin) < minPW1Length {
		return ErrTooShort
	}

	if yk.gpgData == nil {
		return ErrNotFound
	}

	return gpgLogin(yk.tx, pin, paramOpenGPGVerifyPW2)
}

func gpgAppletVersion(tx SCTx) (string, error) {
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
func gpgDecipher(tx SCTx, ciphertext []byte) ([]byte, error) {
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

// gpgAttestationCert.
// returns der formatted X509.3 cert.
func gpgAttestationCert(tx SCTx) ([]byte, error) {
	cmd := apdu{
		instruction: insGetDataA,
		param1:      paramOpenGPGGetAttestCertParam1,
		param2:      paramOpenGPGGetAttestCertParam2,
	}

	data, err := tx.Transmit(cmd)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// gpgAttestationCert.
// returns der formatted X509.3 cert.
func gpgAttestationCertByType(tx SCTx, keyType KeyType) ([]byte, error) {
	var slot byte

	//# TLV: 0x60, TLV(0x5c, 0x7f21)
	//    # key slots:
	//    # sig: 1
	//    # enc: 2
	//    # aut: 3
	//    # att: 4

	switch keyType {
	case SignatureKey:
		slot = 1
	case DecryptionKey:
		slot = 2
	case AuthenticationKey:
		slot = 3
	case AttestKey:
		fallthrough
	default:
		return nil, ErrUnknownKeyType
	}

	cmd := apdu{
		instruction: insSelectData,
		param1:      slot,
		param2:      0x04,
		data:        []byte{0x04, 0x07, 0x06, 0x60, 0x04, 0x5c, 0x02, 0x7f, 0x21},
	}

	data, err := tx.Transmit(cmd)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// gpgSelectData.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 57
// 7.2.5 SELECT DATA.
func gpgSelectData(tx SCTx, param1, param2 byte, data []byte) ([]byte, error) {
	cmd := apdu{
		instruction: insSelectData,
		param1:      param1,
		param2:      param2,
		data:        data,
	}

	data, err := tx.Transmit(cmd)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (yk *GPGYubiKey) Decrypt(data []byte) ([]byte, error) {
	if yk.trace {
		fmt.Println("\u001b[31mGPGYubiKey.Decrypt\u001b[0m")
	}

	if yk.gpgData == nil {
		return nil, ErrNotFound
	}

	if len(data) == 0 {
		return nil, ErrTooShort
	}

	return gpgDecipher(yk.tx, data)
}

func (yk *GPGYubiKey) String() string {
	if yk.trace {
		fmt.Println("\u001b[31mGPGYubiKey.String\u001b[0m")
	}
	return bertlv.MakeJSONString(*yk)
}

func (yk *GPGYubiKey) EnableDebug() {
	yk.tx.EnableDebug()
}

func (yk *GPGYubiKey) DisableDebug() {
	yk.tx.DisableDebug()
}

func (yk *GPGYubiKey) EnableTrace() {
	yk.trace = true
	yk.EnableDebug()
}

func (yk *GPGYubiKey) DisableTrace() {
	yk.trace = false
	yk.DisableDebug()
}

func (yk *GPGYubiKey) Close() error {
	return closeHandles(yk.ctx, yk.h)
}

func (yk *GPGYubiKey) GetAttestationCert(keyType KeyType) ([]byte, error) {
	if yk.trace {
		fmt.Println("\u001b[31mGPGYubiKey.GetAttestationCert\u001b[0m")
	}

	if yk.gpgData == nil {
		return nil, ErrNotFound
	}

	switch keyType {
	case AttestKey:
		// Attest key is done differently.
		return gpgAttestationCert(yk.tx)
	case SignatureKey, DecryptionKey, AuthenticationKey:
		// Attest key is done differently.
		return gpgAttestationCertByType(yk.tx, keyType)
	default:
		return nil, ErrUnknownKeyType
	}
}

func (yk *YubiKey) String() string {
	return bertlv.MakeJSONString(*yk)
}

// NewTestGpgYubikey is for testing.
func NewTestGpgYubikey(gpgData *GpgData, trace bool, origins map[KeyType]KeyOrigin) *GPGYubiKey {
	rv := &GPGYubiKey{
		ctx:   &TestSCContext{},
		h:     &TestSCHandle{},
		tx:    &TestSCTx{},
		trace: trace,
		gpgData: &GpgData{
			tlvValues: bertlv.TLVData{},
		},
	}

	rv.gpgData.Copy(gpgData)
	rv.gpgData.debug = trace

	if origins != nil {
		originsBytes := make([]byte, KeyTypeSize)
		for keyType, keyOrigin := range origins {
			originsBytes[keyType.Offset()] = byte(keyOrigin)
		}

		rv.gpgData.tlvValues[keyOriginAttributesTag] = originsBytes
	}

	return rv
}
