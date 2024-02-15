package piv

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"text/template"
	"time"
)

// HasTag will check if a tag exists and return the length.
func (g *GpgData) HasTag(key string) (int, bool) {
	aid, ok := g.tlvValues[key]

	return len(aid), ok
}

// getKeyLen will return of the offset and expected length for a given key type.
// key type is an int between 0 and 2.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23-24.
// 4.4.1 DOs for GET DATA.
// 6E.73.C5, 6E.73.C5 and 6E.73.CD are all arrays of keys.
// each one is index*len offset.
// SignatureKey is at [0:n-1].
// DecryptionKey is at [n:2n-1].
// AuthenticationKey is at [2n:3n-1].
// len depends on which field is being examined, keyDateLen and keyFingerprintLen are used for len.
func getKeyLen(keyType KeyType, len int) (int, int) {
	index := int(keyType)
	offset := index * len
	expectedLen := offset + len

	return offset, expectedLen
}

func (g *GpgData) update() error {
	// assumes tlvValues is set.
	//        aid = card.tv['6E.4F']
	// where 0x6E is a tag

	// make sure aid is long enough.
	aid, err := g.GetTag("6E.4F", 13)
	if err != nil {
		return err
	}

	// card.serial = f'{aid[10]:X}{aid[11]:02X}{aid[12]:02X}{aid[13]:02X}'
	g.Serial = fmt.Sprintf("%X%02X%02X%02X", aid[10], aid[11], aid[12], aid[13])
	g.SerialInt = binary.BigEndian.Uint32(aid[10:14])

	// card.longname = f'{reader} SN {card.serial} OpenPGP {aid[6]:X}.{aid[7]:X}'
	g.LongName = fmt.Sprintf("%s SN %s OpenPGP %X.%X", g.Reader, g.Serial, aid[6], aid[7])

	// card.cardholder = ''.join(chr(x) for x in card.tv['65.5B'])
	cardHolderBytes, _ := g.GetTag("65.5B", 0)
	// probably an issue, need to see if it's UTF-8 or ASCII or what from the pgp spec
	g.CardHolder = string(cardHolderBytes)

	// if args.fingerprint is not None and (
	//	args.fingerprint == keyfingerprint(card, 0) or
	// args.fingerprint == keyfingerprint(card, 2) ):
	// print("WARNING: The requested fingerprint matches a non-encryption key")

	g.Rid = UpperCaseHexString(aid[0:5])

	app := ""
	if aid[5] == 1 {
		app = " (OpenPGP)"
	}

	g.Application = fmt.Sprintf("%s%s", UpperCaseHexString(aid[5:6]), app)

	g.Version = fmt.Sprintf("%X.%X", aid[6], aid[7])

	mfg := ""
	if aid[8] == 0 && aid[9] == 6 {
		mfg = " (YubiCo)"
	}

	g.Manufacturer = fmt.Sprintf("%02X%02X%s", aid[8], aid[9], mfg)

	err = g.loadExtendedData()
	if err != nil {
		return err
	}

	return nil
}

const infoTemplate = `
  Card:            {{.LongName}}
  RID:             {{.Rid}}
  Application:     {{.Application}}
  Version:         {{.Version}}
  Manufacturer:    {{.Manufacturer}}
  Serial Number:   {{.Serial}}
  Cardholder Name: {{.CardHolder}}
`

// String makes a GpgData struct readable.
func (g *GpgData) String() (string, error) {
	t1 := template.New("GpgData")
	t1, err := t1.Parse(infoTemplate)
	if err != nil {
		return "", err
	}

	b := strings.Builder{}

	err = t1.Execute(&b, *g)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

// Algorithm returns the Algorithm of the key at index.
//	def keyalg(card, n):
//	   ka = card.tv[f'6E.73.C{n+1}']
//	   if 1 <= ka[0] <= 3:		# RSA
//		   return f'RSA {ka[1]*256+ka[2]}'
//	   else:
//		   return f'Alg={ka[0]:<4d}'
func (g *GpgData) Algorithm(keyType KeyType) (string, error) {
	key := ""
	switch keyType {
	case SignatureKey:
		key = keyAlgorithmSignatureAttributesTag
	case DecryptionKey:
		key = keyAlgorithmDecryptionAttributesTag
	case AuthenticationKey:
		key = keyAlgorithmAuthenticationAttributesTag
	default:
		return "", fmt.Errorf("%w : unknown value: %d", ErrNoSuchTag, keyType)
	}

	// We expect between 1 and 4 bytes.
	data, err := g.GetTag(key, 1)
	if err != nil {
		return "", err
	}

	// RSA
	if data[0] > 0 && data[0] > 3 {
		if len(data) < 3 {
			return "", fmt.Errorf("%w: expected length [%d] > [3]", ErrNoSuchAlgorithm, len(data))
		}

		algorithmNum := uint16(data[1])*256 + uint16(data[2])

		return fmt.Sprintf("RSA %d", algorithmNum), nil
	}

	return fmt.Sprintf("Alg=%-*d", 4, data[0]), nil
}

// Fingerprint returns the Fingerprint of the key at index.
//	def keyfingerprint(card, n):
//	   kf = card.tv['6E.73.C5'][n*20:n*20+20]
//	   return ''.join(f'{x:02X}' for x in kf)
func (g *GpgData) Fingerprint(keyType KeyType) (string, error) {
	offset, expectedLen := getKeyLen(keyType, keyFingerprintLen)

	data, err := g.GetTag(keyInformationTag, expectedLen)
	if err != nil {
		return "", err
	}

	return UpperCaseHexString(data[offset:expectedLen]), nil
}

// def print_keys(card):
//    for i,name in enumerate(['Sig','Dec','Aut']):
//        print(f"  {name}  {keyalg(card,i):8s}  {keyid(card,i)}  {keyfingerprint(card,i):40s}  {keydate(card,i)}  {keyorigin(card,i)}", file=sys.stderr)

// ID returns the ID of the key at index.
// ID is the last 8 bytes of the fingerprint.
//	def keyid(card, n):
//	   kf = card.tv['6E.73.C5'][n*20:n*20+20]
//	   return ''.join(f'{x:02X}' for x in kf[-8:])
func (g *GpgData) ID(keyType KeyType) (string, error) {
	_, expectedLen := getKeyLen(keyType, keyFingerprintLen)

	data, err := g.GetTag(keyInformationTag, expectedLen)
	if err != nil {
		return "", err
	}

	// we only want the last 8 bytes of the key.
	start := expectedLen - 8

	return UpperCaseHexString(data[start:expectedLen]), nil
}

// Date returns the Date of the key at index.
//	def keydate(card, n):
//	   kd = card.tv['6E.73.CD'][n*4:n*4+4]
//	   timestamp = (kd[0]<<24)|(kd[1]<<16)|(kd[2]<<8)|kd[3]
//	   return datetime.fromtimestamp(timestamp)		# TODO fix time zone
func (g *GpgData) Date(keyType KeyType) (time.Time, error) {
	offset, expectedLen := getKeyLen(keyType, keyDateLen)

	data, err := g.GetTag(keyDateTag, expectedLen)
	if err != nil {
		return time.Time{}, err
	}

	dateData := data[offset:expectedLen]
	//  Each value shall be seconds since Jan 1, 1970. Default value is 00000000 (not specified).
	dateInt := binary.BigEndian.Uint32(dateData[0:4])

	return time.Unix(int64(dateInt), 0), nil
}

// Origin returns the Origin of the key at index.
//	def keyorigin(card, n):
//	   if '6E.73.DE' in card.tv:
//		   return (['empty    ','generated','imported '])[card.tv['6E.73.DE'][2*n+1]]
//	   else:
//		   return ''
func (g *GpgData) Origin(keyType KeyType) (KeyOrigin, error) {
	offset := int(keyType)*2 + 1

	if tagLen, hasDate := g.HasTag(keyOriginAttributesTag); tagLen == 0 || !hasDate {
		// If the tag doesn't exist it's not present.
		return KeyNotPresent, nil
	}

	data, err := g.GetTag(keyOriginAttributesTag, 6)
	if err != nil {
		return KeyNotPresent, err
	}

	keyValue := uint(data[offset])
	if keyValue > uint(KeyOriginLast) {
		return KeyNotPresent, fmt.Errorf("%w: [%d] > KeyOriginLast(%d)", ErrUnknownKeyOrigin, keyValue, KeyOriginLast)
	}

	return KeyOrigin(keyValue), nil
}

func (g *GpgData) dprintf(format string, a ...any) {
	if !g.debug {
		return
	}

	fmt.Printf(format, a...)
}

func ExportRsaPublicKeyAsPemStr(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	pemString := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)

	return string(pemString), nil
}

// tagBytes returns a []byte from the 1 based offset.  This is here to make it easier to compare to the spec.
// The spec is 1 based.
// We expect 2,3 to return b[1,2] which is 2 bytes #1 and #2.
func getBytesWith1BasedIndexing(b []byte, start, end int) []byte {
	// since start is 1 shorter, end is 1 longer.
	return b[start-1 : end]
}

// getByteWith1BasedIndexing returns a byte from the 1 based offset.  This is here to make it easier to compare to the spec.
// The spec is 1 based.
// we expect 2,3 to return b[1,2] which is 2 bytes #1 and #2.
func getByteWith1BasedIndexing(b []byte, index int) byte {
	return b[index-1]
}

func (g *GpgData) loadExtendedData() error {
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23.
	// 4.4.1 DOs for GET DATA.
	// Application Related Data.
	// 6E.73.C0 == Extended Capabilities Flag list.
	// This tag has bits to determine what is supported in 4.4.3.7 Extended Capabilities.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 33.
	// 4.4.3.7 Extended Capabilities

	g.SecureMessaging = NoSecureMessaging
	g.MaximumChallengeLength = 0
	g.MaximumCardholderCertificatesLength = 0
	g.MaximumSpecialDOsLength = 0
	g.PinBlock2Supported = false
	g.MSECommandSupported = false

	tag, err := g.GetTag(extendedCapabilitiesTag, 10)
	if errors.Is(err, ErrNoSuchTag) {
		return nil
	} else if err != nil {
		return fmt.Errorf("loadExtendedData failed: %w", err)
	}

	// tag is 10 bytes, need to decode it.
	// byte 1 is a bit field.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 32.
	// 4.4.3.7 Extended Capabilities.
	// byte 1
	capabilitiesByte := getByteWith1BasedIndexing(tag, 1)

	// set capabilities.
	// byte1 bit8, byte 2
	err = g.setSecureMessaging(capabilitiesByte, getByteWith1BasedIndexing(tag, 2))
	if err != nil {
		return fmt.Errorf("loadExtendedData(setSecureMessaging) failed: %w", err)
	}

	// byte1 bit7,  byte 3-4
	err = g.setGetChallengeSupported(capabilitiesByte, getBytesWith1BasedIndexing(tag, 3, 4))
	if err != nil {
		return fmt.Errorf("loadExtendedData(setGetChallengeSupported) failed: %w", err)
	}

	// byte1 bit6
	g.KeyImportSupported = isSupported(capabilitiesByte, KeyImport)
	// byte1 bit5
	g.PWStatusChangeable = isSupported(capabilitiesByte, PWStatusChangeable)
	// byte1 bit4
	g.PrivateUseDOsSupported = isSupported(capabilitiesByte, PrivateUseDOs)
	// byte1 bit3
	g.AlgorithmAttributesChangeable = isSupported(capabilitiesByte, AlgorithmAttributesChangeable)
	// byte1 bit2
	g.SupportsPSODecryptionEncryptionWithAES = isSupported(capabilitiesByte, PSODECENCwithAES)
	// byte1 bit1
	g.KDFSupported = isSupported(capabilitiesByte, KDFSupported)

	// byte 5-6
	g.MaximumCardholderCertificatesLength = binary.BigEndian.Uint16(getBytesWith1BasedIndexing(tag, 5, 6))

	// byte 7-8
	g.MaximumSpecialDOsLength = binary.BigEndian.Uint16(getBytesWith1BasedIndexing(tag, 7, 8))

	// byte 9
	// opening Yubico Yubikey NEO CCID
	// PinBlock2Supported: 0x0: false
	// MSECommandSupported: 0xff: true
	// opening Yubico Yubikey NEO U2F+CCID
	// PinBlock2Supported: 0x0: false
	// MSECommandSupported: 0xff: true
	// opening Yubico YubiKey OTP+FIDO+CCID
	// PinBlock2Supported: 0x0: false
	// MSECommandSupported: 0x0: false
	g.PinBlock2Supported = isSupported(getByteWith1BasedIndexing(tag, 9), 0x01)
	// fmt.Printf("%s: 0x%x: %t\n", "PinBlock2Supported", getByteWith1BasedIndexing(tag, 9), g.PinBlock2Supported)

	// byte 10
	g.MSECommandSupported = isSupported(getByteWith1BasedIndexing(tag, 10), 0x01)
	// fmt.Printf("%s: 0x%x: %t\n", "MSECommandSupported", getByteWith1BasedIndexing(tag, 10), g.MSECommandSupported)

	return nil
}

func (g *GpgData) setSecureMessaging(capabilitiesByte, smByte byte) error {
	if capabilitiesByte&SecureMessaging != SecureMessaging {
		return nil
	}

	if smByte > byte(SecureMessagingAlgorithmLast) {
		return ErrNoSuchAlgorithm
	}

	g.SecureMessagingSupported = true
	g.SecureMessaging = SecureMessagingAlgorithm(smByte)

	return nil
}

func (g *GpgData) setGetChallengeSupported(capabilitiesByte byte, challenge []byte) error {
	if capabilitiesByte&GetChallenge != GetChallenge {
		return nil
	}

	if len(challenge) != 2 {
		return ErrTooShort
	}

	g.GetChallengeSupported = true
	g.MaximumChallengeLength = binary.BigEndian.Uint16(challenge)

	return nil
}

func isSupported(capabilitiesByte, flagValue byte) bool {
	return capabilitiesByte&flagValue == flagValue
}
