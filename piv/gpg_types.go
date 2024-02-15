package piv

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/go-piv/piv-go/bertlv"
)

// References:
//    http://www.unsads.com/specs/ISO/7816/ISO7816-4.pdf
//    also found at: https://github.com/dongri/emv-qrcode-doc/blob/master/ISO%20IEC%207816-4.pdf
//
//    ftp://ftp.gnupg.org/specs/OpenPGP-smart-card-application-3.4.1.pdf
//    https://pyscard.sourceforge.io/user-guide.html
//
//    https://github.com/LedgerHQ/openpgp-card-app

const (
	// insGetDataA is the instruction to get data from a card.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 58
	// 7.2.6 GET DATA.
	// GET DATA with odd INS (CB) is used for reading data from EF.DIR and/or EF.ATR/INFO.
	insGetDataA = 0xca

	// insGetGPGAppletVersion
	// https://developers.yubico.com/ykneo-openpgp/SecurityAdvisory%202015-04-14.html
	insGetGPGAppletVersion = 0xf1

	// insPerformSecurityOperation
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 48
	// 7.1 Usage of ISO Standard Commands.
	// 7.2.10 PSO: COMPUTE DIGITAL SIGNATURE.
	// 7.2.11 PSO: DECIPHER.
	// 7.2.12 PSO: ENCIPHER.
	insPerformSecurityOperation = 0x2a

	// 7.2.10 PSO: COMPUTE DIGITAL SIGNATURE.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 63
	// must have performed PW1 auth first.
	securityOperationComputeDigitalSignatureParam1 = 0x9E
	securityOperationComputeDigitalSignatureParam2 = 0x9A

	// 7.2.11 PSO: DECIPHER.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 67-69
	// must have performed PW2 auth first.
	securityOperationDecipherParam1 = 0x80 // 80 = Return plain value
	securityOperationDecipherParam2 = 0x86 // 86 = Enciphered data present in the data field

	// 7.2.12 PSO: ENCIPHER.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 70
	// must have performed PW1 auth first.
	// these are reversed from decipher.
	securityOperationEncipherParam1 = 0x86 // 86 = Return enciphered data with Padding indicator byte
	securityOperationEncipherParam2 = 0x80 // 80 = Plain data present in the data field

	// cardHolderDataTag is used with insGetDataA to get the Cardholder Related Data.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 22.
	// 4.4.1 DOs for GET DATA.
	cardHolderDataTag = 0x65

	// applicationRelatedDataTag is used with insGetDataA to get the Application Related Data.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23.
	// 4.4.1 DOs for GET DATA.
	applicationRelatedDataTag = 0x6E

	// securitySupportTemplateTag is used with insGetDataA to get the Application Related Data.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 24.
	// 4.4.1 DOs for GET DATA.
	securitySupportTemplateTag = 0x7A

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23.
	// 4.4.1 DOs for GET DATA.
	// Application Related Data.
	// 6E.73.C0 == Extended Capabilities Flag list.
	// This tag has bits to determine what is supported in 4.4.3.7 Extended Capabilities.
	extendedCapabilitiesTag = "6E.73.C0"

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23.
	// 4.4.1 DOs for GET DATA.
	// Application Related Data.
	// Algorithm attributes for signature key.
	// 6E.73.C1 == 1 Byte Algorithm ID, according to RFC 4880/6637 further bytes depending on algorithm (e. g. length modulus and length exponent).
	keyAlgorithmSignatureAttributesTag = "6E.73.C1"

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23.
	// 4.4.1 DOs for GET DATA.
	// Application Related Data.
	// Algorithm attributes for decryption key.
	// 6E.73.C2 == 1 Byte Algorithm ID, according to RFC 4880/6637 further bytes depending on algorithm (e. g. length modulus and length exponent).
	keyAlgorithmDecryptionAttributesTag = "6E.73.C2"

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23.
	// 4.4.1 DOs for GET DATA.
	// Application Related Data.
	// Algorithm attributes for authentication key.
	// 6E.73.C2 == 1 Byte Algorithm ID, according to RFC 4880/6637 further bytes depending on algorithm (e. g. length modulus and length exponent).
	keyAlgorithmAuthenticationAttributesTag = "6E.73.C3"

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23.
	// 4.4.1 DOs for GET DATA.
	// Application Related Data.
	// 6E.73.C5 == Fingerprints (binary, 20 bytes (dec.) each for Sig, Dec, Aut in that order), zero bytes indicate a not defined private key.
	keyInformationTag = "6E.73.C5"
	keyFingerprintLen = 20

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 24.
	// 4.4.1 DOs for GET DATA.
	// Application Related Data.
	// 6E.73.CD == List of generation dates/times of key pairs, binary. 4 bytes, Big Endian each for Sig, Dec and Aut. Each value shall be seconds since Jan 1, 1970. Default value is 00000000 (not specified).
	keyDateTag = "6E.73.CD"
	keyDateLen = 4

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 24.
	// 4.4.1 DOs for GET DATA.
	// Application Related Data.
	// 6E.73.DE == Key Information
	// Every key is presented with its Key-Reference number first (1 byte) and a second status byte.
	// Byte 1-2: Key-Ref. and Status of the signature key Byte 3-4: Key-Ref. and Status of the decryption key Byte 5-6: Key-Ref. and Status of the authentication
	// key
	// Further bytes: Key-Ref. and Status of additional keys
	//( optional) Values for the Status byte:
	// 00 = Key not present (not generated or imported).
	// 01 = Key generated by the card.
	// 02 = Key imported into the card.
	keyOriginAttributesTag = "6E.73.DE"

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 74
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	paramOpenGPGAsymmetricGenerate = paramAsymmetricCryptoMechanism // 0x80
	paramOpenGPGAsymmetricRead     = paramAsymmetricParameter       // 0x81

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 74
	// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=95
	openGpgModulusTag  = "3FC9.81"
	openGpgExponentTag = "3FC9.82"

	// 7.2 Commands in Detail.
	// 7.2.2 VERIFY.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 52-53.
	paramOpenGPGVerifyPW1 = 0x81
	paramOpenGPGVerifyPW2 = 0x82
	paramOpenGPGVerifyPW3 = 0x83

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 23
	paramOpenGPGGetRetries = 0xC4
)

// KeyType is for indexing the keys from a yubikey.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 24
// 4.4.1 DOs for GET DATA.
// Application Related Data.
// 6E.73.DE == Key Information.
type KeyType byte

const (
	// SignatureKey is at  offset 0.
	// 6E.73.C1.
	SignatureKey KeyType = 0

	// DecryptionKey is at  offset 1.
	// 6E.73.C2 .
	DecryptionKey KeyType = 1

	// AuthenticationKey is at offset 2.
	// 6E.73.C3 .
	AuthenticationKey KeyType = 2
	KeyTypeLast               = AuthenticationKey
	KeyTypeUnknown            = 0xFF
)

func (k KeyType) String() string {
	switch k {
	case SignatureKey:
		return "Signature"
	case DecryptionKey:
		return "Decryption"
	case AuthenticationKey:
		return "Authentication"
	}

	return fmt.Sprintf("unknown: %d", k)
}

// KeyOrigin is for determining the Origin of a key.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 24
// 4.4.1 DOs for GET DATA.
// Application Related Data.
// 6E.73.DE == Key Information.
type KeyOrigin byte

const (
	KeyNotPresent      KeyOrigin = 0
	KeyGeneratedByCard KeyOrigin = 1
	KeyImportedToCard  KeyOrigin = 2
	KeyOriginLast                = KeyImportedToCard
)

func (k KeyOrigin) String() string {
	switch k {
	case KeyNotPresent:
		return "KeyNotPresent"
	case KeyGeneratedByCard:
		return "KeyGeneratedByCard"
	case KeyImportedToCard:
		return "KeyImportedToCard"
	}

	return fmt.Sprintf("unknown: %d", k)
}

// AsymmetricKeyType is for determining the type of asymmetric key to create.
// CRT fields for generating key pairs.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 74
// 7.2.14 GENERATE ASYMMETRIC KEY PAIR.
type AsymmetricKeyType byte

const (
	AsymmetricDigitalSignature AsymmetricKeyType = iota
	AsymmetricConfidentiality
	AsymmetricAuthentication
	AsymmetricDigitalSignatureExt
	AsymmetricConfidentialityExt
	AsymmetricAuthenticationExt
	AsymmetricKeyTypeLast = AsymmetricAuthenticationExt
)

func (k AsymmetricKeyType) String() string {
	switch k {
	case AsymmetricDigitalSignature:
		return "Digital Signature"
	case AsymmetricConfidentiality:
		return "Confidentiality"
	case AsymmetricAuthentication:
		return "Authentication"
	case AsymmetricDigitalSignatureExt:
		return "Digital Signature (Extended)"
	case AsymmetricConfidentialityExt:
		return "Confidentiality (Extended)"
	case AsymmetricAuthenticationExt:
		return "Authentication (Extended)"
	}

	return fmt.Sprintf("unknown: %d", k)
}

func (k AsymmetricKeyType) KeyType() KeyType {
	switch k {
	case AsymmetricDigitalSignature, AsymmetricDigitalSignatureExt:
		return SignatureKey
	case AsymmetricConfidentiality, AsymmetricConfidentialityExt:
		return DecryptionKey
	case AsymmetricAuthentication, AsymmetricAuthenticationExt:
		return AuthenticationKey
	}

	return KeyTypeUnknown
}

const (
	AsymmetricGenerateKey = 0 // 0x80
	AsymmetricReadKey     = 1 // 0x81
)

func ReadOrGenerateString(readOrGenerate int) string {
	switch readOrGenerate {
	case AsymmetricReadKey:
		return "AsymmetricReadKey"
	case AsymmetricGenerateKey:
		return "AsymmetricGenerateKey"
	default:
		return fmt.Sprintf("[%d] is not understood as AsymmetricReadKey[%d] or AsymmetricGenerateKey[%d]", readOrGenerate, AsymmetricReadKey, AsymmetricGenerateKey)
	}
}

const (
	// SecureMessaging
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 32.
	// 4.4.3.7 Extended Capabilities.
	// byte 1.
	SecureMessaging               = 0x80 // byte 1, bit8
	GetChallenge                  = 0x40 // byte 1, bit7
	KeyImport                     = 0x20 // byte 1, bit6
	PWStatusChangeable            = 0x10 // byte 1, bit5
	PrivateUseDOs                 = 0x08 // byte 1, bit4
	AlgorithmAttributesChangeable = 0x04 // byte 1, bit3
	PSODECENCwithAES              = 0x02 // byte 1, bit2
	KDFSupported                  = 0x01 // byte 1, bit1

	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 33.
	// 4.4.3.7 Extended Capabilities.
	// byte 2 is covered by SecureMessagingAlgorithm
	// byte 3-4 are Maximum length of a challenge supported by the command GET CHALLENGE (unsigned integer, Most Significant Bit ... Least Significant Bit). If GET CHALLENGE is not supported (see 1st byte), the coding is 0000.
	// byte 5-6 are Maximum length of Cardholder Certificates (DO 7F21, each for AUT, DEC and SIG), coded as unsigned integer (Most Signific- ant Bit ... Least Significant Bit).
	// byte 7-8 are Maximum length of special DOs with no precise length information given in the definition (Private Use, Login data, URL, Algorithm attributes, KDF etc.), coded as unsigned integer (Most Significant Bit ... Least Significant Bit).

	// PinBlock2NotSupported
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 33.
	// 4.4.3.7 Extended Capabilities.
	// byte 9 PIN block 2 format.
	pinBlock2NotSupported = 0x00
	pinBlock2Supported    = 0x01

	// MSECommandNotSupported
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 33.
	// 4.4.3.7 Extended Capabilities.
	// byte 10 (0xA) MSE command for key numbers 2 (DEC) and 3 (AUT).
	MSECommandNotSupported = 0x00
	MSECommandSupported    = 0x01
)

// SecureMessagingAlgorithm the type of secure messaging supported.
// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 33
// 4.4.3.7 Extended Capabilities.
type SecureMessagingAlgorithm byte

const (
	// NoSecureMessaging No secure messaging or proprietary implementation.
	NoSecureMessaging SecureMessagingAlgorithm = 0
	// AES128bit AES 128 bit.
	AES128bit SecureMessagingAlgorithm = 1
	// AES256bit AES 256 bit.
	AES256bit SecureMessagingAlgorithm = 2
	// SCP11b SCP11b.
	SCP11b SecureMessagingAlgorithm = 3

	SecureMessagingAlgorithmLast = SCP11b
)

func (s SecureMessagingAlgorithm) String() string {
	switch s {
	case NoSecureMessaging:
		return "NoSecureMessaging"
	case AES128bit:
		return "AES128bit"
	case AES256bit:
		return "AES256bit"
	case SCP11b:
		return "SCP11b"
	}

	return fmt.Sprintf("unknown: %d", s)
}

var (
	ErrTooShort         = errors.New("error too short")
	ErrNoSuchTag        = errors.New("error too short")
	ErrNoSuchAlgorithm  = errors.New("unable to get key algorithm")
	ErrUnknownKeyOrigin = errors.New("unknown key origin")
	ErrUnknownKeyType   = errors.New("unknown key type")
	ErrKeyNotPresent    = errors.New("key not present")
)

// GpgData holds data about the GPG functionality of the card.
type GpgData struct {
	debug bool

	// SecureMessagingAlgorithm the type of secure messaging supported.
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 33
	// 4.4.3.7 Extended Capabilities.
	// byte 1 SecureMessagingSupported.
	SecureMessagingSupported bool
	// GetChallengeSupported Support for GET CHALLENGE
	// The maximum supported length of a challenge can be found in MaximumChallengeLength.
	GetChallengeSupported bool
	// Support for Key Import
	KeyImportSupported bool
	// PWStatusChangeable PW Status changeable (DO C4 available for PUT DATA)
	PWStatusChangeable bool
	// PrivateUseDOsSupported Support for Private use DOs (0101-0104)
	PrivateUseDOsSupported bool
	// AlgorithmAttributesChangeable Algorithm attributes changeable with PUT DATA
	AlgorithmAttributesChangeable bool
	// SupportsPSODecryptionEncryptionWithAES PSO:DEC/ENC with AES
	SupportsPSODecryptionEncryptionWithAES bool
	// KDF-DO (F9) and related functionality avail- able
	KDFSupported bool

	// PinBlock2Supported
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 33.
	// 4.4.3.7 Extended Capabilities.
	// byte 9 PIN block 2 format.
	PinBlock2Supported bool

	// MSECommandSupported
	// https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf Page 33.
	// 4.4.3.7 Extended Capabilities.
	// byte 10 (0xA) MSE command for key numbers 2 (DEC) and 3 (AUT).
	MSECommandSupported bool

	// SerialInt is an integer of the serial number.
	SerialInt uint32
	// Serial is a hex string of the serial number as displayed by ykman list.
	Serial      string
	LongName    string
	CardHolder  string
	Rid         string
	Application string
	Version     string
	// https://developers.yubico.com/ykneo-openpgp/SecurityAdvisory%202015-04-14.html
	AppletVersion                       string
	Manufacturer                        string
	Reader                              string
	SecureMessaging                     SecureMessagingAlgorithm
	MaximumChallengeLength              uint16
	MaximumCardholderCertificatesLength uint16
	MaximumSpecialDOsLength             uint16
	// tlvValues holds the raw data from the card.
	tlvValues bertlv.TLVData
}

func (g *GpgData) DumpTLV() string {
	return bertlv.MakeJSONString(g.tlvValues)
}

// UpperCaseHexString is the same as hex.EncodeToString but all uppercase.
func UpperCaseHexString(d []byte) string {
	return strings.ToUpper(hex.EncodeToString(d))
}
