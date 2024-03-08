package shared

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/areese/piv-go/bertlv"
	"github.com/areese/piv-go/piv"
)

// HasValidKeyType will check if the yubikey has the expected key.
// This is used in the filtering to make sure we pick the first yubikey with a gpg key.
// FIXME: move to piv.
func HasValidKeyType(logger LogI, yubikey *piv.GPGYubiKey, keyType piv.KeyType) (bool, error) {
	logger = Nop(logger)

	if keyType > piv.KeyTypeLast {
		return false, piv.ErrUnknownKeyType
	}

	gpgData, err := yubikey.GPGData()
	if err != nil {
		logger.ErrorMsg(err, "yubikey.GPGData failed")

		return false, err
	}

	keyOrigin, err := gpgData.Origin(keyType)
	if err != nil {
		logger.ErrorMsgf(err, "gpgData.Origin(%d)  failed", keyType)

		return false, err
	}

	return keyOrigin > piv.KeyNotPresent && keyOrigin <= piv.KeyOriginLast, nil
}

// DisplayKey will display information about a yubikey.
// if closeKey is true, it will close the key.
// nolint:funlen,cyclop
func (c *Config) DisplayKey(ctx context.Context, logger LogI, index int, yubikey *piv.GPGYubiKey, closeKey bool, showPublicKey bool) error {
	logger = Nop(logger)

	if closeKey {
		defer yubikey.Close()
	}

	var (
		gpgData *piv.GpgData
		serial  string
	)

	gpgData, err := yubikey.GPGData()
	if err != nil {
		logger.ErrorMsg(err, "yubikey.GPGData failed")

		return err
	}

	logger.InfoMsgf("card [%d]: %s", index, gpgData.LongName)

	serial, err = yubikey.SerialString()
	if err != nil {
		logger.ErrorMsg(err, "yubikey.GPGData failed")

		return err
	}

	keyType := piv.DecryptionKey

	//     print(f"Dec  {keyalg(card,1):8s}  {keyfingerprint(card,1):40s}  {keydate(card,1)}  {keyorigin(card,1)}", file=sys.stderr)
	keyAlgorithm, err := gpgData.Algorithm(keyType)
	if err != nil {
		err = fmt.Errorf("%w: Failed to get gpgData algorithm for key type [%s] ", err, keyType.String())
		logger.ErrorMsg(err, "Failed to get gpgData algorithm using gpgData.Algorithm")

		return err
	}

	keyFingerprint, err := gpgData.Fingerprint(keyType)
	if err != nil {
		err = fmt.Errorf("%w: Failed to get gpgData fingerprint for key type [%s] ", err, keyType.String())
		logger.ErrorMsg(err, "Failed to get fingerprint using gpgData.Fingerprint.")

		return err
	}

	keyDate, err := gpgData.Date(keyType)
	if err != nil {
		logger.ErrorMsgf(err, "gpgData.Date(%d) failed", keyType)

		return err
	}

	keyOrigin, err := gpgData.Origin(keyType)
	if err != nil {
		logger.ErrorMsgf(err, "gpgData.Origin(%d)  failed", keyType)

		return err
	}

	keyID, err := gpgData.ID(keyType)
	if err != nil {
		logger.ErrorMsgf(err, "gpgData.ID(%d)  failed", keyType)

		return err
	}

	logger.VerboseMsgf("got KeyID %s", keyID)

	// nolint: gomnd
	logger.InfoMsgf("Dec %.*s   %.*s   %s   %s", 8, keyAlgorithm, 40, keyFingerprint, keyDate, keyOrigin)
	logger.InfoMsgf("serial: %s", serial)

	logger.DebugMsgf("bertlv: %s", gpgData.DumpTLV())
	logger.VerboseMsgf("gpgData: %s", bertlv.MakeJSONString(gpgData))

	// # read the encryption public key (7.2.14 page 74)
	// # 0x00 instruction, param1=0x81, param2=0x00, len=0x02, data[0xB8,0x00], 0x00
	// 0x81 == read
	// 0xB8 0x00 == Confidentiality

	if showPublicKey {
		var (
			pubkey    *rsa.PublicKey
			pemString string
		)

		logger.VerboseMsg("Getting Public Key")

		pubkey, err = yubikey.ReadPublicKey(piv.AsymmetricConfidentiality)
		if err != nil {
			logger.ErrorMsgf(err, "yubikey.ReadPublicKey(%s) failed", piv.AsymmetricConfidentiality)

			return err
		}

		pemString, err = piv.ExportRsaPublicKeyAsPemStr(pubkey)
		if err != nil {
			logger.ErrorMsgf(err, "ExportRsaPublicKeyAsPemStr failed")

			return err
		}

		logger.InfoMsgf("pubkey: %s", pemString)
	}

	return nil
}

func (c *Config) DisplayKeys(ctx context.Context, logger LogI, yubikeys []*piv.GPGYubiKey, closeKey bool, showPublicKey bool) error {
	logger = Nop(logger)

	for index, yubikey := range yubikeys {
		err := c.DisplayKey(ctx, logger, index, yubikey, closeKey, showPublicKey)
		if err != nil {
			logger.ErrorMsgf(err, "Failed handling yubikey %s", yubikey)
		}
	}

	return nil
}
