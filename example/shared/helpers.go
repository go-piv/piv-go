package shared

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/areese/piv-go/piv"
)

// DecryptSetup will look for the specified yubikey and return it open.
// The caller *MUST* close the yubikey if err is nil.
// nolint:ireturn
func (c *Config) DecryptSetup(ctx context.Context, logger LogI) (*GPGYubiKeyImpl, error) {
	logger = Nop(logger)

	yubikey, err := c.internalDecryptSetup(ctx, logger)
	if err != nil {
		err = fmt.Errorf("%w: DecryptSetup failed", err)
		logger.ErrorMsg(err, "DecryptSetup failed.")

		return nil, err
	}

	rv := NewGPGYubiKeyImpl(yubikey)

	return rv, nil
}

func (c *Config) internalDecryptSetup(ctx context.Context, logger LogI) (*piv.GPGYubiKey, error) {
	yubikeys, err := c.SelectCards(ctx, logger)
	if err != nil {
		err = fmt.Errorf("%w: SelectCards failed", err)
		logger.ErrorMsg(err, "Failed finding keys")

		return nil, err
	}

	if len(yubikeys) > 1 {
		logger.InfoMsgf("[%d] yubikeys found using first key", len(yubikeys))
	}

	yubikey := yubikeys[0]

	err = c.DisplayKey(ctx, logger, 0, yubikey, false, c.ShowPublic)
	if err != nil {
		err = fmt.Errorf("%w: DisplayKey failed", err)
		logger.ErrorMsgf(err, "Failed handling yubikey [%s]", yubikey)

		return nil, err
	}

	return yubikey, nil
}

// DevEncryptDecryptSetup will look for the specified yubikey and return it open.
// It will also load and base64 decode the file argument.
// The caller *MUST* close the yubikey if err is nil.
func (c *Config) DevEncryptDecryptSetup(ctx context.Context, logger LogI, commandName, fileName string) (*GPGYubiKeyImpl, []byte, error) {
	yubikey, data, err := c.internalDevEncryptDecryptSetup(ctx, logger, commandName, fileName)
	if err != nil {
		err = fmt.Errorf("%w: internalDevEncryptDecryptSetup failed", err)
		logger.ErrorMsg(err, "internalDevEncryptDecryptSetup failed")

		return nil, data, err
	}

	return yubikey, data, nil
}

func (c *Config) internalDevEncryptDecryptSetup(ctx context.Context, logger LogI, commandName, fileName string) (*GPGYubiKeyImpl, []byte, error) {
	logger = Nop(logger)

	yubikey, err := c.DecryptSetup(ctx, logger)
	if err != nil {
		err = fmt.Errorf("%w: internalDevEncryptDecryptSetup failed", err)
		logger.ErrorMsg(err, "internalDevEncryptDecryptSetup failed.")

		return nil, nil, err
	}

	err = ValidateFileFlag(ctx, logger, commandName, fileName)
	if err != nil {
		err = fmt.Errorf("%w: ValidateFileFlag failed for command: [%s] fileName: [%s]", err, commandName, fileName)
		logger.ErrorMsgf(err, "Failed ValidateFileFlag failed [%s].", fileName)

		return nil, nil, err
	}

	fileBytes, err := LoadFile(ctx, logger, fileName)
	if err != nil {
		err = fmt.Errorf("%w: LoadFile failed for command: [%s] fileName: [%s]", err, commandName, fileName)
		logger.ErrorMsgf(err, "Failed loading file [%s].", fileName)

		return nil, nil, err
	}

	fileBytesLen := len(fileBytes)
	if fileBytesLen == 0 {
		err = fmt.Errorf("%w: LoadFile failed for command: [%s] fileName: [%s] was 0 bytes", err, commandName, fileName)
		logger.ErrorMsgf(err, "Failed loading file [%s], zero bytes read.", fileName)

		return nil, nil, err
	}

	if c.Base64Encoded {
		var (
			newBytes  = make([]byte, fileBytesLen)
			readCount int
		)

		readCount, err = base64.StdEncoding.Decode(newBytes, fileBytes)
		if err != nil {
			err = fmt.Errorf("%w: failed decoding base64 forcommand: [%s] fileName: [%s], error after [%d] bytes read", err, commandName, fileName, readCount)
			logger.ErrorMsgf(err, "Failed decoding base64 for file [%s], error after [%d] bytes read", fileName, readCount)

			return nil, nil, err
		}

		fileBytes = newBytes[:readCount]
	}

	logger.VerboseMsgf("Loaded [%d] bytes from [%s]", len(fileBytes), fileName)

	return yubikey, fileBytes, nil
}

func Decrypt(yubikey *piv.GPGYubiKey, cipherTextBytes []byte) ([]byte, error) {
	plainText, err := yubikey.Decrypt(cipherTextBytes)
	if err != nil {
		err = fmt.Errorf("failed to decrypt cipherTextBytes, likely malformed input: %w", err)

		return nil, err
	}

	return plainText, nil
}

func DecryptBase64(yubikey *piv.GPGYubiKey, base64Data string) ([]byte, error) {
	cipherTextBytes, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		err = fmt.Errorf("failed to base64 decode cipherTextBytes, likely malformed input: %w", err)

		return nil, err
	}

	return Decrypt(yubikey, cipherTextBytes)
}
