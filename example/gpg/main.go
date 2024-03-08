package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"

	"github.com/areese/piv-go/example/shared"
	"github.com/areese/piv-go/piv"
)

func main() {
}

//nolint:deadcode
func Encrypt(fileName string, logger shared.LogI) error {
	ctx := context.Background()

	pgpConfig := shared.Config{
		CardSelection: nil,
		Debug:         false,
		Verbose:       false,
		Trace:         false,
		Quiet:         false,
		ShowPublic:    false,
		Base64Encoded: false,
	}

	// do the general setup
	yubikeyClient, fileBytes, err := pgpConfig.DevEncryptDecryptSetup(ctx, logger, "encrypt", fileName)
	defer func() { yubikeyClient.Close(ctx, logger) }()

	if err != nil {
		return err
	}

	// we have file bytes, now we can encrypt it.
	var pubkey *rsa.PublicKey

	pubkey, err = yubikeyClient.ReadPublicKey(ctx, logger, piv.AsymmetricConfidentiality)
	if err != nil {
		logger.ErrorMsg(err, "Failed to load public key")

		return err
	}

	fileSize := len(fileBytes)
	// nolint:gomnd // -11 must be a header size, this is from the rsa.go source.
	maxSize := pubkey.Size() - 11

	if fileSize > maxSize {
		logger.InfoMsgf("Only encrypting [%d] bytes out of [%d] from file [%s]", maxSize, fileSize, fileName)
		fileSize = maxSize
	}

	var encData []byte

	encData, err = rsa.EncryptPKCS1v15(rand.Reader, pubkey, fileBytes[:fileSize])
	if err != nil {
		logger.ErrorMsg(err, "Failed to load public key")

		return err
	}

	logger.InfoMsg(base64.StdEncoding.EncodeToString(encData))

	return nil
}
