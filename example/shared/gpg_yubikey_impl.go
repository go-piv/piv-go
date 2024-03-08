package shared

import (
	"context"
	"crypto/rsa"
	"fmt"
	"syscall"

	"github.com/areese/piv-go/piv"
	"golang.org/x/term"
)

type GPGWrapper interface {
	// SerialString returns the YubiKey's serial number.
	SerialString(ctx context.Context, logger LogI) (string, error)
	// Close closes the yubikey.
	Close(ctx context.Context, logger LogI)
	// ReadPasswordAndSendToYubikey reads the password from the terminal and sends it to the yubikey for verification.
	// This must be called before the Decrypt call will work.
	ReadPasswordAndSendToYubikey(ctx context.Context, logger LogI) error
	Decrypt(ctx context.Context, logger LogI, data []byte) ([]byte, error)
	Encrypt(ctx context.Context, logger LogI, data []byte) ([]byte, error)
	ReadPublicKey(ctx context.Context, logger LogI, keyType piv.AsymmetricKeyType) (*rsa.PublicKey, error)
	AuthPIN(ctx context.Context, logger LogI, pin []byte) error
	Fingerprint(ctx context.Context, logger LogI) (string, error)
	GetAttestationCert(ctx context.Context, logger LogI, keyType piv.KeyType) ([]byte, error)
}

var _ GPGWrapper = (*GPGYubiKeyImpl)(nil)

type GPGYubiKeyImpl struct {
	yk *piv.GPGYubiKey
}

func (g *GPGYubiKeyImpl) AuthPIN(ctx context.Context, logger LogI, pin []byte) error {
	err := g.yk.AuthPIN(pin)
	if err != nil {
		err = fmt.Errorf("%w: failed to authorize pin", err)

		return err
	}

	return nil
}

func (g *GPGYubiKeyImpl) SerialString(ctx context.Context, logger LogI) (string, error) {
	rv, err := g.yk.SerialString()
	if err != nil {
		err = fmt.Errorf("%w: failed to get serial", err)

		return "", err
	}

	return rv, nil
}

func (g *GPGYubiKeyImpl) Fingerprint(ctx context.Context, logger LogI) (string, error) {
	logger = Nop(logger)

	var gpgData *piv.GpgData

	gpgData, err := g.yk.GPGData()
	if err != nil {
		err = fmt.Errorf("%w: failed to get GPGData", err)
		logger.ErrorMsg(err, "Failed to get GPG data.")

		return "", err
	}

	keyType := piv.DecryptionKey

	keyFingerprint, err := gpgData.Fingerprint(keyType)
	if err != nil {
		err = fmt.Errorf("%w: Failed to get fingerprint type [%s]", err, keyType.String())
		logger.ErrorMsg(err, "Failed to get GPG Fingerprint.")

		return "", err
	}

	return keyFingerprint, nil
}

func (g *GPGYubiKeyImpl) Close(ctx context.Context, logger LogI) {
	logger = Nop(logger)
	isDebugEnabled := logger.IsDebugEnabled()

	if nil == g.yk {
		if isDebugEnabled {
			logger.DebugMsg("Closing nil yubikey.")
		}

		return
	}

	if isDebugEnabled {
		serial, _ := g.yk.SerialString()

		logger.DebugMsgf("Closing yubikey [%s].", serial)
	}

	err := g.yk.Close()
	if err != nil {
		logger.ErrorMsg(err, "Failed to close Yubikey.")
	}
}

// ReadPasswordAndSendToYubikey reads the password from the terminal and sends it to the yubikey for verification.
// This must be called before the Decrypt call will work.
// nolint:forbidigo
func (g *GPGYubiKeyImpl) ReadPasswordAndSendToYubikey(ctx context.Context, logger LogI) error {
	logger = Nop(logger)

	var (
		bytePassword []byte
		err          error
	)

	fmt.Print("Enter Password: ")

	bytePassword, err = term.ReadPassword(syscall.Stdin)

	// add a newline after reading.
	fmt.Println()

	if err != nil {
		err = fmt.Errorf("failed to read password from terminal: %w", err)
		logger.ErrorMsg(err, "Failed to read password")

		return err
	}

	// try logging into the key.
	err = g.yk.AuthPIN(bytePassword)
	if err != nil {
		err = fmt.Errorf("authenticating pin with yubikey failed: %w", err)
		logger.ErrorMsg(err, "Failed to auth to yubikey with password")

		return err
	}

	return nil
}

func NewGPGYubiKeyImpl(yubikey *piv.GPGYubiKey) *GPGYubiKeyImpl {
	rv := &GPGYubiKeyImpl{
		yk: yubikey,
	}

	return rv
}

func (g *GPGYubiKeyImpl) Decrypt(ctx context.Context, logger LogI, data []byte) ([]byte, error) {
	rv, err := g.yk.Decrypt(data)
	if err != nil {
		err = fmt.Errorf("%w: failed to decrypt data", err)

		return nil, err
	}

	return rv, nil
}

func (g *GPGYubiKeyImpl) ReadPublicKey(ctx context.Context, logger LogI, keyType piv.AsymmetricKeyType) (*rsa.PublicKey, error) {
	rv, err := g.yk.ReadPublicKey(keyType)
	if err != nil {
		err = fmt.Errorf("%w: failed to read public key", err)

		return nil, err
	}

	return rv, nil
}

func (g *GPGYubiKeyImpl) Encrypt(ctx context.Context, logger LogI, data []byte) ([]byte, error) {
	var rv []byte
	// FIXME: not implemented.
	// return g.yk.Encrypt(data)
	err := ErrNotYetImplemented
	if err != nil {
		err = fmt.Errorf("%w: failed to encrypt data", err)

		return nil, err
	}

	return rv, nil
}

func (g *GPGYubiKeyImpl) GetAttestationCert(ctx context.Context, logger LogI, keyType piv.KeyType) ([]byte, error) {
	rv, err := g.yk.GetAttestationCert(keyType)
	if err != nil {
		err = fmt.Errorf("%w: failed to get attestation cert", err)

		return nil, err
	}

	return rv, nil
}
