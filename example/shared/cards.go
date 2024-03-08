package shared

import (
	"context"
	"fmt"
	"strings"

	"github.com/areese/piv-go/piv"
)

type CardAccess interface {
	OpenGPG(card string) (*piv.GPGYubiKey, error)
	Cards() ([]string, error)
}

type PGPCardAccess struct{}

var _ CardAccess = (*PGPCardAccess)(nil)

func (p *PGPCardAccess) Cards() ([]string, error) {
	return piv.Cards()
}

func (p *PGPCardAccess) OpenGPG(card string) (*piv.GPGYubiKey, error) {
	return piv.OpenGPG(card)
}

// GetCards returns an array of pointers to piv.GPGPYubikey that have been filtered based on serial.
// TODO: add fingerprint and other styles.
// nolint:funlen,cyclop
func (c *CardSelection) GetCards(ctx context.Context, logger LogI, cfg *Config) ([]*piv.GPGYubiKey, error) {
	logger = Nop(logger)
	// List all smartcards connected to the system.
	cards, err := c.CardAccessor.Cards()
	if err != nil {
		return nil, err
	}

	// Find a Yubikey and open the reader.
	yubikeys := make([]*piv.GPGYubiKey, len(cards))
	ykIndex := 0

	for index, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			logger.VerboseMsgf("skipping %s", card)

			continue
		}

		logger.VerboseMsgf("opening %s", card)

		var gpgCard *piv.GPGYubiKey

		gpgCard, err = c.CardAccessor.OpenGPG(card)
		if err != nil {
			logger.ErrorMsgf(err, "piv.OpenGPG failed for card [%s]", card)

			continue
		}

		var valid bool

		// Filter closes the card for us if it's not valid.
		valid, err = c.filter(ctx, logger, gpgCard, card)
		if err != nil {
			logger.VerboseMsgf("ignoring card [%s] due to error: %v", card, err)

			continue
		}

		if !valid {
			logger.VerboseMsgf("ignoring card [%s] due to not valid", card)

			continue
		}

		if cfg.Debug && cfg.Verbose {
			logger.VerboseMsgf("Enabling debug for [%d] card", index)
			gpgCard.EnableDebug()
		}

		if cfg.Trace {
			gpgCard.EnableTrace()
		}

		yubikeys[ykIndex] = gpgCard
		ykIndex++
	}

	if ykIndex == 0 {
		err = ErrNoCardsSelected

		if c.Serial != "" {
			err = fmt.Errorf("no card with serial [%s] found: %w", c.Serial, err)
		}

		return nil, err
	}

	return yubikeys[0:ykIndex], nil
}

// nolint:unparam
func (c *CardSelection) filter(ctx context.Context, logger LogI, gpgCard *piv.GPGYubiKey, card string) (bool, error) {
	var (
		serial      string
		hasKey      bool
		shouldClose = true
	)

	logger = Nop(logger)

	defer func() {
		if shouldClose {
			err := gpgCard.Close()
			if err != nil {
				err = fmt.Errorf("%w: gpgCard.Close() of [%s] failed", err, card)
				logger.ErrorMsgf(err, "gpgCard.Close() of [%s] failed", card)
			}
		}
	}()

	serial, err := gpgCard.SerialString()
	if err != nil {
		err = fmt.Errorf("%w: gpgCard.SerialString() of [%s] failed", err, card)
		logger.ErrorMsgf(err, "gpgCard.SerialString() of [%s] failed", card)

		return false, err
	}

	logger.VerboseMsgf("Got card serial [%s] for card [%s]", serial, card)

	// TODO: we only support decryption keys right now.
	hasKey, err = HasValidKeyType(logger, gpgCard, piv.DecryptionKey)
	if err != nil {
		logger.ErrorMsgf(err, "gpgCard.HasValidKeyType() of [%s] failed", card)

		return false, err
	}

	if !hasKey {
		logger.VerboseMsgf("Ignoring card serial [%s] no DecryptionKey keys found for [%s]", serial, card)

		return false, piv.ErrKeyNotPresent
	}

	if c.Serial != "" && serial != c.Serial {
		logger.VerboseMsgf("Ignoring card serial [%s] != [%s] for [%s]", serial, c.Serial, card)

		return false, nil
	}

	// don't close it if we return true
	shouldClose = false

	logger.VerboseMsgf("Using card serial [%s] [%s]", serial, card)

	return true, nil
}
