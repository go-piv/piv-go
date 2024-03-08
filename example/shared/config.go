package shared

import (
	"context"

	"github.com/areese/piv-go/piv"
)

// CardSelection is created to filter cards.
// Currently, it can only filter on serial.
type CardSelection struct {
	*YubikeyData

	CardAccessor CardAccess
}

type Config struct {
	*CardSelection

	// Debug toggles verbose logging in downstream commands.
	Debug bool

	// Verbose toggles verbose logging in downstream commands.
	Verbose bool

	// Debug toggles verbose logging in downstream commands.
	Trace bool

	// Quiet disables all output other than expected value outputs.
	Quiet bool

	ShowPublic bool

	Base64Encoded bool
}

func (c *Config) SelectCards(ctx context.Context, logger LogI) ([]*piv.GPGYubiKey, error) {
	return c.CardSelection.GetCards(ctx, logger, c)
}

func (c *Config) PGPCardSelection() *CardSelection {
	return c.CardSelection
}

func (c *Config) String() string {
	return MakeJSONString(c)
}

func NewYubikeyData() *YubikeyData {
	rv := &YubikeyData{
		Fingerprint: "",
		KeyID:       "",
		Serial:      "",
		Name:        "",
	}

	return rv
}

func NewCardSelection() *CardSelection {
	yubikeyData := NewYubikeyData()

	cardSelection := &CardSelection{
		YubikeyData:  yubikeyData,
		CardAccessor: &PGPCardAccess{},
	}

	return cardSelection
}

func New(ctx context.Context, logger LogI) *Config {
	cardSelection := NewCardSelection()

	rv := &Config{
		CardSelection: cardSelection,
		Debug:         false,
		Verbose:       false,
		Trace:         false,
		Quiet:         false,
		ShowPublic:    false,
		Base64Encoded: false,
	}

	return rv
}

func (c *CardSelection) WithYubikeyData(value *YubikeyData) *CardSelection {
	c.YubikeyData = value

	return c
}

func (c *Config) WithCardSelection(value *CardSelection) *Config {
	c.CardSelection = value

	return c
}

func (c *Config) WithYubikeyData(value *YubikeyData) *Config {
	c.CardSelection.WithYubikeyData(value)

	return c
}

func (c *Config) WithDebug(value bool) *Config {
	c.Debug = value

	return c
}

func (c *Config) WithVerbose(value bool) *Config {
	c.Verbose = value

	return c
}

func (c *Config) WithTrace(value bool) *Config {
	c.Trace = value

	return c
}

func (c *Config) WithQuiet(value bool) *Config {
	c.Quiet = value

	return c
}

func (c *Config) WithShowPublic(value bool) *Config {
	c.ShowPublic = value

	return c
}

func (c *Config) WithBase64Encoded(value bool) *Config {
	c.Base64Encoded = value

	return c
}
