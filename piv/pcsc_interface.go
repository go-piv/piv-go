package piv

import "github.com/go-piv/piv-go/bertlv"

// The interfaces here are for wrapping the pcsc code.
// This allows us to better test the parts of piv by returning various errors from the pcsc stack.
// This also allows for testing without yubikeys that are modifiable attached.

// ClientInterface wraps client.
type ClientInterface interface {
	OpenGPG(card string) (*GPGYubiKey, error)
	Cards() ([]string, error)
	Open(card string) (*YubiKey, error)
}

// SCTx wraps scTx.
type SCTx interface {
	Close() error
	DisableDebug()
	EnableDebug()
	Transmit(d apdu) ([]byte, error)
	TransmitBytes(req []byte) (more bool, b []byte, err error)
	IsDebugEnabled() bool
}

// SCHandle wraps scHandle.
type SCHandle interface {
	Begin() (SCTx, error)
	Close() error
}

// SCContext wraps scContext.
type SCContext interface {
	Close() error
	Connect(reader string) (SCHandle, error)
	ListReaders() ([]string, error)
}

// SCConstructor is a constructor for SCContext.
type SCConstructor interface {
	NewSCContext() (SCContext, error)
}

type Client struct {
	client      *client
	SCConstruct SCConstructor
}

type PCSCConstructor struct{}

type PCSCContext struct {
	ctx *scContext
}

type PCSCHandle struct {
	h *scHandle
}

type PCSCTx struct {
	tx    *scTx
	debug bool
}

var (
	_ ClientInterface = (*Client)(nil)
	_ SCConstructor   = (*PCSCConstructor)(nil)
	_ SCContext       = (*PCSCContext)(nil)
	_ SCHandle        = (*PCSCHandle)(nil)
	_ SCTx            = (*PCSCTx)(nil)
)

func (c Client) Open(card string) (*YubiKey, error) {
	return c.client.Open(card)
}

func (c Client) Cards() ([]string, error) {
	return c.client.Cards()
}

// nolint:ireturn
func (p *PCSCConstructor) NewSCContext() (SCContext, error) {
	var err error

	rv := &PCSCContext{}
	rv.ctx, err = newSCContext()

	return rv, err
}

func (p *PCSCConstructor) String() string {
	return bertlv.MakeJSONString(p)
}

func (p *PCSCContext) Close() error {
	return p.ctx.Close()
}

// nolint:ireturn
func (p *PCSCContext) Connect(reader string) (SCHandle, error) {
	var err error
	rv := PCSCHandle{}
	rv.h, err = p.ctx.Connect(reader)
	return &rv, err
}

func (p *PCSCContext) ListReaders() ([]string, error) {
	return p.ctx.ListReaders()
}

func (p *PCSCContext) String() string {
	return bertlv.MakeJSONString(p)
}

// nolint:ireturn
func (p *PCSCHandle) Begin() (SCTx, error) {
	return p.h.Begin()
}

func (p *PCSCHandle) Close() error {
	return p.h.Close()
}

func (p *PCSCHandle) String() string {
	return bertlv.MakeJSONString(p)
}

func (p *PCSCTx) Close() error {
	return p.tx.Close()
}

func (p *PCSCTx) DisableDebug() {
	p.tx.DisableDebug()
}

func (p *PCSCTx) EnableDebug() {
	p.tx.EnableDebug()
}

func (p *PCSCTx) Transmit(d apdu) ([]byte, error) {
	// FIXME: this and transmitBytes don't overlap correctly.
	// tx.Transmit will call tx.transmit() without calling transmit bytes.
	return p.tx.Transmit(d)
}

func (p *PCSCTx) TransmitBytes(req []byte) (more bool, b []byte, err error) {
	return p.tx.transmit(req)
}

func (p *PCSCTx) IsDebugEnabled() bool {
	return p.tx.debug
}

func (p *PCSCTx) String() string {
	return bertlv.MakeJSONString(p)
}
