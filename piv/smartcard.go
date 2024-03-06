package piv

import (
	"fmt"
)

type Smartcard struct {
	ctx *scContext
	h   *scHandle
	tx  *scTx
}

func OpenSmartcard(reader string) (*Smartcard, error) {
	ctx, err := newSCContext()
	if err != nil {
		return nil, fmt.Errorf("connecting to smart card daemon: %w", err)
	}

	h, err := ctx.Connect(reader)
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("connecting to smart card: %w", err)
	}
	tx, err := h.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning smart card transaction: %w", err)
	}

	return &Smartcard{ctx: ctx, h: h, tx: tx}, nil
}

func (sc *Smartcard) Transmit(apduRaw []byte) ([]byte, error) {
	_, resp, err := sc.tx.transmit(apduRaw)
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU: %w", err)
	}
	return resp, nil
}

func (sc *Smartcard) Close() error {
	if sc.tx != nil {
		sc.tx.Close()
	}
	if sc.h != nil {
		sc.h.Close()
	}
	if sc.ctx != nil {
		sc.ctx.Close()
	}
	return nil
}
