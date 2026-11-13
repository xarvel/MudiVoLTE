package main

// CSIM transport: simcard.Transmitter over AT+CSIM. APDU encoding and
// response parsing are the ready-made types of wwan-go/at (covered by its
// tests); our part is only the ATLink channel.

import (
	"context"
	"fmt"

	wwanat "github.com/damonto/wwan-go/at"
	usimcard "github.com/damonto/wwan-go/sim/card"
)

// csimTransmitter is a simcard.Transmitter over AT+CSIM.
type csimTransmitter struct {
	link *ATLink
}

var _ usimcard.Transmitter = (*csimTransmitter)(nil)

func newCSIMTransmitter(link *ATLink) *csimTransmitter {
	return &csimTransmitter{link: link}
}

func (t *csimTransmitter) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	var cmd wwanat.CSIMCommand
	if err := cmd.UnmarshalBinary(apdu); err != nil {
		return nil, fmt.Errorf("CSIM: APDU: %w", err)
	}
	text, err := cmd.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("CSIM: encoding APDU %X: %w", apdu, err)
	}
	out, err := t.link.csim(ctx, string(text))
	if err != nil {
		return nil, fmt.Errorf("CSIM: %w", err)
	}
	var resp wwanat.CSIMResponse
	if err := resp.UnmarshalText([]byte(out)); err != nil {
		return nil, fmt.Errorf("CSIM: parsing the reply: %w", err)
	}
	if len(resp) < 2 {
		return nil, fmt.Errorf("CSIM: reply without a status word")
	}
	return append([]byte(nil), resp...), nil
}

func (t *csimTransmitter) Close() error { return nil }
