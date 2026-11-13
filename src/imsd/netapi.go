package main

// A network call as the daemon sees it: types and interfaces that do not
// depend on the IMS stack. The implementation on top of the volte library is
// netstack.go; tests use fakes.

import (
	"context"
	"fmt"
	"net"
)

type CallDirection string

const (
	CallIncoming CallDirection = "incoming"
	CallOutgoing CallDirection = "outgoing"
)

type CallState string

const (
	CallStateDialing    CallState = "dialing"
	CallStateRinging    CallState = "ringing"
	CallStateEarlyMedia CallState = "early-media"
	CallStateActive     CallState = "active"
	CallStateEnded      CallState = "ended"
	CallStateFailed     CallState = "failed"
)

// NetMedia is the negotiated audio stream of a network call.
type NetMedia struct {
	Negotiated  bool
	Codec       string // AMR-WB | PCMA | PCMU
	PayloadType int
	ClockRate   int
	ModeSet     string
	OctetAlign  bool
	DTMFPT      int
	DTMFHz      int
}

// imsMedia is the RTP of a network call (complete packets both ways).
type imsMedia interface {
	Media() NetMedia
	ReadPacket(ctx context.Context) ([]byte, net.Addr, error)
	WriteRTP(ctx context.Context, data []byte) error
}

// imsCall is what the manager needs from a network call.
type imsCall interface {
	imsMedia
	ID() string
	Direction() CallDirection
	Ring() error
	Answer(ctx context.Context) error
	Reject(ctx context.Context, code int, reason string) error
	Hangup(ctx context.Context) error
	SendDTMF(ctx context.Context, digits string) error
}

type imsDialer interface {
	Dial(ctx context.Context, to string) (imsCall, error)
}

// dialError means the network answered our INVITE with a failure.
type dialError struct {
	Code   int
	Reason string
}

func (e *dialError) Error() string { return fmt.Sprintf("%d %s", e.Code, e.Reason) }
