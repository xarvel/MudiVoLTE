// Package sim defines what the IMS client needs from the SIM: the AKA
// AUTHENTICATE run (3GPP TS 31.102 §7.1.2, TS 33.102 §6.3). The transport
// (AT+CSIM, PC/SC, QMI) lives in the application.
package sim

import (
	"context"
	"errors"
)

// ErrMAC means the SIM rejected AUTN: the network is not authentic
// (TS 33.102 §6.3.3). The UE answers with an empty-password Digest.
var ErrMAC = errors.New("SIM: AUTN MAC failure")

// AuthResult is a successful run (RES, CK, IK) or a synchronisation failure
// (only AUTS set).
type AuthResult struct {
	RES, CK, IK []byte
	AUTS        []byte
}

// SyncFailure reports whether the SIM asked for resynchronisation.
func (r AuthResult) SyncFailure() bool { return len(r.AUTS) > 0 }

// Authenticator runs AKA on the USIM/ISIM application.
type Authenticator interface {
	Authenticate(ctx context.Context, rand, autn [16]byte) (AuthResult, error)
}
