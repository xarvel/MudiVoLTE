package main

// SRTP for the phones: RFC 3711 with the keys in the SDP (SDES, RFC 4568).
// The keys travel only inside TLS: over UDP and TCP anyone on the Wi-Fi reads
// the SDP, so an RTP/SAVP offer there gets 488 and our offers carry no keys.
// Over TLS:
//
//   - the phone offers RTP/SAVP: we answer RTP/SAVP with our own key of the
//     suite and tag of the first line we support (RFC 4568 §6.1); RTP/AVP with
//     a=crypto lines (best-effort SRTP): the same, in RTP/AVP; RTP/AVP without
//     keys: plain RTP, the phone's choice;
//   - we offer to a phone signed in over TLS: RTP/SAVP with one line per suite
//     of offerSuites. Linphone set up by QR code has
//     media_encryption_mandatory=1, and then it takes only SAVP offers
//     (liblinphone, offeranswer.cpp: SAVP is compatible with SAVP only).
//
// A re-INVITE keeps the leg as it is: an SRTP leg stays SRTP (a new key of the
// phone replaces the old one, our key stays), and an offer that drops the keys
// gets 488 instead of a silent fall back to plain RTP. DTLS-SRTP and ZRTP are
// not done.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/xarvel/MudiVoLTE/volte/srtp"
)

// offerSuites are the suites of our offers, best first. Both are in
// Linphone's default list (srtp_crypto_suites).
var offerSuites = []srtp.Suite{srtp.AES128CMSHA1_80, srtp.AES256CMSHA1_80}

// srtpTagMax is the longest authentication tag of our suites.
const srtpTagMax = 10

// secureTransport reports a SIP transport the SRTP keys may travel over.
func secureTransport(t string) bool { return strings.EqualFold(t, "tls") }

// mediaPlan is the decision on a phone's offer.
type mediaPlan struct {
	offer   *sdpAudio
	format  lanFormat
	remote  *srtp.Crypto // the phone's key from the accepted line; nil = plain RTP
	profile string       // the m= profile of our answer
}

var errNoCodec = errors.New("no common codec")

// planFromOffer decides on the phone's SDP offer that came over transport.
func planFromOffer(offer *sdpAudio, transport string, codecs []string) (mediaPlan, error) {
	plan := mediaPlan{offer: offer, profile: "RTP/AVP"}
	f, ok := offer.chooseByPreference(codecs)
	if !ok {
		return plan, errNoCodec
	}
	plan.format = f
	secure := secureTransport(transport)
	switch {
	case offer.savp():
		if !secure {
			return plan, fmt.Errorf("%s with keys over %s, not TLS", offer.Proto, strings.ToUpper(transport))
		}
		if len(offer.Crypto) == 0 {
			return plan, fmt.Errorf("%s without a crypto suite we support (%d a=crypto lines)", offer.Proto, offer.CryptoLines)
		}
		plan.remote, plan.profile = &offer.Crypto[0], "RTP/SAVP"
	case offer.avp():
		if secure && len(offer.Crypto) > 0 {
			plan.remote = &offer.Crypto[0]
		}
	default:
		return plan, fmt.Errorf("media profile %s is not supported", offer.Proto)
	}
	return plan, nil
}

// newOfferKeys returns our keys for an offer to phones over TLS, one per
// suite, tags 1, 2, …
func newOfferKeys() ([]srtp.Crypto, error) {
	keys := make([]srtp.Crypto, 0, len(offerSuites))
	for i, s := range offerSuites {
		k, err := srtp.NewCrypto(i+1, s)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// keysFromAnswer pairs the phone's answer with our offer: the answer's line
// must carry the tag and suite of one of our lines (RFC 4568 §7.1.3).
func keysFromAnswer(ans *sdpAudio, offered []srtp.Crypto) (local, remote srtp.Crypto, err error) {
	for _, r := range ans.Crypto {
		for _, o := range offered {
			if r.Tag == o.Tag && r.Suite == o.Suite {
				return o, r, nil
			}
		}
	}
	return srtp.Crypto{}, srtp.Crypto{}, fmt.Errorf("the phone answered %s without a key for our offer (%d a=crypto lines)", ans.Proto, ans.CryptoLines)
}

// setSRTP turns the leg to SRTP: we send under local, the phone sends under
// remote.
func (l *rtpLeg) setSRTP(local, remote srtp.Crypto, profile string) error {
	tx, err := local.Context()
	if err != nil {
		return err
	}
	rx, err := remote.Context()
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tx, l.rx, l.localKey, l.remoteKey, l.profile, l.fails = tx, rx, local, remote, profile, 0
	return nil
}

// secure reports an SRTP leg.
func (l *rtpLeg) secure() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tx != nil
}

// security returns the SRTP part of the leg's SDP; nil for plain RTP.
func (l *rtpLeg) security() *sdpSecurity {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.tx == nil {
		return nil
	}
	return &sdpSecurity{Profile: l.profile, Keys: []srtp.Crypto{l.localKey}}
}

// refreshKeys answers the SRTP part of a re-INVITE or UPDATE offer for the
// leg. A plain leg stays plain and refuses keys; an SRTP leg stays SRTP and
// refuses an offer without keys. Our answer repeats the offer's tag; our key
// stays unless the phone moved to another suite, and a new key of the phone
// replaces its old one. Only the context of a changed key starts anew: the
// other side keeps counting the rollover of a key that did not change.
func (l *rtpLeg) refreshKeys(offer *sdpAudio) (*sdpSecurity, error) {
	l.mu.Lock()
	secure, local, remote, profile := l.tx != nil, l.localKey, l.remoteKey, l.profile
	l.mu.Unlock()
	if !secure {
		if offer.savp() {
			return nil, errors.New("keys offered for a call without SRTP")
		}
		return nil, nil
	}
	if len(offer.Crypto) == 0 {
		return nil, fmt.Errorf("an SRTP call re-offered as %s without keys", offer.Proto)
	}
	pick := offer.Crypto[0]
	for _, c := range offer.Crypto {
		if c.Suite == local.Suite {
			pick = c
			break
		}
	}
	if offer.savp() {
		profile = "RTP/SAVP"
	} else if offer.avp() {
		profile = "RTP/AVP"
	}
	ours := local
	ours.Tag = pick.Tag
	var tx, rx *srtp.Context
	var err error
	if pick.Suite != local.Suite {
		if ours, err = srtp.NewCrypto(pick.Tag, pick.Suite); err != nil {
			return nil, err
		}
		if tx, err = ours.Context(); err != nil {
			return nil, err
		}
	}
	if !sameKey(pick, remote) {
		if rx, err = pick.Context(); err != nil {
			return nil, err
		}
	}
	l.mu.Lock()
	if tx != nil {
		l.tx = tx
	}
	if rx != nil {
		l.rx, l.fails = rx, 0
	}
	l.localKey, l.remoteKey, l.profile = ours, pick, profile
	l.mu.Unlock()
	return &sdpSecurity{Profile: profile, Keys: []srtp.Crypto{ours}}, nil
}

func sameKey(a, b srtp.Crypto) bool {
	return a.Suite == b.Suite && string(a.Key) == string(b.Key) && string(a.Salt) == string(b.Salt)
}

// srtpFailed counts a received packet that failed the SRTP check; the first
// one and then every 500th get a log line (a wrong key shows at once).
func (l *rtpLeg) srtpFailed(err error) {
	l.mu.Lock()
	l.fails++
	n := l.fails
	l.mu.Unlock()
	if l.logger != nil && (n == 1 || n%500 == 0) {
		l.logger.Warn("SRTP: a packet from the phone failed the check", "port", l.port, "count", n, "err", err)
	}
}
