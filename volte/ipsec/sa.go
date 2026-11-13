package ipsec

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"

	"github.com/xarvel/MudiVoLTE/volte/auth"
)

// Endpoint is one side of sec-agree: its address, the SPIs it chose for its
// inbound SAs and its protected client/server ports.
type Endpoint struct {
	Addr  netip.Addr
	SPIc  uint32 // receives on PortC
	SPIs  uint32 // receives on PortS
	PortC uint16
	PortS uint16
}

// Set is the complete security association set for one registration.
type Set struct {
	UE    Endpoint
	PCSCF Endpoint
	Alg   string // hmac-md5-96 | hmac-sha-1-96
	Ealg  string // null | aes-cbc | des-ede3-cbc
	IK    []byte // IK_IM from the SIM
	CK    []byte // CK_IM from the SIM

	// LooseInboundSrcPort drops the P-CSCF source port from the inbound
	// policies. Some P-CSCFs (192.0.2.20 of the tested network) open
	// requests towards the UE server port from an unpredictable port; the SA
	// is still bound by SPI.
	LooseInboundSrcPort bool
}

// SA is one unidirectional ESP security association.
type SA struct {
	Src, Dst netip.Addr
	SPI      uint32
}

// Policy binds a traffic selector to the SA that must protect it.
type Policy struct {
	Dir              string // "out" | "in"
	Src, Dst         netip.Addr
	SrcPort, DstPort uint16 // 0 = any
	SA               SA
}

// SAs returns the four associations, named after the flow they carry:
// UE client → P-CSCF server, UE server → P-CSCF client and the two reverse ones.
// Each SA uses the SPI chosen by its receiver.
func (s Set) SAs() (ucToPs, usToPc, pcToUs, psToUc SA) {
	ue, p := s.UE.Addr, s.PCSCF.Addr
	return SA{ue, p, s.PCSCF.SPIs}, SA{ue, p, s.PCSCF.SPIc},
		SA{p, ue, s.UE.SPIs}, SA{p, ue, s.UE.SPIc}
}

// Policies returns the selectors; each applies to both TCP and UDP.
func (s Set) Policies() []Policy {
	ucToPs, usToPc, pcToUs, psToUc := s.SAs()
	ue, p := s.UE, s.PCSCF
	inSrc := func(port uint16) uint16 {
		if s.LooseInboundSrcPort {
			return 0
		}
		return port
	}
	return []Policy{
		{"out", ue.Addr, p.Addr, ue.PortC, p.PortS, ucToPs},
		{"out", ue.Addr, p.Addr, ue.PortS, p.PortC, usToPc},
		{"in", p.Addr, ue.Addr, inSrc(p.PortC), ue.PortS, pcToUs},
		{"in", p.Addr, ue.Addr, inSrc(p.PortS), ue.PortC, psToUc},
	}
}

// Validate checks addresses, SPIs and that keys can be derived.
func (s Set) Validate() error {
	if !s.UE.Addr.IsValid() || !s.PCSCF.Addr.IsValid() {
		return fmt.Errorf("UE and P-CSCF addresses are required")
	}
	if s.UE.Addr.Is4() != s.PCSCF.Addr.Is4() {
		return fmt.Errorf("address family mismatch: %s vs %s", s.UE.Addr, s.PCSCF.Addr)
	}
	for _, spi := range []uint32{s.UE.SPIc, s.UE.SPIs, s.PCSCF.SPIc, s.PCSCF.SPIs} {
		if spi < 256 {
			return fmt.Errorf("SPI %d is reserved (RFC 4303 §2.1)", spi)
		}
	}
	if s.UE.SPIc == s.UE.SPIs {
		return fmt.Errorf("UE spi-c and spi-s must differ")
	}
	for _, port := range []uint16{s.UE.PortC, s.UE.PortS, s.PCSCF.PortC, s.PCSCF.PortS} {
		if port == 0 {
			return fmt.Errorf("protected ports must be set")
		}
	}
	if _, err := auth.IntegrityKey(s.Alg, s.IK); err != nil {
		return err
	}
	_, err := auth.EncryptionKey(s.Ealg, s.CK)
	return err
}

// AllocSPI returns a random SPI outside the reserved range, distinct from avoid.
func AllocSPI(avoid ...uint32) (uint32, error) {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		spi := binary.BigEndian.Uint32(b[:])
		if spi < 256 {
			continue
		}
		clash := false
		for _, a := range avoid {
			clash = clash || a == spi
		}
		if !clash {
			return spi, nil
		}
	}
}

// hexKey renders a key argument for ip-xfrm; an empty key (null cipher)
// is passed as an empty argument.
func hexKey(k []byte) string {
	if len(k) == 0 {
		return ""
	}
	return "0x" + hex.EncodeToString(k)
}
