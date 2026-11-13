package srtp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"
)

// Suite is an SRTP crypto suite: AES in counter mode with HMAC-SHA1.
type Suite struct {
	Name   string // the name in a=crypto
	KeyLen int    // master key and session encryption key, bytes
	TagLen int    // authentication tag of an RTP packet, bytes
}

// SaltLen is the length of the master salt and the session salt of every
// AES-CM suite (112 bits).
const SaltLen = 14

// authKeyLen is the session authentication key of HMAC-SHA1 (160 bits).
const authKeyLen = 20

var (
	AES128CMSHA1_80 = Suite{Name: "AES_CM_128_HMAC_SHA1_80", KeyLen: 16, TagLen: 10}
	AES128CMSHA1_32 = Suite{Name: "AES_CM_128_HMAC_SHA1_32", KeyLen: 16, TagLen: 4}
	AES256CMSHA1_80 = Suite{Name: "AES_256_CM_HMAC_SHA1_80", KeyLen: 32, TagLen: 10}
	AES256CMSHA1_32 = Suite{Name: "AES_256_CM_HMAC_SHA1_32", KeyLen: 32, TagLen: 4}
)

var suites = []Suite{AES128CMSHA1_80, AES128CMSHA1_32, AES256CMSHA1_80, AES256CMSHA1_32}

// SuiteByName returns the suite with the a=crypto name (case matters, as in
// RFC 4568).
func SuiteByName(name string) (Suite, bool) {
	for _, s := range suites {
		if s.Name == name {
			return s, true
		}
	}
	return Suite{}, false
}

// Labels of the key derivation (RFC 3711 §4.3.1).
const (
	labelEncryption = 0x00
	labelAuth       = 0x01
	labelSalt       = 0x02
)

// replayWindow is how many packets behind the newest one are still accepted
// (RFC 3711 §3.3.2: at least 64).
const replayWindow = 64

// maxStreams caps the SSRCs one context tracks. A new SSRC gets state only
// after its first packet passes authentication, so only the holder of the key
// can create them.
const maxStreams = 16

var (
	ErrShort   = errors.New("srtp: packet too short")
	ErrNotRTP  = errors.New("srtp: not an RTP v2 packet")
	ErrAuth    = errors.New("srtp: authentication failed")
	ErrReplay  = errors.New("srtp: replayed or too old packet")
	ErrStreams = errors.New("srtp: too many SSRCs")
)

// Context protects or unprotects one direction of a stream with one master key.
// It is safe for concurrent use.
type Context struct {
	suite Suite
	block cipher.Block // session encryption key
	salt  [SaltLen]byte

	mu      sync.Mutex
	mac     hash.Hash
	streams map[uint32]*stream
}

// stream is the state of one SSRC: the rollover counter and the highest
// sequence number (s_l of RFC 3711 Appendix A), the highest index seen and
// a bitmap of the replayWindow indexes below it.
type stream struct {
	roc      uint32
	lastSeq  uint16
	maxIndex uint64
	seen     uint64 // bit i: index maxIndex-i was received
}

// NewContext derives the session keys from the master key and salt (RFC 3711
// §4.3, key derivation rate 0).
func NewContext(s Suite, masterKey, masterSalt []byte) (*Context, error) {
	if _, ok := SuiteByName(s.Name); !ok {
		return nil, fmt.Errorf("srtp: unknown suite %q", s.Name)
	}
	if len(masterKey) != s.KeyLen {
		return nil, fmt.Errorf("srtp: %s needs a %d-byte master key, got %d", s.Name, s.KeyLen, len(masterKey))
	}
	if len(masterSalt) != SaltLen {
		return nil, fmt.Errorf("srtp: the master salt must be %d bytes, got %d", SaltLen, len(masterSalt))
	}
	master, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	encKey := derive(master, masterSalt, labelEncryption, s.KeyLen)
	authKey := derive(master, masterSalt, labelAuth, authKeyLen)
	c := &Context{suite: s, streams: map[uint32]*stream{}}
	copy(c.salt[:], derive(master, masterSalt, labelSalt, SaltLen))
	if c.block, err = aes.NewCipher(encKey); err != nil {
		return nil, err
	}
	c.mac = hmac.New(sha1.New, authKey)
	return c, nil
}

// Suite returns the crypto suite of the context.
func (c *Context) Suite() Suite { return c.suite }

// derive is the AES-CM PRF of RFC 3711 §4.3.3: the keystream of the master
// key for x*2^16, where x is the master salt XOR (label || index DIV kdr), the
// label landing in the eighth octet from the right of the salt.
func derive(master cipher.Block, masterSalt []byte, label byte, n int) []byte {
	var iv [aes.BlockSize]byte
	copy(iv[:SaltLen], masterSalt)
	iv[7] ^= label
	out := make([]byte, n)
	cipher.NewCTR(master, iv[:]).XORKeyStream(out, out)
	return out
}

// headerLen returns the length of the RTP header with CSRCs and the header
// extension: what SRTP leaves in the clear.
func headerLen(pkt []byte) (int, error) {
	if len(pkt) < 12 {
		return 0, ErrShort
	}
	if pkt[0]>>6 != 2 {
		return 0, ErrNotRTP
	}
	n := 12 + 4*int(pkt[0]&0x0f)
	if pkt[0]&0x10 != 0 {
		if len(pkt) < n+4 {
			return 0, ErrShort
		}
		n += 4 + 4*int(binary.BigEndian.Uint16(pkt[n+2:]))
	}
	if len(pkt) < n {
		return 0, ErrShort
	}
	return n, nil
}

// crypt XORs payload with the keystream of packet index i of ssrc
// (RFC 3711 §4.1.1: IV = k_s*2^16 XOR SSRC*2^64 XOR i*2^16).
func (c *Context) crypt(payload []byte, ssrc uint32, index uint64) {
	var iv [aes.BlockSize]byte
	copy(iv[:SaltLen], c.salt[:])
	for k := 0; k < 4; k++ {
		iv[4+k] ^= byte(ssrc >> (24 - 8*k))
	}
	for k := 0; k < 6; k++ {
		iv[8+k] ^= byte(index >> (40 - 8*k))
	}
	cipher.NewCTR(c.block, iv[:]).XORKeyStream(payload, payload)
}

// tag returns the authentication tag of the packet without its tag: HMAC-SHA1
// over the packet and the rollover counter, truncated (RFC 3711 §4.2).
// Called with c.mu held.
func (c *Context) tag(authenticated []byte, roc uint32) []byte {
	var r [4]byte
	binary.BigEndian.PutUint32(r[:], roc)
	c.mac.Reset()
	c.mac.Write(authenticated)
	c.mac.Write(r[:])
	return c.mac.Sum(nil)[:c.suite.TagLen]
}

// guess estimates the rollover counter of seq (RFC 3711 Appendix A).
func (st *stream) guess(seq uint16) uint32 {
	v := st.roc
	if st.lastSeq < 32768 {
		if int(seq)-int(st.lastSeq) > 32768 && v > 0 {
			v--
		}
	} else if int(st.lastSeq)-32768 > int(seq) {
		v++
	}
	return v
}

// advance records an authenticated packet: the rollover counter, s_l and the
// replay window.
func (st *stream) advance(seq uint16, roc uint32) {
	index := uint64(roc)<<16 | uint64(seq)
	switch {
	case roc > st.roc:
		st.roc, st.lastSeq = roc, seq
	case roc == st.roc && seq > st.lastSeq:
		st.lastSeq = seq
	}
	switch {
	case index > st.maxIndex:
		shift := index - st.maxIndex
		if shift >= replayWindow {
			st.seen = 0
		} else {
			st.seen <<= shift
		}
		st.seen |= 1
		st.maxIndex = index
	default:
		st.seen |= 1 << (st.maxIndex - index)
	}
}

// replayed reports a packet already received or older than the window.
func (st *stream) replayed(index uint64) bool {
	if index > st.maxIndex {
		return false
	}
	d := st.maxIndex - index
	return d >= replayWindow || st.seen&(1<<d) != 0
}

// Protect encrypts and authenticates an RTP packet and appends the SRTP packet
// to dst. Packets of one SSRC must come in sending order: the rollover counter
// follows the sequence numbers.
func (c *Context) Protect(dst, pkt []byte) ([]byte, error) {
	hl, err := headerLen(pkt)
	if err != nil {
		return nil, err
	}
	seq := binary.BigEndian.Uint16(pkt[2:])
	ssrc := binary.BigEndian.Uint32(pkt[8:])
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.streams[ssrc]
	if st == nil {
		if len(c.streams) >= maxStreams {
			return nil, ErrStreams
		}
		st = &stream{lastSeq: seq, maxIndex: uint64(seq)}
		c.streams[ssrc] = st
	}
	roc := st.guess(seq)
	st.advance(seq, roc)
	start := len(dst)
	dst = append(dst, pkt...)
	out := dst[start:]
	c.crypt(out[hl:], ssrc, uint64(roc)<<16|uint64(seq))
	return append(dst, c.tag(out, roc)...), nil
}

// Unprotect checks the tag and the replay window of an SRTP packet, decrypts
// it and appends the RTP packet to dst. A packet that fails changes nothing.
func (c *Context) Unprotect(dst, pkt []byte) ([]byte, error) {
	hl, err := headerLen(pkt)
	if err != nil {
		return nil, err
	}
	n := len(pkt) - c.suite.TagLen
	if n < hl {
		return nil, ErrShort
	}
	seq := binary.BigEndian.Uint16(pkt[2:])
	ssrc := binary.BigEndian.Uint32(pkt[8:])
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.streams[ssrc]
	fresh := st == nil
	if fresh {
		if len(c.streams) >= maxStreams {
			return nil, ErrStreams
		}
		st = &stream{lastSeq: seq, maxIndex: uint64(seq)}
	}
	roc := st.guess(seq)
	index := uint64(roc)<<16 | uint64(seq)
	if !fresh && st.replayed(index) {
		return nil, ErrReplay
	}
	if subtle.ConstantTimeCompare(c.tag(pkt[:n], roc), pkt[n:]) != 1 {
		return nil, ErrAuth
	}
	if fresh {
		c.streams[ssrc] = st
	}
	st.advance(seq, roc)
	start := len(dst)
	dst = append(dst, pkt[:n]...)
	c.crypt(dst[start+hl:], ssrc, index)
	return dst, nil
}
