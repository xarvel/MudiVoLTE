//go:build cgo

// Package amrwb links the AMR-WB speech codec from opencore-amrwb (decoder)
// and vo-amrwbenc (encoder), both Apache-2.0, and registers it with media.
// Import it for its side effect:
//
//	import _ "github.com/xarvel/MudiVoLTE/volte/media/amrwb"
//
// By default it links the distribution's shared runtime (link_shared.go).
// The amrwb_static build tag links the static archives instead
// (link_static.go); CGO_LDFLAGS must point at the directory holding
// libopencore-amrwb.a and libvo-amrwbenc.a.
//
// Distributions ship only the .so.0 runtime without headers, so the stable
// E_IF_*/D_IF_* interface (enc_if.h, dec_if.h) is declared here.
package amrwb

/*
void *E_IF_init(void);
int   E_IF_encode(void *state, int mode, const short *speech, unsigned char *out, int dtx);
void  E_IF_exit(void *state);
void *D_IF_init(void);
void  D_IF_decode(void *state, const unsigned char *bits, short *synth, int bfi);
void  D_IF_exit(void *state);
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"

	"github.com/xarvel/MudiVoLTE/volte/media"
)

func init() { media.NewAMRWBCoder = New }

// Coder holds one encoder and one decoder state.
type Coder struct {
	mu  sync.Mutex
	enc unsafe.Pointer
	dec unsafe.Pointer
}

// New allocates codec state.
func New() (media.FrameCoder, error) {
	enc, dec := C.E_IF_init(), C.D_IF_init()
	if enc == nil || dec == nil {
		if enc != nil {
			C.E_IF_exit(enc)
		}
		if dec != nil {
			C.D_IF_exit(dec)
		}
		return nil, errors.New("AMR-WB codec init failed")
	}
	return &Coder{enc: enc, dec: dec}, nil
}

// EncodeFrame encodes 320 samples (20 ms at 16 kHz) to a storage frame.
func (c *Coder) EncodeFrame(pcm []int16, mode int) ([]byte, error) {
	if len(pcm) != 320 {
		return nil, errors.New("AMR-WB frame is 320 samples")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enc == nil {
		return nil, errors.New("codec closed")
	}
	var out [64]C.uchar
	n := C.E_IF_encode(c.enc, C.int(mode), (*C.short)(unsafe.Pointer(&pcm[0])), &out[0], 0)
	if n <= 0 {
		return nil, errors.New("AMR-WB encode failed")
	}
	return C.GoBytes(unsafe.Pointer(&out[0]), n), nil
}

// DecodeFrame decodes one storage frame to 320 samples.
func (c *Coder) DecodeFrame(storage []byte) ([]int16, error) {
	if len(storage) == 0 {
		return nil, errors.New("empty frame")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dec == nil {
		return nil, errors.New("codec closed")
	}
	in := make([]byte, 64) // decoder may read a full frame's worth
	copy(in, storage)
	out := make([]int16, 320)
	C.D_IF_decode(c.dec, (*C.uchar)(unsafe.Pointer(&in[0])), (*C.short)(unsafe.Pointer(&out[0])), 0)
	return out, nil
}

// Close frees the codec state.
func (c *Coder) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enc != nil {
		C.E_IF_exit(c.enc)
		c.enc = nil
	}
	if c.dec != nil {
		C.D_IF_exit(c.dec)
		c.dec = nil
	}
}
