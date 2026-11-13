package g722

// Table 11: QMF coefficients H0..H23 scaled by 2^13.
var qmf = [24]int32{
	3, -11, -11, 53, 12, -156, 32, 362, -210, -805, 951, 3876,
	3876, 951, -805, -210, 362, 32, -156, 12, 53, -11, -11, 3,
}

// Encoder turns 16 kHz PCM into 64 kbit/s G.722. The state carries over
// from call to call, so a stream may be fed in frames of any even length.
type Encoder struct {
	h        [48]int32 // input history twice over: h[p:p+24] is XIN, XIN1, ..., XIN23
	p        int
	low, hig band
}

// NewEncoder returns an encoder in the reset state.
func NewEncoder() *Encoder {
	e := &Encoder{}
	e.Reset()
	return e
}

// Reset returns the encoder to its initial state.
func (e *Encoder) Reset() {
	e.h, e.p = [48]int32{}, 0
	e.low.reset(32)
	e.hig.reset(8)
}

// Encode codes the sample pairs of src, one octet per pair, into dst and
// returns the number of octets written: min(len(dst), len(src)/2). An odd
// trailing sample is not consumed.
func (e *Encoder) Encode(dst []byte, src []int16) int {
	n := min(len(dst), len(src)/2)
	for k := range n {
		// Transmit QMF: DELAYX, ACCUMA, ACCUMB, LOWT, HIGHT. The samples
		// keep all 16 bits (XIN of Table 9 has 15), hence the shift by 14;
		// XL and XH stay unlimited, SUBTRA saturates the difference.
		p := e.p - 2
		if p < 0 {
			p = 22
		}
		e.p = p
		s0, s1 := int32(src[2*k]), int32(src[2*k+1])
		e.h[p], e.h[p+1], e.h[p+24], e.h[p+25] = s1, s0, s1, s0
		x := (*[24]int32)(e.h[p : p+24])
		xa := x[0]*qmf[0] + x[2]*qmf[2] + x[4]*qmf[4] + x[6]*qmf[6] + x[8]*qmf[8] + x[10]*qmf[10] +
			x[12]*qmf[12] + x[14]*qmf[14] + x[16]*qmf[16] + x[18]*qmf[18] + x[20]*qmf[20] + x[22]*qmf[22]
		xb := x[1]*qmf[1] + x[3]*qmf[3] + x[5]*qmf[5] + x[7]*qmf[7] + x[9]*qmf[9] + x[11]*qmf[11] +
			x[13]*qmf[13] + x[15]*qmf[15] + x[17]*qmf[17] + x[19]*qmf[19] + x[21]*qmf[21] + x[23]*qmf[23]
		xl := (xa + xb) >> 14
		xh := (xa - xb) >> 14

		// Lower sub-band: SUBTRA, QUANTL, then INVQAL and the adaptation
		// on the codeword truncated to 4 bits.
		lo := &e.low
		lo.predict()
		il := quantl(sat(xl-lo.s), lo.det)
		ril := il >> 2
		lo.update(lo.det*invq4[ril]>>15, wl[il4[ril]], 18432, 8)

		// Higher sub-band: SUBTRA, QUANTH, INVQAH and the adaptation.
		hi := &e.hig
		hi.predict()
		ih := quanth(sat(xh-hi.s), hi.det)
		hi.update(hi.det*invq2[ih]>>15, wh[ih2[ih]], 22528, 10)

		dst[k] = ih<<6 | il // IH1 IH2 IL1 ... IL6
	}
	return n
}

// Decoder turns 64 kbit/s G.722 back into 16 kHz PCM. The state carries over
// from call to call.
type Decoder struct {
	hd, hs   [24]int32 // histories twice over: hd[p:p+12] is XD, XD1..XD11, hs likewise XS
	p        int
	low, hig band
}

// NewDecoder returns a decoder in the reset state.
func NewDecoder() *Decoder {
	d := &Decoder{}
	d.Reset()
	return d
}

// Reset returns the decoder to its initial state.
func (d *Decoder) Reset() {
	d.hd, d.hs, d.p = [24]int32{}, [24]int32{}, 0
	d.low.reset(32)
	d.hig.reset(8)
}

// Decode decodes the octets of src in mode 1 (all six lower sub-band bits
// carry audio), two samples per octet, into dst and returns the number of
// samples written: 2·min(len(src), len(dst)/2).
func (d *Decoder) Decode(dst []int16, src []byte) int {
	n := min(len(src), len(dst)/2)
	for k, c := range src[:n] {
		ilr, ih := int32(c&0x3f), c>>6

		// Lower sub-band: INVQBL gives the output, INVQAL on the 4-bit
		// truncated codeword drives the adaptation; RECONS, LIMIT.
		lo := &d.low
		lo.predict()
		rl := limit15(sat(lo.s + lo.det*invq6[ilr]>>15))
		ril := ilr >> 2
		lo.update(lo.det*invq4[ril]>>15, wl[il4[ril]], 18432, 8)

		// Higher sub-band: INVQAH, RECONS, LIMIT.
		hi := &d.hig
		hi.predict()
		dh := hi.det * invq2[ih] >> 15
		rh := limit15(sat(hi.s + dh))
		hi.update(dh, wh[ih2[ih]], 22528, 10)

		// Receive QMF: RECA, RECB, DELAYZ, ACCUMC, ACCUMD, SELECT. The
		// output keeps 16 bits: shift by 11 rather than 12 and saturate at
		// the int16 range.
		p := d.p - 1
		if p < 0 {
			p = 11
		}
		d.p = p
		d.hd[p], d.hd[p+12] = rl-rh, rl-rh
		d.hs[p], d.hs[p+12] = rl+rh, rl+rh
		xd, xs := (*[12]int32)(d.hd[p:p+12]), (*[12]int32)(d.hs[p:p+12])
		w1 := xd[0]*qmf[0] + xd[1]*qmf[2] + xd[2]*qmf[4] + xd[3]*qmf[6] + xd[4]*qmf[8] + xd[5]*qmf[10] +
			xd[6]*qmf[12] + xd[7]*qmf[14] + xd[8]*qmf[16] + xd[9]*qmf[18] + xd[10]*qmf[20] + xd[11]*qmf[22]
		w2 := xs[0]*qmf[1] + xs[1]*qmf[3] + xs[2]*qmf[5] + xs[3]*qmf[7] + xs[4]*qmf[9] + xs[5]*qmf[11] +
			xs[6]*qmf[13] + xs[7]*qmf[15] + xs[8]*qmf[17] + xs[9]*qmf[19] + xs[10]*qmf[21] + xs[11]*qmf[23]
		dst[2*k] = int16(sat(w1 >> 11))
		dst[2*k+1] = int16(sat(w2 >> 11))
	}
	return 2 * n
}
