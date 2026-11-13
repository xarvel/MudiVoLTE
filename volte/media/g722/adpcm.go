package g722

// Sub-band ADPCM of §6.2. All variables are the 16-bit quantities of
// Table 13: "+" and "-" saturate at 16 bits, "A * B" is (A·B) >> 15 and ">>"
// is an arithmetic shift, exactly as the notation of §6.2 defines them.

// Table 14, lower sub-band: decision levels Q6(1..29), 6-bit output values
// QQ6(1..30), and the 4-bit output values QQ4 and log multipliers WL, both
// addressed by IL4 of Table 17. Q6(30), Q6(31) repeat Q6(29) so that the
// search in quantl can run a fixed depth.
var (
	q6  = [32]int32{0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858, 940, 1023, 1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 2919, 2919}
	qq6 = [31]int32{0, 17, 54, 91, 130, 170, 211, 254, 300, 347, 396, 447, 501, 558, 618, 682, 750, 822, 899, 982, 1072, 1170, 1279, 1399, 1535, 1689, 1873, 2088, 2376, 2738, 3101}
	qq4 = [8]int32{0, 150, 323, 530, 786, 1121, 1612, 2557}
	wl  = [8]int32{-60, -30, 58, 172, 334, 538, 1198, 3042}
)

// Table 14, higher sub-band: decision level Q2, output values QQ2 and log
// multipliers WH, addressed by IH2 = 1, 2 of Table 21.
const q2 = 564

var (
	qq2 = [3]int32{0, 202, 926}
	wh  = [3]int32{0, -214, 798}
)

// Table 15: the 32-entry log-to-linear table ILB of SCALEL/SCALEH Method 2.
var ilb = [32]int32{
	2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383,
	2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
	2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371,
	3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008,
}

// Codeword tables of Tables 16–21.
var (
	// Table 16: IL by SIL and MIL, at [32·(-SIL) + MIL].
	ilCode [64]byte
	// Table 17: 4-bit codeword RIL → IL4 and SIL = -1.
	il4    = [16]int32{0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0}
	il4Neg = [16]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true, 7: true}
	// Table 20: IH by SIH and MIH, at [4·(-SIH) + MIH]; Table 21: IH → IH2.
	ihCode = [8]byte{1: 3, 2: 2, 5: 1, 6: 0}
	ih2    = [4]int32{2, 1, 2, 1}

	// WD2 of INVQAL by RIL, of INVQBL (mode 1, Table 18) by ILR and of
	// INVQAH by IH: the table constant << 3 with the sign attached.
	invq4 [16]int32
	invq6 [64]int32
	invq2 [4]int32
)

func init() {
	for m := 1; m <= 30; m++ {
		ilCode[m] = byte(62 - m)
		ilCode[32+m] = byte(34 - m)
	}
	ilCode[32+1], ilCode[32+2] = 63, 62
	for r := range invq4 {
		invq4[r] = qq4[il4[r]] << 3
		if il4Neg[r] {
			invq4[r] = -invq4[r]
		}
	}
	for c := range invq6 {
		switch {
		case c < 4: // the suppressed codewords 0000XX read as 111111
			invq6[c] = -qq6[1] << 3
		case c < 32:
			invq6[c] = -qq6[34-c] << 3
		case c < 62:
			invq6[c] = qq6[62-c] << 3
		default:
			invq6[c] = -qq6[64-c] << 3
		}
	}
	for ih := range invq2 {
		invq2[ih] = qq2[ih2[ih]] << 3
		if ih < 2 {
			invq2[ih] = -invq2[ih]
		}
	}
}

func sat(x int32) int32 { return max(-32768, min(x, 32767)) }

func limit15(x int32) int32 { return max(-16384, min(x, 16383)) }

// magnitude is WD of QUANTL and QUANTH: E for E ≥ 0, 32767 - (E & 32767)
// = |E| - 1 below zero, which is E with the bits flipped.
func magnitude(e int32) int32 { return e ^ e>>31 }

// quantl is QUANTL. MIL is the first interval whose upper decision level
// (Q6(MIL) << 3) * DETL exceeds WD: a WD on a level goes to the larger MIL,
// and an interval whose two levels coincide is never chosen (Notes 1 and 2).
// WD < (Q6 << 3) * DETL holds exactly when (WD + 1) << 12 <= Q6 · DETL. The
// levels grow with MIL, so a binary search of fixed depth counts those at or
// below WD. Speech makes these comparisons and the signs coin flips, so the
// code avoids branching on them.
func quantl(el, detl int32) byte {
	t := (magnitude(el) + 1) << 12
	m := 0
	if q6[16]*detl < t {
		m = 16
	}
	if q6[(m+8)&31]*detl < t {
		m += 8
	}
	if q6[(m+4)&31]*detl < t {
		m += 4
	}
	if q6[(m+2)&31]*detl < t {
		m += 2
	}
	if q6[(m+1)&31]*detl < t {
		m++
	}
	return ilCode[(int(el>>31)&32|min(m+1, 30))&63]
}

// quanth is QUANTH.
func quanth(eh, deth int32) byte {
	mih := 2
	if magnitude(eh) < (q2<<3)*deth>>15 {
		mih = 1
	}
	return ihCode[(int(eh>>31)&4|mih)&7]
}

// band holds the state of one sub-band ADPCM loop: the variables marked * in
// Table 13 plus the FILTEZ and PREDIC outputs of the current sample.
type band struct {
	a1, a2 int32    // pole section coefficients AL1, AL2 (AH1, AH2)
	b      [6]int32 // zero section coefficients BL1..BL6 (BH1..BH6)
	d      [6]int32 // quantized differences DLT1..DLT6 (DH1..DH6)
	p1, p2 int32    // partially reconstructed signals PLT1, PLT2 (PH1, PH2)
	r1, r2 int32    // reconstructed signals RLT1, RLT2 (RH1, RH2)
	nb     int32    // log scale factor NBL (NBH)
	det    int32    // scale factor DETL (DETH)

	sz, s int32 // SZL, SL (SZH, SH) of the current sample
}

// reset is the RS condition: everything 0, the scale factor at its minimum
// (32 for DELAYL, 8 for DELAYH).
func (b *band) reset(det int32) { *b = band{det: det} }

// predict runs FILTEZ, FILTEP and PREDIC.
func (b *band) predict() {
	var sz int32
	for i := 5; i >= 0; i-- { // ((((WD6 + WD5) + WD4) + WD3) + WD2) + WD1
		sz = sat(sz + b.b[i]*sat(b.d[i]+b.d[i])>>15)
	}
	sp := sat(b.a1*sat(b.r1+b.r1)>>15 + b.a2*sat(b.r2+b.r2)>>15)
	b.sz = sz
	b.s = sat(sp + sz)
}

// update takes the quantized difference d of the current sample (DLT, DH)
// and its log multiplier w, and runs LOGSCL/LOGSCH, SCALEL/SCALEH, PARREC,
// RECONS, UPZERO, UPPOL2, UPPOL1 and the delays. nbMax and shift are 18432
// and 8 in the lower sub-band, 22528 and 10 in the higher one. The pole
// section is fed RECONS before LIMIT: RLT in the lower sub-band and YH in the
// higher one, which Table 13 delays into RH1, RH2.
func (b *band) update(d, w, nbMax, shift int32) {
	nb := max(0, min(sat(b.nb*32512>>15+w), nbMax))
	frac, intg := nb>>6&31, nb>>11
	var det int32
	if intg <= shift {
		det = ilb[frac] >> (shift - intg) << 2
	} else {
		det = ilb[frac] << (intg - shift) << 2
	}

	p := sat(d + b.sz)
	r := sat(b.s + d)

	// UPZERO: ±WD1 by whether DLTi has the sign of DLT, without branches
	// (the signs are noise to a branch predictor). BPLi cannot leave the
	// 16-bit range: BLi * 32640 lies within ±32640.
	var g int32
	if d != 0 {
		g = 128
	}
	for i := range b.b {
		ne := (b.d[i] ^ d) >> 31 // -1 if SGi != SG0
		b.b[i] = (g ^ ne) - ne + b.b[i]*32640>>15
	}

	// UPPOL2. f(AL1) = 4·AL1 saturates at ±2 (Q14), as Eq. (3-34) requires.
	// ne1 is -1 where SG0 != SG1 and eq1 where they are equal, ne2 is -1
	// where SG0 != SG2; (x ^ m) - m negates x where m is -1.
	sg0 := p >> 31
	ne1, ne2 := sg0^b.p1>>31, sg0^b.p2>>31
	eq1 := ^ne1
	f := sat(b.a1 + b.a1)
	f = sat(f + f)
	f = sat(f^eq1-eq1) >> 7 // 0 - WD1 if SG0 == SG1
	f = sat(f + (128 ^ ne2 - ne2))
	a2 := max(-12288, min(sat(f+b.a2*32512>>15), 12288))

	// UPPOL1
	a1 := sat(b.a1*32640>>15 + (192 ^ ne1 - ne1))
	lim := sat(15360 - a2)
	a1 = max(-lim, min(a1, lim))

	b.a1, b.a2 = a1, a2
	b.d[5], b.d[4], b.d[3], b.d[2], b.d[1], b.d[0] = b.d[4], b.d[3], b.d[2], b.d[1], b.d[0], d
	b.p2, b.p1 = b.p1, p
	b.r2, b.r1 = b.r1, r
	b.nb, b.det = nb, det
}
