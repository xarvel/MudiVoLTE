package media

// G.711 companding (ITU-T G.711 Tables 1a/2a) in the usual segment form:
// A-law on 13-bit magnitudes with even-bit inversion (XOR 0x55), µ-law on
// 14-bit magnitudes with bias 33 and full inversion.

var (
	alawSegEnd = [8]int{0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff, 0xfff}
	ulawSegEnd = [8]int{0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff, 0xfff, 0x1fff}
)

func segOf(v int, ends *[8]int) int {
	for i, e := range ends {
		if v <= e {
			return i
		}
	}
	return 8
}

// LinearToALaw compresses a 16-bit sample.
func LinearToALaw(s int16) byte {
	v := int(s) >> 3
	mask := byte(0xd5)
	if v < 0 {
		mask = 0x55
		v = -v - 1
	}
	seg := segOf(v, &alawSegEnd)
	if seg >= 8 {
		return 0x7f ^ mask
	}
	out := byte(seg << 4)
	if seg < 2 {
		out |= byte(v>>1) & 0x0f
	} else {
		out |= byte(v>>uint(seg)) & 0x0f
	}
	return out ^ mask
}

// ALawToLinear expands an A-law byte.
func ALawToLinear(a byte) int16 {
	a ^= 0x55
	t := int(a&0x0f) << 4
	switch seg := int(a>>4) & 7; seg {
	case 0:
		t += 8
	case 1:
		t += 0x108
	default:
		t = (t + 0x108) << uint(seg-1)
	}
	if a&0x80 == 0 {
		t = -t
	}
	return int16(t)
}

const ulawBias = 0x84

// LinearToULaw compresses a 16-bit sample.
func LinearToULaw(s int16) byte {
	v := int(s) >> 2
	mask := byte(0xff)
	if v < 0 {
		v = -v
		mask = 0x7f
	}
	if v > 8159 {
		v = 8159
	}
	v += ulawBias >> 2
	seg := segOf(v, &ulawSegEnd)
	if seg >= 8 {
		return 0x7f ^ mask
	}
	return (byte(seg<<4) | byte(v>>uint(seg+1))&0x0f) ^ mask
}

// ULawToLinear expands a µ-law byte.
func ULawToLinear(u byte) int16 {
	u = ^u
	t := (int(u&0x0f) << 3) + ulawBias
	t <<= uint(u>>4) & 7
	if u&0x80 != 0 {
		return int16(ulawBias - t)
	}
	return int16(t - ulawBias)
}
