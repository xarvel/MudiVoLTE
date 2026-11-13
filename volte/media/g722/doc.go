// Package g722 is the ITU-T G.722 wideband speech codec (sub-band ADPCM,
// 7 kHz audio within 64 kbit/s) in pure Go, mode 1 only: 16 kHz 16-bit PCM
// in, one octet per sample pair out, and back. No cgo, no dependencies.
//
// Written from ITU-T Recommendation G.722 (11/88) "7 kHz audio-coding within
// 64 kbit/s", the freely available text on itu.int:
//
//   - §1.4.4: octet format IH1 IH2 IL1 … IL6, IH1 first;
//   - §3, §4: encoder and decoder principles;
//   - §5: transmit and receive QMF with the coefficients of Table 11;
//   - §6.2: the lower and higher sub-band ADPCM sub-blocks bit for bit —
//     SUBTRA, QUANTL, QUANTH, INVQAL, INVQAH, INVQBL (mode 1), LOGSCL,
//     LOGSCH, SCALEL and SCALEH (Method 2, table ILB), UPZERO, UPPOL1,
//     UPPOL2, FILTEZ, FILTEP, PREDIC, RECONS, PARREC, LIMIT — with the
//     constants of Tables 14 to 21 and the reset values of Table 13.
//
// The Recommendation leaves the QMF arithmetic to the implementation (§5.2,
// Note 1), and its conformance sequences bypass the QMF. Here the QMF keeps
// all 16 bits of the PCM on both sides (Table 9 has 15-bit XIN and XOUT) and
// does not limit XL, XH to 15 bits as LOWT and HIGHT would; SUBTRA still
// saturates the differences. With these choices the encoder output is
// identical to ffmpeg's g722 encoder and the decoder output to ffmpeg's
// adpcm_g722 decoder. The 15-bit limit would change only near-full-scale
// input, and for the worse: about 0.05 dB lower SNR on clipped signals.
//
// The ADPCM follows §6.2 literally, including the order and saturation of
// the FILTEZ sum ((((WD6 + WD5) + WD4) + WD3) + WD2) + WD1. ffmpeg sums those
// products in a wide accumulator. That only shows on streams which drive the
// zero predictor into overflow, such as testdata/filtez.g722; no encoder
// input we have tried reaches that state.
//
// RTP (RFC 3551 §4.5.2) carries G.722 as payload type 9 with an 8000 Hz
// clock rate, although the codec samples at 16 kHz: a 20 ms packet holds
// 160 octets, 320 samples, and advances the timestamp by 160.
//
// Provenance: no code of other G.722 implementations was consulted. ffmpeg
// served only as a black box whose encoded and decoded files the tests
// compare against (testdata was produced by ffmpeg 7.1).
package g722
