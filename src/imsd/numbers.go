package main

// Numbers for outgoing calls from the phones: normalisation to E.164 and a
// destination policy (protection against calls to premium-rate and foreign
// destinations).

import (
	"errors"
	"strings"
)

// normalizeDialed brings a dialled number to E.164: "+44 7700…"/"0044…" →
// "+447700…"; "07700…" → "+44" + "7700…" when default_country is set; short
// service numbers stay as they are.
func normalizeDialed(raw, defaultCountry string) (string, error) {
	s := strings.TrimSpace(raw)
	if i := strings.IndexAny(s, ";@"); i >= 0 {
		s = s[:i] // tail of a URI user part (;phone-context=…)
	}
	var out string
	switch {
	case strings.HasPrefix(s, "+"):
		out = "+" + digitsOnly(s[1:])
	case strings.HasPrefix(s, "00"):
		out = "+" + digitsOnly(s[2:])
	case strings.HasPrefix(s, "0") && defaultCountry != "":
		out = "+" + defaultCountry + digitsOnly(s[1:])
	default:
		out = digitsOnly(s)
	}
	d := strings.TrimPrefix(out, "+")
	if len(d) < 2 || len(d) > 15 {
		return "", errors.New("the number is too short or too long")
	}
	// The original string may hold only digits, + and separators.
	for _, r := range s {
		if !(r >= '0' && r <= '9') && !strings.ContainsRune("+-() .", r) {
			return "", errors.New("the number has characters that do not belong in one")
		}
	}
	return out, nil
}

// dialAllowed reports whether an E.164 number starts with an allowed prefix.
// Short numbers (without "+") are allowed only when listed explicitly; "*"
// allows everything (the package default: the phones on the home network are
// our own).
func dialAllowed(allow []string, number string) bool {
	for _, p := range allow {
		if p == "*" {
			return true
		}
		if strings.HasPrefix(p, "+") {
			if strings.HasPrefix(number, "+") && strings.HasPrefix(number, p) {
				return true
			}
		} else if number == p {
			return true
		}
	}
	return false
}

// callerUser returns the user part for the From of an incoming call on the
// phone: the caller's number (with "+" if it had one) or anonymous.
func callerUser(from string) string {
	f := strings.TrimSpace(from)
	d := digitsOnly(f)
	switch {
	case d == "":
		return "anonymous"
	case strings.HasPrefix(f, "+"):
		return "+" + d
	case strings.HasPrefix(d, "0"):
		return d // national format: the phone calls back via default_country
	case len(d) >= 11:
		return "+" + d // international without "+"
	}
	return d
}
