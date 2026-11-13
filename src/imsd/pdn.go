package main

// Discovery of the IMS PDN on the device: the rmnet_data* interface with the
// IMS address, the P-CSCF from +CGCONTRDP, P-Access-Network-Info from the
// serving cell.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Indirection layers that make the interface/address lookup testable.
type ifacesGetter func() ([]net.Interface, error)
type addrsGetter func(name string) ([]net.Addr, error)

var netIfaces ifacesGetter = net.Interfaces
var netAddrs addrsGetter = func(name string) ([]net.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return iface.Addrs()
}

// defaultRouteIface returns the interface of the default route (the internet
// PDN), or "" when there is none. Replaced in tests.
var defaultRouteIface = func() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 7 && f[1] == "00000000" && f[7] == "00000000" {
			return f[0]
		}
	}
	return ""
}

// findIMSIface finds the interface with the IMS address. cfgName is a
// specific name or "auto". In auto mode with a known PDN address (want, from
// CGCONTRDP) it looks for the interface with that address: the rmnet_dataN
// numbers of the internet and IMS PDNs swap places (§87). Without an address
// it takes the first rmnet_data* with IPv4 that does not carry the default
// route.
func findIMSIface(cfgName string, want net.IP) (string, net.IP, error) {
	if cfgName != "" && cfgName != "auto" {
		ip, err := firstIPv4(cfgName)
		if err != nil {
			return "", nil, err
		}
		return cfgName, ip, nil
	}
	ifaces, err := netIfaces()
	if err != nil {
		return "", nil, err
	}
	internet := defaultRouteIface()
	for _, iface := range ifaces {
		if !strings.HasPrefix(iface.Name, "rmnet_data") {
			continue
		}
		ip, err := firstIPv4(iface.Name)
		if err != nil || ip == nil {
			continue
		}
		if want != nil {
			if ip.Equal(want) {
				return iface.Name, ip, nil
			}
			continue
		}
		if iface.Name == internet {
			continue
		}
		return iface.Name, ip, nil
	}
	if want != nil {
		return "", nil, fmt.Errorf("no rmnet_data* has the IMS PDN address %s", want)
	}
	return "", nil, fmt.Errorf("no rmnet_data* IMS interface with an IPv4 address")
}

func firstIPv4(name string) (net.IP, error) {
	addrs, err := netAddrs(name)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("%s has no IPv4 address", name)
}

// pdnInfo is what the modem knows about the active PDN (the IPv4 part).
type pdnInfo struct {
	APN   string
	Local net.IP
	PCSCF []net.IP
}

// parseCGCONTRDP parses a +CGCONTRDP reply (TS 27.007 §10.1.23) by position:
// <cid>,<bearer_id>,<apn>,<local_addr[.mask]>,<gw>,<dns1>,<dns2>,<pcscf1>,<pcscf2>,…
// A live reply (§75, the DNS addresses replaced with documentation ones):
// 2,6,"ims","198.51.100.20",,"203.0.113.105","203.0.113.106","192.0.2.20",
// "192.0.2.28": the gateway is empty, the
// P-CSCFs come after the DNS servers. There can be several lines (IPv4/IPv6,
// extra P-CSCF pairs): the IPv4 addresses are collected from all of them,
// without duplicates, in the modem's order.
func parseCGCONTRDP(out string) pdnInfo {
	var info pdnInfo
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+CGCONTRDP:") {
			continue
		}
		var f []string
		for _, v := range strings.Split(line[len("+CGCONTRDP:"):], ",") {
			f = append(f, strings.Trim(strings.TrimSpace(v), "\""))
		}
		if len(f) > 2 && info.APN == "" {
			info.APN = f[2]
		}
		if len(f) > 3 && info.Local == nil {
			info.Local = ipv4Field(f[3])
		}
		for k := 7; k <= 8 && k < len(f); k++ {
			if ip := ipv4Field(f[k]); ip != nil && !seen[ip.String()] {
				seen[ip.String()] = true
				info.PCSCF = append(info.PCSCF, ip)
			}
		}
	}
	return info
}

// ipv4Field returns the IPv4 address of a CGCONTRDP field: "a.b.c.d",
// "a.b.c.d/len" or an address with the mask in dotted form "a.b.c.d.m.m.m.m"
// (TS 27.007). IPv6 and empty fields give nil.
func ipv4Field(s string) net.IP {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 8 {
		parts = parts[:4]
	}
	if len(parts) != 4 {
		return nil
	}
	ip := net.ParseIP(strings.Join(parts, ".")).To4()
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return nil
	}
	return ip
}

// parseIMSProfile returns the cid of the profile with APN "ims" from a
// +CGDCONT? reply; 0 when not found.
func parseIMSProfile(out string) int {
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+CGDCONT:") {
			continue
		}
		f := strings.Split(line[len("+CGDCONT:"):], ",")
		if len(f) < 3 || !strings.EqualFold(strings.Trim(strings.TrimSpace(f[2]), "\""), "ims") {
			continue
		}
		if cid, err := strconv.Atoi(strings.TrimSpace(f[0])); err == nil && cid > 0 {
			return cid
		}
	}
	return 0
}

// servingCellANI builds P-Access-Network-Info from the live cell
// (AT+QENG="servingcell"). Format (TS 24.229 §7.2A.4):
// access-type;utran-cell-id-3gpp=PLMN+TAC+ECI, where PLMN is 5-6 digits, TAC
// 4 hex digits and ECI 7 hex digits (11 hex digits in total after the PLMN).
// The QENG reply format varies (the state/RAT field is sometimes there and
// sometimes not: transient modem states), so we parse by the "LTE" TOKEN, not
// by indices, and make up to 3 attempts with a pause.
func servingCellANI(ctx context.Context, link *ATLink) (string, error) {
	var out string
	var err error
	const cmd = `AT+QENG="servingcell"`
	for attempt := 1; attempt <= 3; attempt++ {
		out, err = link.query(ctx, cmd)
		if err != nil {
			return "", err
		}
		ani, perr := parseQENGANI(out)
		if perr == nil {
			return ani, nil
		}
		if attempt == 3 {
			return "", fmt.Errorf("QENG (attempt 3): %w; raw reply: %.160q", perr, out)
		}
		if err := sleepCtx(ctx, 3*time.Second); err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("QENG: unreachable")
}

func parseQENGANI(out string) (string, error) {
	// Single-line format: +QENG: "servingcell",<state>,"LTE",<duplex>,…
	// Multi-line (EN-DC, LTE+NR5G-NSA): "servingcell",<state> on a line of its
	// own, then +QENG: "LTE",<duplex>,… and +QENG: "NR5G-NSA",… (§85). The fields
	// of all +QENG lines are joined: the order after "LTE" is the same.
	var s []string
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "+QENG:") {
			continue
		}
		for _, f := range strings.Split(line[len("+QENG:"):], ",") {
			s = append(s, strings.Trim(strings.TrimSpace(f), "\" "))
		}
	}
	if len(s) == 0 {
		return "", errors.New("no +QENG in the reply")
	}
	ratIdx := -1
	for k, v := range s {
		if v == "LTE" {
			ratIdx = k
			break
		}
	}
	// After "LTE": duplex, MCC, MNC, cellID, PCID, EARFCN, band, UL bw, DL bw, TAC.
	if ratIdx < 0 || ratIdx+10 >= len(s) {
		return "", fmt.Errorf("no LTE entry or too few fields: %v", firstN(s, 6))
	}
	duplex := strings.ToUpper(s[ratIdx+1])
	if duplex != "FDD" && duplex != "TDD" {
		return "", fmt.Errorf("duplex is neither FDD nor TDD: %q", s[ratIdx+1])
	}
	mcc, mnc, eci := s[ratIdx+2], s[ratIdx+3], s[ratIdx+4]
	tac := s[ratIdx+10] // before §85 this was the EARFCN (+6) by mistake; the network accepted it
	if !allDigits(mcc) || !allDigits(mnc) {
		return "", fmt.Errorf("PLMN is not digits: %q%q", mcc, mnc)
	}
	padHex := func(v string, n int) (string, error) {
		v = strings.ToUpper(v)
		if len(v) > n || !isHex(v) {
			return "", fmt.Errorf("%q is not hex of at most %d digits", v, n)
		}
		return strings.Repeat("0", n-len(v)) + v, nil
	}
	eciHex, err := padHex(eci, 7)
	if err != nil {
		return "", err
	}
	tacHex, err := padHex(tac, 4)
	if err != nil {
		return "", err
	}
	cellID := mcc + mnc + tacHex + eciHex
	return "3GPP-E-UTRAN-" + duplex + ";utran-cell-id-3gpp=" + cellID, nil
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func isHex(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789ABCDEF", c) {
			return false
		}
	}
	return len(s) > 0
}
