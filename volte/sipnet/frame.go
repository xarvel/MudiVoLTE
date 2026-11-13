// Package sipnet is the minimal SIP transport and transaction layer for a
// single UE talking to its P-CSCF over TCP (RFC 3261 §18.3 framing, §17 matching).
// Message syntax comes from github.com/emiago/sipgo/sip; connection handling,
// port binding and transaction matching are ours, because sec-agree pins the
// local ports (TS 33.203 §7.1) and the network opens inbound connections freely.
package sipnet

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// maxMessage bounds one SIP message; IMS NOTIFY bodies are a few kB.
const maxMessage = 256 << 10

var errNeedMore = errors.New("need more data")

// splitFrame cuts one message off buf (RFC 3261 §18.3: Content-Length is
// mandatory on streams). It returns the message, bytes consumed, and how many
// leading CRLFs were skipped (RFC 5626 §3.5.1 keep-alive pings).
func splitFrame(buf []byte) (msg []byte, n int, crlfs int, err error) {
	for len(buf) >= 2 && buf[0] == '\r' && buf[1] == '\n' {
		buf = buf[2:]
		n += 2
		crlfs++
	}
	end := bytes.Index(buf, []byte("\r\n\r\n"))
	if end < 0 {
		if len(buf) > maxMessage {
			return nil, 0, 0, fmt.Errorf("header block exceeds %d bytes", maxMessage)
		}
		return nil, n, crlfs, errNeedMore
	}
	head := buf[:end+4]
	clen, err := contentLength(head)
	if err != nil {
		return nil, 0, 0, err
	}
	// Compared apart, because their sum can overflow.
	if clen > maxMessage-len(head) {
		return nil, 0, 0, fmt.Errorf("message of %d+%d bytes exceeds %d", len(head), clen, maxMessage)
	}
	total := len(head) + clen
	if len(buf) < total {
		return nil, n, crlfs, errNeedMore
	}
	return buf[:total], n + total, crlfs, nil
}

func contentLength(head []byte) (int, error) {
	for _, line := range strings.Split(string(head), "\r\n")[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if strings.EqualFold(name, "Content-Length") || name == "l" {
			v, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || v < 0 {
				return 0, fmt.Errorf("bad Content-Length %q", value)
			}
			if v > maxMessage {
				return 0, fmt.Errorf("bad Content-Length %d: over %d", v, maxMessage)
			}
			return v, nil
		}
	}
	return 0, errors.New("stream message without Content-Length")
}
