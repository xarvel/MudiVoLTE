package main

// QR code of the phone setup link: to the terminal (black on white via ANSI
// colours, two rows of modules per line, so a dark terminal theme does not
// get in the way) and as SVG for the web interface. Encoding is rsc.io/qr
// (BSD-3-Clause).

import (
	"fmt"
	"io"
	"strings"

	"rsc.io/qr"
)

const qrQuiet = 2 // quiet zone in modules (in the terminal the background around it is white anyway)

func qrEncode(text string) (*qr.Code, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, fmt.Errorf("QR code: %w", err)
	}
	return c, nil
}

// qrDark reports whether module (x, y) is dark, counting the quiet zone;
// outside the code it is light.
func qrDark(c *qr.Code, x, y int) bool {
	x, y = x-qrQuiet, y-qrQuiet
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return false
	}
	return c.Black(x, y)
}

// writeQRTerminal draws the code with "▀▄█" blocks on a white background.
func writeQRTerminal(w io.Writer, text string) error {
	c, err := qrEncode(text)
	if err != nil {
		return err
	}
	n := c.Size + 2*qrQuiet
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		b.WriteString("\x1b[30;47m")
		for x := 0; x < n; x++ {
			top, bottom := qrDark(c, x, y), qrDark(c, x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\x1b[0m\n")
	}
	_, err = io.WriteString(w, b.String())
	return err
}

// qrSVG returns the code as SVG: a white square and the black modules as one path.
func qrSVG(text string) (string, error) {
	c, err := qrEncode(text)
	if err != nil {
		return "", err
	}
	n := c.Size + 2*qrQuiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" shape-rendering="crispEdges">`, n, n, n*8, n*8)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if qrDark(c, x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}
