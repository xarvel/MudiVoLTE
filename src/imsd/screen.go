package main

// Phone setup QR code on the display of the Mudi 7 itself: 240×320, RGB565,
// /dev/fb0 (GC9307C panel over SPI). The display belongs to gl_screen (the
// GL.iNet LVGL interface), which has no API for pages of our own, so the
// `mudi-volte phone screen` wrapper stops gl_screen while the code is shown,
// and this subcommand draws the frame itself, turns on the backlight and
// waits for a touch on the screen (/dev/input/event0) or a timeout. The font
// is our own, 5×7: phone names are Latin letters, digits and a few signs,
// nothing more is needed.

import (
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	screenW, screenH = 240, 320
	screenFB         = "/dev/fb0"
	screenBlank      = "/sys/class/graphics/fb0/blank" // FB_BLANK: 0 = on
	screenTouch      = "/dev/input/event0"
	screenBacklight  = "/sys/class/backlight/soc:backlight"
	screenBrightness = "56" // as GL has it by default (36 + offset 20); maximum 120

	colorWhite uint16 = 0xffff
	colorBlack uint16 = 0x0000
	colorGrey  uint16 = 0x7bef
)

// screenFont is a 5×7 font: rows from top to bottom, the highest of the five
// bits is the left column.
var screenFont = map[rune][7]byte{
	'A': {0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001},
	'B': {0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110},
	'C': {0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110},
	'D': {0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110},
	'E': {0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111},
	'F': {0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000},
	'G': {0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01111},
	'H': {0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001},
	'I': {0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110},
	'J': {0b00111, 0b00010, 0b00010, 0b00010, 0b00010, 0b10010, 0b01100},
	'K': {0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001},
	'L': {0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111},
	'M': {0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001},
	'N': {0b10001, 0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001},
	'O': {0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110},
	'P': {0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000},
	'Q': {0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101},
	'R': {0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001},
	'S': {0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110},
	'T': {0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100},
	'U': {0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110},
	'V': {0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100},
	'W': {0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b10101, 0b01010},
	'X': {0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001},
	'Y': {0b10001, 0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100},
	'Z': {0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111},
	'0': {0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110},
	'1': {0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110},
	'2': {0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111},
	'3': {0b11111, 0b00010, 0b00100, 0b00010, 0b00001, 0b10001, 0b01110},
	'4': {0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010},
	'5': {0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110},
	'6': {0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110},
	'7': {0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000},
	'8': {0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110},
	'9': {0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100},
	' ': {0, 0, 0, 0, 0, 0, 0},
	'-': {0, 0, 0, 0b11111, 0, 0, 0},
	'.': {0, 0, 0, 0, 0, 0b01100, 0b01100},
	'_': {0, 0, 0, 0, 0, 0, 0b11111},
	':': {0, 0b01100, 0b01100, 0, 0b01100, 0b01100, 0},
	'/': {0, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0},
	'!': {0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0, 0b00100},
	'?': {0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0, 0b00100},
	'(': {0b00010, 0b00100, 0b01000, 0b01000, 0b01000, 0b00100, 0b00010},
	')': {0b01000, 0b00100, 0b00010, 0b00010, 0b00010, 0b00100, 0b01000},
}

// frame is a screen frame, RGB565 row by row.
type frame struct {
	pix []uint16
}

func newFrame() *frame {
	f := &frame{pix: make([]uint16, screenW*screenH)}
	for i := range f.pix {
		f.pix[i] = colorWhite
	}
	return f
}

func (f *frame) rect(x, y, w, h int, c uint16) {
	for yy := max(y, 0); yy < min(y+h, screenH); yy++ {
		for xx := max(x, 0); xx < min(x+w, screenW); xx++ {
			f.pix[yy*screenW+xx] = c
		}
	}
}

// text draws a line in the 5×7 font scaled by scale; a character takes 6
// cells in width (five plus a gap). Lower-case letters are drawn as capitals,
// unknown signs as "?".
func (f *frame) text(x, y int, s string, scale int, c uint16) {
	for _, r := range strings.ToUpper(s) {
		g, ok := screenFont[r]
		if !ok {
			g = screenFont['?']
		}
		for row, bits := range g {
			for col := 0; col < 5; col++ {
				if bits&(0x10>>col) != 0 {
					f.rect(x+col*scale, y+row*scale, scale, scale, c)
				}
			}
		}
		x += 6 * scale
	}
}

func textWidth(s string, scale int) int {
	n := len([]rune(s))
	if n == 0 {
		return 0
	}
	return n*6*scale - scale
}

func (f *frame) textCentered(y int, s string, scale int, c uint16) {
	f.text((screenW-textWidth(s, scale))/2, y, s, scale, c)
}

// bytes returns the bytes for /dev/fb0: 16 bits per pixel, low byte first.
func (f *frame) bytes() []byte {
	b := make([]byte, 2*len(f.pix))
	for i, p := range f.pix {
		binary.LittleEndian.PutUint16(b[2*i:], p)
	}
	return b
}

func (f *frame) image() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, screenW, screenH))
	for i, p := range f.pix {
		r, g, b := (p>>11)&0x1f, (p>>5)&0x3f, p&0x1f
		img.Set(i%screenW, i/screenW, color.RGBA{uint8(r * 255 / 31), uint8(g * 255 / 63), uint8(b * 255 / 31), 255})
	}
	return img
}

// renderScreenQR renders the frame: the phone name at the top, the QR code in
// the middle, hints at the bottom. The quiet zone around the code is qrQuiet
// modules plus the white background of the frame, at least four modules in
// total, as the QR specification requires.
func renderScreenQR(name, url string, seconds int) (*frame, error) {
	c, err := qrEncode(url)
	if err != nil {
		return nil, err
	}
	f := newFrame()
	const top, bottom, margin = 54, 72, 16
	n := c.Size + 2*qrQuiet
	scale := min((screenW-2*margin)/n, (screenH-top-bottom)/n)
	if scale < 1 {
		return nil, fmt.Errorf("QR code of %d modules does not fit the display", n)
	}
	side := n * scale
	x0 := (screenW - side) / 2
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if qrDark(c, x, y) {
				f.rect(x0+x*scale, top+y*scale, scale, scale, colorBlack)
			}
		}
	}
	title := strings.ToUpper(name)
	ts := 3
	if textWidth(title, ts) > screenW-12 {
		ts = 2
	}
	if w := (screenW - 12) / (6 * ts); len([]rune(title)) > w {
		title = string([]rune(title)[:w])
	}
	f.textCentered(16, title, ts, colorBlack)
	hintY := top + side + 14
	f.textCentered(hintY, "SCAN IN LINPHONE", 2, colorBlack)
	// The second line is honest: a tap on the screen is not always read (the
	// touchscreen delivers events only while gl_screen owns it), but the timeout
	// always fires.
	if seconds > 0 {
		f.textCentered(hintY+22, fmt.Sprintf("CLOSES IN %ds", seconds), 2, colorGrey)
	}
	return f, nil
}

// screenWake wakes the display before showing: it unblanks the framebuffer
// and turns on the backlight. Unblanking is a must: the touch driver
// (semi_touch_fb_notifier_callback) puts the touchscreen to sleep on a blank
// event, and while fb0 is blanked no touches arrive at all; the backlight
// alone is not enough. gl_screen is stopped at this point, so the blank
// stays until our call.
func screenWake(blankPath, blDir string) {
	if blankPath != "" {
		if err := os.WriteFile(blankPath, []byte("0\n"), 0o644); err != nil {
			screenDebug("unblank %s: err=%v", blankPath, err)
		}
	}
	if err := backlightOn(blDir); err != nil {
		screenDebug("backlight %s: err=%v", blDir, err)
	}
}

// backlightOn turns on the backlight through sysfs: bl_power 0 and a non-zero
// brightness. It is not turned back off: afterwards gl_screen controls the
// display again and blanks it on its own timer. Errors are not fatal (no such
// directory means no backlight; the frame is drawn anyway).
func backlightOn(dir string) error {
	if dir == "" {
		return nil
	}
	if err := os.WriteFile(filepath.Join(dir, "bl_power"), []byte("0\n"), 0o644); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "brightness"))
	if err != nil {
		return err
	}
	if v, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && v > 0 {
		return nil
	}
	return os.WriteFile(filepath.Join(dir, "brightness"), []byte(screenBrightness+"\n"), 0o644)
}

// screenDebug logs the wait for a touch to the file named by
// $MUDI_SCREEN_DEBUG (for debugging on the device).
func screenDebug(format string, args ...any) {
	path := os.Getenv("MUDI_SCREEN_DEBUG")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	fmt.Fprintf(f, time.Now().Format("15:04:05.000")+" "+format+"\n", args...)
	f.Close()
}

// waitTouchOrTimeout waits for the first event from the touch sensor (any
// touch), a termination signal or the timeout.
func waitTouchOrTimeout(touch string, d time.Duration) {
	done := make(chan struct{}, 1)
	if touch != "" {
		f, err := os.Open(touch)
		screenDebug("touch open %s: err=%v", touch, err)
		if err == nil {
			start := time.Now()
			go func() {
				defer f.Close()
				buf := make([]byte, 4096)
				for {
					n, err := f.Read(buf)
					// The first 400 ms bring panel wake-up events and queued old
					// touches: drain them so that the frame does not close right
					// after it is shown.
					fresh := time.Since(start) > 400*time.Millisecond
					screenDebug("touch read: n=%d err=%v fresh=%v", n, err, fresh)
					if n > 0 && fresh {
						done <- struct{}{}
						return
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)
	select {
	case <-done:
		screenDebug("closed by touch")
	case s := <-sig:
		screenDebug("closed by signal %v", s)
	case <-time.After(d):
		screenDebug("closed by timeout %v", d)
	}
}

// runScreenQR — `mudi-imsd screen-qr [-name NAME] [-seconds N] URL`.
// seconds 0: draw and exit without touching the backlight (for checks).
// -png FILE: write the frame to a PNG instead of the display.
func runScreenQR(args []string) int {
	fs := flag.NewFlagSet("screen-qr", flag.ContinueOnError)
	name := fs.String("name", "", "phone name above the code")
	seconds := fs.Int("seconds", 90, "seconds to keep the frame; 0 draws it and exits")
	fbPath := fs.String("fb", screenFB, "framebuffer of the display")
	touchPath := fs.String("touch", screenTouch, "touch device; empty: do not wait for a touch")
	blDir := fs.String("backlight", screenBacklight, "backlight directory in sysfs; empty: leave it alone")
	blankPath := fs.String("blank", screenBlank, "fb blank node; empty: leave blank as it is")
	pngPath := fs.String("png", "", "write the frame to a PNG instead of the display")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: mudi-imsd screen-qr [-name NAME] [-seconds N] [-png FILE] URL")
		return 2
	}
	f, err := renderScreenQR(*name, fs.Arg(0), *seconds)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *pngPath != "" {
		out, err := os.Create(*pngPath)
		if err == nil {
			err = png.Encode(out, f.image())
			if cerr := out.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	// Wake the panel first (unblank + backlight): per the snapshot, the touch
	// sensor resumes only on an unblank event, otherwise no touches arrive. Then
	// the frame.
	if *seconds > 0 {
		screenWake(*blankPath, *blDir)
	}
	if err := os.WriteFile(*fbPath, f.bytes(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "display:", err)
		return 1
	}
	if *seconds <= 0 {
		return 0
	}
	waitTouchOrTimeout(*touchPath, time.Duration(*seconds)*time.Second)
	return 0
}
