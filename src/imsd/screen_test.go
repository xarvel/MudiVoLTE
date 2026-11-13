package main

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

const testScreenURL = "http://192.168.8.1:8060/p/f5d6a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7" // 66 characters; a real link is 50

func TestScreenFont(t *testing.T) {
	for _, r := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -._:/!?()" {
		g, ok := screenFont[r]
		if !ok {
			t.Errorf("no glyph for %q", r)
			continue
		}
		for row, bits := range g {
			if bits&^0x1f != 0 {
				t.Errorf("glyph %q, row %d: extra bits %05b", r, row, bits)
			}
		}
	}
	if textWidth("pixel", 3) != 5*18-3 {
		t.Errorf("text width: %d", textWidth("pixel", 3))
	}
}

func darkIn(f *frame, y0, y1 int) int {
	n := 0
	for y := y0; y < y1; y++ {
		for x := 0; x < screenW; x++ {
			if f.pix[y*screenW+x] != colorWhite {
				n++
			}
		}
	}
	return n
}

func TestScreenQRFrame(t *testing.T) {
	f, err := renderScreenQR("pixel", testScreenURL, 90)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(f.bytes()); n != screenW*screenH*2 {
		t.Fatalf("frame of %d bytes, want %d", n, screenW*screenH*2)
	}
	for _, i := range []int{0, screenW - 1, len(f.pix) - screenW, len(f.pix) - 1} {
		if f.pix[i] != colorWhite {
			t.Errorf("corner %d is not white: %04x", i, f.pix[i])
		}
	}
	if n := darkIn(f, 16, 37); n == 0 {
		t.Error("phone name at the top not drawn")
	}
	if n := darkIn(f, 54, 240); n < 3000 {
		t.Errorf("QR code too empty: %d dark pixels", n)
	}
	if n := darkIn(f, 240, screenH); n == 0 {
		t.Error("hints at the bottom not drawn")
	}
	// QR finder pattern: the 7-module square in the top left corner of the code,
	// aligned to the scale grid, which means the modules and the scale are
	// computed correctly.
	qc, _ := qrEncode(testScreenURL)
	n := qc.Size + 2*qrQuiet
	scale := min((screenW-32)/n, (screenH-54-72)/n)
	x0 := (screenW-n*scale)/2 + qrQuiet*scale
	y0 := 54 + qrQuiet*scale
	for dy := 0; dy < 7*scale; dy++ {
		for dx := 0; dx < 7*scale; dx++ {
			inner := dx >= scale && dx < 6*scale && dy >= scale && dy < 6*scale
			ring := dx >= 2*scale && dx < 5*scale && dy >= 2*scale && dy < 5*scale
			want := colorBlack
			if inner && !ring {
				want = colorWhite
			}
			if got := f.pix[(y0+dy)*screenW+x0+dx]; got != want {
				t.Fatalf("QR finder at (%d,%d): %04x, want %04x", dx, dy, got, want)
			}
		}
	}
	// A long name does not run off the screen: a smaller font or truncation.
	if _, err := renderScreenQR("very-long-phone-name-for-the-display", testScreenURL, 90); err != nil {
		t.Fatal(err)
	}
}

func TestScreenQRCommand(t *testing.T) {
	dir := t.TempDir()
	fb := filepath.Join(dir, "fb0")
	bl := filepath.Join(dir, "backlight")
	if err := os.Mkdir(bl, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"bl_power": "1\n", "brightness": "0\n"} {
		if err := os.WriteFile(filepath.Join(bl, name), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if rc := runScreenQR([]string{"-name", "iphone", "-seconds", "0", "-fb", fb, "-touch", "", "-backlight", bl, testScreenURL}); rc != 0 {
		t.Fatalf("screen-qr: exit code %d", rc)
	}
	if st, err := os.Stat(fb); err != nil || st.Size() != screenW*screenH*2 {
		t.Fatalf("framebuffer: %v, %v", st, err)
	}
	if raw, _ := os.ReadFile(filepath.Join(bl, "bl_power")); string(raw) != "1\n" {
		t.Errorf("with seconds=0 the backlight must not be touched: bl_power=%q", raw)
	}
	if err := backlightOn(bl); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"bl_power": "0\n", "brightness": screenBrightness + "\n"} {
		if raw, _ := os.ReadFile(filepath.Join(bl, name)); string(raw) != want {
			t.Errorf("%s=%q, want %q", name, raw, want)
		}
	}
	// A non-zero brightness is left alone.
	_ = os.WriteFile(filepath.Join(bl, "brightness"), []byte("100\n"), 0o644)
	_ = backlightOn(bl)
	if raw, _ := os.ReadFile(filepath.Join(bl, "brightness")); string(raw) != "100\n" {
		t.Errorf("brightness overwritten: %q", raw)
	}

	pngPath := filepath.Join(dir, "frame.png")
	if rc := runScreenQR([]string{"-png", pngPath, "-name", "pixel", testScreenURL}); rc != 0 {
		t.Fatalf("screen-qr -png: exit code %d", rc)
	}
	pf, err := os.Open(pngPath)
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()
	img, err := png.Decode(pf)
	if err != nil {
		t.Fatal(err)
	}
	if b := img.Bounds(); b.Dx() != screenW || b.Dy() != screenH {
		t.Errorf("PNG %dx%d", b.Dx(), b.Dy())
	}
	if rc := runScreenQR([]string{"-png", pngPath}); rc != 2 {
		t.Errorf("without a URL want exit code 2, got %d", rc)
	}
}
