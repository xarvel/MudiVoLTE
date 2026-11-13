package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// spoolFile builds an smsd spool file the way GL's smsd writes them.
func spoolFile(from, toa, sent, received, charset, alphabet string, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("From: " + from + "\nFrom_TOA: " + toa + "\nFrom_SMSC: 38160000099\n")
	b.WriteString("Sent: " + sent + "\nReceived: " + received + "\nSubject: GMS1\nModem: GMS1\n")
	b.WriteString("Alphabet: " + alphabet + "\nCharset: " + charset + "\nUDH: no\n\n")
	b.Write(body)
	return b.Bytes()
}

func utf16be(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u>>8), byte(u))
	}
	return b
}

func TestParseSpoolSMS(t *testing.T) {
	loc := time.FixedZone("CET", 3600)
	cases := []struct {
		name, from, toa, charset, alphabet string
		body                               []byte
		wantFrom, wantText                 string
	}{
		{"utf-8, alphanumeric sender", "Operator", "D0 alphanumeric, unknown", "UTF-8", "UTF-8",
			[]byte("Código: 1234"), "Operator", "Código: 1234"},
		{"UCS-2 with a surrogate pair, international number", "447700900789", "91 international, ISDN/telephone",
			"UTF-16BE", "UCS2", utf16be("Γειά σου 👋"), "+447700900789", "Γειά σου 👋"},
		{"stock smstools ISO-8859-15", "447700900789", "91 international, ISDN/telephone", "", "ISO",
			[]byte("Price 5 \xa4\n"), "+447700900789", "Price 5 €"},
		{"national number keeps its form", "07700900789", "81 national", "UTF-8", "UTF-8",
			[]byte("ok\n"), "07700900789", "ok"},
	}
	for _, c := range cases {
		b := spoolFile(c.from, c.toa, "26-11-06 13:21:28", "26-11-06 13:21:30", c.charset, c.alphabet, c.body)
		it, ok := parseSpoolSMS(b, time.Time{}, loc)
		if !ok {
			t.Fatalf("%s: not parsed", c.name)
		}
		if it.From != c.wantFrom || it.Text != c.wantText || it.Via != "modem" {
			t.Errorf("%s: got %q %q %q", c.name, it.From, it.Text, it.Via)
		}
		if want := time.Date(2026, 11, 6, 13, 21, 30, 0, loc); !it.at.Equal(want) {
			t.Errorf("%s: time %v, want %v", c.name, it.at, want)
		}
	}
	if _, ok := parseSpoolSMS([]byte("From: x\nno body separator"), time.Time{}, loc); ok {
		t.Error("a file without the empty line must be skipped")
	}
	mtime := time.Date(2026, 11, 5, 9, 0, 0, 0, loc)
	b := []byte("From: Operator\n\nhello")
	if it, ok := parseSpoolSMS(b, mtime, loc); !ok || !it.at.Equal(mtime) {
		t.Errorf("without Received the file time counts: %v %v", it.at, ok)
	}
}

func TestListSMS(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "incoming")
	if err := os.Mkdir(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(spool, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The same message read through both slot contexts: one entry, the
	// earlier copy.
	write("GMS2.aaaaaa", spoolFile("Bank", "D0 alphanumeric, unknown", "26-11-05 15:07:40", "26-11-05 15:07:42", "UTF-8", "UTF-8", []byte("Code 1111")))
	write("GMS1.bbbbbb", spoolFile("Bank", "D0 alphanumeric, unknown", "26-11-05 15:07:40", "26-11-05 15:07:45", "UTF-8", "UTF-8", []byte("Code 1111")))
	// Same sender and text, another time stamp: a message of its own.
	write("GMS1.cccccc", spoolFile("Bank", "D0 alphanumeric, unknown", "26-11-06 04:27:45", "26-11-06 04:27:47", "UTF-8", "UTF-8", []byte("Code 1111")))
	write("GMS1.dddddd", spoolFile("447700900789", "91 international, ISDN/telephone", "26-11-05 16:05:50", "26-11-05 16:05:53", "UTF-16BE", "UCS2", utf16be("Γειά")))
	inbox := filepath.Join(dir, "sms-inbox.jsonl")
	if err := os.WriteFile(inbox, []byte(`{"received_at":"2026-11-06T10:00:00+01:00","from":"+447700900123","service_center":"+447700900099","text":"over IMS"}`+"\nbroken line\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	loc := time.FixedZone("CET", 3600)
	items, err := listSMS(spool, inbox, loc, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, it := range items {
		got = append(got, it.Time+" "+it.From+" "+it.Via+" "+it.Text)
	}
	want := []string{
		"2026-11-06T10:00:00+01:00 +447700900123 ims over IMS",
		"2026-11-06T04:27:47+01:00 Bank modem Code 1111",
		"2026-11-05T16:05:53+01:00 +447700900789 modem Γειά",
		"2026-11-05T15:07:42+01:00 Bank modem Code 1111",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("list:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if items, _ := listSMS(spool, inbox, loc, 2); len(items) != 2 || items[0].Via != "ims" {
		t.Fatalf("limit 2: %v", items)
	}
	b, _ := json.Marshal(items[:1])
	if string(b) != `[{"time":"2026-11-06T10:00:00+01:00","from":"+447700900123","text":"over IMS","via":"ims"}]` {
		t.Fatalf("JSON: %s", b)
	}
	if items, err := listSMS(filepath.Join(dir, "none"), filepath.Join(dir, "none.jsonl"), loc, 0); err != nil || len(items) != 0 {
		t.Fatalf("missing sources: %v %v", items, err)
	}
}

// What another SIM in the router receives is for another number (§117). A
// file that does not name a slot is ours.
func TestListSMSOnlyThisSIM(t *testing.T) {
	dir := t.TempDir()
	file := func(name, from, slot string) {
		t.Helper()
		head := "From: " + from + "\nFrom_TOA: D0 alphanumeric, unknown\nReceived: 26-11-08 11:23:09\n"
		if slot != "" {
			head += "Slot: " + slot + "\n"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(head+"\nhello"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	file("GMS1.aaaaaa", "Ours", "1")
	file("GMS2.bbbbbb", "Other", "2")
	file("GMS1.cccccc", "Unnamed", "")
	items, err := listSMS(dir, filepath.Join(dir, "none.jsonl"), time.UTC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, it := range items {
		got = append(got, it.From)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "Ours,Unnamed" {
		t.Fatalf("listed: %v", got)
	}
}

func TestPrintSMS(t *testing.T) {
	var out bytes.Buffer
	printSMS(&out, nil)
	if out.String() != "No SMS.\n" {
		t.Fatalf("empty: %q", out.String())
	}
	out.Reset()
	at := time.Date(2026, 11, 6, 13, 21, 30, 0, time.FixedZone("CET", 3600))
	printSMS(&out, []smsItem{
		{From: "Operator", Text: "line one\nline two", Via: "modem", at: at},
		{From: "+447700900123", Text: "hi", Via: "ims", at: at},
	})
	want := "2026-11-06 13:21  Operator\n    line one\n    line two\n" +
		"2026-11-06 13:21  +447700900123  (over IMS)\n    hi\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
}
