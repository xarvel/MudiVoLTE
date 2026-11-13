package main

// SMS to the SIM, for the web page and `mudi-volte sms`, newest first. Most
// come through the modem: the operator delivers them over SGs, and GL's smsd
// stores each one as a file in its incoming spool, the same messages the SMS
// page of the GL admin panel shows. SMS over IMS, which this daemon receives
// itself, are lines of its inbox file (saveSMS). Both are only read here;
// deleting and sending stay with the GL admin panel.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

type smsItem struct {
	Time string `json:"time"` // RFC 3339
	From string `json:"from"`
	Text string `json:"text"`
	Via  string `json:"via"` // modem | ims

	at   time.Time
	sent string // the service centre's time stamp, to drop copies
	slot string // the SIM slot smsd filed it under; "" when the file does not say
}

// parseSpoolSMS reads one smsd spool file: "Key: value" lines, an empty
// line, the text in the charset the headers name. mtime stands in for a
// missing Received line.
func parseSpoolSMS(b []byte, mtime time.Time, loc *time.Location) (smsItem, bool) {
	head, body, ok := bytes.Cut(b, []byte("\n\n"))
	if !ok {
		return smsItem{}, false
	}
	h := map[string]string{}
	for _, line := range strings.Split(string(head), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			h[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	from := h["From"]
	if from == "" {
		return smsItem{}, false
	}
	// TOA 91: an international number, stored without its plus.
	if strings.HasPrefix(h["From_TOA"], "91") && digitsOnly(from) == from {
		from = "+" + from
	}
	at := mtime
	if t, err := time.ParseInLocation("06-01-02 15:04:05", h["Received"], loc); err == nil {
		at = t
	}
	return smsItem{From: from, Text: spoolText(body, h["Charset"], h["Alphabet"]), Via: "modem",
		at: at, sent: h["Sent"], slot: h["Slot"]}, true
}

// spoolText decodes the text of a spool file. smsd keeps UCS-2 as raw
// UTF-16BE ("Charset: UTF-16BE", "Alphabet: UCS2"), GSM text as UTF-8 or,
// in stock smstools, as ISO-8859-15.
func spoolText(body []byte, charset, alphabet string) string {
	cs := strings.ToUpper(charset + " " + alphabet)
	switch {
	case strings.Contains(cs, "UTF-16") || strings.Contains(cs, "UCS"):
		u := make([]uint16, len(body)/2)
		for i := range u {
			u[i] = uint16(body[2*i])<<8 | uint16(body[2*i+1])
		}
		return string(utf16.Decode(u))
	case strings.Contains(cs, "BINARY"):
		return "(binary message)"
	case strings.Contains(cs, "UTF-8"):
		return strings.ToValidUTF8(strings.TrimRight(string(body), "\n"), "�")
	}
	return latin9(bytes.TrimRight(body, "\n"))
}

// latin9 decodes ISO-8859-15: Latin-1 with eight places changed, € among them.
func latin9(b []byte) string {
	diff := map[byte]rune{0xA4: '€', 0xA6: 'Š', 0xA8: 'š', 0xB4: 'Ž', 0xB8: 'ž', 0xBC: 'Œ', 0xBD: 'œ', 0xBE: 'Ÿ'}
	var sb strings.Builder
	for _, c := range b {
		if r, ok := diff[c]; ok {
			sb.WriteRune(r)
		} else {
			sb.WriteRune(rune(c))
		}
	}
	return sb.String()
}

func readSpoolSMS(dir string, loc *time.Location) ([]smsItem, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	own := fmt.Sprint(imsSlot)
	var items []smsItem
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // smsd may be moving it
		}
		var mtime time.Time
		if fi, err := e.Info(); err == nil {
			mtime = fi.ModTime()
		}
		// Only this line's SIM: what another SIM in the router receives is
		// for another number (§117). The one copy of our own SMS seen under
		// the other slot had its twin under ours (§97, §118).
		if it, ok := parseSpoolSMS(b, mtime, loc); ok && (it.slot == "" || it.slot == own) {
			items = append(items, it)
		}
	}
	return items, nil
}

// readInboxSMS reads the SMS over IMS that saveSMS wrote.
func readInboxSMS(path string) ([]smsItem, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var items []smsItem
	for _, line := range strings.Split(string(b), "\n") {
		var rec struct {
			ReceivedAt string `json:"received_at"`
			From       string `json:"from"`
			Text       string `json:"text"`
		}
		if line == "" || json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		t, err := time.Parse(time.RFC3339, rec.ReceivedAt)
		if err != nil {
			continue
		}
		items = append(items, smsItem{From: rec.From, Text: rec.Text, Via: "ims", at: t})
	}
	return items, nil
}

// listSMS merges both sources, newest first, at most limit (0: all). The
// GL poller reads the SIM through both slot contexts (PROTOCOLS 3.1), so the
// spool can hold one message twice: same sender, service centre time stamp
// and text. The first copy stays.
func listSMS(spool, inbox string, loc *time.Location, limit int) ([]smsItem, error) {
	a, err := readSpoolSMS(spool, loc)
	if err != nil {
		return nil, err
	}
	b, err := readInboxSMS(inbox)
	if err != nil {
		return nil, err
	}
	all := append(a, b...)
	sort.SliceStable(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	seen := map[string]bool{}
	var items []smsItem
	for _, it := range all {
		if it.sent != "" {
			key := it.From + "\x00" + it.sent + "\x00" + it.Text
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		it.Time = it.at.Format(time.RFC3339)
		items = append(items, it)
	}
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// printSMS is `mudi-imsd sms`: the list for a human.
func printSMS(w io.Writer, items []smsItem) {
	if len(items) == 0 {
		fmt.Fprintln(w, "No SMS.")
		return
	}
	for _, it := range items {
		via := ""
		if it.Via == "ims" {
			via = "  (over IMS)"
		}
		fmt.Fprintf(w, "%s  %s%s\n", it.at.Format("2006-01-02 15:04"), it.From, via)
		for _, line := range strings.Split(it.Text, "\n") {
			fmt.Fprintf(w, "    %s\n", line)
		}
	}
}

// runSMS: mudi-imsd sms [-json] [-n N] SPOOL_DIR INBOX_FILE
func runSMS(args []string) int {
	asJSON, limit := false, 50
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch {
		case args[0] == "-json":
			asJSON = true
		case args[0] == "-n" && len(args) > 1:
			if _, err := fmt.Sscan(args[1], &limit); err != nil {
				return smsUsage()
			}
			args = args[1:]
		default:
			return smsUsage()
		}
		args = args[1:]
	}
	if len(args) != 2 {
		return smsUsage()
	}
	items, err := listSMS(args[0], args[1], time.Local, limit)
	if err != nil {
		fmt.Fprintln(os.Stderr, "SMS:", err)
		return 1
	}
	if !asJSON {
		printSMS(os.Stdout, items)
		return 0
	}
	if items == nil {
		items = []smsItem{}
	}
	b, _ := json.Marshal(items)
	fmt.Println(string(b))
	return 0
}

func smsUsage() int {
	fmt.Fprintln(os.Stderr, "usage: mudi-imsd sms [-json] [-n N] SPOOL_DIR INBOX_FILE")
	return 2
}
